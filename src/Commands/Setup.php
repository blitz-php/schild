<?php

declare(strict_types=1);

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace BlitzPHP\Schild\Commands;

use BlitzPHP\Cli\Console\Command;
use BlitzPHP\Cli\Traits\ContentReplacer;
use InvalidArgumentException;
use Throwable;

class Setup extends Command
{
    use ContentReplacer { ContentReplacer::copyAndReplace as _copyAndReplace; }

    protected string $group = 'Schild';

    protected string $name = 'schild:setup';

    protected string $description = 'Configuration initiale pour BlitzPHP Schild.';

    protected array $options = [
        '-f|--force'           => 'Forcer le remplacement de TOUS les fichiers existants dans la destination.',
        '--no-interaction'     => 'Ne pas demander de confirmation, exécuter en mode automatique.',
    ];

    /**
     * {@inheritDoc}
     */
    public function handle()
    {
        $this->sourcePath = __DIR__ . '/../';
        $force            = $this->option('force') !== null;
        $noInteraction    = $this->option('no-interaction') !== null;

        if ($noInteraction) {
            // $this->setNoInteraction();
        }

        // Demander le type d'application
        $defaultChoice = $noInteraction ? 0 : null;
        $appType = $this->choice(
            'Quel type d\'application souhaitez-vous configurer ?',
            ['web', 'api-jwt', 'api-token', 'api-full', 'web + api-jwt', 'web + api-token', 'web + api-full'],
            $defaultChoice
        );

        $this->publishConfigAuth($force);
        $this->publishConfigAuthGroups($force);
        
        // Publier les configurations selon le type
		if (str_contains($appType, 'web')) {
			$this->setupWebSpecific();
		}
		if (str_contains($appType, 'api-jwt')) {
			$this->publishApi('jwt', $force);
		}
		if (str_contains($appType, 'api-token')) {
			$this->publishApi('tokens', $force);
		}
		if (str_contains($appType, 'api-full')) {
			$this->publishApiFull($force);
		}

        // Demander si on configure l'email (utile pour l'envoi de notifications)
        if ($this->confirm('Voulez-vous configurer l\'envoi d\'emails (nécessaire pour l\'activation, 2FA, liens magiques) ?', 'y')) {
            $this->setupEmail();
        }

        // Demander si on exécute les migrations
        if ($this->confirm('Exécuter les migrations maintenant ?', 'y')) {
            $this->runMigrations();
        }

        $this->success('Configuration de Schild terminée avec succès.');
        
        // Afficher un message de rappel si en mode API
        if (str_contains($appType, 'api')) {
            $this->eol()->bulletList(
                title: 'Rappel pour votre API :',
                items: [
                    'Pensez à configurer les clés JWT dans Config/auth-jwt.php si nécessaire.',
                    'Pour les tests, utilisez: php klinge schild:user create',
                    'Documentez vos endpoints d\'authentification (/api/login, /api/register, etc.)',
                ]
            );
        }
        
        // Afficher un message de rappel si en mode web
        if (str_contains($appType, 'web')) {
            $this->eol()->bulletList(
                title: 'Rappel pour votre application web :',
                items: [
                    'Configurez votre mailer pour l\'envoi des emails d\'activation/2FA',
                    'Personnalisez les vues dans Config/auth.php si nécessaire',
                ]
            );
        }
    }

    private function publishApi(string $authenticator, bool $force): void
    {
        if ($authenticator === 'jwt') {
            $this->publishConfigAuthJwt($force);
            $this->generateJwtKeys();
        } else {
            $this->publishConfigAuthToken($force);
        }

        $this->setupApiSpecific($authenticator);
    }

    private function publishApiFull(bool $force): void
    {
        $this->publishConfigAuthToken($force);
        $this->publishConfigAuthJwt($force);
        $this->generateJwtKeys();
        $this->setupApiFull();
    }

    private function publishConfigAuth(bool $force): void
    {
        $file     = 'Config/auth.php';
        $replaces = [];

        if (class_exists('\App\Models\UserModel')) {
            $replaces['BlitzPHP\Schild\Models\UserModel'] = 'App\Models\UserModel';
        }

        $this->copyAndReplace($file, $replaces, $force);
    }

    private function publishConfigAuthGroups(bool $force): void
    {
        $file     = 'Config/auth-groups.php';
        $replaces = [];

        $this->copyAndReplace($file, $replaces, $force);
    }

    private function publishConfigAuthToken(bool $force): void
    {
        $file     = 'Config/auth-token.php';
        $replaces = [];

        $this->copyAndReplace($file, $replaces, $force);
    }

    private function publishConfigAuthJwt(bool $force): void
    {
        $file     = 'Config/auth-jwt.php';
        $replaces = [];

        $this->copyAndReplace($file, $replaces, $force);
    }

    private function generateJwtKeys(): void
    {
        $path = $this->distPath . 'Config/auth-jwt.php';
        
        if (! is_file($path)) {
            return;
        }
        
        $content = file_get_contents($path);
        $needsUpdate = false;
        
        // Vérifier si les clés par défaut sont encore présentes
        if (strpos($content, "'secret' => '<Définir une chaîne aléatoire secrète>'") !== false) {
            if ($this->confirm('Voulez-vous générer automatiquement des clés JWT aléatoires ?')) {
                $secret = base64_encode(random_bytes(64));
                $content = str_replace(
                    "'secret' => '<Définir une chaîne aléatoire secrète>'",
                    "'secret' => '{$secret}'",
                    $content
                );
                $needsUpdate = true;
                $this->comment('Clé secrète JWT générée');
            }
        }
        
        if ($needsUpdate) {
            helper('filesystem');
            if (write_file($path, $content)) {
                $this->badge()->success('Clés JWT générées avec succès.', 'GÉNÉRÉ');
            } else {
                $this->error("Erreur lors de la génération des clés JWT.");
            }
        }
    }

    private function setupWebSpecific(): void
    {
        $this->setupRoutes();
        $this->setSecurityCSRF();
    }

    private function setupApiSpecific(string $authenticator): void
    {
        // Ajouter des routes API préfixées
        $this->setupApiRoutes();
        // Configurer l'authentificateur par défaut
        $this->updateAuthConfigForApi($authenticator);
    }

    private function setupApiFull(): void
    {
        // Ajouter des routes API préfixées
        $this->setupApiRoutes();
        // Configurer la chaîne d'authentification
        $this->updateAuthConfigForApiChain();
    }

    private function setupRoutes(): void
    {
		$files = config('routing.route_files', []);
		$files = array_filter($files, fn($f) => str_ends_with($f, 'web.php'));

		$file = $files !== [] ? array_shift($files) : 'Config/routes.php';

        $check   = 'service(\'auth\')->routes($routes);';
        $pattern = '/(.*)(\n' . preg_quote('$routes->', '/') . '[^\n]+?;\n)/su';
        $replace = '$1$2' . "\n" . $check . "\n";

        $this->addContent($file, $check, $pattern, $replace);
    }

    private function setupApiRoutes(): void
    {
		
		$files = config('routing.route_files', []);
		$files = array_filter($files, fn($f) => str_ends_with($f, 'api.php'));

		$file = $files !== [] ? array_shift($files) : 'Config/routes.php';

        // On ajoute un groupe /api avec le namespace API
        $apiRoutes = <<<'PHP'
$routes->group('/api', ['namespace' => 'App\Controllers\Api'], function($routes) {
    // Routes d'authentification pour l'API
    service('auth')->routes($routes);
});
PHP;

        $this->addContent($file, $apiRoutes, '/(.*)(\n' . preg_quote('service(\'auth\')->routes', '/') . '.*)/su', '$1' . "\n" . $apiRoutes . "\n");
    }

    private function setSecurityCSRF(): void
    {
        $file     = 'Config/security.php';
        $replaces = [
            '\'csrf_protection\' => \'cookie\',' => '\'csrf_protection\' => \'session\',',
        ];

        $path      = $this->distPath . $file;
        $cleanPath = clean_path($path);

        if (! is_file($path)) {
            $this->error("Pas de fichier trouvé '{$cleanPath}'.");
            return;
        }

        if (! $this->replace($path, $replaces)) {
            $this->badge()->success('Tout va bien.', 'Configuration de la sécurité');
            return;
        }

        $this->badge()->success("Nous avons mis à jour le fichier '{$cleanPath}' pour des raisons de sécurité.", 'UPDATED');
    }

    private function updateAuthConfigForApi(string $authenticator): void
    {
        $file = 'Config/auth.php';
        $path = $this->distPath . $file;

        if (! is_file($path)) {
            // Si le fichier n'existe pas, on le publie d'abord
            $this->publishConfigAuth(true);
        }

        $content = file_get_contents($path);
        
        // Modifier le default_authenticator
        $output = preg_replace(
            "/('default_authenticator'\s*=>\s*)'[^']*'/",
            "$1'{$authenticator}'",
            $content
        );

        // S'assurer que l'authentificateur est bien dans la liste des authenticators
        $authenticatorClass = $authenticator === 'jwt' 
            ? 'BlitzPHP\\Schild\\Authentication\\Authenticators\\JWT::class'
            : 'BlitzPHP\\Schild\\Authentication\\Authenticators\\AccessTokens::class';
        
        // Vérifier si l'authentificateur est déjà dans le tableau
        if (strpos($output, "'{$authenticator}' =>") === false) {
            // Ajouter l'authentificateur
            $pattern = "/(['\"]authenticators['\"]\s*=>\s*\[\s*)(.*?)(\s*\])/s";
            $output = preg_replace_callback($pattern, function($matches) use ($authenticator, $authenticatorClass) {
                return $matches[1] . $matches[2] . "\n        '{$authenticator}' => {$authenticatorClass}," . $matches[3];
            }, $output);
        }

        if ($output === $content) {
            $this->success('Configuration auth déjà adaptée pour l\'API.');
            return;
        }

        helper('filesystem');
        if (write_file($path, $output)) {
            $this->badge()->success("Mise à jour du fichier '{$path}' pour l'API.", 'UPDATED');
        } else {
            $this->error("Erreur lors de la mise à jour du fichier '{$path}'.");
        }
    }

    private function updateAuthConfigForApiChain(): void
    {
        $file = 'Config/auth.php';
        $path = $this->distPath . $file;

        if (! is_file($path)) {
            $this->publishConfigAuth(true);
        }

        $content = file_get_contents($path);
        
        // Modifier le default_authenticator pour 'chain'
        $output = preg_replace(
            "/('default_authenticator'\s*=>\s*)'[^']*'/",
            "$1'chain'",
            $content
        );

        // Configurer la chaîne d'authentification
        $chainConfig = <<<'PHP'
    'authentication_chain' => [
        'tokens',
        'jwt',
    ],
PHP;

        // Vérifier si la clé authentication_chain existe
        if (preg_match("/('authentication_chain'\s*=>\s*\[[^\]]*\])/s", $output)) {
            // Remplacer la chaîne existante
            $output = preg_replace(
                "/('authentication_chain'\s*=>\s*\[[^\]]*\])/s",
                $chainConfig,
                $output
            );
        } else {
            // Ajouter la chaîne après le tableau authenticators
            $pattern = "/(['\"]authenticators['\"]\s*=>\s*\[[^\]]*\]\s*,?)/s";
            $output = preg_replace($pattern, "$1\n\n    " . $chainConfig, $output);
        }

        if ($output === $content) {
            $this->success('Configuration auth déjà adaptée pour la chaîne API.');
            return;
        }

        helper('filesystem');
        if (write_file($path, $output)) {
            $this->badge()->success("Mise à jour du fichier '{$path}' pour la chaîne d'authentification.", 'UPDATED');
        } else {
            $this->error("Erreur lors de la mise à jour du fichier '{$path}'.");
        }
    }

    private function setupEmail(): void
    {
        $file = 'Config/mail.php';
        $path = $this->distPath . $file;
        $cleanPath = clean_path($path);

        if (! is_file($path)) {
            try {
                $this->call('config:publish', ['name' => 'mail']);
            } catch (Throwable) {
                $this->error("Fichier introuvable: '{$cleanPath}'.");
                return;
            }
        }

        $config = config('mail');
        $fromAddress = $config['from']['address'] ?? '';
        $fromName = $config['from']['name'] ?? '';

        if ($fromAddress !== '' && $fromAddress !== 'hello@example.com' && $fromName !== '' && $fromName !== 'Example') {
            $this->badge()->success('Tout va bien.', 'Configuration de la messagerie');
            return;
        }

        $content = file_get_contents($path);
        $output = $content;

        if ($fromAddress === '' || $fromAddress === 'hello@example.com') {
            if ($this->confirm('La configuration mail.from.address requise n\'est pas définie. Voulez-vous le faire maintenant ?', 'y')) {
                $fromAddress = $this->prompt('  Quel est votre email?', null, function($value) {
                    if (! filter_var($value, FILTER_VALIDATE_EMAIL)) {
                        throw new InvalidArgumentException('Veuillez entrer une adresse email valide.');
                    }
                    return $value;
                });
                
                // Remplacer l'adresse dans le tableau
                $output = preg_replace(
                    "/('address'\s*=>\s*env\('mail\.from\.address',\s*')([^']*)('\))/",
                    "$1{$fromAddress}$3",
                    $output
                );
            }
        }

        if ($fromName === '' || $fromName === 'Example') {
            if ($this->confirm('La configuration mail.from.name requise n\'est pas définie. Voulez-vous le faire maintenant ?', 'y')) {
                $fromName = $this->prompt('  Quel est votre nom?', null, function($value) {
                    if (trim($value) === '') {
                        throw new InvalidArgumentException('Le nom ne peut pas être vide.');
                    }
                    return $value;
                });
                
                // Remplacer le nom dans le tableau
                $output = preg_replace(
                    "/('name'\s*=>\s*env\('mail\.from\.name',\s*')([^']*)('\))/",
                    "$1{$fromName}$3",
                    $output
                );
            }
        }

        helper('filesystem');

        if (write_file($path, $output)) {
            $this->badge()->success("Nous avons mis à jour le fichier '{$cleanPath}' pour l'envoi d'emails.", 'UPDATED');
        } else {
            $this->error("Erreur lors de la mise à jour du fichier '{$cleanPath}'.");
        }
    }

    private function runMigrations(): void
    {
        $this->eol()->call('migrate', options: ['--namespace' => 'BlitzPHP\\Schild']);
		$this->eol();
    }

    /**
     * Surcharge de copyAndReplace pour gérer l'option force
     */
    private function copyAndReplace(string $file, array $replaces = [], bool $force = false): void
    {
        $source = $this->sourcePath($file);
        $target = $this->distPath($file);

        if (! $force && is_file($target)) {
            if (! $this->confirm("Le fichier '{$target}' existe déjà. Voulez-vous l'écraser ?", 'n')) {
                return;
            }
        }

        $this->_copyAndReplace($file, $replaces);
    }
}
