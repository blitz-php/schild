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

class Setup extends Command
{
    use ContentReplacer;

    /**
     * @var string
     */
    protected $group = 'Schild';

    /**
     * @var string
     */
    protected $name = 'schild:setup';

    /**
     * @var string
     */
    protected $description = 'Configuration initiale pour BlitzPHP Schild.';

    /**
     * @var array
     */
    protected $options = [
        '-f|--force' => 'Forcer le remplacement de TOUS les fichiers existants dans la destination.',
    ];

    /**
     * {@inheritDoc}
     */
    public function execute(array $params): void
    {
        $this->sourcePath = __DIR__ . '/../';

        $this->publishConfig();
    }

    private function publishConfig(): void
    {
        $this->publishConfigAuth();
        $this->publishConfigAuthGroups();
        $this->publishConfigAuthToken();
        $this->publishConfigAuthJwt();

        $this->setupRoutes();

        $this->setSecurityCSRF();
        // $this->setupEmail();

        $this->runMigrations();
    }

    private function publishConfigAuth(): void
    {
        $file     = 'Config/auth.php';
        $replaces = [];

        if (class_exists('\App\Models\UserModel')) {
            $replaces['BlitzPHP\Schild\Models\UserModel'] = 'App\Models\UserModel';
        }

        $this->copyAndReplace($file, $replaces);
    }

    private function publishConfigAuthGroups(): void
    {
        $file     = 'Config/auth-groups.php';
        $replaces = [];

        $this->copyAndReplace($file, $replaces);
    }

    private function publishConfigAuthToken(): void
    {
        $file     = 'Config/auth-token.php';
        $replaces = [];

        $this->copyAndReplace($file, $replaces);
    }

    private function publishConfigAuthJwt(): void
    {
        $file     = 'Config/auth-jwt.php';
        $replaces = [];

        $this->copyAndReplace($file, $replaces);
    }

    private function setupConstants(): void
    {
        $file  = 'Config/constants.php';
        $path  = $this->distPath($file);
        $label = 'Modifié:';

        if (! file_exists($path)) {
            file_put_contents($path, "<?php \n");
            $label = 'Créé:';
        }

        $content = file_get_contents($this->sourcePath($file));

        file_put_contents($path, str_replace('<?php', '', $content), FILE_APPEND);

        $cleanPath = clean_path($path);
        $this->success($cleanPath, true, $label)->eol();
    }

    private function setupRoutes(): void
    {
        $file = 'Config/routes.php';

        $check   = 'service(\'auth\')->routes($routes);';
        $pattern = '/(.*)(\n' . preg_quote('$routes->', '/') . '[^\n]+?;\n)/su';
        $replace = '$1$2' . "\n" . $check . "\n";

        $this->addContent($file, $check, $pattern, $replace);
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

        $content = file_get_contents($path);
        $output  = $this->replacer->replace($content, $replaces);

        // verifions que $csrfProtection = 'session'
        if ($output === $content) {
            $this->success('Tout va bien.', true, 'Configuration de la sécurité');

            return;
        }

        helper('filesystem');

        if (write_file($path, $output)) {
            $this->success("Nous avons mis à jour le fichier '{$cleanPath}' pour des raisons de sécurité.", true, 'UPDATED');
        } else {
            $this->error("Erreur lors de la mise à jour du fichier '{$cleanPath}'.");
        }
    }

    private function setupEmail(): void
    {
        $file = 'Config/mail.php';

        $path      = $this->distPath . $file;
        $cleanPath = clean_path($path);

        if (! is_file($path)) {
            $this->error("Fichier introuvable: '{$cleanPath}'.");

            return;
        }

        $config    = (object) config('mail');
        $fromEmail = (string) $config->from['email'] ?? '';
        $fromName  = (string) $config->from['name'] ?? '';

        if ($fromEmail !== '' && $fromName !== '') {
            $this->success('Tout va bien.', true, 'Configuration de la messagerie');

            return;
        }

        $content = file_get_contents($path);
        $output  = $content;

        if ($fromEmail === '') {
            if ($this->confirm('La configuration Config\mail::$from.email requise n\'est pas définie. Voulez-vous le faire maintenant ?')) {
                // Input from email
                $fromEmail = $this->prompt('  Quel est votre email?', null);

                $pattern = '/^    public .*\$fromEmail\s+= \'\';/mu';
                $replace = '    public string $fromEmail  = \'' . $fromEmail . '\';';
                $output  = preg_replace($pattern, $replace, $content);
            }
        }

        if ($fromName === '') {
            if ($this->confirm('La configuration Config\mail::$from.name requise n\'est pas définie. Voulez-vous le faire maintenant ?')) {
                $fromName = $this->prompt('  Quel est votre nom?', null, 'required');

                $pattern = '/^    public .*\$fromName\s+= \'\';/mu';
                $replace = '    public string $fromName   = \'' . $fromName . '\';';
                $output  = preg_replace($pattern, $replace, $output);
            }
        }

        helper('filesystem');

        if (write_file($path, $output)) {
            $this->success("Nous avons mis à jour le fichier '{$cleanPath}' pour des raisons de sécurité.", true, 'UPDATED');
        } else {
            $this->error("Erreur lors de la mise à jour du fichier '{$cleanPath}'.");
        }
    }

    private function runMigrations(): void
    {
        if (! $this->confirm('Exécuter `klinge migrate --all` maintenant?')) {
            return;
        }

        $this->eol()->app->call('migrate', ['all' => true], ['all' => true]);
    }
}
