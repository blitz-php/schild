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

namespace BlitzPHP\Schild\Commands\Generators;

use BlitzPHP\Cli\Commands\Generators\GeneratorCommand;
use BlitzPHP\Cli\Traits\ContentReplacer;

/**
 * Generates a custom user model file.
 */
class UserModelGenerator extends GeneratorCommand
{
    use ContentReplacer;

    protected string $group = 'Schild';

    protected string $name = 'schild:model';

    protected string $description = 'Générer un nouveau modèle utilisateur personnalisé.';

    protected string $usage = <<<'EOL'
        schild:model [name] [options]
        
        Exemples:
        # Générer un modèle simple sans entité
        php klinge schild:model
        
        # Générer un modèle avec l'entité User par défaut
        php klinge schild:model --with-entity
        
        # Générer un modèle avec une entité personnalisée nommée "Utilisateur"
        php klinge schild:model --with-entity=Utilisateur
        
        # Générer un modèle avec entité dans un namespace spécifique
        php klinge schild:model --with-entity="App\Modules\Auth\Entities\Admin"
        EOL;

    protected array $arguments = [
        'name' => ['Nom de la classe du modèle.', 'UserModel'],
    ];

    protected array $options = [
        '--namespace'   => ['Défini le namespace racine.', APP_NAMESPACE],
        '--suffix'      => 'Ajouter le suffixe "Model" au nom de la classe (ex: User => UserModel).',
        '--force'       => 'Forcer le remplacement du fichier existant.',
        '--with-entity' => 'Créer/utiliser une entité personnalisée. Peut être un nom de classe (ex: User, Utilisateur) ou un FQCN.',
    ];

    /**
     * {@inheritDoc}
     */
    protected string $component = 'Model';

    /**
     * {@inheritDoc}
     */
    protected string $directory = 'Models';

    /**
     * {@inheritDoc}
     */
    protected string $template = 'usermodel.tpl.php';

    /**
     * {@inheritDoc}
     */
    protected string $templatePath = __DIR__ . '/Views';

    protected string $classNameLang = 'CLI.generator.className.model';

    /**
     * @var array{created: bool, hasCustomEntity: bool, entityClass: string, entityNamespace: string} $entityInfo
     */
    private array $entityInfo = [];

    /**
     * {@inheritDoc}
     */
    public function process(array $params)
    {
        $this->setHasClassName(false);

        $class  = $this->argument('name', 'UserModel');
        
        // Vérifier le nom de la classe
        if (! $this->verifyChosenModelClassName($class, $params)) {
            $this->error('Impossible d\'utiliser "SchildUserModel" comme nom de classe car cela entre en conflit avec la classe parente.');
            $this->line('Veuillez choisir un autre nom, par exemple: "UserModel", "AppUserModel", etc.');

            return EXIT_ERROR;
        }

        // Gérer l'entité personnalisée
        $this->entityInfo = $this->handleCustomEntity($params);
        
        // Générer la classe
        $params[0] = $class;
        $this->generateClass($params);

        // Afficher un message de succès avec les prochaines étapes
        $this->eol();
        $this->success('Modèle utilisateur généré avec succès !');
        $this->eol();
        
        $this->numberedList(
            title: 'Prochaines étapes',
            items: [
                'Personnalisez la méthode fetchByCredentials() si nécessaire.',
                'Ajoutez vos propres méthodes spécifiques à votre application',
                'Configurez le modèle dans Config/auth.php (\'user_provider\' => \\' . $this->getNamespace() . '\\' . $class . '::class)'
            ]
        );
        
        if ($this->entityInfo['created']) {
            $this->eol();
            $this->info('Entité créée :');
            $this->line('  ' . $this->entityInfo['entityNamespace'] . '\\' . $this->entityInfo['entityClass']);
            $this->line('  Personnalisez cette entité pour ajouter vos propres propriétés et méthodes.');
        } elseif ($this->entityInfo['hasCustomEntity']) {
            $this->eol();
            $this->info('Entité existante utilisée :');
            $this->line('  ' . $this->entityInfo['entityNamespace'] . '\\' . $this->entityInfo['entityClass']);
        }

        return EXIT_SUCCESS;
    }

    /**
     * {@inheritDoc}
     */
    protected function prepare(string $class): string
    {
        $data    = ['hasCustomEntity' => $this->entityInfo['hasCustomEntity']];
        $search  = ['{entityClass}', '{entityNamespace}'];
        $replace = [
            $this->entityInfo['entityClass'], 
            $this->entityInfo['entityNamespace'] . '\\' . $this->entityInfo['entityClass']
        ];

        return $this->parseTemplate($class, $search, $replace, $data);
    }

    /**
     * Gère la création/utilisation de l'entité personnalisée
     */
    private function handleCustomEntity(array $params): array
    {
        $result = [
            'hasCustomEntity' => false,
            'entityClass'     => 'User',
            'entityNamespace' => 'BlitzPHP\\Schild\\Entities',
            'created'         => false,
        ];

        if (isset($params['entity'])) {
            $params['with-entity'] = $params['with-entity'] ?? $params['entity'] ?? null;
        }

        
        // Vérifier si l'option --with-entity est présente
        if (! isset($params['with-entity'])) {
            return $result;
        }
        
        $entityOption    = $params['with-entity'];
        $namespace       = $this->getNamespace();
        $entityName      = 'User';
        $entityNamespace = $namespace . '\\Entities';
        
        // Traiter l'option
        if (is_string($entityOption) && $entityOption !== '') {
            // Vérifier si c'est un FQCN (contient des backslashes)
            if (str_contains($entityOption, '\\')) {
                // C'est un FQCN complet
                $parts = explode('\\', $entityOption);
                $entityName = array_pop($parts);
                $entityNamespace = implode('\\', $parts);
            } else {
                // C'est juste un nom de classe
                $entityName = $entityOption; 
            }
        }
        
        $result['entityClass'] = $entityName;
        $result['entityNamespace'] = $entityNamespace;
        
        $fullEntityClass = $entityNamespace . '\\' . $entityName;
        
        if (class_exists($fullEntityClass)) {
            $result['hasCustomEntity'] = true;
        
            $this->badge()->info("Entité existante trouvée: {$fullEntityClass}");
        
            return $result;
        }
        
        // Créer l'entité
        $this->line("Création de l'entité: {$fullEntityClass}");
        
        if ($this->createEntity($entityName, $entityNamespace)) {
            $result['hasCustomEntity'] = true;
            $result['created'] = true;
            $this->badge()->success("Entité créée avec succès")->eol();
        } else {
            $this->error("Impossible de créer l'entité. Utilisation de l'entité par défaut.");
        }
        
        return $result;
    }

    /**
     * Crée un fichier d'entité User personnalisée
     */
    private function createEntity(string $entityName, string $namespace): bool
    {
        $path = $this->getEntityFilePath($entityName, $namespace);
        
        if (file_exists($path)) {
            return false;
        }
        
        $entityTemplate = file_get_contents($this->templatePath . '/userentity.tpl.php');
        $entityTemplate = str_replace(
            ['<@php', '{namespace}', '{entityName}'], 
            ['<?php', $namespace, $entityName],
            $entityTemplate
        );

        if (! is_dir($directory = dirname($path))) {
            mkdir($directory, 0755, true);
        }
        
        helper('filesystem');
        if (write_file($path, $entityTemplate)) {
            return true;
        }
        
        return false;
    }

    /**
     * Récupère le chemin du fichier d'entité
     */
    private function getEntityFilePath(string $entityName, string $namespace): string
    {
        // Convertir le namespace en chemin
        $relativePath = str_replace('\\', '/', $namespace);
        
        return app_path($relativePath . '/' . $entityName . '.php');
    }

    /**
     * Le nom de classe choisi ne doit pas être en conflit avec l'alias de la classe parente.
     */
    private function verifyChosenModelClassName(string $class, array $params): bool
    {
        helper('inflector');

        if (array_key_exists('suffix', $params) && ! str_contains($class, 'Model')) {
            $class .= 'Model';
        }

        return strtolower(pascalize($class)) !== 'schildusermodel';
    }
}
