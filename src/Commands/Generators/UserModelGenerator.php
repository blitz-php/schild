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

use BlitzPHP\Cli\Console\Command;
use BlitzPHP\Cli\Traits\GeneratorTrait;

/**
 * Generates a custom user model file.
 */
class UserModelGenerator extends Command
{
    use GeneratorTrait;

    /**
     * @var string
     */
    protected $group = 'Schild';

    /**
     * @var string
     */
    protected $name = 'schild:model';

    /**
     * @var string
     */
    protected $description = 'Générer un nouveau fichier UserModel.';

    /**
     * @var array<string, string>
     */
    protected $arguments = [
        'name' => 'Nom de la classe de modèle. S\'il n\'a pas été fourni, il sera mis à `UserModel` par défaut.',
    ];

    /**
     * @var array<string, string>
     */
    protected $options = [
        '--namespace' => 'Defini le namespace racine. Defaut: "APP_NAMESPACE".',
        '--suffix'    => 'Ajouter le titre du composant au nom de la classe (ex. User => UserModel).',
        '--force'     => 'Forcer le remplacement du fichier existant.',
    ];

    /**
     * {@inheritDoc}
     */
    public function execute(array $params)
    {
        $this->component    = 'Model';
        $this->directory    = 'Models';
        $this->template     = 'usermodel.tpl.php';
        $this->templatePath = __DIR__ . '/Views';

        $this->classNameLang = 'CLI.generator.className.model';
        $this->setHasClassName(false);

        $class = $this->argument('name', 'UserModel');

        if (! $this->verifyChosenModelClassName($class, $params)) {
            $this->error('Impossible d\'utiliser le nom de `SchildUserModel` en tant que nom de classe car cela entre en conflit avec la classe parente.');

            return 1;
        }

        $params[0] = $class;

        $this->runGeneration($params);

        return 0;
    }

    /**
     * Le nom de classe choisi ne doit pas être en conflit avec l'alias de la classe parente.
     */
    private function verifyChosenModelClassName(string $class, array $params): bool
    {
        helper('inflector');

        if (array_key_exists('suffix', $params) && ! strripos($class, 'Model')) {
            $class .= 'Model';
        }

        return strtolower(pascalize($class)) !== 'schildusermodel';
    }
}
