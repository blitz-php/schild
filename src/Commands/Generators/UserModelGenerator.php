<?php

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
    protected $description = 'Generate a new UserModel file.';

    /**
     * @var array<string, string>
     */
    protected $arguments = [
        'name' => 'The model class name. If not provided, this will default to `UserModel`.',
    ];

    /**
     * @var array<string, string>
     */
    protected $options = [
        '--namespace' => 'Set root namespace. Default: "APP_NAMESPACE".',
        '--suffix'    => 'Append the component title to the class name (e.g. User => UserModel).',
        '--force'     => 'Force overwrite existing file.',
    ];

    /**
     * Actually execute the command.
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
            $this->error('Cannot use `SchildUserModel` as class name as this conflicts with the parent class.');

            return 1;
        }

        $params[0] = $class;

        $this->runGeneration($params);

        return 0;
    }

    /**
     * The chosen class name should not conflict with the alias of the parent class.
     */
    private function verifyChosenModelClassName(string $class, array $params): bool
    {
        helper('inflector');

        if (array_key_exists('suffix', $params) && ! strripos($class, 'Model')) {
            $class .= 'Model';
        }

        return strtolower(pascalize($class)) !== 'shieldusermodel';
    }
}
