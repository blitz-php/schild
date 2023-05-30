<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace BlitzPHP\Schild\Commands;

use BlitzPHP\Cli\Commands\Database\Migration\Migrate;
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
        '-f' => 'Forcer le remplacement de TOUS les fichiers existants dans la destination.',
    ];

    /**
     * {@inheritDoc}
     */
    public function execute(array $params)
    {
        $this->sourcePath = __DIR__ . '/../';

        $this->publishConfig();
    }

    private function publishConfig(): void
    {
        $this->publishConfigAuth();
        $this->publishConfigAuthGroups();

        // $this->setupConstants();
        $this->setupHelper();
        $this->setupRoutes();

        $this->runMigrations();
    }

    private function publishConfigAuth(): void
    {
        $file     = 'Config/auth.php';
        $replaces = [];

        $this->copyAndReplace($file, $replaces);
    }

    private function publishConfigAuthGroups(): void
    {
        $file     = 'Config/auth-groups.php';
        $replaces = [];

        $this->copyAndReplace($file, $replaces);
    }

    private function setupConstants(): void
    {
        $file  = 'Config/constants.php';
        $path  = $this->distPath($file);
        $label = 'Updated:';

        if (! file_exists($path)) {
            file_put_contents($path, "<?php \n");
            $label = 'Created:';
        }

        $content = file_get_contents($this->sourcePath($file));

        file_put_contents($path, str_replace('<?php', '', $content), FILE_APPEND);

        $cleanPath = clean_path($path);
        $this->success($cleanPath, true, $label);
    }

    private function setupHelper(): void
    {
        $file  = 'Controllers/BaseController.php';
        $check = '$this->helpers = array_merge($this->helpers, [\'auth\']);';

        // Remplacer l'ancienne configuration de l'assistant
        $replaces = [
            '$this->helpers = array_merge($this->helpers, [\'auth\']);' => $check,
        ];
        if ($this->replace($file, $replaces)) {
            return;
        }

        // Ajouter une configuration d'assistance
        $pattern = '/(' . preg_quote('// Do Not Edit This Line', '/') . ')/u';
        $replace = $check . "\n\n        " . '$1';

        $this->addContent($file, $check, $pattern, $replace);
    }

    private function setupRoutes(): void
    {
        $file = 'Config/routes.php';

        $check   = 'service(\'auth\')->routes($routes);';
        $pattern = '/(.*)(\n' . preg_quote('$routes->', '/') . '[^\n]+?;\n)/su';
        $replace = '$1$2' . "\n" . $check . "\n";

        $this->addContent($file, $check, $pattern, $replace);
    }

    private function runMigrations(): void
    {
        if (! $this->confirm('Run `klinge migrate --all` now?')) {
            return;
        }

        $command = new Migrate($this->app, $this->logger);
        $command->setOptions(['all' => true])->execute(['all' => true]);
    }
}
