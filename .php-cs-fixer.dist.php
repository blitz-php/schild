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

use BlitzPHP\CodingStandard\Blitz;
use Nexus\CsConfig\Factory;
use PhpCsFixer\Finder;

$finder = Finder::create()
    ->files()
    ->in([__DIR__ . '/src', __DIR__ . '/spec'])
    ->exclude('build')
    ->append([__FILE__]);

$overrides = [
    'declare_strict_types' => true,
    'void_return'          => true,
];

$options = [
    'cacheFile'    => 'build/.php-cs-fixer.cache',
    'finder'       => $finder,
];

return Factory::create(new Blitz(), $overrides, $options)->forLibrary(
    'Blitz PHP framework - Schild',
    'Dimitri Sitchet Tomkeu',
    'devcode.dst@gmail.com',
    2023
);
