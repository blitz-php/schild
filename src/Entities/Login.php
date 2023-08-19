<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace BlitzPHP\Schild\Entities;

class Login extends Entity
{
    /**
     * {@inheritDoc}
     *
     * @var array<string, string>
     */
    protected array $casts = [
        'date'    => 'datetime',
        'success' => 'boolean',
    ];
}
