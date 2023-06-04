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

namespace BlitzPHP\Schild\Entities;

use BlitzPHP\Models\BaseEntity;
use BlitzPHP\Schild\Entities\Cast\IntBoolCast;

/**
 * Base Entity
 */
abstract class Entity extends BaseEntity
{
    /**
     * Custom convert handlers
     *
     * @var array<string, string>
     * @phpstan-var array<string, class-string>
     */
    protected $castHandlers = [
        'int_bool' => IntBoolCast::class,
    ];

    protected array $authTables = [
        User::class         => 'users',
        Login::class        => 'logins',
        UserIdentity::class => 'identities',
        Group::class        => 'groups_users',
    ];

    /**
     * {@inheritDoc}
     */
    public function getTable(): string
    {
        return config('auth.tables')[$this->authTables[static::class] ?? static::class] ?: parent::getTable();
    }
}
