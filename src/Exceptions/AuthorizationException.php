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

namespace BlitzPHP\Schild\Exceptions;

class AuthorizationException extends RuntimeException
{
    protected $code = 401;

    public static function unknownGroup(string $group): self
    {
        return new self(lang('Auth.unknownGroup', [$group]));
    }

    public static function unknownPermission(string $permission): self
    {
        return new self(lang('Auth.unknownPermission', [$permission]));
    }

    public static function unauthorized(): self
    {
        return new self(lang('Auth.notEnoughPrivilege'));
    }
}
