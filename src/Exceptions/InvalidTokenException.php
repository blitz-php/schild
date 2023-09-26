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

use Exception;

class InvalidTokenException extends ValidationException
{
    public const INVALID_TOKEN      = 1;
    public const EXPIRED_TOKEN      = 2;
    public const BEFORE_VALID_TOKEN = 3;

    public static function invalidToken(Exception $e): self
    {
        return new self(lang('Auth.invalidJWT'), self::INVALID_TOKEN, $e);
    }

    public static function expiredToken(Exception $e): self
    {
        return new self(lang('Auth.expiredJWT'), self::EXPIRED_TOKEN, $e);
    }

    public static function beforeValidToken(Exception $e): self
    {
        return new self(lang('Auth.beforeValidJWT'), self::BEFORE_VALID_TOKEN, $e);
    }
}
