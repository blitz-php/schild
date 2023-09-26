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

use BlitzPHP\Exceptions\HttpException;

class AuthenticationException extends RuntimeException
{
    protected $code = 403;

    /**
     * @param string $alias Authenticator alias
     */
    public static function unknownAuthenticator(string $alias): self
    {
        return new self(lang('Auth.unknownAuthenticator', [$alias]));
    }

    public static function unknownUserProvider(): self
    {
        return new self(lang('Auth.unknownUserProvider'));
    }

    public static function invalidUser(): self
    {
        return new self(lang('Auth.invalidUser'));
    }

    public static function bannedUser(): self
    {
        return new self(lang('Auth.invalidUser'));
    }

    public static function noEntityProvided(): self
    {
        return new self(lang('Auth.noUserEntity'), 500);
    }

    /**
     * Se déclenche lorsqu'aucun minimumPasswordLength n'a été défini dans le fichier de configuration Auth.
     */
    public static function unsetPasswordLength(): self
    {
        return new self(lang('Auth.unsetPasswordLength'), 500);
    }

    /**
     * Lorsque la requête cURL (to Have I Been Pwned) dans PwnedValidator lève une HTTPException,
     * elle est relancée comme celle-ci
     */
    public static function HIBPCurlFail(HttpException $e): self
    {
        return new self($e->getMessage(), $e->getCode(), $e);
    }
}
