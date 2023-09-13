<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace BlitzPHP\Schild\Config;

use BlitzPHP\Container\Services as BaseServices;
use BlitzPHP\Schild\Auth;
use BlitzPHP\Schild\Authentication\Authentication;
use BlitzPHP\Schild\Authentication\Jwt\JwtManager;
use BlitzPHP\Schild\Authentication\Passwords;

class Services extends BaseServices
{
    /**
     * La classe d'authentification de base
     */
    public static function auth(bool $shared = true): Auth
    {
        if ($shared && isset(static::$instances[Auth::class])) {
            return static::$instances[Auth::class];
        }

        $config = (object) config('auth');

        return static::$instances[Auth::class] = new Auth(new Authentication($config));
    }

    /**
     * Utilitaires de mot de passe.
     */
    public static function passwords(bool $shared = true): Passwords
    {
        if ($shared && isset(static::$instances[Passwords::class])) {
            return static::$instances[Passwords::class];
        }

        return static::$instances[Passwords::class] = new Passwords((object) config('auth'));
    }

    /**
     * JWT Manager.
     */
    public static function jwtManager(bool $shared = true): JwtManager
    {
        if ($shared && isset(static::$instances[JwtManager::class])) {
            return static::$instances[JwtManager::class];
        }

        return static::$instances[JwtManager::class] = new JwtManager();
    }
}
