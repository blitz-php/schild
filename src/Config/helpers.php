<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

use BlitzPHP\Schild\Auth;
use BlitzPHP\Schild\Config\Services;

if (! function_exists('auth')) {
    /**
     * Fournit un accès pratique à la classe Auth principale.
     *
     * @param string|null $alias Authenticator alias
     */
    function auth(?string $alias = null): Auth
    {
        return Services::auth()->setAuthenticator($alias);
    }
}

if (! function_exists('user_id')) {
    /**
     * Renvoie l'ID de l'utilisateur actuellement connecté.
     * Remarque : Pour \BlitzPHP\Schild\Entities\User, cela renverra toujours un int.
     *
     * @return int|string|null
     */
    function user_id()
    {
        return Services::auth()->id();
    }
}
