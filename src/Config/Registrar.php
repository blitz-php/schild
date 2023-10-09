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

namespace BlitzPHP\Schild\Config;

use BlitzPHP\Schild\Authentication\Passwords\ValidationRules as PasswordRules;
use BlitzPHP\Schild\Collectors\Auth;
use BlitzPHP\Schild\Middlewares\AuthRates;
use BlitzPHP\Schild\Middlewares\ChainAuth;
use BlitzPHP\Schild\Middlewares\ForcePasswordResetFilter;
use BlitzPHP\Schild\Middlewares\GroupFilter;
use BlitzPHP\Schild\Middlewares\Guest;
use BlitzPHP\Schild\Middlewares\HmacAuth;
use BlitzPHP\Schild\Middlewares\JWTAuth;
use BlitzPHP\Schild\Middlewares\PermissionFilter;
use BlitzPHP\Schild\Middlewares\SessionAuth;
use BlitzPHP\Schild\Middlewares\TokenAuth;

class Registrar
{
    /**
     * Regles de validation
     */
    private static array $validationRules = [
        /**
         * Les règles de validation du nom d'utilisateur
         *
         * @var string[]
         */
        'username' => [
            'required',
            'max:30',
            'min:3',
            'regex:/\A[a-zA-Z0-9\.]+\z/',
        ],
        /**
         * Les règles de validation des emails
         *
         * @var string[]
         */
        'email' => [
            'required',
            'max:254',
            'email',
        ],
    ];

    /**
     * Enregistre les middlewares Schild.
     */
    public static function middlewares(): array
    {
        return [
            'aliases' => [
                'session'     => SessionAuth::class,
                'tokens'      => TokenAuth::class,
                'hmac'        => HmacAuth::class,
                'chain'       => ChainAuth::class,
                'auth-rates'  => AuthRates::class,
                'group'       => GroupFilter::class,
                'permission'  => PermissionFilter::class,
                'force-reset' => ForcePasswordResetFilter::class,
                'jwt'         => JWTAuth::class,
                'guest'       => Guest::class,
            ],
        ];
    }

    public static function validation(?string $key = null): array
    {
        if (! empty($key)) {
            return static::$validationRules[$key] ?? [];
        }

        return [
            'ruleSets' => [
                PasswordRules::class,
            ],
        ];
    }

    public static function toolbar(): array
    {
        return [
            'collectors' => [
                Auth::class,
            ],
        ];
    }

    public static function Generators(): array
    {
        return [
            'views' => [
                'shield:model' => 'BlitzPHP\Schild\Commands\Generators\Views\usermodel.tpl.php',
            ],
        ];
    }

    /**
     * Routes d'authentification
     */
    public static function routes(): array
    {
        return [
            'register' => [
                [
                    'get',
                    'register',
                    'RegisterController::registerView',
                    'register', // Route name
                ],
                [
                    'post',
                    'register',
                    'RegisterController::registerAction',
                ],
            ],
            'login' => [
                [
                    'get',
                    'login',
                    'LoginController::loginView',
                    'login', // Route name
                ],
                [
                    'post',
                    'login',
                    'LoginController::loginAction',
                ],
            ],
            'magic-link' => [
                [
                    'get',
                    'login/magic-link',
                    'MagicLinkController::loginView',
                    'magic-link',        // Route name
                ],
                [
                    'post',
                    'login/magic-link',
                    'MagicLinkController::loginAction',
                ],
                [
                    'get',
                    'login/verify-magic-link',
                    'MagicLinkController::verify',
                    'verify-magic-link', // Route name
                ],
            ],
            'logout' => [
                [
                    'get',
                    'logout',
                    'LoginController::logoutAction',
                    'logout', // Route name
                ],
            ],
            'auth-actions' => [
                [
                    'get',
                    'auth/a/show',
                    'ActionController::show',
                    'auth-action-show', // Route name
                ],
                [
                    'post',
                    'auth/a/handle',
                    'ActionController::handle',
                    'auth-action-handle', // Route name
                ],
                [
                    'post',
                    'auth/a/verify',
                    'ActionController::verify',
                    'auth-action-verify', // Route name
                ],
            ],
        ];
    }
}
