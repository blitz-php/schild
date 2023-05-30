<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

return [
    'routes' => [
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
    ],
];
