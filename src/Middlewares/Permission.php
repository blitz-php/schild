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

namespace BlitzPHP\Schild\Middlewares;

use BlitzPHP\Http\Redirection;

/**
 * Middleware d'autorisation d'autorisation.
 */
class Permission extends AbstractAuthMiddleware
{
    /**
     * {@inheritDoc}
     */
    protected function isAuthorized(): bool
    {
        foreach ($this->arguments as $permission) {
            if (auth()->user()->can($permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Si l'utilisateur ne dispose pas de l'autorisation, redirigez vers l'URL configurée avec un message d'erreur.
     */
    protected function redirectToDeniedUrl(): Redirection
    {
        return redirect()->to(call_user_func(config('auth.permissionDeniedRedirect')))->withErrors(lang('Auth.notEnoughPrivilege'));
    }
}
