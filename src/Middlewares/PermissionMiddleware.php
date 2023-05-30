<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace BlitzPHP\Schild\Middlewares;

/**
 * Filtre d'autorisation d'autorisation.
 */
class PermissionMiddleware extends AbstractAuthMiddleware
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
}
