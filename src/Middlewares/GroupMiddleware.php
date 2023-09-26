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

/**
 * Intergiciel d'autorisation de groupe.
 */
class GroupMiddleware extends AbstractAuthMiddleware
{
    /**
     * {@inheritDoc}
     */
    protected function isAuthorized(): bool
    {
        return auth()->user()->inGroup(...$this->arguments);
    }
}
