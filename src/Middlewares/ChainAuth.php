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

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Vérifie tous les systèmes d'authentification spécifiés dans
 * `Config\auth[authentication_chain]`
 */
class ChainAuth implements MiddlewareInterface
{
    /**
     * Vérifie les authentificateurs dans l'ordre pour voir si l'utilisateur est connecté via  l'un ou l'autre des authentificateurs.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $chain = config('auth.authentication_chain');

        foreach ($chain as $alias) {
            $auth = auth($alias);

            if ($auth->loggedIn()) {
                // Assurez-vous que Auth utilise cet authentificateur
                auth()->setAuthenticator($alias);

                if (config('auth.record_active_date')) {
                    $auth->getAuthenticator()->recordActiveDate();
                }

                return $handler->handle($request);
            }
        }

        return redirect()->route('login');
    }
}
