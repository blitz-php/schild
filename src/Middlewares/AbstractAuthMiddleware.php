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

use BlitzPHP\Middlewares\BaseMiddleware;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

abstract class AbstractAuthMiddleware extends BaseMiddleware implements MiddlewareInterface
{
    /**
     * {@inheritDoc}
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (! auth()->loggedIn()) {
            // Définir l'URL d'entrée pour rediriger un utilisateur après une connexion réussie
            if (! url_is('login')) {
                session()->setTempdata('beforeLoginUrl', current_url(), 300);
            }

            return redirect()->route('login');
        }

        if ($this->isAuthorized()) {
            return $handler->handle($request);
        }

        // Sinon, nous les enverrons simplement à la page d'accueil.
        return redirect()->to('/')->withErrors(lang('Auth.notEnoughPrivilege'));
    }

    /**
     * Garantit que l'utilisateur est connecté et membre d'un ou plusieurs groupes comme spécifié dans le filtre.
     */
    abstract protected function isAuthorized(): bool;
}
