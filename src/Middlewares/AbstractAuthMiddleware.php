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
            if (uri_string() !== route('login')) {
                session()->setTempdata('beforeLoginUrl', $current_url = current_url(), 300);
                redirect()->setIntendedUrl($current_url);
            }

            return redirect()->route('login');
        }

        if ($this->isAuthorized()) {
            return $handler->handle($request);
        }

        // Sinon, nous les enverrons simplement à la page specifier pour le cas echeant.
        return $this->redirectToDeniedUrl();
    }

    /**
     * Garantit que l'utilisateur est connecté et membre d'un ou plusieurs groupes comme spécifié dans le filtre.
     */
    abstract protected function isAuthorized(): bool;

    /**
     * Renvoie la réponse de redirection lorsque l'utilisateur ne dispose pas d'autorisations d'accès.
     */
    abstract protected function redirectToDeniedUrl(): Redirection;
}
