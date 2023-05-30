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

use BlitzPHP\Http\ServerRequest;
use BlitzPHP\Schild\Authentication\Authenticators\Session;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class ForcePasswordResetMiddleware implements MiddlewareInterface
{
    /**
     * Vérifie si un utilisateur connecté doit réinitialiser son mot de passe,
     * puis rediriger vers la page appropriée.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (! $request instanceof ServerRequest) {
            return $handler->handle($request);
        }

        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        if ($authenticator->loggedIn() && $authenticator->getUser()->requiresPasswordReset()) {
            return redirect()->to(config('auth.forcePasswordResetRedirect')());
        }

        return $handler->handle($request);
    }
}
