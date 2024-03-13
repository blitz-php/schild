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

use BlitzPHP\Schild\Authentication\Authenticators\Session;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class ForcePasswordReset implements MiddlewareInterface
{
    /**
     * Vérifie si un utilisateur connecté doit réinitialiser son mot de passe,
     * puis rediriger vers la page appropriée.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        if ($authenticator->loggedIn() && $authenticator->getUser()->requiresPasswordReset()) {
            return redirect()->to(config('auth.force_password_reset_redirect')());
        }

        return $handler->handle($request);
    }
}
