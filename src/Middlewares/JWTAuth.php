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

use BlitzPHP\Contracts\Http\StatusCode;
use BlitzPHP\Schild\Authentication\Authenticators\JWT;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Authentification par JSON Web Token pour les applications Web.
 */
class JWTAuth implements MiddlewareInterface
{
    /**
     * Obtient le JWT à partir de l'en-tête de la demande et le vérifie.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        /** @var JWT $authenticator */
        $authenticator = auth('jwt')->getAuthenticator();

        $token = $authenticator->getTokenFromRequest($request);

        $result = $authenticator->attempt(['token' => $token]);

        if (! $result->isOK()) {
            return service('response')->json([
                'error' => $result->reason(),
            ], StatusCode::INVALID_TOKEN);
        }

        if (parametre('auth.record_active_date')) {
            $authenticator->recordActiveDate();
        }

        return $handler->handle($request);
    }
}
