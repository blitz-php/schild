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
use BlitzPHP\Http\ServerRequest;
use BlitzPHP\Schild\Authentication\Authenticators\JWT;
use BlitzPHP\Schild\Config\Services;
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
        if (! $request instanceof ServerRequest) {
            return $handler->handle($request);
        }

        /** @var JWT $authenticator */
        $authenticator = auth('jwt')->getAuthenticator();

        $token = $this->getTokenFromHeader($request);

        $result = $authenticator->attempt(['token' => $token]);

        if (! $result->isOK()) {
            return Services::response()->json([
                'error' => $result->reason(),
            ], StatusCode::UNAUTHORIZED);
        }

        if (config('auth.record_active_date')) {
            $authenticator->recordActiveDate();
        }

        return $handler->handle($request);
    }

    private function getTokenFromHeader(ServerRequestInterface $request): string
    {
        assert($request instanceof ServerRequest);

        $config = (object) config('auth-jwt');

        $tokenHeader = $request->getHeaderLine(
            $config->authenticator_header ?? 'Authorization'
        );

        if (str_starts_with($tokenHeader, 'Bearer')) {
            return trim(substr($tokenHeader, 6));
        }

        return $tokenHeader;
    }
}
