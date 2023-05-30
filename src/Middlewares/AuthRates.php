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
use BlitzPHP\Schild\Config\Services;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Fournit la limitation nominale destinée aux routes AUTH.
 */
class AuthRates implements MiddlewareInterface
{
    /**
     * Destiné à une utilisation sur les pages de formulaire AUTH pour restreindre le nombre de tentatives qui peuvent être générées.
     * Le limiter à 10 tentatives par minute, ce que l'Auth0 utilise.
     *
     * @see https://auth0.com/docs/troubleshoot/customer-support/operational-policies/rate-limit-policy/database-connections-rate-limits
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (! $request instanceof ServerRequest) {
            return $handler->handle($request);
        }

        $throttler = service('throttler');

        // Restreignez une adresse IP à pas plus de 10 demandes par minute
        // sur les pages de forme d'automne (connexion, enregistrement, oublié, etc.).
        if ($throttler->check(md5($request->clientIp()), 10, MINUTE, 1) === false) {
            return Services::response()->withStatus(
                429,
                lang('Auth.throttled', [$throttler->getTokenTime()]) // message
            );
        }

        return $handler->handle($request);
    }
}
