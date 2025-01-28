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
use BlitzPHP\Middlewares\BaseMiddleware;
use BlitzPHP\Schild\Authentication\Authenticators\HmacSha256;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Authentification par jeton d'accès personnel pour les applications Web.
 */
class HmacAuth extends BaseMiddleware implements MiddlewareInterface
{
    /**
     * Faites le traitement que ce filtre doit faire.
     * Par défaut, il ne devrait rien retourner lors de l'exécution normale.
     * Cependant, lorsqu'un état anormal est trouvé, il doit retourner une instance de BlitzPHP\Http\Response.
     * Si c'est le cas, l'exécution du script se terminera et cette réponse sera renvoyée au client,
     * permettant des pages d'erreur, des redirectes, etc.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        /** @var HmacSha256 $authenticator */
        $authenticator = auth('hmac')->getAuthenticator();

        $result = $authenticator->attempt([
            'token' => $request->getHeaderLine(parametre('auth-token.authenticator_header.hmac') ?? 'Authorization'),
            'body'  => $request->getBody()->getContents() ?? '',
        ]);

        if (! $result->isOK() || (! empty($this->arguments) && $result->extraInfo()->hmacTokenCant($this->arguments[0]))) {
            return service('response')->json(['message' => lang('Auth.badToken')], StatusCode::UNAUTHORIZED);
        }

        if (parametre('auth.record_active_date')) {
            $authenticator->recordActiveDate();
        }

        // Bloquer les utilisateurs inactifs lorsque l'activation par e-mail est activée
        $user = $authenticator->getUser();
        if ($user !== null && ! $user->isActivated()) {
            $authenticator->logout();

            return service('response')->json(['message' => lang('Auth.activationBlocked')], StatusCode::FORBIDDEN);
        }

        return $handler->handle($request);
    }
}
