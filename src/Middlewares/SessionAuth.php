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

/**
 * Authentification par e-mail/mot de passe pour les applications Web.
 */
class SessionAuth implements MiddlewareInterface
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
        if (! $request instanceof ServerRequest) {
            return $handler->handle($request);
        }

        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        if ($authenticator->loggedIn()) {
            if (config('auth.record_active_date')) {
                $authenticator->recordActiveDate();
            }

            // Bloquer les utilisateurs inactifs lorsque l'activation par e-mail est activée
            $user = $authenticator->getUser();

            if ($user->isBanned()) {
                $error = $user->getBanMessage() ?? lang('Auth.logOutBannedUser');
                $authenticator->logout();

                return redirect()->to(call_user_func(config('auth.logoutRedirect')))->with('error', $error);
            }

            if ($user !== null && ! $user->isActivated()) {
                $authenticator->logout();

                return redirect()->route('login')->with('error', lang('Auth.activationBlocked'));
            }

            return $handler->handle($request);
        }

        if ($authenticator->isPending()) {
            return redirect()->route('auth-action-show')->with('error', $authenticator->getPendingMessage());
        }

        return redirect()->route('login');
    }
}
