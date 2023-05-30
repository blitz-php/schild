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

        $chain = config('auth.authentication_chain');

        foreach ($chain as $alias) {
            if (auth($alias)->loggedIn()) {
                // Assurez-vous que Auth utilise cet authentificateur
                auth()->setAuthenticator($alias);

                return $handler->handle($request);
            }
        }

        return redirect()->route('login');
    }
}
