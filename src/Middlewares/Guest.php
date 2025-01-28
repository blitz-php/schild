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

/**
 * Middleware specifiant que l'utilisateur ne doit pas etre connecter
 */
class Guest extends BaseMiddleware implements MiddlewareInterface
{
    protected array $fillable = [
        'authenticator',
    ];

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $authenticator = auth($this->arguments['authenticator'] ?? (parametre('auth.default_authenticator') ?? 'session'))->getAuthenticator();

        if (! $authenticator->loggedIn()) {
            return $handler->handle($request);
        }

        return redirect()->to('/');
    }
}
