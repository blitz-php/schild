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

namespace BlitzPHP\Schild\Controllers;

use BlitzPHP\Controllers\ApplicationController;
use BlitzPHP\Schild\Traits\Viewable;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

class BaseController extends ApplicationController
{
    use Viewable;

    /**
     * Nom des tables de l'authentification
     */
    protected array $tables = [];

    /**
     * Configurations de l'authentification
     */
    protected object $config;

    public function initialize(ServerRequestInterface $request, ResponseInterface $response, LoggerInterface $logger): void
    {
        parent::initialize($request, $response, $logger);

        $this->config = (object) config('auth');
        $this->tables = $this->config->tables;
    }
}
