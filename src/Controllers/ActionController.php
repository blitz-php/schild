<?php

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
use BlitzPHP\Exceptions\PageNotFoundException;
use BlitzPHP\Http\Response;
use BlitzPHP\Schild\Authentication\Actions\ActionInterface;
use BlitzPHP\Schild\Authentication\Authenticators\Session;

/**
 * Un contrôleur générique pour gérer les actions d'authentification.
 */
class ActionController extends ApplicationController
{
    protected ?ActionInterface $action = null;

    /**
     * Perform an initial check if we have a valid action or not.
     *
     * @param string[] $params
     *
     * @return Response|string
     */
    public function _remap(string $method, ...$params)
    {
        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        // Saisissez notre instance d'action si elle a été définie.
        $this->action = $authenticator->getAction();

        if (empty($this->action) || ! $this->action instanceof ActionInterface) {
            throw new PageNotFoundException();
        }

        return $this->{$method}(...$params);
    }

    /**
     * Affiche l'écran initial à l'utilisateur pour démarrer le flux.
     * Il peut s'agir de demander l'adresse e-mail de l'utilisateur pour réinitialiser un mot de passe ou de demander un numéro de portable pour une 2FA.
     *
     * @return Response|string
     */
    public function show()
    {
        return $this->action->show();
    }

    /**
     * Traite le formulaire qui était affiché dans le formulaire précédent.
     *
     * @return Response|string
     */
    public function handle()
    {
        return $this->action->handle($this->request);
    }

    /**
     * Cela gère la réponse après que l'utilisateur ait pris des mesures en réponse au flux show/handle.
     * Cela peut être dû au fait de cliquer sur l'action "confirmer mon e-mail" ou à la suite de la saisie d'un code envoyé dans un SMS.
     *
     * @return Response|string
     */
    public function verify()
    {
        return $this->action->verify($this->request);
    }
}
