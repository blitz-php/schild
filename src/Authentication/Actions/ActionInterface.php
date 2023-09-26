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

namespace BlitzPHP\Schild\Authentication\Actions;

use BlitzPHP\Http\Request;
use BlitzPHP\Http\Response;
use BlitzPHP\Schild\Entities\User;

/**
 * Les actions d'authentification sont des étapes qui peuvent se produire après
 * les principales étapes d'authentification, comme l'enregistrement et la connexion.
 * Il peut s'agir d'étapes d'activation par e-mail, de 2FA par SMS, etc.
 */
interface ActionInterface
{
    /**
     * Affiche l'écran initial à l'utilisateur pour démarrer le flux.
     * Il peut s'agir de demander l'adresse e-mail de l'utilisateur pour réinitialiser un mot de passe ou de demander un numéro de portable pour une 2FA.
     *
     * @return Response|string
     */
    public function show();

    /**
     * Traite le formulaire qui était affiché dans le formulaire précédent.
     *
     * @return Response|string
     */
    public function handle(Request $request);

    /**
     * Cela gère la réponse après que l'utilisateur ait pris des mesures en réponse au flux show/handle.
     * Cela peut être dû au fait de cliquer sur l'action "confirmer mon e-mail" ou à la suite de la saisie d'un code envoyé dans un SMS.
     *
     * @return Response|string
     */
    public function verify(Request $request);

    /**
     * Renvoie le type de chaîne de la classe d'action.
     * Ex., 'email_2fa', 'email_activate'.
     */
    public function getType(): string;

    /**
     * Crée une identité pour l'action de l'utilisateur.
     *
     * @return string secret
     */
    public function createIdentity(User $user): string;
}
