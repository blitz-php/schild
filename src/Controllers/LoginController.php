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

use BlitzPHP\Http\Redirection;
use BlitzPHP\Schild\Authentication\Authenticators\Session;
use BlitzPHP\Schild\Validation\ValidationRules;
use BlitzPHP\Validation\Validation;
use BlitzPHP\Validation\Validator;

class LoginController extends BaseController
{
    /**
     * Affiche le formulaire de connexion au site.
     *
     * @return RedirectResponse|string
     */
    public function loginView()
    {
        if (auth()->loggedIn()) {
            return redirect()->to(($this->config->loginRedirect)());
        }

        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        // Si une action a été définie, lancez-la.
        if ($authenticator->hasAction()) {
            return redirect()->route('auth-action-show');
        }

        return $this->view($this->config->views['login']);
    }

    /**
     * Tente de connecter l'utilisateur.
     */
    public function loginAction(): Redirection
    {
        // Validez ici d'abord, car certaines choses,
        // comme le mot de passe, ne peut être validé correctement qu'ici.
        if (($validation = $this->processValidate())->fails()) {
            return redirect()->back()->withInput()->withErrors($validation->errors());
        }

        /** @var array $credentials */
        $credentials             = $this->request->only($this->config->valid_fields);
        $credentials             = array_filter($credentials);
        $credentials['password'] = $this->request->post('password');
        $remember                = $this->request->boolean('remember');

        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        // Tentative de connexion
        $result = $authenticator->remember($remember)->attempt($credentials);
        if (! $result->isOK()) {
            return redirect()->route('login')->withInput()->withErrors($result->reason());
        }

        // Si une action a été définie pour la connexion, démarrez-la.
        if ($authenticator->hasAction()) {
            return redirect()->route('auth-action-show');
        }

        $this->event->emit('schild:login');

        return redirect()->to(($this->config->loginRedirect)());
    }

    /**
     * Règles qui doivent être utilisées pour la validation.
     */
    protected function processValidate(): Validation
    {
        ['rules' => $rules, 'alias' => $alias, 'messages' => $messages] = ValidationRules::login();

        return Validator::make($this->request->post(), $rules)->alias($alias)->messages($messages);
    }

    /**
     * Déconnecte l'utilisateur actuel.
     */
    public function logoutAction(): Redirection
    {
        // Capturez l'URL de redirection de déconnexion avant la déconnexion d'authentification,
        // sinon vous ne pouvez pas vérifier l'utilisateur dans `logoutRedirect()`.
        $url  = ($this->config->logoutRedirect)();
        $user = auth()->user();

        auth()->logout();

        $this->event->emit('schild:logout', $user);

        return redirect()->to($url)->with('message', lang('Auth.successLogout'));
    }
}
