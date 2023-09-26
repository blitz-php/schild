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
use BlitzPHP\Schild\Authentication\Passwords;
use BlitzPHP\Schild\Config\Registrar;
use BlitzPHP\Schild\Config\Services;
use BlitzPHP\Schild\Entities\User;
use BlitzPHP\Schild\Models\UserModel;
use BlitzPHP\Validation\Rule;
use BlitzPHP\Validation\Validation;
use BlitzPHP\Validation\Validator;
use BlitzPHP\View\View;
use Exception;

/**
 * Poignées affichant le formulaire d'inscription,
 * et la gestion du flux d'enregistrement réel.
 */
class RegisterController extends BaseController
{
    /**
     * Affiche le formulaire d'inscription.
     *
     * @return Redirection|View
     */
    public function registerView()
    {
        if (auth()->loggedIn()) {
            return redirect()->to(($this->config->registerRedirect)());
        }

        // Vérifier si l'inscription est autorisée
        if (! $this->config->allow_registration) {
            return redirect()->back()->withInput()->withErrors(lang('Auth.registerDisabled'));
        }

        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        // Si une action a été définie, lancez-la.
        if ($authenticator->hasAction()) {
            return redirect()->route('auth-action-show');
        }

        return $this->view($this->config->views['register']);
    }

    /**
     * Tente d'enregistrer l'utilisateur.
     */
    public function registerAction(): Redirection
    {
        if (auth()->loggedIn()) {
            return redirect()->to(($this->config->registerRedirect)());
        }

        // Vérifier si l'inscription est autorisée
        if (! $this->config->allow_registration) {
            return redirect()->back()->withInput()->withErrors(lang('Auth.registerDisabled'));
        }

        $users = $this->getUserProvider();

        // Validez ici d'abord, car certaines choses,
        // comme le mot de passe, ne peut être validé correctement qu'ici.
        if (($validation = $this->processValidate())->fails()) {
            return redirect()->back()->withInput()->withErrors($validation->errors()->all());
        }

        // Enregistrer l'utilisateur
        $user = $this->getUserEntity();
        $user->fill($this->request->only('username'));

        // Solution de contournement pour l'inscription/la connexion par e-mail uniquement
        if ($user->username === null) {
            $user->username = null;
        }

        try {
            $user->setEmail($this->request->post('email'));
            $user->setPassword($this->request->post('password'));
            $user->save();
            $user->saveEmailIdentity();

            // Ajouter au groupe par défaut
            $users->addToDefaultGroup($user);
        } catch (Exception $e) {
            return redirect()->back()->withInput()->with('errors', $e->getMessage());
        }

        Services::event()->trigger('register', $user);

        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        $authenticator->startLogin($user);

        // Si une action a été définie pour l'enregistrement, démarrez-la.
        $hasAction = $authenticator->startUpAction('register', $user);
        if ($hasAction) {
            return redirect()->to('auth/a/show');
        }

        // Activer l'utilisateur
        $user->activate();

        $authenticator->completeLogin($user);

        // Success!
        return redirect()->to(($this->config->registerRedirect)())
            ->with('message', lang('Auth.registerSuccess'));
    }

    /**
     * Renvoie le fournisseur de l'utilisateur
     */
    protected function getUserProvider(): UserModel
    {
        $provider = model($this->config->user_provider);

        assert($provider instanceof UserModel, 'Config Auth.user_provider n\'est pas un UserProvider valide.');

        return $provider;
    }

    /**
     * Renvoie la classe Entity qui doit être utilisée
     */
    protected function getUserEntity(): User
    {
        return new User();
    }

    /**
     * Règles qui doivent être utilisées pour la validation.
     */
    protected function processValidate(): Validation
    {
        $config = config('validation');
        $rules  = $config['register'] ?? [
            'username' => array_merge(
                Registrar::validation('username'),
                [Rule::unique($this->tables['users'], 'username')]
            ),
            'email' => array_merge(
                Registrar::validation('email'),
                [Rule::unique($this->tables['identities'], 'secret')]
            ),
            'password' => [
                'required', 'confirmed', Passwords::getMaxLengthRule(), Rule::password()->strong(),
            ],
        ];

        return Validator::make($this->request->post(), $rules)->alias([
            'username'              => lang('Auth.username'),
            'email'                 => lang('Auth.email'),
            'password'              => lang('Auth.password'),
            'password_confirmation' => lang('Auth.passwordConfirm'),
        ]);
    }
}
