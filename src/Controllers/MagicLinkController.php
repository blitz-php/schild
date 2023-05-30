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

use BlitzPHP\Http\Redirection;
use BlitzPHP\Schild\Authentication\Authenticators\Session;
use BlitzPHP\Schild\Config\Registrar;
use BlitzPHP\Schild\Config\Services;
use BlitzPHP\Schild\Models\LoginModel;
use BlitzPHP\Schild\Models\UserIdentityModel;
use BlitzPHP\Schild\Models\UserModel;
use BlitzPHP\Utilities\Date;
use BlitzPHP\Utilities\String\Text;
use BlitzPHP\Validation\Validation;
use BlitzPHP\Validation\Validator;

/**
 * Gère les connexions "Magic Link" - un protocole de connexion sans mot de passe basé sur le courrier électronique.
 * Cela fonctionne un peu comme le ferait la réinitialisation du mot de passe, mais Shield le propose à la place de la réinitialisation du mot de passe.
 * Il peut également être utilisé seul sans stratégie de connexion par e-mail/mot de passe.
 */
class MagicLinkController extends BaseController
{
    /**
     * @var UserModel
     */
    protected $provider;

    public function __construct()
    {
        /** @var class-string<UserModel> $providerClass */
        $providerClass = config('auth.user_provider');

        $this->provider = new $providerClass();
    }

    /**
     * Affiche la vue permettant de saisir leur adresse e-mail afin qu'un e-mail puisse leur être envoyé.
     *
     * @return RedirectResponse|string
     */
    public function loginView()
    {
        if (auth()->loggedIn()) {
            return redirect()->to($this->config->loginRedirect());
        }

        return $this->view($this->config->views['magic-link-login']);
    }

    /**
     * Reçoit l'e-mail de l'utilisateur, crée le hachage vers une identité d'utilisateur et envoie un e-mail à l'adresse e-mail indiquée.
     *
     * @return RedirectResponse|string
     */
    public function loginAction()
    {
        // Valider le format de l'e-mail
        if (($validation = $this->processValidate())->fails()) {
            return redirect()->route('magic-link')->with('errors', $validation->errors()->all());
        }

        // Vérifier si l'utilisateur existe
        $email = $this->request->post('email');
        $user  = $this->provider->findByCredentials(['email' => $email]);

        if ($user === null) {
            return redirect()->route('magic-link')->with('error', lang('Auth.invalidEmail'));
        }

        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        // Supprimer toutes les identités de lien magique précédentes
        $identityModel->deleteIdentitiesByType($user, Session::ID_TYPE_MAGIC_LINK);

        // Générez le code et enregistrez-le en tant qu'identité
        $token = Text::random(20);

        $identityModel->insert([
            'user_id' => $user->id,
            'type'    => Session::ID_TYPE_MAGIC_LINK,
            'secret'  => $token,
            'expires' => Date::now()->addSeconds($this->config->magic_link_lifetime)->format('Y-m-d H:i:s'),
        ]);

        $ipAddress = $this->request->ip();
        $userAgent = (string) $this->request->userAgent();
        $date      = Date::now()->toDateTimeString();

        // Envoyer à l'utilisateur un e-mail avec le code
        $email = emailer()
            ->from(config('email.from.email'), config('email.from.name') ?? '')
            ->to($user->email)
            ->ubject(lang('Auth.magicLinkSubject'))
            ->message($this->view($this->config->views['magic-link-email'], ['token' => $token, 'ipAddress' => $ipAddress, 'userAgent' => $userAgent, 'date' => $date]));

        if ($email->send(false) === false) {
            logger('error', $email->printDebugger(['headers']));

            return redirect()->route('magic-link')->with('error', lang('Auth.unableSendEmailToUser', [$user->email]));
        }

        // Effacer l'e-mail
        $email->clear();

        return $this->displayMessage();
    }

    /**
     * Affichez le message « Ce qui se passe/suivant » à l'utilisateur.
     */
    protected function displayMessage(): string
    {
        return $this->view($this->config->views['magic-link-message']);
    }

    /**
     * Gère la requête GET à partir de l'e-mail
     */
    public function verify(): Redirection
    {
        $token = $this->request->getGet('token');

        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        $identity = $identityModel->getIdentityBySecret(Session::ID_TYPE_MAGIC_LINK, $token);

        $identifier = $token ?? '';

        // Aucun jeton trouvé ?
        if ($identity === null) {
            $this->recordLoginAttempt($identifier, false);

            $credentials = ['magicLinkToken' => $token];
            Services::event()->trigger('failedLogin', $credentials);

            return redirect()->route('magic-link')->with('error', lang('Auth.magicTokenNotFound'));
        }

        // Supprimez l'entrée db afin qu'elle ne puisse plus être utilisée.
        $identityModel->delete($identity->id);

        // Jeton expiré ?
        if (Date::now()->isAfter($identity->expires)) {
            $this->recordLoginAttempt($identifier, false);

            $credentials = ['magicLinkToken' => $token];
            Services::event()->trigger('failedLogin', $credentials);

            return redirect()->route('magic-link')->with('error', lang('Auth.magicLinkExpired'));
        }

        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        // Si une action a été définie
        if ($authenticator->hasAction($identity->user_id)) {
            return redirect()->route('auth-action-show')->with('error', lang('Auth.needActivate'));
        }

        // Connecter l'utilisateur
        $authenticator->loginById($identity->user_id);

        $user = $authenticator->getUser();

        $this->recordLoginAttempt($identifier, true, $user->id);

        // Donnez au développeur un moyen de connaître l'utilisateur connecté via un lien magique.
        Services::session()->setTempdata('magicLogin', true);

        Services::event()->trigger('magicLogin');

        // Obtenez notre URL de redirection de connexion
        return redirect()->to(config(Auth::class)->loginRedirect());
    }

    /**
     * @param int|string|null $userId
     */
    private function recordLoginAttempt(
        string $identifier,
        bool $success,
        $userId = null
    ): void {
        /** @var LoginModel $loginModel */
        $loginModel = model(LoginModel::class);

        $loginModel->recordLoginAttempt(
            Session::ID_TYPE_MAGIC_LINK,
            $identifier,
            $success,
            $this->request->ip(),
            (string) $this->request->userAgent(),
            $userId
        );
    }

    /**
     * Règles qui doivent être utilisées pour la validation.
     */
    protected function processValidate(): Validation
    {
        $rules = [
            'email' => Registrar::validation('email'),
        ];

        return Validator::make($this->request->post(), $rules)->alias([
            'email' => lang('Auth.email'),
        ]);
    }
}