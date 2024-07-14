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

use BlitzPHP\Http\Redirection;
use BlitzPHP\Http\Request;
use BlitzPHP\Http\ServerRequest;
use BlitzPHP\Schild\Authentication\Authenticators\Session;
use BlitzPHP\Schild\Config\Services;
use BlitzPHP\Schild\Entities\User;
use BlitzPHP\Schild\Entities\UserIdentity;
use BlitzPHP\Schild\Exceptions\RuntimeException;
use BlitzPHP\Schild\Models\UserIdentityModel;
use BlitzPHP\Schild\Traits\Viewable;
use BlitzPHP\Utilities\Date;
use BlitzPHP\Utilities\String\Text;

/**
 * Envoie un e-mail à l'utilisateur avec un code pour vérifier son compte.
 */
class Email2FA implements ActionInterface
{
    use Viewable;

    private string $type = Session::ID_TYPE_EMAIL_2FA;

    /**
     * Affiche le message "Hé, nous allons vous envoyer un numéro sur votre adresse e-mail" à l'utilisateur avec une invite à continuer.
     */
    public function show()
    {
        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        $user = $authenticator->getPendingUser();
        if ($user === null) {
            throw new RuntimeException('Impossible d\'obtenir l\'utilisateur en cours de connexion.');
        }

        $this->createIdentity($user);

        return $this->view(config('auth.views.action_email_2fa'), compact('user'));
    }

    /**
     * Génère le nombre aléatoire, l'enregistre en tant qu'identité temporaire avec l'utilisateur
     * et envoie un e-mail à l'utilisateur avec le code, puis affiche le formulaire pour accepter les 6 chiffres
     *
     * @return RedirectResponse|string
     */
    public function handle(Request $request)
    {
        $email = $request->post('email');

        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        $user = $authenticator->getPendingUser();
        if ($user === null) {
            throw new RuntimeException('Impossible d\'obtenir l\'utilisateur en cours de connexion.');
        }

        if (empty($email) || $email !== $user->email) {
            return redirect()->route('auth-action-show')->withErrors(lang('Auth.invalidEmail'));
        }

        $identity = $this->getIdentity($user);

        if (empty($identity)) {
            return redirect()->route('auth-action-show')->withErrors(lang('Auth.need2FA'));
        }

        $code = $identity->secret;
        $ipAddress = $request->ip();
        $userAgent = (string) $request->userAgent();
        $date      = Date::now()->toDateTimeString();

        // Envoyer à l'utilisateur un e-mail avec le code
        $email = Services::mail()->merge(['debug' => false])
            ->to($user->email)
            ->subject(lang('Auth.email2FASubject'))
            ->view(config('auth.views.action_email_2fa_email'), compact('code', 'user', 'ipAddress', 'userAgent', 'date'));

        if ($email->send() === false) {
            throw new RuntimeException('Impossible d\'envoyer un e-mail à l\'utilisateur: ' . $user->email . "\n" . $email->printDebugger(['headers']));
        }

        // Effacer l'e-mail
        $email->clear();

        return $this->view(config('Auth.views.action_email_2fa_verify'));
    }

    /**
     * Tente de vérifier le code saisi par l'utilisateur.
     *
     * @return Redirection|string
     */
    public function verify(ServerRequest $request)
    {
        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        $postedToken = $request->post('token');

        $user = $authenticator->getPendingUser();
        if ($user === null) {
            throw new RuntimeException('Impossible d\'obtenir l\'utilisateur en cours de connexion.');
        }

        $identity = $this->getIdentity($user);

        // Incompatibilité de jeton ? Qu'ils réessayent...
        if (! $authenticator->checkAction($identity, $postedToken)) {
            Services::session()->flashErrors(lang('Auth.invalid2FAToken'));

            return $this->view(config('auth.views.action_email_2fa_verify'));
        }

        // Obtenez notre URL de redirection de connexion
        return redirect()->to(call_user_func(config('auth.loginRedirect')));
    }

    /**
     * {@inheritDoc}
     */
    public function createIdentity(User $user): string
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        // Supprimer toutes les identités précédentes pour action
        $identityModel->deleteIdentitiesByType($user, $this->type);

        $generator = static fn (): string => Text::random(6);

        return $identityModel->createCodeIdentity(
            $user,
            [
                'type'  => $this->type,
                'name'  => 'login',
                'extra' => lang('Auth.need2FA'),
            ],
            $generator
        );
    }

    /**
     * Renvoie une identité pour l'action de l'utilisateur.
     */
    private function getIdentity(User $user): ?UserIdentity
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        return $identityModel->getIdentityByType(
            $user,
            $this->type
        );
    }

    /**
     * Renvoie le type de chaîne de la classe d'action.
     */
    public function getType(): string
    {
        return $this->type;
    }
}
