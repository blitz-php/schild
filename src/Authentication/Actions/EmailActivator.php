<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace BlitzPHP\Schild\Authentication\Actions;

use BlitzPHP\Exceptions\PageNotFoundException;
use BlitzPHP\Http\Redirection;
use BlitzPHP\Http\Request;
use BlitzPHP\Schild\Authentication\Authenticators\Session;
use BlitzPHP\Schild\Config\Services;
use BlitzPHP\Schild\Entities\User;
use BlitzPHP\Schild\Entities\UserIdentity;
use BlitzPHP\Schild\Exceptions\LogicException;
use BlitzPHP\Schild\Exceptions\RuntimeException;
use BlitzPHP\Schild\Models\UserIdentityModel;
use BlitzPHP\Schild\Traits\Viewable;
use BlitzPHP\Utilities\Date;
use BlitzPHP\Utilities\String\Text;

class EmailActivator implements ActionInterface
{
    use Viewable;

    private string $type = Session::ID_TYPE_EMAIL_ACTIVATE;

    /**
     * Montre l'écran initial à l'utilisateur lui indiquant qu'un e-mail
     * vient de lui être envoyé avec un lien pour confirmer son adresse e-mail.
     */
    public function show(): string
    {
        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        $user = $authenticator->getPendingUser();
        if ($user === null) {
            throw new RuntimeException('Impossible d\'obtenir l\'utilisateur de connexion en attente.');
        }

        $userEmail = $user->email;
        if ($userEmail === null) {
            throw new LogicException(
                'L\'activation par e-mail nécessite l\'adresse e-mail de l\'utilisateur. user_id: ' . $user->id
            );
        }

        $code = $this->createIdentity($user);

        $request = Services::request();

        $ipAddress = $request->ip();
        $userAgent = (string) $request->userAgent();
        $date      = Date::now()->toDateTimeString();

        // Envoyez le courriel
        $email = emailer()
            ->from(config('email.from.email'), config('email.from.name') ?? '')
            ->to($userEmail)
            ->subject(lang('Auth.emailActivateSubject'))
            ->message($this->view(config('auth.views.action_email_activate_email'), compact('code', 'ipAddress', 'userAgent', 'date')));

        if ($email->send(false) === false) {
            throw new RuntimeException('Impossible d\'envoyer un e-mail à l\'utilisateur: ' . $user->email . "\n" . $email->printDebugger(['headers']));
        }

        // Effacer l'e-mail
        $email->clear();

        // Afficher la page d'informations
        return $this->view(config('auth.views.action_email_activate_show'), compact('user'));
    }

    /**
     * Cette méthode est inutilisée.
     *
     * @return Response|string
     */
    public function handle(Request $request)
    {
        throw new PageNotFoundException();
    }

    /**
     * Vérifie que l'adresse e-mail et le code correspondent à une identité que nous avons pour cet utilisateur.
     *
     * @return Redirection|string
     */
    public function verify(Request $request)
    {
        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        $postedToken = $request->data('token');

        $user = $authenticator->getPendingUser();
        if ($user === null) {
            throw new RuntimeException('Impossible d\'obtenir l\'utilisateur en cours de connexion.');
        }

        $identity = $this->getIdentity($user);

        // Pas de match - laissez-les essayer à nouveau.
        if (! $authenticator->checkAction($identity, $postedToken)) {
            Services::session()->setFlashdata('error', lang('Auth.invalidActivateToken'));

            return $this->view(config('auth.views.action_email_activate_show'));
        }

        $user = $authenticator->getUser();

        // Activez l'utilisateur maintenant
        $user->activate();

        // Success!
        return redirect()->to(config('auth.registerRedirect')())->with('message', lang('Auth.registerSuccess'));
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
                'name'  => 'register',
                'extra' => lang('Auth.needVerification'),
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
