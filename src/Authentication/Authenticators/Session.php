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

namespace BlitzPHP\Schild\Authentication\Authenticators;

use BlitzPHP\Http\Request;
use BlitzPHP\Http\Response;
use BlitzPHP\Schild\Authentication\Actions\ActionInterface;
use BlitzPHP\Schild\Authentication\AuthenticatorInterface;
use BlitzPHP\Schild\Authentication\Passwords;
use BlitzPHP\Schild\Entities\User;
use BlitzPHP\Schild\Entities\UserIdentity;
use BlitzPHP\Schild\Exceptions\InvalidArgumentException;
use BlitzPHP\Schild\Exceptions\LogicException;
use BlitzPHP\Schild\Exceptions\SecurityException;
use BlitzPHP\Schild\Models\LoginModel;
use BlitzPHP\Schild\Models\RememberModel;
use BlitzPHP\Schild\Models\UserIdentityModel;
use BlitzPHP\Schild\Models\UserModel;
use BlitzPHP\Schild\Result;
use BlitzPHP\Session\Cookie\Cookie;
use BlitzPHP\Utilities\Date;
use stdClass;

class Session extends BaseAuthenticator implements AuthenticatorInterface
{
    /**
     * @var string Type d'identification spécial.
     *             `username` est stocké dans la table `users`, donc pas d'enregistrement `auth_identities`.
     */
    public const ID_TYPE_USERNAME = 'username';

    // Types d'identité
    public const ID_TYPE_EMAIL_PASSWORD = 'email_password';
    public const ID_TYPE_MAGIC_LINK     = 'magic-link';
    public const ID_TYPE_EMAIL_2FA      = 'email_2fa';
    public const ID_TYPE_EMAIL_ACTIVATE = 'email_activate';

    // Etats utilisateurs
    private const STATE_UNKNOWN   = 0; // Pas encore vérifié.
    private const STATE_ANONYMOUS = 1;
    private const STATE_PENDING   = 2; // 2FA ou activation requise.
    private const STATE_LOGGED_IN = 3;

    /**
     * L'état d'authentification de l'utilisateur
     */
    private int $userState = self::STATE_UNKNOWN;

    /**
     * Faut-il se rappeler de l'utilisateur ?
     */
    protected bool $shouldRemember = false;

    protected LoginModel $loginModel;
    protected RememberModel $rememberModel;
    protected UserIdentityModel $userIdentityModel;

    public function __construct(protected UserModel $provider)
    {
        $this->loginModel        = model(LoginModel::class);
        $this->rememberModel     = model(RememberModel::class);
        $this->userIdentityModel = model(UserIdentityModel::class);

        // $this->checkSecurityConfig();
    }

    /**
     * Vérifie la configuration moins sécurisée.
     */
    private function checkSecurityConfig(): void
    {
        $securityConfig = (object) config('security');

        if ($securityConfig->csrf_protection === 'cookie') {
            throw new SecurityException(
                'Config\Security::$csrfProtection is set to \'cookie\'.'
                . ' Same-site attackers may bypass the CSRF protection.'
                . ' Please set it to \'session\'.'
            );
        }
    }

    /**
     * Définit le drapeau $shouldRemember
     */
    public function remember(bool $shouldRemember = true): self
    {
        $this->shouldRemember = $shouldRemember;

        return $this;
    }

    /**
     * Tente d'authentifier un utilisateur avec les $credentials donnés.
     * Connecte l'utilisateur avec une vérification réussie.
     *
     * @phpstan-param array{email?: string, username?: string, password?: string} $credentials
     */
    public function attempt(array $credentials): Result
    {
        /** @var Request $request */
        $request = service('request');

        $ipAddress = $request->ip();
        $userAgent = (string) $request->userAgent();

        $result = $this->check($credentials);

        // Non-concordance des informations d'identification.
        if (! $result->isOK()) {
            // Enregistrez toujours une tentative de connexion, qu'elle soit réussie ou non.
            $this->recordLoginAttempt($credentials, false, $ipAddress, $userAgent);

            $this->user = null;

            // Déclenchez un événement en cas d'échec afin que les développeurs aient la possibilité de leur faire savoir que quelqu'un a tenté de se connecter à leur compte
            unset($credentials['password']);
            service('event')->emit('schild:failedLogin', $credentials);

            return $result;
        }

        /** @var User $user */
        $user = $result->extraInfo();

        if ($user->isBanned()) {
            $this->user = null;

            return new Result([
                'success' => false,
                'reason'  => $user->getBanMessage() ?? lang('Auth.bannedUser'),
            ]);
        }

        $this->user = $user;

        // Mettez à jour la date de dernière utilisation de l'utilisateur sur son identité de mot de passe.
        $user->touchIdentity($user->getEmailIdentity());

        // Définir l'action d'authentification à partir de la base de données.
        $this->setAuthAction();

        // Si une action a été définie pour la connexion, démarrez-la.
        $this->startUpAction('login', $user);

        $this->startLogin($user);

        $this->recordLoginAttempt($credentials, true, $ipAddress, $userAgent, $user->id);

        $this->issueRememberMeToken();

        if (! $this->hasAction()) {
            $this->completeLogin($user);
        }

        return $result;
    }

    /**
     * Si une action a été définie, lancez-la.
     *
     * @param string $type 'register', 'login'
     *
     * @return bool Si l'action a été définie ou non.
     */
    public function startUpAction(string $type, User $user): bool
    {
        if (null === $actionClass = config('auth.actions.' . $type)) {
            return false;
        }

        /** @var ActionInterface $action */
        $action = service('container')->make($actionClass); // @phpstan-ignore-line

        // Créer une identité pour l'action.
        $action->createIdentity($user);

        $this->setAuthAction();

        return true;
    }

    /**
     * Renvoie un objet d'action à partir des données de session
     */
    public function getAction(): ?ActionInterface
    {
        /** @var class-string<ActionInterface>|null $actionClass */
        $actionClass = $this->getSessionUserKey('auth_action');

        if ($actionClass === null) {
            return null;
        }

        return service('container')->make($actionClass); // @phpstan-ignore-line
    }

    /**
     * Vérifier le token dans l'action
     */
    public function checkAction(UserIdentity $identity, string $token): bool
    {
        $user = ($this->loggedIn() || $this->isPending()) ? $this->user : null;

        if ($user === null) {
            throw new LogicException('Impossible d\'obtenir l\'utilisateur.');
        }

        if ($token === '' || $token !== $identity->secret) {
            return false;
        }

        // En cas de succès - supprimer l'identité
        $this->userIdentityModel->deleteIdentitiesByType($user, $identity->type);

        // Nettoyer notre session
        $this->removeSessionUserKey('auth_action');
        $this->removeSessionUserKey('auth_action_message');

        $this->user = $user;

        $this->completeLogin($user);

        return true;
    }

    /**
     * Termine le processus de connexion
     */
    public function completeLogin(User $user): void
    {
        $this->userState = self::STATE_LOGGED_IN;

        // une connexion réussie
        service('event')->emit('schild:login', $user);
    }

    /**
     * @param int|string|null $userId
     */
    private function recordLoginAttempt(
        array $credentials,
        bool $success,
        string $ipAddress,
        string $userAgent,
        $userId = null
    ): void {
        // Determine le type d'identificateur que nous devons utiliser (email ou username).
        // Les champs standard seraient l'e-mail, le nom d'utilisateur, mais n'importe quelle colonne dans config('auth.valid_fields') peut être utilisée.
        $field = array_intersect(config('auth.valid_fields') ?? [], array_keys($credentials));

        if (count($field) !== 1) {
            throw new InvalidArgumentException('Informations d\'identification non valides transmises à recordLoginAttempt.');
        }

        $field = array_pop($field);

        if (! in_array($field, ['email', 'username'], true)) {
            $idType = $field;
        } else {
            $idType = (! isset($credentials['email']) && isset($credentials['username']))
                ? self::ID_TYPE_USERNAME
                : self::ID_TYPE_EMAIL_PASSWORD;
        }

        $this->loginModel->recordLoginAttempt(
            $idType,
            $credentials[$field],
            $success,
            $ipAddress,
            $userAgent,
            $userId
        );
    }

    /**
     * Vérifie les $credentials d'un utilisateur pour voir s'ils correspondent à un utilisateur existant.
     *
     * @phpstan-param array{email?: string, username?: string, password?: string} $credentials
     */
    public function check(array $credentials): Result
    {
        // Impossible de valider sans mot de passe.
        if (empty($credentials['password']) || count($credentials) < 2) {
            return new Result([
                'success' => false,
                'reason'  => lang('Auth.badAttempt'),
            ]);
        }

        // Supprimez le mot de passe des informations d'identification afin que nous puissions vérifier la postface.
        $givenPassword = $credentials['password'];
        unset($credentials['password']);

        // Trouver l'utilisateur existant
        $user = $this->provider->findByCredentials($credentials);

        if ($user === null) {
            return new Result([
                'success' => false,
                'reason'  => lang('Auth.badAttempt'),
            ]);
        }

        /** @var Passwords $passwords */
        $passwords = service('passwords');

        // Vérifiez si le mot de passe doit être ressassé.
        // Cela serait dû à la modification de l'algorithme de hachage ou du coût de hachage depuis la dernière fois qu'un utilisateur s'est connecté.
        if ($passwords->needsRehash($user->password_hash)) {
            $user->password_hash = $passwords->hash($givenPassword);
            $user->getIdentity(static::ID_TYPE_EMAIL_PASSWORD)->forceFill([
                'secret2' => $user->password_hash,
            ])->save();
        }

        // Maintenant, essayez de faire correspondre les mots de passe.
        if (! $passwords->verify($givenPassword, $user->password_hash)) {
            return new Result([
                'success' => false,
                'reason'  => lang('Auth.invalidPassword'),
            ]);
        }

        return new Result([
            'success'   => true,
            'extraInfo' => $user,
        ]);
    }

    /**
     * Vérifie si l'utilisateur est actuellement connecté.
     */
    public function loggedIn(): bool
    {
        $this->checkUserState();

        return $this->userState === self::STATE_LOGGED_IN;
    }

    /**
     * Vérifie l'état de l'utilisateur
     */
    private function checkUserState(): void
    {
        if ($this->userState !== self::STATE_UNKNOWN) {
            // Vérifié déjà.
            return;
        }

        /** @var int|string|null $userId */
        $userId = $this->getSessionUserKey('id');

        // A des informations sur l'utilisateur dans la session.
        if ($userId !== null) {
            $this->user = $this->provider->findById($userId);

            if ($this->user === null) {
                // L'utilisateur est supprimé.
                $this->userState = self::STATE_ANONYMOUS;

                // Supprimer les informations utilisateur dans la session.
                $this->removeSessionUserInfo();

                return;
            }

            // Si vous avez `auth_action`, il est en attente.
            if ($this->getSessionUserKey('auth_action')) {
                $this->userState = self::STATE_PENDING;

                return;
            }

            $this->userState = self::STATE_LOGGED_IN;

            return;
        }

        // Aucune information utilisateur dans la session.
        // Vérifie le jeton souvenir de moi.
        if (config('auth.session.allow_remembering')) {
            if ($this->checkRememberMe()) {
                $this->setAuthAction();
            }

            return;
        }

        $this->userState = self::STATE_ANONYMOUS;
    }

    /**
     * A une action d'authentification ?
     *
     * @param int|string|null $userId Fournir un identifiant utilisateur uniquement lors de la vérification d'un utilisateur non connecté
     *                                (e.g. utilisateur qui essaie de se connecter au lien magique)
     */
    public function hasAction($userId = null): bool
    {
        // Vérifier l'utilisateur non connecté
        if ($userId !== null) {
            $user = $this->provider->findById($userId);

            // Vérifier les identités pour les actions
            if ($this->getIdentitiesForAction($user) !== []) {
                // Rendre l'état de connexion en attente
                $this->user = $user;
                $this->setSessionUserKey('id', $user->id);
                $this->setAuthAction();

                return true;
            }
        }

        // Vérifier la session
        if ($this->getSessionUserKey('auth_action')) {
            return true;
        }

        // Vérifier la base de données
        return $this->setAuthAction();
    }

    /**
     * Recherche une identité pour les actions à partir de la base de données
     * et définit l'identité trouvée en premier dans la session.
     *
     * @return bool true si l'action est définie dans la session.
     */
    private function setAuthAction(): bool
    {
        if ($this->user === null) {
            return false;
        }

        $authActions = config('auth.actions');

        foreach ($authActions as $actionClass) {
            if ($actionClass === null) {
                continue;
            }

            /** @var ActionInterface $action */
            $action = service('container')->make($actionClass);  // @phpstan-ignore-line

            $identity = $this->userIdentityModel->getIdentityByType($this->user, $action->getType());

            if ($identity) {
                $this->userState = self::STATE_PENDING;

                $this->setSessionUserKey('auth_action', $actionClass);
                $this->setSessionUserKey('auth_action_message', $identity->extra);

                return true;
            }
        }

        return false;
    }

    /**
     * Obtient des identités pour l'action
     *
     * @return UserIdentity[]
     */
    private function getIdentitiesForAction(User $user): array
    {
        return $this->userIdentityModel->getIdentitiesByTypes(
            $user,
            $this->getActionTypes()
        );
    }

    /**
     * @return string[]
     */
    private function getActionTypes(): array
    {
        $actions = config('auth.actions');
        $types   = [];

        foreach ($actions as $actionClass) {
            if ($actionClass === null) {
                continue;
            }

            /** @var ActionInterface $action */
            $action  = service('container')->make($actionClass);  // @phpstan-ignore-line
            $types[] = $action->getType();
        }

        return $types;
    }

    /**
     * Vérifie si l'utilisateur est actuellement dans l'état de connexion en attente.
     * Ils doivent effectuer une action d'authentification.
     */
    public function isPending(): bool
    {
        $this->checkUserState();

        return $this->userState === self::STATE_PENDING;
    }

    /**
     * Vérifie si le visiteur est anonyme. L'identifiant de l'utilisateur est inconnu.
     * Ils ne sont pas connectés, ne sont pas en attente de connexion.
     */
    public function isAnonymous(): bool
    {
        $this->checkUserState();

        return $this->userState === self::STATE_ANONYMOUS;
    }

    /**
     * Renvoie le message d'erreur de connexion en attente
     */
    public function getPendingMessage(): string
    {
        $this->checkUserState();

        return $this->getSessionUserKey('auth_action_message') ?? '';
    }

    /**
     * @return bool true si connecté avec le jeton Remember-me.
     */
    private function checkRememberMe(): bool
    {
        // Obtenez un token remember-token.
        $remember = $this->getRememberMeToken();
        if ($remember === null) {
            $this->userState = self::STATE_ANONYMOUS;

            return false;
        }

        // Verifiez le token remember-token.
        $token = $this->checkRememberMeToken($remember);
        if ($token === false) {
            $this->userState = self::STATE_ANONYMOUS;

            return false;
        }

        $user = $this->provider->findById($token->user_id);

        if ($user === null) {
            // L'utilisateur est supprimé.
            $this->userState = self::STATE_ANONYMOUS;

            // Supprimer le cookie remember-me.
            $this->removeRememberCookie();

            return false;
        }

        $this->startLogin($user);

        $this->refreshRememberMeToken($token);

        $this->userState = self::STATE_LOGGED_IN;

        return true;
    }

    private function getRememberMeToken(): ?string
    {
        $cookieName = config('cookie.prefix') . config('auth.session.remember_cookie_name');

        return service('request')->getCookie($cookieName);
    }

    /**
     * @return false|stdClass
     */
    private function checkRememberMeToken(string $remember)
    {
        [$selector, $validator] = explode(':', $remember);

        $hashedValidator = hash('sha256', $validator);

        $token = $this->rememberModel->getRememberToken($selector);

        if ($token === null) {
            return false;
        }

        if (hash_equals($token->hashedValidator, $hashedValidator) === false) {
            return false;
        }

        return $token;
    }

    /**
     * Démarre le processus de connexion
     */
    public function startLogin(User $user): void
    {
        /** @var int|string|null $userId */
        $userId = $this->getSessionUserKey('id');

        // Vérifiez si vous êtes déjà connecté.
        if ($userId !== null) {
            throw new LogicException(
                'L\'utilisateur a des informations sur l\'utilisateur dans la session, donc déjà connecté ou en attente de connexion.'
                . ' Si un utilisateur connecté se reconnecte avec un autre compte, les données de session de l\'utilisateur précédent seront utilisées comme nouvel utilisateur.'
                . ' Corrigez votre code pour empêcher les utilisateurs de se connecter sans se déconnecter ou supprimer les données de session.'
                . ' user_id: ' . $userId
            );
        }

        $this->user = $user;

        // L'utilisateur a des informations sur l'utilisateur dans la session, donc déjà connecté ou en attente de connexion.
        if (! on_test()) {
            session()->regenerate(true);

            // Régénérer le jeton CSRF même si `security.regenerate = false`.
            // Services::security()->generateHash();
        }

        // Faire savoir à la session que nous sommes connectés
        $this->setSessionUserKey('id', $user->id);

        // Une fois connecté, assurez-vous que les en-têtes de contrôle du cache sont en place
        service('set', Response::class, service('response')->noCache());
    }

    /**
     * Obtient les informations utilisateur en session
     */
    protected function getSessionUserInfo(): array
    {
        return session()->get(config('auth.session.field')) ?? [];
    }

    /**
     * Supprime les informations utilisateur dans la session
     */
    protected function removeSessionUserInfo(): void
    {
        session()->remove(config('auth.session.field'));
    }

    /**
     * Obtient la valeur de la clé dans les informations sur l'utilisateur de la session
     *
     * @return int|string|null
     */
    protected function getSessionUserKey(string $key)
    {
        $sessionUserInfo = $this->getSessionUserInfo();

        return $sessionUserInfo[$key] ?? null;
    }

    /**
     * Définit la valeur de clé dans Session User Info
     *
     * @param int|string|null $value
     */
    protected function setSessionUserKey(string $key, $value): void
    {
        $sessionUserInfo       = $this->getSessionUserInfo();
        $sessionUserInfo[$key] = $value;

        session()->set(config('auth.session.field'), $sessionUserInfo);
    }

    /**
     * Supprimer la valeur de la clé dans les informations sur l'utilisateur de la session
     */
    protected function removeSessionUserKey(string $key): void
    {
        $sessionUserInfo = $this->getSessionUserInfo();
        unset($sessionUserInfo[$key]);

        session()->set(config('auth.session.field'), $sessionUserInfo);
    }

    /**
     * Connecte l'utilisateur donné.
     */
    public function login(User $user): void
    {
        $this->user = $user;

        // Vérifier les identités pour les actions
        if ($this->getIdentitiesForAction($user) !== []) {
            throw new LogicException(
                'L\'utilisateur a des identités pour l\'action, il ne peut donc pas terminer la connexion.'
                . ' Si vous souhaitez commencer à vous connecter avec l\'action auth, utilisez plutôt startLogin().'
                . ' Ou supprimez les identités pour action dans la base de données.'
                . ' user_id: ' . $user->id
            );
        }
        // Vérifiez auth_action dans la session
        if ($this->getSessionUserKey('auth_action')) {
            throw new LogicException(
                'L\'utilisateur a une action d\'authentification dans la session, il ne peut donc pas terminer la connexion.'
                . ' Si vous souhaitez commencer à vous connecter avec l\'action auth, utilisez plutôt startLogin().'
                . ' Ou supprimez `auth_action` et `auth_action_message` dans les données de session.'
                . ' user_id: ' . $user->id
            );
        }

        $this->startLogin($user);

        $this->issueRememberMeToken();

        $this->completeLogin($user);
    }

    private function issueRememberMeToken(): void
    {
        if ($this->shouldRemember && config('auth.session.allow_remembering')) {
            $this->rememberUser($this->user);

            // Réinitialisez pour ne pas gâcher les futurs appels.
            $this->shouldRemember = false;
        } elseif ($this->getRememberMeToken()) {
            $this->removeRememberCookie();

            // @TODO supprimer l'enregistrement de jeton.
        }

        // Nous donnerons 20 % de chances d'avoir besoin de faire une purge puisque nous n'avons pas besoin de purger CELA souvent, c'est juste un problème de maintenance.
        // Pour empêcher la table de devenir incontrôlable.
        if (random_int(1, 100) <= 20) {
            $this->rememberModel->purgeOldRememberTokens();
        }
    }

    private function removeRememberCookie(): void
    {
        // Supprimer le cookie remember-me
        service('set', Response::class, service('response')->withoutCookie(
            config('auth.session.remember_cookie_name'),
            config('cookie.path'),
            config('cookie.domain'),
            // config('cookie.prefix')
        ));
    }

    /**
     * Déconnecte l'utilisateur actuel.
     */
    public function logout(): void
    {
        $this->checkUserState();

        if ($this->user === null) {
            return;
        }

        // Détruisez les données de session - mais assurez-vous qu'une session est toujours disponible pour les messages flash, etc.
        $session     = session();
        $sessionData = $session->get();
        if (isset($sessionData)) {
            foreach (array_keys($sessionData) as $key) {
                $session->remove($key);
            }
        }

        // Régénérez l'ID de session pour une touche de sécurité supplémentaire.
        $session->regenerate(true);

        // Prenez soin de toutes les fonctionnalités de rappel de moi
        $this->rememberModel->purgeRememberTokens($this->user);

        // Déclencher un événement de déconnexion
        service('event')->emit('schild:logout', $this->user);

        $this->user      = null;
        $this->userState = self::STATE_ANONYMOUS;
    }

    /**
     * Supprime tous les jetons souvenir de moi, le cas échéant.
     */
    public function forget(?User $user = null): void
    {
        $user ??= $this->user;
        if ($user === null) {
            return;
        }

        $this->rememberModel->purgeRememberTokens($user);
    }

    /**
     * {@inheritDoc}
     */
    public function getUser(): ?User
    {
        $this->checkUserState();

        if ($this->userState === self::STATE_LOGGED_IN) {
            return $this->user;
        }

        return null;
    }

    /**
     * Renvoie l'utilisateur de connexion en attente actuel.
     */
    public function getPendingUser(): ?User
    {
        $this->checkUserState();

        if ($this->userState === self::STATE_PENDING) {
            return $this->user;
        }

        return null;
    }

    /**
     * Génère un token remember-me sécurisé contre les attaques temporelles et stocke les informations nécessaires dans la base de données et un cookie.
     *
     * @see https://paragonie.com/blog/2015/04/secure-authentication-php-with-long-term-persistence
     */
    protected function rememberUser(User $user): void
    {
        $selector  = bin2hex(random_bytes(12));
        $validator = bin2hex(random_bytes(20));
        $expires   = $this->calcExpires();

        $rawToken = $selector . ':' . $validator;

        // Stockez-le dans la base de données.
        $this->rememberModel->rememberUser(
            $user,
            $selector,
            $this->hashValidator($validator),
            $expires
        );

        $this->setRememberMeCookie($rawToken);
    }

    private function calcExpires(): string
    {
        $timestamp = Date::now()->getTimestamp() + config('auth.session.remember_length');

        return Date::createFromTimestamp($timestamp)->format('Y-m-d H:i:s');
    }

    private function setRememberMeCookie(string $rawToken): void
    {
        // Enregistrez-le dans le navigateur de l'utilisateur dans un cookie.
        // Créer le cookie
        service('set', Response::class, service('response')->withCookie(
            Cookie::create(config('auth.session.remember_cookie_name'), $rawToken, [
                'expires'  => config('auth.session.remember_length'),
                'path'     => config('cookie.path'),
                'domain'   => config('cookie.domain'),
                'secure'   => config('cookie.secure'),
                'httponly' => true,
            ])
        ));
    }

    /**
     * Hash le validateur du remember-me
     */
    private function hashValidator(string $validator): string
    {
        return hash('sha256', $validator);
    }

    private function refreshRememberMeToken(stdClass $token): void
    {
        // Mise a jour du validateur
        $validator = bin2hex(random_bytes(20));

        $token->hashedValidator = $this->hashValidator($validator);
        $token->expires         = $this->calcExpires();

        $this->rememberModel->updateRememberValidator($token);

        $rawToken = $token->selector . ':' . $validator;

        $this->setRememberMeCookie($rawToken);
    }
}
