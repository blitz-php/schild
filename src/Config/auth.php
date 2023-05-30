<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

use BlitzPHP\Schild\Authentication\Actions\ActionInterface;
use BlitzPHP\Schild\Authentication\AuthenticatorInterface;
use BlitzPHP\Schild\Authentication\Authenticators\AccessTokens;
use BlitzPHP\Schild\Authentication\Authenticators\JWT;
use BlitzPHP\Schild\Authentication\Authenticators\Session;
use BlitzPHP\Schild\Authentication\Passwords\CompositionValidator;
use BlitzPHP\Schild\Authentication\Passwords\DictionaryValidator;
use BlitzPHP\Schild\Authentication\Passwords\NothingPersonalValidator;
use BlitzPHP\Schild\Authentication\Passwords\PwnedValidator;
use BlitzPHP\Schild\Authentication\Passwords\ValidatorInterface;
use BlitzPHP\Schild\Models\UserModel;

return [

    'views' => [
        'login'                       => '\BlitzPHP\Schild\Views\login',
        'register'                    => '\BlitzPHP\Schild\Views\register',
        'layout'                      => '\BlitzPHP\Schild\Views\layout',
        'action_email_2fa'            => '\BlitzPHP\Schild\Views\email_2fa_show',
        'action_email_2fa_verify'     => '\BlitzPHP\Schild\Views\email_2fa_verify',
        'action_email_2fa_email'      => '\BlitzPHP\Schild\Views\Email\email_2fa_email',
        'action_email_activate_show'  => '\BlitzPHP\Schild\Views\email_activate_show',
        'action_email_activate_email' => '\BlitzPHP\Schild\Views\Email\email_activate_email',
        'magic-link-login'            => '\BlitzPHP\Schild\Views\magic_link_form',
        'magic-link-message'          => '\BlitzPHP\Schild\Views\magic_link_message',
        'magic-link-email'            => '\BlitzPHP\Schild\Views\Email\magic_link_email',
    ],

    /**
     * @var ?string
     */
    'db_group' => 'default',

    /**
     * ------------------------------------------------- -------------------
     * Fournisseur d'utilisateurs
     * ------------------------------------------------- -------------------
     * Le nom de la classe qui gère la persistance de l'utilisateur.
     * Par défaut, il s'agit du UserModel inclus, qui fonctionne avec tous les moteurs de base de données pris en charge par BlitzPHP.
     * Vous pouvez le modifier tant qu'ils respectent le modele BlitzPHP\Schild\Models\UserModel.
     *
     * @var class-string<UserModel>
     */
    'user_provider' => UserModel::class,

    /**
     * --------------------------------------------------------------------
     * Personnaliser le nom des tables de protection
     * ------------------------------------------------- -------------------
     * Ne changez que si vous souhaitez renommer les noms de table Shield par défaut
     *
     * Il peut être nécessaire de modifier les noms des tables pour
     * raisons de sécurité, pour éviter les conflits de noms de tables,
     * la politique interne des entreprises ou toute autre raison.
     *
     * - users Auth Users Table, les informations des utilisateurs sont stockées.
     * - auth_identities Auth Identities Table, utilisé pour le stockage des mots de passe, des jetons d'accès, des identités de connexion sociale, etc.
     * - auth_logins Auth Login Tentatives, le tableau enregistre les tentatives de connexion.
     * - auth_token_logins Tableau des tentatives de connexion au jeton d'authentification, enregistre les tentatives de connexion de type jeton porteur.
     * - auth_remember_tokens Tableau des jetons de mémorisation d'authentification (se souvenir de moi).
     * - auth_groups_users Tableau des utilisateurs des groupes.
     * - auth_permissions_users Tableau des autorisations des utilisateurs .
     *
     * @var array<string, string>
     */
    'tables' => [
        'users'             => 'users',
        'identities'        => 'auth_identities',
        'logins'            => 'auth_logins',
        'token_logins'      => 'auth_token_logins',
        'remember_tokens'   => 'auth_remember_tokens',
        'groups_users'      => 'auth_groups_users',
        'permissions_users' => 'auth_permissions_users',
    ],

    /**
     * ------------------------------------------------- -------------------
     * URL de redirection
     * ------------------------------------------------- -------------------
     * L'URL par défaut vers laquelle un utilisateur sera redirigé après plusieurs authentifications.
     * Il peut s'agir de l'un des éléments suivants :
     *
     * 1. Une URL absolue. Par exemple. http://exemple.com OU https://exemple.com
     * 2. Une route nommée accessible en utilisant `link_to()` ou `url_to()`
     * 3. Un chemin URI dans l'application. par exemple 'admin', 'login', 'expath'
     *
     * Si vous avez besoin de plus de flexibilité, vous pouvez remplacer la méthode `getUrl()`
     * pour appliquer toute logique dont vous pourriez avoir besoin.
     *
     * @var array<string, string>
     */
    'redirects' => [
        'register'    => '/',
        'login'       => '/',
        'logout'      => 'login',
        'force_reset' => '/',
    ],

    /**
     * --------------------------------------------------------------------
     * Authentication Actions
     * --------------------------------------------------------------------
     * Specifies the class that represents an action to take after
     * the user logs in or registers a new account at the site.
     *
     * You must register actions in the order of the actions to be performed.
     *
     * Available actions with Shield:
     * - register: \BlitzPHP\Schild\Authentication\Actions\EmailActivator::class
     * - login:    \BlitzPHP\Schild\Authentication\Actions\Email2FA::class
     *
     * @var array<string, class-string<ActionInterface>|null>
     */
    'actions' => [
        'register' => null,
        'login'    => null,
    ],

    /**
     * --------------------------------------------------------------------
     * Authentificateur par défaut
     * --------------------------------------------------------------------
     * L'authentificateur à utiliser en cas de spécification.
     * Utilise la clé $ du tableau $ Authenticators ci-dessus.
     *
     * @var string
     */
    'default_authenticator' => 'session',

    /**
     * --------------------------------------------------------------------
     * Authentificateurs
     * --------------------------------------------------------------------
     * Les systèmes d'authentification disponibles, répertoriés avec un alias et un nom de classe.
     * Ceux-ci peuvent être référencés par Alias dans l'assistant Auth:
     *      auth('tokens')->attempt($credentials);
     *
     * @var array<string, class-string<AuthenticatorInterface>>
     */
    'authenticators' => [
        'tokens'  => AccessTokens::class,
        'session' => Session::class,
        // 'jwt'     => JWT::class,
    ],

    /**
     * -------------------------------------------------- ------------------
     * Nom de l'en-tête de l'authentificateur
     * ------------------------------------------------- -------------------
     * Le nom de l'en-tête dans lequel le jeton d'autorisation doit être trouvé.
     * Selon les spécifications, cela devrait être "Autorisation", mais de rares
     * circonstances peuvent nécessiter un en-tête différent.
     *
     * @var array
     */
    'authenticator_header' => [
        'tokens' => 'Authorization',
    ],

    /**
     * --------------------------------------------------------------------
     * Durée de vie du jeton inutilisé
     * ------------------------------------------------- -------------------
     * Détermine la durée, en secondes, pendant laquelle un jeton d'accès inutilisé peut être utilisé.
     *
     * @var int
     */
    'unused_token_lifetime' => YEAR,

    /**
     * --------------------------------------------------------------------
     * Chaîne d'authentification
     * --------------------------------------------------------------------
     * Les authentificateurs avec lesquels tester le statut de connexion lors de l'utilisation du filtre "chaîne".
     * Chaque authentificateur répertorié sera vérifié.
     * Si aucune correspondance n'est trouvée, le suivant dans la chaîne sera vérifié.
     *
     * @var string[]
     * @phpstan-var list<string>
     */
    'authentication_chain' => [
        'session',
        'tokens',
        // 'jwt',
    ],

    /**
     * --------------------------------------------------------------------
     * Allow Registration
     * --------------------------------------------------------------------
     * Determines whether users can register for the site.
     *
     * @var bool
     */
    'allow_registration' => true,

    /**
     * --------------------------------------------------------------------
     * Enregistrer la dernière date d'activité
     * --------------------------------------------------------------------
     * Si vrai, mettra toujours à jour la date et l'heure `last_active` pour l'utilisateur connecté à chaque demande de page.
     * Cette fonctionnalité ne fonctionne que lorsque le filtre de session/tokens est actif.
     *
     * @var bool
     */
    'record_active_date' => true,

    /**
     * --------------------------------------------------------------------
     * Autoriser les connexions Magic Link
     * --------------------------------------------------------------------
     * Si vrai, permettra l'utilisation de "liens magiques" envoyés par e-mail
     * comme moyen de connecter un utilisateur sans avoir besoin d'un mot de passe.
     * Par défaut, ceci est utilisé à la place d'un flux de réinitialisation de mot de passe,
     * mais peut être modifié comme seule méthode de connexion une fois qu'un compte a été configuré.
     *
     * @var bool
     */
    'allow_magic_link_logins' => true,

    /**
     * --------------------------------------------------------------------
     * Durée de vie du lien magique
     * --------------------------------------------------------------------
     * Spécifie la durée, en secondes, pendant laquelle un lien magique est valide.
     * Vous pouvez utiliser des constantes de temps ou n'importe quel nombre désiré.
     *
     * @var int
     */
    'magic_link_lifetime' => HOUR,

    /**
     * --------------------------------------------------------------------
     * Configuration de l'authentificateur de session
     * --------------------------------------------------------------------
     * Ces paramètres ne s'appliquent que si vous utilisez l'authentificateur de session pour l'authentification.
     *
     * - field                  Le nom de la clé dans laquelle les informations de l'utilisateur actuel sont stockées dans la session
     * - allow_remembering      Le système permet-il l'utilisation de "remember-me"
     * - remember_cookie_name   Le nom du cookie à utiliser pour "remember-me"
     * - remember_length        La durée, en secondes, de mémorisation d'un utilisateur.
     *
     * @var array<string, bool|int|string>
     */
    'session' => [
        'field'                => 'user',
        'allow_remembering'    => true,
        'remember_cookie_name' => 'remember',
        'remember_length'      => 30 * DAY,
    ],

    /**
     * --------------------------------------------------------------------
     * Longueur minimale du mot de passe
     * ------------------------------------------------- -------------------
     * La longueur minimale que doit avoir un mot de passe pour être accepté.
     * Valeur minimale recommandée par NIST = 8 caractères.
     *
     * @var int
     */
    'minimum_password_length' => 8,

    /**
     * --------------------------------------------------------------------
     * Assistants de vérification de mot de passe
     * ------------------------------------------------- -------------------
     * La classe PasswordValidator exécute le mot de passe à travers toutes ces classes,
     * chacune ayant la possibilité de réussir/échouer le mot de passe.
     * Vous pouvez ajouter des classes personnalisées tant qu'elles adhèrent à
     * BlitzPHP\Schild\Authentication\Passwords\ValidatorInterface.
     *
     * @var class-string<ValidatorInterface>[]
     */
    'password_validators' => [
        CompositionValidator::class,
        NothingPersonalValidator::class,
        DictionaryValidator::class,
        // PwnedValidator::class,
    ],

    /**
     * --------------------------------------------------------------------
     * Valid login fields
     * --------------------------------------------------------------------
     * Fields that are available to be used as credentials for login.
     *
     * @var array
     */
    'valid_fields' => [
        'email',
        // 'username',
    ],

    /**
     * --------------------------------------------------------------------
     * Additional Fields for "Nothing Personal"
     * --------------------------------------------------------------------
     * The NothingPersonalValidator prevents personal information from
     * being used in passwords. The email and username fields are always
     * considered by the validator. Do not enter those field names here.
     *
     * An extended User Entity might include other personal info such as
     * first and/or last names. $personalFields is where you can add
     * fields to be considered as "personal" by the NothingPersonalValidator.
     * For example:
     *     $personalFields = ['firstname', 'lastname'];
     */
    'personal_fields' => [],

    /**
     * --------------------------------------------------------------------
     * Password / Username Similarity
     * --------------------------------------------------------------------
     * Among other things, the NothingPersonalValidator checks the
     * amount of sameness between the password and username.
     * Passwords that are too much like the username are invalid.
     *
     * The value set for $maxSimilarity represents the maximum percentage
     * of similarity at which the password will be accepted. In other words, any
     * calculated similarity equal to, or greater than $maxSimilarity
     * is rejected.
     *
     * The accepted range is 0-100, with 0 (zero) meaning don't check similarity.
     * Using values at either extreme of the *working range* (1-100) is
     * not advised. The low end is too restrictive and the high end is too permissive.
     * The suggested value for $maxSimilarity is 50.
     *
     * You may be thinking that a value of 100 should have the effect of accepting
     * everything like a value of 0 does. That's logical and probably true,
     * but is unproven and untested. Besides, 0 skips the work involved
     * making the calculation unlike when using 100.
     *
     * The (admittedly limited) testing that's been done suggests a useful working range
     * of 50 to 60. You can set it lower than 50, but site users will probably start
     * to complain about the large number of proposed passwords getting rejected.
     * At around 60 or more it starts to see pairs like 'captain joe' and 'joe*captain' as
     * perfectly acceptable which clearly they are not.
     *
     * To disable similarity checking set the value to 0.
     *     public $maxSimilarity = 0;
     */
    'max_similarity' => 50,

    /**
     * --------------------------------------------------------------------
     * Hashing Algorithm to use
     * --------------------------------------------------------------------
     * Valid values are
     * - PASSWORD_DEFAULT (default)
     * - PASSWORD_BCRYPT
     * - PASSWORD_ARGON2I  - As of PHP 7.2 only if compiled with support for it
     * - PASSWORD_ARGON2ID - As of PHP 7.3 only if compiled with support for it
     */
    'hash_algorithm' => PASSWORD_DEFAULT,

    /**
     * --------------------------------------------------------------------
     * Options de l'algorithme ARGON2I/ARGON2ID
     * --------------------------------------------------------------------
     * La méthode de hachage ARGON2I permet de définir le "memory_cost", le "time_cost"
     * et le nombre de "threads", à chaque fois qu'un hachage de mot de passe est créé.
     *
     * @var int
     */
    'hash_memory_cost' => 65536, // PASSWORD_ARGON2_DEFAULT_MEMORY_COST;

    /**
     * @var int
     */
    'hash_time_cost' => 4,   // PASSWORD_ARGON2_DEFAULT_TIME_COST;

    /**
     * @var int
     */
    'hash_threads' => 1,   // PASSWORD_ARGON2_DEFAULT_THREADS;

    /**
     * --------------------------------------------------------------------
     * Options de l'algorithme BCRYPT
     * --------------------------------------------------------------------
     * La méthode de hachage BCRYPT vous permet de définir le "coût" ou le nombre d'itérations effectuées, chaque fois qu'un hachage de mot de passe est créé.
     * La valeur par défaut est 10, ce qui est un nombre acceptable.
     * Cependant, en fonction des besoins de sécurité de votre application et de la puissance de votre matériel, vous souhaiterez peut-être augmenter le coût.
     * Cela rend le processus de hachage plus long.
     *
     * La plage valide est comprise entre 4 et 31.
     *
     * @var int
     */
    'hash_cost' => 10,

    /**
     * Renvoie l'URL vers laquelle un utilisateur doit être redirigé après une connexion réussie.
     */
    'loginRedirect' => static function (): string {
        $url = config('auth.redirects.login');

        return call_user_func(config('auth.getUrl'), $url);
    },

    /**
     * Renvoie l'URL vers laquelle un utilisateur doit être redirigé après sa déconnexion.
     */
    'logoutRedirect' => static function (): string {
        $url = config('auth.redirects.logout');

        return call_user_func(config('auth.getUrl'), $url);
    },

    /**
     * Renvoie l'URL vers laquelle l'utilisateur doit être redirigé après une inscription réussie.
     */
    'registerRedirect' => static function (): string {
        $url = config('auth.redirects.register');

        return call_user_func(config('auth.getUrl'), $url);
    },

    /**
     * Renvoie l'URL vers laquelle l'utilisateur doit être redirigé si force_reset identity est défini sur true.
     */
    'forcePasswordResetRedirect' => static function (): string {
        $url = config('auth.redirects.force_reset');

        return call_user_func(config('auth.getUrl'), $url);
    },

    /**
     * Accepte une chaîne qui peut être une URL absolue ou
     * une route nommée ou simplement un chemin URI, et renvoie le chemin complet.
     *
     * @param string $url une URL absolue ou une route nommée ou simplement un chemin URI
     */
    'getUrl' => static function (string $url): string {
        // Pour s'adapter à tous les modèles d'URL
        $final_url = '';

        switch (true) {
            case strpos($url, 'http://') === 0 || strpos($url, 'https://') === 0: // L'URL commence par 'http' ou 'https'. Par exemple. http://exemple.com
                $final_url = $url;
                break;

            case link_to($url) !== false: // L'URL est une route nommée
                $final_url = rtrim(url_to($url), '/ ');
                break;

            default: // L'URL est une route (chemin URI)
                $final_url = rtrim(site_url($url), '/ ');
                break;
        }

        return $final_url;
    },
];
