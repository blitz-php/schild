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

use BlitzPHP\Schild\Authentication\AuthenticatorInterface;
use BlitzPHP\Schild\Config\Services;
use BlitzPHP\Schild\Exceptions\AuthenticationException;
use BlitzPHP\Schild\Models\TokenLoginModel;
use BlitzPHP\Schild\Models\UserIdentityModel;
use BlitzPHP\Schild\Models\UserModel;
use BlitzPHP\Schild\Result;
use BlitzPHP\Utilities\Date;

class AccessTokens extends BaseAuthenticator implements AuthenticatorInterface
{
    public const ID_TYPE_ACCESS_TOKEN = 'access_token';

    protected TokenLoginModel $loginModel;

    /**
     * Constructor.
     *
     * @param UserModel $provider Le moteur de persistance
     */
    public function __construct(protected UserModel $provider)
    {
        $this->loginModel = model(TokenLoginModel::class);
    }

    /**
     * Tente d'authentifier un utilisateur avec les $credentials donnés.
     * Connecte l'utilisateur avec une vérification réussie.
     *
     * @throws AuthenticationException
     */
    public function attempt(array $credentials): Result
    {
        $request = Services::request();
        $config  = (object) config('auth-token');

        $ipAddress = $request->ip();
        $userAgent = (string) $request->userAgent();

        $result = $this->check($credentials);

        if (! $result->isOK()) {
            if ($config->record_login_attempt >= RECORD_LOGIN_ATTEMPT_FAILURE) {
                // Enregistrez toutes les tentatives de connexion échouées.
                $this->loginModel->recordLoginAttempt(
                    self::ID_TYPE_ACCESS_TOKEN,
                    $credentials['token'] ?? '',
                    false,
                    $ipAddress,
                    $userAgent
                );
            }

            return $result;
        }

        $user  = $result->extraInfo();
        $token = $user->getAccessToken($this->getBearerToken());

        if ($user->isBanned()) {
            if ($config->record_login_attempt >= RECORD_LOGIN_ATTEMPT_FAILURE) {
                // Enregistrer une tentative de connexion interdite.
                $this->loginModel->recordLoginAttempt(
                    self::ID_TYPE_ACCESS_TOKEN,
                    $token->name ?? '',
                    false,
                    $ipAddress,
                    $userAgent,
                    $user->id
                );
            }

            $this->user = null;

            return new Result([
                'success' => false,
                'reason'  => $user->getBanMessage() ?? lang('Auth.bannedUser'),
            ]);
        }

        $user = $user->setAccessToken($token);

        $this->login($user);

        if ($config->record_login_attempt >= RECORD_LOGIN_ATTEMPT_ALL) {
            // Enregistrez une tentative de connexion réussie.
            $this->loginModel->recordLoginAttempt(
                self::ID_TYPE_ACCESS_TOKEN,
                $token->name ?? '',
                true,
                $ipAddress,
                $userAgent,
                $this->user->id
            );
        }

        return $result;
    }

    /**
     * Vérifie les $credentials d'un utilisateur pour voir s'ils correspondent à un utilisateur existant.
     *
     * Dans ce cas, $credentials n'a qu'une seule valeur valide : token, qui est le jeton de texte brut à renvoyer.
     */
    public function check(array $credentials): Result
    {
        if (! array_key_exists('token', $credentials) || empty($credentials['token'])) {
            return new Result([
                'success' => false,
                'reason'  => lang('Auth.noToken', [config('auth-token.authenticator_header.tokens')]),
            ]);
        }

        if (str_starts_with($credentials['token'], 'Bearer')) {
            $credentials['token'] = trim(substr($credentials['token'], 6));
        }

        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        $token = $identityModel->getAccessTokenByRawToken($credentials['token']);

        if ($token === null) {
            return new Result([
                'success' => false,
                'reason'  => lang('Auth.badToken'),
            ]);
        }

        assert($token->last_used_at instanceof Date || $token->last_used_at === null);

        // N'a pas été utilisé depuis longtemps
        if (
            $token->last_used_at
            && $token->last_used_at->isBefore(Date::now()->subSeconds(config('auth.unused_token_lifetime')))
        ) {
            return new Result([
                'success' => false,
                'reason'  => lang('Auth.oldToken'),
            ]);
        }

        $token->last_used_at = Date::now()->format('Y-m-d H:i:s');

        if ($token->hasChanged()) {
            $identityModel->save($token);
        }

        // Assurez-vous que le jeton est défini comme le jeton actuel
        $user = $token->user();
        $user->setAccessToken($token);

        return new Result([
            'success'   => true,
            'extraInfo' => $user,
        ]);
    }

    /**
     * Vérifie si l'utilisateur est actuellement connecté.
     * Étant donné que l'utilisation d'AccessToken est intrinsèquement sans état,
     * il exécute $this->attempt à chaque utilisation.
     */
    public function loggedIn(): bool
    {
        if (! empty($this->user)) {
            return true;
        }

        $request = Services::request();

        return $this->attempt([
            'token' => $request->getHeaderLine(config('auth-token.authenticator_header.tokens')),
        ])->isOK();
    }

    /**
     * Connecte un utilisateur en fonction de son ID.
     *
     * @param int|string $userId
     *
     * @throws AuthenticationException
     */
    public function loginById($userId): void
    {
        $user = $this->provider->findById($userId);

        if (empty($user)) {
            throw AuthenticationException::invalidUser();
        }

        $user->setAccessToken(
            $user->getAccessToken($this->getBearerToken())
        );

        $this->login($user);
    }

    /**
     * Renvoie le jeton Bearer de l'en-tête d'autorisation
     */
    public function getBearerToken(): ?string
    {
        $request = Services::request();

        $header = $request->getHeaderLine(config('auth-token.authenticator_header.tokens'));

        if (empty($header)) {
            return null;
        }

        return trim(substr($header, 6));   // 'Bearer'
    }
}
