<?php

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

class HmacSha256 extends BaseAuthenticator implements AuthenticatorInterface
{
    public const ID_TYPE_HMAC_TOKEN = 'hmac_sha256';

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
     * @param array{token?: string} $credentials
     */
    public function attempt(array $credentials): Result
    {
        $config = (object) config('auth-token');

        $request = Services::request();

        $ipAddress = $request->ip();
        $userAgent = (string) $request->userAgent();

        $result = $this->check($credentials);

        if (! $result->isOK()) {
            if ($config->record_login_attempt >= RECORD_LOGIN_ATTEMPT_FAILURE) {
                // Enregistrer une tentative de connexion échouée.
                $this->loginModel->recordLoginAttempt(
                    self::ID_TYPE_HMAC_TOKEN,
                    $credentials['token'] ?? '',
                    false,
                    $ipAddress,
                    $userAgent
                );
            }

            return $result;
        }

        $user = $result->extraInfo();

        if ($user->isBanned()) {
            if ($config->record_login_attempt >= RECORD_LOGIN_ATTEMPT_FAILURE) {
                // Enregistrer une tentative de connexion interdite.
                $this->loginModel->recordLoginAttempt(
                    self::ID_TYPE_HMAC_TOKEN,
                    $credentials['token'] ?? '',
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

        $user = $user->setHmacToken(
            $user->getHmacToken($this->getHmacKeyFromToken())
        );

        $this->login($user);

        if ($config->record_login_attempt === RECORD_LOGIN_ATTEMPT_ALL) {
            // Enregistrez une tentative de connexion réussie.
            $this->loginModel->recordLoginAttempt(
                self::ID_TYPE_HMAC_TOKEN,
                $credentials['token'] ?? '',
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
     *
     * @param array{token?: string} $credentials
     */
    public function check(array $credentials): Result
    {
        if (! array_key_exists('token', $credentials) || $credentials['token'] === '') {
            return new Result([
                'success' => false,
                'reason'  => lang(
                    'Auth.noToken',
                    [config('auth-token.authenticator_header.hmac')]
                ),
            ]);
        }

        if (strpos($credentials['token'], 'HMAC-SHA256') === 0) {
            $credentials['token'] = trim(substr($credentials['token'], 11)); // HMAC-SHA256
        }

        // Extraire la signature UserToken et HMACSHA256 du jeton d'autorisation
        [$userToken, $signature] = $this->getHmacAuthTokens($credentials['token']);

        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        $token = $identityModel->getHmacTokenByKey($userToken);

        if ($token === null) {
            return new Result([
                'success' => false,
                'reason'  => lang('Auth.badToken'),
            ]);
        }

        // Vérifier la signature...
        $hash = hash_hmac('sha256', $credentials['body'], $token->secret2);
        if ($hash !== $signature) {
            return new Result([
                'success' => false,
                'reason'  => lang('Auth.badToken'),
            ]);
        }

        assert($token->last_used_at instanceof Date || $token->last_used_at === null);

        // N'a pas été utilisé depuis longtemps
        if (
            isset($token->last_used_at)
            && $token->last_used_at->isBefore(
                Date::now()->subSeconds(config('auth-token.unused_token_lifetime'))
            )
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

        // Assurez-vous que le jeton est défini comme jeton actuel
        $user = $token->user();
        $user->setHmacToken($token);

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
        if ($this->user !== null) {
            return true;
        }

        $request = Services::request();

        return $this->attempt([
            'token' => $request->getHeaderLine(config('auth-token.authenticator_header.hmac')),
        ])->isOK();
    }

    /**
     * Connecte un utilisateur en fonction de son identifiant.
     *
     * @param int|string $userId User ID
     *
     * @throws AuthenticationException
     */
    public function loginById($userId): void
    {
        $user = $this->provider->findById($userId);

        if ($user === null) {
            throw AuthenticationException::invalidUser();
        }

        $user->setHmacToken(
            $user->getHmacToken($this->getHmacKeyFromToken())
        );

        $this->login($user);
    }

    /**
     * Renvoie le jeton d'autorisation HMAC complète à partir de l'en-tête d'autorisation
     *
     * @return ?string Jeton d'autorisation coupé de l'en-tête
     */
    public function getFullHmacToken(): ?string
    {
        $request = Services::request();

        $header = $request->getHeaderLine(config('auth-token.authenticator_header.hmac'));

        if ($header === '') {
            return null;
        }

        return trim(substr($header, 11));   // 'HMAC-SHA256'
    }

    /**
     * Obtenez la clé et le hachage HMAC à partir du jeton d'authentification
     *
     * @return ?array [key, hmacHash]
     */
    public function getHmacAuthTokens(?string $fullToken = null): ?array
    {
        if (! isset($fullToken)) {
            $fullToken = $this->getFullHmacToken();
        }

        if (isset($fullToken)) {
            return preg_split('/:/', $fullToken, -1, PREG_SPLIT_NO_EMPTY);
        }

        return null;
    }

    /**
     * Récupérer la clé du jeton d'authentification
     *
     * @return ?string Clé du jeton HMAC
     */
    public function getHmacKeyFromToken(): ?string
    {
        [$key, $secretKey] = $this->getHmacAuthTokens();

        return $key;
    }

    /**
     * Récupérer le hachage HMAC du jeton d'authentification
     *
     * @return ?string Hachage HMAC
     */
    public function getHmacHashFromToken(): ?string
    {
        [$key, $hash] = $this->getHmacAuthTokens();

        return $hash;
    }
}
