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
use BlitzPHP\Schild\Authentication\Jwt\JwtManager;
use BlitzPHP\Schild\Config\Services;
use BlitzPHP\Schild\Exceptions\RuntimeException;
use BlitzPHP\Schild\Models\TokenLoginModel;
use BlitzPHP\Schild\Models\UserModel;
use BlitzPHP\Schild\Result;
use Psr\Http\Message\ServerRequestInterface;
use stdClass;

/**
 * Authentificateur JWT sans état
 */
class JWT extends BaseAuthenticator implements AuthenticatorInterface
{
    /**
     * @var string Type d'identification spécial.
     *             Cet authentificateur est sans état, donc pas d'enregistrement `auth_identities`.
     */
    public const ID_TYPE_JWT = 'jwt';

    protected JwtManager $jwtManager;
    protected TokenLoginModel $tokenLoginModel;
    protected ?stdClass $payload = null;

    /**
     * @var string Le groupe clé. La clé du tableau de config/auth-jwt::$keys.
     */
    protected $keyset = 'default';

    /**
     * Constructor.
     *
     * @param UserModel $provider Le moteur de persistance
     */
    public function __construct(protected UserModel $provider)
    {
        $this->jwtManager      = Services::jwtManager();
        $this->tokenLoginModel = model(TokenLoginModel::class);
    }

    /**
     * Tente d'authentifier un utilisateur avec les $credentials donnés.
     * Connecte l'utilisateur avec une vérification réussie.
     *
     * @param array{token?: string} $credentials
     */
    public function attempt(array $credentials): Result
    {
        $config = (object) config('auth-jwt');

        $request = Services::request();

        $ipAddress = $request->ip();
        $userAgent = (string) $request->userAgent();

        $result = $this->check($credentials);

        if (! $result->isOK()) {
            if ($config->record_login_attempt >= RECORD_LOGIN_ATTEMPT_FAILURE) {
                // Enregistrer une tentative de connexion échouée.
                $this->tokenLoginModel->recordLoginAttempt(
                    self::ID_TYPE_JWT,
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
                $this->tokenLoginModel->recordLoginAttempt(
                    self::ID_TYPE_JWT,
                    'sha256:' . hash('sha256', $credentials['token'] ?? ''),
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

        $this->login($user);

        if ($config->record_login_attempt === RECORD_LOGIN_ATTEMPT_ALL) {
            // Enregistrez une tentative de connexion réussie.
            $this->tokenLoginModel->recordLoginAttempt(
                self::ID_TYPE_JWT,
                'sha256:' . hash('sha256', $credentials['token']),
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
                    [config('auth.authenticator_header')]
                ),
            ]);
        }

        // Verifie JWT
        try {
            $this->payload = $this->jwtManager->parse($credentials['token'], $this->keyset);
        } catch (RuntimeException $e) {
            return new Result([
                'success' => false,
                'reason'  => $e->getMessage(),
            ]);
        }

        $userId = $this->payload->sub ?? null;

        if ($userId === null) {
            return new Result([
                'success' => false,
                'reason'  => 'Invalid JWT: no user_id',
            ]);
        }

        // Cherche l'utilisateur
        $user = $this->provider->findById($userId);

        if ($user === null) {
            return new Result([
                'success' => false,
                'reason'  => lang('Auth.invalidUser'),
            ]);
        }

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

        $token = $this->getTokenFromRequest($request);

        return $this->attempt([
            'token' => $token,
        ])->isOK();
    }

    /**
     * Gets token from Request.
     */
    public function getTokenFromRequest(ServerRequestInterface $request): string
    {
        $tokenHeader = $request->getHeaderLine(config('auth-jwt.authenticator_header', 'Authorization'));

        if (strpos($tokenHeader, 'Bearer') === 0) {
            return trim(substr($tokenHeader, 6));
        }

        return $tokenHeader;
    }

    /**
     * @param string $keyset Le groupe clé. La clé du tableau de config/auth-jwt::$keys.
     */
    public function setKeyset($keyset): void
    {
        $this->keyset = $keyset;
    }

    /**
     * Renvoie la charge utile
     */
    public function getPayload(): ?stdClass
    {
        return $this->payload;
    }
}
