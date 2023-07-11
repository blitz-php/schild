<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace BlitzPHP\Schild\Models;

use BlitzPHP\Schild\Authentication\Authenticators\AccessTokens;
use BlitzPHP\Schild\Authentication\Authenticators\Session;
use BlitzPHP\Schild\Config\Services;
use BlitzPHP\Schild\Entities\AccessToken;
use BlitzPHP\Schild\Entities\User;
use BlitzPHP\Schild\Entities\UserIdentity;
use BlitzPHP\Schild\Exceptions\DatabaseException;
use BlitzPHP\Schild\Exceptions\LogicException;
use BlitzPHP\Utilities\Date;
use BlitzPHP\Utilities\String\Text;
use InvalidArgumentException;

class UserIdentityModel extends BaseModel
{
    protected string $returnType = UserIdentity::class;

    public function __construct()
    {
        parent::__construct();

        $this->table = $this->tables['identities'];
    }

    /**
     * Insère un enregistrement
     *
     * @throws DatabaseException
     */
    public function create(array|object|null $data = null, bool $returnID = true): void
    {
        if (null === $data) {
            throw new InvalidArgumentException('$data doit etre un objet ou un tableau');
        }
        $this->disableDBDebug();

        $return = parent::create($data, $returnID);

        $this->checkQueryReturn($return);
    }

    /**
     * Crée une nouvelle identité pour cet utilisateur avec une combinaison email/mot de passe.
     *
     * @phpstan-param array{email: string, password: string} $credentials
     */
    public function createEmailIdentity(User $user, array $credentials): void
    {
        $this->checkUserId($user);

        $className = $this->returnType;
        $identity = new $className();
        $identity->forceFill([
            'user_id' => $user->id,
            'type'    => Session::ID_TYPE_EMAIL_PASSWORD,
            'secret'  => $credentials['email'],
            'secret2' => Services::passwords()->hash($credentials['password']),
        ])->save();
    }

    private function checkUserId(User $user): void
    {
        if ($user->id === null) {
            throw new LogicException(
                '"$user->id" est nul. Vous ne devez pas utiliser l\'objet utilisateur incomplet.'
            );
        }
    }

    /**
     * Créer une identité avec un code à 6 chiffres pour l'action d'authentification
     *
     * @phpstan-param array{type: string, name: string, extra: string} $data
     * @param callable $codeGenerator générer un code secret
     *
     * @return string secret
     */
    public function createCodeIdentity(User $user, array $data, callable $codeGenerator): string
    {
        $this->checkUserId($user);

        // Créer une identité pour l'action
        $maxTry          = 5;
        $data['user_id'] = $user->id;

        while (true) {
            $data['secret'] = $codeGenerator();

            try {
                $this->create($data);

                break;
            } catch (DatabaseException $e) {
                $maxTry--;

                if ($maxTry === 0) {
                    throw $e;
                }
            }
        }

        return $data['secret'];
    }

    /**
     * Génère un nouveau token d'accès personnel pour l'utilisateur.
     *
     * @param string   $name   Nom du token
     * @param string[] $scopes Autorisations accordées par le token
     */
    public function generateAccessToken(User $user, string $name, array $scopes = ['*']): AccessToken
    {
        $this->checkUserId($user);

        $return = $this->insert([
            'type'    => AccessTokens::ID_TYPE_ACCESS_TOKEN,
            'user_id' => $user->id,
            'name'    => $name,
            'secret'  => hash('sha256', $rawToken = Text::random(64)),
            'extra'   => serialize($scopes),
        ]);

        $this->checkQueryReturn($return);

        /** @var AccessToken $token */
        $token = $this->where(['id' => $this->lastID()])->first(AccessToken::class);

        $token->raw_token = $rawToken;

        return $token;
    }

    public function getAccessTokenByRawToken(string $rawToken): ?AccessToken
    {
        return $this
            ->where('type', AccessTokens::ID_TYPE_ACCESS_TOKEN)
            ->where('secret', hash('sha256', $rawToken))
            ->first(AccessToken::class);
    }

    public function getAccessToken(User $user, string $rawToken): ?AccessToken
    {
        $this->checkUserId($user);

        return $this->where('user_id', $user->id)
            ->where('type', AccessTokens::ID_TYPE_ACCESS_TOKEN)
            ->where('secret', hash('sha256', $rawToken))
            ->first(AccessToken::class);
    }

    /**
     * Étant donné l'ID, renvoie le jeton d'accès donné.
     *
     * @param int|string $id
     */
    public function getAccessTokenById($id, User $user): ?AccessToken
    {
        $this->checkUserId($user);

        return $this->where('user_id', $user->id)
            ->where('type', AccessTokens::ID_TYPE_ACCESS_TOKEN)
            ->where('id', $id)
            ->first(AccessToken::class);
    }

    /**
     * @return AccessToken[]
     */
    public function getAllAccessTokens(User $user): array
    {
        $this->checkUserId($user);

        return $this
            ->where('user_id', $user->id)
            ->where('type', AccessTokens::ID_TYPE_ACCESS_TOKEN)
            ->orderBy($this->primaryKey)
            ->all(AccessToken::class);
    }

    /**
     * Utilisé par 'magic-link'.
     */
    public function getIdentityBySecret(string $type, ?string $secret): ?UserIdentity
    {
        if ($secret === null) {
            return null;
        }

        return $this->where('type', $type)
            ->where('secret', $secret)
            ->first($this->returnType);
    }

    /**
     * Renvoie toutes les identités.
     *
     * @return UserIdentity[]
     */
    public function getIdentities(User $user): array
    {
        $this->checkUserId($user);
        $className = $this->returnType;

        return $className::where('user_id', $user->id)->orderBy($this->primaryKey)->all();
    }

    /**
     * @param int[]|string[] $userIds
     *
     * @return UserIdentity[]
     */
    public function getIdentitiesByUserIds(array $userIds): array
    {
        return $this->whereIn('user_id', $userIds)->orderBy($this->primaryKey)->all($this->returnType);
    }

    /**
     * Renvoie la première identité du type.
     */
    public function getIdentityByType(User $user, string $type): ?UserIdentity
    {
        $this->checkUserId($user);

        return $this->where('user_id', $user->id)
            ->where('type', $type)
            ->orderBy($this->primaryKey)
            ->first($this->returnType);
    }

    /**
     * Renvoie toutes les identités pour les types spécifiques.
     *
     * @param string[] $types
     *
     * @return UserIdentity[]
     */
    public function getIdentitiesByTypes(User $user, array $types): array
    {
        $this->checkUserId($user);

        if ($types === []) {
            return [];
        }

        return $this->where('user_id', $user->id)
            ->whereIn('type', $types)
            ->orderBy($this->primaryKey)
            ->all($this->returnType);
    }

    /**
     * Mettre à jour la dernière date d'utilisation pour un enregistrement d'identité.
     */
    public function touchIdentity(UserIdentity $identity): void
    {
        $identity->last_used_at = Date::now()->format('Y-m-d H:i:s');

        $identity->save();
    }

    public function deleteIdentitiesByType(User $user, string $type): void
    {
        $this->checkUserId($user);

        $return = $this->where('user_id', $user->id)
            ->where('type', $type)
            ->delete();

        $this->checkQueryReturn($return);
    }

    /**
     * Supprimez tous les jetons d'accès pour le jeton brut donné.
     */
    public function revokeAccessToken(User $user, string $rawToken): void
    {
        $this->checkUserId($user);

        $return = $this->where('user_id', $user->id)
            ->where('type', AccessTokens::ID_TYPE_ACCESS_TOKEN)
            ->where('secret', hash('sha256', $rawToken))
            ->delete();

        $this->checkQueryReturn($return);
    }

    /**
     * Révoque tous les jetons d'accès pour cet utilisateur.
     */
    public function revokeAllAccessTokens(User $user): void
    {
        $this->checkUserId($user);

        $return = $this->where('user_id', $user->id)
            ->where('type', AccessTokens::ID_TYPE_ACCESS_TOKEN)
            ->delete();

        $this->checkQueryReturn($return);
    }

    /**
     * Forcer la réinitialisation du mot de passe pour plusieurs utilisateurs.
     *
     * @param int[]|string[] $userIds
     */
    public function forceMultiplePasswordReset(array $userIds): void
    {
        $this->where(['type' => Session::ID_TYPE_EMAIL_PASSWORD, 'force_reset' => 0]);
        $this->whereIn('user_id', $userIds);
        $return = $this->update(['force_reset' => 1]);

        $this->checkQueryReturn($return);
    }

    /**
     * Forcer la réinitialisation globale du mot de passe.
     * Ceci est utile pour forcer une réinitialisation du mot de passe pour TOUS les utilisateurs en cas de faille de sécurité.
     */
    public function forceGlobalPasswordReset(): void
    {
        $whereFilter = [
            'type'        => Session::ID_TYPE_EMAIL_PASSWORD,
            'force_reset' => 0,
        ];
        $this->where($whereFilter);
        $return = $this->update(['force_reset' => 1]);

        $this->checkQueryReturn($return);
    }
}
