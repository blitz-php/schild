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

namespace BlitzPHP\Schild\Authentication\Traits;

use BlitzPHP\Schild\Entities\AccessToken;
use BlitzPHP\Schild\Models\UserIdentityModel;
use ReflectionException;

/**
 * Fournit les fonctionnalités nécessaires pour générer, révoquer et récupérer des jetons d'accès personnels.
 *
 * Destiné à être utilisé avec les entités utilisateur.
 */
trait HasHmacTokens
{
    /**
     * Le jeton d'accès actuel pour l'utilisateur.
     */
    private ?AccessToken $currentHmacToken = null;

    /**
     * Génère un nouveau jeton HMAC personnel pour cet utilisateur.
     *
     * @param string   $name   Nom du jeton
     * @param string[] $scopes Autorisations accordées par le jeton
     *
     * @throws ReflectionException
     */
    public function generateHmacToken(string $name, array $scopes = ['*']): AccessToken
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        return $identityModel->generateHmacToken($this, $name, $scopes);
    }

    /**
     * Supprimez tous les jetons HMAC pour la clé donnée.
     */
    public function revokeHmacToken(string $key): void
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        $identityModel->revokeHmacToken($this, $key);
    }

    /**
     * Révoque tous les jetons HMAC pour cet utilisateur.
     */
    public function revokeAllHmacTokens(): void
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        $identityModel->revokeAllHmacTokens($this);
    }

    /**
     * Récupère tous les jetons HMAC personnels pour cet utilisateur.
     *
     * @return AccessToken[]
     */
    public function hmacTokens(): array
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        return $identityModel->getAllHmacTokens($this);
    }

    /**
     * Étant donné une clé HMAC, il la localisera dans le système.
     */
    public function getHmacToken(?string $key): ?AccessToken
    {
        if (! isset($key) || $key === '') {
            return null;
        }

        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        return $identityModel->getHmacToken($this, $key);
    }

    /**
     * Compte tenu de l'ID, renvoie le jeton d'accès donné.
     */
    public function getHmacTokenById(int $id): ?AccessToken
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        return $identityModel->getHmacTokenById($id, $this);
    }

    /**
     * Détermine si le jeton de l'utilisateur accorde des autorisations à $scope.
     * Vérifie d'abord par rapport à $this->activeToken, qui est défini lors de l'authentification.
     * S'il n'a pas été défini, renvoie false.
     */
    public function hmacTokenCan(string $scope): bool
    {
        if (! $this->currentHmacToken() instanceof AccessToken) {
            return false;
        }

        return $this->currentHmacToken()->can($scope);
    }

    /**
     * Détermine si le jeton de l'utilisateur n'accorde PAS d'autorisations à $scope.
     * Vérifie d'abord par rapport à $this->activeToken, qui est défini lors de l'authentification.
     * S'il n'a pas été défini, renvoie vrai.
     */
    public function hmacTokenCant(string $scope): bool
    {
        if (! $this->currentHmacToken() instanceof AccessToken) {
            return true;
        }

        return $this->currentHmacToken()->cant($scope);
    }

    /**
     * Renvoie le jeton HMAC actuel pour l'utilisateur.
     */
    public function currentHmacToken(): ?AccessToken
    {
        return $this->currentHmacToken;
    }

    /**
     * Définit le jeton actif actuel pour cet utilisateur.
     */
    public function setHmacToken(?AccessToken $accessToken): self
    {
        $this->currentHmacToken = $accessToken;

        return $this;
    }
}
