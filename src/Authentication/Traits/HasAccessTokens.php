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

/**
 * Fournit les fonctionnalités nécessaires pour générer, révoquer et récupérer des jetons d'accès personnels.
 *
 * Destiné à être utilisé avec les entités utilisateur.
 */
trait HasAccessTokens
{
    /**
     * Le jeton d'accès actuel pour l'utilisateur.
     */
    private ?AccessToken $currentAccessToken = null;

    /**
     * Génère un nouveau jeton d'accès personnel pour cet utilisateur.
     *
     * @param string[] $scopes Autorisations accordées par le jeton
     */
    public function generateAccessToken(string $name, array $scopes = ['*']): AccessToken
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        return $identityModel->generateAccessToken($this, $name, $scopes);
    }

    /**
     * Supprimez tous les jetons d'accès pour le jeton brut donné.
     */
    public function revokeAccessToken(string $rawToken): void
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        $identityModel->revokeAccessToken($this, $rawToken);
    }

    /**
     * Révoque tous les jetons d'accès pour cet utilisateur.
     */
    public function revokeAllAccessTokens(): void
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        $identityModel->revokeAllAccessTokens($this);
    }

    /**
     * Récupère tous les jetons d'accès personnels pour cet utilisateur.
     *
     * @return AccessToken[]
     */
    public function accessTokens(): array
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        return $identityModel->getAllAccessTokens($this);
    }

    /**
     * Étant donné un jeton brut, le hachera et tentera de le localiser dans le système.
     */
    public function getAccessToken(?string $rawToken): ?AccessToken
    {
        if (empty($rawToken)) {
            return null;
        }

        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        return $identityModel->getAccessToken($this, $rawToken);
    }

    /**
     * Étant donné l'ID, renvoie le jeton d'accès donné.
     */
    public function getAccessTokenById(int $id): ?AccessToken
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        return $identityModel->getAccessTokenById($id, $this);
    }

    /**
     * Détermine si le jeton de l'utilisateur accorde des autorisations à $scope.
     * Vérifie d'abord $this->activeToken, qui est défini lors de l'authentification.
     * S'il n'a pas été défini, renvoie faux.
     */
    public function tokenCan(string $scope): bool
    {
        if (! $this->currentAccessToken() instanceof AccessToken) {
            return false;
        }

        return $this->currentAccessToken()->can($scope);
    }

    /**
     * Détermine si le jeton de l'utilisateur n'accorde PAS d'autorisations à $scope.
     * Vérifie d'abord $this->activeToken, qui est défini lors de l'authentification.
     * S'il n'a pas été défini, renvoie vrai.
     */
    public function tokenCant(string $scope): bool
    {
        if (! $this->currentAccessToken() instanceof AccessToken) {
            return true;
        }

        return $this->currentAccessToken()->cant($scope);
    }

    /**
     * Renvoie le jeton d'accès actuel pour l'utilisateur.
     */
    public function currentAccessToken(): ?AccessToken
    {
        return $this->currentAccessToken;
    }

    /**
     * Définit le jeton actif actuel pour cet utilisateur.
     */
    public function setAccessToken(?AccessToken $accessToken): self
    {
        $this->currentAccessToken = $accessToken;

        return $this;
    }
}
