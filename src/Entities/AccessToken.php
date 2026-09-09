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

namespace BlitzPHP\Schild\Entities;

/**
 * Représente un jeton d'accès personnel unique, utilisé pour authentifier les utilisateurs pour une API.
 *
 * @property Date|string|null $last_used_at
 */
class AccessToken extends Entity
{
    private ?User $user = null;

    /**
     * {@inheritDoc}
     *
     * @var array<string, string>
     */
    protected array $casts = [
        'id'           => '?integer',
        'last_used_at' => 'datetime',
        'extra'        => 'array',
        'expires'      => 'datetime',
    ];

    /**
     * @var array<string, string>
     */
    protected $datamap = [
        'scopes' => 'extra',
    ];

    /**
     * Renvoie l'utilisateur associé à ce jeton.
     */
    public function user(): ?User
    {
        if ($this->user === null) {
            $users      = auth()->getProvider();
            $this->user = $users->findById($this->user_id);
        }

        return $this->user;
    }

    /**
     * Détermine si ce jeton accorde l'autorisation au $scope
     */
    public function can(string $scope): bool
    {
        if ($this->extra === []) {
            return false;
        }

        // Caractère générique présent
        if (in_array('*', $this->extra, true)) {
            return true;
        }

        // Vérifier les étendues stockées
        return in_array($scope, $this->extra, true);
    }

    /**
     * Détermine si ce jeton n'accorde PAS l'autorisation à $scope.
     */
    public function cant(string $scope): bool
    {
        if ($this->extra === []) {
            return true;
        }

        // Caractère générique présent
        if (in_array('*', $this->extra, true)) {
            return false;
        }

        // vérifier les étendues stockées
        return ! in_array($scope, $this->extra, true);
    }
}
