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

use BlitzPHP\Schild\Authorization\PermissionMatcher;

/**
 * Représente un seul groupe d'utilisateurs et fournit des fonctions utilitaires.
 */
class Group extends Entity
{
    protected ?array $permissions = null;

    /**
     * Renvoie les autorisations pour ce groupe.
     */
    public function permissions(): array
    {
        $this->populatePermissions();

        return $this->permissions;
    }

    /**
     * Remplace et enregistre toutes les autorisations de la classe avec le tableau d'autorisations transmis.
     */
    public function setPermissions(array $permissions): void
    {
        $this->permissions = $permissions;

        $matrix = parametre('auth-groups.matrix');

        $matrix[$this->alias] = $permissions;

        parametre('auth-groups.matrix', $matrix);
    }

    /**
     * Ajoute une seule autorisation à ce groupe et l'enregistre.
     */
    public function addPermission(string $permission): void
    {
        $this->populatePermissions();

        array_unshift($this->permissions, $permission);

        $this->setPermissions($this->permissions);
    }

    /**
     * Supprime une seule autorisation de ce groupe et l'enregistre.
     */
    public function removePermission(string $permission): void
    {
        $this->populatePermissions();

        unset($this->permissions[array_search($permission, $this->permissions, true)]);

        $this->setPermissions($this->permissions);
    }

    /**
     *Détermine si le groupe a l'autorisation donnée
     */
    public function can(string $permission): bool
    {
        $this->populatePermissions();

        return $this->permissions !== null
            && $this->permissions !== []
            && PermissionMatcher::matches($permission, $this->permissions);
    }

    /**
     * Charge nos autorisations pour ce groupe.
     */
    private function populatePermissions(): void
    {
        if ($this->permissions !== null) {
            return;
        }

        $this->permissions = parametre('auth-groups.matrix')[$this->alias] ?? [];
    }
}
