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

        $matrix = config('auth-groups.matrix');

        $matrix[$this->alias] = $permissions;

        config('auth-groups.matrix', $matrix);
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

        // Vérifier la correspondance exacte
        if (! empty($this->permissions) && in_array($permission, $this->permissions, true)) {
            return true;
        }

        // Vérifier la correspondance générique
        $check = substr($permission, 0, strpos($permission, '.')) . '.*';

        return ! empty($this->permissions) && in_array($check, $this->permissions, true);
    }

    /**
     * Charge nos autorisations pour ce groupe.
     */
    private function populatePermissions(): void
    {
        if ($this->permissions !== null) {
            return;
        }

        $this->permissions = config('auth-groups.matrix')[$this->alias] ?? [];
    }
}
