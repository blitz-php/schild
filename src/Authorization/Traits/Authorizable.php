<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace BlitzPHP\Schild\Authorization\Traits;

use BlitzPHP\Schild\Exceptions\AuthorizationException;
use BlitzPHP\Schild\Exceptions\LogicException;
use BlitzPHP\Schild\Models\GroupModel;
use BlitzPHP\Schild\Models\PermissionModel;
use BlitzPHP\Utilities\Date;

trait Authorizable
{
    protected ?array $groupCache       = null;
    protected ?array $permissionsCache = null;

    /**
     * Ajoute un ou plusieurs groupes à l'utilisateur actuel.
     */
    public function addGroup(string ...$groups): self
    {
        $this->populateGroups();

        $configGroups = $this->getConfigGroups();

        $groupCount = count($this->groupCache);

        foreach ($groups as $group) {
            $group = strtolower($group);

            // ne permettent pas dupes
            if (in_array($group, $this->groupCache, true)) {
                continue;
            }

            // assurez-vous que c'est un groupe valide
            if (! in_array($group, $configGroups, true)) {
                throw AuthorizationException::unknownGroup($group);
            }

            $this->groupCache[] = $group;
        }

        // Seulement enregistrer les résultats s'il ya quelque chose de nouveau.
        if (count($this->groupCache) > $groupCount) {
            $this->saveGroups();
        }

        return $this;
    }

    /**
     * Supprime un ou plusieurs groupes de l'utilisateur.
     */
    public function removeGroup(string ...$groups): self
    {
        $this->populateGroups();

        foreach ($groups as &$group) {
            $group = strtolower($group);
        }

        // Supprimer du cache local
        $this->groupCache = array_diff($this->groupCache, $groups);

        // Mettre à jour la base de données.
        $this->saveGroups();

        return $this;
    }

    /**
     * Compte tenu d'un tableau de groupes, va mettre à jour la base de données
     * de sorte que ces groupes sont valables pour cet utilisateur,
     * supprimant tous les groupes pas dans cette liste.
     *
     * @throws AuthorizationException
     */
    public function syncGroups(string ...$groups): self
    {
        $this->populateGroups();

        $configGroups = $this->getConfigGroups();

        foreach ($groups as $group) {
            if (! in_array($group, $configGroups, true)) {
                throw AuthorizationException::unknownGroup($group);
            }
        }

        $this->groupCache = $groups;
        $this->saveGroups();

        return $this;
    }

    /**
     * Retourne tous les groupes auxquels cet utilisateur fait partie.
     */
    public function getGroups(): ?array
    {
        $this->populateGroups();

        return $this->groupCache;
    }

    /**
     * Retourn toutes les autorisations que cet utilisateur leur a attribuées directement.
     */
    public function getPermissions(): ?array
    {
        $this->populatePermissions();

        return $this->permissionsCache;
    }

    /**
     * Ajoute une ou plusieurs autorisations à l'utilisateur actuel.
     *
     * @throws AuthorizationException
     */
    public function addPermission(string ...$permissions): self
    {
        $this->populatePermissions();

        $configPermissions = $this->getConfigPermissions();

        $permissionCount = count($this->permissionsCache);

        foreach ($permissions as $permission) {
            $permission = strtolower($permission);

            // ne permettent pas dupes
            if (in_array($permission, $this->permissionsCache, true)) {
                continue;
            }

            // assurez-vous que c'est une permission valide
            if (! in_array($permission, $configPermissions, true)) {
                throw AuthorizationException::unknownPermission($permission);
            }

            $this->permissionsCache[] = $permission;
        }

        // Seulement enregistrer les résultats s'il ya quelque chose de nouveau.
        if (count($this->permissionsCache) > $permissionCount) {
            $this->savePermissions();
        }

        return $this;
    }

    /**
     * Supprime une ou plusieurs autorisations de l'utilisateur actuel.
     */
    public function removePermission(string ...$permissions): self
    {
        $this->populatePermissions();

        foreach ($permissions as &$permission) {
            $permission = strtolower($permission);
        }

        // Supprimer du cache local
        $this->permissionsCache = array_diff($this->permissionsCache, $permissions);

        // Mettre à jour la base de données.
        $this->savePermissions();

        return $this;
    }

    /**
     * Compte tenu d'un tableau d'autorisations, va mettre à jour la base de données
     * de sorte que ces autorisations sont valides pour cet utilisateur,
     * supprimant toutes les autorisations pas dans cette liste.
     *
     * @throws AuthorizationException
     */
    public function syncPermissions(string ...$permissions): self
    {
        $this->populatePermissions();

        $configPermissions = $this->getConfigPermissions();

        foreach ($permissions as $permission) {
            if (! in_array($permission, $configPermissions, true)) {
                throw AuthorizationException::unknownPermission($permission);
            }
        }

        $this->permissionsCache = $permissions;
        $this->savePermissions();

        return $this;
    }

    /**
     * Vérifie si l'utilisateur dispose de l'autorisation définie directement sur lui-même.
     * Cela ne tient pas compte des groupes dont il fait partie.
     */
    public function hasPermission(string $permission): bool
    {
        $this->populatePermissions();

        $permission = strtolower($permission);

        return in_array($permission, $this->permissionsCache, true);
    }

    /**
     * Vérifie les autorisations d'utilisateur et leurs autorisations de groupe
     * pour voir si l'utilisateur dispose d'une autorisation spécifique.
     *
     * @param string $permission chaînes composées d'une portée et d'une action, comme les users.create
     */
    public function can(string ...$permissions): bool
    {
        // Obtenez les autorisations de l'utilisateur et stockez-les dans le cache
        $this->populatePermissions();

        // Vérifiez les groupes auxquels l'utilisateur appartient
        $this->populateGroups();
        
        foreach ($permissions as $permission) {
            // L'autorisation doit contenir une portée et une action
            if (strpos($permission, '.') === false) {
                throw new LogicException(
                    'Une autorisation doit être une chaîne composée d\'une portée et d\'une action, comme `users.create`.'
                    . ' Autorisation non valide: ' . $permission
                );
            }

            $permission = strtolower($permission);

            // Vérifier les autorisations de l'utilisateur
            if (in_array($permission, $this->permissionsCache, true)) {
                return true;
            }

            if (! count($this->groupCache)) {
                return false;
            }

            $matrix = config('auth-groups.matrix');

            foreach ($this->groupCache as $group) {
                // Vérifier correspondance exacte
                if (isset($matrix[$group]) && in_array($permission, $matrix[$group], true)) {
                    return true;
                }

                // Vérifier match joker
                $check = substr($permission, 0, strpos($permission, '.')) . '.*';
                if (isset($matrix[$group]) && in_array($check, $matrix[$group], true)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Vérifie si l'utilisateur est membre d'un des groupes donnés.
     */
    public function inGroup(string ...$groups): bool
    {
        $this->populateGroups();

        foreach ($groups as $group) {
            if (in_array(strtolower($group), $this->groupCache, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Utilisé en interne pour peupler les groupes d'utilisateurs
     * afin que nous ayons a requeter la base de données aussi peu que possible.
     */
    private function populateGroups(): void
    {
        if (is_array($this->groupCache)) {
            return;
        }

        /** @var GroupModel $groupModel */
        $groupModel = model(GroupModel::class);

        $this->groupCache = $groupModel->getForUser($this);
    }

    /**
     * Utilisé en interne pour remplir les autorisations d'utilisateur
     * afin que nous ayons a requeter la base de données aussi peu que possible.
     */
    private function populatePermissions(): void
    {
        if (is_array($this->permissionsCache)) {
            return;
        }

        /** @var PermissionModel $permissionModel */
        $permissionModel = model(PermissionModel::class);

        $this->permissionsCache = $permissionModel->getForUser($this);
    }

    /**
     * Insertion ou Mises à jour des groupes actuelles.
     */
    private function saveGroups(): void
    {
        /** @var GroupModel $model */
        $model = model(GroupModel::class);

        $cache = $this->groupCache;

        $this->saveGroupsOrPermissions('group', $model, $cache);
    }

    /**
     * Insertion ou Mises à jour des autorisations actuelles.
     */
    private function savePermissions(): void
    {
        /** @var PermissionModel $model */
        $model = model(PermissionModel::class);

        $cache = $this->permissionsCache;

        $this->saveGroupsOrPermissions('permission', $model, $cache);
    }

    /**
     * @phpstan-param 'group'|'permission' $type
     * @param GroupModel|PermissionModel $model
     */
    private function saveGroupsOrPermissions(string $type, $model, array $cache): void
    {
        $existing = $model->getForUser($this);

        $new = array_diff($cache, $existing);

        // Supprimer n'importe quel pas dans le cache
        if ($cache !== []) {
            $model->deleteNotIn($this->id, $cache);
        }
        // Rien dans le cache ? alors, s'assurer que nous supprimons tous de cet utilisateur
        else {
            $model->deleteAll($this->id);
        }

        // Insérez les nouveaux
        if ($new !== []) {
            $inserts = [];

            foreach ($new as $item) {
                $inserts[] = [
                    'user_id'    => $this->id,
                    $type        => $item,
                    'created_at' => Date::now()->format('Y-m-d H:i:s'),
                ];
            }

            $model->bulckInsert($inserts);
        }
    }

    /**
     * @return string[]
     */
    private function getConfigGroups(): array
    {
        return array_keys(config('auth-groups.groups'));
    }

    /**
     * @return string[]
     */
    private function getConfigPermissions(): array
    {
        return array_keys(config('auth-groups.permissions'));
    }
}
