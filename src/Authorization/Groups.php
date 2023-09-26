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

namespace BlitzPHP\Schild\Authorization;

use BlitzPHP\Schild\Entities\Group;
use BlitzPHP\Schild\Exceptions\RuntimeException;

/**
 * Fournit des fonctionnalités utilitaires pour travailler avec des groupes, ajouter des autorisations, etc.
 */
class Groups
{
    /**
     * Attrapes une info de groupe des paramètres.
     */
    public function info(string $group): ?Group
    {
        $info = config('auth-groups.groups')[strtolower($group)] ?? null;

        if (empty($info)) {
            return null;
        }

        $info['alias'] = $group;

        return new Group($info);
    }

    /**
     * Enregistre ou crée le groupe.
     */
    public function save(Group $group): void
    {
        if (empty($group->title)) {
            throw new RuntimeException(lang('Auth.missingTitle'));
        }

        $groups = config('auth-groups.groups');

        $alias = $group->alias;

        if (empty($alias)) {
            $alias = strtolower(url_title($group->title));
        }

        $groups[$alias] = [
            'title'       => $group->title,
            'description' => $group->description,
        ];

        // Save it
        config('auth-groups.groups', $groups);
    }
}
