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

namespace BlitzPHP\Schild\Models;

use BlitzPHP\Schild\Entities\User;

class GroupModel extends BaseModel
{
    protected string $returnType = 'array';

    public function __construct()
    {
        parent::__construct();

        $this->table = $this->tables['groups_users'];
    }

    public function getForUser(User $user): array
    {
        $rows = $this->builder()
            ->select('group')
            ->where('user_id', $user->id)
            ->result($this->returnType);

        return array_column($rows, 'group');
    }

    /**
     * @param int|string $userId
     */
    public function deleteAll($userId): void
    {
        $return = $this->builder()
            ->where('user_id', $userId)
            ->delete();

        $this->checkQueryReturn($return);
    }

    /**
     * @param int|string $userId
     * @param mixed      $cache
     */
    public function deleteNotIn($userId, $cache): void
    {
        $return = $this->builder()
            ->where('user_id', $userId)
            ->whereNotIn('group', $cache)
            ->delete();

        $this->checkQueryReturn($return);
    }

    /**
     * @param non-empty-string $group Nom du groupe
     */
    public function isValidGroup(string $group): bool
    {
        $allowedGroups = array_keys(config('auth-groups.groups'));

        return in_array($group, $allowedGroups, true);
    }
}
