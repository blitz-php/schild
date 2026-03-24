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
    /**
     * {@inheritDoc}
     */
    protected string $returnType = 'array';

    /**
     * {@inheritDoc}
     */
    protected $fillable = ['user_id', 'group', 'created_at'];

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
            ->result('array');

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
        $allowedGroups = array_keys(parametre('auth-groups.groups'));

        return in_array($group, $allowedGroups, true);
    }

    /**
     * @param list<int>|list<string> $userIds
     *
     * @return array<int, array>
     */
    public function getGroupsByUserIds(array $userIds): array
    {
        $groups = $this->builder()
            ->select('user_id, group')
            ->whereIn('user_id', $userIds)
            ->orderBy($this->primaryKey)
            ->result('array');

        return array_map(
            array_keys(...),
            array_reduce($groups, static function ($carry, $item) {
                $carry[$item['user_id']][$item['group']] = true;

                return $carry;
            }, []),
        );
    }
}
