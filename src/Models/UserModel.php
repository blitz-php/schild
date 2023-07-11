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

use BlitzPHP\Database\Exceptions\DataException;
use BlitzPHP\Schild\Authentication\Authenticators\Session;
use BlitzPHP\Schild\Entities\User;
use BlitzPHP\Schild\Entities\UserIdentity;
use BlitzPHP\Schild\Exceptions\InvalidArgumentException;
use BlitzPHP\Schild\Exceptions\ValidationException;
use BlitzPHP\Utilities\Date;
use PDO;

/**
 * @phpstan-consistent-constructor
 */
class UserModel extends BaseModel
{
    protected string $returnType   = User::class;
    protected array $afterFind     = ['fetchIdentities'];
    protected array $afterInsert   = ['saveEmailIdentity'];
    protected array $afterUpdate   = ['saveEmailIdentity'];

    /**
     * Whether identity records should be included
     * when user records are fetched from the database.
     */
    protected bool $fetchIdentities = false;

    /**
     * Save the User for afterInsert and afterUpdate
     */
    protected ?User $tempUser = null;

    public function __construct()
    {
        parent::__construct();

        $this->table = $this->tables['users'];
    }

    /**
     * Mark the next find* query to include identities
     */
    public function withIdentities(): self
    {
        $this->fetchIdentities = true;

        return $this;
    }

    /**
     * Populates identities for all records returned from a find* method. 
     * Called automatically when $this->fetchIdentities == true
     *
     * Model event callback called by `afterFind`.
     */
    protected function fetchIdentities(array $data): array
    {
        if (! $this->fetchIdentities) {
            return $data;
        }

        $userIds = $data['singleton']
            ? array_column($data, 'id')
            : array_column($data['data'], 'id');

        if ($userIds === []) {
            return $data;
        }

        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        // Get our identities for all users
        $identities = $identityModel->getIdentitiesByUserIds($userIds);

        if (empty($identities)) {
            return $data;
        }

        $mappedUsers = $this->assignIdentities($data, $identities);

        $data['data'] = $data['singleton'] ? $mappedUsers[$data['id']] : $mappedUsers;

        return $data;
    }

    /**
     * Map our users by ID to make assigning simpler
     *
     * @param array          $data       Event $data
     * @param UserIdentity[] $identities
     *
     * @return User[] UserId => User object
     * @phpstan-return array<int|string, User> UserId => User object
     */
    private function assignIdentities(array $data, array $identities): array
    {
        $mappedUsers = [];

        $users = $data['singleton'] ? [$data['data']] : $data['data'];

        foreach ($users as $user) {
            $mappedUsers[$user->id] = $user;
        }
        unset($users);

        // Now assign the identities to the user
        foreach ($identities as $identity) {
            $userId = $identity->user_id;

            $newIdentities   = $mappedUsers[$userId]->identities;
            $newIdentities[] = $identity;

            $mappedUsers[$userId]->identities = $newIdentities;
        }

        return $mappedUsers;
    }

    /**
     * Adds a user to the default group.
     * Used during registration.
     */
    public function addToDefaultGroup(User $user): void
    {
        $defaultGroup  = config('auth-groups.default_group');
        $allowedGroups = array_keys(config('auth-groups.groups'));

        if (empty($defaultGroup) || ! in_array($defaultGroup, $allowedGroups, true)) {
            throw new InvalidArgumentException(lang('Auth.unknownGroup', [$defaultGroup ?? '--not found--']));
        }

        $user->addGroup($defaultGroup);
    }

    /**
     * Localise un objet Utilisateur par ID.
     *
     * @param int|string $id
     */
    public function findById($id): ?User
    {
        return $this->select([$this->tables['users'] . '.*', $this->tables['identities'] . '.secret As email'])
            ->where([$this->tables['users'] . '.id' => $id])
            ->join($this->tables['identities'], [$this->tables['users'] . '.id' => $this->tables['identities'] . '.user_id'])
            ->first($this->returnType);
    }

    /**
     * Localisez un objet Utilisateur par les informations d'identification données.
     *
     * @param array<string, string> $credentials
     */
    public function findByCredentials(array $credentials): ?User
    {
        // Le courrier électronique est stocké dans une identité, alors supprimez-le ici
        $email = $credentials['email'] ?? null;
        unset($credentials['email']);

        if ($email === null && $credentials === []) {
            return null;
        }

        // toutes les informations d'identification utilisées doivent être insensibles à la casse
        foreach ($credentials as $key => $value) {
            $this->where(
                'LOWER(' . $this->table . ".{$key})",
                strtolower($value)
            );
        }

        if ($email !== null) {
            $data = $this->select([
                $this->table . '.*',
                $this->tables['identities'] . '.secret As email',
                $this->tables['identities'] . '.secret2 As password_hash',
            ])
                ->join($this->tables['identities'], [$this->tables['identities'] . '.user_id' => $this->table . '.id'])
                ->where($this->tables['identities'] . '.type', Session::ID_TYPE_EMAIL_PASSWORD)
                ->where(
                    'LOWER(' . $this->tables['identities'] . '.secret)',
                    strtolower($email)
                )
                ->first(PDO::FETCH_ASSOC);

            if ($data === null) {
                return null;
            }

            $email = $data['email'];
            unset($data['email']);
            $password_hash = $data['password_hash'];
            unset($data['password_hash']);
            $id = $data['id'];
            unset($data['id']);

            $className           = $this->returnType;
            $user                = new $className($data);
            $user->id            = $id;
            $user->email         = $email;
            $user->password_hash = $password_hash;
            $user->syncOriginal();

            return $user;
        }

        return $this->first($this->returnType);
    }

    /**
     * Activer un utilisateur.
     */
    public function activate(User $user): void
    {
        $user->active = true;

        $this->save($user);
    }

    /**
     *Remplacez la méthode `insert()` du BaseModel.
     * Si vous passez l'objet Utilisateur, insère également l'identité de l'e-mail.
     *
     * @param array|User $data
     *
     * @return int|string|true Insert ID if $returnID is true
     *
     * @throws ValidationException
     */
    public function insert($data = null, bool $returnID = true)
    {
        // Clone User object pour ne pas modifier l'objet passé.
        $this->tempUser = $data instanceof User ? clone $data : null;

        $result = parent::insert($data, true);

        $this->checkQueryReturn($result);

        return $returnID ? $this->insertID() : $result;
    }

    /**
     * Override the BaseModel's `update()` method.
     * If you pass User object, also updates Email Identity.
     *
     * @param array|int|string|null $id
     * @param array|User            $data
     *
     * @return true if the update is successful
     *
     * @throws ValidationException
     */
    public function update2($id = null, $data = null): bool
    {
        // Clone User object for not changing the passed object.
        $this->tempUser = $data instanceof User ? clone $data : null;

        try {
            /** @throws DataException */
            $result = parent::where(['id' => $id])->update($data);
        } catch (DataException $e) {
            // When $data is an array.
            if ($this->tempUser === null) {
                throw $e;
            }

            $messages = [
                lang('Database.emptyDataset', ['update']),
            ];

            if (in_array($e->getMessage(), $messages, true)) {
                $this->tempUser->saveEmailIdentity();

                return true;
            }

            throw $e;
        }

        $this->checkQueryReturn($result);

        return true;
    }

    /**
     * Override the BaseModel's `save()` method.
     * If you pass User object, also updates Email Identity.
     *
     * @param array|User $data
     *
     * @return true if the save is successful
     *
     * @throws ValidationException
     */
    public function save($data): bool
    {
        $result = parent::save($data);

        $this->checkQueryReturn($result);

        return true;
    }

    /**
     * Save Email Identity
     *
     * Model event callback called by `afterInsert` and `afterUpdate`.
     */
    protected function saveEmailIdentity(array $data): array
    {
        // If insert()/update() gets an array data, do nothing.
        if ($this->tempUser === null) {
            return $data;
        }

        // Insert
        if ($this->tempUser->id === null) {
            /** @var User $user */
            $user = $this->find($this->db->insertID());

            // If you get identity (email/password), the User object must have the id.
            $this->tempUser->id = $user->id;

            $user->email         = $this->tempUser->email ?? '';
            $user->password      = $this->tempUser->password ?? '';
            $user->password_hash = $this->tempUser->password_hash ?? '';

            $user->saveEmailIdentity();
            $this->tempUser = null;

            return $data;
        }

        // Update
        $this->tempUser->saveEmailIdentity();
        $this->tempUser = null;

        return $data;
    }

    /**
     * Met à jour la dernière date active de l'utilisateur.
     */
    public function updateActiveDate(User $user): void
    {
        assert($user->last_active instanceof Date);

        // Chaîne de date sûre pour la base de données
        $last_active = $user->last_active->format('Y-m-d H:i:s');

        $this->builder()
            ->where('id', $user->id)
            ->update(['last_active' => $last_active]);
    }
}
