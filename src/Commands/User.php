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

namespace BlitzPHP\Schild\Commands;

use BlitzPHP\Cli\Console\Command;
use BlitzPHP\Database\Builder\BaseBuilder;
use BlitzPHP\Schild\Authentication\Authenticators\Session;
use BlitzPHP\Schild\Commands\Exceptions\BadInputException;
use BlitzPHP\Schild\Commands\Exceptions\CancelException;
use BlitzPHP\Schild\Entities\User as UserEntity;
use BlitzPHP\Schild\Exceptions\UserNotFoundException;
use BlitzPHP\Schild\Exceptions\ValidationException;
use BlitzPHP\Schild\Models\GroupModel;
use BlitzPHP\Schild\Validation\ValidationRules;
use BlitzPHP\Validation\Validator;
use PDO;

class User extends Command
{
    protected string $group       = 'Schild';
    protected string $name        = 'schild:user';
    protected string $description = 'Gérer les utilisateurs de Schild.';
    protected string $usage       = <<<'EOL'
        schild:user <action> options

            schild:user create -n newusername -e newuser@example.com

            schild:user activate -n username
            schild:user activate -e user@example.com

            schild:user deactivate -n username
            schild:user deactivate -e user@example.com

            schild:user changename -n username --new-name newusername
            schild:user changename -e user@example.com --new-name newusername

            schild:user changeemail -n username --new-email newuseremail@example.com
            schild:user changeemail -e user@example.com --new-email newuseremail@example.com

            schild:user delete -i 123
            schild:user delete -n username
            schild:user delete -e user@example.com

            schild:user password -n username
            schild:user password -e user@example.com

            schild:user list
            schild:user list -n username -e user@example.com

            schild:user addgroup -n username -g mygroup
            schild:user addgroup -e user@example.com -g mygroup

            schild:user removegroup -n username -g mygroup
            schild:user removegroup -e user@example.com -g mygroup
        EOL;
    protected array $arguments = [
        'action' => <<<'EOL'

                create:      Créer un nouvel utilisateur
                activate:    Activer un utilisateur
                deactivate:  Désactiver un utilisateur
                changename:  Changer le nom d'utilisateur
                changeemail: Changer l'e-mail de l'utilisateur
                delete:      Supprimer un utilisateur
                password:    Changer un mot de passe utilisateur
                list:        Liste des utilisateurs
                addgroup:    Ajouter un utilisateur à un groupe
                removegroup: Supprimer un utilisateur d'un groupe
            EOL,
    ];
    protected array $options = [
        '-i'          => 'ID de l\'utilisateur',
        '-n'          => 'Nom de l\'utilisateur',
        '-e'          => 'Email de l\'utilisateur',
        '--new-name'  => 'Nouveau nom d\'utilisateur',
        '--new-email' => 'Nouvel email de l\'utilisateur',
        '-g'          => 'Nom du groupe',
    ];
    private array $validActions = [
        'create', 'activate', 'deactivate', 'changename', 'changeemail',
        'delete', 'password', 'list', 'addgroup', 'removegroup',
    ];

    /**
     * Règles de validation des champs utilisateur
     */
    private array $validationRules = [];

    /**
     * Noms des tables d'authentification
     *
     * @var array<string, string>
     */
    private array $tables = [];

    /**
     * {@inheritDoc}
     */
    public function handle()
    {
        $this->setTables();
        $this->setValidationRules();

        $action = $this->argument('action');

        if ($action === null || ! in_array($action, $this->validActions, true)) {
            $this->fail('Indiquez une action valide: ' . implode(',', $this->validActions));

            return EXIT_ERROR;
        }

        $userid      = (int) $this->option('i', 0);
        $username    = $this->option('n');
        $email       = $this->option('e');
        $newUsername = $this->option('new-name');
        $newEmail    = $this->option('new-email');
        $group       = $this->option('g');

        try {
            switch ($action) {
                case 'create':
                    $this->create($username, $email, $group);
                    break;

                case 'activate':
                    $this->activate($username, $email);
                    break;

                case 'deactivate':
                    $this->deactivate($username, $email);
                    break;

                case 'changename':
                    $this->changename($username, $email, $newUsername);
                    break;

                case 'changeemail':
                    $this->changeemail($username, $email, $newEmail);
                    break;

                case 'delete':
                    $this->delete($userid, $username, $email);
                    break;

                case 'password':
                    $this->password($username, $email);
                    break;

                case 'list':
                    $this->list($username, $email);
                    break;

                case 'addgroup':
                    $this->addgroup($group, $username, $email);
                    break;

                case 'removegroup':
                    $this->removegroup($group, $username, $email);
                    break;
            }
        } catch (BadInputException|CancelException|UserNotFoundException $e) {
            $this->fail($e->getMessage());

            return EXIT_ERROR;
        }

        return EXIT_SUCCESS;
    }

    private function setTables(): void
    {
        $this->tables = config('auth.tables');
    }

    private function setValidationRules(): void
    {
        $validationRules = ValidationRules::register();
        $rules           = $validationRules['rules'];

        $this->validationRules = $rules;
    }

    /**
     * Créer un nouvel utilisateur
     *
     * @param string|null $username Nom d'utilisateur à créer (facultatif)
     * @param string|null $email    E-mail de l'utilisateur à créer (facultatif)
     * @param string|null $group    Groupe auquel ajouter l'utilisateur après sa création (facultatif)
     */
    private function create(?string $username = null, ?string $email = null, ?string $group = null): void
    {
        $data = [];

        if ($username === null && isset($this->validationRules['username'])) {
            $username = $this->prompt(lang('Auth.username'), null, function ($value) {
                $v = Validator::make(
                    ['username' => $value],
                    ['username' => $this->validationRules['username']],
                );
                if ($v->fails()) {
                    throw new ValidationException($v->errors()->first('username'));
                }

                return $value;
            });
        }

        if ($email === null) {
            $email = $this->prompt(lang('Auth.email'), null, function ($value) {
                $v = Validator::make(
                    ['email' => $value],
                    ['email' => $this->validationRules['email']],
                );
                if ($v->fails()) {
                    throw new ValidationException($v->errors()->first('email'));
                }

                return $value;
            });
        }

        $password = $this->prompt(lang('Auth.password'), null, function ($value) {
            $v = Validator::make(
                ['password' => $value],
                ['password' => $this->validationRules['password']],
            );
            if ($v->fails()) {
                throw new ValidationException($v->errors()->first('password'));
            }

            return $value;
        });

        $passwordConfirm = $this->prompt(lang('Auth.passwordConfirm'), null, function ($value) use ($password) {
            $v = Validator::make(
                ['password_confirmation' => $value, 'password' => $password],
                ['password_confirmation' => $this->validationRules['password_confirmation']],
            );
            if ($v->fails()) {
                throw new ValidationException($v->errors()->first('password_confirmation'));
            }

            return $value;
        });

        $data = array_filter([
            'username'              => $username,
            'email'                 => $email,
            'password'              => $password,
            'password_confirmation' => $passwordConfirm,
        ]);

        // Run validation if the user has passed username and/or email via command line
        if ($data !== []) {
            $v = Validator::make($data, $this->validationRules);
            if ($v->fails()) {
                foreach ($v->errors()->all() as $message) {
                    $this->error($message);
                }

                throw new CancelException('User creation aborted');
            }
        }

        unset($data['password_confirmation']);

		$userModel = auth()->getProvider();

        $user = $userModel->newUserEntity($data);

        // Validate the group
        if ($group !== null && ! $this->validateGroup($group)) {
            throw new CancelException('Invalid group: "' . $group . '"');
        }

        if ($username === null) {
            $userModel->save($user);
            $this->success('New User created');
        } else {
            $userModel->save($user);
            $this->success('User "' . $username . '" created');
        }

        $user = $userModel->findById($userModel->lastInsertId());

        if ($group === null) {
            // Ajouter l'utilisateur au groupe par défaut
            $userModel->addToDefaultGroup($user);

            $this->success('The user is added to the default group.');
        } else {
            $user->addGroup($group);

            $this->success('The user is added to group "' . $group . '".');
        }
    }

    private function validateGroup(string $group): bool
    {
        $groupModel = model(GroupModel::class);

        return $groupModel->isValidGroup($group);
    }

    /**
     * Activate an existing user by username or email
     *
     * @param string|null $username User name to search for (optional)
     * @param string|null $email    User email to search for (optional)
     */
    private function activate(?string $username = null, ?string $email = null): void
    {
        $user = $this->findUser('Activate user', $username, $email);

        if ($this->confirm('Activate the user ' . $user->username . ' ?')) {
            $userModel = auth()->getProvider();

            $userModel->modify($user->id, ['active' => 1]);

            $this->success('User "' . $user->username . '" activated');
        } else {
            $this->warning('User "' . $user->username . '" activation cancelled');
        }
    }

    /**
     * Deactivate an existing user by username or email
     *
     * @param string|null $username User name to search for (optional)
     * @param string|null $email    User email to search for (optional)
     */
    private function deactivate(?string $username = null, ?string $email = null): void
    {
        $user = $this->findUser('Deactivate user', $username, $email);

        if ($this->confirm('Deactivate the user ' . $user->username . ' ?')) {
            $userModel = auth()->getProvider();

            $userModel->modify($user->id, ['active' => 0]);

            $this->success('User "' . $user->username . '" deactivated');
        } else {
            $this->warning('User "' . $user->username . '" deactivation cancelled');
        }
    }

    /**
     * Change the name of an existing user by username or email
     *
     * @param string|null $username    User name to search for (optional)
     * @param string|null $email       User email to search for (optional)
     * @param string|null $newUsername User new name (optional)
     */
    private function changename(
        ?string $username = null,
        ?string $email = null,
        ?string $newUsername = null,
    ): void {
        $user = $this->findUser('Change username', $username, $email);

        if ($newUsername === null) {
            $newUsername = $this->prompt('New username');
        }

        $v = Validator::make(
            ['username' => $newUsername],
            ['username' => $this->validationRules['username']],
        );
        if ($v->fails()) {
            foreach ($v->errors()->all() as $message) {
                $this->error($message);
            }

            throw new CancelException('User name change aborted');
        }

		$userModel = auth()->getProvider();

        $oldUsername = $user->username;
        $userModel->modify($user->id, ['username' => $newUsername]);

        $this->success('Username "' . $oldUsername . '" changed to "' . $newUsername . '"');
    }

    /**
     * Change the email of an existing user by username or email
     *
     * @param string|null $username User name to search for (optional)
     * @param string|null $email    User email to search for (optional)
     * @param string|null $newEmail User new email (optional)
     */
    private function changeemail(
        ?string $username = null,
        ?string $email = null,
        ?string $newEmail = null,
    ): void {
        $user = $this->findUser('Change email', $username, $email);

        if ($newEmail === null) {
            $newEmail = $this->prompt('New email');
        }

        $v = Validator::make(
            ['email' => $newEmail],
            ['email' => $this->validationRules['email']],
        );
        if ($v->fails()) {
            foreach ($v->errors()->all() as $message) {
                $this->error($message);
            }

            throw new CancelException('User email change aborted');
        }

		$userModel = auth()->getProvider();

        $user->setEmail($newEmail);
        $userModel->save($user);

        $this->success('Email for "' . $user->username . '" changed to ' . $newEmail);
    }

    /**
     * Delete an existing user by username or email
     *
     * @param int         $userid   User id to delete (optional)
     * @param string|null $username User name to search for (optional)
     * @param string|null $email    User email to search for (optional)
     */
    private function delete(int $userid = 0, ?string $username = null, ?string $email = null): void
    {
        $userModel = auth()->getProvider();

        if ($userid !== 0) {
            $user = $userModel->findById($userid);

            $this->checkUserExists($user);
        } else {
            $user = $this->findUser('Delete user', $username, $email);
        }

        if ($this->confirm('Delete the user "' . $user->username . '" (' . $user->email . ') ?')) {
            $userModel->remove($user->id, true);

            $this->success('User "' . $user->username . '" deleted');
        } else {
            $this->warning('User "' . $user->username . '" deletion cancelled');
        }
    }

    /**
     * @param UserEntity|null $user
     */
    private function checkUserExists($user): void
    {
        if ($user === null) {
            throw new UserNotFoundException("User doesn't exist");
        }
    }

    /**
     * Change the password of an existing user by username or email
     *
     * @param string|null $username User name to search for (optional)
     * @param string|null $email    User email to search for (optional)
     */
    private function password($username = null, $email = null): void
    {
        $user = $this->findUser('Change user password', $username, $email);

        if ($this->confirm('Set the password for "' . $user->username . '" ?')) {
            $password = $this->prompt(lang('Auth.password'), null, function ($value) {
                $v = Validator::make(
                    ['password' => $value],
                    ['password' => $this->validationRules['password']],
                );
                if ($v->fails()) {
                    throw new ValidationException($v->errors()->first('password'));
                }

                return $value;
            });

            $this->prompt(lang('Auth.passwordConfirm'), null, function ($value) use ($password) {
                $v = Validator::make(
                    ['password_confirmation' => $value, 'password' => $password],
                    ['password_confirmation' => $this->validationRules['password_confirmation']],
                );
                if ($v->fails()) {
                    throw new ValidationException($v->errors()->first('password_confirmation'));
                }

                return $value;
            });

            $userModel = auth()->getProvider();

            $user->password = $password;
            $userModel->save($user);

            $this->success('Password for "' . $user->username . '" set');
        } else {
            $this->warning('Password setting for "' . $user->username . '" cancelled');
        }
    }

    /**
     * List users searching by username or email
     *
     * @param string|null $username User name to search for (optional)
     * @param string|null $email    User email to search for (optional)
     */
    private function list(?string $username = null, ?string $email = null): void
    {
		$userModel = auth()->getProvider()->asArray();

        $userModel
            ->select($this->tables['users'] . '.id as id, username, secret as email')
            ->leftJoin(
                $this->tables['identities'],
                $this->tables['users'] . '.id',
                '=',
                $this->tables['identities'] . '.user_id',
            )
            ->where(function (BaseBuilder $query): void {
                $query->where($this->tables['identities'] . '.type', Session::ID_TYPE_EMAIL_PASSWORD)
                    ->orWhereNull($this->tables['identities'] . '.type');
            });

        if ($username !== null) {
            $userModel->like('username', $username);
        }
        if ($email !== null) {
            $userModel->like('secret', $email);
        }

        $this->write("Id\tUser");

        foreach ($userModel->findAll() as $user) {
            $this->eol()->write($user['id'] . "\t" . $user['username'] . ' (' . $user['email'] . ')');
        }
    }

    /**
     * Add a user by username or email to a group
     *
     * @param string|null $group    Group to add user to
     * @param string|null $username User name to search for (optional)
     * @param string|null $email    User email to search for (optional)
     */
    private function addgroup($group = null, $username = null, $email = null): void
    {
        if ($group === null) {
            $group = $this->prompt('Group');
        }

        $user = $this->findUser('Add user to group', $username, $email);

        if ($this->confirm('Add the user "' . $user->username . '" to the group "' . $group . '" ?')) {
            $user->addGroup($group);

            $this->success('User "' . $user->username . '" added to group "' . $group . '"');
        } else {
            $this->warning(
                'Addition of the user "' . $user->username . '" to the group "' . $group . '" cancelled',
            );
        }
    }

    /**
     * Remove a user by username or email from a group
     *
     * @param string|null $group    Group to remove user from
     * @param string|null $username User name to search for (optional)
     * @param string|null $email    User email to search for (optional)
     */
    private function removegroup($group = null, $username = null, $email = null): void
    {
        if ($group === null) {
            $group = $this->prompt('Group');
        }

        $user = $this->findUser('Remove user from group', $username, $email);

        if ($this->confirm('Remove the user "' . $user->username . '" from the group "' . $group . '" ?')) {
            $user->removeGroup($group);

            $this->success('User "' . $user->username . '" removed from group "' . $group . '"');
        } else {
            $this->warning('Removal of the user "' . $user->username . '" from the group "' . $group . '" cancelled');
        }
    }

    /**
     * Find an existing user by username or email.
     *
     * @param string      $question Initial question at user prompt
     * @param string|null $username User name to search for (optional)
     * @param string|null $email    User email to search for (optional)
     */
    private function findUser(string $question = '', ?string $username = null, ?string $email = null): UserEntity
    {
        if ($username === null && $email === null) {
            $choice = $this->choice($question . ' par nom d\'utilisateur ou email ?', ['u', 'e']);

            if ($choice === 'u') {
                $username = $this->prompt('Nom d\'utilisateur');
            } elseif ($choice === 'e') {
                $email = $this->prompt('Email');
            }
        }

        $userModel = auth()->getProvider();

        $userModel->select($this->tables['users'] . '.id as id, username, secret')
            ->leftJoin(
                $this->tables['identities'],
                $this->tables['users'] . '.id',
                '=',
                $this->tables['identities'] . '.user_id',
            )
            ->where(function (BaseBuilder $query): void {
                $query->where($this->tables['identities'] . '.type', Session::ID_TYPE_EMAIL_PASSWORD)
                    ->orWhereNull($this->tables['identities'] . '.type');
            });

        $user = null;
        if ($username !== null) {
            $user = $userModel->where('username', $username)->first(PDO::FETCH_ASSOC);
        } elseif ($email !== null) {
            $user = $userModel->where('secret', $email)->first(PDO::FETCH_ASSOC);
        }

        $this->checkUserExists($user);

        return $userModel->findById($user['id']);
    }
}
