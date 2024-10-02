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

use BlitzPHP\Schild\Authentication\Authenticators\Session;
use BlitzPHP\Schild\Authentication\Traits\HasAccessTokens;
use BlitzPHP\Schild\Authentication\Traits\HasHmacTokens;
use BlitzPHP\Schild\Authorization\Traits\Authorizable;
use BlitzPHP\Schild\Config\Services;
use BlitzPHP\Schild\Models\LoginModel;
use BlitzPHP\Schild\Models\UserIdentityModel;
use BlitzPHP\Schild\Traits\Activatable;
use BlitzPHP\Schild\Traits\Bannable;
use BlitzPHP\Schild\Traits\Resettable;
use BlitzPHP\Wolke\SoftDeletes;

/**
 * @property string|null         $email
 * @property int|string|null     $id
 * @property UserIdentity[]|null $identities
 * @property Date|null           $last_active
 * @property string|null         $password
 * @property string|null         $password_hash
 * @property string|null         $username
 */
class User extends Entity
{
    use Authorizable;
    use HasAccessTokens;
    use HasHmacTokens;
    use Resettable;
    use Activatable;
    use Bannable;
    use SoftDeletes;

    /**
     * @var UserIdentity[]|null
     */
    private ?array $identities = null;

    public ?string $email = null;

    /**
     * @var string[]
     * @phpstan-var list<string>
     * @psalm-var list<string>
     */
    protected $dates = [
        'created_at',
        'updated_at',
        'deleted_at',
        'last_active',
    ];

    /**
     * {@inheritDoc}
     *
     * @var array<string, string>
     */
    protected array $casts = [
        'id'          => '?integer',
        'active'      => 'boolean',
        'permissions' => 'array',
        'groups'      => 'array',
    ];

    protected array $fillable = [
        'username',
    ];

    /**
     * {@inheritDoc}
     *
     * @internal
     */
    public function getTable(): string
    {
        return config('auth.tables')[$this->authTables[self::class]] ?: parent::getTable();
    }

    /**
     * {@inheritDoc}
     *
     * @internal
     */
    protected function getAttributesForInsert(): array
    {
        return $this->beforeUpdate(parent::getAttributesForInsert());
    }

    /**
     * {@inheritDoc}
     *
     * @internal
     */
    protected function beforeUpdate(array $attributes): array
    {
        unset($attributes['password'], $attributes['password_hash']);

        return $attributes;
    }

    public function authIdentities()
    {
        return $this->hasOne(UserIdentity::class)->where('type', Session::ID_TYPE_EMAIL_PASSWORD);
    }

    /**
     * Returns the first identity of the given $type for this user.
     *
     * @param string $type See const ID_TYPE_* in Authenticator.
     *                     'email_2fa'|'email_activate'|'email_password'|'magic-link'|'access_token'
     */
    public function getIdentity(string $type): ?UserIdentity
    {
        $identities = $this->getIdentities($type);

        return count($identities) ? array_shift($identities) : null;
    }

    /**
     * ensures that all of the user's identities are loaded
     * into the instance for faster access later.
     */
    private function populateIdentities(): void
    {
        if ($this->identities === null) {
            /** @var UserIdentityModel $identityModel */
            $identityModel = model(UserIdentityModel::class);

            $this->identities = $identityModel->getIdentities($this);
        }
    }

    /**
     * Accessor method for this user's UserIdentity objects.
     * Will populate if they don't exist.
     *
     * @param string $type 'all' returns all identities.
     *
     * @return UserIdentity[]
     */
    public function getIdentities(string $type = 'all'): array
    {
        $this->populateIdentities();

        if ($type === 'all') {
            return $this->identities;
        }

        $identities = [];

        foreach ($this->identities as $identity) {
            if ($identity->type === $type) {
                $identities[] = $identity;
            }
        }

        return $identities;
    }

    public function setIdentities(array $identities): void
    {
        $this->identities = $identities;
    }

    /**
     * Creates a new identity for this user with an email/password
     * combination.
     *
     * @phpstan-param array{email: string, password: string} $credentials
     */
    public function createEmailIdentity(array $credentials): void
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        $identityModel->createEmailIdentity($this, $credentials);

        // Ensure we will reload all identities
        $this->identities = null;
    }

    /**
     * Returns the user's Email/Password identity.
     */
    public function getEmailIdentity(): ?UserIdentity
    {
        if ($this->authIdentities) {
            $this->identities[] = $this->authIdentities;
        }

        return $this->getIdentity(Session::ID_TYPE_EMAIL_PASSWORD);
    }

    /**
     * If $email, $password, or $password_hash have been updated,
     * will update the user's email identity record with the
     * correct values.
     */
    public function saveEmailIdentity(): bool
    {
        if (empty($this->email) && empty($this->password) && empty($this->password_hash)) {
            return true;
        }

        $identity = $this->getEmailIdentity();
        if ($identity === null) {
            // Ensure we reload all identities
            $this->identities = null;

            $this->createEmailIdentity([
                'email'    => $this->email,
                'password' => '',
            ]);

            $identity = $this->getEmailIdentity();
        }

        if (! empty($this->email)) {
            $identity->secret = $this->email;
        }

        if (! empty($this->password)) {
            $identity->secret2 = Services::passwords()->hash($this->password);
        }

        if (! empty($this->password_hash) && empty($this->password)) {
            $identity->secret2 = $this->password_hash;
        }

        return $identity->save();
    }

    /**
     * Update the last used at date for an identity record.
     */
    public function touchIdentity(UserIdentity $identity): void
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        $identityModel->touchIdentity($identity);
    }

    /**
     * Accessor method to grab the user's email address.
     * Will cache it in $this->email, since it has
     * to hit the database the first time to get it, most likely.
     */
    public function getEmail(): ?string
    {
        if ($this->email === null) {
            $this->email = $this->getEmailIdentity()->secret ?? null;
        }

        return $this->email;
    }

    public function setEmail(string $email): void
    {
        $this->email = $email;
    }

    public function getPassword(): ?string
    {
        return $this->attributes['password'] ?? null;
    }

    public function setPassword(string $password): User
    {
        $this->attributes['password'] = $password;

        return $this;
    }

    public function setPasswordHash(string $hash): User
    {
        $this->attributes['password_hash'] = $hash;

        return $this;
    }

    /**
     * Accessor method to grab the user's password hash.
     * Will cache it in $this->attributes, since it has
     * to hit the database the first time to get it, most likely.
     */
    public function getPasswordHash(): ?string
    {
        if (empty($this->attributes['password_hash'])) {
            $this->attributes['password_hash'] = $this->getEmailIdentity()?->secret2 ?? null;
        }

        return $this->attributes['password_hash'] ?? null;
    }

    /**
     * Returns the previous login information for this user
     */
    public function previousLogin(): ?Login
    {
        /** @var LoginModel $logins */
        $logins = model(LoginModel::class);

        return $logins->previousLogin($this);
    }

    /**
     * Returns the last login information for this user as
     */
    public function lastLogin(): ?Login
    {
        /** @var LoginModel $logins */
        $logins = model(LoginModel::class);

        return $logins->lastLogin($this);
    }
}
