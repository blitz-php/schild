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
        return parametre('auth.tables')[$this->authTables[self::class]] ?: parent::getTable();
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
     * Renvoie la première identité du $type donné pour cet utilisateur.
     *
     * @param string $type See const ID_TYPE_* dans l'Authenticator.
     *                     'email_2fa'|'email_activate'|'email_password'|'magic-link'|'access_token'
     */
    public function getIdentity(string $type): ?UserIdentity
    {
        $identities = $this->getIdentities($type);

        return count($identities) ? array_shift($identities) : null;
    }

    /**
     * Garantit que toutes les identités de l'utilisateur sont chargées dans l'instance pour un accès ultérieur plus rapide.
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
     * Méthode d'accès aux objets UserIdentity de cet utilisateur.
     * Les objets sont remplis s'ils n'existent pas.
     *
     * @param string $type 'all' renvoie toutes les identités.
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
     * Crée une nouvelle identité pour cet utilisateur avec une combinaison email/mot de passe.
     *
     * @phpstan-param array{email: string, password: string} $credentials
     */
    public function createEmailIdentity(array $credentials): void
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        $identityModel->createEmailIdentity($this, $credentials);

        // Veiller à ce que toutes les identités soient rechargées
        $this->identities = null;
    }

    /**
     * Renvoie l'identité e-mail/mot de passe de l'utilisateur.
     */
    public function getEmailIdentity(): ?UserIdentity
    {
        if ($this->authIdentities) {
            $this->identities[] = $this->authIdentities;
        }

        return $this->getIdentity(Session::ID_TYPE_EMAIL_PASSWORD);
    }

    /**
     * Si $email, $password, ou $password_hash ont été mis à jour, 
     * l'enregistrement de l'identité électronique de l'utilisateur sera mis à jour avec les valeurs correctes.
     */
    public function saveEmailIdentity(): bool
    {
        if (empty($this->email) && empty($this->password) && empty($this->password_hash)) {
            return true;
        }

        $identity = $this->getEmailIdentity();
        if ($identity === null) {
            // Veiller à ce que toutes les identités soient rechargées
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
            $identity->secret2 = service('passwords')->hash($this->password);
        }

        if (! empty($this->password_hash) && empty($this->password)) {
            $identity->secret2 = $this->password_hash;
        }

        return $identity->save();
    }

    /**
     * Mettre à jour la date de dernière utilisation d'un enregistrement d'identité.
     */
    public function touchIdentity(UserIdentity $identity): void
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        $identityModel->touchIdentity($identity);
    }

    /**
     * Méthode d'accès pour récupérer l'adresse email de l'utilisateur.
     * Elle sera mise en cache dans $this->email, puisqu'il est probable qu'elle doive se rendre dans la base de données la première fois pour l'obtenir.
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
     * Méthode d'accès pour récupérer le hash du mot de passe de l'utilisateur.
     * Il sera mis en cache dans $this->attributes, puisqu'il doit accéder à la base de données la première fois pour l'obtenir, très probablement.
     */
    public function getPasswordHash(): ?string
    {
        if (empty($this->attributes['password_hash'])) {
            $this->attributes['password_hash'] = $this->getEmailIdentity()?->secret2 ?? null;
        }

        return $this->attributes['password_hash'] ?? null;
    }

    /**
     * Renvoie les informations de connexion précédentes pour cet utilisateur
     */
    public function previousLogin(): ?Login
    {
        /** @var LoginModel $logins */
        $logins = model(LoginModel::class);

        return $logins->previousLogin($this);
    }

    /**
     * Renvoie les dernières informations de connexion de cet utilisateur
     */
    public function lastLogin(): ?Login
    {
        /** @var LoginModel $logins */
        $logins = model(LoginModel::class);

        return $logins->lastLogin($this);
    }
}
