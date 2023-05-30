<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace BlitzPHP\Schild\Authentication\Authenticators;

use BlitzPHP\Schild\Entities\User;
use BlitzPHP\Schild\Exceptions\AuthenticationException;
use BlitzPHP\Schild\Models\UserModel;
use BlitzPHP\Utilities\Date;
use InvalidArgumentException;

abstract class BaseAuthenticator
{
    /**
     * Utilisateur authentifié ou en cours d'authentification (connexion en attente)
     */
    protected ?User $user = null;

    /**
     * Constructor.
     *
     * @param UserModel $provider Le moteur de persistance
     */
    public function __construct(protected UserModel $provider)
    {
    }

    /**
     * Connecte l'utilisateur donné en l'enregistrant dans la classe.
     */
    public function login(User $user): void
    {
        $this->user = $user;
    }

    /**
     * Déconnecte l'utilisateur actuel.
     */
    public function logout(): void
    {
        $this->user = null;
    }

    /**
     * Renvoie l'utilisateur actuellement connecté.
     */
    public function getUser(): ?User
    {
        return $this->user;
    }

    /**
     * Met à jour la dernière date active de l'utilisateur.
     */
    public function recordActiveDate(): void
    {
        if (! $this->user instanceof User) {
            throw new InvalidArgumentException(
                __METHOD__ . '() nécessite un utilisateur connecté avant d\'etre appeler.'
            );
        }

        $this->user->last_active = Date::now();

        $this->provider->updateActiveDate($this->user);
    }

    /**
     * Connecte un utilisateur en fonction de son ID.
     *
     * @param int|string $userId
     *
     * @throws AuthenticationException
     */
    public function loginById($userId): void
    {
        $user = $this->provider->findById($userId);

        if ($user === null) {
            throw AuthenticationException::invalidUser();
        }

        $this->login($user);
    }
}
