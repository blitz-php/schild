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

namespace BlitzPHP\Schild\Authentication;

use BlitzPHP\Schild\Entities\User;
use BlitzPHP\Schild\Result;

interface AuthenticatorInterface
{
    /**
     * Tente d'authentifier un utilisateur avec les $credentials donnés.
     * Connecte l'utilisateur avec une vérification réussie.
     *
     * @throws AuthenticationException
     */
    public function attempt(array $credentials): Result;

    /**
     * Vérifie les $credentials d'un utilisateur pour voir s'ils correspondent à un utilisateur existant.
     */
    public function check(array $credentials): Result;

    /**
     * Vérifie si l'utilisateur est actuellement connecté.
     */
    public function loggedIn(): bool;

    /**
     * Connecte l'utilisateur donné.
     * En cas de succès, cela doit déclencher l'événement "login".
     */
    public function login(User $user): void;

    /**
     * Connecte un utilisateur en fonction de son ID.
     * En cas de succès, cela doit déclencher l'événement "login".
     *
     * @param int|string $userId
     */
    public function loginById($userId): void;

    /**
     * Déconnecte l'utilisateur actuel.
     * En cas de succès, cela doit déclencher l'événement "déconnexion".
     */
    public function logout(): void;

    /**
     * Renvoie l'utilisateur actuellement connecté.
     */
    public function getUser(): ?User;

    /**
     * Met à jour la dernière date active de l'utilisateur.
     */
    public function recordActiveDate(): void;
}
