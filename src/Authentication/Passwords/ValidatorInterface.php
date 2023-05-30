<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace BlitzPHP\Schild\Authentication\Passwords;

use BlitzPHP\Schild\Entities\User;
use BlitzPHP\Schild\Result;

interface ValidatorInterface
{
    /**
     * Vérifie le mot de passe et renvoie vrai/faux
     * s'il réussit. Doit renvoyer soit vrai/faux.
     * True signifie que le mot de passe réussit ce test et que le mot de passe sera transmis à tous les validateurs restants.
     * False arrêtera immédiatement le processus de validation
     */
    public function check(string $password, ?User $user = null): Result;

    /**
     * Renvoie la chaîne d'erreur qui doit être affichée à l'utilisateur.
     */
    public function error(): ?string;

    /**
     * Renvoie une suggestion qui peut être affichée à l'utilisateur pour l'aider à choisir un meilleur mot de passe.
     * La méthode est obligatoire, mais une suggestion est facultative.
     * Peut renvoyer null à la place.
     */
    public function suggestion(): ?string;
}
