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

namespace BlitzPHP\Schild\Authentication\Passwords;

class BaseValidator
{
    protected ?string $error      = null;
    protected ?string $suggestion = null;

    public function __construct(protected object $config)
    {
    }

    /**
     * Renvoie la chaîne d'erreur qui doit être affichée à l'utilisateur.
     */
    public function error(): ?string
    {
        return $this->error;
    }

    /**
     * Renvoie une suggestion qui peut être affichée à l'utilisateur pour l'aider à choisir un meilleur mot de passe.
     * La méthode est obligatoire, mais une suggestion est facultative.
     * Peut renvoyer null à la place.
     */
    public function suggestion(): ?string
    {
        return $this->suggestion;
    }
}
