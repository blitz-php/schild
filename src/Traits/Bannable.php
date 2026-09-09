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

namespace BlitzPHP\Schild\Traits;

trait Bannable
{
    /**
     * L'utilisateur est-il banni ?
     */
    public function isBanned(): bool
    {
        return $this->status && $this->status === 'banned';
    }

    /**
     * Interdire à l'utilisateur de se connecter.
     */
    public function ban(?string $message = null): self
    {
        $this->status         = 'banned';
        $this->status_message = $message;

        $users = auth()->getProvider();

        $users->modify($this->id, [
            'status'         => $this->status,
            'status_message' => $this->status_message,
        ]);

        return $this;
    }

    /**
     * Débannir l'utilisateur et lui permettre de se connecter
     */
    public function unBan(): self
    {
        $this->status         = null;
        $this->status_message = null;

        $users = auth()->getProvider();

        $users->modify($this->id, [
            'status'         => $this->status,
            'status_message' => $this->status_message,
        ]);

        return $this;
    }

    /**
     * Renvoie le message d'interdiction.
     */
    public function getBanMessage(): ?string
    {
        return $this->status_message;
    }
}
