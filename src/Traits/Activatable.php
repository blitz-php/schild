<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace BlitzPHP\Schild\Traits;

trait Activatable
{
    /**
     * Renvoie vrai si l'utilisateur a été activé et que l'activation est requise après l'enregistrement.
     */
    public function isActivated(): bool
    {
        // Si l'activation n'est pas requise, nous sommes toujours actifs.
        return ! $this->shouldActivate() || $this->active;
    }

    /**
     * Renvoie vrai si l'utilisateur n'a pas été activé.
     */
    public function isNotActivated(): bool
    {
        return ! $this->isActivated();
    }

    /**
     * Active l'utilisateur.
     */
    public function activate(): void
    {
        $users = auth()->getProvider();

        $users->modify($this->id, ['active' => 1]);
    }

    /**
     * Desactive l'utilisateur.
     */
    public function deactivate(): void
    {
        $users = auth()->getProvider();

        $users->modify($this->id, ['active' => 0]);
    }

    /**
     * Les actions d'authentification nécessitent-elles une activation ?
     * Vérifiez le nom générique de la classe 'Activator' pour permettre des implémentations personnalisées, à condition qu'elles respectent la convention de dénomination.
     */
    private function shouldActivate(): bool
    {
        return strpos(config('auth.actions')['register'] ?? '', 'Activator') !== false;
    }
}
