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

use BlitzPHP\Schild\Authentication\Authenticators\Session;
use BlitzPHP\Schild\Models\UserIdentityModel;

/**
 * Méthodes réutilisables pour faciliter l'application des réinitialisations de mot de passe
 */
trait Resettable
{
    /**
     * Renvoie vrai|faux en fonction de la valeur de la colonne de réinitialisation forcée de l'identité de l'utilisateur.
     */
    public function requiresPasswordReset(): bool
    {
        $identityModel = model(UserIdentityModel::class);
        $identity      = $identityModel->getIdentityByType($this, Session::ID_TYPE_EMAIL_PASSWORD);

        return $identity->force_reset;
    }

    /**
     * Forcer la réinitialisation du mot de passe
     */
    public function forcePasswordReset(): void
    {
        // Ne rien faire si l'utilisateur a déjà besoin d'une réinitialisation
        if ($this->requiresPasswordReset()) {
            return;
        }

        $this->setForceReset(true);
    }

    /**
     * Annuler Forcer la réinitialisation du mot de passe
     */
    public function undoForcePasswordReset(): void
    {
        // Si l'utilisateur n'a pas besoin de réinitialiser le mot de passe, ne rien faire
        if ($this->requiresPasswordReset() === false) {
            return;
        }

        $this->setForceReset(false);
    }

    /**
     * Modifie le force_reset
     */
    private function setForceReset(bool $value): void
    {
        $value = (int) $value;

        $identityModel = model(UserIdentityModel::class);
        $identityModel->set('force_reset', $value);
        $identityModel->where(['user_id' => $this->id, 'type' => Session::ID_TYPE_EMAIL_PASSWORD]);
        $identityModel->update();
    }
}
