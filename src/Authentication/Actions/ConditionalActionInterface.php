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

namespace BlitzPHP\Schild\Authentication\Actions;

use BlitzPHP\Schild\Entities\User;

/**
 * Permet à une action d'authentification de déterminer si elle s'applique à un utilisateur.
 */
interface ConditionalActionInterface
{
    /**
     * Détermine si cette action s'applique à l'utilisateur indiqué.
     *
     * Cette méthode peut être appelée lors du démarrage de Schild ou lorsque celui-ci détecte des actions en attente.
     * Elle doit être déterministe et ne pas entraîner d'effets secondaires.
     */
    public function appliesTo(User $user): bool;
}
