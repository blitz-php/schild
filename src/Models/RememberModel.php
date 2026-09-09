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

namespace BlitzPHP\Schild\Models;

use BlitzPHP\Schild\Entities\User;
use BlitzPHP\Utilities\Date;
use stdClass;

class RememberModel extends BaseModel
{
    protected string $returnType = 'object';

    public function __construct()
    {
        parent::__construct();

        $this->table = $this->tables['remember_tokens'];
    }

    /**
     * Stocke un jeton de rappel pour l'utilisateur.
     */
    public function rememberUser(User $user, string $selector, string $hashedValidator, string $expires): void
    {
        $return = $this->insert([
            'user_id'         => $user->id,
            'selector'        => $selector,
            'hashedValidator' => $hashedValidator,
            'expires'         => Date::parse($expires)->format('Y-m-d H:i:s'),
        ]);

        $this->checkQueryReturn($return);
    }

    /**
     * Renvoie les informations sur le jeton « remember-me » pour un sélecteur donné.
     */
    public function getRememberToken(string $selector): ?stdClass
    {
        return $this->where('selector', $selector)->first(); // @phpstan-ignore-line
    }

    /**
     * Met à jour le validateur pour un sélecteur donné.
     */
    public function updateRememberValidator(stdClass $token): void
    {
        $return = $this->save($token);

        $this->checkQueryReturn($return);
    }

    /**
     * Supprime tous les jetons de connexion persistants (remember-me) pour un seul utilisateur 
     * sur tous les appareils avec lesquels il s'est connecté.
     */
    public function purgeRememberTokens(User $user): void
    {
        $return = $this->where(['user_id' => $user->id])->delete();

        $this->checkQueryReturn($return);
    }

    /**
     * Purge la table 'auth_remember_tokens' de tous les enregistrements dont la date d'expiration est déjà dépassée.
     */
    public function purgeOldRememberTokens(): void
    {
        $return = $this->where('expires <=', date('Y-m-d H:i:s'))
            ->delete();

        $this->checkQueryReturn($return);
    }
}
