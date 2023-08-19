<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace BlitzPHP\Schild\Entities;

use BlitzPHP\Schild\Config\Services;
use BlitzPHP\Utilities\Date;

/**
 * Représente un ensemble unique d'informations d'identification d'identité d'utilisateur.
 * Pour le système Schild de base, il s'agirait de l'un des éléments suivants :
 *  - mot de passe
 * - réinitialiser le hachage
 *  - jeton d'accès
 *
 * Cela peut également être utilisé pour stocker les informations d'identification pour les connexions sociales,
 * Jetons OAUTH ou JWT, etc. Un utilisateur peut en avoir plusieurs,
 * bien qu'un authentificateur veuille imposer qu'il n'y en ait qu'un pour cela
 * utilisateur, comme un mot de passe.
 *
 * @property Date|string|null $last_used_at
 * @property string|null      $secret
 * @property string|null      $secret2
 */
class UserIdentity extends Entity
{
    /**
     * {@inheritDoc}
     */
    protected string $table = 'identities';

    /**
     * {@inheritDoc}
     *
     * @var array<string, string>
     */
    protected array $casts = [
        'id'          => '?integer',
        'force_reset' => 'boolean',
    ];

    /**
     * @var string[]
     * @phpstan-var list<string>
     * @psalm-var list<string>
     */
    protected $dates = [
        'expires',
        'last_used_at',
    ];

    /**
     * Utilise le hachage de la force du mot de passe pour hacher une valeur donnée pour le "secret".
     */
    public function hashSecret(string $value): UserIdentity
    {
        $this->attributes['secret'] = Services::passwords()->hash($value);

        return $this;
    }
}
