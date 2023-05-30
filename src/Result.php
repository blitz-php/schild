<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace BlitzPHP\Schild;

use BlitzPHP\Schild\Entities\User;

class Result
{
    protected bool $success = false;

    /**
     * Fournit une explication simple de l'erreur qui s'est produite.
     * Généralement une seule phrase.
     */
    protected ?string $reason = null;

    /**
     * Informations supplémentaires.
     *
     * @var string|User|null "Utilisateur" en cas de succès. Chaînes de suggestion en cas d'échec.
     */
    protected $extraInfo;

    /**
     * @phpstan-param array{success: bool, reason?: string|null, extraInfo?: string|User} $details
     * @psalm-param array{success: bool, reason?: string|null, extraInfo?: string|User} $details
     */
    public function __construct(array $details)
    {
        foreach ($details as $key => $value) {
            assert(property_exists($this, $key), 'La propriété "' . $key . '" n\'existe pas.');

            $this->{$key} = $value;
        }
    }

    /**
     * Le résultat a-t-il été un succès ?
     */
    public function isOK(): bool
    {
        return $this->success;
    }

    public function reason(): ?string
    {
        return $this->reason;
    }

    /**
     * @return string|User|null "Utilisateur" en cas de succès. Chaînes de suggestion en cas d'échec.
     */
    public function extraInfo()
    {
        return $this->extraInfo;
    }
}
