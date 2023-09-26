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

use BlitzPHP\Schild\Entities\User;
use BlitzPHP\Schild\Exceptions\AuthenticationException;
use BlitzPHP\Schild\Result;

/**
 * Vérifie la composition générale du mot de passe.
 *
 * Alors que les vérifications de composition plus anciennes pouvaient inclure différents
 * groupes de caractères que vous deviez inclure, les normes NIST actuelles préfèrent
 * simplement définir une longueur minimale et un long maximum (plus de 128 caractères).
 *
 * @see https://pages.nist.gov/800-63-3/sp800-63b.html#sec5
 */
class CompositionValidator extends BaseValidator implements ValidatorInterface
{
    /**
     * Renvoie vrai lorsque le mot de passe réussit ce test.
     * Le mot de passe sera transmis à tous les validateurs restants.
     * False arrêtera immédiatement le processus de validation
     */
    public function check(string $password, ?User $user = null): Result
    {
        if (empty($this->config->minimum_password_length)) {
            throw AuthenticationException::unsetPasswordLength();
        }

        $passed = mb_strlen($password, 'UTF-8') >= $this->config->minimum_password_length;

        if (! $passed) {
            return new Result([
                'success'   => false,
                'reason'    => lang('Auth.errorPasswordLength', [$this->config->minimum_password_length]),
                'extraInfo' => lang('Auth.suggestPasswordLength'),
            ]);
        }

        return new Result([
            'success' => true,
        ]);
    }
}
