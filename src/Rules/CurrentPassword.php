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

namespace BlitzPHP\Schild\Rules;

use BlitzPHP\Schild\Authentication\Authenticators\Session;
use BlitzPHP\Schild\Models\UserModel;
use BlitzPHP\Validation\Rules\AbstractRule;

class CurrentPassword extends AbstractRule
{
    protected $message = ':value is not the password of the current user';

    /**
     * @var array
     */
    protected $fillableParams = ['guard'];

    public function check($value): bool
    {
        if (null === $id = auth($this->parameter('guard'))->id()) {
            return false;
        }

        $user = model(UserModel::class)->findById($id, true);

        $passwords = service('passwords');

        // Vérifiez si le mot de passe doit être ressassé.
        // Cela serait dû à la modification de l'algorithme de hachage ou du coût de hachage depuis la dernière fois qu'un utilisateur s'est connecté.
        if ($passwords->needsRehash($user->password_hash)) {
            $user->password_hash = $passwords->hash($value);
            $user->getIdentity(Session::ID_TYPE_EMAIL_PASSWORD)->forceFill([
                'secret2' => $user->password_hash,
            ])->save();
        }

        return $passwords->verify($value, $user->password_hash);
    }
}
