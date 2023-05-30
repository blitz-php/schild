<?php

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
use BlitzPHP\Schild\Result;

/**
 * Vérifie les mots de passe par rapport à une liste de 65 000 mots de passe couramment utilisés qui a été compilée par InfoSec.
 */
class DictionaryValidator extends BaseValidator implements ValidatorInterface
{
    /**
     * Vérifie le mot de passe par rapport aux mots du fichier et renvoie false
     * si une correspondance est trouvée. Renvoie true si aucune correspondance n'est trouvée.
     * Si true est renvoyé, le mot de passe sera transmis au prochain validateur.
     * Si false est renvoyé, le processus de validation sera immédiatement arrêté.
     */
    public function check(string $password, ?User $user = null): Result
    {
        // Boucle sur notre fichier
        $fp = fopen(__DIR__ . '/_dictionary.txt', 'rb');
        if ($fp) {
            while (($line = fgets($fp, 4096)) !== false) {
                if ($password === trim($line)) {
                    fclose($fp);

                    return new Result([
                        'success'   => false,
                        'reason'    => lang('Auth.errorPasswordCommon'),
                        'extraInfo' => lang('Auth.suggestPasswordCommon'),
                    ]);
                }
            }
        }

        fclose($fp);

        return new Result([
            'success' => true,
        ]);
    }
}
