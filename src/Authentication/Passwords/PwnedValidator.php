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

use BlitzPHP\Exceptions\HttpException;
use BlitzPHP\Schild\Entities\User;
use BlitzPHP\Schild\Exceptions\AuthenticationException;
use BlitzPHP\Schild\Result;

/**
 * Vérifie si le mot de passe a été compromis en vérifiant
 * une base de données en ligne de plus de 555 millions de mots de passe volés.
 *
 * @see https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/
 *
 * Le NIST recommande de vérifier les mots de passe par rapport à ceux obtenus lors de précédentes violations de données.
 * @see https://pages.nist.gov/800-63-3/sp800-63b.html#sec5
 */
class PwnedValidator extends BaseValidator implements ValidatorInterface
{
    /**
     * Vérifie le mot de passe par rapport à la base de données en ligne et
     * renvoie faux si une correspondance est trouvée. Renvoie true si aucune correspondance n'est trouvée.
     * Si true est renvoyé, le mot de passe sera transmis au prochain validateur.
     * Si false est renvoyé, le processus de validation sera immédiatement arrêté.
     *
     * @throws AuthenticationException
     */
    public function check(string $password, ?User $user = null): Result
    {
        $hashedPword = strtoupper(sha1($password));
        $rangeHash   = substr($hashedPword, 0, 5);
        $searchHash  = substr($hashedPword, 5);

        try {
            $client = service('httpclient', 'https://api.pwnedpasswords.com/');

            $response = $client->accept('text/plain')->get('range/' . $rangeHash);
        } catch (HttpException $e) {
            $exception = AuthenticationException::HIBPCurlFail($e);
            logger()->error('[ERROR] {exception}', ['exception' => $exception]);

            throw $exception;
        }

        $range    = $response->body();
        $startPos = strpos($range, $searchHash);
        if ($startPos === false) {
            return new Result([
                'success' => true,
            ]);
        }

        $startPos += 36; // juste après le délimiteur (:)
        $endPos = strpos($range, "\r\n", $startPos);
        $hits   = $endPos !== false ? (int) substr($range, $startPos, $endPos - $startPos) : (int) substr($range, $startPos);

        $wording = $hits > 1 ? 'databases' : 'a database';

        return new Result([
            'success'   => false,
            'reason'    => lang('Auth.errorPasswordPwned', [$password, $hits, $wording]),
            'extraInfo' => lang('Auth.suggestPasswordPwned', [$password]),
        ]);
    }
}
