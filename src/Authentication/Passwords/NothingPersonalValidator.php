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
 * Checks password does not contain any personal information
 */
class NothingPersonalValidator extends BaseValidator implements ValidatorInterface
{
    /**
     * Renvoie true si $password ne contient aucune partie du nom d'utilisateur
     * ou l'email de l'utilisateur. Sinon, il renvoie faux.
     * Si true est renvoyé, le mot de passe sera transmis au prochain validateur.
     * Si false est renvoyé, le processus de validation sera immédiatement arrêté.
     */
    public function check(string $password, ?User $user = null): Result
    {
        $password = strtolower($password);

        if ($valid = $this->isNotPersonal($password, $user) === true) {
            $valid = $this->isNotSimilar($password, $user);
        }

        return new Result([
            'success'   => $valid,
            'reason'    => $this->error,
            'extraInfo' => $this->suggestion,
        ]);
    }

    /**
     * Recherche des informations personnelles dans un mot de passe.
     * Les informations personnelles utilisées proviennent du nom d'utilisateur
     * et de l'adresse e-mail de BlitzPHP\Schild\Entities\User properties.
     *
     * Il est possible d'inclure d'autres champs comme sources d'information.
     * Par exemple, un projet peut nécessiter l'ajout des propriétés `firstname` et `lastname` à une
     * version étendue de la classe User.
     * Les nouveaux champs peuvent être inclus dans les tests d'informations personnelles en définissant la clé `personal_fields`
     * dans BlitzPHP/Schild/config/auth.php, par ex.
     *
     *  'personal_fields' => ['firstname', 'lastname'],
     *
     * isNotPersonal() renvoie true si aucune information personnelle ne peut être trouvée, ou false
     * si de telles informations sont trouvées.
     */
    protected function isNotPersonal(string $password, ?User $user): bool
    {
        $userName = strtolower($user->username ?? '');
        $email    = strtolower($user->email);
        $valid    = true;

        // Les transgressions les plus évidentes
        if ($password === $userName
            || $password === $email
            || $password === strrev($userName)) {
            $valid = false;
        }

        // Analysez autant de pièces que possible à partir du nom d'utilisateur, du mot de passe et de l'e-mail.
        // Utilisez les pièces comme des aiguilles et des meules de foin et cherchez des allumettes dans tous les sens.
        if ($valid) {
            // Séparez le nom d'utilisateur pour l'utiliser comme aiguilles de recherche
            $needles = $this->stripExplode($userName);

            // extrait la partie locale et les parties de domaine de l'e-mail en tant qu'aiguilles distinctes
            [$localPart, $domain] = explode('@', $email) + [1 => null];

            // peut être john.doe@example.com et nous voulons toutes les aiguilles que nous pouvons obtenir
            $emailParts = $this->stripExplode($localPart);
            if (! empty($domain)) {
                $emailParts[] = $domain;
            }
            $needles = array_merge($needles, $emailParts);

            // Obtenir tous les autres champs "personnels" définis dans la configuration
            $personalFields = $this->config->personal_fields;

            foreach ($personalFields as $value) {
                if (! empty($user->{$value})) {
                    $needles[] = strtolower($user->{$value});
                }
            }

            $trivial = [
                'a',
                'an',
                'and',
                'as',
                'at',
                'but',
                'for',
                'if',
                'in',
                'not',
                'of',
                'or',
                'so',
                'the',
                'then',
            ];

            // Transforme le mot de passe en meules de foin
            $haystacks = $this->stripExplode($password);

            foreach ($haystacks as $haystack) {
                if (empty($haystack) || in_array($haystack, $trivial, true) || mb_strlen($haystack, 'UTF-8') < 3) {
                    continue; // ignore les mots triviaux
                }

                foreach ($needles as $needle) {
                    if (empty($needle) || in_array($needle, $trivial, true) || mb_strlen($needle, 'UTF-8') < 3) {
                        continue;
                    }

                    // regarde dans les deux sens si le mot de passe est un sous-ensemble de l'aiguille
                    if (strpos($haystack, $needle) !== false
                        || strpos($needle, $haystack) !== false) {
                        $valid = false;
                        break 2;
                    }
                }
            }
        }
        if ($valid) {
            return true;
        }

        $this->error      = lang('Auth.errorPasswordPersonal');
        $this->suggestion = lang('Auth.suggestPasswordPersonal');

        return false;
    }

    /**
     * notSimilar() utilise $password et $userName pour calculer une valeur de similarité.
     * Valeurs de similarité égales ou supérieures à BlitzPHP\Schild\Config::maxSimilarity
     * sont rejetés car trop semblables et false est renvoyé.
     * Sinon, true est renvoyé,
     *
     * Une valeur $maxSimilarity de 0 (zéro) renvoie vrai sans faire de comparaison.
     * En d'autres termes, 0 (zéro) désactive les tests de similarité.
     */
    protected function isNotSimilar(string $password, ?User $user): bool
    {
        if ($user->username === null) {
            return true;
        }

        $maxSimilarity = (float) $this->config->max_similarity;
        // vérification de l'intégrité - plage de travail 1-100, 0 est désactivé
        if ($maxSimilarity < 1) {
            $maxSimilarity = 0;
        } elseif ($maxSimilarity > 100) {
            $maxSimilarity = 100;
        }

        if (! empty($maxSimilarity)) {
            $userName = strtolower($user->username);

            similar_text($password, $userName, $similarity);
            if ($similarity >= $maxSimilarity) {
                $this->error      = lang('Auth.errorPasswordTooSimilar');
                $this->suggestion = lang('Auth.suggestPasswordTooSimilar');

                return false;
            }
        }

        return true;
    }

    /**
     * Remplace tous les caractères non verbaux et les traits de soulignement dans $str par un espace.
     * Ensuite, il explose ce résultat en utilisant l'espace comme délimiteur.
     */
    protected function stripExplode(string $str): array
    {
        $stripped = preg_replace('/[\W_]+/', ' ', $str);
        $parts    = explode(' ', trim($stripped));

        // Si ce n'est pas déjà là, placez l'entrée intacte en haut du tableau
        if (! in_array($str, $parts, true)) {
            array_unshift($parts, $str);
        }

        return $parts;
    }
}
