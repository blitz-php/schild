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

use BlitzPHP\Schild\Authentication\Passwords;
use BlitzPHP\Schild\Config\Services;
use BlitzPHP\Schild\Entities\User;

/**
 * Class ValidationRules
 *
 * Provides auth-related validation rules for CodeIgniter 4.
 *
 * To use, add this class to Config/Validation.php, in the
 * $rulesets array.
 */
class ValidationRules
{
    /**
     * Une méthode d'aide à la validation pour vérifier si le mot de passe transmis passera tous les validateurs actuellement définis.
     *
     * Pratique à utiliser lors de la validation,
     * mais vous obtiendrez une sécurité légèrement meilleure si cela est fait manuellement,
     * puisque vous pouvez personnaliser en fonction d'un utilisateur spécifique à ce stade.
     *
     * @param string $value  Valeur du champ
     * @param string $error1 Erreur qui sera renvoyée (pour un appel sans tableau de données de validation)
     * @param array  $data   Tableau de données de validation
     * @param string $error2 Erreur qui sera renvoyée (pour un appel avec un tableau de données de validation)
     */
    public function strong_password(string $value, ?string &$error1 = null, array $data = [], ?string &$error2 = null): bool
    {
        /** @var Passwords $checker */
        $checker = service('passwords');

        if (function_exists('auth') && auth()->user()) {
            $user = auth()->user();
        } else {
            $user = $data === [] ? $this->buildUserFromRequest() : $this->buildUserFromData($data);
        }

        $result = $checker->check($value, $user);

        if (! $result->isOk()) {
            if ($data === []) {
                $error1 = $result->reason();
            } else {
                $error2 = $result->reason();
            }
        }

        return $result->isOk();
    }

    /**
     * Renvoie vrai si $str a une longueur de $val ou moins d'octets.
     */
    public function max_byte(?string $str, string $val): bool
    {
        return is_numeric($val) && $val >= strlen($str ?? '');
    }

    /**
     * Construit une nouvelle instance d'utilisateur à partir de la requête globale.
     */
    protected function buildUserFromRequest(): User
    {
        $fields = $this->prepareValidFields();

        $request = Services::request();

        $data = $request->only($fields);

        return new User($data);
    }

    /**
     * Construit une nouvelle instance d'utilisateur à partir des données attribuées.
     *
     * @param array $data Assigned data
     */
    protected function buildUserFromData(array $data = []): User
    {
        $fields = $this->prepareValidFields();

        $data = array_intersect_key($data, array_fill_keys($fields, null));

        return new User($data);
    }

    /**
     * Préparer des champs utilisateur valides
     */
    protected function prepareValidFields(): array
    {
        $config   = (object) config('auth');
        $fields   = array_merge($config->valid_fields, $config->personal_fields);
        $fields[] = 'password';

        return $fields;
    }
}
