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

namespace BlitzPHP\Schild\Authentication;

use BlitzPHP\Schild\Authentication\Passwords\ValidatorInterface;
use BlitzPHP\Schild\Entities\User;
use BlitzPHP\Schild\Exceptions\AuthenticationException;
use BlitzPHP\Schild\Result;

/**
 * Fournit un emplacement central pour gérer les tâches liées au mot de passe telles que le hachage, la vérification, la validation, etc.
 */
class Passwords
{
    public function __construct(protected object $config)
    {
    }

    /**
     * Hachez un mot de passe.
     *
     * @return false|string|null
     */
    public function hash(string $password)
    {
        return password_hash($password, $this->config->hash_algorithm, $this->getHashOptions());
    }

    private function getHashOptions(): array
    {
        if (
            (defined('PASSWORD_ARGON2I') && $this->config->hash_algorithm === PASSWORD_ARGON2I)
            || (defined('PASSWORD_ARGON2ID') && $this->config->hash_algorithm === PASSWORD_ARGON2ID)
        ) {
            return [
                'memory_cost' => $this->config->hash_memory_cost,
                'time_cost'   => $this->config->hash_time_cost,
                'threads'     => $this->config->hash_threads,
            ];
        }

        return [
            'cost' => $this->config->hash_cost,
        ];
    }

    /**
     * Vérifie un mot de passe par rapport à un mot de passe précédemment haché.
     */
    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Vérifie si un mot de passe doit être ressassé.
     */
    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, $this->config->hash_algorithm, $this->getHashOptions());
    }

    /**
     * Vérifie un mot de passe par rapport à tous les validateurs spécifiés
     * dans le paramètre `$password_validators` dans config/auth.php.
     *
     * @throws AuthenticationException
     */
    public function check(string $password, ?User $user = null): Result
    {
        if (null === $user) {
            throw AuthenticationException::noEntityProvided();
        }

        $password = trim($password);

        if ($password === '') {
            return new Result([
                'success' => false,
                'reason'  => lang('Auth.errorPasswordEmpty'),
            ]);
        }

        foreach ($this->config->password_validators as $className) {
            /** @var ValidatorInterface $class */
            $class = new $className($this->config);

            $result = $class->check($password, $user);
            if (! $result->isOK()) {
                return $result;
            }
        }

        return new Result([
            'success' => true,
        ]);
    }

    /**
     * Renvoie la règle de validation pour la longueur maximale.
     */
    public static function getMaxLengthRule(): string
    {
        if (config('auth.hash_algorithm') === PASSWORD_BCRYPT) {
            return 'max:72';
        }

        return 'max:255';
    }
}
