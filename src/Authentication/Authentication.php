<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace BlitzPHP\Schild\Authentication;

use BlitzPHP\Schild\Exceptions\AuthenticationException;
use BlitzPHP\Schild\Models\UserModel;

class Authentication
{
    /**
     * Objets Authenticator instanciés,
     * stocké par l'alias de l'authentificateur.
     *
     * @var array<string, AuthenticatorInterface> [Authenticator_alias => Authenticator_instance]
     */
    protected array $instances = [];

    protected ?UserModel $userProvider = null;

    public function __construct(protected object $config)
    {
    }

    /**
     * Renvoie une instance de l'Authenticator spécifié.
     *
     * Vous pouvez passer 'default' comme Authenticator et il renverra une instance du premier
     * Authenticator spécifié dans le fichier de configuration Auth.
     *
     * @param string|null $alias Authenticator alias
     *
     * @throws AuthenticationException
     */
    public function factory(?string $alias = null): AuthenticatorInterface
    {
        // Déterminer l'alias d'authentificateur réel
        $alias ??= $this->config->default_authenticator;

        // Renvoie l'instance en cache si nous l'avons
        if (! empty($this->instances[$alias])) {
            return $this->instances[$alias];
        }

        // Sinon, essayez de créer une nouvelle instance.
        if (! array_key_exists($alias, $this->config->authenticators)) {
            throw AuthenticationException::unknownAuthenticator($alias);
        }

        $className = $this->config->authenticators[$alias];

        assert($this->userProvider !== null, 'You must set $this->userProvider.');

        $this->instances[$alias] = new $className($this->userProvider);

        return $this->instances[$alias];
    }

    /**
     * Définit le fournisseur d'utilisateurs à utiliser
     */
    public function setProvider(UserModel $provider): self
    {
        $this->userProvider = $provider;

        return $this;
    }
}
