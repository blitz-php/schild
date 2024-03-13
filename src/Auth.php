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

namespace BlitzPHP\Schild;

use BlitzPHP\Router\RouteCollection;
use BlitzPHP\Schild\Authentication\Authentication;
use BlitzPHP\Schild\Authentication\AuthenticatorInterface;
use BlitzPHP\Schild\Config\Registrar;
use BlitzPHP\Schild\Entities\User;
use BlitzPHP\Schild\Exceptions\AuthenticationException;
use BlitzPHP\Schild\Models\UserModel;

/**
 * Facade pour l'authentification
 * 
 * @method Result    attempt(array $credentials)
 * @method Result    check(array $credentials)
 * @method bool      checkAction(string $token, string $type) [Session]
 * @method void      forget(?User $user = null)
 * @method User|null getUser()
 * @method bool      loggedIn()
 * @method bool      login(User $user)
 * @method void      loginById($userId)
 * @method bool      logout()
 * @method void      recordActiveDate()
 * @method $this     remember(bool $shouldRemember = true)    [Session]
 */
class Auth
{
    /**
     * Version actuelle de BlitzPHP Schild
     */
    public const VERSION = '1.0.0-beta.1';

    protected ?Authentication $authenticate = null;

    /**
     * L'alias de l'authentificateur à utiliser pour cette demande.
     */
    protected ?string $alias = null;

    protected ?UserModel $userProvider = null;

    public function __construct(protected object $config)
    {
    }

    protected function ensureAuthentication(): void
    {
        if ($this->authenticate !== null) {
            return;
        }

        $authenticate = new Authentication($this->config);
        $authenticate->setProvider($this->getProvider());

        $this->authenticate = $authenticate;
    }

    /**
     * Définit l'alias de l'authentificateur qui doit être utilisé pour cette requête.
     */
    public function setAuthenticator(?string $alias = null): self
    {
        if (! empty($alias)) {
            $this->alias = $alias;
        }

        return $this;
    }

    /**
     * Renvoie la classe d'authentification actuelle.
     */
    public function getAuthenticator(): AuthenticatorInterface
    {
        $this->ensureAuthentication();

        return $this->authenticate->factory($this->alias);
    }

    /**
     * Renvoie l'utilisateur actuel, s'il est connecté.
     */
    public function user(): ?User
    {
        return $this->getAuthenticator()->loggedIn()
            ? $this->getAuthenticator()->getUser()
            : null;
    }

    /**
     * Renvoie l'identifiant de l'utilisateur actuel, s'il est connecté.
     *
     * @return int|string|null
     */
    public function id()
    {
        return (null !== $user = $this->user())
            ? $user->id
            : null;
    }

    public function authenticate(array $credentials): Result
    {
        $this->ensureAuthentication();

        return $this->authenticate
            ->factory($this->alias)
            ->attempt($credentials);
    }

    /**
     * Définit les routes dans votre application pour utiliser les routes d'authentification Schild.
     *
     * Usage (dans config/routes.php):
     *      - auth()->routes($routes);
     *      - auth()->routes($routes, ['except' => ['login', 'register']])
     */
    public function routes(RouteCollection &$routes, array $config = []): void
    {
        $namespace = $config['namespace'] ?? 'BlitzPHP\Schild\Controllers';

        $routes->group('/', ['namespace' => $namespace], static function (RouteCollection $routes) use ($config): void {
            foreach (Registrar::routes() as $name => $row) {
                if (! isset($config['except']) || ! in_array($name, $config['except'], true)) {
                    foreach ($row as $params) {
                        $options = isset($params[3])
                            ? ['as' => $params[3]]
                            : null;
                        $routes->{$params[0]}($params[1], $params[2], $options);
                    }
                }
            }
        });
    }

    /**
     * Renvoie le modèle responsable de l'obtention des utilisateurs.
     *
     * @throws AuthenticationException
     */
    public function getProvider(): UserModel
    {
        if ($this->userProvider !== null) {
            return $this->userProvider;
        }

        if (! property_exists($this->config, 'user_provider')) {
            throw AuthenticationException::unknownUserProvider();
        }

        $className          = $this->config->user_provider;
        $this->userProvider = new $className();

        return $this->userProvider;
    }

    /**
     * Fournissez un accès aux fonctions magiques aux authentificateurs pour éviter
     * de répéter le code ici et pour leur permettre d'avoir leurs propres fonctionnalités
     * supplémentaires en plus de celles requises, comme la fonctionnalité "se souvenir de moi".
     *
     * @param string[] $args
     *
     * @throws AuthenticationException
     */
    public function __call(string $method, array $args)
    {
        $this->ensureAuthentication();

        $authenticate = $this->authenticate->factory($this->alias);

        if (method_exists($authenticate, $method)) {
            return $authenticate->{$method}(...$args);
        }
    }
}
