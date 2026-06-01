<?php

namespace BlitzPHP\Schild\Middlewares;

use BlitzPHP\Middlewares\BaseMiddleware;
use BlitzPHP\Schild\Middlewares\ChainAuth;
use BlitzPHP\Schild\Middlewares\HmacAuth;
use BlitzPHP\Schild\Middlewares\JWTAuth;
use BlitzPHP\Schild\Middlewares\SessionAuth;
use BlitzPHP\Schild\Middlewares\TokenAuth;
use InvalidArgumentException;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Middleware d'authentification générique qui délègue à un garde spécifique.
 *
 * Le garde utilisé est déterminé par la propriété `guard` (configurable lors
 * de l'enregistrement du middleware) ou par la configuration globale
 * `auth.default_authenticator`. Les gardes disponibles sont enregistrés dans
 * le tableau statique `$guards` et peuvent être étendus/modifiés via la méthode
 * statique `guard()`.
 */
class AuthMiddleware extends BaseMiddleware implements MiddlewareInterface
{
    /**
     * {@inheritDoc}
     */
    protected array $fillable = ['guard'];

    /**
     * Correspondance entre les alias de garde et les classes de middleware.
     *
     * @var array<string, class-string<MiddlewareInterface>>
     */
    protected static array $guards = [
        'session' => SessionAuth::class,
        'tokens'  => TokenAuth::class,
        'hmac'    => HmacAuth::class,
        'chain'   => ChainAuth::class,
        'jwt'     => JWTAuth::class,
    ];

    /**
     * Enregistre ou remplace dynamiquement une implémentation de garde.
     *
     * Deux modes d'appel :
     * - Avec un tableau associatif : `guard(['jwt' => CustomJWTAuth::class])`
     * - Avec un alias et une classe : `guard('custom', CustomAuth::class)`
     *
     * @param string|array<string, class-string<MiddlewareInterface>> $guard Soit un alias (string), soit un tableau associatif alias => classe.
     * @param class-string<MiddlewareInterface>|null $implementation Classe du middleware (obligatoire si le premier paramètre est une chaîne).
     *
     * @throws InvalidArgumentException Si l'implémentation fournie n'existe pas, n'est pas une classe, ou n'implémente pas MiddlewareInterface.
     */
    public static function guard(array|string $guard, ?string $implementation = null): void
    {
        if (is_string($guard)) {
            if (empty($implementation)) {
                throw new InvalidArgumentException(
                    'Lorsque le premier paramètre est une chaîne, le second paramètre (implementation) doit être une classe valide.'
                );
            }
            $guard = [$guard => $implementation];
        }

        foreach ($guard as $alias => $class) {
            if (! is_a($class, MiddlewareInterface::class, true)) {
                throw new InvalidArgumentException(
                    sprintf(
                        'La classe "%s" doit implémenter %s pour être utilisée comme garde "%s".',
                        $class,
                        MiddlewareInterface::class,
                        $alias
                    )
                );
            }
            static::$guards[$alias] = $class;
        }
    }

    /**
     * Traite la requête en déléguant au middleware de garde approprié.
     *
     * Le garde est déterminé par :
     * - La propriété `$this->guard` (si définie, via la configuration du middleware)
     * - Sinon, la valeur du paramètre global `auth.default_authenticator`
     * - En dernier recours, la valeur par défaut `'session'`.
     *
     * @param ServerRequestInterface  $request  Requête PSR-7 entrante.
     * @param RequestHandlerInterface $handler  Gestionnaire suivant dans la chaîne.
     *
     * @throws InvalidArgumentException Si l'alias du garde n'existe pas dans `$guards`
     *         ou si la classe associée n'est pas un middleware valide.
     *
     * @return ResponseInterface Réponse après passage par le middleware de garde.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // Récupération du nom du garde : d'abord depuis la propriété (si configurée), sinon depuis la config globale
        $guard = $this->guard ?? parametre('auth.default_authenticator') ?? 'session';

        if (! isset(static::$guards[$guard])) {
            throw new InvalidArgumentException(
                sprintf('Aucun garde enregistré pour l\'alias "%s".', $guard)
            );
        }

        $middlewareClass = static::$guards[$guard];

        if (! is_a($middlewareClass, MiddlewareInterface::class, true)) {
            throw new InvalidArgumentException(
                sprintf(
                    'La classe "%s" associée au garde "%s" n\'implémente pas %s.',
                    $middlewareClass,
                    $guard,
                    MiddlewareInterface::class
                )
            );
        }

        /** @var MiddlewareInterface $middleware */
        $middleware = service($middlewareClass);

        return $middleware->process($request, $handler);
    }
}
