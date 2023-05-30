<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace BlitzPHP\Schild\Authentication\Jwt;

use BlitzPHP\Schild\Entities\User;
use BlitzPHP\Utilities\Date;
use stdClass;

/**
 * JWT Manager
 */
class JwtManager
{
    protected Date $clock;
    protected JwtAdapterInterface $jwtAdapter;

    public function __construct(
        ?Date $clock = null,
        ?JwtAdapterInterface $jwtAdapter = null
    ) {
        $this->clock      = $clock ?? new Date();
        $this->jwtAdapter = $jwtAdapter ?? new FirebaseAdapter();
    }

    /**
     * JWT signé (JWS) pour un utilisateur
     *
     * @param array                      $claims  Les éléments de charge utile.
     * @param int|null                   $ttl     Durée de vie en secondes.
     * @param string                     $keyset  Le groupe de clés.
     * @param array<string, string>|null $headers Un tableau avec les éléments d'en-tête à attacher.
     */
    public function generateToken(
        User $user,
        array $claims = [],
        ?int $ttl = null,
        $keyset = 'default',
        ?array $headers = null
    ): string {
        $payload = array_merge($claims, [
            'sub' => (string) $user->id, // subject
        ]);

        return $this->issue($payload, $ttl, $keyset, $headers);
    }

    /**
     * Issues Signed JWT (JWS)
     *
     * @param array                      $claims  Les éléments de charge utile.
     * @param int|null                   $ttl     Durée de vie en secondes.
     * @param string                     $keyset  Le groupe de clés. La clé de tableau de config/auth-jwt::$keys.
     * @param array<string, string>|null $headers Un tableau avec les éléments d'en-tête à attacher.
     */
    public function issue(
        array $claims,
        ?int $ttl = null,
        $keyset = 'default',
        ?array $headers = null
    ): string {
        $config = (object) config('auth-jwt');

        $payload = array_merge($config->defaultClaims, $claims);

        if (! array_key_exists('iat', $claims)) {
            $payload['iat'] = $this->clock->now()->getTimestamp();
        }

        if (! array_key_exists('exp', $claims)) {
            $payload['exp'] = $payload['iat'] + $config->timeToLive;
        }

        if ($ttl !== null) {
            $payload['exp'] = $payload['iat'] + $ttl;
        }

        return $this->jwtAdapter->encode(
            $payload,
            $keyset,
            $headers
        );
    }

    /**
     * Renvoie la charge utile du JWT
     *
     * @param string $keyset Le groupe de clés. La clé de tableau de config/auth-jwt::$keys.
     */
    public function parse(string $encodedToken, $keyset = 'default'): stdClass
    {
        return $this->jwtAdapter->decode($encodedToken, $keyset);
    }
}
