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

use stdClass;

interface JwtAdapterInterface
{
    /**
     * Problèmes signés JWT (JWS)
     *
     * @param array<mixed>               $payload La charge utile.
     * @param string                     $keyset  Le groupe de clés. La clé de tableau de config/auth-jwt ::$keys.
     * @param array<string, string>|null $headers Un tableau avec les éléments d'en-tête à attacher.
     *
     * @return string JWT (JWS)
     */
    public function encode(array $payload, $keyset, ?array $headers = null): string;

    /**
     * Décoder le JWT signé (JWS)
     *
     * @param string $keyset Le groupe de clés. La clé de tableau de Config\AuthJWT::$keys.
     *
     * @return stdClass Charge utile
     */
    public function decode(string $encodedToken, $keyset): stdClass;
}
