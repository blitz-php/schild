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

use BlitzPHP\Schild\Exceptions\InvalidArgumentException as SchildInvalidArgumentException;
use BlitzPHP\Schild\Exceptions\InvalidTokenException;
use BlitzPHP\Schild\Exceptions\LogicException as SchildLogicException;
use BlitzPHP\Utilities\Helpers;
use DomainException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use InvalidArgumentException;
use LogicException;
use stdClass;
use UnexpectedValueException;

class FirebaseAdapter implements JwtAdapterInterface
{
    /**
     * {@inheritDoc}
     */
    public function decode(string $encodedToken, $keyset): stdClass
    {
        try {
            $keys = $this->createKeysForDecode($keyset);

            return JWT::decode($encodedToken, $keys);
        } catch (InvalidArgumentException $e) {
            // la clé/tableau de clés fourni est vide ou mal formé.
            throw new SchildInvalidArgumentException(
                'Jeu de clés invalide: "' . $keyset . '". ' . $e->getMessage(),
                0,
                $e
            );
        } catch (DomainException $e) {
            // l'algorithme fourni n'est pas pris en charge OU
            // la clé fournie est invalide OU
            // erreur inconnue renvoyée dans openSSL ou libsodium OU
            // libsodium est requis mais non disponible.
            throw new SchildInvalidArgumentException('Impossible de décoder JWT: ' . $e->getMessage(), 0, $e);
        } catch (SignatureInvalidException $e) {
            // à condition que la vérification de la signature JWT ait échoué.
            throw InvalidTokenException::invalidToken($e);
        } catch (BeforeValidException $e) {
            // à condition que JWT essaie d'être utilisé avant la revendication "nbf" OU
            // à condition que JWT essaie d'être utilisé avant la revendication "iat".
            throw InvalidTokenException::beforeValidToken($e);
        } catch (ExpiredException $e) {
            // à condition que JWT essaie d'être utilisé après la revendication "exp".
            throw InvalidTokenException::expiredToken($e);
        } catch (UnexpectedValueException $e) {
            // à condition que JWT soit malformé OU
            // à condition qu'il manque un algorithme à JWT / utilise un algorithme non pris en charge OU
            // l'algorithme JWT fourni ne correspond pas à la clé fournie OU
            // l'ID de clé fourni dans key/key-array est vide ou invalide.
            logger()->error(
                '[Schild] ' . Helpers::classBasename($this) . '::' . __FUNCTION__
                . '(' . __LINE__ . ') '
                . get_class($e) . ': ' . $e->getMessage()
            );

            throw InvalidTokenException::invalidToken($e);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function encode(array $payload, $keyset, ?array $headers = null): string
    {
        try {
            [$key, $keyId, $algorithm] = $this->createKeysForEncode($keyset);

            return JWT::encode($payload, $key, $algorithm, $keyId, $headers);
        } catch (LogicException $e) {
            // erreurs liées à la configuration de l'environnement ou à des clés JWT mal formées
            throw new SchildLogicException('Impossible d\'encoder JWT: ' . $e->getMessage(), 0, $e);
        } catch (UnexpectedValueException $e) {
            // erreurs liées à la signature et aux revendications JWT
            throw new SchildLogicException('Impossible d\'encoder JWT: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Crée des clés pour Encode
     */
    private function createKeysForEncode(string $keyset): array
    {
        $config = (object) config('auth-jwt');

        if (isset($config->keys[$keyset][0]['secret'])) {
            $key = $config->keys[$keyset][0]['secret'];
        } else {
            $passphrase = $config->keys[$keyset][0]['passphrase'] ?? '';

            if ($passphrase !== '') {
                $key = openssl_pkey_get_private(
                    $config->keys[$keyset][0]['private'],
                    $passphrase
                );
            } else {
                $key = $config->keys[$keyset][0]['private'];
            }
        }

        $algorithm = $config->keys[$keyset][0]['alg'];

        $keyId = $config->keys[$keyset][0]['kid'] ?? null;
        if ($keyId === '') {
            $keyId = null;
        }

        return [$key, $keyId, $algorithm];
    }

    /**
     * Crée des clés pour Decode
     *
     * @return array|Key clé ou tableau de clés
     */
    private function createKeysForDecode(string $keyset)
    {
        $config = (object) config('auth-jwt');

        $configKeys = $config->keys[$keyset];

        if (count($configKeys) === 1) {
            $key       = $configKeys[0]['secret'] ?? $configKeys[0]['public'];
            $algorithm = $configKeys[0]['alg'];

            return new Key($key, $algorithm);
        }

        $keys = [];

        foreach ($config->keys[$keyset] as $item) {
            $key       = $item['secret'] ?? $item['public'];
            $algorithm = $item['alg'];

            $keys[$item['kid']] = new Key($key, $algorithm);
        }

        return $keys;
    }
}
