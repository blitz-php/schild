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

namespace BlitzPHP\Schild\Authentication\HMAC;

use BlitzPHP\Contracts\Security\EncrypterInterface;
use BlitzPHP\Exceptions\EncryptionException;
use BlitzPHP\Schild\Config\Services;
use Exception;
use RuntimeException;

/**
 * HMAC Encrypter class
 *
 * This class handles the setup and configuration of the HMAC Encryption
 */
class HmacEncrypter
{
    /**
     * @var array<string, EncrypterInterface>
     */
    private array $encrypter;

    /**
     * Auth Token config
     */
    private object $config;

    /**
     * Configuration du cryptage
     */
    public function __construct()
    {
        $this->config = (object) config('auth-token');

        $this->getEncrypter($this->config->hmac_encryption_current_key);
    }

    /**
     * Decryptage
     *
     * @throws EncryptionException
     */
    public function decrypt(string $string): string
    {
        $matches = [];
        
        if (preg_match('/^\$b6\$(\w+?)\$(.+)\z/', $string, $matches) !== 1) {
            throw new EncryptionException('Impossible de décrypter la chaîne');
        }

        $encrypter = $this->getEncrypter($matches[1]);

        return $encrypter->decrypt(base64_decode($matches[2], true));
    }

    /**
     * Encryptage
     * 
     * @throws EncryptionException
     * @throws RuntimeException
     */
    public function encrypt(string $string): string
    {
        $currentKey = $this->config->hmac_encryption_current_key;

        $encryptedString = '$b6$' . $currentKey . '$' . base64_encode($this->encrypter[$currentKey]->encrypt($string));

        if (strlen($encryptedString) > $this->config->secret2_storage_limit) {
            throw new RuntimeException('Clé cryptée trop longue. Impossible de stocker la valeur.');
        }

        return $encryptedString;
    }

    /**
     * Vérifier si la chaîne est déjà cryptée
     */
    public function isEncrypted(string $string): bool
    {
        return preg_match('/^\$b6\$/', $string) === 1;
    }

    /**
     * Vérifier si la chaîne est déjà cryptée avec la clé actuelle.
     */
    public function isEncryptedWithCurrentKey(string $string): bool
    {
        $currentKey = $this->config->hmac_encryption_current_key;

        return preg_match('/^\$b6\$' . $currentKey . '\$/', $string) === 1;
    }

    /**
     * Générer une clé
     *
     * @return string Secret Key au format base64
     *
     * @throws Exception
     */
    public function generateSecretKey(): string
    {
        return base64_encode(random_bytes($this->config->hmac_secret_key_byte_size));
    }

    /**
     * Récupérer l'encrypteur de la clé sélectionnée
     *
     * @param string $key Clé d'index pour le chiffreur sélectionné
     */
    private function getEncrypter(string $key): EncrypterInterface
    {
        if (! isset($this->encrypter[$key])) {
            if (! isset($this->config->hmac_encryption_keys[$key]['key'])) {
                throw new RuntimeException('La clé de chiffrement n\'existe pas.');
            }

            $config = config('encryption');

            $config['key']    = $this->config->hmac_encryption_keys[$key]['key'];
            $config['driver'] = $this->config->hmac_encryption_keys[$key]['driver'] ?? $this->config->hmac_encryption_default_driver;
            $config['digest'] = $this->config->hmac_encryption_keys[$key]['digest'] ?? $this->config->hmac_encryption_default_digest;

            $this->encrypter[$key] = Services::encrypter($config, false);
        }

        return $this->encrypter[$key];
    }
}
