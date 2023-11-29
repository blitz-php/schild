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

/**
 * Configuration pour l'authentification par jeton et l'authentification HMAC
 */

return [
    /**
     * -------------------------------------------------- -------------------
     * Enregistrer les tentatives de connexion pour l'authentification par jeton et l'authentification HMAC
     * ------------------------------------------------- -------------------
     * Spécifiez quelles tentatives de connexion sont enregistrées dans la base de données.
     *
     * Les valeurs valides sont :
     * - RECORD_LOGIN_ATTEMPT_NONE
     * - RECORD_LOGIN_ATTEMPT_FAILURE
     * - RECORD_LOGIN_ATTEMPT_ALL
     */
    'record_login_attempt' => RECORD_LOGIN_ATTEMPT_FAILURE,

    /**
     * -------------------------------------------------- ------------------
     * Nom de l'en-tête de l'authentificateur
     * ------------------------------------------------- -------------------
     * Le nom de l'en-tête dans lequel le jeton d'autorisation doit être trouvé.
     * Selon les spécifications, cela devrait être "Autorisation", mais de rares
     * circonstances peuvent nécessiter un en-tête différent.
     *
     * @var array
     */
    'authenticator_header' => [
        'tokens' => 'Authorization',
        'hmac'   => 'Authorization',
    ],

    /**
     * --------------------------------------------------------------------
     * Durée de vie du jeton inutilisé
     * ------------------------------------------------- -------------------
     * Détermine la durée, en secondes, pendant laquelle un jeton d'accès inutilisé peut être utilisé.
     *
     * @var int
     */
    'unused_token_lifetime' => YEAR,

    /**
     * --------------------------------------------------------------------
     * Limite de caractères pour le stockage de Secret2
     * --------------------------------------------------------------------
     * Limite de la taille de la base de données pour le champ 'secret2' des identités.
     * 
     * @var int
     */
    'secret2_storage_limit' => 255,

    /**
     * -------------------------------------------------- -------------------
     * Taille en octets de la clé secrète HMAC
     * ------------------------------------------------- -------------------
     * Spécifiez en entier la taille d'octet souhaitée de la taille d'octet HMAC SHA256
     *
     * @var int
     */
    'hmac_secret_key_byte_size' => 32,

    /**
     * --------------------------------------------------------------------
     * Clés de chiffrement HMAC
     * --------------------------------------------------------------------
     * Ceci définit la clé à utiliser lors du cryptage de la clé secrète HMAC d'un utilisateur.
     *
     * 'keys' est un tableau de clés qui facilitera la rotation des clés. 
     * Les titres de clés valides doivent inclure uniquement [a-zA-Z0-9_] et ne doivent pas dépasser 8 caractères.
     *
     * Chaque titre de clé est un tableau associatif contenant la valeur "key" requise et les valeurs facultatives "driver" et "digest". 
     * Si les valeurs "driver" et "digest" ne sont pas spécifiées, les valeurs "driver" et "digest" par défaut seront utilisées.
     *
     * Les anciennes clés seront utilisées pour décrypter les clés secrètes existantes. 
     * Il est recommandé d'exécuter 'php klinge schild:hmac reencrypt' pour mettre à jour les cryptages des clés secrètes existantes.
     *
     * @see https://codeigniter.com/user_guide/libraries/encryption.html
     *
     * @var array<string, array{key : string, driver? : string, digest? : string}>|string
     *
     * NOTE : La valeur devient temporairement une chaîne lorsque la valeur est définie comme JSON à partir d'une variable d'environnement.
     *
     * [key_name => ['key' => key_value]]
     * ou [key_name => ['key' => key_value, 'driver' => driver, 'digest' => digest]]
     * 
     * @var array<string, array<string, mixed>>
     */
    'hmac_encryption_keys' => [
        'k1' => [
            'key' => '',
        ],
    ],

    /**
     * --------------------------------------------------------------------
     * Sélecteur de clé de chiffrement courant HMAC
     * --------------------------------------------------------------------
     * Ceci spécifie laquelle des clés de cryptage doit être utilisée.
     * 
     * @var string
     */
    'hmac_encryption_current_key' => 'k1',

    /**
     * --------------------------------------------------------------------
     * Pilote de la clé de chiffrement HMAC
     * --------------------------------------------------------------------
     * Ceci spécifie lequel des pilotes de cryptage doit être utilisé.
     *
     * Pilotes disponibles :
     *     - OpenSSL
     *     - Sodium
     * 
     * @var string
     */
    'hmac_encryption_default_driver' => 'OpenSSL',

    /**
     * --------------------------------------------------------------------
     * Pilote de la clé de chiffrement HMAC
     * --------------------------------------------------------------------
     * Ceci spécifie le type de cryptage à utiliser, par exemple 'SHA512' ou 'SHA256'.
     * 
     * @var string
     */
    'hmac_encryption_default_digest' => 'SHA512',
];
