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
     * -------------------------------------------------- -------------------
     * Taille en octets de la clé secrète HMAC
     * ------------------------------------------------- -------------------
     * Spécifiez en entier la taille d'octet souhaitée de la taille d'octet HMAC SHA256
     *
     * @var int
     */
    'hmac_secret_key_byte_size' => 32,
];
