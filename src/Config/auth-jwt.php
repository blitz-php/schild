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

return [
    /**
     * ------------------------------------------------- -------------------
     * Nom de l'en-tête de l'authentificateur
     * ------------------------------------------------- -------------------
     * Le nom de l'en-tête dans lequel le jeton d'autorisation doit être trouvé.
     * Selon les spécifications, cela devrait être "Autorisation", mais de rares circonstances peuvent nécessiter un en-tête différent.
     *
     * @var string
     */
    'authenticator_header' => 'Authorization',

    /**
     * --------------------------------------------------------------------
     * Les éléments de charge utile par défaut
     * ------------------------------------------------- -------------------
     * Tous les JWT auront ces revendications dans la charge utile.
     *
     * @var array<string, string>
     */
    'default_claims' => [
        'iss' => '<Issuer of the JWT>',
    ],

    /**
     * --------------------------------------------------------------------
     * Les clés
     * ------------------------------------------------- -------------------
     * La clé du tableau est le nom du groupe de clés.
     * La première clé du groupe est utilisée pour la signature.
     *
     * @var array<string, array<int, array<string, string>>>
     * @phpstan-var array<string, list<array<string, string>>>
     */
    'keys' => [
        'default' => [
            // Cle Symmetrique
            [
                'kid' => '', // ID de clé. Facultatif si vous n'avez qu'une seule clé.
                'alg' => 'HS256', // algorithme.
                // Définit une chaîne aléatoire secrète. Nécessite au moins 256 bits pour l'algorithme HS256.
                // Par exemple, $ php -r 'echo base64_encode(random_bytes(32));'
                'secret' => '<Set secret random string>',
            ],
            // Cle Asymmetrique
            // [
            //     'kid'        => '',      // ID de clé. Facultatif si vous n'avez qu'une seule clé.
            //     'alg'        => 'RS256', // algorithme.
            //     'public'     => '',      // Cle Publique
            //     'private'    => '',      // Cle privee
            //     'passphrase' => ''       // Passphrase
            // ],
        ],
    ],

    /**
     * --------------------------------------------------------------------
     * Durée de vie (en secondes)
     * ------------------------------------------------- -------------------
     * Spécifie la durée, en secondes, pendant laquelle un jeton est valide.
     *
     * @var int
     */
    'time_to_live' => HOUR,

    /**
     * --------------------------------------------------------------------
     * Enregistrer les tentatives de connexion
     * ------------------------------------------------- -------------------
     * Si les tentatives de connexion sont enregistrées dans la base de données.
     *
     * Les valeurs valides sont :
     * - RECORD_LOGIN_ATTEMPT_NONE
     * - RECORD_LOGIN_ATTEMPT_FAILURE
     * - RECORD_LOGIN_ATTEMPT_ALL
     */
    'record_login_attempt' => RECORD_LOGIN_ATTEMPT_FAILURE,
];
