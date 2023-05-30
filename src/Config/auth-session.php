<?php

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
     * Les règles de validation du nom d'utilisateur
     *
     * @var string[]
     */
    'username_validation_rules' => [
        'required',
        'max:30',
        'min:3',
        'regex:/\A[a-zA-Z0-9\.]+\z/',
    ],

    /**
     * Les règles de validation des emails
     *
     * @var string[]
     */
    'email_validation_rules' => [
        'required',
        'max:254',
        'email',
    ],
];
