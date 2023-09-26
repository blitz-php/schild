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
     * --------------------------------------------------------------------
     * Groupe par défaut
     * ------------------------------------------------- -------------------
     * Le groupe auquel un utilisateur nouvellement enregistré est ajouté.
     *
     * @var string
     */
    'default_group' => 'user',

    /**
     * --------------------------------------------------------------------
     * Groupes
     * --------------------------------------------------------------------
     * Un tableau associatif des groupes disponibles dans le système, où les clés
     * sont les noms de groupe et les valeurs sont des tableaux d'informations de groupe.
     *
     * Quelle que soit la valeur que vous attribuez à la clé, elle sera utilisée pour faire
     * référence au groupe lors de l'utilisation de fonctions telles que :
     *      $user->addGroup('superadmin');
     *
     * @var array<string, array<string, string>>
     */
    'groups' => [
        'superadmin' => [
            'title'       => 'Super Admin',
            'description' => 'Complete control of the site.',
        ],
        'admin' => [
            'title'       => 'Admin',
            'description' => 'Day to day administrators of the site.',
        ],
        'developer' => [
            'title'       => 'Developer',
            'description' => 'Site programmers.',
        ],
        'user' => [
            'title'       => 'User',
            'description' => 'General users of the site. Often customers.',
        ],
        'beta' => [
            'title'       => 'Beta User',
            'description' => 'Has access to beta-level features.',
        ],
    ],

    /**
     * --------------------------------------------------------------------
     * Permissions
     * --------------------------------------------------------------------
     * Les autorisations disponibles dans le système.
     *
     * Si une autorisation n'est pas répertoriée ici, elle ne peut pas être utilisée.
     */
    'permissions' => [
        'admin.access'        => 'Can access the sites admin area',
        'admin.settings'      => 'Can access the main site settings',
        'users.manage-admins' => 'Can manage other admins',
        'users.create'        => 'Can create new non-admin users',
        'users.edit'          => 'Can edit existing non-admin users',
        'users.delete'        => 'Can delete existing non-admin users',
        'beta.access'         => 'Can access beta-level features',
    ],

    /**
     * --------------------------------------------------------------------
     * Matrice des autorisations
     * ------------------------------------------------- -------------------
     * Mappe les autorisations aux groupes.
     *
     * Cela définit les autorisations au niveau du groupe.
     */
    'matrix' => [
        'superadmin' => [
            'admin.*',
            'users.*',
            'beta.*',
        ],
        'admin' => [
            'admin.access',
            'users.create',
            'users.edit',
            'users.delete',
            'beta.access',
        ],
        'developer' => [
            'admin.access',
            'admin.settings',
            'users.create',
            'users.edit',
            'beta.access',
        ],
        'user' => [],
        'beta' => [
            'beta.access',
        ],
    ],
];
