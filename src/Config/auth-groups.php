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
            'description' => 'Contrôle total du site.',
        ],
        'admin' => [
            'title'       => 'Admin',
            'description' => 'Administrateurs quotidiens du site.',
        ],
        'developer' => [
            'title'       => 'Développeur',
            'description' => 'Programmeurs du site.',
        ],
        'user' => [
            'title'       => 'Utilisateur',
            'description' => 'Utilisateurs généraux du site. Souvent des clients.',
        ],
        'beta' => [
            'title'       => 'Utilisateur bêta',
            'description' => 'A accès aux fonctionnalités de niveau bêta.',
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
        'admin.access'        => "Peut accéder à la zone d'administration du site",
        'admin.settings'      => 'Peut accéder aux paramètres principaux du site',
        'users.manage-admins' => "Peut gérer d'autres administrateurs",
        'users.create'        => 'Peut créer de nouveaux utilisateurs non-administrateurs',
        'users.edit'          => 'Peut modifier les utilisateurs non-administrateurs existants',
        'users.delete'        => 'Peut supprimer des utilisateurs non-administrateurs existants',
        'beta.access'         => 'Peut accéder aux fonctionnalités de niveau beta',
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
