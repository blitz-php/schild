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

namespace BlitzPHP\Schild\Collectors;

use BlitzPHP\Debug\Toolbar\Collectors\BaseCollector;
use BlitzPHP\Schild\Auth as SchildAuth;

/**
 * Collecteur de la barre d'outils de débogage pour l'authentification
 */
class Auth extends BaseCollector
{
    /**
     * {@inheritDoc}
     */
    protected bool $hasTimeline = false;

    /**
     * {@inheritDoc}
     */
    protected bool $hasTabContent = true;

    /**
     * {@inheritDoc}
     */
    protected bool $hasVarData = false;

    /**
     * {@inheritDoc}
     */
    protected string $title = 'Auth';

    private SchildAuth $auth;

    public function __construct()
    {
        $this->auth = service('auth');
    }

    /**
     * {@inheritDoc}
     */
    public function getTitleDetails(): string
    {
        return SchildAuth::VERSION . ' | ' . get_class($this->auth->getAuthenticator());
    }

    /**
     * {@inheritDoc}
     */
    public function display(): string
    {
        if ($this->auth->loggedIn()) {
            $user        = $this->auth->user();
            $groups      = $user->getGroups();
            $permissions = $user->getPermissions();

            $groupsForUser      = implode(', ', $groups);
            $permissionsForUser = implode(', ', $permissions);

            $html = '<h3>Utilisateur actuel</h3>';
            $html .= '<table><tbody>';
            $html .= "<tr><td style='width:150px;'>User ID</td><td>#{$user->id}</td></tr>";
            $html .= "<tr><td>Nom d'utilisateur</td><td>{$user->username}</td></tr>";
            $html .= "<tr><td>Email</td><td>{$user->email}</td></tr>";
            $html .= "<tr><td>Groupes</td><td>{$groupsForUser}</td></tr>";
            $html .= "<tr><td>Permissions</td><td>{$permissionsForUser}</td></tr>";
            $html .= '</tbody></table>';
        } else {
            $html = '<p>Non connecté.</p>';
        }

        return $html;
    }

    /**
     * Obtient la valeur du "badge" pour le bouton.
     *
     * @return int|string|null ID de l'utilisateur actuel, ou null s'il n'est pas connecté
     */
    public function getBadgeValue()
    {
        return $this->auth->loggedIn() ? $this->auth->id() : null;
    }

    /**
     * Icone a afficher dans la toolbar
     *
     * Icon from https://icons8.com - 1em package
     */
    public function icon(): string
    {
        return 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAADLSURBVEhL5ZRLCsIwGAa7UkE9gd5HUfEoekxxJx7AhXoCca/fhESkJiQxBHwMDG3S/9EmJc0n0JMruZVXK/fMdWQRY7mXt4A7OZJvwZu74hRayIEc2nv3jGtXZrOWrnifiRY0OkhiWK5sWGeS52bkZymJ2ZhRJmwmySxLCL6CmIsZZUIixkiNezCRR+kSUyWH3Cgn6SuQIk2iuOBckvN+t8FMnq1TJloUN3jefN9mhvJeCAVWb8CyUDj0vxc3iPFHDaofFdUPu2+iae7nYJMCY/1bpAAAAABJRU5ErkJggg==';
    }
}
