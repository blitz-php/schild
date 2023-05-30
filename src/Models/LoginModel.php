<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace BlitzPHP\Schild\Models;

use BlitzPHP\Schild\Entities\Login;
use BlitzPHP\Schild\Entities\User;
use BlitzPHP\Utilities\Date;

class LoginModel extends BaseModel
{
    protected $primaryKey     = 'id';
    protected $returnType     = Login::class;
    protected $useSoftDeletes = false;
    protected $allowedFields  = [
        'ip_address',
        'user_agent',
        'id_type',
        'identifier',
        'user_id',
        'date',
        'success',
    ];
    protected $useTimestamps   = false;
    protected $validationRules = [
        'ip_address' => 'required',
        'id_type'    => 'required',
        'identifier' => 'permit_empty|string',
        'user_agent' => 'permit_empty|string',
        'user_id'    => 'permit_empty|integer',
        'date'       => 'required|valid_date',
    ];
    protected $validationMessages = [];
    protected $skipValidation     = false;

    public function __construct()
    {
        parent::__construct();

        $this->table = $this->tables['logins'];
    }

    /**
     * Enregistre la tentative de connexion.
     *
     * @param string          $idType Type d'identifiant. Voir const ID_YPE_* dans Authenticator.
     *                                auth_logins: 'email_password'|'username'|'magic-link'
     *                                auth_token_logins: 'access-token'
     * @param int|string|null $userId
     */
    public function recordLoginAttempt(
        string $idType,
        string $identifier,
        bool $success,
        ?string $ipAddress = null,
        ?string $userAgent = null,
        $userId = null
    ): void {
        $this->disableDBDebug();

        if ($this->db->getPlatform() === 'OCI8' && $identifier === '') {
            $identifier = ' ';
        }

        $return = $this->insert([
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent,
            'id_type'    => $idType,
            'identifier' => $identifier,
            'user_id'    => $userId,
            'date'       => Date::now()->format('Y-m-d H:i:s'),
            'success'    => (int) $success,
        ]);

        $this->checkQueryReturn($return);
    }

    /**
     * Renvoie les informations de connexion précédentes de l'utilisateur,
     * utiles pour afficher à l'utilisateur la dernière fois que le compte a été accédé.
     */
    public function previousLogin(User $user): ?Login
    {
        return $this->builder()
            ->where('success', 1)
            ->where('user_id', $user->id)
            ->sortDesc('id')
            ->limit(1, 1)->first(Login::class);
    }

    /**
     * Renvoie les dernières informations de connexion de l'utilisateur
     */
    public function lastLogin(User $user): ?Login
    {
        return $this->builder()
            ->where('success', 1)
            ->where('user_id', $user->id)
            ->sortDesc('id')
            ->first(Login::class);
    }
}
