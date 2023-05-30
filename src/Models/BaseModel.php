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

use BlitzPHP\Models\BaseModel as ModelsBaseModel;

abstract class BaseModel extends ModelsBaseModel
{
    use CheckQueryReturnTrait;

    /**
     * Noms des tables d'authentification
     */
    protected array $tables;

    protected object $authConfig;

    public function __construct()
    {
        $this->authConfig = (object) config('auth');

        if ($this->authConfig->db_group !== null) {
            $this->group = $this->authConfig->db_group;
        }

        $this->tables = $this->authConfig->tables;

        parent::__construct();
    }
}
