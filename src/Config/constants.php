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

defined('RECORD_LOGIN_ATTEMPT_NONE')    || define('RECORD_LOGIN_ATTEMPT_NONE', 0); // Ne pas enregistrer du tout
defined('RECORD_LOGIN_ATTEMPT_FAILURE') || define('RECORD_LOGIN_ATTEMPT_FAILURE', 1); // Enregistrer uniquement les échecs
defined('RECORD_LOGIN_ATTEMPT_ALL')     || define('RECORD_LOGIN_ATTEMPT_ALL', 2); // Enregistrer toutes les tentatives de connexion
