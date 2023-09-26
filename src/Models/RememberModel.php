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

namespace BlitzPHP\Schild\Models;

use BlitzPHP\Schild\Entities\User;
use DateTime;
use stdClass;

class RememberModel extends BaseModel
{
    protected string $returnType = 'object';

    public function __construct()
    {
        parent::__construct();

        $this->table = $this->tables['remember_tokens'];
    }

    /**
     * Stores a remember-me token for the user.
     */
    public function rememberUser(User $user, string $selector, string $hashedValidator, string $expires): void
    {
        $expires = new DateTime($expires);

        $return = $this->insert([
            'user_id'         => $user->id,
            'selector'        => $selector,
            'hashedValidator' => $hashedValidator,
            'expires'         => $expires->format('Y-m-d H:i:s'),
        ]);

        $this->checkQueryReturn($return);
    }

    /**
     * Returns the remember-me token info for a given selector.
     */
    public function getRememberToken(string $selector): ?stdClass
    {
        return $this->where('selector', $selector)->first(); // @phpstan-ignore-line
    }

    /**
     * Updates the validator for a given selector.
     */
    public function updateRememberValidator(stdClass $token): void
    {
        $return = $this->save($token);

        $this->checkQueryReturn($return);
    }

    /**
     * Removes all persistent login tokens (remember-me) for a single user
     * across all devices they may have logged in with.
     */
    public function purgeRememberTokens(User $user): void
    {
        $return = $this->where(['user_id' => $user->id])->delete();

        $this->checkQueryReturn($return);
    }

    /**
     * Purges the 'auth_remember_tokens' table of any records that are past
     * their expiration date already.
     */
    public function purgeOldRememberTokens(): void
    {
        $return = $this->where('expires <=', date('Y-m-d H:i:s'))
            ->delete();

        $this->checkQueryReturn($return);
    }
}
