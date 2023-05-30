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

use BlitzPHP\Schild\Exceptions\DatabaseException;
use ReflectionObject;
use ReflectionProperty;

trait CheckQueryReturnTrait
{
    protected ?bool $currentDBDebug = null;

    /**
     * @param bool|int|string $return insert() returns insert ID.
     */
    protected function checkQueryReturn($return): void
    {
        $this->restoreDBDebug();

        if ($return === false) {
            $error   = $this->db->error();
            $message = 'Query error: ' . $error['code'] . ', '
                . $error['message'] . ', query: ' . $this->db->getLastQuery();

            throw new DatabaseException($message, (int) $error['code']);
        }
    }

    protected function disableDBDebug(): void
    {
        if (! $this->db->debug) {
            // `DBDebug` is false. Do nothing.
            return;
        }

        $this->currentDBDebug = $this->db->debug;

        $propertyDBDebug = $this->getPropertyDBDebug();
        $propertyDBDebug->setValue($this->db, false);
    }

    protected function restoreDBDebug(): void
    {
        if ($this->currentDBDebug === null) {
            // `DBDebug` has not been changed. Do nothing.
            return;
        }

        $propertyDBDebug = $this->getPropertyDBDebug();
        $propertyDBDebug->setValue($this->db, $this->currentDBDebug);

        $this->currentDBDebug = null;
    }

    protected function getPropertyDBDebug(): ReflectionProperty
    {
        $refClass    = new ReflectionObject($this->db);
        $refProperty = $refClass->getProperty('debug');
        $refProperty->setAccessible(true);

        return $refProperty;
    }
}
