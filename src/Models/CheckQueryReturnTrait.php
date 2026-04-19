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

    protected function hasDebug(): bool
    {
        return $this->db->getConfig('debug');
    }

    protected function setDbDebug(bool $value): void
    {
        $config = array_merge($this->db->getConfig(), ['debug' => $value]);

        $propertyConfig = $this->getPropertyConfig();
        $propertyConfig->setValue($this->db, $config);
    }

    protected function disableDBDebug(): void
    {
        if (! $this->hasDebug()) {
            // `DBDebug` is false. Do nothing.
            return;
        }

        $this->currentDBDebug = true;

        $this->setDbDebug(false);
    }

    protected function restoreDBDebug(): void
    {
        if ($this->currentDBDebug === null) {
            // `DBDebug` has not been changed. Do nothing.
            return;
        }

        $this->setDbDebug($this->currentDBDebug);

        $this->currentDBDebug = null;
    }

    protected function getPropertyConfig(): ReflectionProperty
    {
        $refClass = new ReflectionObject($this->db);

        return $refClass->getProperty('config');
    }
}
