<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace BlitzPHP\Schild\Entities\Cast;

use BlitzPHP\Wolke\Contracts\Castable;
use BlitzPHP\Wolke\Contracts\CastsAttributes;
use BlitzPHP\Wolke\Model;

/**
 * Int Bool Cast
 *
 * DB column: int (0/1) <--> Class property: bool
 */
final class IntBoolCast implements Castable
{
    /**
     * {@inheritDoc}
     */
    public static function castUsing(array $arguments): CastsAttributes
    {
        return new class () implements CastsAttributes {
            public function get(Model $model, string $key, mixed $value, array $attributes): mixed
            {
                return (bool) $value;
            }

            public function set(Model $model, string $key, mixed $value, array $attributes): mixed
            {
                return (int) $value;
            }
        };
    }
}
