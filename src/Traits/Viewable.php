<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace BlitzPHP\Schild\Traits;

use BlitzPHP\View\View;

trait Viewable
{
    /**
     * Fournit aux systèmes tiers un moyen de remplacer simplement la façon dont la vue est convertie en HTML
     * pour s'intégrer à leurs propres systèmes de templates.
     */
    protected function view(string $view, ?array $data = [], ?array $options = []): View
    {
        return view($view, $data, $options);
    }
}
