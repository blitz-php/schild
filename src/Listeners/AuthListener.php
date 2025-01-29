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

namespace BlitzPHP\Schild\Listeners;

use BlitzPHP\Contracts\Event\EventInterface;
use BlitzPHP\Contracts\Event\EventListenerInterface;
use BlitzPHP\Contracts\Event\EventManagerInterface;

class AuthListener implements EventListenerInterface
{
    public function listen(EventManagerInterface $event): void
    {
        $event->on('schild:login', fn($e) => $this->onLogin($e));
	}

	private function onLogin(EventInterface $event) 
	{
		// Apres la connexion, on supprime les erreurs potentiellement survenues (mot de passe invalide)
		// pour eviter les problemes avec des vues d'autres pages qui peuvent les capturer et croire que c'est une erreur de la requete courante
		session()->remove(['errors']);
	}
}
