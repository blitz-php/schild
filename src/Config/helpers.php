<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

use BlitzPHP\Schild\Auth;
use BlitzPHP\Schild\Config\Services;

if (! function_exists('auth')) {
    /**
     * Fournit un accès pratique à la classe Auth principale.
     *
     * @param string|null $alias Authenticator alias
     */
    function auth(?string $alias = null): Auth
    {
        return Services::auth()->setAuthenticator($alias);
    }
}

if (! function_exists('user_id')) {
    /**
     * Renvoie l'ID de l'utilisateur actuellement connecté.
     * Remarque : Pour \BlitzPHP\Schild\Entities\User, cela renverra toujours un int.
     *
     * @return int|string|null
     */
    function user_id()
    {
        return Services::auth()->id();
    }
}

if (! defined('emailer')) {
    /**
     * Fournit un accès pratique à la classe Email.
     *
     * @internal
     */
    function emailer(array $overrides = []): Email
    {
        $config = [
            'userAgent'     => config('email.userAgent'),
            'protocol'      => config('email.protocol'),
            'mailPath'      => config('email.mail_path'),
            'SMTPHost'      => config('email.smtp_host'),
            'SMTPUser'      => config('email.smtp_user'),
            'SMTPPass'      => config('email.smtp_pass'),
            'SMTPPort'      => config('email.smtp_port'),
            'SMTPTimeout'   => config('email.smtp_timeout'),
            'SMTPKeepAlive' => config('email.smtp_keep_alive'),
            'SMTPCrypto'    => config('email.smtp_crypto'),
            'wordWrap'      => config('email.word_wrap'),
            'wrapChars'     => config('email.wrap_chars'),
            'mailType'      => config('email.mail_type'),
            'charset'       => config('email.charset'),
            'validate'      => config('email.validate'),
            'priority'      => config('email.priority'),
            'CRLF'          => config('email.crlf'),
            'newline'       => config('email.newline'),
            'BCCBatchMode'  => config('email.bbc_batch_mode'),
            'BCCBatchSize'  => config('email.bbc_batch_size'),
            'DSN'           => config('email.dsn'),
        ];

        if ($overrides !== []) {
            $config = array_merge($overrides, $config);
        }

        /** @var Email $email */
        $email = service('email');

        return $email->initialize($config);
    }
}
