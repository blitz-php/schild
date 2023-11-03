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

namespace BlitzPHP\Schild\Validation;

use BlitzPHP\Schild\Authentication\Passwords;
use BlitzPHP\Validation\Rule;

class ValidationRules
{
    /**
     * Regles de validation de l'inscription
     *
     * @return array{rules: [], messages: [], alias: []}
     */
    public static function register(): array
    {
        if (! empty($validation = config('validation.register'))) {
            return static::makeValidationItems($validation);
        }

        $config = (object) config('auth');

        $usernameRules            = $config->username_validation_rules;
        $usernameRules['rules'][] = Rule::unique($config->tables['users'], 'username');

        $emailRules            = $config->email_validation_rules;
        $emailRules['rules'][] = Rule::unique($config->tables['identities'], 'secret');

        $passwordRules            = static::password();
        $passwordRules['rules'][] = Rule::password()->strong();

        $validation = [
            'username'              => $usernameRules,
            'email'                 => $emailRules,
            'password'              => $passwordRules,
            'password_confirmation' => static::passwordConfirmation(),
        ];

        return static::makeValidationItems($validation);
    }

    /**
     * Regles de validation de la connexion
     *
     * @return array{rules: [], messages: [], alias: []}
     */
    public static function login(): array
    {
        $config = (object) config('auth');

        $fields = ['password' => static::password()];

        if (in_array('email', $config->valid_fields)) {
            $fields['email'] = $config->email_validation_rules ?? [];
        }
        if (in_array('username', $config->valid_fields)) {
            $fields['username'] = $config->username_validation_rules ?? [];
        }

        $validation = config('validation.login', $fields);

        return static::makeValidationItems($validation);
    }

    /**
     * Regles de validation propres au mot de passe
     */
    public static function password(): array
    {
        return [
            'label'    => lang('Auth.password'),
            'rules'    => ['required', Passwords::getMaxLengthRule()],
            'messages' => [
                'required' => lang('Auth.errorPasswordEmpty'),
            ],
        ];
    }

    /**
     * Regles de validation de la confirmation du mot de passe
     */
    public static function passwordConfirmation(): array
    {
        return [
            'label' => lang('Auth.passwordConfirm'),
            'rules' => ['required', 'same:password'],
        ];
    }

    public static function makeMessage(array &$messages, array $errors, string $label): void
    {
        foreach ($errors as $key => $value) {
            if (is_int($key)) {
                continue;
            }
            $messages[$label . ':' . $key] = $value;
        }
    }

    /**
     * Formate les regles pour le validateur
     *
     * @return array{rules: [], messages: [], alias: []}
     */
    protected static function makeValidationItems(array $validation): array
    {
        $username              = $validation['username'] ?? [];
        $email                 = $validation['email'] ?? [];
        $password              = $validation['password'] ?? [];
        $password              = $validation['password'] ?? [];
        $password_confirmation = $validation['password_confirmation'] ?? [];

        $rules    = [];
        $alias    = [];
        $messages = [];

        if (! empty($username)) {
            $rules['username'] = $username['rules'];
            $alias['username'] = $username['label'];
            static::makeMessage($messages, $username['messages'] ?? [], 'username');
        }
        if (! empty($email)) {
            $rules['email'] = $email['rules'];
            $alias['email'] = $email['label'];
            static::makeMessage($messages, $email['messages'] ?? [], 'email');
        }
        if (! empty($password)) {
            $rules['password'] = $password['rules'];
            $alias['password'] = $password['label'];
            static::makeMessage($messages, $password['messages'] ?? [], 'password');
        }
        if (! empty($password_confirmation)) {
            $rules['password_confirmation'] = $password_confirmation['rules'];
            $alias['password_confirmation'] = $password_confirmation['label'];
            static::makeMessage($messages, $password_confirmation['messages'] ?? [], 'password_confirmation');
        }

        return compact('rules', 'alias', 'messages');
    }
}
