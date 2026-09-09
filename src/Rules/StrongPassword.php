<?php

declare(strict_types=1);

namespace BlitzPHP\Schild\Rules;

use BlitzPHP\Schild\Authentication\Passwords;
use BlitzPHP\Schild\Entities\User;
use BlitzPHP\Validation\Rule;
use BlitzPHP\Validation\Rules\AbstractRule;
use BlitzPHP\Validation\Validator;

class StrongPassword extends AbstractRule
{
    protected $message = ':value is not a stronger password';

    /**
     * @var array
     */
    protected $fillableParams = ['guard'];

    protected array $data = [];

    public function check($value): bool
    {
        $attribute = $this->getAttribute()->getKey();

        $validator = Validator::make(
            [$attribute => $value], 
            [$attribute => Rule::password(1)->strong()],
            $this->validation->getMessages(),
        );

        $rule = static::name();

        // Vérification de la composition du mot de passe
        if ($validator->fails()) {
            $message = $this->getCustomMessage(
				$attribute . ':' . $rule . '.composition',
				$validator->errors()->first($attribute)
			);
            
			$this->validation->errors()->add(
				$attribute, 
				$rule . '.composition',
				$message
			);
		
			return false;
        }

        /** @var Passwords $checker */
        $checker = service('passwords');

        if (null === $user = auth($this->parameter('guard'))->user()) {
            $user = $this->data === [] ? $this->buildUserFromRequest() : $this->buildUserFromData();
        }

        $result = $checker->check($value, $user);

        if (! $result->isOK()) {
			$message = $this->getCustomMessage(
				$attribute . ':' . $rule . '.validator',
				$result->reason()
			);
            
			$this->validation->errors()->add(
				$attribute, 
				$rule . '.validator',
				$message
			);
		}

        return $result->isOK();
    }

    /**
     * Récupère un message personnalisé s'il existe
     */
    protected function getCustomMessage(string $key, string $default): string
    {
        $messages = $this->validation->getMessages();
        
        if (isset($messages[$key])) {
            return $messages[$key];
        }
        
        return $default;
    }

    /**
     * Construit une nouvelle instance d'utilisateur à partir de la requête globale.
     */
    protected function buildUserFromRequest(): User
    {
        $fields = $this->prepareValidFields();

        $data = service('request')->only($fields);

        return new User($data);
    }

    /**
     * Construit une nouvelle instance d'utilisateur à partir des données attribuées.
     */
    protected function buildUserFromData(): User
    {
        $fields = $this->prepareValidFields();

        $data = array_intersect_key($this->data, array_fill_keys($fields, null));

        return new User($data);
    }

    /**
     * Préparer des champs utilisateur valides
     */
    protected function prepareValidFields(): array
    {
        $config = (object) config('auth');
        $fields = array_merge($config->valid_fields, $config->personal_fields, ['email', 'password']);

        return array_unique($fields);
    }
}
