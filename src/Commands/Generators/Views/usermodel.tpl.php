<@php

namespace {namespace};

<?php if (class_exists('\App\Entity\User')): ?>
use App\Entities\User;
<?php endif; ?>
use BlitzPHP\Schild\Models\UserModel as ShieldUserModel;

class {class} extends ShieldUserModel
{
<?php if (class_exists('\App\Entity\User')): ?>
    protected string $returnType = User::class;
<?php endif; ?>
    /**
	 * {@inheritDoc}
	 * 
	 * @override
	 */
	protected function fetchByCredentials(array $credentials, BaseBuilder $builder): ?BaseBuilder
	{
        // Implémentez votre logique personnalisée pour récupérer l'utilisateur en fonction des informations d'identification fournies.
        // Vous pouvez utiliser les informations d'identification $credentials et $builder pour interroger la base de données.
       
		return parent::fetchByCredentials($credentials, $builder);
	}
}
