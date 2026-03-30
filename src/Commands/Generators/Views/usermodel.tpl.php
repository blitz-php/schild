<@php

namespace {namespace};

use BlitzPHP\Database\Builder\BaseBuilder;
<?php if ($hasCustomEntity): ?>
use {entityNamespace};
<?php else: ?>
use BlitzPHP\Schild\Entities\User;
<?php endif; ?>
use BlitzPHP\Schild\Models\UserModel as ShieldUserModel;

/**
 * Modèle utilisateur personnalisé
 * 
 * Ce modèle étend le modèle ShieldUserModel pour permettre des fonctionnalités
 * spécifiques à votre application tout en conservant toutes les fonctionnalités
 * d'authentification de Schild.
 * 
 * @method {entityClass}|null findById($id, bool $withPassword = false)
 * @method {entityClass}|null findByCredentials(array $credentials)
 */
class {class} extends ShieldUserModel
{
    /**
     * {@inheritDoc}
     */
    protected string $returnType = {entityClass}::class;
    
    /**
     * {@inheritDoc}
     * 
     * Personnalisez cette méthode si vous avez besoin d'une logique spécifique
     * pour trouver un utilisateur par ses identifiants (ex: connexion par téléphone, matricule, etc.)
     * 
     * @param array<string, string> $credentials Les identifiants de connexion (email, username, etc.)
     * @param BaseBuilder $builder Le constructeur de requête
     * @return BaseBuilder|null
     */
    protected function fetchByCredentials(array $credentials, BaseBuilder $builder): ?BaseBuilder
    {
        // Exemple de connexion par téléphone:
        // if (isset($credentials['phone'])) {
        //     $builder->where('phone', $credentials['phone']);
        //     unset($credentials['phone']);
        // }
        
        // Exemple de connexion avec un champ personnalisé "matricule":
        // if (isset($credentials['matricule'])) {
        //     $builder->where('matricule', $credentials['matricule']);
        //     unset($credentials['matricule']);
        // }
        
        // Appel parent pour la gestion standard (email, username)
        return parent::fetchByCredentials($credentials, $builder);
    }
}
