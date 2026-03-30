<@php

declare(strict_types=1);

namespace {namespace};

use BlitzPHP\Schild\Entities\User as ShieldUser;

class {entityName} extends ShieldUser
{    
    /**
     * {@inheritDoc}
     */
    protected array $fillable = [
        'username',
        // Ajoutez vos propres champs ici
    ];
    
    /**
     * {@inheritDoc}
     */
    protected array $casts = [
        'id'          => '?integer',
        'active'      => 'boolean',
        'last_active' => 'datetime',
        // Ajoutez vos propres casts ici
    ];
    
    // Ajoutez vos propres méthodes ici
}
