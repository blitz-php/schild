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

namespace BlitzPHP\Schild\Database\Migrations;

use BlitzPHP\Database\Migration\Builder;
use BlitzPHP\Database\Migration\Migration;
use Closure;

class CreateAuthTables extends Migration
{
    /**
     * Noms des tables d'authentification
     *
     * @var array<string, string>
     */
    private array $tables;

    /**
     * Nom du groupe de base de données à utiliser
     */
    private string $group = 'default';

    public function __construct()
    {
        $authConfig = (object) config('auth');

        if ($authConfig->db_group !== null) {
            $this->group = $authConfig->db_group;
        }

        $this->tables = $authConfig->tables;
    }

    public function up(): void
    {
        // Table des utilisateurs
        $this->createTable($this->tables['users'], static function (Builder $table): void {
            $table->id();
            $table->string('username', 30)->nullable()->unique();
            $table->string('status')->nullable();
            $table->string('status_message')->nullable();
            $table->boolean('active')->nullable(false)->default(false);
            $table->dateTime('last_active')->nullable();
            $table->timestamps();
            $table->softDeletes();
        });

        /**
         * Table des identités d'authentification
         * Utilisé pour le stockage des mots de passe, des jetons d'accès, des identités de connexion sociale, etc.
         */
        $this->createTable($this->tables['identities'], function (Builder $table): void {
            $table->id();
            $table->foreignId('user_id')->constrained($this->tables['users'], 'id')->cascadeOnDelete();
            $table->string('type');
            $table->string('name')->nullable();
            $table->string('secret');
            $table->string('secret2')->nullable();
            $table->dateTime('expires')->nullable();
            $table->boolean('force_reset')->default(false);
            $table->text('extra')->nullable();
            $table->dateTime('last_used_at')->nullable();
            $table->timestamps();

            $table->unique(['type', 'secret']);
            $table->index('user_id');
        });

        /**
         * Table des tentatives de connexion d'authentification
         * Enregistre les tentatives de connexion. Une connexion signifie que les utilisateurs pensent qu'il s'agit d'une connexion.
         * Pour se connecter, les utilisateurs effectuent une ou plusieurs actions, comme publier un formulaire.
         */
        $this->createTable($this->tables['logins'], static function (Builder $table): void {
            $table->id();
            $table->unsignedBigInteger('user_id')->nullable();
            $table->ipAddress();
            $table->string('user_agent')->nullable();
            $table->string('id_type');
            $table->string('secret')->nullable();
            $table->string('identifier');
            $table->dateTime('date');
            $table->boolean('success');

            $table->index(['id_type', 'identifier']);
            $table->index('user_id'); // REMARQUE : Ne supprimez PAS le user_id ou l'identifiant lorsque l'utilisateur est supprimé pour les audits de sécurité
        });

        /**
         * Table des tentatives de connexion au jeton d'authentification
         * Enregistre les tentatives de connexion de type Bearer Token.
         */
        $this->createTable($this->tables['token_logins'], static function (Builder $table): void {
            $table->id();
            $table->unsignedBigInteger('user_id')->nullable();
            $table->ipAddress();
            $table->string('user_agent')->nullable();
            $table->string('id_type');
            $table->string('identifier');
            $table->dateTime('date');
            $table->boolean('success');

            $table->index(['id_type', 'identifier']);
            $table->index('user_id'); // REMARQUE : Ne supprimez PAS le user_id ou l'identifiant lorsque l'utilisateur est supprimé pour les audits de sécurité
        });

        /**
         * Table Auth Remember Tokens (remember-me)
         *
         * @see https://paragonie.com/blog/2015/04/secure-authentication-php-with-long-term-persistence
         */
        $this->createTable($this->tables['remember_tokens'], function (Builder $table): void {
            $table->id();
            $table->foreignId('user_id')->constrained($this->tables['users'], 'id')->cascadeOnDelete();
            $table->string('selector')->unique();
            $table->string('hashedValidator');
            $table->dateTime('expires');
            $table->timestamps();
        });

        // Table des utilisateurs des groupes
        $this->createTable($this->tables['groups_users'], function (Builder $table): void {
            $table->id();
            $table->foreignId('user_id')->constrained($this->tables['users'], 'id')->cascadeOnDelete();
            $table->string('group');
            $table->timestamp('created_at');
        });

        // Table des autorisations des utilisateurs
        $this->createTable($this->tables['permissions_users'], function (Builder $table): void {
            $table->id();
            $table->foreignId('user_id')->constrained($this->tables['users'], 'id')->cascadeOnDelete();
            $table->string('permission');
            $table->timestamp('created_at');
        });
    }

    public function down(): void
    {
        $this->db->disableForeignKeyChecks();

        $this->connection($this->group)->dropIfExists($this->tables['logins']);
        $this->connection($this->group)->dropIfExists($this->tables['token_logins']);
        $this->connection($this->group)->dropIfExists($this->tables['remember_tokens']);
        $this->connection($this->group)->dropIfExists($this->tables['identities']);
        $this->connection($this->group)->dropIfExists($this->tables['groups_users']);
        $this->connection($this->group)->dropIfExists($this->tables['permissions_users']);
        $this->connection($this->group)->dropIfExists($this->tables['users']);

        $this->db->enableForeignKeyChecks();
    }

    private function createTable(string $table, Closure $callback): void
    {
        $this->connection($this->group)->create($table, function (Builder $table) use ($callback): void {
            if ($this->db->getDriver() === 'mysql') {
                $table->innoDb();
            }

            $callback($table);
        });
    }
}
