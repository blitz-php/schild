<?php

/**
 * This file is part of Blitz PHP framework - Schild.
 *
 * (c) 2023 Dimitri Sitchet Tomkeu <devcode.dst@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace BlitzPHP\Schild\Database\Migrations;

use BlitzPHP\Database\Migration\Migration;
use BlitzPHP\Database\Migration\Structure;

class CreateAuthTables extends Migration
{
    /**
     * Noms des tables d'authentification
     *
     * @var array<string, string>
     */
    private array $tables;

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
        $this->create($this->tables['users'], static function (Structure $table) {
            $table->id();
            $table->string('username', 30)->nullable()->unique();
            $table->string('status')->nullable();
            $table->string('status_message')->nullable();
            $table->boolean('active')->nullable(false)->default(false);
            $table->dateTime('last_active')->nullable();
            $table->timestamps();
            $table->softDeletes();

            return $table;
        });

        /**
         * Table des identités d'authentification
         * Utilisé pour le stockage des mots de passe, des jetons d'accès, des identités de connexion sociale, etc.
         */
        $this->create($this->tables['identities'], function (Structure $table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
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
            $table->foreign('user_id')->on($this->tables['users'])->references('id')->onDelete('cascade');

            return $table;
        });

        /**
         * Table des tentatives de connexion d'authentification
         * Enregistre les tentatives de connexion. Une connexion signifie que les utilisateurs pensent qu'il s'agit d'une connexion.
         * Pour se connecter, les utilisateurs effectuent une ou plusieurs actions, comme publier un formulaire.
         */
        $this->create($this->tables['logins'], static function (Structure $table) {
            $table->id();
            $table->unsignedBigInteger('user_id')->nullable();
            $table->ipAddress();
            $table->string('user_agent');
            $table->string('id_type');
            $table->string('secret');
            $table->string('identifier');
            $table->dateTime('date');
            $table->boolean('success');

            $table->index(['id_type', 'identifier']);
            $table->index('user_id');

            return $table;
        });
        // REMARQUE : Ne supprimez PAS le user_id ou l'identifiant lorsque l'utilisateur est supprimé pour les audits de sécurité

        /**
         * Table des tentatives de connexion au jeton d'authentification
         * Enregistre les tentatives de connexion de type Bearer Token.
         */
        $this->create($this->tables['token_logins'], static function (Structure $table) {
            $table->id();
            $table->unsignedBigInteger('user_id')->nullable();
            $table->ipAddress();
            $table->string('user_agent')->nullable();
            $table->string('id_type');
            $table->string('identifier');
            $table->dateTime('date');
            $table->boolean('success');

            $table->index(['id_type', 'identifier']);
            $table->index('user_id');

            return $table;
        });
        // REMARQUE : Ne supprimez PAS le user_id ou l'identifiant lorsque l'utilisateur est supprimé pour les audits de sécurité

        /**
         * Table Auth Remember Tokens (remember-me)
         *
         * @see https://paragonie.com/blog/2015/04/secure-authentication-php-with-long-term-persistence
         */
        $this->create($this->tables['remember_tokens'], function (Structure $table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
            $table->string('selector')->unique();
            $table->string('hashedValidator');
            $table->dateTime('expires');
            $table->timestamps();

            $table->foreign('user_id')->on($this->tables['users'])->references('id')->onDelete('CASCADE');

            return $table;
        });

        // Table des utilisateurs des groupes
        $this->create($this->tables['groups_users'], function (Structure $table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
            $table->string('group');
            $table->timestamp('created_at');

            $table->foreign('user_id')->on($this->tables['users'])->references('id')->onDelete('CASCADE');

            return $table;
        });

        // Table des autorisations des utilisateurs
        $this->create($this->tables['permissions_users'], function (Structure $table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
            $table->string('permission');
            $table->timestamp('created_at');

            $table->foreign('user_id')->on($this->tables['users'])->references('id')->onDelete('CASCADE');

            return $table;
        });
    }

    public function down(): void
    {
        // $this->disableForeignKeyChecks();

        $this->dropIfExists($this->tables['logins']);
        $this->dropIfExists($this->tables['token_logins']);
        $this->dropIfExists($this->tables['remember_tokens']);
        $this->dropIfExists($this->tables['identities']);
        $this->dropIfExists($this->tables['groups_users']);
        $this->dropIfExists($this->tables['permissions_users']);
        $this->dropIfExists($this->tables['users']);

        // $this->enableForeignKeyChecks();
    }
}
