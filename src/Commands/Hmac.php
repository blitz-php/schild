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

namespace BlitzPHP\Schild\Commands;

use BlitzPHP\Cli\Console\Command;
use BlitzPHP\Schild\Authentication\HMAC\HmacEncrypter;
use BlitzPHP\Schild\Models\UserIdentityModel;
use Exception;
use InvalidArgumentException;
use ReflectionException;
use RuntimeException;

class Hmac extends Command
{
    /**
     * @var string
     */
    protected $group = 'Schild';

    /**
     * @var string
     */
    protected $name = 'schild:hmac';

    /**
     * @var string
     */
    protected $description = 'Encrypte/Decrypte secretKey pour les tokens HMAC.';

    /**
     * @var string
     */
    protected $usage = <<<'EOL'
        schild:hmac <action>
            schild:hmac reencrypt
            schild:hmac encrypt
            schild:hmac decrypt

            La commande reencrypt doit être utilisée lors de la rotation des clés de chiffrement.
            La commande encrypt ne doit être exécutée que sur des clés secrètes brutes existantes (extrêmement rare).
        EOL;

    /**     *
     * @var array
     */
    protected $arguments = [
        'action' => <<<'EOL'
                reencrypt : réencrypte toutes les clés secrètes HMAC lors de la rotation de la clé de chiffrement
                encrypt : Crypte toutes les clés secrètes HMAC brutes
                decrypt : déchiffrer toutes les clés secrètes HMAC chiffrées
            EOL,
    ];

    /**
     * HMAC Encrypter
     */
    private HmacEncrypter $encrypter;

    /**
     * {@inheritDoc}
     */
    public function execute(array $params)
    {
        $action = $this->argument('action');

        $this->encrypter = new HmacEncrypter();

        try {
            switch ($action) {
                case 'encrypt':
                    $this->encrypt();
                    break;

                case 'decrypt':
                    $this->decrypt();
                    break;

                case 'reencrypt':
                    $this->reEncrypt();
                    break;

                default:
                    throw new InvalidArgumentException('Commande non reconnue');
            }
        } catch (Exception $e) {
            $this->fail($e->getMessage());

            return EXIT_ERROR;
        }

        return EXIT_SUCCESS;
    }

    /**
     * Chiffrer toutes les clés secrètes HMAC brutes
     *
     * @throws ReflectionException
     */
    public function encrypt(): void
    {
        $uIdModel    = new UserIdentityModel();
        $uIdModelSub = new UserIdentityModel(); // Pour économiser.
        $encrypter   = $this->encrypter;

        $that = $this;

        $uIdModel->where('type', 'hmac_sha256')->orderBy('id')->chunk(
            100,
            static function ($identity) use ($uIdModelSub, $encrypter, $that): void {
                if ($encrypter->isEncrypted($identity->secret2)) {
                    $that->write('id: ' . $identity->id . ', déjà crypté, il est ignoré.');

                    return;
                }

                try {
                    $identity->secret2 = $encrypter->encrypt($identity->secret2);
                    $uIdModelSub->save($identity);

                    $that->write('id: ' . $identity->id . ', crypté.');
                } catch (RuntimeException $e) {
                    $that->error('id: ' . $identity->id . ', ' . $e->getMessage());
                }
            }
        );
    }

    /**
     * Déchiffrer toutes les clés secrètes HMAC chiffrées
     *
     * @throws ReflectionException
     */
    public function decrypt(): void
    {
        $uIdModel    = new UserIdentityModel();
        $uIdModelSub = new UserIdentityModel(); // Pour économiser.
        $encrypter   = $this->encrypter;

        $that = $this;

        $uIdModel->where('type', 'hmac_sha256')->orderBy('id')->chunk(
            100,
            static function ($identity) use ($uIdModelSub, $encrypter, $that): void {
                if (! $encrypter->isEncrypted($identity->secret2)) {
                    $that->write('id: ' . $identity->id . ', non crypté, ignoré.');

                    return;
                }

                $identity->secret2 = $encrypter->decrypt($identity->secret2);
                $uIdModelSub->save($identity);

                $that->write('id: ' . $identity->id . ', decrypté.');
            }
        );
    }

    /**
     * Recrypter toutes les clés secrètes HMAC cryptées à partir de la clé de cryptage existante/dépréciée vers la nouvelle clé de cryptage.
     *
     * @throws ReflectionException
     */
    public function reEncrypt(): void
    {
        $uIdModel    = new UserIdentityModel();
        $uIdModelSub = new UserIdentityModel(); // For saving.
        $encrypter   = $this->encrypter;

        $that = $this;

        $uIdModel->where('type', 'hmac_sha256')->orderBy('id')->chunk(
            100,
            static function ($identity) use ($uIdModelSub, $encrypter, $that): void {
                if ($encrypter->isEncryptedWithCurrentKey($identity->secret2)) {
                    $that->write('id: ' . $identity->id . ', déjà chiffré avec la clé actuelle, il est ignoré.');

                    return;
                }

                $identity->secret2 = $encrypter->decrypt($identity->secret2);
                $identity->secret2 = $encrypter->encrypt($identity->secret2);
                $uIdModelSub->save($identity);

                $that->write('id: ' . $identity->id . ', Ré-encrypté.');
            }
        );
    }
}
