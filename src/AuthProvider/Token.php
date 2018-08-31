<?php

/*
 * This file is part of the Pushok package.
 *
 * (c) Arthur Edamov <edamov@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Pushok\AuthProvider;

use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Pushok\AuthProviderInterface;
use Pushok\Request;

/**
 * Class Token
 * @package Pushok\AuthProvider
 *
 * @see http://bit.ly/communicating-with-apns
 */
class Token implements AuthProviderInterface
{
    /**
     * Hash alghorithm for generating auth token.
     */
    const HASH_ALGORITHM = 'ES256';

    /**
     * Generated auth token.
     *
     * @var string
     */
    private $token;

    /**
     * Path to p8 private key.
     *
     * @var string
     */
    private $privateKeyPath;

    /**
     * Private key secret.
     *
     * @var string|null
     */
    private $privateKeySecret;

    /**
     * The Key ID obtained from Apple developer account.
     *
     * @var string
     */
    private $keyId;

    /**
     * The Team ID obtained from Apple developer account.
     *
     * @var string
     */
    private $teamId;

    /**
     * The bundle ID for app obtained from Apple developer account.
     *
     * @var string
     */
    private $appBundleId;

    /**
     * This provider accepts the following options:
     *
     * - key_id
     * - team_id
     * - app_bundle_id
     * - private_key_path
     * - private_key_secret
     *
     * @param array $options
     */
    private function __construct(array $options)
    {
        $this->keyId = $options['key_id'];
        $this->teamId = $options['team_id'];
        $this->appBundleId = $options['app_bundle_id'];
        $this->privateKeyPath = $options['private_key_path'];
        $this->privateKeySecret = $options['private_key_secret'] ?: null;
    }

    /**
     * Create Token Auth Provider.
     *
     * @param array $options
     * @return Token
     */
    public static function create(array $options): Token
    {
        $token = new self($options);
        $token->token = $token->generate();

        return $token;
    }

    /**
     * Use previously generated token.
     *
     * @param string $tokenString
     * @param array $options
     * @return Token
     */
    public static function useExisting(string $tokenString, array $options): Token
    {
        $token = new self($options);
        $token->token = $tokenString;

        return $token;
    }

    /**
     * Authenticate client.
     *
     * @param Request $request
     */
    public function authenticateClient(Request $request)
    {
        $request->addHeaders([
            "apns-topic" => $this->appBundleId,
            'Authorization' => 'bearer ' . $this->token
        ]);
    }

    /**
     * Get last generated token.
     *
     * @return string
     */
    public function get(): string
    {
        return $this->token;
    }

    /**
     * Generate private EC key.
     *
     * @return JWK
     */
    private function generatePrivateECKey(): JWK
    {
        return JWKFactory::createFromKeyFile($this->privateKeyPath, $this->privateKeySecret, [
            'kid' => $this->keyId,
            'alg' => self::HASH_ALGORITHM,
            'use' => 'sig'
        ]);
    }

    /**
     * Get claims payload.
     *
     * @return array
     */
    private function getClaimsPayload(): array
    {
        return [
            'iss' => $this->teamId,
            'iat' => time(),
        ];
    }

    /**
     * Get protected header.
     *
     * @param JWK $privateECKey
     * @return array
     */
    private function getProtectedHeader(JWK $privateECKey): array
    {
        return [
            'alg' => self::HASH_ALGORITHM,
            'kid' => $privateECKey->get('kid'),
        ];
    }

    /**
     * Generate new token.
     *
     * @return string
     */
    private function generate(): string
    {
        $privateECKey = $this->generatePrivateECKey();
        $protectedHeader = $this->getProtectedHeader($privateECKey);

        // This converter wraps json_encode/json_decode with some parameters
        $jsonConverter = new StandardConverter();

        // This managers handles all algorithms we need to use.
        $algorithmManager = AlgorithmManager::create([
            new ES256(),
        ]);

        // The JWS Builder
        $jwsBuilder = new JWSBuilder($jsonConverter, $algorithmManager);

        // First we have to encode the payload. Now only strings are accepted.
        $payload = $jsonConverter->encode($this->getClaimsPayload());

        // We build our JWS object
        $jws = $jwsBuilder
            ->create()                    // Indicates we want to create a new token
            ->withPayload($payload)       // We set the payload
            ->addSignature($privateECKey, $protectedHeader) // We add a signature
            ->build();                    // We compute the JWS

        // We need to serialize the token.
        // In this example we will use the compact serialization mode (most common mode).
        $serializer = new CompactSerializer($jsonConverter);
        $this->token = $serializer->serialize($jws);

        return $this->token;
    }
}
