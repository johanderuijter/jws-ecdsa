<?php

namespace JDR\JWS\ECDSA;

use Lcobucci\JWT\Signature as LcobucciJWTSignature;
use Lcobucci\JWT\Signer\Key;
use Mdanter\Ecc\Crypto\Signature\Signature as EccSignature;
use Mdanter\Ecc\Crypto\Signature\Signer as EccSigner;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Math\GmpMathInterface;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use Mdanter\Ecc\Random\RandomGeneratorFactory;

class Signer
{
    const GENERATOR = [
        'ES256' => 'generator256',
        'ES384' => 'generator384',
        'ES512' => 'generator521',
    ];

    const HASH_ALGORITHM = [
        'ES256' => 'sha256',
        'ES384' => 'sha384',
        'ES512' => 'sha512',
    ];

    /**
     * @var GmpMathInterface
     */
    private $adapter;

    /**
     * @var GeneratorPoint
     */
    private $generator;

    /**
     * @var string
     */
    private $algorithm;

    /**
     * @var KeyParser
     */
    private $keyParser;

    /**
     * @var SignatureSerializer
     */
    private $serializer;

    /**
     * Constructor
     *
     * @param string $algorithm
     */
    public function __construct($algorithm)
    {
        $this->algorithm = $algorithm;
        $this->adapter = EccFactory::getAdapter();
        $this->generator = $this->getGenerator($algorithm);
        $this->keyParser = new KeyParser($this->adapter);
        $this->serializer = new SignatureSerializer($this->adapter);
    }

    /**
     * Returns a signature for given data
     *
     * @param string $payload
     * @param Key|string $key
     *
     * @return LcobucciJWTSignature
     *
     * @throws InvalidArgumentException When given key is invalid
     */
    public function sign($payload, $key)
    {
        if (!$key instanceof Key) {
            $key = new Key($key);
        }
        $privateKey = $this->keyParser->parsePrivateKey($key->getContent());

        $signer = new EccSigner($this->adapter);
        $hash = $signer->hashData($this->generator, $this->getHashAlgorithm($this->algorithm), $payload);

        $random = RandomGeneratorFactory::getRandomGenerator();

        $randomK = $random->generate($this->generator->getOrder());
        $signature = $signer->sign($privateKey, $hash, $randomK);

        return new LcobucciJWTSignature($this->serializer->serialize($signature, $this->algorithm));
    }

    /**
     * Returns if the expected hash matches with the data and key
     *
     * @param string $expected
     * @param string $payload
     * @param Key|string $key
     *
     * @return boolean
     *
     * @throws InvalidArgumentException When given key is invalid
     */
    public function verify($expected, $payload, $key)
    {
        if (!$key instanceof Key) {
            $key = new Key($key);
        }
        $publicKey = $this->keyParser->parsePublicKey($key->getContent());

        $signature = $this->serializer->unserialize($expected, $this->algorithm);

        $signer = new EccSigner($this->adapter);
        $hash = $signer->hashData($this->generator, $this->getHashAlgorithm($this->algorithm), $payload);

        return $signer->verify($publicKey, $signature, $hash);
    }

    /**
     * Get ecc generator
     *
     * @param string $algorithm
     *
     * @return string
     */
    private function getGenerator($algorithm)
    {
        $generator = self::GENERATOR[$algorithm];

        return EccFactory::getNistCurves()->$generator();
    }

    /**
     * Get hash algorithm
     *
     * @param string $algorithm
     *
     * @return string
     */
    private function getHashAlgorithm($algorithm)
    {
        return self::HASH_ALGORITHM[$algorithm];
    }
}
