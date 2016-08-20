<?php

namespace JDR\JWS\ECDSA;

use Lcobucci\JWT\Signature as LcobucciJWTSignature;
use Lcobucci\JWT\Signer as LcobucciJWTSigner;
use Lcobucci\JWT\Signer\Key;
use Mdanter\Ecc\Crypto\Signature\Signature as EccSignature;
use Mdanter\Ecc\Crypto\Signature\Signer as EccSigner;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Math\GmpMathInterface;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use Mdanter\Ecc\Random\RandomGeneratorFactory;

abstract class AbstractSigner implements LcobucciJWTSigner
{
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
     * @param GeneratorPoint $generator
     */
    public function __construct(GeneratorPoint $generator)
    {
        $this->generator = $generator;
        $this->adapter = EccFactory::getAdapter();
        $this->keyParser = new KeyParser($this->adapter);
        $this->serializer = new SignatureSerializer($this->adapter);
    }

    /**
     * Returns the algorithm id
     *
     * @return string
     */
    abstract public function getAlgorithmId();

    /**
     * Apply changes on headers according with algorithm
     *
     * @param array $headers
     */
    public function modifyHeader(array &$headers)
    {
        $headers['alg'] = $this->getAlgorithmId();
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
        $hash = $signer->hashData($this->generator, $this->getHashAlgorithm($this->getAlgorithmId()), $payload);

        $random = RandomGeneratorFactory::getRandomGenerator();

        $randomK = $random->generate($this->generator->getOrder());
        $signature = $signer->sign($privateKey, $hash, $randomK);

        return new LcobucciJWTSignature($this->serializer->serialize($signature, $this->getAlgorithmId()));
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

        $signature = $this->serializer->unserialize($expected, $this->getAlgorithmId());

        $signer = new EccSigner($this->adapter);
        $hash = $signer->hashData($this->generator, $this->getHashAlgorithm($this->getAlgorithmId()), $payload);

        return $signer->verify($publicKey, $signature, $hash);
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
