<?php

namespace JDR\JWS\ECDSA;

use function class_exists;
use GMP;
use Lcobucci\JWT\Signature as LcobucciJWTSignature;
use Lcobucci\JWT\Signer\Key;
use Mdanter\Ecc\Crypto\Signature\Signer as EccSigner;
use Mdanter\Ecc\Crypto\Signature\SignHasher;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Math\GmpMathInterface;
use Mdanter\Ecc\Random\RandomGeneratorFactory;

class Signer
{
    /**
     * @var SignerConfig
     */
    private $config;

    /**
     * @var GmpMathInterface
     */
    private $adapter;

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
     * @param SignerConfig $config
     */
    public function __construct($config)
    {
        $this->config = $config;
        $this->adapter = EccFactory::getAdapter();
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

        $hash = $this->hash($payload);

        $random = RandomGeneratorFactory::getRandomGenerator();
        $randomK = $random->generate($this->config->getGenerator()->getOrder());

        $signer = new EccSigner($this->adapter);
        $signature = $signer->sign($privateKey, $hash, $randomK);

        return new LcobucciJWTSignature($this->serializer->serialize($signature, $this->config->getSignatureLength()));
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

        $signature = $this->serializer->unserialize($expected, $this->config->getSignatureLength());

        $hash = $this->hash($payload);

        $signer = new EccSigner($this->adapter);

        return $signer->verify($publicKey, $signature, $hash);
    }

    /**
     * Hash the payload
     *
     * @param string $payload
     *
     * @return GMP
     */
    private function hash($payload)
    {
        if (class_exists(SignHasher::class)) {
            $hasher = new SignHasher($this->config->getHashingAlgorithm());

            return $hasher->makeHash($payload, $this->config->getGenerator());
        }

        $signer = new EccSigner($this->adapter);

        return $signer->hashData($this->config->getGenerator(), $this->config->getHashingAlgorithm(), $payload);
    }
}
