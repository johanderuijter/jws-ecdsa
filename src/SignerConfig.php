<?php

namespace JDR\JWS\ECDSA;

use Mdanter\Ecc\Primitives\GeneratorPoint;

class SignerConfig
{
    /**
     * @var GeneratorPoint
     */
    private $generator;

    /**
     * @var string
     */
    private $hashingAlgorithm;

    /**
     * @var int
     */
    private $signatureLength;

    /**
     * Constructor
     *
     * @param GeneratorPoint $hashingAlgorithm
     * @param string $hashingAlgorithm
     * @param int $hashingAlgorithm
     */
    public function __construct(GeneratorPoint $generator, $hashingAlgorithm, $signatureLength)
    {
        $this->generator = $generator;
        $this->hashingAlgorithm = $hashingAlgorithm;
        $this->signatureLength = $signatureLength;
    }

    /**
     * Get the generator for the signer
     *
     * @return GeneratorPoint
     */
    public function getGenerator()
    {
        return $this->generator;
    }

    /**
     * Get the hashing algorithm for the signer
     *
     * @return string
     */
    public function getHashingAlgorithm()
    {
        return $this->hashingAlgorithm;
    }

    /**
     * Get the signature length for the signer
     *
     * @return int
     */
    public function getSignatureLength()
    {
        return $this->signatureLength;
    }
}
