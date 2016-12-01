<?php

namespace JDR\JWS\ECDSA;

use Mdanter\Ecc\EccFactory;
use Lcobucci\JWT\Signer as LcobucciJWTSigner;

final class ES256 implements LcobucciJWTSigner
{
    /**
     * @var Signer
     */
    private $signer;

    /**
     * Constructor
     */
    public function __construct()
    {
        $config = new SignerConfig(
            EccFactory::getNistCurves()->generator256(),
            'sha256',
            64
        );
        $this->signer = new Signer($config);
    }

    /**
     * Returns the algorithm id
     *
     * @return string
     */
    public function getAlgorithmId()
    {
        return 'ES256';
    }

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
        return $this->signer->sign($payload, $key);
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
        return $this->signer->verify($expected, $payload, $key);
    }
}
