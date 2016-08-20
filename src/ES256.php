<?php

namespace JDR\JWS\ECDSA;

use Mdanter\Ecc\EccFactory;

final class ES256 extends AbstractSigner
{
    /**
     * Constructor
     */
    public function __construct()
    {
        $generator = EccFactory::getNistCurves()->generator256();
        parent::__construct($generator);
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
}
