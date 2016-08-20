<?php

namespace JDR\JWS\ECDSA;

use Mdanter\Ecc\EccFactory;

class ES384 extends AbstractSigner
{
    /**
     * Constructor
     */
    public function __construct()
    {
        $generator = EccFactory::getNistCurves()->generator384();
        parent::__construct($generator);
    }

    /**
     * Returns the algorithm id
     *
     * @return string
     */
    public function getAlgorithmId()
    {
        return 'ES384';
    }
}
