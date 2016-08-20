<?php

namespace JDR\JWS\ECDSA;

use Mdanter\Ecc\EccFactory;

class ES512 extends AbstractSigner
{
    /**
     * Constructor
     */
    public function __construct()
    {
        $generator = EccFactory::getNistCurves()->generator521();
        parent::__construct($generator);
    }

    /**
     * Returns the algorithm id
     *
     * @return string
     */
    public function getAlgorithmId()
    {
        return 'ES512';
    }
}
