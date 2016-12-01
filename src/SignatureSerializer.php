<?php

namespace JDR\JWS\ECDSA;

use Mdanter\Ecc\Crypto\Signature\Signature;
use Mdanter\Ecc\Math\GmpMathInterface;

class SignatureSerializer
{
    /**
     * @var GmpMathInterface
     */
    private $adapter;

    /**
     * Constructor.
     *
     * @param GmpMathInterface $adapter
     */
    public function __construct(GmpMathInterface $adapter)
    {
        $this->adapter = $adapter;
    }

    /**
     * Serialize a Signature to a binary string
     *
     * @param Signature $signature
     *
     * @return string
     */
    public function serialize(Signature $signature, $length)
    {
        $r = str_pad($this->adapter->decHex((string) $signature->getR()), $length, '0', STR_PAD_LEFT);
        $s = str_pad($this->adapter->decHex((string) $signature->getS()), $length, '0', STR_PAD_LEFT);

        return pack('H*', $r.$s);
    }

    /**
     * Serialize a binary string to a Signature
     *
     * @param string $binary
     *
     * @return Signature
     */
    public function unserialize($binary, $length)
    {
        list($r, $s) = str_split(unpack('H*', $binary)[1], $length);

        return new Signature(gmp_init($this->adapter->hexDec($r), 10), gmp_init($this->adapter->hexDec($s), 10));
    }
}
