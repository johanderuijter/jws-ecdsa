<?php

namespace JDR\JWS\ECDSA;

use Mdanter\Ecc\Crypto\Signature\Signature;
use Mdanter\Ecc\Math\GmpMathInterface;

class SignatureSerializer
{
    const LENGTH = [
        'ES256' => 64,
        'ES384' => 96,
        'ES512' => 132,
    ];

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
    public function serialize(Signature $signature, $algorithm)
    {
        $r = str_pad($this->adapter->decHex((string) $signature->getR()), $this->getLength($algorithm), '0', STR_PAD_LEFT);
        $s = str_pad($this->adapter->decHex((string) $signature->getS()), $this->getLength($algorithm), '0', STR_PAD_LEFT);

        return pack('H*', $r.$s);
    }

    /**
     * Serialize a binary string to a Signature
     *
     * @param string $binary
     *
     * @return Signature
     */
    public function unserialize($binary, $algorithm)
    {
        list($r, $s) = str_split(unpack('H*', $binary)[1], $this->getLength($algorithm));

        return new Signature(gmp_init($this->adapter->hexDec($r), 10), gmp_init($this->adapter->hexDec($s), 10));
    }

    /**
     * Get the length of the binary string
     *
     * @param string $algorithm
     *
     * @return int
     */
    private function getLength($algorithm)
    {
        return self::LENGTH[$algorithm];
    }
}
