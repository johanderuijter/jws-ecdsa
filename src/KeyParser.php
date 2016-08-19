<?php

namespace JDR\JWS\ECDSA;

use Mdanter\Ecc\Math\GmpMathInterface;
use Mdanter\Ecc\Serializer\PrivateKey\DerPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PrivateKey\PemPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\PemPublicKeySerializer;

class KeyParser
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

    public function parsePrivateKey($key)
    {
        $pemSerializer = new PemPrivateKeySerializer(new DerPrivateKeySerializer($this->adapter));

        return $pemSerializer->parse($key);
    }

    public function parsePublicKey($key)
    {
        $pemSerializer = new PemPublicKeySerializer(new DerPublicKeySerializer($this->adapter));

        return $pemSerializer->parse($key);
    }
}
