<?php

namespace JDR\JWS\ECDSA;

use Lcobucci\JWT\Signature as LcobucciJWTSignature;
use Lcobucci\JWT\Signer as LcobucciJWTSigner;
use Lcobucci\JWT\Signer\Key;
use Mdanter\Ecc\Crypto\Signature\Signature as EccSignature;
use Mdanter\Ecc\Crypto\Signature\Signer as EccSigner;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Random\RandomGeneratorFactory;
use Mdanter\Ecc\Serializer\PrivateKey\DerPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PrivateKey\PemPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\PemPublicKeySerializer;
use Mdanter\Ecc\Serializer\Signature\DerSignatureSerializer;

final class ES256 implements LcobucciJWTSigner
{
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
        if (!$key instanceof Key) {
            $key = new Key($key);
        }

        $adapter = EccFactory::getAdapter();
        $generator = EccFactory::getNistCurves()->generator256();

        $pemSerializer = new PemPrivateKeySerializer(new DerPrivateKeySerializer($adapter));
        $privateKey = $pemSerializer->parse($key->getContent());

        $signer = new EccSigner($adapter);
        $hash = $signer->hashData($generator, 'sha256', $payload);

        $random = RandomGeneratorFactory::getRandomGenerator();

        $randomK = $random->generate($generator->getOrder());
        $signature = $signer->sign($privateKey, $hash, $randomK);

        $r = str_pad($adapter->decHex((string) $signature->getR()), 64, '0', STR_PAD_LEFT);
        $s = str_pad($adapter->decHex((string) $signature->getS()), 64, '0', STR_PAD_LEFT);

        return new LcobucciJWTSignature(pack('H*', $r.$s));
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

        $adapter = EccFactory::getAdapter();
        $generator = EccFactory::getNistCurves()->generator256();

        $pemSerializer = new PemPublicKeySerializer(new DerPublicKeySerializer($adapter));
        $publicKey = $pemSerializer->parse($key->getContent());

        list($r, $s) = str_split(unpack('H*', $expected)[1], 64);
        $signature = new EccSignature(gmp_init($adapter->hexDec($r), 10), gmp_init($adapter->hexDec($s), 10));

        $signer = new EccSigner($adapter);
        $hash = $signer->hashData($generator, 'sha256', $payload);

        return $signer->verify($publicKey, $signature, $hash);
    }
}
