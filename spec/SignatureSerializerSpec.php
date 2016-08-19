<?php

namespace spec\JDR\JWS\ECDSA;

use JDR\JWS\ECDSA\SignatureSerializer;
use Mdanter\Ecc\Crypto\Signature\Signature;
use Mdanter\Ecc\Crypto\Signature\SignatureInterface;
use Mdanter\Ecc\EccFactory;
use PhpSpec\ObjectBehavior;

class SignatureSerializerSpec extends ObjectBehavior
{
    function let()
    {
        $adapter = EccFactory::getAdapter();
        $this->beConstructedWith($adapter);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(SignatureSerializer::class);
    }

    function it_should_serialize_an_EC256_signature_to_a_binary_string()
    {
        $r = 1;
        $s = 2;
        $this->serialize($this->getSignature($r, $s), 'ES256')->shouldReturn($this->getBinaryString($r, $s, 64));
    }

    function it_should_unserialize_a_binary_string_to_a_signature_interface()
    {
        $r = 1;
        $s = 2;
        $this->unserialize($this->getBinaryString($r, $s, 64), 'ES256')->shouldReturnAnInstanceOf(SignatureInterface::class);
    }

    function it_should_unserialize_a_binary_string_to_an_EC256_signature()
    {
        $r = 1;
        $s = 2;
        $this->unserialize($this->getBinaryString($r, $s, 64), 'ES256')->shouldBeLike($this->getSignature($r, $s));
    }

    private function getSignature($r, $s)
    {
        return new Signature(gmp_init($r, 10), gmp_init($s, 10));
    }

    private function getBinaryString($r, $s, $length = 64)
    {
        return pack('H*', str_repeat('0', $length-1).$r.str_repeat('0', $length-1).$s);
    }
}
