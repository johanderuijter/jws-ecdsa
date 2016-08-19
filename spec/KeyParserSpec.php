<?php

namespace spec\JDR\JWS\ECDSA;

use JDR\JWS\ECDSA\KeyParser;
use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use Mdanter\Ecc\EccFactory;
use PhpSpec\ObjectBehavior;

class KeyParserSpec extends ObjectBehavior
{
    function let()
    {
        $adapter = EccFactory::getAdapter();
        $this->beConstructedWith($adapter);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(KeyParser::class);
    }

    function it_should_parse_a_private_key()
    {
        $this->parsePrivateKey($this->getPrivateKey())->shouldReturnAnInstanceOf(PrivateKeyInterface::class);
    }

    function it_should_parse_a_public_key()
    {
        $this->parsePublicKey($this->getPublicKey())->shouldReturnAnInstanceOf(PublicKeyInterface::class);
    }

    private function getPrivateKey()
    {
        return <<<ES256
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEsP542fnbo3TNRiUqECa9x1M6UfdOyr2Fyb4qZoW6iUoAoGCCqGSM49
AwEHoUQDQgAEUcDxhEw3zo0RIrn1BqEg9p9qrn917bLjFEOuIGQlKXrOCLIO7QLQ
B7tWdxyLgAIq/yEYUoU4Lbp3rCxOWAYdIg==
-----END EC PRIVATE KEY-----
ES256;
    }

    private function getPublicKey()
    {
        return <<<ES256
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUcDxhEw3zo0RIrn1BqEg9p9qrn91
7bLjFEOuIGQlKXrOCLIO7QLQB7tWdxyLgAIq/yEYUoU4Lbp3rCxOWAYdIg==
-----END PUBLIC KEY-----
ES256;
    }
}
