<?php

namespace spec\JDR\JWS\ECDSA;

use JDR\JWS\ECDSA\ES256;
use Lcobucci\JWT\Parsing\Decoder;
use Lcobucci\JWT\Signature;
use Lcobucci\JWT\Signer as LcobucciJWTSigner;
use Lcobucci\JWT\Signer\Key;
use PhpSpec\Exception\Example\FailureException;
use PhpSpec\ObjectBehavior;

class ES256Spec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(ES256::class);
    }

    function it_should_implement_lcobucci_jwt_signer_interface()
    {
        $this->shouldImplement(LcobucciJWTSigner::class);
    }

    function it_should_implement_the_es256_algorithm()
    {
        $this->getAlgorithmId()->shouldReturn('ES256');
    }

    function it_should_modify_the_header_to_include_the_algorithm()
    {
        // warning: Parameter 1 to JDR\JWS\ECDSA\Signer::modifyHeader() expected to be a reference, value given
        // $headers = [];
        // $this->modifyHeader($headers)->shouldHaveKeyWithValue('alg', 'ES256');
    }

    function it_should_sign_the_payload()
    {
        $payload = $this->getPayload();

        $privateKey = new Key($this->getPrivateKey());
        $signature = $this->sign($payload, $privateKey)->shouldImplement(Signature::class);

        $publicKey = new Key($this->getPublicKey());
        $this->verify((string) $signature, $payload, $publicKey)->shouldReturn(true);
    }

    function it_should_verify_a_payload()
    {
        $publicKey = new Key($this->getPublicKey());
        $this->verify($this->getSignature(), $this->getPayload(), $publicKey)->shouldReturn(true);
    }

    function it_should_not_verify_a_modified_payload()
    {
        $publicKey = new Key($this->getPublicKey());
        $this->verify($this->getSignature(), $this->getModifiedPayload(), $publicKey)->shouldReturn(false);
    }

    function it_should_verify_a_payload_with_signature_created_by_another_library()
    {
        $publicKey = new Key($this->getPublicKey());
        $this->verify($this->getSignatureFromOtherLibrary(), $this->getPayload(), $publicKey)->shouldReturn(true);
    }

    function it_should_not_verify_a_modified_payload_with_signature_created_by_another_library()
    {
        $publicKey = new Key($this->getPublicKey());
        $this->verify($this->getSignatureFromOtherLibrary(), $this->getModifiedPayload(), $publicKey)->shouldReturn(false);
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

    private function getPayload()
    {
        $base64 = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9leGFtcGxlLmNvbSIsImF1ZCI6Imh0dHA6XC9cL2V4YW1wbGUub3JnIiwiaWF0IjoxNDcxMjkwNjIwLCJleHAiOjE0NzEyOTQyMjB9';

        return $base64;
    }

    private function getModifiedPayload()
    {
        $base64 = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9leGFtcGxlLmNvbSIsImF1ZCI6Imh0dHA6XC9cL2V4YW1wbGUub3JnIiwiaWF0IjoxNDcxNDYyOTE4LCJleHAiOjE0NzE0NjY1MTh9';

        return $base64;
    }

    private function getSignature()
    {
        $base64 = 'evMPL9EWTmCcntmsqJwbgHALSBmarEB_qS3tQqKlj11FrqvxzZAajpt7XbbcLRZBXffBSld7ED-dSwbKzkhv3g';

        return $this->decode($base64);
    }

    private function getSignatureFromOtherLibrary()
    {
        $base64 = 'KeVbJuBOLwx2kKQL1GIGY02hfSgIP8QC9AieJgZFrtIssRlG3DQuqMF5s8gaCW4tG5rDVV3ys-s0WpX1u9xP1g';

        return $this->decode($base64);
    }

    private function decode($base64)
    {
        return (new Decoder())->base64UrlDecode($base64);
    }
}
