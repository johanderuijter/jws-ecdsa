<?php

namespace spec\JDR\JWS\ECDSA;

use JDR\JWS\ECDSA\ES512;
use Lcobucci\JWT\Parsing\Decoder;
use Lcobucci\JWT\Signature;
use Lcobucci\JWT\Signer as LcobucciJWTSigner;
use Lcobucci\JWT\Signer\Key;
use PhpSpec\ObjectBehavior;

class ES512Spec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(ES512::class);
    }

    function it_should_implement_lcobucci_jwt_signer_interface()
    {
        $this->shouldImplement(LcobucciJWTSigner::class);
    }

    function it_should_implement_the_es512_algorithm()
    {
        $this->getAlgorithmId()->shouldReturn('ES512');
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
        return <<<ES512
-----BEGIN EC PRIVATE KEY-----
MIHbAgEBBEFlHlQg97FJ3W9AP4KiVb+6S7sg+nybGaAKc1SpDcjp7wnoKoZWK38+
5KXxz/3DIyBTS+/sqcw49MLVCdexIHGCmqAHBgUrgQQAI6GBiQOBhgAEAehBPfAk
UDehMUbCkfzQWFDyvtGKs9jMhBWtEfozHGYOS/WPWeilD2v7uGdrcQoNSpczKhpQ
Rev9alCqMUaDGB+iATCmhDq5Qa+w5PuUDXYC0scRa7WFuHHa3DfmNvpuOACpxzeG
W5U7FES56WAs92hUJJpqymzgBfuNnlEDeFe4PCsU
-----END EC PRIVATE KEY-----
ES512;
    }

    private function getPublicKey()
    {
        return <<<ES512
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB6EE98CRQN6ExRsKR/NBYUPK+0Yqz
2MyEFa0R+jMcZg5L9Y9Z6KUPa/u4Z2txCg1KlzMqGlBF6/1qUKoxRoMYH6IBMKaE
OrlBr7Dk+5QNdgLSxxFrtYW4cdrcN+Y2+m44AKnHN4ZblTsURLnpYCz3aFQkmmrK
bOAF+42eUQN4V7g8KxQ=
-----END PUBLIC KEY-----
ES512;
    }

    private function getPayload()
    {
        $base64 = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJodHRwOlwvXC9leGFtcGxlLmNvbSIsImF1ZCI6Imh0dHA6XC9cL2V4YW1wbGUub3JnIiwiaWF0IjoxNDcxMjkwNjIwLCJleHAiOjE0NzEyOTQyMjB9';

        return $base64;
    }

    private function getModifiedPayload()
    {
        $base64 = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJodHRwOlwvXC9leGFtcGxlLmNvbSIsImF1ZCI6Imh0dHA6XC9cL2V4YW1wbGUub3JnIiwiaWF0IjoxNDcxNDYyOTE4LCJleHAiOjE0NzE0NjY1MTh9';

        return $base64;
    }

    private function getSignature()
    {
        $base64 = 'APYFHxBJ1ovuSxGcH7_9bypTD233YowvY9lht5hvQFXRjmxxkA94WK0sjfaoBCwtOhWrZ1gnV24BIQdIZaHq8xKxARV-I2bOjJ4r7yielm5UNtIqiGId2NdvZAMFXHstG1M5yZNfnm3CK48BHjjQqKkBAzzdshDBGW5x6fBRYyAcgZOL';

        return $this->decode($base64);
    }

    private function getSignatureFromOtherLibrary()
    {
        $base64 = 'AA0X6g9Mza34JyLQzqzJLVBfKa3iifgIfFTNvM6hnlGih5DTC-ua_L0P69Ol2nA_0Ow0aqjxMU1E4iTu_Tj4IR4HAAnx5wpg0Xy4mQkLPrt8hCboFwC-iU4tIqVvjabrur6dCO5ykAwVZzBwdjtt6aS4fSXkcV8eYGTbYby3M8yV1qNk';

        return $this->decode($base64);
    }

    private function decode($base64)
    {
        return (new Decoder())->base64UrlDecode($base64);
    }
}
