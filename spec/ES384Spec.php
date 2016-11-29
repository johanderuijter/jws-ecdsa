<?php

namespace spec\JDR\JWS\ECDSA;

use JDR\JWS\ECDSA\ES384;
use Lcobucci\JWT\Parsing\Decoder;
use Lcobucci\JWT\Signature;
use Lcobucci\JWT\Signer as LcobucciJWTSigner;
use Lcobucci\JWT\Signer\Key;
use PhpSpec\ObjectBehavior;

class ES384Spec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(ES384::class);
    }

    function it_should_implement_lcobucci_jwt_signer_interface()
    {
        $this->shouldImplement(LcobucciJWTSigner::class);
    }

    function it_should_implement_the_es384_algorithm()
    {
        $this->getAlgorithmId()->shouldReturn('ES384');
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
        return <<<ES384
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCN2T6NC1zKnSKcrD48vwFgbHoTDo0Ju5JGad17aZqpa7n3efaU8bsY
zUoIa1u+ZVSgBwYFK4EEACKhZANiAARXTzKP3stkpZvD6UdV87aWgN3zEhE3SgPR
NfK/5/8QyJbJPd8xOlaqscFYsBaTz8bmrUqtYKWU3usG96dAOs6dytjepu1mmGTu
UteJpanutAKhH1ZWOhYPc6tviuMwp68=
-----END EC PRIVATE KEY-----
ES384;
    }

    private function getPublicKey()
    {
        return <<<ES384
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEV08yj97LZKWbw+lHVfO2loDd8xIRN0oD
0TXyv+f/EMiWyT3fMTpWqrHBWLAWk8/G5q1KrWCllN7rBvenQDrOncrY3qbtZphk
7lLXiaWp7rQCoR9WVjoWD3Orb4rjMKev
-----END PUBLIC KEY-----
ES384;
    }

    private function getPayload()
    {
        $base64 = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJodHRwOlwvXC9leGFtcGxlLmNvbSIsImF1ZCI6Imh0dHA6XC9cL2V4YW1wbGUub3JnIiwiaWF0IjoxNDcxMjkwNjIwLCJleHAiOjE0NzEyOTQyMjB9';

        return $base64;
    }

    private function getModifiedPayload()
    {
        $base64 = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJodHRwOlwvXC9leGFtcGxlLmNvbSIsImF1ZCI6Imh0dHA6XC9cL2V4YW1wbGUub3JnIiwiaWF0IjoxNDcxNDYyOTE4LCJleHAiOjE0NzE0NjY1MTh9';

        return $base64;
    }

    private function getSignature()
    {
        $base64 = 'huSojKPuPVGdbqDfDy4Nl5_I4tOcZDiUuEM98eTdxGZp3mGqG-56O3_Mo4LciWzNRu7dD4S9H4BMbVpZ9iuP0DDBuGqcHRUlaOBQ0lHjXk7L1XUOPrurpN30vzmBTCGo';

        return $this->decode($base64);
    }

    private function getSignatureFromOtherLibrary()
    {
        $base64 = 'FK0DywKK4-8Xydvs2k4ZOlCmt5g9V7DsFfLlmjqLjOT0tGPlZvo88LchZoa1q4QYKafODs8LI66GUUNDpkwY-rZewlDVBWMDWLMYR_RWQ1hYVa7TigN1SgSk8njq0SPt';

        return $this->decode($base64);
    }

    private function decode($base64)
    {
        return (new Decoder())->base64UrlDecode($base64);
    }
}
