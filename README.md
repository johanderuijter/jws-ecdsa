# jws-ecdsa

[![Latest Version on Packagist][ico-version]][link-packagist]
[![Software License][ico-license]](LICENSE.md)
[![Build Status][ico-travis-ci-build-status]][link-travis-ci]
[![Total Downloads][ico-downloads]][link-downloads]

ECDSA signers for [`lcobucci/jwt`][link-lcobucci-jwt].

This library was created in order to support [`mdanter/ecc`][link-mdanter-ecc] 0.4.x in combination with lcobucci/jwt 3.x and will be deprecated once `lcobucci/jwt` itself offers support for this version of the `mdanter/ecc` library.



## Instalation

Require the library with composer:
```bash
composer require jdr/jws-ecdsa
```

## Usage

The signers supplied by this library are drop in replacements for the ones supplied by `lcobucci/jwt`.
```php
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use JDR\JWS\ECDSA\ES256;

$signer = new ES256();

$privateKey = new Key('file://...');

$token = (new Builder())
    ->setIssuedAt(time())
    ->setExpiration(time() + 3600)
    // ... Set additional claims
    ->sign($signer, $privateKey)
    ->getToken();

$publicKey = new Key('file://...');

$token->verify($signer, $publicKey);
```

## Credits

- [Johan de Ruijter][link-jdr]
- [All Contributors][link-contributors]

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.


[ico-version]: https://img.shields.io/packagist/v/jdr/jws-ecdsa.svg?style=flat-square
[ico-license]: https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square
[ico-travis-ci-build-status]: https://img.shields.io/travis/johanderuijter/jws-ecdsa/master.svg?style=flat-square
[ico-downloads]: https://img.shields.io/packagist/dt/jdr/jws-ecdsa.svg?style=flat-square

[link-packagist]: https://packagist.org/packages/jdr/jws-ecdsa
[link-travis-ci]: https://travis-ci.org/johanderuijter/jws-ecdsa
[link-downloads]: https://packagist.org/packages/jdr/jws-ecdsa
[link-jdr]: https://github.com/johanderuijter
[link-lcobucci-jwt]: https://github.com/lcobucci/jwt
[link-mdanter-ecc]:  https://github.com/phpecc/phpecc
[link-contributors]: ../../contributors
