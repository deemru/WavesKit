# WavesKit

[![packagist](https://img.shields.io/packagist/v/deemru/waveskit.svg)](https://packagist.org/packages/deemru/waveskit) [![php-v](https://img.shields.io/packagist/php-v/deemru/waveskit.svg)](https://packagist.org/packages/deemru/waveskit)  [![travis](https://img.shields.io/travis/deemru/WavesKit.svg?label=travis)](https://travis-ci.org/deemru/WavesKit) [![codacy](https://img.shields.io/codacy/grade/5b22f904c9ba417cb278cb4efc58a7ce.svg?label=codacy)](https://app.codacy.com/project/deemru/WavesKit/dashboard) [![license](https://img.shields.io/packagist/l/deemru/WavesKit.svg)](https://packagist.org/packages/deemru/WavesKit)

[WavesKit](https://github.com/deemru/WavesKit) is an all-in-one Waves Platform development kit for the PHP language.

- Implements all the functions you need in the single class
- Easy to use
- Advanced features

## Usage

```php
$wk = new WavesKit( 'T' );
$wk->setSeed( 'manage manual recall harvest series desert melt police rose hollow moral pledge kitten position add' );
$tx = $wk->txBroadcast( $wk->txSign( $wk->txTransfer( 'test', 1 ) ) );
$tx = $wk->ensure( $tx );
```

## Requirements

Will be installed automatically through `composer install`:

- [PHP](http://php.net) >=7.2
- [deemru/abcode](https://packagist.org/packages/deemru/waveskit)
- [deemru/curve25519](https://packagist.org/packages/deemru/curve25519)
- [kornrunner/keccak](https://packagist.org/packages/kornrunner/keccak)
- [composer/ca-bundle](https://packagist.org/packages/composer/ca-bundle)
- [deemru/cryptash](https://packagist.org/packages/deemru/cryptash)
- [cURL](http://php.net/manual/en/book.curl.php)
- [GMP](http://php.net/manual/en/book.gmp.php)
- [Sodium](http://php.net/manual/en/book.sodium.php)

## Installation

Require through Composer:

```json
{
    "minimum-stability": "dev",
    "require": {
        "deemru/waveskit": "*"
    }
}
```

## Notice

- It is BETA
- Lack of documentation
