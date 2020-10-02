# WavesKit

[![packagist](https://img.shields.io/packagist/v/deemru/waveskit.svg)](https://packagist.org/packages/deemru/waveskit) [![php-v](https://img.shields.io/packagist/php-v/deemru/waveskit.svg)](https://packagist.org/packages/deemru/waveskit)  [![travis](https://img.shields.io/travis/deemru/WavesKit.svg?label=travis)](https://travis-ci.org/deemru/WavesKit) [![codacy](https://img.shields.io/codacy/grade/439e2cedcdaf4091be29b7b1755e7c16.svg?label=codacy)](https://app.codacy.com/project/deemru/WavesKit/dashboard) [![license](https://img.shields.io/packagist/l/deemru/waveskit.svg)](https://packagist.org/packages/deemru/waveskit)

[WavesKit](https://github.com/deemru/WavesKit) is an all-in-one Waves Platform development kit for the PHP language.

- All you need to work with Waves in a single class
- Really easy to use
- Best practices for all
- Advanced features for pros

## Basic usage

```php
$wk = new WavesKit( 'T' );
$wk->setSeed( 'manage manual recall harvest series desert melt police rose hollow moral pledge kitten position add' );
$tx = $wk->txBroadcast( $wk->txSign( $wk->txTransfer( 'test', 1 ) ) );
$tx = $wk->ensure( $tx );
```

## Documentaion

- WavesKit documention: [WavesKit.md](https://github.com/deemru/WavesKit/blob/master/docs/WavesKit.md)
- Consider to learn self tests: [selftest.php](https://github.com/deemru/WavesKit/blob/master/test/selftest.php)
- Self tests contain tests of all transactions which can easily be used as examples

## Requirements

Will be installed automatically through `composer install`:

- [PHP](http://php.net) >= 5.6
- [deemru/abcode](https://packagist.org/packages/deemru/abcode)
- [deemru/blake2b](https://packagist.org/packages/deemru/blake2b)
- [deemru/curve25519](https://packagist.org/packages/deemru/curve25519)
- [deemru/cryptash](https://packagist.org/packages/deemru/cryptash)
- [deemru/pairs](https://packagist.org/packages/deemru/pairs)
- [composer/ca-bundle](https://packagist.org/packages/composer/ca-bundle)
- [cURL](http://php.net/manual/en/book.curl.php)
- [GMP](http://php.net/manual/en/book.gmp.php)
- [Multibyte String](http://php.net/manual/en/book.mbstring.php)
- [SQLite (PDO)](http://php.net/manual/en/ref.pdo-sqlite.php)

## Recommended

- [PHP](http://php.net) >= 7.2
- [Sodium](http://php.net/manual/en/book.sodium.php)

## Installation

Require through Composer: `composer require deemru/waveskit`

```json
{
    "require": {
        "deemru/waveskit": "*"
    }
}
```
