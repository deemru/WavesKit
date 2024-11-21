<?php

namespace deemru;

use deemru\ABCode;
use deemru\Blake2b;
use deemru\Curve25519;
use deemru\Cryptash;
use deemru\Pairs;
use Composer\CaBundle\CaBundle;

class WavesKit
{
    private $chainId;
    public $logFunction;
    public $logFilter;
    public $lastLog;

    private $c25519;

    /**
     * Creates WavesKit instance
     *
     * @param  string       $chainId        Blockchain identifier (default: 'W')
     * @param  mixed|null   $logFunction    Log functionality (default: null)
     * @param  bool         $keyCaching     Cache key flag (default: false)
     *
     * @return void
     */
    public function __construct( $chainId = 'W', $logFunction = null, $keyCaching = false )
    {
        $this->chainId = $chainId;
        if( isset( $logFunction ) )
            $this->logFunction = $logFunction;

        static $tz;
        if( !isset( $tz ) )
        {
            date_default_timezone_set( date_default_timezone_get() );
            $tz = true;
        }

        $this->c25519 = new Curve25519( $keyCaching );

        if( !isset( $this->curlTimeout ) )
        {
            if( !defined( 'WK_CURL_TIMEOUT' ) )
                define( 'WK_CURL_TIMEOUT', 15 );

            $this->curlTimeout = WK_CURL_TIMEOUT;
        }

        if( PHP_MAJOR_VERSION > 5 )
        {
            if( !defined( 'WK_CURL_OPTIONS' ) )
                define( 'WK_CURL_OPTIONS', [] );
            foreach( WK_CURL_OPTIONS as $k => $v )
                $this->curlOptions[$k] = $v;
        }
    }

    /**
     * Gets blockchain identifier value
     *
     * @return string Blockchain identifier value
     */
    public function getChainId()
    {
        return $this->chainId;
    }

    /**
     * Logs a message with a level
     *
     * @param  string $level    Message level
     * @param  string $message  Message
     *
     * @return void
     */
    public function log( $level, $message = null )
    {
        if( !isset( $message ) )
        {
            $message = $level;
            $level = 'i';
        }

        if( isset( $this->logFunction ) )
        {
            if( is_callable( $this->logFunction ) )
            {
                $logFunction = $this->logFunction;
                return $logFunction( $level, $message );
            }
            elseif( $this->logFunction === false )
                return;
            elseif( is_array( $this->logFunction ) && !in_array( $level, $this->logFunction, true ) )
                return;
        }

        if( isset( $this->logFilter ) )
            foreach( $this->logFilter as $filter )
                if( false !== strpos( $message, $filter ) )
                    return;

        $log = date( 'Y.m.d H:i:s ' );
        switch( $level )
        {
            case 'd': $log .= '  DEBUG: '; break;
            case 'w': $log .= 'WARNING: '; break;
            case 'e': $log .= '  ERROR: '; break;
            case 'i': $log .= '   INFO: '; break;
            case 's': $log .= 'SUCCESS: '; break;
            default:  $log .= 'UNKNOWN: '; break;
        }

        $log .= $message;
        if( $level === 'e' )
            error_log( $log );
        else
            echo $log . PHP_EOL;
        $this->lastLog = $log;
    }

    /**
     * Set filter specific messages
     *
     * @param  array $filter Array of sub-strings to filter
     *
     * @return void
     */
    public function setLogFilter( $filter )
    {
        $this->logFilter = $filter;
    }

    /**
     * Encodes data to base58 string
     *
     * @param  string $data Data to encode
     *
     * @return string Encoded data
     */
    public function base58Encode( $data ){ return ABCode::base58()->encode( $data ); }

    /**
     * Decodes data from base58 string
     *
     * @param  string $data     Base58 string
     * @param  bool   $useCache Use cache or not (default: true)
     *
     * @return string|false Decoded data or FALSE on failure
     */
    public function base58Decode( $data, $useCache = true )
    {
        static $cache = [];

        if( isset( $cache[$data] ) )
            return $cache[$data];

        if( count( $cache ) >= 256 )
            $cache = [];

        $result = ABCode::base58()->decode( $data );
        if( $useCache === true )
            $cache[$data] = $result;
        return $result;
    }

    /**
     * Hashes data with sha256
     *
     * @param  string $data Data to hash
     *
     * @return string Hash result
     */
    public function sha256( $data ){ return hash( 'sha256', $data, true ); }

    /**
     * Hashes data with sha512
     *
     * @param  string $data Data to hash
     *
     * @return string Hash result
     */
    public function sha512( $data ){ return hash( 'sha512', $data, true ); }

    /**
     * Hashes data with blake2b256 and keccak256
     *
     * @param  string $data Data to hash
     *
     * @return string Hash result
     */
    public function secureHash( $data ){ return $this->keccak256( $this->blake2b256( $data ) ); }

    /**
     * Hashes data with keccak256
     *
     * @param  string $data Data to hash
     *
     * @return string Hash result
     */
    public function keccak256( $data )
    {
        static $keccak;

        if( !isset( $keccak ) )
        {
            require_once __DIR__ . '/../support/Keccak.php';
            $keccak = new \deemru\Keccak();
        }

        return $keccak->hash( $data, 256, true );
    }

    /**
     * Hashes data with blake2b256
     *
     * @param  string $data Data to hash
     *
     * @return string Hash result
     */
    public function blake2b256( $data )
    {
        static $sodiumBlake;
        static $blake2b;

        if( !isset( $sodiumBlake ) )
        {
            if( function_exists( 'sodium_crypto_generichash' ) )
                $sodiumBlake = true;
            else
                $blake2b = new Blake2b();
        }

        if( $sodiumBlake )
            return sodium_crypto_generichash( $data );
        else
            return $blake2b->hash( $data );
    }

    private $rseed;

    /**
     * Signs a message with a private key
     *
     * @param  string       $data Data to sign
     * @param  string|null  $key  Private key (default: null)
     *
     * @return string|false Signature of data or FALSE on failure
     */
    public function sign( $data, $key = null )
    {
        if( $key === null )
        {
            if( !isset( $this->rseed ) )
            {
                static $sodiumSign;
                if( !isset( $sodiumSign ) )
                {
                    $sodiumSign = false;
                    if( function_exists( 'sodium_crypto_sign_seed_keypair' ) )
                    {
                        $seed = hex2bin( '3030303030303030303030303030303030303030303030303030303030303030' );
                        $pubkey = hex2bin( '0a8907a1ec72d1b80373cd41e8e4eb5a6a25fdda4ef82be7b635a54700b42289' );
                        $pubkey_sodium = substr( sodium_crypto_sign_seed_keypair( $seed ), 32, 32 );
                        if( $pubkey === $pubkey_sodium )
                            $sodiumSign = true;
                    }
                }

                if( $sodiumSign )
                {
                    if( !isset( $this->privateKeyPairCloaked ) )
                    {
                        $this->privateKeyCloaked->uncloak( function( $key )
                        {
                            $keypair = substr( sodium_crypto_sign_seed_keypair( $this->getSodium() ? substr( $this->sha512( $key ), 0, 32 ) : $key ), 0, 64 );
                            $this->privateKeyPairBit = ord( $keypair[63] ) & 128;
                            $this->privateKeyPairCloaked = new Cloaked;
                            $this->privateKeyPairCloaked->cloak( $keypair );
                        } );
                    }

                    return $this->privateKeyPairCloaked->uncloak( function( $keypair ) use ( $data )
                    {
                        $sig = sodium_crypto_sign_detached( $data, $keypair );
                        if( $this->privateKeyPairBit !== 0 )
                            $sig[63] = chr( ord( $sig[63] ) | $this->privateKeyPairBit );
                        return $sig;
                    } );
                }

                return $this->privateKeyCloaked->uncloak( function( $key ) use ( $data )
                {
                    if( $this->getSodium() )
                        return $this->c25519->sign_sodium( $data, $key );
                    return $this->c25519->sign( $data, $key );
                } );
            }
            else // rseed
            {
                return $this->privateKeyCloaked->uncloak( function( $key ) use ( $data )
                {
                    $rseed = $this->rseed;
                    unset( $this->rseed );
                    return $this->c25519->sign( $data, $key, $rseed );
                } );
            }
        }

        return $this->c25519->sign( $data, $key );
    }

    /**
     * Verifies a signature of a message by a public key
     *
     * @param  string       $sig  Signature to verify
     * @param  string       $data Signed data
     * @param  string|null  $key  Public key (default: null)
     *
     * @return bool Returns TRUE if the signature is valid or FALSE on failure
     */
    public function verify( $sig, $data, $key = null ){ return $this->c25519->verify( $sig, $data, isset( $key ) ? $key : $this->getPublicKey( true ) ); }

    /**
     * Generates random seed string
     *
     * @param  int $words Words in seed string (default: 15)
     *
     * @return string|false Returns random seed or FALSE on failure
     */
    public function randomSeed( $words = 15 )
    {
        static $english;

        if( !isset( $english ) )
        {
            $temp = file_get_contents( __DIR__ . '/../support/english.txt' );
            if( $temp === false )
                return false;

            $temp = explode( "\n", $temp );
            $n = count( $temp );
            if( $temp === false || $n < 2048 )
                return false;

            for( $i = 0; $i < $n; $i++ )
                $temp[$i] = trim( $temp[$i] );

            $english = $temp;
        }

        $seed = '';
        $mod = count( $english );
        for( $i = 0; $i < $words; $i++ )
        {
            $ri = ( ( ord( Cryptash::rnd( 1 ) ) << 8 ) | ord( Cryptash::rnd( 1 ) ) ) % $mod;
            $seed .= ( $i ? ' ' : '' ) . $english[$ri];
        }

        return $seed;
    }

    /**
     * Validates an address by a current blockchain identifier
     *
     * @param  mixed $address
     * @param  mixed $raw
     *
     * @return bool Returns TRUE if the address is valid or FALSE on failure
     */
    public function isAddressValid( $address, $raw = false )
    {
        $data = $raw ? $address : $this->base58Decode( $address );
        if( $data === false || strlen( $data ) !== 26 )
            return false;

        if( $data[0] !== chr( 1 ) || $data[1] !== $this->chainId )
            return false;

        $xsum = $this->secureHash( substr( $data, 0, 22 ) );
        if( substr( $xsum, 0, 4 ) !== substr( $data, 22, 4 ) )
            return false;

        return true;
    }

    private $privateKeyCloaked;
    private $privateKeyPairCloaked;
    private $privateKeyPairBit;
    private $publicKey;
    private $publicKey58;
    private $address;
    private $address58;

    private function cleanup( $full = true )
    {
        if( $full )
        {
            unset( $this->privateKeyCloaked );
            unset( $this->privateKeyPairCloaked );
            unset( $this->privateKeyPairBit );
        }

        unset( $this->publicKey );
        unset( $this->publicKey58 );
        unset( $this->address );
        unset( $this->address58 );
    }

    /**
     * Sets user seed string
     *
     * @param  string      $seed   Seed string
     * @param  bool        $raw    String format is binary or base58 (default: binary)
     * @param  string|null $prefix Prefix string in binary format (default: "\0\0\0\0")
     *
     * @return void
     */
    public function setSeed( $seed, $raw = true, $prefix = "\0\0\0\0" )
    {
        $this->cleanup();
        $this->getPrivateKey( true, $raw ? $seed : $this->base58Decode( $seed, false ), $prefix, true );
    }

    /**
     * Sets private key
     *
     * @param  string   $privateKey Private key
     * @param  bool     $raw        String format is binary or base58 (default: base58)
     *
     * @return void
     */
    public function setPrivateKey( $privateKey, $raw = false )
    {
        $this->cleanup();
        $key = $raw ? $privateKey : $this->base58Decode( $privateKey, false );
        $this->privateKeyCloaked = new Cloaked;
        $this->privateKeyCloaked->cloak( $key );
    }

    /**
     * Gets private key
     *
     * @param  bool         $raw    String format is binary or base58 (default: binary)
     * @param  string|null  $seed   Seed string in binary format (default: null)
     * @param  string|null  $prefix Prefix string in binary format (default: "\0\0\0\0")
     * @param  bool|false   $noret  Do not return the key (default: false)
     *
     * @return string|bool Private key or FALSE on failure or TRUE on noret
     */
    public function getPrivateKey( $raw = true, $seed = null, $prefix = "\0\0\0\0", $noret = false )
    {
        if( !isset( $this->privateKeyCloaked ) )
        {
            if( !isset( $seed ) )
                return false;
            $temp = $prefix . $seed;
            $temp = $this->secureHash( $temp );
            $temp = $this->sha256( $temp );
            $this->privateKeyCloaked = new Cloaked;
            $this->privateKeyCloaked->cloak( $temp );
        }

        if( $noret )
            return true;

        $key = $this->privateKeyCloaked->uncloak( function( $key ){ return $key; } );
        return $raw ? $key : $this->base58Encode( $key );
    }

    /**
     * Sets public key
     *
     * @param  string   $publicKey  Public key
     * @param  bool     $raw        String format is binary or base58 (default: base58)
     *
     * @return void
     */
    public function setPublicKey( $publicKey, $raw = false )
    {
        $this->cleanup();
        $this->publicKey = $raw ? $publicKey : $this->base58Decode( $publicKey );
    }

    /**
     * Gets public Key
     *
     * @param  bool $raw String format is binary or base58 (default: base58)
     *
     * @return string|false Public key or FALSE on failure
     */
    public function getPublicKey( $raw = false )
    {
        if( !isset( $this->publicKey ) )
        {
            if( !isset( $this->privateKeyCloaked ) )
                return false;

            $this->publicKey = $this->privateKeyCloaked->uncloak( function( $key )
            {
                $temp = $key;
                if( $temp === false || strlen( $temp ) !== 32 )
                    return false;
                if( $this->getSodium() )
                    $temp = $this->c25519->getSodiumPrivateKeyFromPrivateKey( $temp );
                $temp = $this->c25519->getPublicKeyFromPrivateKey( $temp, $this->getLastBitFlip() );
                return $temp;
            } );
        }

        if( $raw )
            return $this->publicKey;

        if( !isset( $this->publicKey58 ) )
            $this->publicKey58 = $this->base58Encode( $this->publicKey );

        return $this->publicKey58;
    }

    /**
     * Sets address
     *
     * @param  string   $address    Address
     * @param  bool     $raw        String format is binary or base58 (default: base58)
     *
     * @return void
     */
    public function setAddress( $address, $raw = false )
    {
        $this->cleanup();
        if( !$this->isAddressValid( $address, $raw ) )
            return;

        $this->address = $raw ? $address : $this->base58Decode( $address );
    }

    /**
     * Gets address
     *
     * @param  bool $raw String format is binary or base58 (default: base58)
     *
     * @return string|false Address or FALSE on failure
     */
    public function getAddress( $raw = false )
    {
        if( !isset( $this->address ) )
        {
            $temp = $this->getPublicKey( true );
            if( $temp === false || strlen( $temp ) !== 32 )
                return false;
            $temp = $this->secureHash( $temp );
            $temp = chr( 1 ) . $this->chainId . substr( $temp, 0, 20 );
            $temp .= substr( $this->secureHash( $temp ), 0, 4 );
            $this->address = $temp;
        }

        if( $raw )
            return $this->address;

        if( !isset( $this->address58 ) )
            $this->address58 = $this->base58Encode( $this->address );

        return $this->address58;
    }

    private $sodium;

    /**
     * Sets sodium option
     *
     * @param  bool $enabled Enable or disable (default: enable)
     *
     * @return void
     */
    public function setSodium( $enabled = true )
    {
        $this->cleanup();
        if( $enabled )
            $this->sodium = $enabled;
        else
            unset( $this->sodium );
    }

    /**
     * Gets sodium option status
     *
     * @return bool Enabled or disabled
     */
    public function getSodium()
    {
        return isset( $this->sodium );
    }

    private $lastbitflip;

    /**
     * Sets last bit flip option
     *
     * @param  bool $enabled Enable or disable (default: enable)
     *
     * @return void
     */
    public function setLastBitFlip( $enabled = true )
    {
        $this->cleanup( false );
        if( $enabled )
            $this->lastbitflip = $enabled;
        else
            unset( $this->lastbitflip );
    }

    /**
     * Get last bit flip option status
     *
     * @return bool Enabled or disabled
     */
    public function getLastBitFlip()
    {
        return isset( $this->lastbitflip );
    }

    /**
     * Sets RSEED value (DANGEROUS)
     *
     * @param  string $rseed RSEED value
     *
     * @return void
     */
    public function setRSEED( $rseed )
    {
        $this->rseed = $rseed;
    }

    /**
     * json_decode wrapper for WavesKit
     *
     * @param  string $json
     *
     * @return array|false
     */
    public function json_decode( $json )
    {
        $decoded = json_decode( $json, true, 512, JSON_BIGINT_AS_STRING );
        return $decoded === null ? false : $decoded;
    }

    public $curlTimeout;
    public $curlOptions;
    private $setBestOnError = false;
    private $fetcher;

    /**
     * Sets node address with cache lifetime and backup node addresses
     *
     * @param  string|array $nodeAddress    Main node address to work with
     * @param  int|float    $cacheLifetime  Cache lifetime in seconds (default: 0.5)
     * @param  array|null   $backupNodes    Backup node addresses to fallback
     *
     * @return void
     */
    public function setNodeAddress( $nodeAddress, $cacheLifetime = 0.5, $backupNodes = null )
    {
        $hosts = is_array( $nodeAddress ) ? $nodeAddress : [ $nodeAddress ];
        if( isset( $backupNodes ) )
            $hosts = array_merge( $hosts, $backupNodes );
        $this->fetcher = Fetcher::hosts( $hosts )->setTimeoutCache( $cacheLifetime );
        $this->fetcher->setTimeoutConnect( $this->curlTimeout )->setTimeoutExec( $this->curlTimeout )->setOptions( $this->curlOptions );
        if( count( $hosts ) > 1 && defined( 'WK_CURL_SETBESTONERROR' ) )
            $this->setBestOnError = true;
    }

    /**
     * Gets main node address
     *
     * @return string|false Main node address or FALSE on failure
     */
    public function getNodeAddress()
    {
        return isset( $this->fetcher ) ? $this->fetcher->getHost() : false;
    }

    private function setDefaultNode()
    {
        if( !isset( $this->fetcher ) )
        {
            switch( $this->chainId )
            {
                case 'W':
                    $this->setNodeAddress( [
                        'https://nodes.wavesplatform.com',
                        'https://nodes.wavesnodes.com',
                        'https://nodes.wx.network',
                        'https://nodes.wavesexplorer.com',
                    ] );
                    break;
                case 'T':
                    $this->setNodeAddress( [
                        'https://nodes-testnet.wavesnodes.com',
                        'https://testnode1.wavesnodes.com',
                        'https://testnode2.wavesnodes.com',
                        'https://testnode4.wavesnodes.com',
                    ] );
                    break;
                default:
                    break;
            }
        }
    }

    public $matcher;
    public $matcherPublicKey;

    private function setDefaultMatcher()
    {
        if( !isset( $this->matcher ) )
        {
            $this->matcher = new WavesKit( $this->getChainId(), isset( $this->logFunction ) ? $this->logFunction : null );
            switch( $this->chainId )
            {
                case 'W':
                    $this->matcher->setNodeAddress( 'https://matcher.waves.exchange' );
                    break;
                case 'T':
                    $this->matcher->setNodeAddress( 'https://matcher-testnet.waves.exchange' );
                    break;
                default:
                    break;
            }
        }

        if( !isset( $this->matcherPublicKey ) )
        {
            switch( $this->chainId )
            {
                case 'W':
                    $this->matcherPublicKey = '9cpfKN9suPNvfeUNphzxXMjcnn974eme8ZhWUjaktzU5';
                    break;
                case 'T':
                    $this->matcherPublicKey = '8QUAqtTckM5B8gvcuP7mMswat9SjKUuafJMusEoSn1Gy';
                    break;
                default:
                    break;
            }
        }
    }

    public $matcherBaseFee;
    public $matcherDiscountAsset;
    public $matcherRates;
    public $matcherDiscountRate;
    public $matcherPairMinFees;
    public $matcherPairMinFeesInWaves;
    public $matcherVerified;
    public $matcherVerifiedMinFee;
    public $matcherVerifiedMinFeeInWaves;

    /**
     * Sets matcher settings
     *
     * @param  array|null   $settings   Matcher settings or NULL to get them on-the-fly (default: null)
     *
     * @return bool TRUE on success or FALSE on failure
     */
    public function setMatcherSettings( $settings = null )
    {
        $this->setDefaultMatcher();

        if( !isset( $settings ) )
        {
            $settings = $this->matcher->fetch( '/matcher/settings' );
            if( $settings === false || false === ( $settings = $this->json_decode( $settings ) ) )
                return false;
        }

        if( !isset( $settings['rates'] ) ||
            !isset( $settings['orderFee']['composite']['default']['dynamic']['baseFee'] ) ||
            !isset( $settings['orderFee']['composite']['custom'] ) ||
            !isset( $settings['orderFee']['composite']['discount']['assetId'] ) ||
            !isset( $settings['orderFee']['composite']['discount']['value'] ) )
            return false;

        $this->matcherBaseFee = $settings['orderFee']['composite']['default']['dynamic']['baseFee'];
        $this->matcherDiscountAsset = $settings['orderFee']['composite']['discount']['assetId'];

        $this->matcherRates = [];
        foreach( $settings['rates'] as $asset => $rate )
        {
            $assetDecimals = $this->assetDecimals( $asset );
            if( $assetDecimals === false )
                return false;
            $this->matcherRates[$asset] = $rate / $this->decimalize( 8 - $assetDecimals );
        }

        $this->matcherDiscountRate = $this->matcherRates[$this->matcherDiscountAsset] * ( ( 100 - $settings['orderFee']['composite']['discount']['value'] ) / 100 );

        $this->matcherPairMinFees = [];
        $this->matcherPairMinFeesInWaves = [];
        foreach( $settings['orderFee']['composite']['custom'] as $pair => $config )
        {
            if( !isset( $config['percent']['type'] ) ||
                !isset( $config['percent']['minFee'] ) ||
                !isset( $config['percent']['minFeeInWaves'] ) )
                return false;

            if( $config['percent']['type'] !== 'spending' )
                return false;

            $minFeeAB = isset( $config['percent']['amount']['minFee'] ) ? $config['percent']['amount']['minFee'] : $config['percent']['minFee'];
            $minFeeBA = isset( $config['percent']['price']['minFee'] ) ? $config['percent']['price']['minFee'] : $config['percent']['minFee'];
            $minFeeInWavesAB = isset( $config['percent']['amount']['minFeeInWaves'] ) ? $config['percent']['amount']['minFeeInWaves'] : $config['percent']['minFeeInWaves'];
            $minFeeInWavesBA = isset( $config['percent']['price']['minFeeInWaves'] ) ? $config['percent']['price']['minFeeInWaves'] : $config['percent']['minFeeInWaves'];

            $this->matcherPairMinFees[$pair][1] = $minFeeAB / 100;
            $this->matcherPairMinFees[$pair][0] = $minFeeBA / 100;
            $this->matcherPairMinFeesInWaves[$pair][1] = $minFeeInWavesAB;
            $this->matcherPairMinFeesInWaves[$pair][0] = $minFeeInWavesBA;
        }

        $this->matcherVerified = [];
        if( isset( $settings['orderFee']['composite']['verified']['assets'] ) &&
            isset( $settings['orderFee']['composite']['verified']['settings']['percent']['minFee'] ) &&
            isset( $settings['orderFee']['composite']['verified']['settings']['percent']['minFeeInWaves'] ) )
        {
            foreach( $settings['orderFee']['composite']['verified']['assets'] as $asset )
                $this->matcherVerified[$asset] = true;
            $this->matcherVerifiedMinFee = $settings['orderFee']['composite']['verified']['settings']['percent']['minFee'] / 100;
            $this->matcherVerifiedMinFeeInWaves = $settings['orderFee']['composite']['verified']['settings']['percent']['minFeeInWaves'];
        }

        return true;
    }

    private function assetDecimals( $asset )
    {
        if( $asset === 'WAVES' || $asset === null )
            return 8;

        static $db;
        if( isset( $db[$asset] ) )
            return $db[$asset];

        $info = $this->fetch( '/assets/details/' . $asset );
        if( $info === false || false === ( $info = $this->json_decode( $info ) ) || !isset( $info['decimals'] ) )
            return false;

        $db[$asset] = $info['decimals'];
        return $info['decimals'];
    }

    private function assetId( $asset )
    {
        return isset( $asset ) ? $asset : 'WAVES';
    }

    private function decimalize( $n )
    {
        if( $n === 0 ) return 1;
        if( $n === 1 ) return 10;
        if( $n === 2 ) return 100;
        if( $n === 3 ) return 1000;
        if( $n === 4 ) return 10000;
        if( $n === 5 ) return 100000;
        if( $n === 6 ) return 1000000;
        if( $n === 7 ) return 10000000;
        return 100000000;
    }

    /**
     * Sets an order fee based on matcher settings
     *
     * @param  array    $order      Order as an array
     * @param  bool     $discount   Use dicount asset (default: true)
     *
     * @return array|false Order as an array or FALSE on failure
     */
    public function setMatcherFee( $order, $discount = true )
    {
        $isSell = $order['orderType'] === 'sell';
        $amountAsset = $this->assetId( $order['assetPair']['amountAsset'] );
        $priceAsset = $this->assetId( $order['assetPair']['priceAsset'] );
        $mainAsset = $isSell ? $amountAsset : $priceAsset;
        $pair = $amountAsset . '-' . $priceAsset;
        $direction = $isSell ? 1 : 0;

        if( !isset( $this->matcherBaseFee ) && !$this->setMatcherSettings() )
            return false;

        if( isset( $this->matcherPairMinFees[$pair][$direction] ) )
        {
            $rate = $this->matcherRates[$mainAsset];
            $amount = $isSell ? $order['amount'] : ( $order['amount'] * $order['price'] / 100000000 );

            $matcherBaseFee = $this->matcherPairMinFeesInWaves[$pair][$direction];
            $fee = $amount * $this->matcherPairMinFees[$pair][$direction];
            $fee /= $rate;
            if( $fee < $matcherBaseFee )
                $fee = $matcherBaseFee;

            if( $discount )
            {
                $asset = $this->matcherDiscountAsset;
                $rate = $this->matcherDiscountRate;
            }
            else
            {
                $asset = $mainAsset === 'WAVES' ? null : $mainAsset;
                //$rate = $rate;
            }
        }
        else
        if( isset( $this->matcherVerified[$priceAsset] ) || isset( $this->matcherVerified[$amountAsset] ) )
        {
            $isPrice = isset( $this->matcherVerified[$priceAsset] );
            $mainAsset = $isPrice ? $priceAsset : $amountAsset;

            $rate = $this->matcherRates[$mainAsset];
            $amount = $isPrice ? ( $order['amount'] * $order['price'] / 100000000 ) : $order['amount'];

            $matcherBaseFee = $this->matcherVerifiedMinFeeInWaves;
            $fee = $amount * $this->matcherVerifiedMinFee;
            $fee /= $rate;
            if( $fee < $matcherBaseFee )
                $fee = $matcherBaseFee;

            if( $discount )
            {
                $asset = $this->matcherDiscountAsset;
                $rate = $this->matcherDiscountRate;
            }
            else
            {
                $asset = null; // fixedAsset WAVES only
                $rate = 1;
            }
        }
        else
        {
            $fee = $this->matcherBaseFee;

            if( $discount )
            {
                $asset = $this->matcherDiscountAsset;
                $rate = $this->matcherDiscountRate;
            }
            else
            {
                $asset = null;
                $rate = 1;
            }
        }

        $fee *= $rate;
        $order['matcherFee'] = (int)ceil( $fee );
        $order['matcherFeeAssetId'] = $asset;

        return $order;
    }

    /**
     * Fetches GET or POST response
     *
     * @param  string       $url            URL of request
     * @param  bool         $post           POST or GET (default: GET)
     * @param  string|null  $data           Data for POST (default: null)
     * @param  array|null   $ignoreCodes    Array of ignored HTTP codes (default: null)
     * @param  array|null   $headers        Optional HTTP headers (default: null)
     *
     * @return string|false Returns response data or FALSE on failure
     */
    public function fetch( $url, $post = false, $data = null, $ignoreCodes = null, $headers = null )
    {
        $this->setDefaultNode();
        $result = $this->fetcher->fetch( $url, $post, $data, $ignoreCodes, $headers );
        $lastError = $this->fetcher->getLastError();
        if( $lastError !== false )
        {
            $this->log( 'e', $lastError );
            if( $this->setBestOnError )
                $this->setBestNode();
        }
        return $result;
    }

    /**
     * Fetches GET or POST responses from all nodes
     *
     * @param  string       $url            URL of request
     * @param  bool         $post           POST or GET (default: GET)
     * @param  string|null  $data           Data for POST (default: null)
     * @param  array|null   $ignoreCodes    Array of ignored HTTP codes (default: null)
     * @param  array|null   $headers        Optional HTTP headers (default: null)
     *
     * @return array|false Returns data responses from all nodes or FALSE on failure
     */
    public function fetchMulti( $url, $post = false, $data = null, $ignoreCodes = null, $headers = null )
    {
        return $this->fetcher->fetch( $url, $post, $data, $ignoreCodes, $headers );
    }

    /**
     * Internally sets nodes in order of priority by the current height and response time
     *
     * @return void
     */
    public function setBestNode()
    {
        $this->setDefaultNode();
        $this->fetcher->setBest( '/blocks/height', function( $json, $elapsed )
        {
            if( false === $json ||
                false === ( $json = $this->json_decode( $json ) ) ||
                !isset( $json['height'] ) )
                return 0;

            $height = $json['height'];
            $score = $height + ( 1 - ( $elapsed / ( $this->curlTimeout + 10 ) ) );
            return $score;
        } );
    }

    /**
     * Gets current timestamp
     *
     * @param  bool $fromNode Timstamp from node or local (default: local)
     *
     * @return int|false Timestamp or FALSE on failure
     */
    public function timestamp( $fromNode = false )
    {
        if( $fromNode )
        {
            if( false === ( $json = $this->fetch( '/utils/time' ) ) )
                return false;

            if( false === ( $json = $this->json_decode( $json ) ) )
                return false;

            if( !isset( $json['NTP'] ) )
                return false;

            return $json['NTP'];
        }

        return (int)( microtime( true ) * 1000 );
    }

    /**
     * Gets current blockchain height
     *
     * @return int|false Current blockchain height or FALSE on failure
     */
    public function height()
    {
        if( false === ( $json = $this->fetch( '/blocks/height' ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) || !isset( $json['height'] ) )
            return false;

        return $json['height'];
    }

    /**
     * Gets a block at a certain height
     *
     * @param  int  $height     Height of the block
     * @param  bool $headers    Just headers or the full block information (default: full block)
     *
     * @return array|false Block information or FALSE on failure
     */
    public function getBlockAt( $height, $headers = false )
    {
        $fetch = '/blocks' . ( $headers ? '/headers' : '' ) . ( $height ? ( '/at/' . $height ) : '/last' );
        if( false === ( $json = $this->fetch( $fetch ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        if( !isset( $json['signature'] ) || !isset( $json['reference'] ) )
            return false;

        return $json;
    }

    /**
     * Compiles a script
     *
     * @param  string $script Text of the script
     *
     * @return array|false Compiled script information or FALSE on failure
     */
    public function compile( $script )
    {
        if( false === ( $json = $this->fetch( '/utils/script/compileCode', true, $script ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        if( !isset( $json['script'] ) )
            return false;

        return $json;
    }

    /**
     * Gets a script associated with an address
     *
     * @param  string|null $address Address to get the script for (default: null)
     *
     * @return string|false Address script information or FALSE on failure
     */
    public function getAddressScript( $address = null )
    {
        if( false === ( $address = isset( $address ) ? $address : $this->getAddress() ) )
            return false;

        if( false === ( $json = $this->fetch( "/addresses/scriptInfo/$address" ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        if( !isset( $json['script'] ) )
            return false;

        return $json;
    }

    /**
     * Validates a transaction
     *
     * @param  array $tx Transaction as an array
     *
     * @return array|false Validated transaction as an array or FALSE on failure
     */
    public function txValidate( $tx )
    {
        if( !isset( $tx['proofs'] ) )
            $tx['proofs'] = [];

        if( false === ( $json = $this->fetch( '/debug/validate', true, json_encode( $tx ) ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        if( !isset( $json['valid'] ) )
            return false;

        return $json;
    }

    /**
     * Evaluates a transaction
     *
     * @param  array $tx Transaction as an array
     *
     * @return array|false Evaluated transaction as an array or FALSE on failure
     */
    public function txEvaluate( $tx )
    {
        if( !isset( $tx['dApp'] ) )
            return false;

        if( false === ( $json = $this->fetch( '/utils/script/evaluate/' . $tx['dApp'], true, json_encode( $tx ) ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        if( !isset( $json['stateChanges'] ) && !isset( $json['error'] ) )
            return false;

        $json['valid'] = isset( $json['stateChanges'] ) && !isset( $json['error'] );
        return $json;
    }

    private function txDiffsAmount( &$diffs, $address, $asset, $amount )
    {
        $diffs[$address][$asset] = $amount + ( isset( $diffs[$address][$asset] ) ? $diffs[$address][$asset] : 0 );
    }

    /**
     * Calculates a transaction address/assets/amounts diffs as an array
     *
     * @param  array $tx Transaction as an array
     *
     * @return array|false Calculated diffs as an array or FALSE on failure
     */
    public function txDiffs( $tx, $caller = null, &$diffs = null )
    {
        if( $diffs === null )
            $diffs = [];
        
        if( $caller === null )
            $caller = $tx['sender'];

        $dApp = $tx['dApp'];
        $payments = $tx['payment'];
        $stateChanges = $tx['stateChanges'];

        foreach( $stateChanges['invokes'] as $tx )
            $this->txDiffs( $tx, $dApp, $diffs );

        foreach( $payments as $payment )
        {
            $amount = $payment['amount'];
            $asset = isset( $payment['assetId'] ) ? $payment['assetId'] : 'WAVES';
            $this->txDiffsAmount( $diffs, $caller, $asset, -$amount );
            $this->txDiffsAmount( $diffs, $dApp, $asset, +$amount );
        }
        foreach( $stateChanges['transfers'] as $transfer )
        {
            $amount = $transfer['amount'];
            $asset = isset( $transfer['asset'] ) ? $transfer['asset'] : 'WAVES';
            $this->txDiffsAmount( $diffs, $dApp, $asset, -$amount );
            $this->txDiffsAmount( $diffs, $transfer['address'], $asset, +$amount );
        }

        return $diffs;
    }

    /**
     * Broadcasts a transaction
     *
     * @param  array $tx Transaction as an array
     *
     * @return array|false Broadcasted transaction as an array or FALSE on failure
     */
    public function txBroadcast( $tx )
    {
        if( !isset( $tx['proofs'] ) )
            $tx['proofs'] = [];

        if( false === ( $json = $this->fetch( '/transactions/broadcast', true, json_encode( $tx ) ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        if( !isset( $json['id'] ) )
            return false;

        return $json;
    }

    /**
     * Broadcasts an order to a matcher
     *
     * @param  array $tx Order as an array
     *
     * @return array|false Broadcasted order as an array or FALSE on failure
     */
    public function txOrderBroadcast( $tx )
    {
        $this->setDefaultMatcher();

        if( false === ( $json = $this->matcher->fetch( '/matcher/orderbook', true, json_encode( $tx ) ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        if( !isset( $json['message']['id'] ) )
            return false;

        return $json['message'];
    }

    /**
     * Cancels an order on a matcher
     *
     * @param  array|string $tx Order as an array or word "ALL" to cancel all orders
     *
     * @return bool TRUE on cancel or FALSE on failure
     */
    public function txOrderCancel( $tx )
    {
        $this->setDefaultMatcher();

        if( is_array( $tx ) )
        {
            $cancel = [];
            $cancel['sender'] = $this->getPublicKey();
            $cancel['orderId'] = $tx['id'];
            $cancel['signature'] = $this->base58Encode( $this->sign( $this->getPublicKey( true ) . $this->base58Decode( $tx['id'] ) ) );
        }
        else if( is_string( $tx ) && strtoupper( $tx ) === "ALL" )
        {
            $cancel = [];
            $cancel['sender'] = $this->getPublicKey();
            $cancel['timestamp'] = $this->timestamp();
            $cancel['signature'] = $this->base58Encode( $this->sign( $this->getPublicKey( true ) . pack( 'J', $cancel['timestamp'] ) ) );
        }
        else
            return false;

        if( false === ( $json = $this->matcher->fetch( '/matcher/orderbook/cancel', true, json_encode( $cancel ) ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        if( !isset( $json['success'] ) && $json['success'] === true )
            return false;

        return true;
    }

    /**
     * Gets order history for your account
     *
     * @param  bool      $activeOnly Active only orders (default: true)
     * @param  bool|null $closedOnly Closed only orders (default: null)
     *
     * @return array|false Your orders as an array or FALSE on failure
     */
    public function getOrders( $activeOnly = true, $closedOnly = null )
    {
        $this->setDefaultMatcher();

        $timestamp = $this->timestamp();
        $signature = $this->base58Encode( $this->sign( $this->getPublicKey( true ) . pack( 'J', $timestamp ) ) );

        $headers = [ 'Timestamp: ' . $timestamp, 'Signature: ' . $signature ];

        $params = '?activeOnly=' . ( $activeOnly ? 'true' : 'false' );
        if( isset( $closedOnly ) )
            $params .= '&closedOnly=' . ( $closedOnly ? 'true' : 'false' );
        if( false === ( $json = $this->matcher->fetch( '/matcher/orderbook/' . $this->getPublicKey() . $params, false, null, null, $headers ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        return $json;
    }

    /**
     * Gets an order with status by its id for your account
     *
     * @param  string      $orderId Id of the order
     *
     * @return array|false Your order as an array or FALSE on failure
     */
    public function getOrderById( $orderId )
    {
        $this->setDefaultMatcher();

        $timestamp = $this->timestamp();
        $signature = $this->base58Encode( $this->sign( $this->getPublicKey( true ) . pack( 'J', $timestamp ) ) );

        $headers = [ 'Timestamp: ' . $timestamp, 'Signature: ' . $signature ];

        if( false === ( $json = $this->matcher->fetch( '/matcher/orderbook/' . $this->getPublicKey() . '/' . $orderId, false, null, null, $headers ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        return $json;
    }

    /**
     * Gets an address by an alias
     *
     * @param  string $alias Alias
     *
     * @return string|false Address or FALSE on failure
     */
    public function getAddressByAlias( $alias )
    {
        if( false === ( $json = $this->fetch( "/alias/by-alias/$alias", false, null, [ 404 ] ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        if( !isset( $json['address'] ) )
            return false;

        return $json['address'];
    }

    /**
     * Gets a transaction by its id
     *
     * @param  string   $id             Id of the transaction
     * @param  bool     $unconfirmed    Search in unconfirmed or confirmed transactions (default: confirmed)
     *
     * @return array|false  Found transaction as an array or FALSE on failure
     */
    public function getTransactionById( $id, $unconfirmed = false )
    {
        $unconfirmed = $unconfirmed ? '/unconfirmed' : '';
        if( false === ( $json = $this->fetch( "/transactions$unconfirmed/info/$id", false, null, [ 404 ] ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        return $json;
    }

    /**
     * Gets state changes of an invoke transaction by its id
     *
     * @param  string   $id             Id of the invoke transaction
     *
     * @return array|false  Invoke transaction with state changes as an array or FALSE on failure
     */
    public function getStateChanges( $id )
    {
        if( false === ( $json = $this->fetch( "/debug/stateChanges/info/$id", false, null, [ 404 ] ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) || !isset( $json['stateChanges'] ) || $json['id'] !== $id )
            return false;

        return $json;
    }

    /**
     * Gets transactions for an address
     *
     * @param  string|null  $address    Address to get transactions (default: null)
     * @param  int          $limit      Limit of transactions count (default: 100)
     * @param  string|null  $after      Id of a transaction to paginate from (default: null)
     *
     * @return array|false Transactions as an arrays or FALSE on failure
     */
    public function getTransactions( $address = null, $limit = 100, $after = null )
    {
        $address = isset( $address ) ? $address : $this->getAddress();
        $after = isset( $after ) ? "?after=$after" : '';
        if( false === ( $json = $this->fetch( "/transactions/address/$address/limit/$limit$after" ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        if( !isset( $json[0][0] ) )
            return false;

        return $json[0];
    }

    /**
     * Ensures a transaction confirmed and reached required confirmations
     *
     * @param  array    $tx             Transaction as an array
     * @param  int      $confirmations  Number of confirmations to reach (default: 0)
     * @param  int|float $sleep         Seconds to sleep between requests (default: 0.5)
     * @param  int      $timeout        Timeout to reach lost status (default: 30)
     * @param  bool     $hard           Use hard timeout (default: false)
     *
     * @return array|false Ensured transaction as an array or FALSE on failure
     */
    public function ensure( $tx, $confirmations = 0, $sleep = 0.5, $timeout = 30, $hard = false )
    {
        if( $tx === false )
            return false;

        $id = $tx['id'];
        $n = 0;
        $n_utx = 0;
        $usleep = (int)( $sleep * 1000000 );
        $tsleep = 0;

        while( false === ( $tx = $this->getTransactionById( $id ) ) )
        {
            if( $usleep === 0 )
                return false;

            if( $hard && $n > $timeout )
            {
                $this->log( 'w', "($id) hard timeout reached ($n)" );
                return false;
            }

            usleep( $usleep );
            $tsleep += $usleep;
            if( (int)( ( 1 + $tsleep ) / 1000000 ) === $n )
                continue;

            ++$n;
            $n_diff = $n - $n_utx;
            if( $n_utx )
            {
                $n_diff = $n - $n_utx;
                if( $n_diff > $timeout )
                {
                    if( false === ( $tx = $this->getTransactionById( $id, true ) ) )
                    {
                        $this->log( 'e', "($id) not found (timeout reached)" );
                        return false;
                    }

                    $this->log( 'w', "($id) found in unconfirmed again ($n)" );
                    $n_utx = 0;
                    continue;
                }

                if( $n_diff >= 1 )
                    $this->log( 'i', "($id) still unconfirmed ($n) (timeout $n_diff/$timeout)" );
            }
            else
            {
                if( false === ( $tx = $this->getTransactionById( $id, true ) ) )
                {
                    $n_utx = $n;
                    continue;
                }

                $this->log( 'i', "($id) unconfirmed ($n)" );
            }
        }

        $succeeded = isset( $tx['applicationStatus'] ) && $tx['applicationStatus'] === 'succeeded';
        if( $usleep !== 0 )
        {
            if( $succeeded )
                $this->log( 's', "($id) confirmed" . ( $n > 0 ? " ($n)" : '' ) );
            else
                $this->log( 'e', "($id) failed" . ( $n > 0 ? " ($n)" : '' ) );
        }

        if( $succeeded && $confirmations > 0 )
        {
            $n = 0;
            while( $confirmations > ( $c = $this->height() - $tx['height'] ) )
            {
                if( $usleep === 0 )
                    return false;

                $n++;
                $this->log( 'i', "($id) $c/$confirmations confirmations ($n)" );
                sleep( $sleep > 1 ? (int)$sleep : $confirmations );
            }

            if( $tx !== $this->getTransactionById( $id ) )
            {
                $this->log( 'w', "($id) change detected" );
                $this->fetcher->resetCache();
                return $this->ensure( $tx, $confirmations, $sleep, $timeout, $hard );
            }

            $this->log( 's', "($id) reached $c confirmations" );
            $tx['confirmations'] = $c;
        }

        return $tx;
    }

    /**
     * Gets an address full balance
     *
     * @param  string|null $address Address to get balance (default: null)
     * @param  string|null $asset   Asset to get balance (default: null)
     *
     * @return array|int|false Balance of all assets as an array or balance of specific asset or FALSE on failure
     */
    public function balance( $address = null, $asset = null )
    {
        if( false === ( $address = isset( $address ) ? $address : $this->getAddress() ) )
            return false;

        if( isset( $asset ) )
        {
            if( $asset === 'WAVES' )
                $query = '/addresses/balance/' . $address;
            else
                $query = '/assets/balance/' . $address . '/' . $asset;

            if( false === ( $json = $this->fetch( $query ) ) )
                return false;

            if( false === ( $json = $this->json_decode( $json ) ) )
                return false;

            return $json['balance'];
        }

        if( false === ( $json = $this->fetch( "/addresses/balance/$address" ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        $waves = $json;

        if( false === ( $json = $this->fetch( "/assets/balance/$address" ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        $balance = [];
        $balance[0] = $waves;
        foreach( $json['balances'] as $rec )
            $balance[$rec['assetId']] = $rec;

        return $balance;
    }

    /**
     * Gets an address NFTs balance
     *
     * @param  string|null $address Address to get NFTs (default: null)
     *
     * @return array|int|false Balance of all NFTs as an array or FALSE on failure
     */
    public function nfts( $address = null )
    {
        if( false === ( $address = isset( $address ) ? $address : $this->getAddress() ) )
            return false;

        $nfts = [];
        $after = '';

        for( ;; )
        {
            $fetch = '/assets/nft/' . $address . '/limit/100' . $after;
            if( false === ( $json = $this->fetch( $fetch ) ) )
                return false;

            if( false === ( $json = $this->json_decode( $json ) ) )
                return false;

            unset( $nft );
            foreach( $json as $nft )
                $nfts[] = $nft;

            if( !isset( $nft ) )
                break;

            $after = '?after=' . $nft['assetId'];
        }

        return $nfts;
    }

    private function recipientAddressOrAlias( $recipient )
    {
        if( strlen( $recipient ) === 35 )
            return $recipient;

        return 'alias:' . $this->getChainId() . ":$recipient";
    }

    private function recipientAddressOrAliasBytes( $recipient )
    {
        if( $recipient[0] === '3' )
            return $this->base58Decode( $recipient );

        $network = $recipient[6];
        $recipient = substr( $recipient, 8 );
        return chr( 2 ) . $network . pack( 'n', strlen( $recipient ) ) . $recipient;
    }

    /**
     * Makes alias transaction as an array
     *
     * @param  string $alias        Alias
     * @param  array|null $options  Transaction options as an array (default: null)
     *
     * @return array Alias transaction as an array or FALSE on failure
     */
    public function txAlias( $alias, $options = null )
    {
        $tx = [];
        $tx['type'] = 10;
        $tx['version'] = 2;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->getAddress();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->getPublicKey();
        $tx['fee'] = isset( $options['fee'] ) ? $options['fee'] : 100000;
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        $tx['alias'] = $alias;
        return $tx;
    }

    /**
     * Makes issue transaction as an array
     *
     * @param  string       $name           Asset name
     * @param  string       $description    Asset description
     * @param  int          $quantity       Asset quantity to issue
     * @param  int          $decimals       Asset decimals (0 .. 8)
     * @param  bool         $reissuable     Asset is reissuable or not
     * @param  string       $script         Asset script (default: null)
     * @param  array|null   $options        Transaction options as an array (default: null)
     *
     * @return array Issue transaction as an array or FALSE on failure
     */
    public function txIssue( $name, $description, $quantity, $decimals, $reissuable, $script = null, $options = null )
    {
        if( isset( $script ) && substr( $script, 0, 7 ) === 'base64:' )
            $script = substr( $script, 7 );

        $tx = [];
        $tx['type'] = 3;
        $tx['version'] = 2;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->getAddress();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->getPublicKey();
        $tx['fee'] = isset( $options['fee'] ) ? $options['fee'] : 100000000;
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        $tx['name'] = $name;
        $tx['description'] = $description;
        $tx['quantity'] = $quantity;
        $tx['decimals'] = $decimals;
        $tx['reissuable'] = $reissuable;
        if( isset( $script ) || isset( $options['script'] ) )
            $tx['script'] = isset( $options['script'] ) ? $options['script'] : ( isset( $script ) ? 'base64:' . $script : null );
        return $tx;
    }

    /**
     * Makes reissue transaction as an array
     *
     * @param  string       $asset        Asset id
     * @param  int          $quantity       Asset quantity to reissue
     * @param  bool         $reissuable     Asset is reissuable or not
     * @param  array|null   $options        Transaction options as an array (default: null)
     *
     * @return array Reissue transaction as an array or FALSE on failure
     */
    public function txReissue( $asset, $quantity, $reissuable, $options = null )
    {
        $tx = [];
        $tx['type'] = 5;
        $tx['version'] = 2;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->getAddress();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->getPublicKey();
        $tx['fee'] = isset( $options['fee'] ) ? $options['fee'] : 100000;
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        $tx['assetId'] = $asset;
        $tx['quantity'] = $quantity;
        $tx['reissuable'] = $reissuable;
        return $tx;
    }

    /**
     * Makes burn transaction as an array
     *
     * @param  string       $asset      Asset id
     * @param  int          $quantity   Asset quantity to burn
     * @param  array|null   $options    Transaction options as an array (default: null)
     *
     * @return array Burn transaction as an array or FALSE on failure
     */
    public function txBurn( $asset, $quantity, $options = null )
    {
        $tx = [];
        $tx['type'] = 6;
        $tx['version'] = 2;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->getAddress();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->getPublicKey();
        $tx['fee'] = isset( $options['fee'] ) ? $options['fee'] : 100000;
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        $tx['amount'] = $quantity;
        $tx['assetId'] = $asset;
        return $tx;
    }

    /**
     * Makes transfer transaction as an array
     *
     * @param  string       $recipient  Recipient address or alias
     * @param  int          $amount     Amount to send
     * @param  string|null  $asset      Asset id (default: null)
     * @param  array|null   $options    Transaction options as an array (default: null)
     *
     * @return array Transfer transaction as an array or FALSE on failure
     */
    public function txTransfer( $recipient, $amount, $asset = null, $options = null )
    {
        if( isset( $asset ) && ( $asset === 0 || ( strlen( $asset ) === 5 && strtoupper( $asset ) === 'WAVES' ) ) )
            unset( $asset );

        $tx = [];
        $tx['type'] = 4;
        $tx['version'] = 2;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->getAddress();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->getPublicKey();
        $tx['recipient'] = $this->recipientAddressOrAlias( $recipient );
        if( isset( $asset ) ) $tx['assetId'] = $asset;
        $tx['amount'] = $amount;
        if( isset( $options['feeAssetId'] ) ) $tx['feeAssetId'] = $options['feeAssetId'];
        $tx['fee'] = isset( $options['fee'] ) ? $options['fee'] : 100000;
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        if( isset( $options['attachment'] ) ) $tx['attachment'] = $options['attachment'];
        return $tx;
    }

    /**
     * Makes lease transaction as an array
     *
     * @param  string       $recipient  Recipient address or alias
     * @param  int          $amount     Amount to lease
     * @param  array|null   $options    Transaction options as an array (default: null)
     *
     * @return array Lease transaction as an array or FALSE on failure
     */
    public function txLease( $recipient, $amount, $options = null )
    {
        $tx = [];
        $tx['type'] = 8;
        $tx['version'] = 2;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->getAddress();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->getPublicKey();
        $tx['recipient'] = $this->recipientAddressOrAlias( $recipient );
        $tx['amount'] = $amount;
        $tx['fee'] = isset( $options['fee'] ) ? $options['fee'] : 100000;
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        return $tx;
    }

    /**
     * Makes lease cancel transaction as an array
     *
     * @param  string       $leaseId    Lease transaction id to cancel
     * @param  array|null   $options    Transaction options as an array (default: null)
     *
     * @return array Lease cancel transaction as an array or FALSE on failure
     */
    public function txLeaseCancel( $leaseId, $options = null )
    {
        $tx = [];
        $tx['type'] = 9;
        $tx['version'] = 2;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->getAddress();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->getPublicKey();
        $tx['leaseId'] = $leaseId;
        $tx['fee'] = isset( $options['fee'] ) ? $options['fee'] : 100000;
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        $tx['chainId'] = ord( $this->getChainId() );
        return $tx;
    }

    /**
     * Makes order as an array
     *
     * @param  string       $amountAsset    Amount asset id
     * @param  string       $priceAsset     Price asset id
     * @param  bool         $isSell         Sell or buy
     * @param  int          $amount         Order amount
     * @param  int          $price          Order price
     * @param  int          $expiration     Order expiration
     * @param  array|null   $options        Order options as an array (default: null)
     *
     * @return array Order as an array
     */
    public function txOrder( $amountAsset, $priceAsset, $isSell, $amount, $price, $expiration = 30 * 24 * 60 * 60 * 1000, $options = null )
    {
        $this->setDefaultMatcher();

        $tx = [];
        $tx['version'] = 3;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->getAddress();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->getPublicKey();
        $tx['matcherPublicKey'] = isset( $options['matcherPublicKey'] ) ? $options['matcherPublicKey'] : $this->matcherPublicKey;
        $tx['assetPair'] = [
            'amountAsset' => $amountAsset,
            'priceAsset' => $priceAsset ];
        $tx['orderType'] = $isSell ? 'sell' : 'buy';
        $tx['amount'] = $amount;
        $tx['price'] = $price;
        $tx['matcherFee'] = isset( $options['matcherFee'] ) ? $options['matcherFee'] : 300000;
        $tx['matcherFeeAssetId'] = isset( $options['matcherFeeAssetId'] ) ? $options['matcherFeeAssetId'] : null;
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        $tx['expiration'] = $tx['timestamp'] + $expiration;
        return $tx;
    }

    /**
     * Makes mass transfer transaction as an array
     *
     * @param  array        $recipients Array of recipient addresses or aliases
     * @param  array        $amounts    Array of amounts to send
     * @param  string       $asset      Asset id to send
     * @param  array|null   $options    Transaction options as an array (default: null)
     *
     * @return array|false Mass transfer transaction as an array or FALSE on failure
     */
    public function txMass( $recipients, $amounts, $asset = null, $options = null )
    {
        $n = count( $recipients );
        if( $n !== count( $amounts ) )
        {
            $this->log( 'e', 'recipients !== amounts' );
            return false;
        }

        if( isset( $asset ) && ( $asset === 0 || ( strlen( $asset ) === 5 && strtoupper( $asset ) === 'WAVES' ) ) )
            unset( $asset );

        $tx = [];
        $tx['type'] = 11;
        $tx['version'] = 1;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->getAddress();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->getPublicKey();
        $tx['fee'] = 100000 + $n * 50000 + ( $n % 2 ) * 50000;
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        if( isset( $asset ) ) $tx['assetId'] = $asset;
        if( isset( $options['attachment'] ) ) $tx['attachment'] = $options['attachment'];
        $tx['transfers'] = [];
        for( $i = 0; $i < $n; $i++ )
            $tx['transfers'][] = [ 'recipient' => $this->recipientAddressOrAlias( $recipients[$i] ), 'amount' => $amounts[$i] ];
        return $tx;
    }

    /**
     * Makes data transaction as an array
     *
     * @param  array        $userData   Array of key value pairs
     * @param  array|null   $options    Transaction options as an array (default: null)
     *
     * @return array|false Data transaction as an array or FALSE on failure
     */
    public function txData( $userData, $options = null )
    {
        $tx = [];
        $tx['type'] = 12;
        $tx['version'] = 1;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->getAddress();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->getPublicKey();
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        $tx['data'] = isset( $options['data'] ) ? $options['data'] : $this->userDataToTxData( $userData );
        $tx['fee'] = isset( $options['fee'] ) ? $options['fee'] : $this->getDataFee( $tx );
        return $tx;
    }

    /**
     * Makes address script transaction as an array
     *
     * @param  string       $script     Script to set
     * @param  array|null   $options    Transaction options as an array (default: null)
     *
     * @return array|false Address script transaction as an array or FALSE on failure
     */
    public function txAddressScript( $script, $options = null )
    {
        if( isset( $script ) && substr( $script, 0, 7 ) === 'base64:' )
            $script = substr( $script, 7 );

        $tx = [];
        $tx['type'] = 13;
        $tx['version'] = 1;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->getAddress();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->getPublicKey();
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        $tx['script'] = isset( $options['script'] ) ? $options['script'] : ( isset( $script ) ? 'base64:' . $script : null );
        $tx['fee'] = isset( $options['fee'] ) ? $options['fee'] : $this->getScriptFee( $tx );
        return $tx;
    }

    /**
     * Makes sponsorship transaction as an array
     *
     * @param  string       $asset                Asset id of the sponsorship
     * @param  int          minSponsoredAssetFee    Minimal sponsored asset fee
     * @param  array|null   $options                Transaction options as an array (default: null)
     *
     * @return array|false Sponsorship transaction as an array or FALSE on failure
     */
    public function txSponsorship( $asset, $minSponsoredAssetFee, $options = null )
    {
        $tx = [];
        $tx['type'] = 14;
        $tx['version'] = 1;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->getAddress();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->getPublicKey();
        $tx['assetId'] = $asset;
        $tx['minSponsoredAssetFee'] = $minSponsoredAssetFee;
        $tx['fee'] = isset( $options['fee'] ) ? $options['fee'] : 100000000;
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        return $tx;
    }

    /**
     * Makes asset script transaction as an array
     *
     * @param  string       $asset    Asset id to script change
     * @param  string       $script     Asset script
     * @param  array|null   $options    Transaction options as an array (default: null)
     *
     * @return array|false Asset script transaction as an array or FALSE on failure
     */
    public function txAssetScript( $asset, $script, $options = null )
    {
        if( isset( $script ) && substr( $script, 0, 7 ) === 'base64:' )
            $script = substr( $script, 7 );

        $tx = [];
        $tx['type'] = 15;
        $tx['version'] = 1;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->getAddress();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->getPublicKey();
        $tx['assetId'] = $asset;
        $tx['script'] = isset( $options['script'] ) ? $options['script'] : ( isset( $script ) ? 'base64:' . $script : null );
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        $tx['fee'] = isset( $options['fee'] ) ? $options['fee'] : 100000000;
        $tx['chainId'] = ord( $this->getChainId() );
        return $tx;
    }

    /**
     * Makes invoke script transaction as an array
     *
     * @param  string       $dappAddress    Address of dApp script
     * @param  string       $function       Function to call
     * @param  array|null   $args           Arguments as an array (default: null)
     * @param  array|null   $payments       Payments as an array (default: null)
     * @param  array|null   $options        Transaction options as an array (default: null)
     *
     * @return array|false Invoke script transaction as an array or FALSE on failure
     */
    public function txInvokeScript( $dappAddress, $function, $args = null, $payments = null, $options = null )
    {
        $tx = [];
        $tx['type'] = 16;
        $tx['version'] = 1;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->getAddress();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->getPublicKey();
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        $tx['dApp'] = $this->recipientAddressOrAlias( $dappAddress );
        if( isset( $function ) )
        {
            $tx['call']['function'] = $function;
            $tx['call']['args'] = isset( $args ) ? $this->argsValuesToTxValues( $args ) : [];
        }
        $tx['payment'] = isset( $payments ) ? $payments : [];
        if( isset( $options['feeAssetId'] ) ) $tx['feeAssetId'] = $options['feeAssetId'];
        $tx['fee'] = isset( $options['fee'] ) ? $options['fee'] : 500000;
        $tx['chainId'] = ord( $this->getChainId() );
        return $tx;
    }

    /**
     * Makes update asset information transaction as an array
     *
     * @param  string       $assetId          Asset ID
     * @param  string       $name           Updated asset name
     * @param  string       $description    Updated asset description
     * @param  array|null   $options        Transaction options as an array (default: null)
     *
     * @return array Update asset information transaction as an array or FALSE on failure
     */
    public function txUpdateAssetInfo( $assetId, $name, $description, $options = null )
    {
        $tx = [];
        $tx['type'] = 17;
        $tx['version'] = 1;
        $tx['chainId'] = ord( $this->getChainId() );
        $tx['assetId'] = $assetId;
        $tx['name'] = $name;
        $tx['description'] = $description;
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->getPublicKey();
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        $tx['fee'] = isset( $options['fee'] ) ? $options['fee'] : 100000;
        return $tx;
    }

    private function userDataToTxData( $userData )
    {
        $data = [];
        foreach( $userData as $key => $value )
        {
            if( is_array( $value ) )
                $data[] = [ 'key' => $key, 'type' => 'binary', 'value' => $this->binToBase64Tx( $value[0] ) ];
            else
                $data[] = [ 'key' => $key, 'type' => gettype( $value ), 'value' => $value ];
        }
        return $data;
    }

    private function argsValuesToTxValues( $args )
    {
        $data = [];
        foreach( $args as $value )
        {
            if( isset( $value['list'] ) )
                $data[] = [ 'type' => 'list', 'value' => $this->argsValuesToTxValues( $value['list'] ) ];
            else
            if( is_array( $value ) )
                $data[] = [ 'type' => 'binary', 'value' => $this->binToBase64Tx( $value[0] ) ];
            else
                $data[] = [ 'type' => gettype( $value ), 'value' => $value ];
        }
        return $data;
    }

    /**
     * Converts string from base64 to base64 in transaction notation
     *
     * @param  string $base64 Base64 string
     *
     * @return string Base64 string in transaction notation
     */
    public function base64ToBase64Tx( $base64 )
    {
        return 'base64:' . $base64;
    }

    /**
     * Converts string from base64 in transaction notation to base64
     *
     * @param  string $base64 Base64 string in transaction notation
     *
     * @return string Base64 string
     */
    public function base64TxToBase64( $base64 )
    {
        return substr( $base64, 7 );
    }

    /**
     * Converts binary data to base64 string in transaction notation
     *
     * @param  string $bin Binary data
     *
     * @return string Base64 string in transaction notation
     */
    public function binToBase64Tx( $bin )
    {
        return $this->base64ToBase64Tx( base64_encode( $bin ) );
    }

    /**
     * Converts base64 string in transaction notation to binary data
     *
     * @param  string $base64 Base64 string in transaction notation
     *
     * @return string Binary data
     */
    public function base64TxToBin( $base64 )
    {
        return base64_decode( $this->base64TxToBase64( $base64 ) );
    }

    private function getDataRecordBody( $rec )
    {
        $key = $rec['key'];
        $type = $rec['type'];
        $value = $rec['value'];

        $body = pack( 'n', strlen( $key ) ) . $key;

        switch( $type )
        {
            case 'integer':
                return $body . chr( 0 ) . pack( 'J', $value );
            case 'boolean':
                return $body . chr( 1 ) . chr( ( $value === true || $value === 'true' ) ? 1 : 0 );
            case 'binary':
                $value = $this->base64TxToBin( $value );
                return $body . chr( 2 ) . pack( 'n', strlen( $value ) ) . $value;
            case 'string':
                return $body . chr( 3 ) . pack( 'n', strlen( $value ) ) . $value;
        }
    }

    private function getArgsRecordBody( $args )
    {
        $body = pack( 'N', count( $args ) );
        foreach( $args as $rec )
            $body .= $this->getArgRecordBody( $rec );
        return $body;
    }

    private function getArgRecordBody( $rec )
    {
        $type = $rec['type'];
        $value = $rec['value'];

        switch( $type )
        {
            case 'list':
                return chr( 11 ) . $this->getArgsRecordBody( $value );
            case 'integer':
                return chr( 0 ) . pack( 'J', $value );
            case 'binary':
                $value = $this->base64TxToBin( $value );
                return chr( 1 ) . pack( 'N', strlen( $value ) ) . $value;
            case 'string':
                return chr( 2 ) . pack( 'N', strlen( $value ) ) . $value;
            case 'boolean':
                return chr( ( $value === true || $value === 'true' ) ? 6 : 7 );
        }
    }

    /**
     * Calculates fee of a transaction on a node
     *
     * @param  array $tx Transaction as an array
     *
     * @return int|false Minimal fee for transaction or FALSE on failure
     */
    public function calculateFee( $tx )
    {
        if( false === ( $json = $this->fetch( '/transactions/calculateFee', true, json_encode( $tx ) ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        if( !isset( $json['feeAmount'] ) )
            return false;

        return $json['feeAmount'];
    }

    /**
     * Gets data value by an address key from the blockchain
     *
     * @param  string   $key        Key to get value
     * @param  string   $address    Address of the key value pair (default: null)
     * @param  bool     $justValue  Get just value or full information (default: just value)
     *
     * @return mixed|false Value from blockchain by the key
     */
    public function getData( $key, $address = null, $justValue = true )
    {
        $address = isset( $address ) ? $address : $this->getAddress();
        if( false === ( $json = $this->fetch( "/addresses/data/$address/$key", false, null, [ 404 ] ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        if( !isset( $json['value'] ) )
            return false;

        return $justValue ? $json['value'] : $json;
    }

    private function getDataFee( $tx )
    {
        if( !isset( $tx['fee'] ) )
            $tx['fee'] = 0;

        $size = strlen( $this->txBody( $tx ) );
        return 100000 * ( 1 + (int)( ( $size - 1 ) / 1024 ) );
    }

    private function getScriptFee( $tx )
    {
        if( !isset( $tx['script'] ) )
            return 100000;

        $size = strlen( $this->base64TxToBin( $tx['script'] ) );
        if( $size === 0 )
            return 100000;

        return 100000 * ( 1 + (int)( ( $size - 1 ) / 1024 ) );
    }

    /**
     * Gets transaction body
     *
     * @param  array $tx Transaction as an array
     *
     * @return string|false Body of the transaction or FALSE on failure
     */
    public function txBody( $tx )
    {
        $body = '';

        if( isset( $tx['orderType'] ) )
        {
            $body .= chr( 3 );
            $body .= $this->base58Decode( $tx['senderPublicKey'] );
            $body .= $this->base58Decode( $tx['matcherPublicKey'] );
            $body .= isset( $tx['assetPair']['amountAsset'] ) ? chr( 1 ) . $this->base58Decode( $tx['assetPair']['amountAsset'] ) : chr( 0 );
            $body .= isset( $tx['assetPair']['priceAsset'] ) ? chr( 1 ) . $this->base58Decode( $tx['assetPair']['priceAsset'] ) : chr( 0 );
            $body .= $tx['orderType'] === 'buy' ? chr( 0 ) : chr( 1 );
            $body .= pack( 'J', $tx['price'] );
            $body .= pack( 'J', $tx['amount'] );
            $body .= pack( 'J', $tx['timestamp'] );
            $body .= pack( 'J', $tx['expiration'] );
            $body .= pack( 'J', $tx['matcherFee'] );
            $body .= isset( $tx['matcherFeeAssetId'] ) ? chr( 1 ) . $this->base58Decode( $tx['matcherFeeAssetId'] ) : chr( 0 );
            return $body;
        }

        switch( $tx['type'] )
        {
            case 3: // issue
                $script = isset( $tx['script'] ) ? base64_decode( substr( $tx['script'], 7 ) ) : null;

                $body .= chr( 3 );
                $body .= chr( 2 );
                $body .= $this->getChainId();
                $body .= $this->base58Decode( $tx['senderPublicKey'] );
                $body .= pack( 'n', strlen( $tx['name'] ) ) . $tx['name'];
                $body .= pack( 'n', strlen( $tx['description'] ) ) . $tx['description'];
                $body .= pack( 'J', $tx['quantity'] );
                $body .= chr( $tx['decimals'] );
                $body .= chr( $tx['reissuable'] ? 1 : 0 );
                $body .= pack( 'J', $tx['fee'] );
                $body .= pack( 'J', $tx['timestamp'] );
                $body .= isset( $script ) ? chr( 1 ) . pack( 'n', strlen( $script ) ) . $script : chr( 0 );
                break;

            case 4: // transfer
                $attachment = isset( $tx['attachment'] ) ? $this->base58Decode( $tx['attachment'] ) : null;

                $body .= chr( 4 );
                $body .= chr( 2 );
                $body .= $this->base58Decode( $tx['senderPublicKey'] );
                $body .= isset( $tx['assetId'] ) ? chr( 1 ) . $this->base58Decode( $tx['assetId'] ) : chr( 0 );
                $body .= isset( $tx['feeAssetId'] ) ? chr( 1 ) . $this->base58Decode( $tx['feeAssetId'] ) : chr( 0 );
                $body .= pack( 'J', $tx['timestamp'] );
                $body .= pack( 'J', $tx['amount'] );
                $body .= pack( 'J', $tx['fee'] );
                $body .= $this->recipientAddressOrAliasBytes( $tx['recipient'] );
                $body .= isset( $attachment ) ? pack( 'n', strlen( $attachment ) ) . $attachment : chr( 0 ) . chr( 0 );
                break;

            case 5: // reissue
                $body .= chr( 5 );
                $body .= chr( 2 );
                $body .= $this->getChainId();
                $body .= $this->base58Decode( $tx['senderPublicKey'] );
                $body .= $this->base58Decode( $tx['assetId'] );
                $body .= pack( 'J', $tx['quantity'] );
                $body .= chr( $tx['reissuable'] ? 1 : 0 );
                $body .= pack( 'J', $tx['fee'] );
                $body .= pack( 'J', $tx['timestamp'] );
                break;

            case 6: // burn
                $body .= chr( 6 );
                $body .= chr( 2 );
                $body .= $this->getChainId();
                $body .= $this->base58Decode( $tx['senderPublicKey'] );
                $body .= $this->base58Decode( $tx['assetId'] );
                $body .= pack( 'J', $tx['amount'] );
                $body .= pack( 'J', $tx['fee'] );
                $body .= pack( 'J', $tx['timestamp'] );
                break;

            case 8: // lease
                $body .= chr( 8 );
                $body .= chr( 2 );
                $body .= chr( 0 );
                //$body .= $this->getChainId();
                $body .= $this->base58Decode( $tx['senderPublicKey'] );
                $body .= $this->recipientAddressOrAliasBytes( $tx['recipient'] );
                $body .= pack( 'J', $tx['amount'] );
                $body .= pack( 'J', $tx['fee'] );
                $body .= pack( 'J', $tx['timestamp'] );
                break;

            case 9: // lease cancel
                $body .= chr( 9 );
                $body .= chr( 2 );
                $body .= $this->getChainId();
                $body .= $this->base58Decode( $tx['senderPublicKey'] );
                $body .= pack( 'J', $tx['fee'] );
                $body .= pack( 'J', $tx['timestamp'] );
                $body .= $this->base58Decode( $tx['leaseId'] );
                break;

            case 10: // alias
                $body .= chr( 10 );
                $body .= chr( 2 );
                $body .= $this->base58Decode( $tx['senderPublicKey'] );
                $body .= pack( 'n', strlen( $tx['alias'] ) + 4 );
                $body .= chr( 2 ) . $this->getChainId();
                $body .= pack( 'n', strlen( $tx['alias'] ) );
                $body .= $tx['alias'];
                $body .= pack( 'J', $tx['fee'] );
                $body .= pack( 'J', $tx['timestamp'] );
                break;

            case 11: // mass
                $attachment = isset( $tx['attachment'] ) ? $this->base58Decode( $tx['attachment'] ) : null;

                $body .= chr( 11 );
                $body .= chr( 1 );
                $body .= $this->base58Decode( $tx['senderPublicKey'] );
                $body .= isset( $tx['assetId'] ) ? chr( 1 ) . $this->base58Decode( $tx['assetId'] ) : chr( 0 );
                $body .= pack( 'n', count( $tx['transfers'] ) );
                foreach( $tx['transfers'] as $rec )
                {
                    $body .= $this->recipientAddressOrAliasBytes( $rec['recipient'] );
                    $body .= pack( 'J', $rec['amount'] );
                }
                $body .= pack( 'J', $tx['timestamp'] );
                $body .= pack( 'J', $tx['fee'] );
                $body .= isset( $attachment ) ? pack( 'n', strlen( $attachment ) ) . $attachment : chr( 0 ) . chr( 0 );
                break;

            case 12: // data
                $body .= chr( 12 );
                $body .= chr( 1 );
                $body .= $this->base58Decode( $tx['senderPublicKey'] );
                $body .= pack( 'n', count( $tx['data'] ) );
                foreach( $tx['data'] as $rec )
                    $body .= $this->getDataRecordBody( $rec );
                $body .= pack( 'J', $tx['timestamp'] );
                $body .= pack( 'J', $tx['fee'] );
                break;

            case 13: // smart account
                $script = isset( $tx['script'] ) ? base64_decode( substr( $tx['script'], 7 ) ) : null;

                $body .= chr( 13 );
                $body .= chr( 1 );
                $body .= $this->getChainId();
                $body .= $this->base58Decode( $tx['senderPublicKey'] );
                $body .= isset( $script ) ? chr( 1 ) . pack( 'n', strlen( $script ) ) . $script : chr( 0 );
                $body .= pack( 'J', $tx['fee'] );
                $body .= pack( 'J', $tx['timestamp'] );
                break;

            case 14: // sponsorship
                $body .= chr( 14 );
                $body .= chr( 1 );
                $body .= $this->base58Decode( $tx['senderPublicKey'] );
                $body .= $this->base58Decode( $tx['assetId'] );
                $body .= pack( 'J', $tx['minSponsoredAssetFee'] );
                $body .= pack( 'J', $tx['fee'] );
                $body .= pack( 'J', $tx['timestamp'] );
                break;

            case 15: // smart asset
                $script = isset( $tx['script'] ) ? base64_decode( substr( $tx['script'], 7 ) ) : null;

                $body .= chr( 15 );
                $body .= chr( 1 );
                $body .= $this->getChainId();
                $body .= $this->base58Decode( $tx['senderPublicKey'] );
                $body .= $this->base58Decode( $tx['assetId'] );
                $body .= pack( 'J', $tx['fee'] );
                $body .= pack( 'J', $tx['timestamp'] );
                $body .= isset( $script ) ? chr( 1 ) . pack( 'n', strlen( $script ) ) . $script : chr( 0 );
                break;

            case 16: // invoke script
                if( $tx['version'] === 2 )
                {
                    $dApp = new \Waves\Protobuf\Recipient;
                    if( $tx['dApp'][0] === '3' )
                        $dApp->setPublicKeyHash( substr( $this->base58Decode( $tx['dApp'] ), 2, 20 ) );
                    else
                        $dApp->setAlias( substr( $tx['dApp'], 8 ) );

                    if( isset( $tx['call']['function'] ) )
                    {
                        $body .= chr( 1 ) . chr( 9 ) . chr( 1 );
                        $body .= pack( 'N', strlen( $tx['call']['function'] ) ) . $tx['call']['function'];
                        $body .= $this->getArgsRecordBody( $tx['call']['args'] );
                    }
                    else
                    {
                        $body .= chr( 0 );
                    }

                    $payments = [];
                    foreach( $tx['payment'] as $rec )
                    {
                        $amount = new \Waves\Protobuf\Amount;
                        if( isset( $rec['assetId'] ) ) $amount->setAssetId( $this->base58Decode( $rec['assetId'] ) );
                        $amount->setAmount( $rec['amount'] );
                        $payments[] = $amount;
                    }

                    $feeAmount = new \Waves\Protobuf\Amount;
                    if( isset( $tx['feeAssetId'] ) ) $feeAmount->setAssetId( $this->base58Decode( $tx['feeAssetId'] ) );
                    $feeAmount->setAmount( $tx['fee'] );

                    $invokeScript = new \Waves\Protobuf\InvokeScriptTransactionData;
                    $invokeScript->setDApp( $dApp );
                    $invokeScript->setFunctionCall( $body );
                    $invokeScript->setPayments( $payments );

                    $pbtx = new \Waves\Protobuf\Transaction();
                    $pbtx->setInvokeScript( $invokeScript );

                    $pbtx->setVersion( $tx['version'] );
                    $pbtx->setChainId( $tx['chainId'] );
                    $pbtx->setSenderPublicKey( $this->base58Decode( $tx['senderPublicKey'] ) );
                    $pbtx->setFee( $feeAmount );
                    $pbtx->setTimestamp( $tx['timestamp'] );

                    $body = $pbtx->serializeToString();
                    break;
                }

                $body .= chr( 16 );
                $body .= chr( 1 );
                $body .= $this->getChainId();
                $body .= $this->base58Decode( $tx['senderPublicKey'] );
                $body .= $this->recipientAddressOrAliasBytes( $tx['dApp'] );
                if( isset( $tx['call']['function'] ) )
                {
                    $body .= chr( 1 ) . chr( 9 ) . chr( 1 );
                    $body .= pack( 'N', strlen( $tx['call']['function'] ) ) . $tx['call']['function'];
                    $body .= $this->getArgsRecordBody( $tx['call']['args'] );
                }
                else
                {
                    $body .= chr( 0 );
                }
                $body .= pack( 'n', count( $tx['payment'] ) );
                foreach( $tx['payment'] as $rec )
                {
                    $payment = pack( 'J', $rec['amount'] );
                    $payment .= isset( $rec['assetId'] ) ? ( chr( 1 ) . $this->base58Decode( $rec['assetId'] ) ) : chr( 0 );
                    $body .= pack( 'n', strlen( $payment ) ) . $payment;
                }
                $body .= pack( 'J', $tx['fee'] );
                $body .= isset( $tx['feeAssetId'] ) ? chr( 1 ) . $this->base58Decode( $tx['feeAssetId'] ) : chr( 0 );
                $body .= pack( 'J', $tx['timestamp'] );
                break;

            case 17: // update asset info
                $updateAssetInfo = new \Waves\Protobuf\UpdateAssetInfoTransactionData;
                $updateAssetInfo->setAssetId( $this->base58Decode( $tx['assetId'] ) );
                $updateAssetInfo->setName( $tx['name'] );
                $updateAssetInfo->setDescription( $tx['description'] );

                $feeAmount = new \Waves\Protobuf\Amount;
                if( isset( $tx['feeAssetId'] ) ) $feeAmount->setAssetId( $tx['feeAssetId'] );
                $feeAmount->setAmount( $tx['fee'] );

                $pbtx = new \Waves\Protobuf\Transaction();
                $pbtx->setUpdateAssetInfo( $updateAssetInfo );

                $pbtx->setVersion( $tx['version'] );
                $pbtx->setChainId( $tx['chainId'] );
                $pbtx->setSenderPublicKey( $this->base58Decode( $tx['senderPublicKey'] ) );
                $pbtx->setFee( $feeAmount );
                $pbtx->setTimestamp( $tx['timestamp'] );

                $body = $pbtx->serializeToString();
                break;

            default:
                return false;
        }

        return $body;
    }

    /**
     * Signs a transaction
     *
     * @param  array    $tx         Transaction as an array
     * @param  int|null $proofIndex Index of a proof in proofs (default: null)
     *
     * @return array|false Signed transaction as an array or FALSE on failure
     */
    public function txSign( $tx, $proofIndex = null )
    {
        if( false === ( $body = $this->txBody( $tx ) ) )
            return false;

        $sig = $this->sign( $body );
        $id = $this->blake2b256( $body );

        if( false === $sig || false === $id )
            return false;

        $tx['id'] = $this->base58Encode( $id );

        $sig = $this->base58Encode( $sig );

        if( !isset( $tx['proofs'] ) )
            $tx['proofs'] = [];

        if( !isset( $proofIndex ) )
            $tx['proofs'][] = $sig;
        else
        {
            $tx['proofs'][$proofIndex] = $sig;
            ksort( $tx['proofs'] );
        }

        return $tx;
    }

    /**
     * Sets cryptash parameters
     *
     * @param  string   $secret Secret string
     * @param  int      $iv     IV size
     * @param  int      $mac    MAC size
     * @param  string   $hash   Hash algorithm (default: sha256)
     *
     * @return void
     */
    public function setCryptash( $secret, $iv = 4, $mac = 4, $hash = 'sha256' )
    {
        $this->cryptash = new Cryptash( $secret, $iv, $mac, $hash );
    }

    private $cryptash;

    /**
     * Encrypts data with cryptash parameters
     *
     * @param  string $data Data to encrypt
     *
     * @return string|false Encrypted data or FALSE on failure
     */
    public function encryptash( $data )
    {
        if( !isset( $this->cryptash ) )
            return false;

        return $this->cryptash->encryptash( $data );
    }

    /**
     * Decrypts data with cryptash parameters
     *
     * @param  string $data Data to decrypt
     *
     * @return string|false Decrypted data or FALSE on failure
     */
    public function decryptash( $data )
    {
        if( !isset( $this->cryptash ) )
            return false;

        return $this->cryptash->decryptash( $data );
    }

    private $pairs;

    private function getPairsDatabase()
    {
        if( isset( $this->pairs ) )
            return $this->pairs;
        return false;
    }

    /**
     * Sets database pairs path
     *
     * @param  mixed $path Path or an existing PDO for the database
     *
     * @return void
     */
    public function setPairsDatabase( $path )
    {
        $this->pairs['transactions'] = new Pairs( $path, 'savedTransactions', true, 'TEXT UNIQUE|INTEGER|0|0' );
        $this->pairs['signatures'] = new Pairs( $this->pairs['transactions']->db(), 'savedSignatures', true, 'INTEGER PRIMARY KEY|TEXT|0|0' );
    }

    private function watchTransactions( $transactionPairs, $signaturePairs, &$newTransactions, &$newSignatures, $confirmations, $depth )
    {
        $id = null;
        $lastNewTransaction = null;
        $lastHeight = 0;
        $limit = 10;
        $passedBlocks = 0;

        for( ;; )
        {
            if( false === ( $transactions = $this->getTransactions( null, $limit, $id ) ) )
                return isset( $id ) ? $lastNewTransaction : [ 'id' => '', 'height' => 0 ];

            foreach( $transactions as $transaction )
            {
                $id = $transaction['id'];
                $height = $transaction['height'];
                if( !isset( $lastNewTransaction ) )
                    $lastNewTransaction = $transaction;

                if( $lastHeight !== $height )
                {
                    $passedBlocks++;
                    $lastHeight = $height;

                    if( $depth > $height )
                        return $lastNewTransaction;

                    if( false === ( $header = $this->getBlockAt( $height, true ) ) )
                    {
                        $this->log( 'e', 'getBlockAt failed' );
                        return false;
                    }

                    $signature = $header['signature'];
                    $savedSignature = $signaturePairs->getValue( $height );
                    if( $savedSignature !== $signature )
                    {
                        $newSignatures[$height] = $signature;
                        $stableConfirmations = null;
                    }
                    elseif( !isset( $stableConfirmations ) )
                        $stableConfirmations = 0;
                    elseif( isset( $stableConfirmations ) && ++$stableConfirmations >= $confirmations )
                        return $lastNewTransaction;
                }

                $savedHeight = $transactionPairs->getValue( $id, 'i' );

                if( $savedHeight === false )
                    $transaction['status'] = 'new';
                elseif( $savedHeight !== $height )
                    $transaction['status'] = 'replaced';
                else
                    continue;

                $newTransactions[] = $transaction;
                if( isset( $stableConfirmations ) )
                    $stableConfirmations = null;
            }

            if( $passedBlocks > 10 )
                $limit = 100;
        }
    }

    private function getNewTransaction( $lastTransaction )
    {
        if( false === ( $transaction = $this->getTransactions( null, 1 ) ) )
            return false;

        $transaction = $transaction[0];
        if( $lastTransaction['id'] !== $transaction['id'] || $lastTransaction['height'] !== $transaction['height'] )
            return $transaction;

        return false;
    }

    /**
     * Monitors for new transaction in realtime
     *
     * @param  callable $callback       Function to call when new transactions apear
     * @param  int      $confirmations  Number of confirmations to reach stability
     * @param  int      $depth          Minimal height to scan back
     * @param  int      $sleep          Seconds to sleep between requests
     *
     * @return bool TRUE if monitoring was successful or FALSE on failure
     */
    public function txMonitor( $callback, $confirmations = 2, $depth = 0, $sleep = 1 )
    {
        if( false === ( $pairs = $this->getPairsDatabase() ) )
        {
            $this->log( 'e', 'setPairsDatabase() first' );
            return false;
        }

        for( ;; )
        {
            $newTransactions = [];
            $newSignatures = [];
            if( false === ( $lastTx = $this->watchTransactions( $pairs['transactions'], $pairs['signatures'],
                                                                $newTransactions, $newSignatures,
                                                                $confirmations, $depth ) ) )
            {
                $this->log( 'e', 'watchTransactions() failed' );
                return false;
            }

            $refreshed = count( $newTransactions ) || count( $newSignatures );
            $newTransactions = array_reverse( $newTransactions );

            if( false === ( $result = $callback( $this, $refreshed, $newTransactions ) ) )
                return false;

            if( $refreshed )
            {
                $n = 0;
                $pairs['transactions']->begin();
                foreach( $newTransactions as $tx )
                {
                    $pairs['transactions']->setKeyValue( $tx['id'], $tx['height'] );
                    if( $tx['status'] === 'new' )
                        $n++;
                }
                foreach( $newSignatures as $height => $signature )
                    $pairs['signatures']->setKeyValue( $height, $signature );
                $pairs['transactions']->commit();

                if( $n )
                    $this->log( 'i', 'new transactions (' . $n . ')' );
            }

            if( $result > 0 )
            {
                $height = $this->height();

                if( $height - $lastTx['height'] > $confirmations )
                {
                    $n = 0;
                    while( false === ( $newTx = $this->getNewTransaction( $lastTx ) ) )
                    {
                        $n += $sleep;
                        if( $n >= $result )
                        {
                            $this->log( 'i', "no new transactions" );
                            break;
                        }
                        sleep( $sleep );
                    }

                    if( $newTx !== false )
                        $this->log( 'i', "new transaction found" );

                    continue;
                }
                else
                {
                    sleep( $sleep );
                    continue;
                }
            }

            break;
        }

        return true;
    }
}
