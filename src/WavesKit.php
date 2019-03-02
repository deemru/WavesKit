<?php

namespace deemru;

use deemru\ABCode;
use deemru\Blake2b;
use deemru\Curve25519;
use deemru\Cryptash;
use deemru\Pairs;
use Composer\CaBundle\CaBundle;

interface WavesKitInterface
{
    public function __construct( $chainId = 'W', $logFunction = null );

    public function base58Encode( $data );
    public function base58Decode( $data );

    public function sha256( $data );
    public function blake2b256( $data );
    public function keccak256( $data );
    public function secureHash( $data );

    public function setSodium( $enabled = true );
    public function getSodium();

    public function getChainId();
    public function randomSeed( $words = 15 );
    public function isAddressValid( $address );

    public function setSeed( $seed, $raw = true );

    public function setPrivateKey( $privateKey, $raw = false );
    public function getPrivateKey( $raw = false );
    public function setPublicKey( $publicKey, $raw = false );
    public function getPublicKey( $raw = false );
    public function setAddress( $address, $raw = false );
    public function getAddress( $raw = false );

    public function sign( $data );
    public function verify( $sig, $data );

    public function txIssue( $name, $description, $quantity, $decimals, $reissuable, $script = null, $options = null );
    public function txTransfer( $recipient, $amount, $asset = null, $options = null );
    public function txReissue( $asset, $quantity, $reissuable, $options = null );
    public function txBurn( $amount, $asset, $options = null );
    public function txLease( $recipient, $amount, $options = null );
    public function txLeaseCancel( $leaseId, $options = null );
    public function txAlias( $alias, $options = null );
    public function txMass( $recipients, $amounts, $asset = null, $options = null );
    public function txData( $userData, $options = null );
    public function txSetScript( $script, $options = null );
    public function txSponsorship( $assetId, $minSponsoredAssetFee, $options = null );
    public function txSetAssetScript( $assetId, $script, $options = null );

    public function txBody( $tx );
    public function txSign( $tx, $proofIndex = null );
    public function txBroadcast( $tx );

    public function txOrder( $amountAsset, $priceAsset, $isSell, $price, $amount, $expiration, $options = null );
    public function txOrderBroadcast( $tx );
    public function txOrderCancel( $tx );

    public function setNodeAddress( $nodeAddress, $cacheLifetime = 1, $backupAddresses );
    public function getNodeAddress();

    public function fetch( $url, $post = false, $data = null, $log = true );
    public function timestamp( $fromNode = false );
    public function height();
    public function getTransactionById( $id, $unconfirmed = false );
    public function ensure( $tx, $confirmations = 0, $sleep = 1, $lost = 30 );
    public function balance( $address );
    public function compile( $script );
}

class WavesKit implements WavesKitInterface
{
    private $wk = [];

    public function __construct( $chainId = 'W', $logFunction = null )
    {
        $this->wk['chainId'] = $chainId;
        if( isset( $logFunction ) )
            $this->wk['logFunction'] = $logFunction;
    }

    public function getChainId()
    {
        return $this->wk['chainId'];
    }

    public function log( $level, $message )
    {
        if( isset( $this->wk['logFunction'] ) )
        {
            if( is_callable( $this->wk['logFunction'] ) )
                return $this->wk['logFunction']( $level, $message );
            elseif( $this->wk['logFunction'] === false )
                return;
            elseif( is_array( $this->wk['logFunction'] ) && !in_array( $level, $this->wk['logFunction'], true ) )
                return;
        }

        static $tz;

        if( !isset( $tz ) )
        {
            date_default_timezone_set( date_default_timezone_get() );
            $tz = true;
        }

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
        echo $log . $message . PHP_EOL;
    }

    public function base58Encode( $data ){ return ABCode::base58()->encode( $data ); }
    public function base58Decode( $data ){ return ABCode::base58()->decode( $data ); }

    public function sha256( $data ){ return hash( 'sha256', $data, true ); }
    public function sha512( $data ){ return hash( 'sha512', $data, true ); }
    public function secureHash( $data ){ return $this->keccak256( $this->blake2b256( $data ) ); }

    public function keccak256( $data )
    {
        static $keccak;

        if( !isset( $keccak ) )
        {
            require_once __DIR__ . '/../support/Keccak.php';
            $keccak = new \kornrunner\Keccak();
        }

        return $keccak->hash( $data, 256, true );
    }

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

    public function sign( $data, $key = null )
    {
        if( $this->getSodium() )
            return $this->sign_sodium( $data, $key );

        if( isset( $this->wk['rseed'] ) )
        {
            $rseed = $this->wk['rseed'];
            unset( $this->wk['rseed'] );
            return $this->sign_rseed( $data, $rseed, $key );
        }

        return $this->sign_php( $data, $key );
    }
    private function sign_php( $data, $key = null ){ return $this->c25519()->sign( $data, isset( $key ) ? $key : $this->getPrivateKey( true ) ); }
    private function sign_sodium( $data, $key = null ){ return $this->c25519()->sign_sodium( $data, isset( $key ) ? $key : $this->getPrivateKey( true ) ); }
    private function sign_rseed( $data, $rseed, $key = null ){ return $this->c25519()->sign( $data, isset( $key ) ? $key : $this->getPrivateKey( true ), $rseed ); }
    public function verify( $sig, $data, $key = null ){ return $this->c25519()->verify( $sig, $data, isset( $key ) ? $key : $this->getPublicKey( true ) ); }


    private function c25519()
    {
        static $c25519;

        if( !isset( $c25519 ) )
            $c25519 = new Curve25519();

        return $c25519;
    }

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

    public function isAddressValid( $address, $raw = false )
    {
        $data = $raw ? $address : $this->base58Decode( $address );
        if( $data === false || strlen( $data ) !== 26 )
            return false;

        if( $data[0] !== chr( 1 ) || $data[1] !== $this->wk['chainId'] )
            return false;

        $xsum = $this->secureHash( substr( $data, 0, 22 ) );
        if( substr( $xsum, 0, 4 ) !== substr( $data, 22, 4 ) )
            return false;

        return true;
    }

    private function cleanup( $full = true )
    {
        if( $full )
        {
            unset( $this->wk['seed'] );
            unset( $this->wk['privateKey'] );
            unset( $this->wk['b58_privateKey'] );
        }

        unset( $this->wk['publicKey'] );
        unset( $this->wk['b58_publicKey'] );
        unset( $this->wk['address'] );
        unset( $this->wk['b58_address'] );
    }

    public function setSeed( $seed, $raw = true )
    {
        $this->cleanup();
        $this->getPrivateKey( true, $raw ? $seed : $this->base58Decode( $seed ) );
    }

    public function setPrivateKey( $privateKey, $raw = false )
    {
        $this->cleanup();
        $this->wk['privateKey'] = $raw ? $privateKey : $this->base58Decode( $privateKey );
    }

    public function getPrivateKey( $raw = false, $seed = null )
    {
        if( !isset( $this->wk['privateKey'] ) )
        {
            if( !isset( $seed ) )
                return false;
            $temp = chr( 0 ) . chr( 0 ) . chr( 0 ) . chr( 0 ) . $seed;
            $temp = $this->secureHash( $temp );
            $temp = $this->sha256( $temp );
            $this->wk['privateKey'] = $temp;
        }

        if( $raw )
            return $this->wk['privateKey'];

        if( !isset( $this->wk['b58_privateKey'] ) )
            $this->wk['b58_privateKey'] = $this->base58Encode( $this->wk['privateKey'] );

        return $this->wk['b58_privateKey'];
    }

    public function setPublicKey( $publicKey, $raw = false )
    {
        $this->cleanup();
        $this->wk['publicKey'] = $raw ? $publicKey : $this->base58Decode( $publicKey );
    }

    public function getPublicKey( $raw = false )
    {
        if( !isset( $this->wk['publicKey'] ) )
        {
            $temp = $this->getPrivateKey( true );
            if( $temp === false || strlen( $temp ) !== 32 )
                return false;
            if( $this->getSodium() )
                $temp = $this->c25519()->getSodiumPrivateKeyFromPrivateKey( $temp );
            $temp = $this->c25519()->getPublicKeyFromPrivateKey( $temp, $this->getLastBitFlip() );
            $this->wk['publicKey'] = $temp;
        }

        if( $raw )
            return $this->wk['publicKey'];

        if( !isset( $this->wk['b58_publicKey'] ) )
            $this->wk['b58_publicKey'] = $this->base58Encode( $this->wk['publicKey'] );

        return $this->wk['b58_publicKey'];
    }

    public function setAddress( $address, $raw = false )
    {
        $this->cleanup();
        if( !$this->isAddressValid( $address, $raw ) )
            return;

        $this->wk['address'] = $raw ? $address : $this->base58Decode( $address );
    }

    public function getAddress( $raw = false )
    {
        if( !isset( $this->wk['address'] ) )
        {
            $temp = $this->getPublicKey( true );
            if( $temp === false || strlen( $temp ) !== 32 )
                return false;
            $temp = $this->secureHash( $temp );
            $temp = chr( 1 ) . $this->wk['chainId'] . substr( $temp, 0, 20 );
            $temp .= substr( $this->secureHash( $temp ), 0, 4 );
            $this->wk['address'] = $temp;
        }

        if( $raw )
            return $this->wk['address'];

        if( !isset( $this->wk['b58_address'] ) )
            $this->wk['b58_address'] = $this->base58Encode( $this->wk['address'] );

        return $this->wk['b58_address'];
    }

    public function setSodium( $enabled = true )
    {
        $this->cleanup();
        if( $enabled )
            $this->wk['sodium'] = $enabled;
        else
            unset( $this->wk['sodium'] );
    }

    public function getSodium()
    {
        return isset( $this->wk['sodium'] );
    }

    public function setLastBitFlip( $enabled = true )
    {
        $this->cleanup( false );
        if( $enabled )
            $this->wk['lastbitflip'] = $enabled;
        else
            unset( $this->wk['lastbitflip'] );
    }

    public function getLastBitFlip()
    {
        return isset( $this->wk['lastbitflip'] );
    }

    public function setRSEED( $rseed )
    {
        $this->wk['rseed'] = $rseed;
    }

    public function json_decode( $json )
    {
        return json_decode( $json, true, 512, JSON_BIGINT_AS_STRING );
    }

    private function curl( $address )
    {
        if( false === ( $curl = curl_init() ) )
            return false;

        if( false === curl_setopt_array( $curl, [
            CURLOPT_CONNECTTIMEOUT  => 5,
            CURLOPT_TIMEOUT         => 5,
            CURLOPT_URL             => $address,
            CURLOPT_CONNECT_ONLY    => true,
            CURLOPT_CAINFO          => CaBundle::getBundledCaBundlePath(),
            //CURLOPT_SSL_VERIFYPEER  => false, // not secure
        ] ) )
            return false;

        if( !curl_exec( $curl ) && 0 !== ( $errno = curl_errno( $curl ) ) )
        {
            $this->log( 'e', "curl error $errno: " . curl_error( $curl ) );
            curl_close( $curl );
            return false;
        }

        if( false === curl_setopt_array( $curl, [
            CURLOPT_RETURNTRANSFER  => true,
            CURLOPT_CONNECT_ONLY    => false,
            CURLOPT_FOLLOWLOCATION  => true,
            CURLOPT_MAXREDIRS       => 3,
        ] ) )
        {
            curl_close( $curl );
            return false;
        }

        return $curl;
    }

    public function setNodeAddress( $nodeAddress, $cacheLifetime = 1, $backupNodes = null )
    {
        if( !isset( $this->nodes ) ||
            $this->nodes[0] !== $nodeAddress ||
            $this->cacheLifetime !== $cacheLifetime )
        {
            $this->nodes = [ $nodeAddress ];
            if( isset( $backupNodes ) )
                $this->nodes = array_merge( $this->nodes, $backupNodes );
 
            $this->curls = [];
            $this->cacheLifetime = $cacheLifetime;
            $this->resetNodeCache();
        }
    }

    public function getNodeAddress()
    {
        return isset( $this->nodes[0] ) ? $this->nodes[0] : false;
    }

    public function fetch( $url, $post = false, $data = null, $ignoreCodes = null, $headers = null )
    {
        if( !isset( $this->nodes[0] ) )
        {
            switch( $this->wk['chainId'] )
            {
                case 'W':
                    $this->setNodeAddress( 'https://nodes.wavesplatform.com' );
                    break;
                case 'T':
                    $this->setNodeAddress( 'https://testnode2.wavesnodes.com' );
                    break;
                default:
                    return false;
            }
        }

        $n = count( $this->nodes );
        for( $i = 0; $i < $n; $i++ )
        {
            $curl = isset( $this->curls[$i] ) ? $this->curls[$i] : null;
            $node = $this->nodes[$i];

            if( !is_resource( $curl ) && false === ( $curl = $this->curl( $node ) ) )
                continue;

            if( false !== ( $fetch = $this->fetchCurl( $node, $curl, $url, $post, $data, $ignoreCodes, $headers ) ) )
            {
                $this->curls[$i] = $curl;
                return $fetch;
            }

            if( isset( $ignoreCodes ) )
                return false;
        }

        return false;
    }

    private function fetchCurl( $host, $curl, $url, $post = false, $data = null, $ignoreCodes = null, $headers = null )
    {
        if( !$post && null !== ( $data = $this->getNodeCache( $url ) ) )
            return $data;

        $options = [ CURLOPT_URL => $host . $url, CURLOPT_POST => $post ];

        if( isset( $headers ) )
            $options[CURLOPT_HTTPHEADER] = $headers;

        if( isset( $data ) )
        {
            $options[CURLOPT_POSTFIELDS] = $data;
            if( !isset( $options[CURLOPT_HTTPHEADER] ) )
                $options[CURLOPT_HTTPHEADER] = [ 'Content-Type: application/json', 'Accept: application/json' ];
        }

        if( false === curl_setopt_array( $curl, $options ) )
            return false;

        $data = curl_exec( $curl );
        $code = curl_getinfo( $curl, CURLINFO_HTTP_CODE );

        if( 0 !== ( $errno = curl_errno( $curl ) ) || $code !== 200 || false === $data )
        {
            if( !isset( $ignoreCodes ) || $errno !== 0 || !in_array( $code, $ignoreCodes ) )
            {
                $curl_error = curl_error( $curl );
                if( is_string( $data ) && false !== ( $json = $this->json_decode( $data ) ) && isset( $json['message'] ) )
                {
                    $status = isset( $json['error'] ) ? $json['error'] : ( isset( $json['status'] ) ? $json['status'] : '...' );
                    $this->log( 'e', "$host ($status)" . ( isset( $json['message'] ) ? " ({$json['message']})" : '' ) );
                }
                else
                    $this->log( 'e', "$host (HTTP $code) (cURL $errno" . ( empty( $curl_error ) ? ')' : ":$curl_error)" ) );
            }

            $data = false;
        }

        if( !$post )
            $this->setNodeCache( $url, $data );

        return $data;
    }

    private function setNodeCache( $key, $data )
    {
        if( count( $this->cache ) > 256 )
            $this->resetNodeCache();

        $this->cache[$key] = [ $data, microtime( true ) ];
    }

    private function getNodeCache( $key )
    {
        if( $this->cacheLifetime > 0 && isset( $this->cache[$key] ) )
        {
            if( microtime( true ) - $this->cache[$key][1] < $this->cacheLifetime )
                return $this->cache[$key][0];

            unset( $this->cache[$key] );
        }

        return null;
    }

    private function resetNodeCache()
    {
        $this->cache = [];
    }

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

        list( $usec, $sec ) = explode( " ", microtime() );
        return (int)(( $sec + $usec ) * 1000 );
    }

    public function height()
    {
        if( false === ( $json = $this->fetch( '/blocks/height' ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        if( !isset( $json['height'] ) )
            return false;

        return $json['height'];
    }

    public function getBlockAt( $height, $headers = false )
    {
        $headers = $headers ? '/headers' : '';
        if( false === ( $json = $this->fetch( "/blocks$headers/at/$height" ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        return $json;
    }

    public function compile( $script )
    {
        if( false === ( $json = $this->fetch( '/utils/script/compile', true, $script ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        if( !isset( $json['script'] ) )
            return false;

        return $json;
    }

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

    public function txOrderBroadcast( $tx )
    {
        if( false === ( $json = $this->fetch( '/matcher/orderbook', true, json_encode( $tx ) ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        if( !isset( $json['message']['id'] ) )
            return false;

        return $json['message'];
    }

    public function txOrderCancel( $tx )
    {
        $cancel = [ 'sender' => $tx['senderPublicKey'], 'orderId' => $tx['id'] ];
        $cancelBody = $this->base58Decode( $tx['senderPublicKey'] ) . $this->base58Decode( $tx['id'] );
        $cancel['signature'] = $this->base58Encode( $this->sign( $cancelBody ) );

        $amountAsset = isset( $tx['assetPair']['amountAsset'] ) ? $tx['assetPair']['amountAsset'] : 'WAVES';
        $priceAsset = isset( $tx['assetPair']['priceAsset'] ) ? $tx['assetPair']['priceAsset'] : 'WAVES';

        if( false === ( $json = $this->fetch( "/matcher/orderbook/$amountAsset/$priceAsset/cancel", true, json_encode( $cancel ) ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        if( !isset( $json['orderId'] ) )
            return false;

        return $tx;
    }

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

    public function getTransactionById( $id, $unconfirmed = false )
    {
        $unconfirmed = $unconfirmed ? '/unconfirmed' : '';
        if( false === ( $json = $this->fetch( "/transactions$unconfirmed/info/$id", false, null, [ 404 ] ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        return $json;
    }

    public function getTransactions( $address = null, $limit = 1000, $after = null )
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

    public function ensure( $tx, $confirmations = 0, $sleep = 1, $timeout = 30 )
    {
        if( $tx === false )
            return false;

        $id = $tx['id'];
        $n = 1;
        $n_utx = 0;

        while( false === ( $tx = $this->getTransactionById( $id ) ) )
        {
            if( !$sleep )
                return false;

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

                if( $n_diff > 1 )
                    $this->log( 'i', "($id) still unconfirmed ($n) (timeout $n_diff/$timeout)" );
            }
            else
            {
                if( false === ( $tx = $this->getTransactionById( $id, true ) ) )
                {
                    $this->log( 'i', "($id) not in unconfirmed ($n)" );
                    $n_utx = $n;
                    continue;
                }

                $this->log( 'i', "($id) unconfirmed ($n)" );
            }

            sleep( $sleep );
            $n++;
        }

        if( $sleep )
            $this->log( 's', "($id) confirmed ($n)" );

        if( $confirmations > 0 )
        {
            $n = 0;
            while( $confirmations > ( $c = $this->height() - $tx['height'] ) )
            {
                if( !$sleep )
                    return false;

                $n++;
                $this->log( 'i', "($id) $c/$confirmations confirmations ($n)" );
                sleep( $sleep > 1 ? $sleep : $sleep * $confirmations );
            }

            if( $tx !== $this->getTransactionById( $id ) )
            {
                $this->log( 'w', "($id) change detected" );
                $this->resetNodeCache();
                return $this->ensure( $tx, $confirmations, $sleep, $timeout );
            }

            $this->log( 's', "($id) reached $c confirmations" );
            $tx['confirmations'] = $c;
        }

        return $tx;
    }
    public function balance( $address = null )
    {
        if( false === ( $address = isset( $address ) ? $address : $this->getAddress() ) )
            return false;

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
            $tx['script'] = isset( $options['script'] ) ? $options['script'] : isset( $script ) ? 'base64:' . $script : null;
        return $tx;
    }

    public function txReissue( $asset, $quantity, $reissuable, $options = null )
    {
        $tx = [];
        $tx['type'] = 5;
        $tx['version'] = 2;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->getAddress();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->getPublicKey();
        $tx['fee'] = isset( $options['fee'] ) ? $options['fee'] : 100000000;
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        $tx['assetId'] = $asset;
        $tx['quantity'] = $quantity;
        $tx['reissuable'] = $reissuable;
        return $tx;
    }

    public function txBurn( $quantity, $asset, $options = null )
    {
        $tx = [];
        $tx['type'] = 6;
        $tx['version'] = 2;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->getAddress();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->getPublicKey();
        $tx['fee'] = isset( $options['fee'] ) ? $options['fee'] : 100000;
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        $tx['quantity'] = $quantity;
        $tx['assetId'] = $asset;
        return $tx;
    }

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

    public function txOrder( $amountAsset, $priceAsset, $isSell, $amount, $price, $expiration = 30 * 24 * 60 * 60 * 1000, $options = null )
    {
        $tx = [];
        $tx['version'] = 2;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->getAddress();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->getPublicKey();
        $tx['matcherPublicKey'] = isset( $options['matcherPublicKey'] ) ? $options['matcherPublicKey'] : '7kPFrHDiGw1rCm7LPszuECwWYL3dMf6iMifLRDJQZMzy';
        $tx['assetPair'] = [
            'amountAsset' => $amountAsset,
            'priceAsset' => $priceAsset ];
        $tx['orderType'] = $isSell ? 'sell' : 'buy';
        $tx['amount'] = $amount;
        $tx['price'] = $price;
        $tx['matcherFee'] = isset( $options['matcherFee'] ) ? $options['matcherFee'] : 300000;
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        $tx['expiration'] = $tx['timestamp'] + $expiration;
        return $tx;
    }

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

    public function txSetScript( $script, $options = null )
    {
        if( isset( $script ) && substr( $script, 0, 7 ) === 'base64:' )
            $script = substr( $script, 7 );

        $tx = [];
        $tx['type'] = 13;
        $tx['version'] = 1;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->getAddress();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->getPublicKey();
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        $tx['script'] = isset( $options['script'] ) ? $options['script'] : isset( $script ) ? 'base64:' . $script : null;
        $tx['fee'] = isset( $options['fee'] ) ? $options['fee'] : 1000000;
        return $tx;
    }

    public function txSponsorship( $assetId, $minSponsoredAssetFee, $options = null )
    {
        $tx = [];
        $tx['type'] = 14;
        $tx['version'] = 1;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->getAddress();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->getPublicKey();
        $tx['assetId'] = $assetId;
        $tx['minSponsoredAssetFee'] = $minSponsoredAssetFee;
        $tx['fee'] = isset( $options['fee'] ) ? $options['fee'] : 100000000;
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        return $tx;
    }

    public function txSetAssetScript( $assetId, $script, $options = null )
    {
        if( isset( $script ) && substr( $script, 0, 7 ) === 'base64:' )
            $script = substr( $script, 7 );

        $tx = [];
        $tx['type'] = 15;
        $tx['version'] = 1;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->getAddress();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->getPublicKey();
        $tx['assetId'] = $assetId;
        $tx['script'] = isset( $options['script'] ) ? $options['script'] : isset( $script ) ? 'base64:' . $script : null;
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        $tx['fee'] = isset( $options['fee'] ) ? $options['fee'] : 100000000;
        $tx['chainId'] = ord( $this->getChainId() );
        return $tx;
    }

    private function userDataToTxData( $userData )
    {
        $data = [];
        foreach( $userData as $key => $value )
            $data[] = [ 'key' => $key, 'type' => gettype( $value ), 'value' => $value ];
        return $data;
    }

    public function base64ToBase64Tx( $base64 )
    {
        return 'base64:' . $base64;
    }

    public function base64TxToBase64( $base64 )
    {
        return substr( $base64, 7 );
    }

    public function binToBase64Tx( $bin )
    {
        return $this->base64ToBase64Tx( base64_encode( $bin ) );
    }

    public function Base64TxToBin( $base64 )
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
                $value = $this->Base64TxToBin( $value );
                return $body . chr( 2 ) . pack( 'n', strlen( $value ) ) . $value;
            case 'string':
                return $body . chr( 3 ) . pack( 'n', strlen( $value ) ) . $value;
        }
    }

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

    public function getData( $key, $justValue = true )
    {
        if( false === ( $json = $this->fetch( '/addresses/data/' . $this->getAddress() . "/$key", false, null, [ 404 ] ) ) )
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

    public function txBody( $tx )
    {
        $body = '';

        if( isset( $tx['orderType'] ) )
        {
            $body .= chr( 2 );
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
                $body .= pack( 'J', $tx['quantity'] );
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

            default:
                return false;
        }

        return $body;
    }

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

    public function setCryptash( $secret, $iv = 4, $mac = 4, $hash = 'sha256' )
    {
        $this->wk['cryptash'] = new Cryptash( $secret, $iv, $mac, $hash );
    }

    public function encryptash( $data )
    {
        if( !isset( $this->wk['cryptash'] ) )
            return false;

        return $this->wk['cryptash']->encryptash( $data );
    }

    public function decryptash( $data )
    {
        if( !isset( $this->wk['cryptash'] ) )
            return false;

        return $this->wk['cryptash']->decryptash( $data );
    }

    private function getPairsDatabase()
    {
        if( isset( $this->wk['pairs'] ) )
            return $this->wk['pairs'];
        return false;
    }

    public function setPairsDatabase( $path )
    {
        $this->wk['pairs']['transactions'] = new Pairs( $path, 'savedTransactions', true, 'TEXT UNIQUE|INTEGER|0|0' );
        $this->wk['pairs']['signatures'] = new Pairs( $this->wk['pairs']['transactions']->db(), 'savedSignatures', true, 'INTEGER PRIMARY KEY|TEXT|0|0' );
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
                    elseif( ++$stableConfirmations >= $confirmations )
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

    public function getNewTransaction( $lastTransaction )
    {
        if( false === ( $transaction = $this->getTransactions( null, 1 ) ) )
            return false;

        $transaction = $transaction[0];
        if( $lastTransaction['id'] !== $transaction['id'] || $lastTransaction['height'] !== $transaction['height'] )
            return $transaction;

        return false;
    }

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
                $this->log( 'i', 'save new transactions (' . count( $newTransactions ) . ')' );
                $pairs['transactions']->begin();
                foreach( $newTransactions as $tx )
                    $pairs['transactions']->setKeyValue( $tx['id'], $tx['height'] );
                foreach( $newSignatures as $height => $signature )
                    $pairs['signatures']->setKeyValue( $height, $signature );
                $pairs['transactions']->commit();
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
