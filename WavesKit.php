<?php

namespace deemru;

use deemru\ABCode;
use deemru\Curve25519;
use kornrunner\Keccak;
use Composer\CaBundle\CaBundle;

interface WavesKitInterface
{
    public function __construct( $chainId = 'W', $logFunction = null );

    public function base58Encode( $data );
    public function base58Decode( $data );

    public function sha256( $data );
    public function sha512( $data );
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

    //public function txPayment( $options = null );
    //public function txIssue( $options = null );
    public function txTransfer( $recipient, $amount, $asset = null, $options = null );
    //public function txReissue( $options = null );
    //public function txBurn( $options = null );
    //public function txOrder( $options = null );
    //public function txLease( $options = null );
    //public function txLeaseCancel( $options = null );
    //public function txAlias( $options = null );
    public function txMass( $recipients, $amounts, $asset = null, $options = null );
    //public function txData( $options = null );
    //public function txSetScript( $options = null );
    //public function txSponsorship( $options = null );
    //public function txSetAssetScript( $options = null );
    
    public function txBody( $tx );
    public function txSign( $tx, $proofIndex = null );
    public function txBroadcast( $tx );

    public function setNodeAddress( $nodeAddress, $cacheLifetime = 1 );
    public function getNodeAddress();    

    public function fetch( $url, $post = false, $data = null, $log = true );
    public function timestamp( $fromNode = false );
    public function height();
    public function getTransactionById( $id, $unconfirmed = false );
    public function ensure( $tx, $confirmations = 0, $sleep = 1, $lost = 30 );
    public function balance( $address );
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

    public function base58Encode( $data ){ return $this->b58()->encode( $data ); }
    public function base58Decode( $data ){ return $this->b58()->decode( $data ); }

    public function sha256( $data ){ return hash( 'sha256', $data, true ); }
    public function sha512( $data ){ return hash( 'sha512', $data, true ); }
    public function blake2b256( $data ){ return sodium_crypto_generichash( $data ); }
    public function keccak256( $data ){ return $this->k256()->hash( $data, 256, true ); }
    public function secureHash( $data ){ return $this->keccak256( $this->blake2b256( $data ) ); }

    public function sign( $data, $key = null ){ return $this->getSodium() ? $this->signSodium( $data, $key ) : $this->signPHP( $data, $key ); }
    public function signPHP( $data, $key = null ){ return $this->c25519()->sign( $data, isset( $key ) ? $key : $this->getPrivateKey( true ) ); }
    public function signSodium( $data, $key = null ){ return $this->c25519()->sign_sodium( $data, isset( $key ) ? $key : $this->getPrivateKey( true ) ); }
    public function signRSEED( $data, $rseed, $key = null ){ return $this->c25519()->sign( $data, isset( $key ) ? $key : $this->getPrivateKey( true ), $rseed ); }
    public function verify( $sig, $data, $key = null ){ return $this->c25519()->verify( $sig, $data, isset( $key ) ? $key : $this->getPublicKey( true ) ); }

    private function b58()
    {
        static $b58;

        if( !isset( $b58 ) )
            $b58 = new ABCode( '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' );

        return $b58;
    }

    private function k256()
    {
        static $k256;

        if( !isset( $k256 ) )
            $k256 = new Keccak();

        return $k256;
    }

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
            $temp = file_get_contents( __DIR__ . '/support/english.txt' );
            if( $temp === false )
                return false;

            $temp = explode( "\n", $temp );
            if( $temp === false || count( $temp ) < 2048 )
                return false;

            $english = $temp;
        }

        $seed = '';
        $max = count( $english ) - 1;
        for( $i = 0; $i < $words; $i++ )
            $seed .= ( $i ? ' ' : '' ) . $english[random_int( 0, $max )];

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

    private function cleanup()
    {
        unset( $this->wk['seed'] );
        unset( $this->wk['privateKey'] );
        unset( $this->wk['publicKey'] );
        unset( $this->wk['address'] );
        unset( $this->wk['b58_privateKey'] );
        unset( $this->wk['b58_publicKey'] );
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
            $temp = $seed;
            $temp = chr( 0 ) . chr( 0 ) . chr( 0 ) . chr( 0 ) . $temp;
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
            if( isset( $this->wk['sodium'] ) && $this->wk['sodium'] )
                $temp = substr( $this->sha512( $temp ), 0, 32 );
            $temp = sodium_crypto_box_publickey_from_secretkey( $temp );
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

    private function json_decode( $json )
    {
        return json_decode( $json, true, 512, JSON_BIGINT_AS_STRING );
    }

    private function curl()
    {
        static $curl;

        if( !isset( $this->wk['nodeAddress'] ) )
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

        if( !is_resource( $curl ) )
        {
            if( false === ( $temp = curl_init() ) )
                return false;

            if( false === curl_setopt_array( $temp, [
                CURLOPT_CONNECTTIMEOUT  => 5,
                CURLOPT_TIMEOUT         => 15,
                CURLOPT_URL             => $this->wk['nodeAddress'],
                CURLOPT_CONNECT_ONLY    => true,
                CURLOPT_CAINFO          => CaBundle::getBundledCaBundlePath(),
                //CURLOPT_SSL_VERIFYPEER  => false, // not secure
            ] ) )
                return false;

            if( !curl_exec( $temp ) && 0 !== ( $errno = curl_errno( $temp ) ) )
            {
                $this->log( 'e', "curl error $errno: " . curl_error( $temp ) );
                curl_close( $temp );
                return false;
            }

            if( false === curl_setopt_array( $temp, [
                CURLOPT_RETURNTRANSFER  => true,
                CURLOPT_CONNECT_ONLY    => false,
                CURLOPT_FOLLOWLOCATION  => true,
                CURLOPT_MAXREDIRS       => 3,
            ] ) )
            {
                curl_close( $temp );
                return false;
            }

            $curl = $temp;
        }

        return $curl;
    }

    public function setNodeAddress( $nodeAddress, $cacheLifetime = 1 )
    {
        $this->wk['nodeAddress'] = $nodeAddress;
        $this->wk['cacheLifetime'] = $cacheLifetime;
        $this->resetNodeCache();
    }

    public function getNodeAddress()
    {
        return isset( $this->wk['nodeAddress'] ) ? $this->wk['nodeAddress'] : false;
    }

    public function fetch( $url, $post = false, $data = null, $ignoreCodes = null )
    {
        if( false === ( $curl = $this->curl() ) )
            return false;

        if( !$post && null !== ( $data = $this->getNodeCache( $url ) ) )
            return $data;

        $host = $this->wk['nodeAddress'];
        $options = [
            CURLOPT_URL             => $host . $url,
            CURLOPT_POST            => $post,
        ];

        if( isset( $data ) )
        {
            $options[CURLOPT_HTTPHEADER] = [ 'Content-Type: application/json', 'Accept: application/json' ];
            $options[CURLOPT_POSTFIELDS] = $data;
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
                if( is_string( $data ) && false !== ( $json = $this->json_decode( $data ) ) && isset( $json['error'] ) )
                    $this->log( 'e', "$host ({$json['error']})" . ( isset( $json['message'] ) ? " ({$json['message']})" : '' ) );
                else
                    $this->log( 'e', "$host (HTTP $code) (cURL $errno" . ( empty( $curl_error ) ? ')' : ":$curl_error)" ) );
            }

            $data = false;
        }

        if( !$post )
            $this->setNodeCache( $url, $data );

        return $data;
    }

    private function setNodeCache( $newkey, $data )
    {
        $now = microtime( true );
        $cacheLifetime = $this->wk['cacheLifetime'];

        foreach( $this->wk['cache'][1] as $key => $time )
            if( $now - $time > $cacheLifetime )
            {
                unset( $this->wk['cache'][0][$key] );
                unset( $this->wk['cache'][1][$key] );
            }

        $this->wk['cache'][0][$newkey] = $data;
        $this->wk['cache'][1][$newkey] = $now;
    }

    private function getNodeCache( $key )
    {
        $cacheLifetime = $this->wk['cacheLifetime'];
        if( $cacheLifetime > 0 && isset( $this->wk['cache'][0][$key] ) )
        {
            if( microtime( true ) - $this->wk['cache'][1][$key] < $cacheLifetime )
                return $this->wk['cache'][0][$key];

            unset( $this->wk['cache'][0][$key] );
            unset( $this->wk['cache'][1][$key] );
        }

        return null;
    }

    private function resetNodeCache()
    {
        $this->wk['cache'] = [ [], [] ];
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

    public function txBroadcast( $tx )
    {
        if( false === ( $json = $this->fetch( '/transactions/broadcast', true, json_encode( $tx ) ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        if( !isset( $json['id'] ) )
            return false;

        return $json;
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

    public function ensure( $tx, $confirmations = 0, $sleep = 1, $timeout = 30 )
    {
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
                {
                    $counter = $n - $n_utx;
                    $this->log( 'i', "($id) still unconfirmed ($n) (timeout $n_diff/$timeout)" );
                }
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
                return $this->ensure( $tx, $confirmations, $timeout );
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

    public function txTransfer( $recipient, $amount, $asset = null, $options = null )
    {
        if( isset( $asset ) && ( $asset === 0 || ( strlen( $asset ) === 5 && strtoupper( $asset ) === 'WAVES' ) ) )
            unset( $asset );

        $tx = [];
        $tx['version'] = 2;
        $tx['type'] = 4;
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

    public function txBody( $tx )
    {
        $body = '';

        switch( $tx['type'] )
        {
            case 4:
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
            case 11:
                $attachment = isset( $tx['attachment'] ) ? $this->base58Decode( $tx['attachment'] ) : null;
                $n = count( $tx['transfers'] );

                $body .= chr( 11 );
                $body .= chr( 1 );
                $body .= $this->base58Decode( $tx['senderPublicKey'] );
                $body .= isset( $tx['assetId'] ) ? chr( 1 ) . $this->base58Decode( $tx['assetId'] ) : chr( 0 );
                $body .= pack( 'n', $n );
                for( $i = 0; $i < $n; $i++ )
                {
                    $body .= $this->recipientAddressOrAliasBytes( $tx['transfers'][$i]['recipient'] );
                    $body .= pack( 'J', $tx['transfers'][$i]['amount'] );
                }
                $body .= pack( 'J', $tx['timestamp'] );
                $body .= pack( 'J', $tx['fee'] );
                $body .= isset( $attachment ) ? pack( 'n', strlen( $attachment ) ) . $attachment : chr( 0 ) . chr( 0 );
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

    public function setCryptex( $secret, $iv = 4, $mac = 4, $hash = 'sha256' )
    {
        if( !isset( $this->wk['cryptex'] ) )
            require_once __DIR__ . '/third_party/secqru/include/secqru_cryptex.php';

        $this->wk['cryptex'] = new \secqru_cryptex( $secret, $iv, $mac, $hash );
    }

    public function encryptex( $data )
    {
        if( !isset( $this->wk['cryptex'] ) )
            return false;

        return $this->wk['cryptex']->cryptex( $data );
    }

    public function decryptex( $data )
    {
        if( !isset( $this->wk['cryptex'] ) )
            return false;

        return $this->wk['cryptex']->decryptex( $data );
    }
}
