<?php

interface IWavesKit
{
    public function base58_encode( $data );
    public function base58_decode( $data );

    public function sha256( $data );
    public function sha512( $data );
    public function blake2b256( $data );
    public function keccak256( $data );
    public function secureHash( $data );

    public function sign( $msg );
    public function sign_php( $msg );
    public function sign_sodium( $msg );
    public function sign_rseed( $msg, $rseed );
    public function verify( $sign, $msg );

    public function random_seed();
    public function set_seed( $seed );
    public function set_privkey( $privkey );
    public function set_pubkey( $pubkey );
    public function set_address( $address );

    public function get_seed();
    public function get_privkey();
    public function get_pubkey();
    public function get_address();
    public function is_address_valid( $address );

    public function set_sodium();
    public function get_sodium();

    public function transfer_tx( $recipient, $amount, $options );
    public function mass_tx( $recipients, $amounts, $options );
    public function sign_tx( $tx );

    public function set_node( $node );
    public function get_node();

    public function fetch( $url, $method, $data );
    public function timestamp();
    public function height();
    public function broadcast( $tx );
    public function txid( $id );
    public function utxid( $id );
    public function ensure( $tx, $confirmations );
    public function balance( $address );
}

class WavesKit implements IWavesKit
{
    private $wk = [];

    public function __construct( $network = 'W', $logger = null )
    {
        $this->wk['network'] = $network;
        if( isset( $logger ) )
            $this->wk['logger'] = $logger;
    }

    private function logger( $level, $message )
    {
        if( isset( $this->wk['logger'] ) )
        {
            if( is_callable( $this->wk['logger'] ) )
                return $this->wk['logger']( $level, $message );
            elseif( $this->wk['logger'] === false )
                return;
            elseif( is_array( $this->wk['logger'] ) && !in_array( $level, $this->wk['logger'], true ) )
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

    public function base58_encode( $data ){ return $this->b58()->encode( $data ); }
    public function base58_decode( $data ){ return $this->b58()->decode( $data ); }

    public function sha256( $data ){ return hash( 'sha256', $data, true ); }
    public function sha512( $data ){ return hash( 'sha512', $data, true ); }
    public function blake2b256( $data ){ return sodium_crypto_generichash( $data ); }
    public function keccak256( $data ){ return $this->k256()->hash( $data, 256, true ); }
    public function secureHash( $data ){ return $this->keccak256( $this->blake2b256( $data ) ); }

    public function sign( $msg, $key = null ){ return $this->get_sodium() ? $this->sign_sodium( $msg, $key ) : $this->sign_php( $msg, $key ); }
    public function sign_php( $msg, $key = null ){ return $this->c25519()->sign( $msg, isset( $key ) ? $key : $this->get_privkey( true ) ); }
    public function sign_sodium( $msg, $key = null ){ return $this->c25519()->sign_sodium( $msg, isset( $key ) ? $key : $this->get_privkey( true ) ); }
    public function sign_rseed( $msg, $rseed, $key = null ){ return $this->c25519()->sign( $msg, isset( $key ) ? $key : $this->get_privkey( true ), $rseed ); }
    public function verify( $sign, $msg, $key = null ){ return $this->c25519()->verify( $sign, $msg, isset( $key ) ? $key : $this->get_pubkey( true ) ); }

    private function b58()
    {
        static $b58;

        if( !isset( $b58 ) )
        {
            require_once __DIR__ . '/third_party/secqru/include/secqru_abcode.php';
            $b58 = new secqru_abcode( '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' );
        }

        return $b58;
    }

    private function k256()
    {
        static $k256;

        if( !isset( $k256 ) )
        {
            require_once __DIR__ . '/third_party/php-keccak/src/Keccak.php';
            $k256 = new kornrunner\Keccak();
        }

        return $k256;
    }

    private function c25519()
    {
        static $c25519;

        if( !isset( $c25519 ) )
        {
            require_once __DIR__ . '/third_party/curve25519-php/curve25519.php';
            $c25519 = new curve25519\Curve25519();
        }

        return $c25519;
    }

    public function random_seed( $words = 15 )
    {
        static $english;

        if( !isset( $english ) )
        {
            $temp = file_get_contents( __DIR__ . '/third_party/english.txt' );
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

    public function is_address_valid( $address, $raw = false )
    {
        $data = $raw ? $address : $this->base58_decode( $address );
        if( $data === false || strlen( $data ) !== 26 )
            return false;

        if( $data[0] !== chr( 1 ) || $data[1] !== $this->wk['network'] )
            return false;

        $xsum = $this->secureHash( substr( $data, 0, 22 ) );
        if( substr( $xsum, 0, 4 ) !== substr( $data, 22, 4 ) )
            return false;

        return true;
    }

    private function cleanup()
    {
        unset( $this->wk['seed'] );
        unset( $this->wk['privkey'] );
        unset( $this->wk['pubkey'] );
        unset( $this->wk['address'] );
    }

    public function set_seed( $seed, $raw = true )
    {
        $this->cleanup();
        $this->wk['seed'] = $raw ? $seed : $this->base58_decode( $seed );
    }

    public function get_seed( $raw = false )
    {
        if( !isset( $this->wk['seed'] ) )
            return false;

        return $raw ? $this->wk['seed'] : $this->base58_encode( $this->wk['seed'] );
    }

    public function set_privkey( $privkey, $raw = false )
    {
        $this->cleanup();
        $this->wk['privkey'] = $raw ? $privkey : $this->base58_decode( $privkey );
    }

    public function get_privkey( $raw = false )
    {
        if( !isset( $this->wk['privkey'] ) )
        {
            $temp = $this->get_seed( true );
            if( $temp === false )
                return false;
            $temp = chr( 0 ) . chr( 0 ) . chr( 0 ) . chr( 0 ) . $temp;
            $temp = $this->secureHash( $temp );
            $temp = $this->sha256( $temp );
            $this->wk['privkey'] = $temp;
        }

        return $raw ? $this->wk['privkey'] : $this->base58_encode( $this->wk['privkey'] );
    }

    public function set_pubkey( $pubkey, $raw = false )
    {
        $this->cleanup();
        $this->wk['pubkey'] = $raw ? $pubkey : $this->base58_decode( $pubkey );
    }

    public function get_pubkey( $raw = false )
    {
        if( !isset( $this->wk['pubkey'] ) )
        {
            $temp = $this->get_privkey( true );
            if( $temp === false || strlen( $temp ) !== 32 )
                return false;
            if( isset( $this->wk['sodium'] ) && $this->wk['sodium'] )
                $temp = substr( $this->sha512( $temp ), 0, 32 );
            $temp = sodium_crypto_box_publickey_from_secretkey( $temp );
            $this->wk['pubkey'] = $temp;
        }

        return $raw ? $this->wk['pubkey'] : $this->base58_encode( $this->wk['pubkey'] );
    }

    public function set_address( $address, $raw = false )
    {
        $this->cleanup();
        if( !$this->is_address_valid( $address, $raw ) )
            return;

        $this->wk['address'] = $raw ? $address : $this->base58_decode( $address );
    }

    public function get_address( $raw = false )
    {
        if( !isset( $this->wk['address'] ) )
        {
            $temp = $this->get_pubkey( true );
            if( $temp === false || strlen( $temp ) !== 32 )
                return false;
            $temp = $this->secureHash( $temp );
            $temp = chr( 1 ) . $this->wk['network'] . substr( $temp, 0, 20 );
            $temp .= substr( $this->secureHash( $temp ), 0, 4 );
            $this->wk['address'] = $temp;
        }

        return $raw ? $this->wk['address'] : $this->base58_encode( $this->wk['address'] );
    }

    public function set_sodium( $true = true )
    {
        $this->cleanup();
        $this->wk['sodium'] = $true;
    }

    public function get_sodium()
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

        if( !isset( $this->wk['node'] ) )
        {
            switch( $this->wk['network'] )
            {
                case 'W':
                    $this->set_node( 'https://nodes.wavesplatform.com' );
                    break;
                case 'T':
                    $this->set_node( 'https://testnode2.wavesnodes.com' );
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
                CURLOPT_URL             => $this->wk['node'],
                CURLOPT_CONNECT_ONLY    => true,
                CURLOPT_CAINFO          => __DIR__ . '/third_party/ca-bundle/res/cacert.pem',
                //CURLOPT_SSL_VERIFYPEER  => false, // not secure
            ] ) )
                return false;

            if( !curl_exec( $temp ) && 0 !== ( $errno = curl_errno( $temp ) ) )
            {
                $this->logger( 'e', "curl error $errno: " . curl_error( $temp ) );
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

    public function set_node( $node, $cachetime = 1 )
    {
        $this->wk['node'] = $node;
        $this->wk['cachetime'] = $cachetime;
        $this->reset_cache();
    }

    private function reset_cache()
    {
        $this->wk['cache'] = [ [], [] ];
    }

    public function get_node(){ return isset( $this->wk['node'] ) ? $this->wk['node'] : false; }

    public function fetch( $url, $post = false, $data = null, $log = true )
    {
        if( false === ( $curl = $this->curl() ) )
            return false;

        if( !$post && null !== ( $data = $this->get_cache_data( $url ) ) )
            return $data;

        $host = $this->wk['node'];
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
            $curl_error = curl_error( $curl );
            if( $log )
            {
                if( is_string( $data ) && false !== ( $json = $this->json_decode( $data ) ) && isset( $json['error'] ) )
                    $this->logger( 'e', "$host ({$json['error']})" . ( isset( $json['message'] ) ? " ({$json['message']})" : '' ) );
                else
                    $this->logger( 'e', "$host (HTTP $code) (cURL $errno" . ( empty( $curl_error ) ? ')' : ":$curl_error)" ) );
            }

            $data = false;
        }

        if( !$post )
            $this->set_cache_data( $url, $data );

        return $data;
    }

    private function set_cache_data( $newkey, $data )
    {
        $now = microtime( true );
        $cachetime = $this->wk['cachetime'];

        foreach( $this->wk['cache'][1] as $key => $time )
            if( $now - $time > $cachetime )
            {
                unset( $this->wk['cache'][0][$key] );
                unset( $this->wk['cache'][1][$key] );
            }

        $this->wk['cache'][0][$newkey] = $data;
        $this->wk['cache'][1][$newkey] = $now;
    }

    private function get_cache_data( $key )
    {
        $cachetime = $this->wk['cachetime'];
        if( $cachetime > 0 && isset( $this->wk['cache'][0][$key] ) )
        {
            if( microtime( true ) - $this->wk['cache'][1][$key] < $cachetime )
                return $this->wk['cache'][0][$key];

            unset( $this->wk['cache'][0][$key] );
            unset( $this->wk['cache'][1][$key] );
        }

        return null;
    }

    public function timestamp( $node = false )
    {
        if( $node )
        {
            if( false === ( $json = $this->fetch( '/utils/time' ) ) )
                return false;

            if( false === ( $json = $this->json_decode( $json ) ) )
                return false;

            if( !isset( $json['NTP'] ) )
                return false;

            return $json['NTP'];
        }

        static $last = 0;
        list( $usec, $sec ) = explode( " ", microtime() );
        $timestamp = (int)(( $sec + $usec ) * 1000 );
        if( $last === $timestamp )
            exit;
        $last = $timestamp;
        return $timestamp;
    }

    public function height( $node = false )
    {
        if( false === ( $json = $this->fetch( '/blocks/height' ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        if( !isset( $json['height'] ) )
            return false;

        return $json['height'];
    }

    public function broadcast( $tx )
    {
        if( false === ( $json = $this->fetch( '/transactions/broadcast', true, json_encode( $tx ) ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        if( !isset( $json['id'] ) )
            return false;

        return $json;
    }

    public function txid( $id )
    {
        if( false === ( $json = $this->fetch( "/transactions/info/$id", false, null, false ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        return $json;
    }

    public function utxid( $id )
    {
        if( false === ( $json = $this->fetch( "/transactions/unconfirmed/info/$id", false, null, false ) ) )
            return false;

        if( false === ( $json = $this->json_decode( $json ) ) )
            return false;

        return $json;
    }

    public function ensure( $tx, $confirmations = 0, $sleep = 1, $timeout = 30 )
    {
        $id = $tx['id'];
        $n = 0;
        $n_utx = 0;

        while( false === ( $tx = $this->txid( $id ) ) )
        {
            if( !$sleep )
                return false;

            $n++;

            if( $n_utx && $n - $n_utx > $timeout )
            {
                $this->logger( 'e', "($id) lost" );
                return false;
            }

            if( !$n_utx && false === ( $tx = $this->utxid( $id ) ) )
            {
                $this->logger( 'i', "($id) not in unconfirmed #$n" );
                $n_utx = $n;
                continue;
            }

            $this->logger( 'i', "($id) unconfirmed #$n" );
            sleep( $sleep );
        }

        $this->logger( 's', "($id) confirmed" );

        if( $confirmations > 0 )
        {
            $n = 0;
            while( $confirmations > ( $c = $this->height() - $tx['height'] ) )
            {
                if( !$sleep )
                    return false;

                $n++;
                $this->logger( 'i', "($id) $c/$confirmations confirmations #$n" );
                sleep( $sleep > 1 ? $sleep : $sleep * $confirmations );
            }

            if( $tx !== $this->txid( $id ) )
            {
                $this->logger( 'w', "($id) change detected" );
                $this->reset_cache();
                return $this->ensure( $tx, $confirmations, $timeout );
            }

            $this->logger( 's', "($id) reached $c confirmations" );
            $tx['confirmations'] = $c;
        }

        return $tx;
    }
    public function balance( $address = null )
    {
        if( false === ( $address = isset( $address ) ? $address : $this->get_address() ) )
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

    public function transfer_tx( $recipient, $amount, $options )
    {
        $tx = [];
        $tx['version'] = 2;
        $tx['type'] = 4;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->get_address();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->get_pubkey();
        $tx['recipient'] = $recipient;
        if( isset( $options['assetId'] ) ) $tx['assetId'] = $options['assetId'];
        $tx['amount'] = $amount;
        if( isset( $options['feeAssetId'] ) ) $tx['feeAssetId'] = $options['feeAssetId'];
        $tx['fee'] = isset( $options['fee'] ) ? $options['fee'] : 100000;
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        if( isset( $options['attachment'] ) ) $tx['attachment'] = $options['attachment'];

        return $tx;
    }

    public function mass_tx( $recipients, $amounts, $options )
    {
        $n = count( $recipients );
        if( $n !== count( $amounts ) )
        {
            $this->logger( 'e', 'recipients !== amounts' );
            return false;
        }

        $tx = [];
        $tx['type'] = 11;
        $tx['version'] = 1;
        $tx['sender'] = isset( $options['sender'] ) ? $options['sender'] : $this->get_address();
        $tx['senderPublicKey'] = isset( $options['senderPublicKey'] ) ? $options['senderPublicKey'] : $this->get_pubkey();
        $tx['fee'] = 100000 + $n * 50000 + ( $n % 2 ) * 50000;
        $tx['timestamp'] = isset( $options['timestamp'] ) ? $options['timestamp'] : $this->timestamp();
        if( isset( $options['assetId'] ) ) $tx['assetId'] = $options['assetId'];
        if( isset( $options['attachment'] ) ) $tx['attachment'] = $options['attachment'];

        $tx['transfers'] = [];
        for( $i = 0; $i < $n; $i++ )
            $tx['transfers'][] = [ 'recipient' => $recipients[$i], 'amount' => $amounts[$i] ];

        return $tx;
    }

    public function sign_tx( $tx, $proofnum = null )
    {
        $body = '';

        switch( $tx['type'] )
        {
            case 4:
                $attachment = isset( $tx['attachment'] ) ? $this->base58_decode( $tx['attachment'] ) : null;

                $body .= chr( 4 );
                $body .= chr( 2 );
                $body .= $this->base58_decode( $tx['senderPublicKey'] );
                $body .= isset( $tx['assetId'] ) ? chr( 1 ) . $this->base58_decode( $tx['assetId'] ) : chr( 0 );
                $body .= isset( $tx['feeAssetId'] ) ? chr( 1 ) . $this->base58_decode( $tx['feeAssetId'] ) : chr( 0 );
                $body .= pack( 'J', $tx['timestamp'] );
                $body .= pack( 'J', $tx['amount'] );
                $body .= pack( 'J', $tx['fee'] );
                $body .= $this->base58_decode( $tx['recipient'] );
                $body .= isset( $attachment ) ? pack( 'n', strlen( $attachment ) ) . $attachment : chr( 0 ) . chr( 0 );
                break;
            case 11:
                $attachment = isset( $tx['attachment'] ) ? $this->base58_decode( $tx['attachment'] ) : null;
                $n = count( $tx['transfers'] );

                $body .= chr( 11 );
                $body .= chr( 1 );
                $body .= $this->base58_decode( $tx['senderPublicKey'] );
                $body .= isset( $tx['assetId'] ) ? chr( 1 ) . $this->base58_decode( $tx['assetId'] ) : chr( 0 );
                $body .= pack( 'n', $n );
                for( $i = 0; $i < $n; $i++ )
                {
                    $body .= $this->base58_decode( $tx['transfers'][$i]['recipient'] );
                    $body .= pack( 'J', $tx['transfers'][$i]['amount'] );
                }
                $body .= pack( 'J', $tx['timestamp'] );
                $body .= pack( 'J', $tx['fee'] );
                $body .= isset( $attachment ) ? pack( 'n', strlen( $attachment ) ) . $attachment : chr( 0 ) . chr( 0 );
                break;
            default:
                return false;
        }

        $sig = $this->sign( $body );
        $id = $this->blake2b256( $body );

        if( false === $sig || false === $id )
            return false;

        $tx['id'] = $this->base58_encode( $id );

        $sig = $this->base58_encode( $sig );

        if( !isset( $tx['proofs'] ) )
            $tx['proofs'] = [];

        if( !isset( $proofnum ) )
            $tx['proofs'][] = $sig;
        else
        {
            $tx['proofs'][$proofnum] = $sig;
            ksort( $tx['proofs'] );
        }

        return $tx;
    }
}
