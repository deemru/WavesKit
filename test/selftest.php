<?php

require __DIR__ . '/../vendor/autoload.php';
use deemru\WavesKit;

use function deemru\curve25519\rnd;

$wk = new WavesKit();

function a2b( $a )
{
    $b = '';
    foreach( $a as $c )
        $b .= chr( $c );

    return $b;
}

function ms( $ms )
{
    if( $ms > 100 )
        return round( $ms );
    else if( $ms > 10 )
        return sprintf( '%.01f', $ms );
    return sprintf( '%.02f', $ms );
}

class tester
{
    private $successful = 0;
    public $failed = 0;
    private $depth = 0;
    private $info = [];
    private $start = [];

    public function pretest( $info )
    {
        $this->info[$this->depth] = $info;
        $this->start[$this->depth] = microtime( true );
        if( !isset( $this->init ) )
            $this->init = $this->start[$this->depth];
        $this->depth++;
    }

    private function ms( $start )
    {
        $ms = ( microtime( true ) - $start ) * 1000;
        $ms = $ms > 100 ? round( $ms ) : $ms;
        $ms = sprintf( $ms > 10 ? ( $ms > 100 ? '%.00f' : '%.01f' ) : '%.02f', $ms );
        return $ms;
    }

    public function test( $cond )
    {
        global $wk;
        $this->depth--;
        $ms = $this->ms( $this->start[$this->depth] );
        $wk->log( $cond ? 's' : 'e', "{$this->info[$this->depth]} ($ms ms)" );
        $cond ? $this->successful++ : $this->failed++;
        return $cond;
    }

    public function finish()
    {
        $total = $this->successful + $this->failed;
        $ms = $this->ms( $this->init );
        echo "  TOTAL: {$this->successful}/$total ($ms ms)\n";
        sleep( 3 );

        if( $this->failed > 0 )
            exit( 1 );
    }
}

echo '   TEST: WavesKit @ PHP ' . PHP_VERSION . PHP_EOL;
$t = new tester();

// https://docs.wavesplatform.com/en/waves-environment/waves-protocol/cryptographic-practical-details.html
$wk->log( 'i', 'cryptographic-practical-details' );

$t->pretest( 'base58Decode' );
{
    $t->test( $wk->base58Decode( 'teststring' ) === a2b( [ 5, 83, 9, -20, 82, -65, 120, -11 ] ) );
}

$seed = 'manage manual recall harvest series desert melt police rose hollow moral pledge kitten position add';

$t->pretest( 'base58Encode' );
{
    $t->test( $wk->base58Encode( $seed ) === 'xrv7ffrv2A9g5pKSxt7gHGrPYJgRnsEMDyc4G7srbia6PhXYLDKVsDxnqsEqhAVbbko7N1tDyaSrWCZBoMyvdwaFNjWNPjKdcoZTKbKr2Vw9vu53Uf4dYpyWCyvfPbRskHfgt9q' );
}

$t->pretest( 'getPrivateKey' );
{
    $wk->setSeed( $seed );
    $t->test( $wk->getPrivateKey( false ) === '49mgaSSVQw6tDoZrHSr9rFySgHHXwgQbCRwFssboVLWX' );
}

$t->pretest( 'getPublicKey' );
{
    $t->test( $wk->getPublicKey() === 'HBqhfdFASRQ5eBBpu2y6c6KKi1az6bMx8v1JxX4iW1Q8' );
}

$t->pretest( 'getAddress' );
{
    $address_saved = $wk->getAddress();
    $t->test( $address_saved === '3PPbMwqLtwBGcJrTA5whqJfY95GqnNnFMDX' );
}

$t->pretest( 'randomSeed' );
{
    $wk->setSeed( $wk->randomSeed() );
    $address = $wk->getAddress();
    $wk->setSeed( $wk->randomSeed() );
    $t->test( $wk->getAddress() !== $address );
}

// sig/verify

$t->pretest( 'getPublicKey' );
{
    $wk = new WavesKit( 'T' );
    $wk->setPrivateKey( '7VLYNhmuvAo5Us4mNGxWpzhMSdSSdEbEPFUDKSnA6eBv' );
    $t->test( $wk->getPublicKey() === 'EENPV1mRhUD9gSKbcWt84cqnfSGQP5LkCu5gMBfAanYH' );
}

$t->pretest( 'getAddress' );
{
    $t->test( $wk->getAddress() === '3N9Q2sdkkhAnbR4XCveuRaSMLiVtvebZ3wp' );
}

$t->pretest( 'verify (known)' );
{
    $msg = $wk->base58Decode( 'Ht7FtLJBrnukwWtywum4o1PbQSNyDWMgb4nXR5ZkV78krj9qVt17jz74XYSrKSTQe6wXuPdt3aCvmnF5hfjhnd1gyij36hN1zSDaiDg3TFi7c7RbXTHDDUbRgGajXci8PJB3iJM1tZvh8AL5wD4o4DCo1VJoKk2PUWX3cUydB7brxWGUxC6mPxKMdXefXwHeB4khwugbvcsPgk8F6YB' );
    $sig = $wk->base58Decode( '2mQvQFLQYJBe9ezj7YnAQFq7k9MxZstkrbcSKpLzv7vTxUfnbvWMUyyhJAc1u3vhkLqzQphKDecHcutUrhrHt22D' );
    $t->test( $wk->verify( $sig, $msg ) === true );
}

for( $i = 1; $i <= 3; $i++ )
{
    $t->pretest( "sign/verify #$i" );
    {
        $sig = $wk->sign( $msg );
        $t->test( $wk->verify( $sig, $msg ) === true );
    }
}

$t->pretest( "verify (lastbitflip)" );
{
    $addr_saved = $wk->getAddress();
    $wk->setLastBitFlip();
    $addr = $wk->getAddress();
    $t->test( $addr !== $addr_saved && $wk->verify( $sig, $msg ) === true );
    $wk->setLastBitFlip( false );
}

$t->pretest( 'setSodium' );
{
    $wk->setSodium();
    $wk->setPrivateKey( '7VLYNhmuvAo5Us4mNGxWpzhMSdSSdEbEPFUDKSnA6eBv' );
    $t->test( $wk->getPublicKey() !== 'EENPV1mRhUD9gSKbcWt84cqnfSGQP5LkCu5gMBfAanYH' );
}

for( $i = 1; $i <= 3; $i++ )
{
    $t->pretest( "sign/verify (sodium) #$i" );
    {
        $sig = $wk->sign( $msg );
        $t->test( $wk->verify( $sig, $msg ) === true );
    }
}

$t->pretest( "verify (lastbitflip)" );
{
    $addr_saved = $wk->getAddress();
    $wk->setLastBitFlip();
    $addr = $wk->getAddress();
    $t->test( $addr !== $addr_saved && $wk->verify( $sig, $msg ) === true );
    $wk->setLastBitFlip( false );
}

$t->pretest( 'rseed' );
{
    $wk->setSodium( false );
    $wk->setPrivateKey( '7VLYNhmuvAo5Us4mNGxWpzhMSdSSdEbEPFUDKSnA6eBv' );
    $t->test( $wk->getPublicKey() === 'EENPV1mRhUD9gSKbcWt84cqnfSGQP5LkCu5gMBfAanYH' );
}

$t->pretest( "sign/verify (rseed) without knowing" );
{
    $wk->setRSEED( '123' );
    $t->test( false === $wk->sign( $msg ) );
}

define( 'IREALLYKNOWWHAT_RSEED_MEANS', null );

for( $i = 1; $i <= 2; $i++ )
{
    $t->pretest( "sign/verify (rseed) #$i" );
    {
        $wk->setRSEED( '123' );
        $sig = $wk->sign( $msg );
        if( $i === 1 )
        {
            $t->test( $wk->verify( $sig, $msg ) === true );
            $sig_saved = $sig;
            continue;
        }
        $t->test( $sig === $sig_saved );
    }
}

$t->pretest( "verify (lastbitflip)" );
{
    $addr_saved = $wk->getAddress();
    $wk->setLastBitFlip();
    $addr = $wk->getAddress();
    $t->test( $addr !== $addr_saved && $wk->verify( $sig, $msg ) === true );
    $wk->setLastBitFlip( false );
}

$t->pretest( "base58Decode (cache much faster)" );
{
    $data = [];
    for( $i = 0; $i < 64; ++$i )
        $data[] = $wk->base58Encode( rnd( 26 + $i ) );

    $tt = microtime( true );
    for( $i = 0; $i < 128; ++$i )
        foreach( $data as $value )
            $wk->base58Decode( $value, false );
    $tt_cache_false = microtime( true ) - $tt;

    $tt = microtime( true );
    for( $i = 0; $i < 128; ++$i )
        foreach( $data as $value )
            $wk->base58Decode( $value, true );
    $tt_cache_true = microtime( true ) - $tt;

    $t->test( $tt_cache_true * 32 < $tt_cache_false  );
}

$wk->log( 'i', 'check transactions' );

$t->pretest( "64-bit required for transactions" );
{
    if( !$t->test( PHP_INT_SIZE >= 8 ) )
    {
        $t->finish();
        exit( 1 );
    }
}

if( file_exists( __DIR__ . '/private.php' ) )
    require_once __DIR__ . '/private.php';

$wavesAmount = 1000000000;
$confirmations = 0;
$sleep = 1;
$nodes =
[
    'https://example.com',
    'https://testnode1.wavesnodes.com',
    'https://testnode2.wavesnodes.com',
    'https://testnode3.wavesnodes.com',
    'https://testnode4.wavesnodes.com',
];

$t->pretest( 'private faucet ready' );
{
    $wkFaucet = new WavesKit( 'T' );
    $wkFaucet->height();
    $wkFaucet->setNodeAddress( $nodes[0], 1, array_slice( $nodes, 1 ) );
    $wkFaucet->logFunction = [ 'd', 'w', 'i', 's' ];
    $wkFaucet->setBestNode();
    $wkFaucet->log( 'i', 'best node = ' . $wkFaucet->getNodeAddress() );
    define( 'WK_CURL_SETBESTONERROR', true );
    $wkFaucet->setNodeAddress( $nodes, 0 );
    $wkFaucet->height();
    $wkFaucet->height();
    unset( $wkFaucet->logFunction );
    $wkFaucet->height();
    $wkFaucet->setNodeAddress( $wkFaucet->nodes );
    $wkFaucet->setSeed( getenv( 'WAVESKIT_SEED' ) );
    $address = $wkFaucet->getAddress();
    $balance = $wkFaucet->balance();
    $balance = $balance[0]['balance'];
    $t->test( $balance >= 10000000000 );
    $wkFaucet->log( 'i', "faucet = $address (" . number_format( $balance / 100000000, 8, '.', '' ) . ' Waves)' );
}

if( $t->failed > 0 )
    $t->finish();

$t->pretest( 'new tester' );
{
    $wk = new WavesKit( $wkFaucet->getChainId() );
    if( !empty( getenv( 'WAVESKIT_NODES' ) ) )
        $wk->setNodeAddress( getenv( 'WAVESKIT_NODES' ) );
    $wk->setSeed( $wk->randomSeed() );
    $address = $wk->getAddress();
    $balance = $wk->balance();
    $balance = $balance[0]['balance'];
    $tx = $wk->getTransactions();

    $t->test( $balance === 0 && $tx === false );
    $wk->log( 'i', "tester = $address" );
}

if( $balance < $wavesAmount )
{
    $wavesAmountPrint = number_format( $wavesAmount / 100000000, 8, '.', '' ) . ' Waves';
    $t->pretest( "txTransfer faucet => tester ($wavesAmountPrint)" );
    {
        $tx = $wkFaucet->txTransfer( $wk->getAddress(), $wavesAmount );
        $tx = $wkFaucet->txSign( $tx );
        $tx = $wkFaucet->txBroadcast( $tx );
        $tx = $wkFaucet->ensure( $tx, $confirmations, $sleep );

        $balance = $wk->balance();
        $balance = $balance[0]['balance'];
        $t->test( $balance === $wavesAmount );
    }
}

$tokenQuantity = mt_rand( 1000000, 9999999 );
$tokenDecimals = mt_rand( 0, 8 );
$tokenName = "wk-$tokenQuantity-$tokenDecimals";
$t->pretest( "txIssue ($tokenName)" );
{
    $tokenDescription = 'Asset test @ ' . date( 'Y.m.d H:i:s' );

    $tx = $wk->txIssue( $tokenName, $tokenDescription, $tokenQuantity, $tokenDecimals, true );
    $tx = $wk->txSign( $tx );
    $tx = $wk->txBroadcast( $tx );
    $tx = $wk->ensure( $tx, $confirmations, $sleep );

    $tokenId = $tx['id'];
    $balance = $wk->balance();
    $balance = $balance[$tokenId]['balance'];

    $t->test( $balance === $tokenQuantity );
}

$t->pretest( "txReissue (x2)" );
{
    $tx = $wk->txReissue( $tokenId, $tokenQuantity, false );
    $tx = $wk->txSign( $tx );
    $tx = $wk->txBroadcast( $tx );
    $tx = $wk->ensure( $tx, $confirmations, $sleep );

    $balance = $wk->balance();
    $balance = $balance[$tokenId]['balance'];

    $t->test( $balance === $tokenQuantity * 2 );
}

$t->pretest( "txReissue (reissue = false)" );
{
    $tx = $wk->txReissue( $tokenId, $tokenQuantity, false );
    $tx = $wk->txSign( $tx );
    $wk->logFunction = [ 'd', 'w', 'i', 's' ];
    $tx = $wk->txBroadcast( $tx );
    unset( $wk->logFunction );

    $t->test( $tx === false );
}

$t->pretest( "txBurn (x/2)" );
{
    $tx = $wk->txBurn( $tokenId, $tokenQuantity );
    $tx = $wk->txSign( $tx );
    $tx = $wk->txBroadcast( $tx );
    $tx = $wk->ensure( $tx, $confirmations, $sleep );

    $balance = $wk->balance();
    $balance = $balance[$tokenId]['balance'];

    $t->test( $balance === $tokenQuantity );
}

$t->pretest( "txSponsorship" );
{
    $tx = $wk->txSponsorship( $tokenId, 1 );
    $tx = $wk->txSign( $tx );
    $tx = $wk->txBroadcast( $tx );
    $tx = $wk->ensure( $tx, $confirmations, $sleep );

    $balance = $wk->balance();
    $balance = $balance[0]['balance'];

    $options = [ 'fee' => 1, 'feeAssetId' => $tokenId ];
    $tx = $wk->txTransfer( $wkFaucet->getAddress(), 1, $tokenId, $options );
    $tx = $wk->txSign( $tx );
    $tx = $wk->txBroadcast( $tx );
    $tx = $wk->ensure( $tx, $confirmations, $sleep );

    $balanceNew = $wk->balance();
    $balanceNew = $balanceNew[0]['balance'];

    $t->test( $tx !== false && $balance - $balanceNew === 100000 );
}

$t->pretest( "txLease + txLeaseCancel" );
{
    $balance = $wk->balance();
    $balance = $balance[0]['balance'];
    $leaseAmount = (int)( $balance / 2 );

    $tx = $wk->txLease( $wkFaucet->getAddress(), $leaseAmount );
    $tx = $wk->txSign( $tx );
    $tx = $wk->txBroadcast( $tx );
    $tx = $wk->ensure( $tx, $confirmations, $sleep );

    $leaseId = $tx['id'];

    $tx = $wk->txTransfer( $wkFaucet->getAddress(), $leaseAmount );
    $tx = $wk->txSign( $tx );
    $wk->logFunction = [ 'd', 'w', 'i', 's' ];
    $tx = $wk->txBroadcast( $tx );
    unset( $wk->logFunction );

    $leasedTransfer = $tx;

    $tx = $wk->txLeaseCancel( $leaseId );
    $tx = $wk->txSign( $tx );
    $tx = $wk->txBroadcast( $tx );
    $tx = $wk->ensure( $tx, 0, $sleep );

    $t->test( $tx !== false && $leasedTransfer === false );
}

$alias = 'waveskit_' . substr( sha1( $wk->getAddress() ), 0, 8 );
$t->pretest( "txAlias ($alias)" );
{
    $tx = $wk->txAlias( $alias );
    $tx = $wk->txSign( $tx );
    $tx = $wk->txBroadcast( $tx );
    $tx = $wk->ensure( $tx, $confirmations, $sleep );

    $address = $wk->getAddressByAlias( $alias );

    $t->test( $wk->getAddressByAlias( $alias ) === $wk->getAddress() );
}

$n = mt_rand( 1, 100 );
$t->pretest( "txMass (x$n)" );
{
    $recipients = [];
    $amounts = [];
    $temp = new WavesKit( $wk->getChainId() );
    for( $i = 0; $i < $n; $i++ )
    {
        $temp->setSeed( $temp->randomSeed() );
        $recipients[] = $temp->getAddress();
        $amounts[] = mt_rand( 1, 10000 );
    }

    $tx = $wk->txMass( $recipients, $amounts, $tokenId );
    $tx = $wk->txSign( $tx );
    $tx = $wk->txBroadcast( $tx );
    $tx = $wk->ensure( $tx, $confirmations, $sleep );

    $balancesOK = true;
    for( $i = 0; $i < $n; $i++ )
    {
        for( $j = 0; $j < 3; ++$j )
        {
            if( false !== ( $balance = $wk->balance( $recipients[$i] ) ) &&
                isset( $balance[$tokenId]['balance'] ) )
                break;
            sleep( 2 );
        }
        $balance = $balance[$tokenId]['balance'];
        $balancesOK &= $balance === $amounts[$i];
    }

    $t->test( $balancesOK );
}

$n = mt_rand( 4, 100 );
$t->pretest( "txData (x$n)" );
{
    $data = [];
    for( $i = 0; $i < $n; $i++ )
    {
        if( $i === 0 )
        {
            $integer = mt_rand();
            $data["key_$i"] = $integer;
        }
        else if( $i === 1 )
        {
            $boolean = mt_rand( 0, 1 ) ? true : false;
            $data["key_$i"] = $boolean;
        }
        else if( $i === 2 )
        {
            $binary = $wk->sha256( $wk->randomSeed() );
            $data["key_$i"] = [ $binary ];
        }
        else
        {
            $string = $wk->randomSeed( 1 );
            $data["key_$i"] = $string;
        }
    }

    $tx = $wk->txData( $data );
    $tx = $wk->txSign( $tx );
    $tx = $wk->txBroadcast( $tx );
    $tx = $wk->ensure( $tx, $confirmations, $sleep );

    function getData( $wk, $key )
    {
        for( $i = 0; $i < 3; ++$i )
        {
            if( false !== ( $value = $wk->getData( $key, null, false ) ) )
                return $value['value'];
            sleep( 2 );
        }
        return false;
    }

    $dataOK = true;
    foreach( $data as $key => $value )
    {
        if( is_array( $value ) )
        {
            $value = $value[0];
            $bcValue = $wk->base64TxToBin( getData( $wk, $key ) );
            if( $value !== $bcValue )
            {
                $wk->log( 'e', 'value = ' . bin2hex( $value ) );
                $wk->log( 'e', 'bcValue = ' . bin2hex( $bcValue ) );
                $dataOK = false;
            }
        }
        else
        {
            $bcValue = getData( $wk, $key );
            if( $value !== $bcValue )
            {
                $wk->log( 'e', 'value = ' . $value );
                $wk->log( 'e', 'bcValue = ' . $bcValue );
                $dataOK = false;
            }
        }
    }

    $t->test( $dataOK );
}

$t->pretest( "txAddressScript" );
{
    $publicKey = $wkFaucet->getPublicKey();
    $script = "sigVerify( tx.bodyBytes, tx.proofs[0], base58'$publicKey' )";
    $script = $wk->compile( $script );

    $tx = $wk->txAddressScript( $script['script'] );
    $tx = $wk->txSign( $tx );
    $tx = $wk->txBroadcast( $tx );
    $tx = $wk->ensure( $tx, $confirmations, $sleep );

    $scriptOK = $script['script'] === $wk->getAddressScript()['script'];

    $tx = $wk->txAddressScript( null );
    $tx['fee'] = $wk->calculateFee( $tx );
    $tx = $wkFaucet->txSign( $tx );
    $tx = $wk->txBroadcast( $tx );
    $tx = $wk->ensure( $tx, $confirmations, $sleep );

    $t->test( $scriptOK && $tx !== false );
}

$tokenName = "s$tokenName";
$t->pretest( "txIssue + txAssetScript (s$tokenName)" );
{
    $tokenDescription = 'Smart asset test @ ' . date( 'Y.m.d H:i:s' );

    $script = $wk->compile( 'true' )['script'];
    $tx = $wk->txIssue( $tokenName, $tokenDescription, $tokenQuantity, $tokenDecimals, true, $script );
    $tx = $wk->txSign( $tx );
    $tx = $wk->txBroadcast( $tx );
    $tx = $wk->ensure( $tx, $confirmations, $sleep );

    $tokenId = $tx['id'];
    $balance = $wk->balance();
    $balance = $balance[$tokenId]['balance'];
    $balanceOK = $balance === $tokenQuantity;

    $script = $wk->compile( 'false' )['script'];
    $tx = $wk->txAssetScript( $tokenId, $script );
    $tx = $wk->txSign( $tx );
    $tx = $wk->txBroadcast( $tx );
    $tx = $wk->ensure( $tx, $confirmations, $sleep );

    $tx = $wk->txReissue( $tokenId, $tokenQuantity, false );
    $tx = $wk->txSign( $tx );
    $wk->logFunction = [ 'd', 'w', 'i', 's' ];
    $tx = $wk->txBroadcast( $tx );
    unset( $wk->logFunction );

    $t->test( $balanceOK && $tx === false );
}

$t->pretest( 'txInvokeScript (return Waves)' );
{
    $balance = $wk->balance();
    $balance = $balance[0]['balance'] - 500001;

    // version 1
    $args =
    [
        $wkFaucet->getAddress(),
        $balance - 500000,
        [ $wk->sha256( $wkFaucet->getAddress() ) ],
        true,
    ];
    $payments =
    [
        [
            "amount" => $balance - 500000,
            "assetId" => null,
        ],
    ];

    $tx = $wk->txInvokeScript( '3N7uoMNjqNt1jf9q9f9BSr7ASk1QtzJABEY', 'retransmit', $args, $payments );
    $tx = $wk->txSign( $tx );
    $tx = $wk->txBroadcast( $tx );

    $result = $tx !== false;

    // version 2
    $args =
    [
        $wkFaucet->getAddress(),
        1,
        [ $wk->sha256( $wkFaucet->getAddress() ) ],
        true,
    ];
    $payments =
    [
        [
            "amount" => 1,
            "assetId" => null,
        ],
    ];

    $tx = $wk->txInvokeScript( '3N7uoMNjqNt1jf9q9f9BSr7ASk1QtzJABEY', 'retransmit', $args, $payments );
    $tx['version'] = 2;
    $tx = $wk->txSign( $tx );
    $tx = $wk->txBroadcast( $tx );

    $result &= $tx !== false;

    $t->test( $result );
}

$t->finish();