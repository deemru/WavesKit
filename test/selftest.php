<?php

require __DIR__ . '/../vendor/autoload.php';
use deemru\WavesKit;

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
    private $failed = 0;
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
        $this->depth--;
        $ms = $this->ms( $this->start[$this->depth] );
        echo ( $cond ? 'SUCCESS: ' : '  ERROR: ' ) . "{$this->info[$this->depth]} ($ms ms)\n";
        $cond ? $this->successful++ : $this->failed++;
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

echo "   TEST: WavesKit\n";
$t = new tester( $wk );

// https://docs.wavesplatform.com/en/technical-details/cryptographic-practical-details.html

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
    $t->test( $wk->getPrivateKey() === '49mgaSSVQw6tDoZrHSr9rFySgHHXwgQbCRwFssboVLWX' );
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

$t->finish();