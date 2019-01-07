<?php

require_once __DIR__ .'/../WavesKit.php';
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
    private $init;
    private $info;
    private $line;
    private $start;
    private $successful = 0;
    private $failed = 0;

    public function pretest( $info, $line )
    {
        $this->info = $info;
        $this->line = $line;
        $this->start = microtime( true );
        if( !isset( $this->init ) )
            $this->init = $this->start;
    }

    private function ms( &$start )
    {
        $ms = ( microtime( true ) - $start ) * 1000;
        $ms = $ms > 100 ? round( $ms ) : $ms;
        $ms = sprintf( $ms > 10 ? ( $ms > 100 ? '%.00f' : '%.01f' ) : '%.02f', $ms );
        $start = 0;
        return $ms;
    }

    public function test( $cond )
    {
        $ms = $this->ms( $this->start );
        echo ( $cond ? 'SUCCESS: ' : 'ERROR:   ' ) . "{$this->info} @ {$this->line} ($ms ms)\n";
        $cond ? $this->successful++ : $this->failed++;
    }

    public function finish()
    {
        $total = $this->successful + $this->failed;
        $ms = $this->ms( $this->init );
        echo "TOTAL:   {$this->successful}/$total ($ms ms)\n";
        if( $this->failed > 0 )
            exit( 1 );
    }
}

echo "TEST:    WavesKit\n";
$t = new tester( $wk );

// https://docs.wavesplatform.com/en/technical-details/cryptographic-practical-details.html

$t->pretest( 'base58_decode', __LINE__ );
{
    $t->test( $wk->base58_decode( 'teststring' ) === a2b( [ 5, 83, 9, -20, 82, -65, 120, -11 ] ) );
}

$t->pretest( 'base58_encode', __LINE__ );
{
    $wk->set_seed( 'manage manual recall harvest series desert melt police rose hollow moral pledge kitten position add' );
    $t->test( $wk->get_seed() === 'xrv7ffrv2A9g5pKSxt7gHGrPYJgRnsEMDyc4G7srbia6PhXYLDKVsDxnqsEqhAVbbko7N1tDyaSrWCZBoMyvdwaFNjWNPjKdcoZTKbKr2Vw9vu53Uf4dYpyWCyvfPbRskHfgt9q' );
}

$t->pretest( 'get_privkey', __LINE__ );
{
    $t->test( $wk->get_privkey() === '49mgaSSVQw6tDoZrHSr9rFySgHHXwgQbCRwFssboVLWX' );
}

$t->pretest( 'get_pubkey', __LINE__ );
{
    $t->test( $wk->get_pubkey() === 'HBqhfdFASRQ5eBBpu2y6c6KKi1az6bMx8v1JxX4iW1Q8' );
}

$t->pretest( 'get_address', __LINE__ );
{
    $address_saved = $wk->get_address();
    $t->test( $address_saved === '3PPbMwqLtwBGcJrTA5whqJfY95GqnNnFMDX' );
}

$t->pretest( 'random_seed', __LINE__ );
{
    $wk->set_seed( $wk->random_seed() );
    $t->test( $wk->get_address() !== '3PPbMwqLtwBGcJrTA5whqJfY95GqnNnFMDX' );
}

// sig/verify

$t->pretest( 'get_pubkey', __LINE__ );
{
    $wk = new WavesKit( 'T' );
    $wk->set_privkey( '7VLYNhmuvAo5Us4mNGxWpzhMSdSSdEbEPFUDKSnA6eBv' );
    $t->test( $wk->get_pubkey() === 'EENPV1mRhUD9gSKbcWt84cqnfSGQP5LkCu5gMBfAanYH' );
}

$t->pretest( 'get_address', __LINE__ );
{
    $t->test( $wk->get_address() === '3N9Q2sdkkhAnbR4XCveuRaSMLiVtvebZ3wp' );
}

$t->pretest( 'verify (known)', __LINE__ );
{
    $msg = $wk->base58_decode( 'Ht7FtLJBrnukwWtywum4o1PbQSNyDWMgb4nXR5ZkV78krj9qVt17jz74XYSrKSTQe6wXuPdt3aCvmnF5hfjhnd1gyij36hN1zSDaiDg3TFi7c7RbXTHDDUbRgGajXci8PJB3iJM1tZvh8AL5wD4o4DCo1VJoKk2PUWX3cUydB7brxWGUxC6mPxKMdXefXwHeB4khwugbvcsPgk8F6YB' );
    $sig = $wk->base58_decode( '2mQvQFLQYJBe9ezj7YnAQFq7k9MxZstkrbcSKpLzv7vTxUfnbvWMUyyhJAc1u3vhkLqzQphKDecHcutUrhrHt22D' );
    $t->test( $wk->verify( $sig, $msg ) === true );
}

for( $i = 1; $i <= 3; $i++ )
{
    $t->pretest( "sign/verify #$i", __LINE__ );
    {
        $sig = $wk->sign( $msg );
        $t->test( $wk->verify( $sig, $msg ) === true );
    }
}

$t->pretest( 'set_sodium', __LINE__ );
{
    $wk->set_sodium();
    $wk->set_privkey( '7VLYNhmuvAo5Us4mNGxWpzhMSdSSdEbEPFUDKSnA6eBv' );
    $t->test( $wk->get_pubkey() !== 'EENPV1mRhUD9gSKbcWt84cqnfSGQP5LkCu5gMBfAanYH' );
}

for( $i = 1; $i <= 3; $i++ )
{
    $t->pretest( "sign/verify (sodium) #$i", __LINE__ );
    {
        $sig = $wk->sign( $msg );
        $t->test( $wk->verify( $sig, $msg ) === true );
    }
}

$t->pretest( 'rseed', __LINE__ );
{
    $wk->set_sodium( null );
    $wk->set_privkey( '7VLYNhmuvAo5Us4mNGxWpzhMSdSSdEbEPFUDKSnA6eBv' );
    $t->test( $wk->get_pubkey() === 'EENPV1mRhUD9gSKbcWt84cqnfSGQP5LkCu5gMBfAanYH' );
}

$t->pretest( "sign/verify (rseed) without knowing", __LINE__ );
{
    $t->test( false === $wk->sign_rseed( $msg, '123' ) );
}

define( 'IREALLYKNOWWHAT_RSEED_MEANS', null );

for( $i = 1; $i <= 2; $i++ )
{
    $t->pretest( "sign/verify (rseed) #$i", __LINE__ );
    {
        $sig = $wk->sign_rseed( $msg, '123' );
        if( $i === 1 )
        {
            $t->test( $wk->verify( $sig, $msg ) === true );
            $sig_saved = $sig;
            continue;
        }
        $t->test( $sig === $sig_saved );
    }
}

$t->finish();