<?php
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: waves/order.proto

namespace GPBMetadata\Waves;

class Order
{
    public static $is_initialized = false;

    public static function initOnce() {
        $pool = \Google\Protobuf\Internal\DescriptorPool::getGeneratedPool();

        if (static::$is_initialized == true) {
          return;
        }
        \GPBMetadata\Waves\Amount::initOnce();
        $pool->internalAddGeneratedFile(
            '
�
waves/order.protowaves"<
	AssetPair
amount_asset_id (
price_asset_id ("�
Order
chain_id (
matcher_public_key ($

asset_pair (2.waves.AssetPair%

order_side (2.waves.Order.Side
amount (
price (
	timestamp (

expiration	 ("
matcher_fee
 (2.waves.Amount
version (
proofs (*

price_mode (2.waves.Order.PriceMode
sender_public_key (H 
eip712_signature (H "
Side
BUY 
SELL"@
	PriceMode
DEFAULT 
FIXED_DECIMALS
ASSET_DECIMALSB
senderBe
 com.wavesplatform.protobuf.orderZ9github.com/wavesplatform/gowaves/pkg/grpc/generated/waves�Wavesbproto3'
        , true);

        static::$is_initialized = true;
    }
}

