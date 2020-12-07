<?php
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: waves/transaction.proto

namespace Waves;

use Google\Protobuf\Internal\GPBType;
use Google\Protobuf\Internal\RepeatedField;
use Google\Protobuf\Internal\GPBUtil;

/**
 * Generated from protobuf message <code>waves.Transaction</code>
 */
class Transaction extends \Google\Protobuf\Internal\Message
{
    /**
     * Generated from protobuf field <code>int32 chain_id = 1;</code>
     */
    protected $chain_id = 0;
    /**
     * Generated from protobuf field <code>bytes sender_public_key = 2;</code>
     */
    protected $sender_public_key = '';
    /**
     * Generated from protobuf field <code>.waves.Amount fee = 3;</code>
     */
    protected $fee = null;
    /**
     * Generated from protobuf field <code>int64 timestamp = 4;</code>
     */
    protected $timestamp = 0;
    /**
     * Generated from protobuf field <code>int32 version = 5;</code>
     */
    protected $version = 0;
    protected $data;

    /**
     * Constructor.
     *
     * @param array $data {
     *     Optional. Data for populating the Message object.
     *
     *     @type int $chain_id
     *     @type string $sender_public_key
     *     @type \Waves\Amount $fee
     *     @type int|string $timestamp
     *     @type int $version
     *     @type \Waves\GenesisTransactionData $genesis
     *     @type \Waves\PaymentTransactionData $payment
     *     @type \Waves\IssueTransactionData $issue
     *     @type \Waves\TransferTransactionData $transfer
     *     @type \Waves\ReissueTransactionData $reissue
     *     @type \Waves\BurnTransactionData $burn
     *     @type \Waves\ExchangeTransactionData $exchange
     *     @type \Waves\LeaseTransactionData $lease
     *     @type \Waves\LeaseCancelTransactionData $lease_cancel
     *     @type \Waves\CreateAliasTransactionData $create_alias
     *     @type \Waves\MassTransferTransactionData $mass_transfer
     *     @type \Waves\DataTransactionData $data_transaction
     *     @type \Waves\SetScriptTransactionData $set_script
     *     @type \Waves\SponsorFeeTransactionData $sponsor_fee
     *     @type \Waves\SetAssetScriptTransactionData $set_asset_script
     *     @type \Waves\InvokeScriptTransactionData $invoke_script
     *     @type \Waves\UpdateAssetInfoTransactionData $update_asset_info
     * }
     */
    public function __construct($data = NULL) {
        \GPBMetadata\Waves\Transaction::initOnce();
        parent::__construct($data);
    }

    /**
     * Generated from protobuf field <code>int32 chain_id = 1;</code>
     * @return int
     */
    public function getChainId()
    {
        return $this->chain_id;
    }

    /**
     * Generated from protobuf field <code>int32 chain_id = 1;</code>
     * @param int $var
     * @return $this
     */
    public function setChainId($var)
    {
        GPBUtil::checkInt32($var);
        $this->chain_id = $var;

        return $this;
    }

    /**
     * Generated from protobuf field <code>bytes sender_public_key = 2;</code>
     * @return string
     */
    public function getSenderPublicKey()
    {
        return $this->sender_public_key;
    }

    /**
     * Generated from protobuf field <code>bytes sender_public_key = 2;</code>
     * @param string $var
     * @return $this
     */
    public function setSenderPublicKey($var)
    {
        GPBUtil::checkString($var, False);
        $this->sender_public_key = $var;

        return $this;
    }

    /**
     * Generated from protobuf field <code>.waves.Amount fee = 3;</code>
     * @return \Waves\Amount
     */
    public function getFee()
    {
        return isset($this->fee) ? $this->fee : null;
    }

    public function hasFee()
    {
        return isset($this->fee);
    }

    public function clearFee()
    {
        unset($this->fee);
    }

    /**
     * Generated from protobuf field <code>.waves.Amount fee = 3;</code>
     * @param \Waves\Amount $var
     * @return $this
     */
    public function setFee($var)
    {
        GPBUtil::checkMessage($var, \Waves\Amount::class);
        $this->fee = $var;

        return $this;
    }

    /**
     * Generated from protobuf field <code>int64 timestamp = 4;</code>
     * @return int|string
     */
    public function getTimestamp()
    {
        return $this->timestamp;
    }

    /**
     * Generated from protobuf field <code>int64 timestamp = 4;</code>
     * @param int|string $var
     * @return $this
     */
    public function setTimestamp($var)
    {
        GPBUtil::checkInt64($var);
        $this->timestamp = $var;

        return $this;
    }

    /**
     * Generated from protobuf field <code>int32 version = 5;</code>
     * @return int
     */
    public function getVersion()
    {
        return $this->version;
    }

    /**
     * Generated from protobuf field <code>int32 version = 5;</code>
     * @param int $var
     * @return $this
     */
    public function setVersion($var)
    {
        GPBUtil::checkInt32($var);
        $this->version = $var;

        return $this;
    }

    /**
     * Generated from protobuf field <code>.waves.GenesisTransactionData genesis = 101;</code>
     * @return \Waves\GenesisTransactionData
     */
    public function getGenesis()
    {
        return $this->readOneof(101);
    }

    public function hasGenesis()
    {
        return $this->hasOneof(101);
    }

    /**
     * Generated from protobuf field <code>.waves.GenesisTransactionData genesis = 101;</code>
     * @param \Waves\GenesisTransactionData $var
     * @return $this
     */
    public function setGenesis($var)
    {
        GPBUtil::checkMessage($var, \Waves\GenesisTransactionData::class);
        $this->writeOneof(101, $var);

        return $this;
    }

    /**
     * Generated from protobuf field <code>.waves.PaymentTransactionData payment = 102;</code>
     * @return \Waves\PaymentTransactionData
     */
    public function getPayment()
    {
        return $this->readOneof(102);
    }

    public function hasPayment()
    {
        return $this->hasOneof(102);
    }

    /**
     * Generated from protobuf field <code>.waves.PaymentTransactionData payment = 102;</code>
     * @param \Waves\PaymentTransactionData $var
     * @return $this
     */
    public function setPayment($var)
    {
        GPBUtil::checkMessage($var, \Waves\PaymentTransactionData::class);
        $this->writeOneof(102, $var);

        return $this;
    }

    /**
     * Generated from protobuf field <code>.waves.IssueTransactionData issue = 103;</code>
     * @return \Waves\IssueTransactionData
     */
    public function getIssue()
    {
        return $this->readOneof(103);
    }

    public function hasIssue()
    {
        return $this->hasOneof(103);
    }

    /**
     * Generated from protobuf field <code>.waves.IssueTransactionData issue = 103;</code>
     * @param \Waves\IssueTransactionData $var
     * @return $this
     */
    public function setIssue($var)
    {
        GPBUtil::checkMessage($var, \Waves\IssueTransactionData::class);
        $this->writeOneof(103, $var);

        return $this;
    }

    /**
     * Generated from protobuf field <code>.waves.TransferTransactionData transfer = 104;</code>
     * @return \Waves\TransferTransactionData
     */
    public function getTransfer()
    {
        return $this->readOneof(104);
    }

    public function hasTransfer()
    {
        return $this->hasOneof(104);
    }

    /**
     * Generated from protobuf field <code>.waves.TransferTransactionData transfer = 104;</code>
     * @param \Waves\TransferTransactionData $var
     * @return $this
     */
    public function setTransfer($var)
    {
        GPBUtil::checkMessage($var, \Waves\TransferTransactionData::class);
        $this->writeOneof(104, $var);

        return $this;
    }

    /**
     * Generated from protobuf field <code>.waves.ReissueTransactionData reissue = 105;</code>
     * @return \Waves\ReissueTransactionData
     */
    public function getReissue()
    {
        return $this->readOneof(105);
    }

    public function hasReissue()
    {
        return $this->hasOneof(105);
    }

    /**
     * Generated from protobuf field <code>.waves.ReissueTransactionData reissue = 105;</code>
     * @param \Waves\ReissueTransactionData $var
     * @return $this
     */
    public function setReissue($var)
    {
        GPBUtil::checkMessage($var, \Waves\ReissueTransactionData::class);
        $this->writeOneof(105, $var);

        return $this;
    }

    /**
     * Generated from protobuf field <code>.waves.BurnTransactionData burn = 106;</code>
     * @return \Waves\BurnTransactionData
     */
    public function getBurn()
    {
        return $this->readOneof(106);
    }

    public function hasBurn()
    {
        return $this->hasOneof(106);
    }

    /**
     * Generated from protobuf field <code>.waves.BurnTransactionData burn = 106;</code>
     * @param \Waves\BurnTransactionData $var
     * @return $this
     */
    public function setBurn($var)
    {
        GPBUtil::checkMessage($var, \Waves\BurnTransactionData::class);
        $this->writeOneof(106, $var);

        return $this;
    }

    /**
     * Generated from protobuf field <code>.waves.ExchangeTransactionData exchange = 107;</code>
     * @return \Waves\ExchangeTransactionData
     */
    public function getExchange()
    {
        return $this->readOneof(107);
    }

    public function hasExchange()
    {
        return $this->hasOneof(107);
    }

    /**
     * Generated from protobuf field <code>.waves.ExchangeTransactionData exchange = 107;</code>
     * @param \Waves\ExchangeTransactionData $var
     * @return $this
     */
    public function setExchange($var)
    {
        GPBUtil::checkMessage($var, \Waves\ExchangeTransactionData::class);
        $this->writeOneof(107, $var);

        return $this;
    }

    /**
     * Generated from protobuf field <code>.waves.LeaseTransactionData lease = 108;</code>
     * @return \Waves\LeaseTransactionData
     */
    public function getLease()
    {
        return $this->readOneof(108);
    }

    public function hasLease()
    {
        return $this->hasOneof(108);
    }

    /**
     * Generated from protobuf field <code>.waves.LeaseTransactionData lease = 108;</code>
     * @param \Waves\LeaseTransactionData $var
     * @return $this
     */
    public function setLease($var)
    {
        GPBUtil::checkMessage($var, \Waves\LeaseTransactionData::class);
        $this->writeOneof(108, $var);

        return $this;
    }

    /**
     * Generated from protobuf field <code>.waves.LeaseCancelTransactionData lease_cancel = 109;</code>
     * @return \Waves\LeaseCancelTransactionData
     */
    public function getLeaseCancel()
    {
        return $this->readOneof(109);
    }

    public function hasLeaseCancel()
    {
        return $this->hasOneof(109);
    }

    /**
     * Generated from protobuf field <code>.waves.LeaseCancelTransactionData lease_cancel = 109;</code>
     * @param \Waves\LeaseCancelTransactionData $var
     * @return $this
     */
    public function setLeaseCancel($var)
    {
        GPBUtil::checkMessage($var, \Waves\LeaseCancelTransactionData::class);
        $this->writeOneof(109, $var);

        return $this;
    }

    /**
     * Generated from protobuf field <code>.waves.CreateAliasTransactionData create_alias = 110;</code>
     * @return \Waves\CreateAliasTransactionData
     */
    public function getCreateAlias()
    {
        return $this->readOneof(110);
    }

    public function hasCreateAlias()
    {
        return $this->hasOneof(110);
    }

    /**
     * Generated from protobuf field <code>.waves.CreateAliasTransactionData create_alias = 110;</code>
     * @param \Waves\CreateAliasTransactionData $var
     * @return $this
     */
    public function setCreateAlias($var)
    {
        GPBUtil::checkMessage($var, \Waves\CreateAliasTransactionData::class);
        $this->writeOneof(110, $var);

        return $this;
    }

    /**
     * Generated from protobuf field <code>.waves.MassTransferTransactionData mass_transfer = 111;</code>
     * @return \Waves\MassTransferTransactionData
     */
    public function getMassTransfer()
    {
        return $this->readOneof(111);
    }

    public function hasMassTransfer()
    {
        return $this->hasOneof(111);
    }

    /**
     * Generated from protobuf field <code>.waves.MassTransferTransactionData mass_transfer = 111;</code>
     * @param \Waves\MassTransferTransactionData $var
     * @return $this
     */
    public function setMassTransfer($var)
    {
        GPBUtil::checkMessage($var, \Waves\MassTransferTransactionData::class);
        $this->writeOneof(111, $var);

        return $this;
    }

    /**
     * Generated from protobuf field <code>.waves.DataTransactionData data_transaction = 112;</code>
     * @return \Waves\DataTransactionData
     */
    public function getDataTransaction()
    {
        return $this->readOneof(112);
    }

    public function hasDataTransaction()
    {
        return $this->hasOneof(112);
    }

    /**
     * Generated from protobuf field <code>.waves.DataTransactionData data_transaction = 112;</code>
     * @param \Waves\DataTransactionData $var
     * @return $this
     */
    public function setDataTransaction($var)
    {
        GPBUtil::checkMessage($var, \Waves\DataTransactionData::class);
        $this->writeOneof(112, $var);

        return $this;
    }

    /**
     * Generated from protobuf field <code>.waves.SetScriptTransactionData set_script = 113;</code>
     * @return \Waves\SetScriptTransactionData
     */
    public function getSetScript()
    {
        return $this->readOneof(113);
    }

    public function hasSetScript()
    {
        return $this->hasOneof(113);
    }

    /**
     * Generated from protobuf field <code>.waves.SetScriptTransactionData set_script = 113;</code>
     * @param \Waves\SetScriptTransactionData $var
     * @return $this
     */
    public function setSetScript($var)
    {
        GPBUtil::checkMessage($var, \Waves\SetScriptTransactionData::class);
        $this->writeOneof(113, $var);

        return $this;
    }

    /**
     * Generated from protobuf field <code>.waves.SponsorFeeTransactionData sponsor_fee = 114;</code>
     * @return \Waves\SponsorFeeTransactionData
     */
    public function getSponsorFee()
    {
        return $this->readOneof(114);
    }

    public function hasSponsorFee()
    {
        return $this->hasOneof(114);
    }

    /**
     * Generated from protobuf field <code>.waves.SponsorFeeTransactionData sponsor_fee = 114;</code>
     * @param \Waves\SponsorFeeTransactionData $var
     * @return $this
     */
    public function setSponsorFee($var)
    {
        GPBUtil::checkMessage($var, \Waves\SponsorFeeTransactionData::class);
        $this->writeOneof(114, $var);

        return $this;
    }

    /**
     * Generated from protobuf field <code>.waves.SetAssetScriptTransactionData set_asset_script = 115;</code>
     * @return \Waves\SetAssetScriptTransactionData
     */
    public function getSetAssetScript()
    {
        return $this->readOneof(115);
    }

    public function hasSetAssetScript()
    {
        return $this->hasOneof(115);
    }

    /**
     * Generated from protobuf field <code>.waves.SetAssetScriptTransactionData set_asset_script = 115;</code>
     * @param \Waves\SetAssetScriptTransactionData $var
     * @return $this
     */
    public function setSetAssetScript($var)
    {
        GPBUtil::checkMessage($var, \Waves\SetAssetScriptTransactionData::class);
        $this->writeOneof(115, $var);

        return $this;
    }

    /**
     * Generated from protobuf field <code>.waves.InvokeScriptTransactionData invoke_script = 116;</code>
     * @return \Waves\InvokeScriptTransactionData
     */
    public function getInvokeScript()
    {
        return $this->readOneof(116);
    }

    public function hasInvokeScript()
    {
        return $this->hasOneof(116);
    }

    /**
     * Generated from protobuf field <code>.waves.InvokeScriptTransactionData invoke_script = 116;</code>
     * @param \Waves\InvokeScriptTransactionData $var
     * @return $this
     */
    public function setInvokeScript($var)
    {
        GPBUtil::checkMessage($var, \Waves\InvokeScriptTransactionData::class);
        $this->writeOneof(116, $var);

        return $this;
    }

    /**
     * Generated from protobuf field <code>.waves.UpdateAssetInfoTransactionData update_asset_info = 117;</code>
     * @return \Waves\UpdateAssetInfoTransactionData
     */
    public function getUpdateAssetInfo()
    {
        return $this->readOneof(117);
    }

    public function hasUpdateAssetInfo()
    {
        return $this->hasOneof(117);
    }

    /**
     * Generated from protobuf field <code>.waves.UpdateAssetInfoTransactionData update_asset_info = 117;</code>
     * @param \Waves\UpdateAssetInfoTransactionData $var
     * @return $this
     */
    public function setUpdateAssetInfo($var)
    {
        GPBUtil::checkMessage($var, \Waves\UpdateAssetInfoTransactionData::class);
        $this->writeOneof(117, $var);

        return $this;
    }

    /**
     * @return string
     */
    public function getData()
    {
        return $this->whichOneof("data");
    }

}
