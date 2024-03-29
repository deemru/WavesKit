<?php
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: waves/invoke_script_result.proto

namespace Waves;

use Google\Protobuf\Internal\GPBType;
use Google\Protobuf\Internal\RepeatedField;
use Google\Protobuf\Internal\GPBUtil;

/**
 * Generated from protobuf message <code>waves.InvokeScriptResult</code>
 */
class InvokeScriptResult extends \Google\Protobuf\Internal\Message
{
    /**
     * Generated from protobuf field <code>repeated .waves.DataTransactionData.DataEntry data = 1;</code>
     */
    private $data;
    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.Payment transfers = 2;</code>
     */
    private $transfers;
    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.Issue issues = 3;</code>
     */
    private $issues;
    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.Reissue reissues = 4;</code>
     */
    private $reissues;
    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.Burn burns = 5;</code>
     */
    private $burns;
    /**
     * Generated from protobuf field <code>.waves.InvokeScriptResult.ErrorMessage error_message = 6;</code>
     */
    protected $error_message = null;
    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.SponsorFee sponsor_fees = 7;</code>
     */
    private $sponsor_fees;
    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.Lease leases = 8;</code>
     */
    private $leases;
    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.LeaseCancel lease_cancels = 9;</code>
     */
    private $lease_cancels;
    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.Invocation invokes = 10;</code>
     */
    private $invokes;

    /**
     * Constructor.
     *
     * @param array $data {
     *     Optional. Data for populating the Message object.
     *
     *     @type array<\Waves\DataTransactionData\DataEntry>|\Google\Protobuf\Internal\RepeatedField $data
     *     @type array<\Waves\InvokeScriptResult\Payment>|\Google\Protobuf\Internal\RepeatedField $transfers
     *     @type array<\Waves\InvokeScriptResult\Issue>|\Google\Protobuf\Internal\RepeatedField $issues
     *     @type array<\Waves\InvokeScriptResult\Reissue>|\Google\Protobuf\Internal\RepeatedField $reissues
     *     @type array<\Waves\InvokeScriptResult\Burn>|\Google\Protobuf\Internal\RepeatedField $burns
     *     @type \Waves\InvokeScriptResult\ErrorMessage $error_message
     *     @type array<\Waves\InvokeScriptResult\SponsorFee>|\Google\Protobuf\Internal\RepeatedField $sponsor_fees
     *     @type array<\Waves\InvokeScriptResult\Lease>|\Google\Protobuf\Internal\RepeatedField $leases
     *     @type array<\Waves\InvokeScriptResult\LeaseCancel>|\Google\Protobuf\Internal\RepeatedField $lease_cancels
     *     @type array<\Waves\InvokeScriptResult\Invocation>|\Google\Protobuf\Internal\RepeatedField $invokes
     * }
     */
    public function __construct($data = NULL) {
        \GPBMetadata\Waves\InvokeScriptResult::initOnce();
        parent::__construct($data);
    }

    /**
     * Generated from protobuf field <code>repeated .waves.DataTransactionData.DataEntry data = 1;</code>
     * @return \Google\Protobuf\Internal\RepeatedField
     */
    public function getData()
    {
        return $this->data;
    }

    /**
     * Generated from protobuf field <code>repeated .waves.DataTransactionData.DataEntry data = 1;</code>
     * @param array<\Waves\DataTransactionData\DataEntry>|\Google\Protobuf\Internal\RepeatedField $var
     * @return $this
     */
    public function setData($var)
    {
        $arr = GPBUtil::checkRepeatedField($var, \Google\Protobuf\Internal\GPBType::MESSAGE, \Waves\DataTransactionData\DataEntry::class);
        $this->data = $arr;

        return $this;
    }

    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.Payment transfers = 2;</code>
     * @return \Google\Protobuf\Internal\RepeatedField
     */
    public function getTransfers()
    {
        return $this->transfers;
    }

    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.Payment transfers = 2;</code>
     * @param array<\Waves\InvokeScriptResult\Payment>|\Google\Protobuf\Internal\RepeatedField $var
     * @return $this
     */
    public function setTransfers($var)
    {
        $arr = GPBUtil::checkRepeatedField($var, \Google\Protobuf\Internal\GPBType::MESSAGE, \Waves\InvokeScriptResult\Payment::class);
        $this->transfers = $arr;

        return $this;
    }

    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.Issue issues = 3;</code>
     * @return \Google\Protobuf\Internal\RepeatedField
     */
    public function getIssues()
    {
        return $this->issues;
    }

    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.Issue issues = 3;</code>
     * @param array<\Waves\InvokeScriptResult\Issue>|\Google\Protobuf\Internal\RepeatedField $var
     * @return $this
     */
    public function setIssues($var)
    {
        $arr = GPBUtil::checkRepeatedField($var, \Google\Protobuf\Internal\GPBType::MESSAGE, \Waves\InvokeScriptResult\Issue::class);
        $this->issues = $arr;

        return $this;
    }

    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.Reissue reissues = 4;</code>
     * @return \Google\Protobuf\Internal\RepeatedField
     */
    public function getReissues()
    {
        return $this->reissues;
    }

    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.Reissue reissues = 4;</code>
     * @param array<\Waves\InvokeScriptResult\Reissue>|\Google\Protobuf\Internal\RepeatedField $var
     * @return $this
     */
    public function setReissues($var)
    {
        $arr = GPBUtil::checkRepeatedField($var, \Google\Protobuf\Internal\GPBType::MESSAGE, \Waves\InvokeScriptResult\Reissue::class);
        $this->reissues = $arr;

        return $this;
    }

    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.Burn burns = 5;</code>
     * @return \Google\Protobuf\Internal\RepeatedField
     */
    public function getBurns()
    {
        return $this->burns;
    }

    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.Burn burns = 5;</code>
     * @param array<\Waves\InvokeScriptResult\Burn>|\Google\Protobuf\Internal\RepeatedField $var
     * @return $this
     */
    public function setBurns($var)
    {
        $arr = GPBUtil::checkRepeatedField($var, \Google\Protobuf\Internal\GPBType::MESSAGE, \Waves\InvokeScriptResult\Burn::class);
        $this->burns = $arr;

        return $this;
    }

    /**
     * Generated from protobuf field <code>.waves.InvokeScriptResult.ErrorMessage error_message = 6;</code>
     * @return \Waves\InvokeScriptResult\ErrorMessage|null
     */
    public function getErrorMessage()
    {
        return $this->error_message;
    }

    public function hasErrorMessage()
    {
        return isset($this->error_message);
    }

    public function clearErrorMessage()
    {
        unset($this->error_message);
    }

    /**
     * Generated from protobuf field <code>.waves.InvokeScriptResult.ErrorMessage error_message = 6;</code>
     * @param \Waves\InvokeScriptResult\ErrorMessage $var
     * @return $this
     */
    public function setErrorMessage($var)
    {
        GPBUtil::checkMessage($var, \Waves\InvokeScriptResult\ErrorMessage::class);
        $this->error_message = $var;

        return $this;
    }

    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.SponsorFee sponsor_fees = 7;</code>
     * @return \Google\Protobuf\Internal\RepeatedField
     */
    public function getSponsorFees()
    {
        return $this->sponsor_fees;
    }

    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.SponsorFee sponsor_fees = 7;</code>
     * @param array<\Waves\InvokeScriptResult\SponsorFee>|\Google\Protobuf\Internal\RepeatedField $var
     * @return $this
     */
    public function setSponsorFees($var)
    {
        $arr = GPBUtil::checkRepeatedField($var, \Google\Protobuf\Internal\GPBType::MESSAGE, \Waves\InvokeScriptResult\SponsorFee::class);
        $this->sponsor_fees = $arr;

        return $this;
    }

    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.Lease leases = 8;</code>
     * @return \Google\Protobuf\Internal\RepeatedField
     */
    public function getLeases()
    {
        return $this->leases;
    }

    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.Lease leases = 8;</code>
     * @param array<\Waves\InvokeScriptResult\Lease>|\Google\Protobuf\Internal\RepeatedField $var
     * @return $this
     */
    public function setLeases($var)
    {
        $arr = GPBUtil::checkRepeatedField($var, \Google\Protobuf\Internal\GPBType::MESSAGE, \Waves\InvokeScriptResult\Lease::class);
        $this->leases = $arr;

        return $this;
    }

    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.LeaseCancel lease_cancels = 9;</code>
     * @return \Google\Protobuf\Internal\RepeatedField
     */
    public function getLeaseCancels()
    {
        return $this->lease_cancels;
    }

    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.LeaseCancel lease_cancels = 9;</code>
     * @param array<\Waves\InvokeScriptResult\LeaseCancel>|\Google\Protobuf\Internal\RepeatedField $var
     * @return $this
     */
    public function setLeaseCancels($var)
    {
        $arr = GPBUtil::checkRepeatedField($var, \Google\Protobuf\Internal\GPBType::MESSAGE, \Waves\InvokeScriptResult\LeaseCancel::class);
        $this->lease_cancels = $arr;

        return $this;
    }

    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.Invocation invokes = 10;</code>
     * @return \Google\Protobuf\Internal\RepeatedField
     */
    public function getInvokes()
    {
        return $this->invokes;
    }

    /**
     * Generated from protobuf field <code>repeated .waves.InvokeScriptResult.Invocation invokes = 10;</code>
     * @param array<\Waves\InvokeScriptResult\Invocation>|\Google\Protobuf\Internal\RepeatedField $var
     * @return $this
     */
    public function setInvokes($var)
    {
        $arr = GPBUtil::checkRepeatedField($var, \Google\Protobuf\Internal\GPBType::MESSAGE, \Waves\InvokeScriptResult\Invocation::class);
        $this->invokes = $arr;

        return $this;
    }

}

