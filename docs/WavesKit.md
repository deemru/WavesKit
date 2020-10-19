# deemru\WavesKit  

- Consider to learn self tests: [selftest.php](https://github.com/deemru/WavesKit/blob/master/test/selftest.php)
- Self tests contain tests of all transactions which can easily be used as examples

## Methods

| Name | Description |
|------|-------------|
|[__construct](#waveskit__construct)|Creates WavesKit instance|
|[balance](#waveskitbalance)|Gets an address full balance|
|[base58Decode](#waveskitbase58decode)|Decodes data from base58 string|
|[base58Encode](#waveskitbase58encode)|Encodes data to base58 string|
|[base64ToBase64Tx](#waveskitbase64tobase64tx)|Converts string from base64 to base64 in transaction notation|
|[base64TxToBase64](#waveskitbase64txtobase64)|Converts string from base64 in transaction notation to base64|
|[base64TxToBin](#waveskitbase64txtobin)|Converts base64 string in transaction notation to binary data|
|[binToBase64Tx](#waveskitbintobase64tx)|Converts binary data to base64 string in transaction notation|
|[blake2b256](#waveskitblake2b256)|Hashes data with blake2b256|
|[calculateFee](#waveskitcalculatefee)|Calculates fee of a transaction on a node|
|[compile](#waveskitcompile)|Compiles a script|
|[decryptash](#waveskitdecryptash)|Decrypts data with cryptash parameters|
|[encryptash](#waveskitencryptash)|Encrypts data with cryptash parameters|
|[ensure](#waveskitensure)|Ensures a transaction confirmed and reached required confirmations|
|[fetch](#waveskitfetch)|Fetches GET or POST response|
|[fetchMulti](#waveskitfetchmulti)|Fetches GET or POST responses from all nodes|
|[getAddress](#waveskitgetaddress)|Gets address|
|[getAddressByAlias](#waveskitgetaddressbyalias)|Gets an address by an alias|
|[getAddressScript](#waveskitgetaddressscript)|Gets a script associated with an address|
|[getBlockAt](#waveskitgetblockat)|Gets a block at a certain height|
|[getChainId](#waveskitgetchainid)|Gets blockchain identifier value|
|[getData](#waveskitgetdata)|Gets data value by an address key from the blockchain|
|[getLastBitFlip](#waveskitgetlastbitflip)|Get last bit flip option status|
|[getNodeAddress](#waveskitgetnodeaddress)|Gets main node address|
|[getOrders](#waveskitgetorders)|Gets order history for your account|
|[getPrivateKey](#waveskitgetprivatekey)|Gets private key|
|[getPublicKey](#waveskitgetpublickey)|Gets public Key|
|[getSodium](#waveskitgetsodium)|Gets sodium option status|
|[getStateChanges](#waveskitgetstatechanges)|Gets state changes of an invoke transaction by its id|
|[getTransactionById](#waveskitgettransactionbyid)|Gets a transaction by its id|
|[getTransactions](#waveskitgettransactions)|Gets transactions for an address|
|[height](#waveskitheight)|Gets current blockchain height|
|[isAddressValid](#waveskitisaddressvalid)|Validates an address by a current blockchain identifier|
|[json_decode](#waveskitjson_decode)|json_decode wrapper for WavesKit|
|[keccak256](#waveskitkeccak256)|Hashes data with keccak256|
|[log](#waveskitlog)|Logs a message with a level|
|[randomSeed](#waveskitrandomseed)|Generates random seed string|
|[secureHash](#waveskitsecurehash)|Hashes data with blake2b256 and keccak256|
|[setAddress](#waveskitsetaddress)|Sets address|
|[setBestNode](#waveskitsetbestnode)|Internally sets nodes in order of priority by the current height and response time|
|[setCryptash](#waveskitsetcryptash)|Sets cryptash parameters|
|[setLastBitFlip](#waveskitsetlastbitflip)|Sets last bit flip option|
|[setNodeAddress](#waveskitsetnodeaddress)|Sets node address with cache lifetime and backup node addresses|
|[setPairsDatabase](#waveskitsetpairsdatabase)|Sets database pairs path|
|[setPrivateKey](#waveskitsetprivatekey)|Sets private key|
|[setPublicKey](#waveskitsetpublickey)|Sets public key|
|[setRSEED](#waveskitsetrseed)|Sets RSEED value (DANGEROUS)|
|[setSeed](#waveskitsetseed)|Sets user seed string|
|[setSodium](#waveskitsetsodium)|Sets sodium option|
|[sha256](#waveskitsha256)|Hashes data with sha256|
|[sha512](#waveskitsha512)|Hashes data with sha512|
|[sign](#waveskitsign)|Signs a message with a private key|
|[timestamp](#waveskittimestamp)|Gets current timestamp|
|[txAddressScript](#waveskittxaddressscript)|Makes address script transaction as an array|
|[txAlias](#waveskittxalias)|Makes alias transaction as an array|
|[txAssetScript](#waveskittxassetscript)|Makes asset script transaction as an array|
|[txBody](#waveskittxbody)|Gets transaction body|
|[txBroadcast](#waveskittxbroadcast)|Broadcasts a transaction|
|[txBurn](#waveskittxburn)|Makes burn transaction as an array|
|[txData](#waveskittxdata)|Makes data transaction as an array|
|[txInvokeScript](#waveskittxinvokescript)|Makes invoke script transaction as an array|
|[txIssue](#waveskittxissue)|Makes issue transaction as an array|
|[txLease](#waveskittxlease)|Makes lease transaction as an array|
|[txLeaseCancel](#waveskittxleasecancel)|Makes lease cancel transaction as an array|
|[txMass](#waveskittxmass)|Makes mass transfer transaction as an array|
|[txMonitor](#waveskittxmonitor)|Monitors for new transaction in realtime|
|[txOrder](#waveskittxorder)|Makes order as an array|
|[txOrderBroadcast](#waveskittxorderbroadcast)|Broadcasts an order to a matcher|
|[txOrderCancel](#waveskittxordercancel)|Cancels an order on a matcher|
|[txReissue](#waveskittxreissue)|Makes reissue transaction as an array|
|[txSign](#waveskittxsign)|Signs a transaction|
|[txSponsorship](#waveskittxsponsorship)|Makes sponsorship transaction as an array|
|[txTransfer](#waveskittxtransfer)|Makes transfer transaction as an array|
|[txUpdateAssetInfo](#waveskittxupdateassetinfo)|Makes update asset information transaction as an array|
|[verify](#waveskitverify)|Verifies a signature of a message by a public key|




### WavesKit::__construct  

**Description**

```php
public __construct (string $chainId, mixed|null $logFunction)
```

Creates WavesKit instance 

 

**Parameters**

* `(string) $chainId`
: Blockchain identifier (default: 'W')  
* `(mixed|null) $logFunction`
: Log functionality (default: null)  

**Return Values**

`void`




<hr />


### WavesKit::balance  

**Description**

```php
public balance (string|null $address)
```

Gets an address full balance 

 

**Parameters**

* `(string|null) $address`
: Address to get balance (default: null)  

**Return Values**

`array|false`

> Balance of all assets as an array or FALSE on failure


<hr />


### WavesKit::base58Decode  

**Description**

```php
public base58Decode (string $data)
```

Decodes data from base58 string 

 

**Parameters**

* `(string) $data`
: Base58 string  

**Return Values**

`string|false`

> Decoded data or FALSE on failure


<hr />


### WavesKit::base58Encode  

**Description**

```php
public base58Encode (string $data)
```

Encodes data to base58 string 

 

**Parameters**

* `(string) $data`
: Data to encode  

**Return Values**

`string`

> Encoded data


<hr />


### WavesKit::base64ToBase64Tx  

**Description**

```php
public base64ToBase64Tx (string $base64)
```

Converts string from base64 to base64 in transaction notation 

 

**Parameters**

* `(string) $base64`
: Base64 string  

**Return Values**

`string`

> Base64 string in transaction notation


<hr />


### WavesKit::base64TxToBase64  

**Description**

```php
public base64TxToBase64 (string $base64)
```

Converts string from base64 in transaction notation to base64 

 

**Parameters**

* `(string) $base64`
: Base64 string in transaction notation  

**Return Values**

`string`

> Base64 string


<hr />


### WavesKit::base64TxToBin  

**Description**

```php
public base64TxToBin (string $base64)
```

Converts base64 string in transaction notation to binary data 

 

**Parameters**

* `(string) $base64`
: Base64 string in transaction notation  

**Return Values**

`string`

> Binary data


<hr />


### WavesKit::binToBase64Tx  

**Description**

```php
public binToBase64Tx (string $bin)
```

Converts binary data to base64 string in transaction notation 

 

**Parameters**

* `(string) $bin`
: Binary data  

**Return Values**

`string`

> Base64 string in transaction notation


<hr />


### WavesKit::blake2b256  

**Description**

```php
public blake2b256 (string $data)
```

Hashes data with blake2b256 

 

**Parameters**

* `(string) $data`
: Data to hash  

**Return Values**

`string`

> Hash result


<hr />


### WavesKit::calculateFee  

**Description**

```php
public calculateFee (array $tx)
```

Calculates fee of a transaction on a node 

 

**Parameters**

* `(array) $tx`
: Transaction as an array  

**Return Values**

`int|false`

> Minimal fee for transaction or FALSE on failure


<hr />


### WavesKit::compile  

**Description**

```php
public compile (string $script)
```

Compiles a script 

 

**Parameters**

* `(string) $script`
: Text of the script  

**Return Values**

`array|false`

> Compiled script information or FALSE on failure


<hr />


### WavesKit::decryptash  

**Description**

```php
public decryptash (string $data)
```

Decrypts data with cryptash parameters 

 

**Parameters**

* `(string) $data`
: Data to decrypt  

**Return Values**

`string|false`

> Decrypted data or FALSE on failure


<hr />


### WavesKit::encryptash  

**Description**

```php
public encryptash (string $data)
```

Encrypts data with cryptash parameters 

 

**Parameters**

* `(string) $data`
: Data to encrypt  

**Return Values**

`string|false`

> Encrypted data or FALSE on failure


<hr />


### WavesKit::ensure  

**Description**

```php
public ensure (array $tx, int $confirmations, int $sleep, int $timeout)
```

Ensures a transaction confirmed and reached required confirmations 

 

**Parameters**

* `(array) $tx`
: Transaction as an array  
* `(int) $confirmations`
: Number of confirmations to reach  
* `(int) $sleep`
: Seconds to sleep between requests  
* `(int) $timeout`
: Timeout to reach lost status  

**Return Values**

`array|false`

> Ensured transaction as an array or FALSE on failure


<hr />


### WavesKit::fetch  

**Description**

```php
public fetch (string $url, bool $post, string|null $data, array|null $ignoreCodes, array|null $headers)
```

Fetches GET or POST response 

 

**Parameters**

* `(string) $url`
: URL of request  
* `(bool) $post`
: POST or GET (default: GET)  
* `(string|null) $data`
: Data for POST (default: null)  
* `(array|null) $ignoreCodes`
: Array of ignored HTTP codes (default: null)  
* `(array|null) $headers`
: Optional HTTP headers (default: null)  

**Return Values**

`string|false`

> Returns response data or FALSE on failure


<hr />


### WavesKit::fetchMulti  

**Description**

```php
public fetchMulti (string $url, bool $post, string|null $data, array|null $ignoreCodes, array|null $headers)
```

Fetches GET or POST responses from all nodes 

 

**Parameters**

* `(string) $url`
: URL of request  
* `(bool) $post`
: POST or GET (default: GET)  
* `(string|null) $data`
: Data for POST (default: null)  
* `(array|null) $ignoreCodes`
: Array of ignored HTTP codes (default: null)  
* `(array|null) $headers`
: Optional HTTP headers (default: null)  

**Return Values**

`array|false`

> Returns data responses from all nodes or FALSE on failure


<hr />


### WavesKit::getAddress  

**Description**

```php
public getAddress (bool $raw)
```

Gets address 

 

**Parameters**

* `(bool) $raw`
: String format is binary or base58 (default: base58)  

**Return Values**

`string`

> Address


<hr />


### WavesKit::getAddressByAlias  

**Description**

```php
public getAddressByAlias (string $alias)
```

Gets an address by an alias 

 

**Parameters**

* `(string) $alias`
: Alias  

**Return Values**

`string|false`

> Address or FALSE on failure


<hr />


### WavesKit::getAddressScript  

**Description**

```php
public getAddressScript (string|null $address)
```

Gets a script associated with an address 

 

**Parameters**

* `(string|null) $address`
: Address to get the script for (default: null)  

**Return Values**

`string|false`

> Address script information or FALSE on failure


<hr />


### WavesKit::getBlockAt  

**Description**

```php
public getBlockAt (int $height, bool $headers)
```

Gets a block at a certain height 

 

**Parameters**

* `(int) $height`
: Height of the block  
* `(bool) $headers`
: Just headers or the full block information (default: full block)  

**Return Values**

`array|false`

> Block information or FALSE on failure


<hr />


### WavesKit::getChainId  

**Description**

```php
public getChainId (void)
```

Gets blockchain identifier value 

 

**Parameters**

`This function has no parameters.`

**Return Values**

`string`

> Blockchain identifier value


<hr />


### WavesKit::getData  

**Description**

```php
public getData (string $key, string $address, bool $justValue)
```

Gets data value by an address key from the blockchain 

 

**Parameters**

* `(string) $key`
: Key to get value  
* `(string) $address`
: Address of the key value pair (default: null)  
* `(bool) $justValue`
: Get just value or full information (default: just value)  

**Return Values**

`mixed|false`

> Value from blockchain by the key


<hr />


### WavesKit::getLastBitFlip  

**Description**

```php
public getLastBitFlip (void)
```

Get last bit flip option status 

 

**Parameters**

`This function has no parameters.`

**Return Values**

`bool`

> Enabled or disabled


<hr />


### WavesKit::getNodeAddress  

**Description**

```php
public getNodeAddress (void)
```

Gets main node address 

 

**Parameters**

`This function has no parameters.`

**Return Values**

`string|false`

> Main node address or FALSE on failure


<hr />


### WavesKit::getOrders  

**Description**

```php
public getOrders (bool $activeOnly)
```

Gets order history for your account 

 

**Parameters**

* `(bool) $activeOnly`
: Active only orders (default: true)  

**Return Values**

`array|false`

> Your orders as an array or FALSE on failure


<hr />


### WavesKit::getPrivateKey  

**Description**

```php
public getPrivateKey (bool $raw, string|null $seed, string|null $prefix)
```

Gets private key 

 

**Parameters**

* `(bool) $raw`
: String format is binary or base58 (default: binary)  
* `(string|null) $seed`
: Seed string in binary format (default: null)  
* `(string|null) $prefix`
: Prefix string in binary format (default: "\0\0\0\0")  

**Return Values**

`string`

> Private key


<hr />


### WavesKit::getPublicKey  

**Description**

```php
public getPublicKey (bool $raw)
```

Gets public Key 

 

**Parameters**

* `(bool) $raw`
: String format is binary or base58 (default: base58)  

**Return Values**

`string`

> Public key


<hr />


### WavesKit::getSodium  

**Description**

```php
public getSodium (void)
```

Gets sodium option status 

 

**Parameters**

`This function has no parameters.`

**Return Values**

`bool`

> Enabled or disabled


<hr />


### WavesKit::getStateChanges  

**Description**

```php
public getStateChanges (string $id)
```

Gets state changes of an invoke transaction by its id 

 

**Parameters**

* `(string) $id`
: Id of the invoke transaction  

**Return Values**

`array|false`

> Invoke transaction with state changes as an array or FALSE on failure


<hr />


### WavesKit::getTransactionById  

**Description**

```php
public getTransactionById (string $id, bool $unconfirmed)
```

Gets a transaction by its id 

 

**Parameters**

* `(string) $id`
: Id of the transaction  
* `(bool) $unconfirmed`
: Search in unconfirmed or confirmed transactions (default: confirmed)  

**Return Values**

`array|false`

> Found transaction as an array or FALSE on failure


<hr />


### WavesKit::getTransactions  

**Description**

```php
public getTransactions (string|null $address, int $limit, string|null $after)
```

Gets transactions for an address 

 

**Parameters**

* `(string|null) $address`
: Address to get transactions (default: null)  
* `(int) $limit`
: Limit of transactions count (default: 100)  
* `(string|null) $after`
: Id of a transaction to paginate from (default: null)  

**Return Values**

`array|false`

> Transactions as an arrays or FALSE on failure


<hr />


### WavesKit::height  

**Description**

```php
public height (void)
```

Gets current blockchain height 

 

**Parameters**

`This function has no parameters.`

**Return Values**

`int|false`

> Current blockchain height or FALSE on failure


<hr />


### WavesKit::isAddressValid  

**Description**

```php
public isAddressValid (mixed $address, mixed $raw)
```

Validates an address by a current blockchain identifier 

 

**Parameters**

* `(mixed) $address`
* `(mixed) $raw`

**Return Values**

`bool`

> Returns TRUE if the address is valid or FALSE on failure


<hr />


### WavesKit::json_decode  

**Description**

```php
public json_decode (string $json)
```

json_decode wrapper for WavesKit 

 

**Parameters**

* `(string) $json`

**Return Values**

`array|false`




<hr />


### WavesKit::keccak256  

**Description**

```php
public keccak256 (string $data)
```

Hashes data with keccak256 

 

**Parameters**

* `(string) $data`
: Data to hash  

**Return Values**

`string`

> Hash result


<hr />


### WavesKit::log  

**Description**

```php
public log (string $level, string $message)
```

Logs a message with a level 

 

**Parameters**

* `(string) $level`
: Message level  
* `(string) $message`
: Message  

**Return Values**

`void`




<hr />


### WavesKit::randomSeed  

**Description**

```php
public randomSeed (int $words)
```

Generates random seed string 

 

**Parameters**

* `(int) $words`
: Words in seed string (default: 15)  

**Return Values**

`string|false`

> Returns random seed or FALSE on failure


<hr />


### WavesKit::secureHash  

**Description**

```php
public secureHash (string $data)
```

Hashes data with blake2b256 and keccak256 

 

**Parameters**

* `(string) $data`
: Data to hash  

**Return Values**

`string`

> Hash result


<hr />


### WavesKit::setAddress  

**Description**

```php
public setAddress (string $address, bool $raw)
```

Sets address 

 

**Parameters**

* `(string) $address`
: Address  
* `(bool) $raw`
: String format is binary or base58 (default: base58)  

**Return Values**

`void`




<hr />


### WavesKit::setBestNode  

**Description**

```php
public setBestNode (void)
```

Internally sets nodes in order of priority by the current height and response time 

 

**Parameters**

`This function has no parameters.`

**Return Values**

`void`




<hr />


### WavesKit::setCryptash  

**Description**

```php
public setCryptash (string $secret, int $iv, int $mac, string $hash)
```

Sets cryptash parameters 

 

**Parameters**

* `(string) $secret`
: Secret string  
* `(int) $iv`
: IV size  
* `(int) $mac`
: MAC size  
* `(string) $hash`
: Hash algorithm (default: sha256)  

**Return Values**

`void`




<hr />


### WavesKit::setLastBitFlip  

**Description**

```php
public setLastBitFlip (bool $enabled)
```

Sets last bit flip option 

 

**Parameters**

* `(bool) $enabled`
: Enable or disable (default: enable)  

**Return Values**

`void`




<hr />


### WavesKit::setNodeAddress  

**Description**

```php
public setNodeAddress (string|array $nodeAddress, int $cacheLifetime, array|null $backupNodes)
```

Sets node address with cache lifetime and backup node addresses 

 

**Parameters**

* `(string|array) $nodeAddress`
: Main node address to work with  
* `(int) $cacheLifetime`
: Cache lifetime in seconds (default: 1)  
* `(array|null) $backupNodes`
: Backup node addresses to fallback  

**Return Values**

`void`




<hr />


### WavesKit::setPairsDatabase  

**Description**

```php
public setPairsDatabase (mixed $path)
```

Sets database pairs path 

 

**Parameters**

* `(mixed) $path`
: Path or an existing PDO for the database  

**Return Values**

`void`




<hr />


### WavesKit::setPrivateKey  

**Description**

```php
public setPrivateKey (string $privateKey, bool $raw)
```

Sets private key 

 

**Parameters**

* `(string) $privateKey`
: Private key  
* `(bool) $raw`
: String format is binary or base58 (default: base58)  

**Return Values**

`void`




<hr />


### WavesKit::setPublicKey  

**Description**

```php
public setPublicKey (string $publicKey, bool $raw)
```

Sets public key 

 

**Parameters**

* `(string) $publicKey`
: Public key  
* `(bool) $raw`
: String format is binary or base58 (default: base58)  

**Return Values**

`void`




<hr />


### WavesKit::setRSEED  

**Description**

```php
public setRSEED (string $rseed)
```

Sets RSEED value (DANGEROUS) 

 

**Parameters**

* `(string) $rseed`
: RSEED value  

**Return Values**

`void`




<hr />


### WavesKit::setSeed  

**Description**

```php
public setSeed (string $seed, bool $raw, string|null $prefix)
```

Sets user seed string 

 

**Parameters**

* `(string) $seed`
: Seed string  
* `(bool) $raw`
: String format is binary or base58 (default: binary)  
* `(string|null) $prefix`
: Prefix string in binary format (default: "\0\0\0\0")  

**Return Values**

`void`




<hr />


### WavesKit::setSodium  

**Description**

```php
public setSodium (bool $enabled)
```

Sets sodium option 

 

**Parameters**

* `(bool) $enabled`
: Enable or disable (default: enable)  

**Return Values**

`void`




<hr />


### WavesKit::sha256  

**Description**

```php
public sha256 (string $data)
```

Hashes data with sha256 

 

**Parameters**

* `(string) $data`
: Data to hash  

**Return Values**

`string`

> Hash result


<hr />


### WavesKit::sha512  

**Description**

```php
public sha512 (string $data)
```

Hashes data with sha512 

 

**Parameters**

* `(string) $data`
: Data to hash  

**Return Values**

`string`

> Hash result


<hr />


### WavesKit::sign  

**Description**

```php
public sign (string $data, string|null $key)
```

Signs a message with a private key 

 

**Parameters**

* `(string) $data`
: Data to sign  
* `(string|null) $key`
: Private key (default: null)  

**Return Values**

`string|false`

> Signature of data or FALSE on failure


<hr />


### WavesKit::timestamp  

**Description**

```php
public timestamp (bool $fromNode)
```

Gets current timestamp 

 

**Parameters**

* `(bool) $fromNode`
: Timstamp from node or local (default: local)  

**Return Values**

`int|false`

> Timestamp or FALSE on failure


<hr />


### WavesKit::txAddressScript  

**Description**

```php
public txAddressScript (string $script, array|null $options)
```

Makes address script transaction as an array 

 

**Parameters**

* `(string) $script`
: Script to set  
* `(array|null) $options`
: Transaction options as an array (default: null)  

**Return Values**

`array|false`

> Address script transaction as an array or FALSE on failure


<hr />


### WavesKit::txAlias  

**Description**

```php
public txAlias (string $alias, array|null $options)
```

Makes alias transaction as an array 

 

**Parameters**

* `(string) $alias`
: Alias  
* `(array|null) $options`
: Transaction options as an array (default: null)  

**Return Values**

`array`

> Alias transaction as an array or FALSE on failure


<hr />


### WavesKit::txAssetScript  

**Description**

```php
public txAssetScript (string $asset, string $script, array|null $options)
```

Makes asset script transaction as an array 

 

**Parameters**

* `(string) $asset`
: Asset id to script change  
* `(string) $script`
: Asset script  
* `(array|null) $options`
: Transaction options as an array (default: null)  

**Return Values**

`array|false`

> Asset script transaction as an array or FALSE on failure


<hr />


### WavesKit::txBody  

**Description**

```php
public txBody (string $tx)
```

Gets transaction body 

 

**Parameters**

* `(string) $tx`
: Transaction as an array  

**Return Values**

`string|false`

> Body of the transaction or FALSE on failure


<hr />


### WavesKit::txBroadcast  

**Description**

```php
public txBroadcast (array $tx)
```

Broadcasts a transaction 

 

**Parameters**

* `(array) $tx`
: Transaction as an array  

**Return Values**

`array|false`

> Broadcasted transaction as an array or FALSE on failure


<hr />


### WavesKit::txBurn  

**Description**

```php
public txBurn (string $asset, int $quantity, array|null $options)
```

Makes burn transaction as an array 

 

**Parameters**

* `(string) $asset`
: Asset id  
* `(int) $quantity`
: Asset quantity to burn  
* `(array|null) $options`
: Transaction options as an array (default: null)  

**Return Values**

`array`

> Burn transaction as an array or FALSE on failure


<hr />


### WavesKit::txData  

**Description**

```php
public txData (array $userData, array|null $options)
```

Makes data transaction as an array 

 

**Parameters**

* `(array) $userData`
: Array of key value pairs  
* `(array|null) $options`
: Transaction options as an array (default: null)  

**Return Values**

`array|false`

> Data transaction as an array or FALSE on failure


<hr />


### WavesKit::txInvokeScript  

**Description**

```php
public txInvokeScript (string $dappAddress, string $function, array|null $args, array|null $payments, array|null $options)
```

Makes invoke script transaction as an array 

 

**Parameters**

* `(string) $dappAddress`
: Address of dApp script  
* `(string) $function`
: Function to call  
* `(array|null) $args`
: Arguments as an array (default: null)  
* `(array|null) $payments`
: Payments as an array (default: null)  
* `(array|null) $options`
: Transaction options as an array (default: null)  

**Return Values**

`array|false`

> Invoke script transaction as an array or FALSE on failure


<hr />


### WavesKit::txIssue  

**Description**

```php
public txIssue (string $name, string $description, int $quantity, int $decimals, bool $reissuable, string $script, array|null $options)
```

Makes issue transaction as an array 

 

**Parameters**

* `(string) $name`
: Asset name  
* `(string) $description`
: Asset description  
* `(int) $quantity`
: Asset quantity to issue  
* `(int) $decimals`
: Asset decimals (0 .. 8)  
* `(bool) $reissuable`
: Asset is reissuable or not  
* `(string) $script`
: Asset script (default: null)  
* `(array|null) $options`
: Transaction options as an array (default: null)  

**Return Values**

`array`

> Issue transaction as an array or FALSE on failure


<hr />


### WavesKit::txLease  

**Description**

```php
public txLease (string $recipient, int $amount, array|null $options)
```

Makes lease transaction as an array 

 

**Parameters**

* `(string) $recipient`
: Recipient address or alias  
* `(int) $amount`
: Amount to lease  
* `(array|null) $options`
: Transaction options as an array (default: null)  

**Return Values**

`array`

> Lease transaction as an array or FALSE on failure


<hr />


### WavesKit::txLeaseCancel  

**Description**

```php
public txLeaseCancel (string $leaseId, array|null $options)
```

Makes lease cancel transaction as an array 

 

**Parameters**

* `(string) $leaseId`
: Lease transaction id to cancel  
* `(array|null) $options`
: Transaction options as an array (default: null)  

**Return Values**

`array`

> Lease cancel transaction as an array or FALSE on failure


<hr />


### WavesKit::txMass  

**Description**

```php
public txMass (array $recipients, array $amounts, string $asset, array|null $options)
```

Makes mass transfer transaction as an array 

 

**Parameters**

* `(array) $recipients`
: Array of recipient addresses or aliases  
* `(array) $amounts`
: Array of amounts to send  
* `(string) $asset`
: Asset id to send  
* `(array|null) $options`
: Transaction options as an array (default: null)  

**Return Values**

`array|false`

> Mass transfer transaction as an array or FALSE on failure


<hr />


### WavesKit::txMonitor  

**Description**

```php
public txMonitor (callable $callback, int $confirmations, int $depth, int $sleep)
```

Monitors for new transaction in realtime 

 

**Parameters**

* `(callable) $callback`
: Function to call when new transactions apear  
* `(int) $confirmations`
: Number of confirmations to reach stability  
* `(int) $depth`
: Minimal height to scan back  
* `(int) $sleep`
: Seconds to sleep between requests  

**Return Values**

`bool`

> TRUE if monitoring was successful or FALSE on failure


<hr />


### WavesKit::txOrder  

**Description**

```php
public txOrder (string $amountAsset, string $priceAsset, bool $isSell, int $amount, int $price, int $expiration, array|null $options)
```

Makes order as an array 

 

**Parameters**

* `(string) $amountAsset`
: Amount asset id  
* `(string) $priceAsset`
: Price asset id  
* `(bool) $isSell`
: Sell or buy  
* `(int) $amount`
: Order amount  
* `(int) $price`
: Order price  
* `(int) $expiration`
: Order expiration  
* `(array|null) $options`
: Order options as an array (default: null)  

**Return Values**

`array`

> Order as an array


<hr />


### WavesKit::txOrderBroadcast  

**Description**

```php
public txOrderBroadcast (array $tx)
```

Broadcasts an order to a matcher 

 

**Parameters**

* `(array) $tx`
: Order as an array  

**Return Values**

`array|false`

> Broadcasted order as an array or FALSE on failure


<hr />


### WavesKit::txOrderCancel  

**Description**

```php
public txOrderCancel (array|string $tx)
```

Cancels an order on a matcher 

 

**Parameters**

* `(array|string) $tx`
: Order as an array or word "ALL" to cancel all orders  

**Return Values**

`bool`

> TRUE on cancel or FALSE on failure


<hr />


### WavesKit::txReissue  

**Description**

```php
public txReissue (string $asset, int $quantity, bool $reissuable, array|null $options)
```

Makes reissue transaction as an array 

 

**Parameters**

* `(string) $asset`
: Asset id  
* `(int) $quantity`
: Asset quantity to reissue  
* `(bool) $reissuable`
: Asset is reissuable or not  
* `(array|null) $options`
: Transaction options as an array (default: null)  

**Return Values**

`array`

> Reissue transaction as an array or FALSE on failure


<hr />


### WavesKit::txSign  

**Description**

```php
public txSign (array $tx, int|null $proofIndex)
```

Signs a transaction 

 

**Parameters**

* `(array) $tx`
: Transaction as an array  
* `(int|null) $proofIndex`
: Index of a proof in proofs (default: null)  

**Return Values**

`array|false`

> Signed transaction as an array or FALSE on failure


<hr />


### WavesKit::txSponsorship  

**Description**

```php
public txSponsorship (string $asset, int , array|null $options)
```

Makes sponsorship transaction as an array 

 

**Parameters**

* `(string) $asset`
: Asset id of the sponsorship  
* `(int) `
: minSponsoredAssetFee    Minimal sponsored asset fee  
* `(array|null) $options`
: Transaction options as an array (default: null)  

**Return Values**

`array|false`

> Sponsorship transaction as an array or FALSE on failure


<hr />


### WavesKit::txTransfer  

**Description**

```php
public txTransfer (string $recipient, int $amount, string|null $asset, array|null $options)
```

Makes transfer transaction as an array 

 

**Parameters**

* `(string) $recipient`
: Recipient address or alias  
* `(int) $amount`
: Amount to send  
* `(string|null) $asset`
: Asset id (default: null)  
* `(array|null) $options`
: Transaction options as an array (default: null)  

**Return Values**

`array`

> Transfer transaction as an array or FALSE on failure


<hr />


### WavesKit::txUpdateAssetInfo  

**Description**

```php
public txUpdateAssetInfo (string $assetId, string $name, string $description, array|null $options)
```

Makes update asset information transaction as an array 

 

**Parameters**

* `(string) $assetId`
: Asset ID  
* `(string) $name`
: Updated asset name  
* `(string) $description`
: Updated asset description  
* `(array|null) $options`
: Transaction options as an array (default: null)  

**Return Values**

`array`

> Update asset information transaction as an array or FALSE on failure


<hr />


### WavesKit::verify  

**Description**

```php
public verify (string $sig, string $data, string|null $key)
```

Verifies a signature of a message by a public key 

 

**Parameters**

* `(string) $sig`
: Signature to verify  
* `(string) $data`
: Signed data  
* `(string|null) $key`
: Public key (default: null)  

**Return Values**

`bool`

> Returns TRUE if the signature is valid or FALSE on failure


<hr />

