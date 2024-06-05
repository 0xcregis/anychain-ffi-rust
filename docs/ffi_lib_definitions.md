# Standard Interface Definition

## Return Value

To facilitate unified processing in various languages, the return value is a json string, specifically defined as
follows

```
{
"success":bool // true indicates successful execution, false indicates failure
"payload":string | json_value // When success is true, this field represents the returned data, when success is false, this field represents the error message
}
```

For convenience, the return values of the following interfaces only explain the business data

### create_mnemonic

Create random mnemonic

Parameters:

| Type   | Name        | Description                  |
|--------|-------------|------------------------------|
| string | language    | Language type (en \| zh-cn)  |
| int    | words_count | Number of words (12, 15, 24) |

Return Value

Type: string

Description: A string composed of words, separated by spaces

### parse_mnemonic

Get the master extended private key

Parameters:

| Type   | Name   | Description                                              |
|--------|--------|----------------------------------------------------------|
| string | phrase | Mnemonic (automatically detects language and word count) |

Return Value

Type: object

Description:

* object.xprv Master extended private key (base58 format starting with xprv)
* object.xpub Master extended public key (base58 format starting with xprv)
* object.hash Hash of the mnemonic

### generate_master_xpub

Generate master extended public key

Parameters:

| Type   | Name       | Description                        |
|--------|------------|------------------------------------|
| string | public_key | Compressed public key (hex format) |
| string | chain_code | Chain code (hex format)            |

Return Value

Type: string

Description: Master extended public key (base58 format starting with xpub)

### create_address

Derive the coin's sub-address based on the sub-extended public key

Parameters:

| Type   | Name       | Description                                          |
|--------|------------|------------------------------------------------------|
| string | xpub       | Wallet public key (base58 format starting with xpub) |
| int    | chain_type | Chain type number                                    |
| int    | index1     | Index 1, starting from 0                             |
| int    | index2     | Index 2 (sub-address index, starting from 0)         |

Return Value

Type: string

Description: Address string value

### build_raw_transaction

Build raw transaction data

Parameters:

| Type   | Name       | Description                          |
|--------|------------|--------------------------------------|
| int    | chain_type | Chain type number                    |
| string | param      | Transaction parameters (json format) |

For param structure explanation, refer to [Transaction Parameter Explanation](chain_param.md)

Return Value

Type: string

Description: Unsigned transaction (hex format)

### raw_transaction_signing_hashes

Calculate multiple hash values for signing an unsigned transaction

Parameters:

| Type   | Name            | Description                                                                                                                        |
|--------|-----------------|------------------------------------------------------------------------------------------------------------------------------------|
| int    | chain_type      | Chain type number                                                                                                                  |
| string | raw_transaction | Unsigned transaction (hex format)                                                                                                  |
| string | reserved        | Additional information, can include master extended public key, derivation path, sub-address balance, address format (json object) |

Return Value

Type: string

Description: Json array containing multiple hash values (hex format)

### insert_signatures

Insert signature data into an unsigned transaction, making it a signed transaction

Parameters:

| Type   | Name            | Description                                                                                                               |
|--------|-----------------|---------------------------------------------------------------------------------------------------------------------------|
| string | signatures      | Multiple signatures, format is a json array containing multiple json objects ({ "r": "xxx", "s": "yyy", "recid": "zzz"})  
| int    | chain_type      | Chain type number                                                                                                         |
| string | raw_transaction | Unsigned transaction (hex format)                                                                                         |
| string | reserved        | Additional information, can include coin public key, sub-address index, sub-address balance, address format (json object) |

Return Value

Type: string

Description: Signed transaction (hex format)

### decode_raw_transaction

Convert the broadcast transaction data stream into a readable json object

Parameters:

| Type   | Name       | Description                       |
|--------|------------|-----------------------------------|
| string | raw_tx     | Broadcast transaction data stream |
| int    | chain_type | Chain type number                 |

Return Value

Type: string

Description: Transaction data json object

### verify_address

Verify whether the address is legal

Parameters:

| Type   | Name       | Description                  |
|--------|------------|------------------------------|
| string | address    | Coin address, case sensitive |
| int    | chain_type | Chain type number            |

Return Value

Type:bool

Description: true is legal, false is illegal

### estimate_bandwidth

Estimate the bandwidth resources consumed by a transaction

Parameters:

| Type   | Name       | Description                                                      |
|--------|------------|------------------------------------------------------------------|
| string | params     | Transaction parameters (json format)                             |
| int    | chain_type | Chain type number                                                |
| string | reserved   | Additional information, can include address format (json format) |

Return Value

Type: string

Description: Quantity of bandwidth consumed by the transaction

### transaction_parameters_use_case

Print different types of transaction parameter use cases

Parameters:

| Type | Name       | Description       |
|------|------------|-------------------|
| int  | chain_type | Chain type number |

Return Value

Type: string

Description: Transaction parameter use case (json format)

### keygen (cregis_keygen for iOS C call)

Generate random key pair

Return Value

Type: string

Description: json string: {"secret_key": "fd06a4e8764bb02312eb7e4067b818df14664bb43326f7c0dd777e692edf4699", "
public_key": "02f251e6e8a793701b0dbe04db77461d624220d1afd0d48bf335488c527d51eb08",
"secret_key_hash": "60b7114a078cfc2f5ea00c885037fdf544ede3fc"}

### sign

Sign any data

Parameters:

| Type   | Name       | Description              |
|--------|------------|--------------------------|
| string | data       | Original string          |
| string | secret_key | Private key (hex format) |

Return Value

Type: string

Description: Signature (hex format)

### verify

Verify whether the signature passes

Parameters:

| Type   | Name       | Description             |
|--------|------------|-------------------------|
| string | data       | Original string         |
| string | signature  | Signature (hex format)  |
| string | public_key | Public key (hex format) |

Return Value

Type: string

Description: Text description of the verification result

### hash

Return the ripemd hash value of the input data

Parameters:

| Type   | Name | Description     |
|--------|------|-----------------|
| string | data | Original string |

Return Value

Type: string

Description: Hash value (hex format)

```
