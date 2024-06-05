# Specification

Here we provide a unified definition of relevant professional terms to facilitate accurate understanding of the SDK in
subsequent descriptions.

## Private key

A 256-bit (32-byte) integer used for signing or exporting public keys, usually represented in Hex format (64
characters), such as

```
0838b9c472def15e82fed31208944a683b37dfb09f5a04febc45416bd8b00161
```

## Public key

A point P(x,y) on the ECC curve, where x and y are both 32-byte integers. The corresponding public key can be calculated
from the private key, but the reverse is not possible. There are two formats for public keys. One is the full format, 65
bytes in size, starting with 04, followed by the values of x and y. The other is the compressed format. Since y can be
calculated from x, only x is displayed. The size is 33 bytes. If y is an even number, it starts with 02. If y is an odd
number, it starts with 03. The following 32 bytes are the value of x. Public keys can generate addresses.

## Mnemonic

A sentence composed of a series of English words representing a value.

## Seed

The bytes array generated by mapping the mnemonic, either 128bits or 256bits.

## Extended key

A structure for recursive extension, containing key, hierarchy, chain code, and other information, represented in base58
encoding.

## Extended private key

An ExtendedKey with a private key, which can generate an extended public key, derive a child extended private key, or
export the corresponding private key.

## Extended public key

An ExtendedKey with a public key, which can derive a child extended public key or export the corresponding public key.

## Derive path

Used to define the generation path of the extended key, conforming to
the [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) specification, the format is

```
m / purpose' / coin_type' / account' / change / address_index
```

For example m / 44' / 0' / 0' / 0 / 0

## Chain code table:

| Chain Name         | Chain Number | Series |
|--------------------|--------------|--------|
| Bitcoin            | 0            | BTC    |
| BitcoinTestnet     | 1            | BTC    |
| BitcoinCash        | 5            | BTC    |
| BitcoinCashTestnet | 51           | BTC    |
| Litecoin           | 2            | BTC    |
| LitecoinTestnet    | 21           | BTC    |
| Dogecoin           | 3            | BTC    |
| DogecoinTestnet    | 31           | BTC    |

```