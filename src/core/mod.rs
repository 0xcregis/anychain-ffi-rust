use _type::{ChainType, CurveType};
use anychain_bitcoin::{
    public_key::BitcoinPublicKey, Bitcoin, BitcoinAddress, BitcoinCash, BitcoinCashTestnet,
    BitcoinFormat, BitcoinTestnet, Dogecoin, DogecoinTestnet, Litecoin, LitecoinTestnet,
};
use anychain_core::{Address, PublicKey};
use anychain_ethereum::{
    Arbitrum, ArbitrumGoerli, Avalanche, AvalancheTestnet, Base, BaseGoerli, BinanceSmartChain,
    BinanceSmartChainTestnet, Ethereum, EthereumAddress, EthereumClassic, EthereumFormat,
    EthereumPublicKey, Goerli, HuobiEco, HuobiEcoTestnet, Kotti, Mumbai, Okex, OkexTestnet, OpBnb,
    OpBnbTestnet, Optimism, OptimismGoerli, Polygon, Sepolia,
};
use anychain_kms::{
    bip32::{
        ChildNumber, DerivationPath, ExtendedKey, ExtendedKeyAttrs, HmacSha512, Prefix,
        XprvSecp256k1, XpubSecp256k1,
    },
    bip39::{Language, Mnemonic, MnemonicType, Seed},
    crypto::ripemd,
};
use anychain_tron::{TronAddress, TronFormat, TronPublicKey};
use anyhow::{anyhow, Result};
use digest::Mac;
use libaes::Cipher;
use rand::thread_rng;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{str::FromStr, time::SystemTime};

mod btc;
mod eth;
mod trx;

mod _type;
mod util;

/**
* Create a mnemonic
* argument 0: lang_code, optional values: en, zh-cn
* argument 1: word_count, number of words, optional values: 12, 15, 18, 21, 24
*/
pub fn create_mnemonic(lang_code: String, size: u8) -> Result<Value> {
    let word_count = MnemonicType::for_word_count(size.into())?;
    let language = Language::from_language_code(lang_code.as_str())
        .ok_or(anychain_kms::bip39::ErrorKind::InvalidWord)?;
    let mnemonic = Mnemonic::new(word_count, language);
    Ok(Value::String(mnemonic.phrase().to_string()))
}

/**
 * Parse the mnemonic to get wallet attributes
 * phrase: Mnemonic
 * return {"hash": "wallet_hash_id", "xpub": "master extended public key"}
 */
pub fn parse_mnemonic(phrase: String) -> Result<Value> {
    if let Some(language) = Language::from_phrase(phrase.as_str()) {
        Mnemonic::validate(phrase.as_str(), language)?;
        let mut seed = Vec::<u8>::new();
        let mnemonic = Mnemonic::from_phrase(phrase.as_str(), language)?;
        seed.extend_from_slice(Seed::new(&mnemonic, "").as_bytes());
        let hash = ripemd(&seed);
        let xprv = XprvSecp256k1::new(seed)?;
        let xpub = xprv.public_key().to_string(Prefix::XPUB);
        let data = json!({
            "xpub": xpub,
            "hash": hash,
        });
        Ok(data)
    } else {
        Err(anyhow::Error::msg("invalid phrase"))
    }
}

pub fn generate_master_xpub(public_key: String, chain_code: String) -> Result<Value> {
    let pk = serde_json::from_str::<Value>(&public_key)?;
    let pk = pk.as_array().unwrap();
    let pk: Vec<u8> = pk.iter().map(|byte| byte.as_u64().unwrap() as u8).collect();

    let cc = hex::decode(chain_code)?;

    if pk.len() != 33 {
        return Err(anyhow!("Invalid public key length"));
    }
    if cc.len() != 32 {
        return Err(anyhow!("Invalid chain code length"));
    }

    let mut key_bytes = [0u8; 33];
    let mut chain_code = [0u8; 32];

    chain_code.copy_from_slice(&cc);
    key_bytes.copy_from_slice(&pk);

    let attrs = ExtendedKeyAttrs {
        depth: 0,
        parent_fingerprint: [0u8; 4],
        chain_code,
        child_number: ChildNumber(0),
    };

    let xpub = ExtendedKey {
        prefix: Prefix::XPUB,
        attrs,
        key_bytes,
    };

    Ok(Value::String(
        XpubSecp256k1::try_from(xpub)?.to_string(Prefix::XPUB),
    ))
}

pub fn create_address(
    xpub: String,
    chain_type: u32,
    index1: u32,
    index2: u32,
    format: String,
) -> Result<Value> {
    let path = format!("m/44/{}/0/{}/{}", chain_type, index1, index2);
    let chain_type = ChainType::try_from(chain_type)?;

    match chain_type.curve() {
        CurveType::Secp256k1 => {
            let xpub = XpubSecp256k1::from_str(xpub.as_str())?;
            let derive_path = DerivationPath::from_str(path.as_str())?;
            let pubkey = *xpub.derive_from_path(&derive_path)?.public_key();
            match chain_type {
                ChainType::Bitcoin => {
                    let fmt = match format.as_str() {
                        "" | "1" => BitcoinFormat::P2PKH,
                        "3" => BitcoinFormat::P2SH_P2WPKH,
                        "bc1" => BitcoinFormat::Bech32,
                        _ => return Err(anyhow!("invalid address format for bitcoin")),
                    };
                    let address =
                        BitcoinPublicKey::<Bitcoin>::from_secp256k1_public_key(pubkey, true)
                            .to_address(&fmt)?;
                    Ok(Value::String(address.to_string()))
                }
                ChainType::BitcoinTestnet => {
                    let fmt = match format.as_str() {
                        "" | "1" => BitcoinFormat::P2PKH,
                        "3" => BitcoinFormat::P2SH_P2WPKH,
                        "bc1" => BitcoinFormat::Bech32,
                        _ => return Err(anyhow!("invalid address format for bitcoin testnet")),
                    };
                    let address =
                        BitcoinPublicKey::<BitcoinTestnet>::from_secp256k1_public_key(pubkey, true)
                            .to_address(&fmt)?;
                    Ok(Value::String(address.to_string()))
                }
                ChainType::BitcoinCash => {
                    let address =
                        BitcoinPublicKey::<BitcoinCash>::from_secp256k1_public_key(pubkey, true)
                            .to_address(&BitcoinFormat::CashAddr)?;
                    Ok(Value::String(address.to_string()))
                }
                ChainType::BitcoinCashTestnet => {
                    let address =
                        BitcoinPublicKey::<BitcoinCashTestnet>::from_secp256k1_public_key(
                            pubkey, true,
                        )
                        .to_address(&BitcoinFormat::CashAddr)?;
                    Ok(Value::String(address.to_string()))
                }
                ChainType::Litecoin => {
                    let fmt = match format.as_str() {
                        "" | "1" => BitcoinFormat::P2PKH,
                        "3" => BitcoinFormat::P2SH_P2WPKH,
                        "bc1" => BitcoinFormat::Bech32,
                        _ => return Err(anyhow!("invalid address format for litecoin")),
                    };
                    let address =
                        BitcoinPublicKey::<Litecoin>::from_secp256k1_public_key(pubkey, true)
                            .to_address(&fmt)?;
                    Ok(Value::String(address.to_string()))
                }
                ChainType::LitecoinTestnet => {
                    let fmt = match format.as_str() {
                        "" | "1" => BitcoinFormat::P2PKH,
                        "3" => BitcoinFormat::P2SH_P2WPKH,
                        "bc1" => BitcoinFormat::Bech32,
                        _ => return Err(anyhow!("invalid address format for litecoin testnet")),
                    };
                    let address = BitcoinPublicKey::<LitecoinTestnet>::from_secp256k1_public_key(
                        pubkey, true,
                    )
                    .to_address(&fmt)?;
                    Ok(Value::String(address.to_string()))
                }
                ChainType::Dogecoin => {
                    let fmt = match format.as_str() {
                        "" | "1" => BitcoinFormat::P2PKH,
                        "3" => BitcoinFormat::P2SH_P2WPKH,
                        "bc1" => BitcoinFormat::Bech32,
                        _ => return Err(anyhow!("invalid address format for dogecoin")),
                    };
                    let address =
                        BitcoinPublicKey::<Dogecoin>::from_secp256k1_public_key(pubkey, true)
                            .to_address(&fmt)?;
                    Ok(Value::String(address.to_string()))
                }
                ChainType::DogecoinTestnet => {
                    let fmt = match format.as_str() {
                        "" | "1" => BitcoinFormat::P2PKH,
                        "3" => BitcoinFormat::P2SH_P2WPKH,
                        "bc1" => BitcoinFormat::Bech32,
                        _ => return Err(anyhow!("invalid address format for dogecoin testnet")),
                    };
                    let address = BitcoinPublicKey::<DogecoinTestnet>::from_secp256k1_public_key(
                        pubkey, true,
                    )
                    .to_address(&fmt)?;
                    Ok(Value::String(address.to_string()))
                }
                ChainType::Ethereum
                | ChainType::Goerli
                | ChainType::Sepolia
                | ChainType::EthereumClassic
                | ChainType::Kotti
                | ChainType::Polygon
                | ChainType::Mumbai
                | ChainType::Arbitrum
                | ChainType::ArbitrumGoerli
                | ChainType::Optimism
                | ChainType::OptimismGoerli
                | ChainType::Avalanche
                | ChainType::AvalancheTestnet
                | ChainType::Base
                | ChainType::BaseGoerli
                | ChainType::BinanceSmartChain
                | ChainType::BinanceSmartChainTestnet
                | ChainType::HuobiEco
                | ChainType::HuobiEcoTestnet
                | ChainType::Okex
                | ChainType::OkexTestnet
                | ChainType::OpBnb
                | ChainType::OpBnbTestnet => {
                    let address = EthereumPublicKey::from_secp256k1_public_key(pubkey)
                        .to_address(&EthereumFormat::Standard)?;
                    Ok(Value::String(address.to_string().to_lowercase()))
                }
                ChainType::Tron | ChainType::TronTestnet => {
                    let address = TronPublicKey::from_secp256k1_public_key(pubkey)
                        .to_address(&TronFormat::Standard)?;
                    Ok(Value::String(address.to_string()))
                }
            }
        } // CurveType::Ed25519 => match chain_type {
          //     ChainType::Solana | ChainType::SolanaTestnet => {
          //         todo!()
          //     }
          //     _ => return Err(anyhow!("the blockchain does not support ed25519 curve")),
          // },
    }
}

/// Returns the messages of the transaction for signing
pub fn generate_signing_messages(chain_type: u32, tx: String, reserved: String) -> Result<Value> {
    let chain_type = ChainType::try_from(chain_type)?;

    match chain_type {
        ChainType::Bitcoin => btc::generate_signing_messages::<Bitcoin>(tx, reserved),
        ChainType::BitcoinTestnet => btc::generate_signing_messages::<BitcoinTestnet>(tx, reserved),
        ChainType::BitcoinCash => btc::generate_signing_messages::<BitcoinCash>(tx, reserved),
        ChainType::BitcoinCashTestnet => {
            btc::generate_signing_messages::<BitcoinCashTestnet>(tx, reserved)
        }
        ChainType::Litecoin => btc::generate_signing_messages::<Litecoin>(tx, reserved),
        ChainType::LitecoinTestnet => {
            btc::generate_signing_messages::<LitecoinTestnet>(tx, reserved)
        }
        ChainType::Dogecoin => btc::generate_signing_messages::<Dogecoin>(tx, reserved),
        ChainType::DogecoinTestnet => {
            btc::generate_signing_messages::<DogecoinTestnet>(tx, reserved)
        }
        ChainType::Ethereum => eth::generate_signing_messages::<Ethereum>(tx),
        ChainType::Goerli => eth::generate_signing_messages::<Goerli>(tx),
        ChainType::Sepolia => eth::generate_signing_messages::<Sepolia>(tx),
        ChainType::EthereumClassic => eth::generate_signing_messages::<EthereumClassic>(tx),
        ChainType::Kotti => eth::generate_signing_messages::<Kotti>(tx),
        ChainType::Polygon => eth::generate_signing_messages::<Polygon>(tx),
        ChainType::Mumbai => eth::generate_signing_messages::<Mumbai>(tx),
        ChainType::Arbitrum => eth::generate_signing_messages::<Arbitrum>(tx),
        ChainType::ArbitrumGoerli => eth::generate_signing_messages::<ArbitrumGoerli>(tx),
        ChainType::Optimism => eth::generate_signing_messages::<Optimism>(tx),
        ChainType::OptimismGoerli => eth::generate_signing_messages::<OptimismGoerli>(tx),
        ChainType::Avalanche => eth::generate_signing_messages::<Avalanche>(tx),
        ChainType::AvalancheTestnet => eth::generate_signing_messages::<AvalancheTestnet>(tx),
        ChainType::Base => eth::generate_signing_messages::<Base>(tx),
        ChainType::BaseGoerli => eth::generate_signing_messages::<BaseGoerli>(tx),
        ChainType::OpBnb => eth::generate_signing_messages::<OpBnb>(tx),
        ChainType::OpBnbTestnet => eth::generate_signing_messages::<OpBnbTestnet>(tx),
        ChainType::BinanceSmartChain => eth::generate_signing_messages::<BinanceSmartChain>(tx),
        ChainType::BinanceSmartChainTestnet => {
            eth::generate_signing_messages::<BinanceSmartChainTestnet>(tx)
        }
        ChainType::HuobiEco => eth::generate_signing_messages::<HuobiEco>(tx),
        ChainType::HuobiEcoTestnet => eth::generate_signing_messages::<HuobiEcoTestnet>(tx),
        ChainType::Okex => eth::generate_signing_messages::<Okex>(tx),
        ChainType::OkexTestnet => eth::generate_signing_messages::<OkexTestnet>(tx),
        ChainType::Tron | ChainType::TronTestnet => trx::generate_signing_messages(tx),
    }
}

/// Insert the given signatures into the transaction parameter and return
/// the final signed transaction stream to be broadcasted
pub fn insert_signatures(
    signatures: String,
    chain_type: u32,
    tx: String,
    reserved: String,
) -> Result<Value> {
    let chain_type = ChainType::try_from(chain_type)?;

    match chain_type {
        ChainType::Bitcoin => btc::insert_signatures::<Bitcoin>(signatures, tx, reserved),
        ChainType::BitcoinTestnet => {
            btc::insert_signatures::<BitcoinTestnet>(signatures, tx, reserved)
        }
        ChainType::BitcoinCash => btc::insert_signatures::<BitcoinCash>(signatures, tx, reserved),
        ChainType::BitcoinCashTestnet => {
            btc::insert_signatures::<BitcoinCashTestnet>(signatures, tx, reserved)
        }
        ChainType::Litecoin => btc::insert_signatures::<Litecoin>(signatures, tx, reserved),
        ChainType::LitecoinTestnet => {
            btc::insert_signatures::<LitecoinTestnet>(signatures, tx, reserved)
        }
        ChainType::Dogecoin => btc::insert_signatures::<Dogecoin>(signatures, tx, reserved),
        ChainType::DogecoinTestnet => {
            btc::insert_signatures::<DogecoinTestnet>(signatures, tx, reserved)
        }
        ChainType::Ethereum => eth::insert_signatures::<Ethereum>(signatures, tx),
        ChainType::Goerli => eth::insert_signatures::<Goerli>(signatures, tx),
        ChainType::Sepolia => eth::insert_signatures::<Sepolia>(signatures, tx),
        ChainType::EthereumClassic => eth::insert_signatures::<EthereumClassic>(signatures, tx),
        ChainType::Kotti => eth::insert_signatures::<Kotti>(signatures, tx),
        ChainType::Polygon => eth::insert_signatures::<Polygon>(signatures, tx),
        ChainType::Mumbai => eth::insert_signatures::<Mumbai>(signatures, tx),
        ChainType::Arbitrum => eth::insert_signatures::<Arbitrum>(signatures, tx),
        ChainType::ArbitrumGoerli => eth::insert_signatures::<ArbitrumGoerli>(signatures, tx),
        ChainType::Optimism => eth::insert_signatures::<Optimism>(signatures, tx),
        ChainType::OptimismGoerli => eth::insert_signatures::<OptimismGoerli>(signatures, tx),
        ChainType::Avalanche => eth::insert_signatures::<Avalanche>(signatures, tx),
        ChainType::AvalancheTestnet => eth::insert_signatures::<AvalancheTestnet>(signatures, tx),
        ChainType::Base => eth::insert_signatures::<Base>(signatures, tx),
        ChainType::BaseGoerli => eth::insert_signatures::<BaseGoerli>(signatures, tx),
        ChainType::BinanceSmartChain => eth::insert_signatures::<BinanceSmartChain>(signatures, tx),
        ChainType::BinanceSmartChainTestnet => {
            eth::insert_signatures::<BinanceSmartChainTestnet>(signatures, tx)
        }
        ChainType::OpBnb => eth::insert_signatures::<OpBnb>(signatures, tx),
        ChainType::OpBnbTestnet => eth::insert_signatures::<OpBnbTestnet>(signatures, tx),
        ChainType::HuobiEco => eth::insert_signatures::<HuobiEco>(signatures, tx),
        ChainType::HuobiEcoTestnet => eth::insert_signatures::<HuobiEcoTestnet>(signatures, tx),
        ChainType::Okex => eth::insert_signatures::<Okex>(signatures, tx),
        ChainType::OkexTestnet => eth::insert_signatures::<OkexTestnet>(signatures, tx),
        ChainType::Tron | ChainType::TronTestnet => trx::insert_signatures(signatures, tx),
    }
}

/// Decode the raw transaction byte stream to human-readable json object
pub fn decode_raw_transaction(raw_tx: String, chain_type: u32) -> Result<Value> {
    let chain_type = ChainType::try_from(chain_type)?;

    match chain_type {
        ChainType::Bitcoin => btc::decode_raw_transaction::<Bitcoin>(raw_tx),
        ChainType::BitcoinTestnet => btc::decode_raw_transaction::<BitcoinTestnet>(raw_tx),
        ChainType::BitcoinCash => btc::decode_raw_transaction::<BitcoinCash>(raw_tx),
        ChainType::BitcoinCashTestnet => btc::decode_raw_transaction::<BitcoinCashTestnet>(raw_tx),
        ChainType::Litecoin => btc::decode_raw_transaction::<Litecoin>(raw_tx),
        ChainType::LitecoinTestnet => btc::decode_raw_transaction::<LitecoinTestnet>(raw_tx),
        ChainType::Dogecoin => btc::decode_raw_transaction::<Dogecoin>(raw_tx),
        ChainType::DogecoinTestnet => btc::decode_raw_transaction::<DogecoinTestnet>(raw_tx),
        ChainType::Ethereum => eth::decode_raw_transaction::<Ethereum>(raw_tx),
        ChainType::Goerli => eth::decode_raw_transaction::<Goerli>(raw_tx),
        ChainType::Sepolia => eth::decode_raw_transaction::<Sepolia>(raw_tx),
        ChainType::Arbitrum => eth::decode_raw_transaction::<Arbitrum>(raw_tx),
        ChainType::ArbitrumGoerli => eth::decode_raw_transaction::<ArbitrumGoerli>(raw_tx),
        ChainType::Avalanche => eth::decode_raw_transaction::<Avalanche>(raw_tx),
        ChainType::AvalancheTestnet => eth::decode_raw_transaction::<AvalancheTestnet>(raw_tx),
        ChainType::Base => eth::decode_raw_transaction::<Base>(raw_tx),
        ChainType::BaseGoerli => eth::decode_raw_transaction::<BaseGoerli>(raw_tx),
        ChainType::BinanceSmartChain => eth::decode_raw_transaction::<BinanceSmartChain>(raw_tx),
        ChainType::BinanceSmartChainTestnet => {
            eth::decode_raw_transaction::<BinanceSmartChainTestnet>(raw_tx)
        }
        ChainType::EthereumClassic => eth::decode_raw_transaction::<EthereumClassic>(raw_tx),
        ChainType::Kotti => eth::decode_raw_transaction::<Kotti>(raw_tx),
        ChainType::Okex => eth::decode_raw_transaction::<Okex>(raw_tx),
        ChainType::OkexTestnet => eth::decode_raw_transaction::<OkexTestnet>(raw_tx),
        ChainType::HuobiEco => eth::decode_raw_transaction::<HuobiEco>(raw_tx),
        ChainType::HuobiEcoTestnet => eth::decode_raw_transaction::<HuobiEcoTestnet>(raw_tx),
        ChainType::OpBnb => eth::decode_raw_transaction::<OpBnb>(raw_tx),
        ChainType::OpBnbTestnet => eth::decode_raw_transaction::<OpBnbTestnet>(raw_tx),
        ChainType::Optimism => eth::decode_raw_transaction::<Optimism>(raw_tx),
        ChainType::OptimismGoerli => eth::decode_raw_transaction::<OptimismGoerli>(raw_tx),
        ChainType::Polygon => eth::decode_raw_transaction::<Polygon>(raw_tx),
        ChainType::Mumbai => eth::decode_raw_transaction::<Mumbai>(raw_tx),
        ChainType::Tron | ChainType::TronTestnet => trx::decode_raw_transaction(raw_tx),
    }
}

pub fn verify_address(address: String, chain_type: u32) -> Result<Value> {
    let chain_type = ChainType::try_from(chain_type)?;
    let is_valid = match chain_type {
        ChainType::Bitcoin => BitcoinAddress::<Bitcoin>::is_valid(&address),
        ChainType::BitcoinTestnet => BitcoinAddress::<BitcoinTestnet>::is_valid(&address),
        ChainType::BitcoinCash => BitcoinAddress::<BitcoinCash>::is_valid(&address),
        ChainType::BitcoinCashTestnet => BitcoinAddress::<BitcoinCashTestnet>::is_valid(&address),
        ChainType::Litecoin => BitcoinAddress::<Litecoin>::is_valid(&address),
        ChainType::LitecoinTestnet => BitcoinAddress::<LitecoinTestnet>::is_valid(&address),
        ChainType::Dogecoin => BitcoinAddress::<Dogecoin>::is_valid(&address),
        ChainType::DogecoinTestnet => BitcoinAddress::<DogecoinTestnet>::is_valid(&address),
        ChainType::Ethereum
        | ChainType::Goerli
        | ChainType::Sepolia
        | ChainType::EthereumClassic
        | ChainType::Kotti
        | ChainType::Polygon
        | ChainType::Mumbai
        | ChainType::Arbitrum
        | ChainType::ArbitrumGoerli
        | ChainType::Optimism
        | ChainType::OptimismGoerli
        | ChainType::Avalanche
        | ChainType::AvalancheTestnet
        | ChainType::Base
        | ChainType::BaseGoerli
        | ChainType::OpBnb
        | ChainType::OpBnbTestnet
        | ChainType::BinanceSmartChain
        | ChainType::BinanceSmartChainTestnet
        | ChainType::HuobiEco
        | ChainType::HuobiEcoTestnet
        | ChainType::Okex
        | ChainType::OkexTestnet => EthereumAddress::is_valid(&address),
        ChainType::Tron | ChainType::TronTestnet => TronAddress::is_valid(&address),
    };
    Ok(Value::Bool(is_valid))
}

pub fn transfer_params_abi(address: String, amount: String, chain_type: u32) -> Result<Value> {
    let chain_type = ChainType::try_from(chain_type)?;
    match chain_type {
        ChainType::Tron | ChainType::TronTestnet => {
            trx::trc20_transfer_params_abi(&address, &amount)
        }
        _ => panic!("Unsupported chain type"),
    }
}

pub fn approve_params_abi(address: String, amount: String, chain_type: u32) -> Result<Value> {
    let chain_type = ChainType::try_from(chain_type)?;
    match chain_type {
        ChainType::Tron | ChainType::TronTestnet => {
            trx::trc20_approve_params_abi(&address, &amount)
        }
        _ => panic!("Unsupported chain type"),
    }
}

pub fn estimate_bandwidth(tx: String, chain_type: u32, reserved: String) -> Result<Value> {
    let chain_type = ChainType::try_from(chain_type)?;

    match chain_type {
        ChainType::Tron | ChainType::TronTestnet => trx::estimate_bandwidth(tx),
        ChainType::Bitcoin => btc::estimate_bandwidth::<Bitcoin>(tx, reserved),
        ChainType::BitcoinTestnet => btc::estimate_bandwidth::<BitcoinTestnet>(tx, reserved),
        ChainType::BitcoinCash => btc::estimate_bandwidth::<BitcoinCash>(tx, reserved),
        ChainType::BitcoinCashTestnet => {
            btc::estimate_bandwidth::<BitcoinCashTestnet>(tx, reserved)
        }
        ChainType::Litecoin => btc::estimate_bandwidth::<Litecoin>(tx, reserved),
        ChainType::LitecoinTestnet => btc::estimate_bandwidth::<LitecoinTestnet>(tx, reserved),
        ChainType::Dogecoin => btc::estimate_bandwidth::<Dogecoin>(tx, reserved),
        ChainType::DogecoinTestnet => btc::estimate_bandwidth::<DogecoinTestnet>(tx, reserved),
        _ => panic!("Unsupported chain type"),
    }
}

pub fn keygen() -> Result<Value> {
    let mut rng = thread_rng();
    let sk = libsecp256k1::SecretKey::random(&mut rng);
    let pk = libsecp256k1::PublicKey::from_secret_key(&sk);
    let sk = sk.serialize().to_vec();
    let pk = pk.serialize_compressed().to_vec();
    let sk_hex = hex::encode(&sk);
    let skhash = ripemd(sk_hex.as_bytes());
    let sk = hex::encode(&sk);
    let pk = hex::encode(&pk);

    Ok(json!({
        "secret_key": sk,
        "public_key": pk,
        "secret_key_hash": skhash
    }))
}

pub fn sign(data: &str, sk: &str) -> Result<Value> {
    let sk = hex::decode(sk)?;
    let sk = libsecp256k1::SecretKey::parse_slice(&sk)?;

    let elapsed_minutes = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs()
        / 60
        / 30;

    let msg = hmac_digest(data, elapsed_minutes)?;
    let msg = libsecp256k1::Message::parse_slice(&msg)?;

    let sig = libsecp256k1::sign(&msg, &sk).0;
    let sig = sig.serialize().to_vec();
    let sig = hex::encode(&sig);

    Ok(Value::String(sig))
}

pub fn verify(data: &str, signature: &str, pk: &str) -> Result<Value> {
    let elapsed_half_hours = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs()
        / 60
        / 30;

    match do_verify(data, signature, pk, elapsed_half_hours) {
        Ok(true) => Ok(Value::Bool(true)),
        // case when the time has reached the next half-hour of the signing moment
        Ok(false) => match do_verify(data, signature, pk, elapsed_half_hours - 1) {
            Ok(t) => Ok(Value::Bool(t)),
            Err(e) => Err(anyhow!("{}", e)),
        },
        Err(e) => Err(anyhow!("{}", e)),
    }
}

pub fn hash(data: &str) -> Result<Value> {
    Ok(Value::String(ripemd(data.as_bytes())))
}

pub fn encrypt(data: &str, secret_key: &str) -> Result<Value> {
    let data = data.as_bytes();
    let (key, iv) = key_and_iv(secret_key)?;
    let cipher = Cipher::new_128(&key);
    let data = cipher.cbc_encrypt(&iv, data);
    Ok(Value::String(hex::encode(&data)))
}

pub fn decrypt(data: &str, secret_key: &str) -> Result<Value> {
    let data = hex::decode(data)?;
    let (key, iv) = key_and_iv(secret_key)?;
    let cipher = Cipher::new_128(&key);
    let data = cipher.cbc_decrypt(&iv, &data);
    Ok(Value::String(String::from_utf8(data)?))
}

pub fn json_digest(json: &str) -> Result<Value> {
    let val = serde_json::from_str::<Value>(json)?;
    let stream = serialize_json(&val);
    let hash = ripemd(stream.as_bytes());
    Ok(Value::String(hash))
}

fn serialize_json(val: &Value) -> String {
    match val {
        Value::Null => "".to_string(),
        Value::Bool(b) => format!("{}", b),
        Value::Number(n) => format!("{}", n),
        Value::String(s) => s.clone(),
        Value::Array(arr) => {
            let mut ret = String::new();
            for elem in arr {
                ret = format!("{}{}", ret, serialize_json(elem));
            }
            ret
        }
        Value::Object(map) => {
            let mut ret = String::new();
            for (key, value) in map {
                ret = format!("{}{}{}", ret, key, serialize_json(value));
            }
            ret
        }
    }
}

fn do_verify(data: &str, signature: &str, pk: &str, elapsed_half_hours: u64) -> Result<bool> {
    let msg = hmac_digest(data, elapsed_half_hours)?;
    let msg = libsecp256k1::Message::parse_slice(&msg)?;
    let sig = hex::decode(signature)?;
    let sig = libsecp256k1::Signature::parse_standard_slice(&sig)?;
    let pk = hex::decode(pk)?;
    let pk = libsecp256k1::PublicKey::parse_slice(&pk, None)?;
    Ok(libsecp256k1::verify(&msg, &sig, &pk))
}

fn hmac_digest(data: &str, elapsed_half_hours: u64) -> Result<Vec<u8>> {
    let data = data.as_bytes();

    let key = [
        elapsed_half_hours.to_le_bytes().to_vec(), // elapsed half-hours is of type u64, which is 8 bytes
        vec![0; 24],                               // pad 24 zeros to form the key for HmacSha512
    ]
    .concat();

    let mut hasher = HmacSha512::new_from_slice(&key)?;
    hasher.update(data);

    let hash = hasher.finalize().into_bytes();
    let (msg, _) = hash.split_at(32);
    let msg = msg.to_vec();

    Ok(msg)
}

fn key_and_iv(secret_key: &str) -> Result<([u8; 16], [u8; 16])> {
    let sk = hex::decode(secret_key)?;
    let skhash = Sha256::digest(&sk);
    let mut key: [u8; 16] = [0; 16];
    let mut iv: [u8; 16] = [0; 16];

    let mut j = 0;
    let mut k = 0;
    for i in 0..skhash.len() {
        if i % 2 == 0 {
            key[j] = skhash[i];
            j += 1;
        } else {
            iv[k] = skhash[i];
            k += 1;
        }
    }

    Ok((key, iv))
}

// use solana_rpc_client::rpc_client::RpcClient;

// use std::net::{TcpListener, TcpStream};
// use tungstenite::{accept, connect, stream::MaybeTlsStream, Message as WMessage, WebSocket};
// use url::Url;

// fn server_send(ws: &mut WebSocket<TcpStream>, s: String) {
//     let msg = WMessage::from(s);
//     ws.write_message(msg).unwrap();
// }

// fn server_receive(ws: &mut WebSocket<TcpStream>) -> String {
//     let msg = ws.read_message().unwrap();
//     msg.to_string()
// }

// fn client_send(ws: &mut WebSocket<MaybeTlsStream<TcpStream>>, s: String) {
//     let msg = WMessage::from(s);
//     ws.write_message(msg).unwrap();
// }

// fn client_receive(ws: &mut WebSocket<MaybeTlsStream<TcpStream>>) -> String {
//     let msg = ws.read_message().unwrap();
//     msg.to_string()
// }

// fn server_init() -> WebSocket<TcpStream> {
//     let listener = TcpListener::bind("127.0.0.1:8000").unwrap();
//     let (conn, _) = listener.accept().unwrap();
//     let ws = accept(conn).unwrap();
//     ws
// }

// fn client_init() -> WebSocket<MaybeTlsStream<TcpStream>> {
//     connect(Url::parse("ws://127.0.0.1:8000").unwrap()).unwrap().0
// }

// #[test]
// fn test() {
//     let xpub = "xpub661MyMwAqRbcFRmatjv3Ff2dY5rQHNpuEYZ2CbjQ8Qn13taUMRJ82CyYrHApzgE2HRFV3iWMQkNYqAQmPazy2cdNn16phg3BexnjRFqJ8CP";
//     let from = create_address(xpub.to_string(), 0, 0, 1, "bc1".to_string()).unwrap();
//     let to = create_address(xpub.to_string(), 0, 0, 3, "3".to_string()).unwrap();
//     println!("from: {}\nto: {}\n", from, to);
// }

// #[test]
// fn test_tx() {
//     let tx = r#"{
//         "token": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
//         "has_token_account": false,
//         "from": "8gvxAVripdzJ7nDNt1tPQWtmeHkq2nrgpe1BRYWMWUUo",
//         "to": "7q54sdWwR7YLfBtpqWRnvMq3Wd5i4gUyM5kBjdUNH8ZP",
//         "amount": "100000"
//     }"#;
//     let mut tx = serde_json::from_str::<Value>(tx).unwrap();

//     let client = RpcClient::new("https://api.mainnet-beta.solana.com");
//     let blockhash = client.get_latest_blockhash().unwrap().to_string();

//     tx.as_object_mut().unwrap().insert("blockhash".to_string(), json!(blockhash));

//     let tx = serde_json::to_string(&tx).unwrap();

//     let msg = generate_signing_messages(
//         1000,
//         tx.clone(),
//         "".to_string(),
//     ).unwrap().to_string();

//     let mut conn = server_init();
//     server_send(&mut conn, msg);

//     let sig = server_receive(&mut conn);

//     let tx = insert_signatures(
//         sig,
//         1000,
//         tx,
//         "".to_string(),
//     ).unwrap().as_str().unwrap().to_string();

//     println!("{}", tx);
// }

// #[test]
// fn addr() {
//     let xpub = "xpub661MyMwAqRbcFRmatjv3Ff2dY5rQHNpuEYZ2CbjQ8Qn13taUMRJ82CyYrHApzgE2HRFV3iWMQkNYqAQmPazy2cdNn16phg3BexnjRFqJ8CP";
//     let addr = create_address(xpub.to_string(), 0, 0, 1, "3".to_string()).unwrap();

//     println!("addr: {}", addr);
// }

#[test]
fn test_create_addr_eth() {
    let xpub = "xpub661MyMwAqRbcFRmatjv3Ff2dY5rQHNpuEYZ2CbjQ8Qn13taUMRJ82CyYrHApzgE2HRFV3iWMQkNYqAQmPazy2cdNn16phg3BexnjRFqJ8CP";
    let addr = create_address(xpub.to_string(), 60, 0, 1, "".to_string()).unwrap();
    assert_eq!(
        "0x2ec9f63b7b0f2cdb718905dadd925fc637f4f0f2",
        addr.as_str().unwrap()
    );
}
