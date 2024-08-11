use {
    anychain_bitcoin::{
        public_key::BitcoinPublicKey, Bitcoin, BitcoinAddress, BitcoinCash, BitcoinCashTestnet,
        BitcoinFormat, BitcoinTestnet, Dogecoin, DogecoinTestnet, Litecoin, LitecoinTestnet,
    },
    anychain_core::{hex, Address, PublicKey},
    anychain_kms::{
        bip32::{
            ChildNumber, DerivationPath, ExtendedKey, ExtendedKeyAttrs, HmacSha512, Prefix,
            Prefix as XPrefix, XprvSecp256k1, XpubSecp256k1,
        },
        bip39::{Language, Mnemonic, MnemonicType, Seed},
        crypto::ripemd,
    },
    anyhow::{anyhow, Result},
    chain_type::ChainType,
    digest::Mac,
    rand::thread_rng,
    serde_json::Value,
    std::{str::FromStr, time::SystemTime},
};

mod btc;
mod chain_type;
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
        prefix: XPrefix::XPUB,
        attrs,
        key_bytes,
    };

    Ok(Value::String(
        XpubSecp256k1::try_from(xpub)?.to_string(XPrefix::XPUB),
    ))
}

pub fn create_address(xpub: String, chain_type: u32, index1: u32, index2: u32) -> Result<Value> {
    let path = format!("m/44/{}/0/{}/{}", chain_type, index1, index2);
    let xpub = XpubSecp256k1::from_str(xpub.as_str())?;
    let derive_path = DerivationPath::from_str(path.as_str())?;
    let pubkey = *xpub.derive_from_path(&derive_path)?.public_key();
    let chain_type = ChainType::try_from(chain_type)?;

    match chain_type {
        ChainType::Bitcoin => {
            let address = BitcoinPublicKey::<Bitcoin>::from_secp256k1_public_key(pubkey, true)
                .to_address(&BitcoinFormat::P2PKH)?;
            Ok(Value::String(address.to_string()))
        }
        ChainType::BitcoinTestnet => {
            let address =
                BitcoinPublicKey::<BitcoinTestnet>::from_secp256k1_public_key(pubkey, true)
                    .to_address(&BitcoinFormat::P2PKH)?;
            Ok(Value::String(address.to_string()))
        }
        ChainType::BitcoinCash => {
            let address = BitcoinPublicKey::<Bitcoin>::from_secp256k1_public_key(pubkey, true)
                .to_address(&BitcoinFormat::CashAddr)?;
            Ok(Value::String(address.to_string()))
        }
        ChainType::BitcoinCashTestnet => {
            let address =
                BitcoinPublicKey::<BitcoinTestnet>::from_secp256k1_public_key(pubkey, true)
                    .to_address(&BitcoinFormat::CashAddr)?;
            Ok(Value::String(address.to_string()))
        }
        ChainType::Litecoin => {
            let address = BitcoinPublicKey::<Litecoin>::from_secp256k1_public_key(pubkey, true)
                .to_address(&BitcoinFormat::P2PKH)?;
            Ok(Value::String(address.to_string()))
        }
        ChainType::LitecoinTestnet => {
            let address =
                BitcoinPublicKey::<LitecoinTestnet>::from_secp256k1_public_key(pubkey, true)
                    .to_address(&BitcoinFormat::P2PKH)?;
            Ok(Value::String(address.to_string()))
        }
        ChainType::Dogecoin => {
            let address = BitcoinPublicKey::<Dogecoin>::from_secp256k1_public_key(pubkey, true)
                .to_address(&BitcoinFormat::P2PKH)?;
            Ok(Value::String(address.to_string()))
        }
        ChainType::DogecoinTestnet => {
            let address =
                BitcoinPublicKey::<DogecoinTestnet>::from_secp256k1_public_key(pubkey, true)
                    .to_address(&BitcoinFormat::P2PKH)?;
            Ok(Value::String(address.to_string()))
        }
    }
}

/**
 * Construct the original transaction based on the coin type
 * params, transaction parameters, json string
 * coin_type, coin type
 */
pub fn build_raw_transaction(params: String, chain_type: u32) -> Result<Value> {
    let chain_type = ChainType::try_from(chain_type)?;
    match chain_type {
        ChainType::Bitcoin => btc::build_raw_transaction::<Bitcoin>(params),
        ChainType::BitcoinTestnet => btc::build_raw_transaction::<BitcoinTestnet>(params),
        ChainType::BitcoinCash => btc::build_raw_transaction::<BitcoinCash>(params),
        ChainType::BitcoinCashTestnet => btc::build_raw_transaction::<BitcoinCashTestnet>(params),
        ChainType::Litecoin => btc::build_raw_transaction::<Litecoin>(params),
        ChainType::LitecoinTestnet => btc::build_raw_transaction::<LitecoinTestnet>(params),
        ChainType::Dogecoin => btc::build_raw_transaction::<Dogecoin>(params),
        ChainType::DogecoinTestnet => btc::build_raw_transaction::<DogecoinTestnet>(params),
    }
}

/// Returns the hash of the raw transaction as the message to be signed
pub fn raw_transaction_signing_hashes(
    chain_type: u32,
    tx: String,
    reserved: String,
) -> Result<Value> {
    let chain_type = ChainType::try_from(chain_type)?;

    match chain_type {
        ChainType::Bitcoin => btc::raw_transaction_signing_hashes::<Bitcoin>(tx, reserved),
        ChainType::BitcoinTestnet => {
            btc::raw_transaction_signing_hashes::<BitcoinTestnet>(tx, reserved)
        }
        ChainType::BitcoinCash => btc::raw_transaction_signing_hashes::<BitcoinCash>(tx, reserved),
        ChainType::BitcoinCashTestnet => {
            btc::raw_transaction_signing_hashes::<BitcoinCashTestnet>(tx, reserved)
        }
        ChainType::Litecoin => btc::raw_transaction_signing_hashes::<Litecoin>(tx, reserved),
        ChainType::LitecoinTestnet => {
            btc::raw_transaction_signing_hashes::<LitecoinTestnet>(tx, reserved)
        }
        ChainType::Dogecoin => btc::raw_transaction_signing_hashes::<Dogecoin>(tx, reserved),
        ChainType::DogecoinTestnet => {
            btc::raw_transaction_signing_hashes::<DogecoinTestnet>(tx, reserved)
        }
    }
}

/// Insert the given signatures into the 'raw_transaction' and return the signed transaction hex bytes
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
    };
    Ok(Value::Bool(is_valid))
}

pub fn estimate_bandwidth(params: String, chain_type: u32, reserved: String) -> Result<Value> {
    let chain_type = ChainType::try_from(chain_type)?;

    match chain_type {
        ChainType::Bitcoin => btc::estimate_bandwidth::<Bitcoin>(params, reserved),
        ChainType::BitcoinTestnet => btc::estimate_bandwidth::<BitcoinTestnet>(params, reserved),
        ChainType::BitcoinCash => btc::estimate_bandwidth::<BitcoinCash>(params, reserved),
        ChainType::BitcoinCashTestnet => {
            btc::estimate_bandwidth::<BitcoinCashTestnet>(params, reserved)
        }
        ChainType::Litecoin => btc::estimate_bandwidth::<Litecoin>(params, reserved),
        ChainType::LitecoinTestnet => btc::estimate_bandwidth::<LitecoinTestnet>(params, reserved),
        ChainType::Dogecoin => btc::estimate_bandwidth::<Dogecoin>(params, reserved),
        ChainType::DogecoinTestnet => btc::estimate_bandwidth::<DogecoinTestnet>(params, reserved),
        // _ => panic!("Unsupported chain type"),
    }
}

pub fn transaction_parameters_use_case(chain_type: u32) -> Result<Value> {
    let chain_type = ChainType::try_from(chain_type)?;

    match chain_type {
        ChainType::Bitcoin
        | ChainType::BitcoinTestnet
        | ChainType::BitcoinCash
        | ChainType::BitcoinCashTestnet
        | ChainType::Litecoin
        | ChainType::LitecoinTestnet
        | ChainType::Dogecoin
        | ChainType::DogecoinTestnet => Ok(Value::String(btc::tx_params_json())),
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
    let pk = hex::encode(pk);

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
    let sig = hex::encode(sig);

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
