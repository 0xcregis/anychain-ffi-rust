use super::util::get_signatures;
use anychain_bitcoin::{
    create_script_pub_key, BitcoinAddress, BitcoinAmount, BitcoinFormat, BitcoinNetwork,
    BitcoinPublicKey, BitcoinTransaction, BitcoinTransactionInput, BitcoinTransactionOutput,
    BitcoinTransactionParameters, SignatureHash,
};
use anychain_core::Transaction;
use anychain_kms::bip32::{DerivationPath, XpubSecp256k1};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{str::FromStr, vec};

#[derive(Debug, Serialize, Deserialize)]
pub struct BTCParams {
    #[serde(default)]
    property_id: u32,
    #[serde(default)]
    property_amount: u32,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Input {
    txid: String,
    index: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct Output {
    to: String,
    amount: i64,
}

fn address_format(format: &str) -> BitcoinFormat {
    match format {
        "p2pkh" => BitcoinFormat::P2PKH,
        "p2sh_p2wpkh" => BitcoinFormat::P2SH_P2WPKH,
        "p2wsh" => BitcoinFormat::P2WSH,
        "bech32" => BitcoinFormat::Bech32,
        _ => panic!("unrecognized format"),
    }
}

pub fn build_raw_transaction<N: BitcoinNetwork>(params: String) -> Result<Value> {
    let params = serde_json::from_str::<BTCParams>(&params).unwrap();

    let inputs: Result<Vec<BitcoinTransactionInput<N>>> = params
        .inputs
        .iter()
        .map(|input| -> Result<BitcoinTransactionInput<N>> {
            Ok(BitcoinTransactionInput::<N>::new(
                hex::decode(&input.txid)?,
                input.index,
                None,
                None,
                None,
                None,
                SignatureHash::SIGHASH_ALL,
            )?)
        })
        .collect();

    let outputs: Result<Vec<BitcoinTransactionOutput>> = params
        .outputs
        .iter()
        .map(|output| -> Result<BitcoinTransactionOutput> {
            Ok(BitcoinTransactionOutput {
                amount: BitcoinAmount::from_satoshi(output.amount)?,
                script_pub_key: create_script_pub_key(&BitcoinAddress::<N>::from_str(&output.to)?)?,
            })
        })
        .collect();

    let inputs = inputs.unwrap();
    let mut outputs = outputs.unwrap();

    // it's a transaction that spends omni-layer assets on top of bitcoin network,
    // so we insert an OP_RETURN data output to the end of the utxo set
    if params.property_id != 0 {
        let amount = BitcoinAmount(params.property_amount as i64);
        let output_data = BitcoinTransactionOutput::omni_data_output(params.property_id, amount)?;
        // insert the data output
        outputs.push(output_data);
        // move the reference output to the end
        // (implicitly the first output)
        outputs.push(outputs[0].clone());
        outputs.remove(0);
    }

    let parameters = BitcoinTransactionParameters::<N>::new(inputs, outputs)?;

    let tx = BitcoinTransaction::<N>::new(&parameters)?;

    Ok(json!(hex::encode(tx.to_bytes()?)))
}

pub fn raw_transaction_signing_hashes<N: BitcoinNetwork>(
    tx: String,
    reserved: String,
) -> Result<Value> {
    if reserved.is_empty() {
        return Err(anyhow!("Missing reserved"));
    }

    let mut tx = BitcoinTransaction::<N>::from_str(&tx)?;
    let input_count = tx.parameters.inputs.len() as u32;
    let reserved = serde_json::from_str::<Value>(&reserved)?;

    if !reserved.is_object() {
        return Err(anyhow!("Unsupported format for \'reserved\'"));
    }

    let xpub = reserved["master_xpub"].as_str().unwrap().to_string();
    let infos = reserved["infos"].as_array().unwrap().clone();
    let infos: Vec<(&str, BitcoinFormat, i64)> = infos
        .iter()
        .map(|info| {
            if info.is_string() {
                let path = info.as_str().unwrap();
                let format = BitcoinFormat::P2PKH;
                let balance = 0;
                (path, format, balance)
            } else {
                let path = info["path"].as_str().unwrap();
                let format = address_format(info["format"].as_str().unwrap());
                let balance = info["balance"].as_i64().unwrap();
                (path, format, balance)
            }
        })
        .collect();

    let mut txids = json!([]);

    for i in 0..input_count {
        let (path, format, balance) = infos[i as usize].clone();
        let xpub = XpubSecp256k1::from_str(&xpub)?;
        let path = DerivationPath::from_str(path)?;
        let xpub = xpub.derive_from_path(&path)?;
        let public_key = *xpub.public_key();
        let public_key = BitcoinPublicKey::<N>::from_secp256k1_public_key(public_key, true);

        tx.input(i)?.set_public_key(public_key, format.clone())?;
        tx.input(i)?.set_balance(balance)?;

        if format == BitcoinFormat::CashAddr {
            tx.input(i)?
                .set_sighash(SignatureHash::SIGHASH_ALL_SIGHASH_FORKID)?;
        }

        let txid = json!(hex::encode(tx.digest(i)?));

        txids.as_array_mut().unwrap().push(txid);
    }

    Ok(txids)
}

pub fn insert_signatures<N: BitcoinNetwork>(
    signatures: String,
    tx: String,
    reserved: String,
) -> Result<Value> {
    if reserved.is_empty() {
        return Err(anyhow!("Missing reserved"));
    }

    let sigs = get_signatures(signatures, false)?;

    let mut tx = BitcoinTransaction::<N>::from_str(&tx)?;
    let input_count = tx.parameters.inputs.len();
    let reserved = serde_json::from_str::<Value>(&reserved)?;

    if !reserved.is_object() {
        return Err(anyhow!("Unsupported format for \'reserved\'"));
    }

    let xpub = reserved["master_xpub"].as_str().unwrap().to_string();
    let infos = reserved["infos"].as_array().unwrap().clone();
    let infos: Vec<(&str, BitcoinFormat, i64)> = infos
        .iter()
        .map(|info| {
            if info.is_string() {
                let path = info.as_str().unwrap();
                let format = BitcoinFormat::P2PKH;
                let balance = 0;
                (path, format, balance)
            } else {
                let path = info["path"].as_str().unwrap();
                let format = address_format(info["format"].as_str().unwrap());
                let balance = info["balance"].as_i64().unwrap();
                (path, format, balance)
            }
        })
        .collect();

    for i in 0..input_count {
        let (path, format, _) = infos[i].clone();
        let xpub = XpubSecp256k1::from_str(&xpub)?;
        let path = DerivationPath::from_str(path).unwrap();
        let xpub = xpub.derive_from_path(&path).unwrap();
        let public_key = *xpub.public_key();
        let public_key = BitcoinPublicKey::<N>::from_secp256k1_public_key(public_key, true);
        tx.input(i as u32)?.set_format(format)?;
        tx.input(i as u32)?
            .sign(sigs[i].clone(), public_key.serialize())?;
    }

    tx.set_segwit()?;

    Ok(json!(hex::encode(tx.to_bytes()?)))
}

pub fn decode_raw_transaction<N: BitcoinNetwork>(raw_tx: String) -> Result<Value> {
    let tx = BitcoinTransaction::<N>::from_str(&raw_tx)?;

    let mut inputs = json!([]);
    for input in tx.parameters.inputs {
        let mut txid = input.outpoint.reverse_transaction_id;
        txid.reverse();
        let index = input.outpoint.index;
        let txid = hex::encode(&txid);
        let input = json!({
            "txid": txid,
            "index": index,
        });
        inputs.as_array_mut().unwrap().push(input);
    }

    let mut outputs = json!([]);
    for output in tx.parameters.outputs {
        let to = BitcoinAddress::<N>::from_script_pub_key(&output.script_pub_key)?;
        let amount = output.amount;
        let output = json!({
            "to": to.to_string(),
            "amount": amount,
        });
        outputs.as_array_mut().unwrap().push(output);
    }

    Ok(json!({
        "inputs": inputs,
        "outputs": outputs,
    }))
}

pub fn estimate_bandwidth<N: BitcoinNetwork>(params: String, reserved: String) -> Result<Value> {
    let tx = build_raw_transaction::<N>(params)?;
    let mut tx = BitcoinTransaction::<N>::from_str(tx.as_str().unwrap())?;

    let input_count = tx.parameters.inputs.len() as u32;

    let formats = if !reserved.is_empty() {
        let reserved = serde_json::from_str::<Value>(&reserved)?;
        let reserved = reserved.as_array().unwrap().clone();
        let formats: Vec<BitcoinFormat> = reserved
            .iter()
            .map(|val| address_format(val.as_str().unwrap()))
            .collect();
        formats
    } else {
        vec![BitcoinFormat::P2PKH; input_count as usize]
    };

    let dummy_sig = [0xf1u8; 64];
    let dummy_public_key = [1u8; 33];

    for i in 0..input_count {
        let format = formats[i as usize].clone();
        tx.input(i)?.set_format(format.clone())?;
        if format == BitcoinFormat::P2SH_P2WPKH {
            let public_key = libsecp256k1::PublicKey::parse_compressed(&dummy_public_key)?;
            let public_key = BitcoinPublicKey::<N>::from_secp256k1_public_key(public_key, true);
            tx.input(i)?.set_public_key(public_key, format)?;
        }
        // Insert the dummy signature and public key into every transaction input
        tx.input(i)?
            .sign(dummy_sig.to_vec(), dummy_public_key.to_vec())?;
    }

    tx.set_segwit()?;

    let stream = tx.to_transaction_bytes_without_witness()?;

    // Returns the estimated byte length of the transaction
    Ok(json!(stream.len() as u32))
}

pub fn tx_params_json() -> String {
    let params = r#"
    use case of arg 'params' for 'build_raw_transaction()':

    {
        "inputs": [
            {
                "txid": "56091f6bbb619518dbb5789d1b20de1c96fe2ca9d931df57a1eab12a7ab61c36",
                "index": 2
            },
            {
                "txid": "36d3815b142fc9a93c1fff1ef7994fe6f3919ccc54a51c891e8418ca95a51020",
                "index": 1
            },
            {
                "txid": "ba2bcfed866d89c59110901ee513ffaba1ab6c8e3b99ab8d386c0f8fc0f8a38b",
                "index": 1
            }
        ],
        "outputs": [
            {
                "to": "n18cKrzVgjchpipLbFRkJ5b4Y2s1KXapD5",
                "amount": 5700
            },
            {
                "to": "mkDvXYHwatg6Bbj1RuHnR7rSUenL1tJ2Va",
                "amount": 10000
            }
        ]
    }


    use case of arg 'params' for 'build_raw_transaction()' when it's for omni layer assets:

    {
        "property_id": 31,
        "property_amount": 100
        "inputs": [
            {
                "txid": "56091f6bbb619518dbb5789d1b20de1c96fe2ca9d931df57a1eab12a7ab61c36",
                "index": 2
            },
            {
                "txid": "36d3815b142fc9a93c1fff1ef7994fe6f3919ccc54a51c891e8418ca95a51020",
                "index": 1
            },
            {
                "txid": "ba2bcfed866d89c59110901ee513ffaba1ab6c8e3b99ab8d386c0f8fc0f8a38b",
                "index": 1
            }
        ],
        "outputs": [
            {
                "to": "n18cKrzVgjchpipLbFRkJ5b4Y2s1KXapD5",
                "amount": 5700
            },
            {
                "to": "mkDvXYHwatg6Bbj1RuHnR7rSUenL1tJ2Va",
                "amount": 10000
            }
        ]
    }


    use case of arg 'reserved' for 'raw_transaction_signing_hashes()':

    {
        "master_xpub": "xpub661MyMwAqRbcFRmatjv3Ff2dY5rQHNpuEYZ2CbjQ8Qn13taUMRJ82CyYrHApzgE2HRFV3iWMQkNYqAQmPazy2cdNn16phg3BexnjRFqJ8CP",
        "infos": ["m/44/1/0/8/10001", "m/44/1/0/8/10002", "m/44/1/0/8/10003"]
    }


    (alt) use case of arg 'reserved' for 'raw_transaction_signing_hashes()':

    {
        "master_xpub": "xpub661MyMwAqRbcFRmatjv3Ff2dY5rQHNpuEYZ2CbjQ8Qn13taUMRJ82CyYrHApzgE2HRFV3iWMQkNYqAQmPazy2cdNn16phg3BexnjRFqJ8CP",
        "infos": [
            {
                "format": "p2sh_p2wpkh",
                "balance": 90000000000,
                "path": "m/44/1/0/8/10001"
            },
            {
                "format": "bech32",
                "balance": 80000000000,
                "path": "m/44/1/0/8/10002"
            },
            {
                "format": "p2pkh",
                "balance": 30000000000,
                "path": "m/44/1/0/8/10003"
            }
        ]
    }

    use case of arg 'reserved' for 'insert_signature()':

    {
        "master_xpub": "xpub661MyMwAqRbcFRmatjv3Ff2dY5rQHNpuEYZ2CbjQ8Qn13taUMRJ82CyYrHApzgE2HRFV3iWMQkNYqAQmPazy2cdNn16phg3BexnjRFqJ8CP",
        "infos": ["m/44/1/0/8/10001", "m/44/1/0/8/10002", "m/44/1/0/8/10003"]
    }


    use case of arg 'reserved' for 'estimate_bandwidth()':

    ["bech32", "p2sh_p2wpkh", "p2pkh"]
    "#;

    params.to_string()
}

#[cfg(test)]
mod tests {
    use super::decode_raw_transaction;
    use crate::core::{
        btc::insert_signatures, build_raw_transaction, raw_transaction_signing_hashes,
    };
    use anychain_bitcoin::BitcoinTestnet;

    #[test]
    fn transaction_gen() {
        let param = r#"{
            "inputs": [
                {
                    "txid": "56091f6bbb619518dbb5789d1b20de1c96fe2ca9d931df57a1eab12a7ab61c36",
                    "index": 2
                },
                {
                    "txid": "36d3815b142fc9a93c1fff1ef7994fe6f3919ccc54a51c891e8418ca95a51020",
                    "index": 1
                },
                {
                    "txid": "ba2bcfed866d89c59110901ee513ffaba1ab6c8e3b99ab8d386c0f8fc0f8a38b",
                    "index": 1
                }
            ],
            "outputs": [
                {
                    "to": "n18cKrzVgjchpipLbFRkJ5b4Y2s1KXapD5",
                    "amount": 5700
                },
                {
                    "to": "mkDvXYHwatg6Bbj1RuHnR7rSUenL1tJ2Va",
                    "amount": 10000
                }
            ]
        }"#;

        let tx = build_raw_transaction(param.to_string(), 1).unwrap();

        println!("tx = {}", tx);

        let reserved = r#"{
            "master_xpub": "xpub661MyMwAqRbcFRmatjv3Ff2dY5rQHNpuEYZ2CbjQ8Qn13taUMRJ82CyYrHApzgE2HRFV3iWMQkNYqAQmPazy2cdNn16phg3BexnjRFqJ8CP",
            "infos": ["m/44/1/0/8/10001", "m/44/1/0/8/10002", "m/44/1/0/8/10003"]
        }"#;

        let hashes = raw_transaction_signing_hashes(
            1,
            tx.as_str().unwrap().to_string(),
            reserved.to_string(),
        )
        .unwrap();

        println!("hashes = {}", hashes);
    }

    #[test]
    fn test_decode() {
        let tx = "0200000003361cb67a2ab1eaa157df31d9a92cfe961cde201b9d78b5db189561bb6b1f09560200000000f2ffffff2010a595ca18841e891ca554cc9c91f3e64f99f71eff1f3ca9c92f145b81d3360100000000f2ffffff8ba3f8c08f0f6c388dab993b8e6caba1abff13e51e901091c5896d86edcf2bba0100000000f2ffffff0244160000000000001976a914d728b204fda0d6ffb3676685a1ffb31c5053241488ac10270000000000001976a91433a01507f56d49c58e8621783d44bea8df684a5088ac00000000";
        let sigs = r#"[
            {
                "r": "1234567890123456789012345678901234567890123456789012345678901234",
                "s": "1234567890123456789012345678901234567890123456789012345678901234",
                "recid": 1
            },
            {
                "r": "1234567890123456789012345678901234567890123456789012345678901234",
                "s": "1234567890123456789012345678901234567890123456789012345678901234",
                "recid": 1
            },
            {
                "r": "1234567890123456789012345678901234567890123456789012345678901234",
                "s": "1234567890123456789012345678901234567890123456789012345678901234",
                "recid": 1
            }
        ]"#;

        let reserved = r#"{
            "master_xpub": "xpub661MyMwAqRbcFRmatjv3Ff2dY5rQHNpuEYZ2CbjQ8Qn13taUMRJ82CyYrHApzgE2HRFV3iWMQkNYqAQmPazy2cdNn16phg3BexnjRFqJ8CP",
            "infos": ["m/44/1/0/8/10001", "m/44/1/0/8/10002", "m/44/1/0/8/10003"]
        }"#;

        let tx = insert_signatures::<BitcoinTestnet>(
            sigs.to_string(),
            tx.to_string(),
            reserved.to_string(),
        )
        .unwrap();
        let tx =
            decode_raw_transaction::<BitcoinTestnet>(tx.as_str().unwrap().to_string()).unwrap();

        println!("{}", tx);
    }
}
