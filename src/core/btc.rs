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
struct BTCParams {
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

pub fn address_format(format: &str) -> Result<BitcoinFormat> {
    match format {
        "" | "1" => Ok(BitcoinFormat::P2PKH),
        "3" => Ok(BitcoinFormat::P2SH_P2WPKH),
        "bc1" => Ok(BitcoinFormat::Bech32),
        _ => Err(anyhow!("Unsupported address format")),
    }
}

fn parse_tx<N: BitcoinNetwork>(tx: String) -> Result<BitcoinTransaction<N>> {
    let params = serde_json::from_str::<BTCParams>(&tx)?;

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

    Ok(BitcoinTransaction::<N>::new(
        &BitcoinTransactionParameters::<N>::new(inputs, outputs)?,
    )?)
}

pub fn generate_signing_messages<N: BitcoinNetwork>(tx: String, reserved: String) -> Result<Value> {
    if reserved.is_empty() {
        return Err(anyhow!("Missing reserved"));
    }

    let mut tx = parse_tx::<N>(tx)?;
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
                let format = address_format(info["format"].as_str().unwrap()).unwrap();
                let balance = info["balance"].as_i64().unwrap();
                (path, format, balance)
            }
        })
        .collect();

    let mut txids = json!([]);

    for i in 0..input_count {
        let (path, mut format, balance) = infos[i as usize].clone();
        let xpub = XpubSecp256k1::from_str(&xpub)?;
        let path = DerivationPath::from_str(path)?;
        let xpub = xpub.derive_from_path(&path)?;
        let public_key = *xpub.public_key();
        let public_key = BitcoinPublicKey::<N>::from_secp256k1_public_key(public_key, true);

        if N::NAME == "bitcoin cash" || N::NAME == "bitcoin cash testnet" {
            format = BitcoinFormat::CashAddr;
        }

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
    let mut tx = parse_tx::<N>(tx)?;

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
                let format = address_format(info["format"].as_str().unwrap()).unwrap();
                let balance = info["balance"].as_i64().unwrap();
                (path, format, balance)
            }
        })
        .collect();

    for i in 0..input_count {
        let (path, mut format, _) = infos[i].clone();
        let xpub = XpubSecp256k1::from_str(&xpub)?;
        let path = DerivationPath::from_str(path).unwrap();
        let xpub = xpub.derive_from_path(&path).unwrap();
        let public_key = *xpub.public_key();
        let public_key = BitcoinPublicKey::<N>::from_secp256k1_public_key(public_key, true);

        if N::NAME == "bitcoin cash" || N::NAME == "bitcoin cash testnet" {
            format = BitcoinFormat::CashAddr;
        }

        if format == BitcoinFormat::CashAddr {
            tx.input(i as u32)?
                .set_sighash(SignatureHash::SIGHASH_ALL_SIGHASH_FORKID)?;
        }

        tx.input(i as u32)?
            .set_public_key(public_key.clone(), format)?;
        tx.input(i as u32)?
            .sign(sigs[i].clone(), public_key.serialize())?;
    }

    tx.set_segwit()?;

    Ok(json!(hex::encode(tx.to_bytes()?)))
}

pub fn decode_raw_transaction<N: BitcoinNetwork>(tx: String) -> Result<Value> {
    let tx = BitcoinTransaction::<N>::from_str(&tx)?;
    let txid = format!("{}", tx.to_transaction_id()?);

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
        let mut to = BitcoinAddress::<N>::from_script_pub_key(&output.script_pub_key)?.to_string();
        let to = if to.starts_with("bitcoincash:") {
            to.split_off(12)
        } else if to.starts_with("bchtest:") {
            to.split_off(8)
        } else {
            to
        };
        let amount = output.amount;
        let output = json!({
            "to": to,
            "amount": amount,
        });
        outputs.as_array_mut().unwrap().push(output);
    }

    Ok(json!({
        "inputs": inputs,
        "outputs": outputs,
        "txid": txid,
    }))
}

pub fn estimate_bandwidth<N: BitcoinNetwork>(tx: String, reserved: String) -> Result<Value> {
    let mut tx = parse_tx::<N>(tx)?;

    let input_count = tx.parameters.inputs.len() as u32;

    let formats = if !reserved.is_empty() {
        let reserved = serde_json::from_str::<Value>(&reserved)?;
        let reserved = reserved.as_array().unwrap().clone();
        let formats: Vec<BitcoinFormat> = reserved
            .iter()
            .map(|val| address_format(val.as_str().unwrap()).unwrap())
            .collect();
        formats
    } else {
        vec![BitcoinFormat::P2PKH; input_count as usize]
    };

    let dummy_sig = [0xf1u8; 64];
    let dummy_public_key = [
        3, 91, 62, 79, 27, 171, 138, 195, 133, 235, 193, 110, 171, 69, 40, 51, 62, 211, 178, 156,
        112, 154, 149, 224, 105, 69, 42, 168, 168, 2, 34, 22, 146,
    ];

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

#[cfg(test)]
mod tests {
    use crate::core::estimate_bandwidth;

    use super::decode_raw_transaction;
    use anychain_bitcoin::BitcoinCashTestnet;

    #[test]
    fn test_decode() {
        let tx = "02000000019376f9bf8c15380ed848010a48a7e06ebbfa30a06081aeacdefd0ec38829555e010000006b483045022100da2c8ede4442585a947c380e61bc7c3c3f2d7c67b36c8160fac9ae1e231007e502205c51d4a08face0ab6072314b986096e535e4f79e64d77b7b21e6d9d15374b3cb412102a03e141bd973f6b10e7d5e861a111f1480a750df3fefedca09971a2f34dd6180f2ffffff02e8030000000000001976a91437c8dedf73f9b0e7d5eca6b14afda37773db62cc88acf9770000000000001976a91461ef9e36742304ce57de3fe8a6aeb7dc53a0270d88ac00000000";
        let tx = decode_raw_transaction::<BitcoinCashTestnet>(tx.to_string()).unwrap();
        println!("{}", tx);
    }

    #[test]
    fn test_bandwidth() {
        let tx = json!({
            "inputs": [
                {
                    "index": 2,
                    "txid": "56091f6bbb619518dbb5789d1b20de1c96fe2ca9d931df57a1eab12a7ab61c36"
                },
                {
                    "index": 0,
                    "txid": "36d3815b142fc9a93c1fff1ef7994fe6f3919ccc54a51c891e8418ca95a51020"
                },
                {
                    "index": 1,
                    "txid": "ba2bcfed866d89c59110901ee513ffaba1ab6c8e3b99ab8d386c0f8fc0f8a38b"
                }
            ],
            "outputs": [
                {
                    "amount": 100000,
                    "to": "1ASxbWAVJgSmECShbr7pNFhuFtbxwn7aww"
                },
                {
                    "amount": 500000,
                    "to": "1EjwNvzypjwuYuqZFcX3wSfPpPf5sNG9b5"
                }
            ]
        })
        .to_string();

        let reserved = json!(["bc1", "bc1", "bc1"]).to_string();

        let bw = estimate_bandwidth(tx, 0, reserved).unwrap();

        println!("bw: {}", bw);
    }
}
