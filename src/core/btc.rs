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

fn address_format(format: &str) -> BitcoinFormat {
    match format {
        "" | "1" => BitcoinFormat::P2PKH,
        "3" => BitcoinFormat::P2SH_P2WPKH,
        "bc1" => BitcoinFormat::Bech32,
        _ => panic!("unsupported format"),
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
                let format = address_format(info["format"].as_str().unwrap());
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
                let format = address_format(info["format"].as_str().unwrap());
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

#[cfg(test)]
mod tests {
    use super::decode_raw_transaction;
    use crate::core::{create_address, generate_signing_messages};
    use anychain_bitcoin::BitcoinTestnet;

    #[test]
    fn test_bitcoin() {
        let tx = r#"{
            "inputs": [
                {
                    "txid": "dd97f755f4f3ddc28a9db93140449032ba45cd76630443053030b6b3e36b51e9",
                    "index": 0
                },
                {
                    "txid": "44f154db13459421f4aae8664b9b731f4f91d998571169ddc97d614fa092ee9b",
                    "index": 1
                }
            ],
            "outputs": [
                {
                    "to": "tb1q2cy376amvx233ka40zw3kgx7rjt0ut9fz9e4el",
                    "amount": 19000
                },
                {
                    "to": "tb1q2cy376amvx233ka40zw3kgx7rjt0ut9fmyca74apa2cj574krsmqk8z5c9",
                    "amount": 19000
                }
            ]
        }"#;

        let reserved = r#"{
            "master_xpub": "xpub661MyMwAqRbcGv3zotXdkWta9HV6Gq3gBAAqeTTi8KDBtQAkSYL6AkKRrw7KfLsg7uaydCDt6xx1cK7pmXCPCaYAYKoTnySpMSu5Z1qNPCG",
            "infos": [
                {
                    "format": "3",
                    "balance": 19756,
                    "path": "m/44/1/0/0/2"
                },
                {
                    "format": "bc1",
                    "balance": 26355,
                    "path": "m/44/1/0/0/2"
                }
            ]
        }"#;

        let _msgs = generate_signing_messages(1, tx.to_string(), reserved.to_string())
            .unwrap()
            .to_string();

        // let mut conn = init();
        // send(&mut conn, msgs);
        //
        // let sigs = receive(&mut conn);

        // let tx = insert_signatures::<BitcoinTestnet>(
        //     sigs.to_string(),
        //     tx.to_string(),
        //     reserved.to_string(),
        // )
        // .unwrap();
        //
        // println!("{}", tx);
    }

    #[test]
    fn test_bitcoincash() {
        let tx = r#"{
            "inputs": [
                {
                    "txid": "d193f0088d7b93bcf3f6d34b1ce21d78c485399a3c426665c47cae3ce3e6b04b",
                    "index": 0
                }
            ],
            "outputs": [
                {
                    "to": "tb1q2cy376amvx233ka40zw3kgx7rjt0ut9fmyca74apa2cj574krsmqk8z5c9",
                    "amount": 1007000
                }
            ]
        }"#;

        let reserved = r#"{
            "master_xpub": "xpub661MyMwAqRbcGv3zotXdkWta9HV6Gq3gBAAqeTTi8KDBtQAkSYL6AkKRrw7KfLsg7uaydCDt6xx1cK7pmXCPCaYAYKoTnySpMSu5Z1qNPCG",
            "infos": [
                {
                    "format": "",
                    "balance": 1015000,
                    "path": "m/44/51/0/0/2"
                }
            ]
        }"#;

        let _msgs = generate_signing_messages(51, tx.to_string(), reserved.to_string())
            .unwrap()
            .to_string();

        // let mut conn = init();
        // send(&mut conn, msgs);
        //
        // let sigs = receive(&mut conn);
        //
        // let tx = insert_signatures::<BitcoinTestnet>(
        //     sigs.to_string(),
        //     tx.to_string(),
        //     reserved.to_string(),
        // )
        // .unwrap();
        //
        // println!("{}", tx);
    }

    #[test]
    fn test_address_gen() {
        let xpub = "xpub661MyMwAqRbcGv3zotXdkWta9HV6Gq3gBAAqeTTi8KDBtQAkSYL6AkKRrw7KfLsg7uaydCDt6xx1cK7pmXCPCaYAYKoTnySpMSu5Z1qNPCG";
        let fmts = [""];

        // to: bchtest:qz9ncj79z033ku0ck2fng032le70rnxdtya9lccsmh

        for fmt in fmts {
            let addr = create_address(xpub.to_string(), 51, 0, 2, fmt.to_string()).unwrap();
            assert_eq!(
                addr,
                serde_json::Value::String(
                    "bchtest:qplny8ud32j59jrq8enrdwunpqlhs3sx7ufa8dcdsu".to_string()
                )
            );
        }
    }

    #[test]
    fn test_address_gen_bitcoin_mainet_0() {
        let xpub = "xpub661MyMwAqRbcEzQAuTRFpp8Wvo7QDHrQ4MxXMRuRSxUUXnKbUq6GdUmUfp2QY9j8Hu21juYrgQYUfd39GitgR9kKkDykohHYAjDpVVBdGjJ";
        let fmts = [""];

        for fmt in fmts {
            let addr = create_address(xpub.to_string(), 0, 0, 1, fmt.to_string()).unwrap();
            assert_eq!(
                addr,
                serde_json::Value::String("1EjwNvzypjwuYuqZFcX3wSfPpPf5sNG9b5".to_string())
            );
        }
    }

    #[test]
    fn test_decode() {
        let tx = "02000000000102e9516be3b3b630300543046376cd45ba3290444031b99d8ac2ddf3f455f797dd000000001716001403e1ec03ca1af39920e0b367450d3f83e744ae7bf2ffffff9bee92a04f617dc9dd69115798d9914f1f739b4b66e8aaf421944513db54f1440100000000f2ffffff02384a00000000000016001456091f6bbb619518dbb5789d1b20de1c96fe2ca9384a00000000000022002056091f6bbb619518dbb5789d1b20de1c96fe2ca9d931df57a1eab12a7ab61c3602483045022100a5d341330880733212decaa31b2535e7e9e7acfacb06a981f3d25c78089ce9370220088427181319b15204a32d7567ff164324d1ec70fd5f8d90f234d6f9607c4ff00121025524f7862c566e0107afe2475fc3db1b29b8daf74781de725675aeefb732c8220247304402204e140e54869a6912e474e7fb90e4214a93794b9f59a143549043a52f2dc34d98022070a460a8f94441cc5f71651c5ed884291abefef18c8342fa06ae90aec3e664730121025524f7862c566e0107afe2475fc3db1b29b8daf74781de725675aeefb732c82200000000";
        let tx = decode_raw_transaction::<BitcoinTestnet>(tx.to_string()).unwrap();
        dbg!("{}", tx);
    }
}
