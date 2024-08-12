use super::util::get_signatures;
use anychain_core::{Transaction, TransactionError};
use anychain_ethereum::{
    decode_transfer, encode_transfer, Eip1559Transaction, Eip1559TransactionParameters,
    Eip1559TransactionSignature, EthereumAddress, EthereumNetwork, EthereumTransaction,
    EthereumTransactionId, EthereumTransactionParameters, EthereumTransactionSignature,
};
use anyhow::{anyhow, Result};
use ethereum_types::U256;
use serde_json::Value;
use std::str::FromStr;

trait EthTx {
    fn to_transaction_id(&self) -> Result<EthereumTransactionId, TransactionError>;
    fn sign(&mut self, rs: Vec<u8>, recid: u8) -> Result<Vec<u8>, TransactionError>;
}

impl<N: EthereumNetwork> EthTx for EthereumTransaction<N> {
    fn to_transaction_id(&self) -> Result<EthereumTransactionId, TransactionError> {
        Transaction::to_transaction_id(self)
    }
    fn sign(&mut self, rs: Vec<u8>, recid: u8) -> Result<Vec<u8>, TransactionError> {
        Transaction::sign(self, rs, recid)
    }
}

impl<N: EthereumNetwork> EthTx for Eip1559Transaction<N> {
    fn to_transaction_id(&self) -> Result<EthereumTransactionId, TransactionError> {
        Transaction::to_transaction_id(self)
    }
    fn sign(&mut self, rs: Vec<u8>, recid: u8) -> Result<Vec<u8>, TransactionError> {
        Transaction::sign(self, rs, recid)
    }
}

fn parse_tx<N: EthereumNetwork>(tx: String) -> Result<Box<dyn EthTx>> {
    let params = serde_json::from_str::<Value>(&tx)?;

    let to = EthereumAddress::from_str(params["to"].as_str().unwrap())?;
    let amount = U256::from_dec_str(params["amount"].as_str().unwrap())?;

    let (to, amount, data) = match &params["contract"] {
        // we are dealing with an ERC20 token transfer
        Value::String(contract) => {
            let data = encode_transfer("transfer", &to, amount);
            let to = EthereumAddress::from_str(contract)?;
            let amount = U256::from_dec_str("0")?;
            (to, amount, data)
        }
        // we are dealing with an ETH transfer
        Value::Null => (to, amount, vec![]),
        _ => return Err(anyhow!("Invalid contract value")),
    };

    let gas_limit = U256::from_dec_str(params["gasLimit"].as_str().unwrap())?;
    let nonce = match &params["nonce"] {
        Value::Number(nonce) => U256::from(nonce.as_u64().unwrap()),
        Value::String(nonce) => U256::from_dec_str(nonce)?,
        _ => return Err(anyhow!("Invalid nonce value")),
    };

    match &params["gasPrice"] {
        // we are dealing with a Legacy tx
        Value::String(gas_price) => {
            let gas_price = U256::from_dec_str(gas_price)?;
            Ok(Box::new(EthereumTransaction::<N>::new(
                &EthereumTransactionParameters {
                    nonce,
                    gas_price,
                    gas_limit,
                    to,
                    amount,
                    data,
                },
            )?))
        }
        // we are dealing with an EIP-1559 tx
        Value::Null => {
            let max_fee_per_gas = U256::from_dec_str(params["maxFeePerGas"].as_str().unwrap())?;
            let max_priority_fee_per_gas =
                U256::from_dec_str(params["maxPriorityFeePerGas"].as_str().unwrap())?;
            Ok(Box::new(Eip1559Transaction::<N>::new(
                &Eip1559TransactionParameters {
                    chain_id: N::CHAIN_ID,
                    nonce,
                    max_priority_fee_per_gas,
                    max_fee_per_gas,
                    gas_limit,
                    to,
                    amount,
                    data,
                    access_list: vec![],
                },
            )?))
        }
        _ => Err(anyhow!("Invalid gasPrice value")),
    }
}

pub fn generate_signing_messages<N: EthereumNetwork>(tx: String) -> Result<Value> {
    let tx = parse_tx::<N>(tx)?;
    let txid = tx.to_transaction_id()?.txid;
    Ok(json!([hex::encode(txid)]))
}

pub fn insert_signatures<N: EthereumNetwork>(signature: String, tx: String) -> Result<Value> {
    let sigs = get_signatures(signature, true)?;
    let mut tx = parse_tx::<N>(tx)?;
    let bytes = tx.sign(sigs[0][..64].to_vec(), sigs[0][64])?;
    Ok(json!(format!("0x{}", hex::encode(bytes))))
}

pub fn decode_raw_transaction<N: EthereumNetwork>(tx: String) -> Result<Value> {
    let (tx_legacy, tx_eip1559) = if tx.starts_with("0x02") || tx.starts_with("02") {
        (None, Some(Eip1559Transaction::<N>::from_str(&tx)?))
    } else {
        (Some(EthereumTransaction::<N>::from_str(&tx)?), None)
    };

    let txid = if tx_legacy.is_some() {
        Transaction::to_transaction_id(&tx_legacy.clone().unwrap())?.txid
    } else {
        Transaction::to_transaction_id(&tx_eip1559.clone().unwrap())?.txid
    };

    let (
        nonce,
        gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        gas_limit,
        from,
        to,
        amount,
        data,
        sig,
    ) = match (tx_legacy, tx_eip1559) {
        (
            Some(EthereumTransaction::<N> {
                sender,
                params,
                signature,
                ..
            }),
            None,
        ) => {
            let sig = match signature {
                Some(EthereumTransactionSignature { v, r, s }) => {
                    let recid = v - 2 * N::CHAIN_ID - 35;
                    Some((r, s, recid as u8))
                }
                None => None,
            };
            (
                params.nonce,
                Some(params.gas_price),
                None,
                None,
                params.gas_limit,
                sender,
                params.to,
                params.amount,
                params.data,
                sig,
            )
        }
        (
            None,
            Some(Eip1559Transaction::<N> {
                sender,
                params,
                signature,
                ..
            }),
        ) => {
            let sig = match signature {
                Some(Eip1559TransactionSignature { y_parity, r, s }) => {
                    let recid = if y_parity { 1 } else { 0 };
                    Some((r, s, recid))
                }
                None => None,
            };
            (
                params.nonce,
                None,
                Some(params.max_fee_per_gas),
                Some(params.max_priority_fee_per_gas),
                params.gas_limit,
                sender,
                params.to,
                params.amount,
                params.data,
                sig,
            )
        }
        _ => return Err(anyhow!("Invalid transaction type")),
    };

    let mut ret = json!({
        "from": match from {
            Some(addr) => Value::String(addr.to_string()),
            None => Value::Null,
        },
        "gasLimit": gas_limit.to_string(),
        "nonce": nonce.to_string(),
        "signature": match sig {
            Some((r, s, recid)) => {
                json!({
                    "r": hex::encode(r),
                    "s": hex::encode(s),
                    "recid": recid,
                })
            }
            None => Value::Null,
        },
        "txid": hex::encode(txid),
    });

    fn insert(val: &mut Value, key: &str, value: &str) {
        val.as_object_mut()
            .unwrap()
            .insert(key.to_string(), json!(value));
    }

    match (data.is_empty(), gas_price) {
        // we are dealing with a Legacy ETH transfer
        (true, Some(gas_price)) => {
            insert(&mut ret, "type", "Legacy Transfer");
            insert(&mut ret, "to", &to.to_string());
            insert(&mut ret, "amount", &amount.to_string());
            insert(&mut ret, "gasPrice", &gas_price.to_string());
        }
        // we are dealing with a Legacy ERC20 token transfer
        (false, Some(gas_price)) => {
            let call = decode_transfer(data)?;
            let contract = to.to_string();
            let to = call["params"]["to"].as_str().unwrap().to_string();
            let amount = call["params"]["amount"].as_str().unwrap().to_string();
            insert(&mut ret, "type", "Legacy ERC20 Transfer");
            insert(&mut ret, "contract", &contract);
            insert(&mut ret, "to", &to);
            insert(&mut ret, "amount", &amount);
            insert(&mut ret, "gasPrice", &gas_price.to_string());
        }
        // we are dealing with an EIP-1559 ETH transfer
        (true, None) => {
            insert(&mut ret, "type", "EIP-1559 Transfer");
            insert(&mut ret, "to", &to.to_string());
            insert(&mut ret, "amount", &amount.to_string());
            insert(
                &mut ret,
                "maxFeePerGas",
                &max_fee_per_gas.unwrap().to_string(),
            );
            insert(
                &mut ret,
                "maxPriorityFeePerGas",
                &max_priority_fee_per_gas.unwrap().to_string(),
            );
        }
        // we are dealing with an EIP-1559 ERC20 token transfer
        (false, None) => {
            let call = decode_transfer(data)?;
            let contract = to.to_string();
            let to = call["params"]["to"].as_str().unwrap().to_string();
            let amount = call["params"]["amount"].as_str().unwrap().to_string();
            insert(&mut ret, "type", "EIP-1559 ERC20 Transfer");
            insert(&mut ret, "contract", &contract);
            insert(&mut ret, "to", &to);
            insert(&mut ret, "amount", &amount);
            insert(
                &mut ret,
                "maxFeePerGas",
                &max_fee_per_gas.unwrap().to_string(),
            );
            insert(
                &mut ret,
                "maxPriorityFeePerGas",
                &max_priority_fee_per_gas.unwrap().to_string(),
            );
        }
    }

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use crate::core::{decode_raw_transaction, generate_signing_messages, insert_signatures};

    #[test]
    fn test_legacy_eth_transfer() {
        let tx = r#"{
            "to": "0xd62eFebf27BC254a441692BCcB7Ce1097E2e4D3a",
            "amount": "10000000000000000",
            "gasLimit": "21000",
            "gasPrice": "100000000000",
            "nonce": 7
        }"#
        .to_string();

        let msg = generate_signing_messages(6002, tx.clone(), "".to_string()).unwrap();
        let msg = msg.as_array().unwrap();
        let msg = msg[0].as_str().unwrap();
        let msg = hex::decode(msg).unwrap();
        let msg = libsecp256k1::Message::parse_slice(&msg).unwrap();

        let sk = "08d586ed207046d6476f92fd4852be3830a9d651fc148d6fa5a6f15b77ba5df0";
        let sk = hex::decode(sk).unwrap();
        let sk = libsecp256k1::SecretKey::parse_slice(&sk).unwrap();

        let (sig, recid) = libsecp256k1::sign(&msg, &sk);
        let sig = sig.serialize().to_vec();
        let r = &sig[..32];
        let s = &sig[32..];
        let recid = recid.serialize();
        let sigs = json!([{
            "r": hex::encode(r),
            "s": hex::encode(s),
            "recid": recid,
        }])
        .to_string();

        let tx = insert_signatures(sigs, 6002, tx, "".to_string()).unwrap();
        let tx = decode_raw_transaction(tx.as_str().unwrap().to_string(), 6002).unwrap();

        println!("{}", tx);
    }

    #[test]
    fn test_eip1559_eth_transfer() {
        let tx = r#"{
            "to": "0xd62eFebf27BC254a441692BCcB7Ce1097E2e4D3a",
            "amount": "10000000000000000",
            "gasLimit": "21000",
            "maxPriorityFeePerGas": "100000000000",
            "maxFeePerGas": "100000000000",
            "nonce": 8
        }"#
        .to_string();

        let msg = generate_signing_messages(6002, tx.clone(), "".to_string()).unwrap();
        let msg = msg.as_array().unwrap();
        let msg = msg[0].as_str().unwrap();
        let msg = hex::decode(msg).unwrap();
        let msg = libsecp256k1::Message::parse_slice(&msg).unwrap();

        let sk = "08d586ed207046d6476f92fd4852be3830a9d651fc148d6fa5a6f15b77ba5df0";
        let sk = hex::decode(sk).unwrap();
        let sk = libsecp256k1::SecretKey::parse_slice(&sk).unwrap();

        let (sig, recid) = libsecp256k1::sign(&msg, &sk);
        let sig = sig.serialize().to_vec();
        let r = &sig[..32];
        let s = &sig[32..];
        let recid = recid.serialize();
        let sigs = json!([{
            "r": hex::encode(r),
            "s": hex::encode(s),
            "recid": recid,
        }])
        .to_string();

        let tx = insert_signatures(sigs, 6002, tx, "".to_string()).unwrap();

        let tx = decode_raw_transaction(tx.as_str().unwrap().to_string(), 6002).unwrap();

        println!("{}", tx);
    }
}
