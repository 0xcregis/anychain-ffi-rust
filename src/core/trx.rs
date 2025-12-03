#![allow(unused_imports)]
use super::util::get_signatures;
use anychain_core::transaction::Transaction;
use anychain_tron::{
    abi,
    protocol::{
        balance_contract::{
            CancelAllUnfreezeV2Contract, DelegateResourceContract, FreezeBalanceContract,
            TransferContract, UnDelegateResourceContract, UnfreezeBalanceV2Contract,
            WithdrawBalanceContract, WithdrawExpireUnfreezeContract,
        },
        common::ResourceCode::BANDWIDTH,
        smart_contract::TriggerSmartContract,
        witness_contract::VoteWitnessContract,
        Tron::transaction::contract::ContractType,
    },
    trx::*,
    TronAddress, TronTransaction, TronTransactionParameters,
};
use anyhow::{anyhow, Result};
use ethabi::{decode, ParamType};
use protobuf::Message;
use serde_json::Value;
use std::str::FromStr;

fn parse_tx(tx: String) -> Result<TronTransaction> {
    let params = match serde_json::from_str::<Value>(&tx) {
        Ok(params) => params,
        Err(_) => return Ok(TronTransaction::from_str(&tx)?),
    };

    let owner = params["owner"].as_str().unwrap();
    let now = params["now"].as_i64().unwrap();
    let fee_limit = params["feeLimit"].as_i64().unwrap();
    let block_number = params["blockNumber"].as_i64().unwrap();
    let block_hash = params["blockHash"].as_str().unwrap();

    let mut tx = TronTransactionParameters::default();

    tx.set_fee_limit(fee_limit);
    tx.set_timestamp(now);
    tx.set_ref_block(block_number, block_hash);

    if let Value::Object(op) = &params["operation"] {
        let key = op.keys().next().unwrap().as_str();
        match key {
            "freezeBalance" => {
                // this is a transaction that freezes TRX for resource
                let val = op.get(key).unwrap();

                let amount = val["amount"].as_str().unwrap();
                let resource = val["resource"].as_u64().unwrap() as u8;

                let contract = build_freeze_balance_v2_contract(owner, amount, resource)?;

                tx.set_contract(contract);
            }
            "unfreezeBalance" => {
                // this is a transaction that unfreezes TRX for resource
                let val = op.get(key).unwrap();

                let amount = val["amount"].as_str().unwrap();
                let resource = val["resource"].as_u64().unwrap() as u8;

                let contract = build_unfreeze_balance_v2_contract(owner, amount, resource)?;

                tx.set_contract(contract);
            }
            "delegateResource" => {
                // this is a transaction that delegates resource
                let val = op.get(key).unwrap();

                let recipient = val["recipient"].as_str().unwrap();
                let amount = val["amount"].as_str().unwrap();
                let resource = val["resource"].as_u64().unwrap() as u8;
                let lock = val["lock"].as_bool().unwrap();

                let contract =
                    build_delegate_resource_contract(owner, recipient, resource, amount, lock)?;

                tx.set_contract(contract);
            }
            "undelegateResource" => {
                // this is a transaction that delegates resource
                let val = op.get(key).unwrap();

                let recipient = val["recipient"].as_str().unwrap();
                let amount = val["amount"].as_str().unwrap();
                let resource = val["resource"].as_u64().unwrap() as u8;

                let contract =
                    build_undelegate_resource_contract(owner, recipient, resource, amount)?;

                tx.set_contract(contract);
            }
            "vote" => {
                // this is a transaction that votes
                let val = op.get(key).unwrap();
                let votes = val["votes"].as_array().unwrap();
                let support = val["support"].as_bool().unwrap();

                let votes = votes
                    .iter()
                    .map(|vote| {
                        let address = vote["vote_address"].as_str().unwrap();
                        let vote_count =
                            vote["vote_count"].as_str().unwrap().parse::<i64>().unwrap();
                        (address, vote_count)
                    })
                    .collect::<Vec<(&str, i64)>>();

                let contract = build_vote_witness_contract(owner, votes, support)?;

                tx.set_contract(contract);
            }
            _ => return Err(anyhow!("Unsupported operation")),
        }
    } else if let Value::String(op) = &params["operation"] {
        match op.as_str() {
            "cancelAllUnfreeze" => {
                // this is a transaction that cancels all unfreeze operations
                let contract = build_cancel_unfreeze_contract(owner)?;
                tx.set_contract(contract);
            }
            "withdrawUnfreezeBalance" => {
                // this is a transaction that withdraws unfrozen TRX
                let contract = build_withdraw_unfreeze_contract(owner)?;
                tx.set_contract(contract);
            }
            "withdrawVoteBalance" => {
                // this is a transaction that withdraws rewarded TRX for voting
                let contract = build_withdraw_vote_contract(owner)?;
                tx.set_contract(contract);
            }
            _ => return Err(anyhow!("Unsupported operation")),
        }
    } else if params["contract"].is_string() {
        // this is a transaction that triggers a smart contract
        let sc = params["contract"].as_str().unwrap();
        if params["function"].is_string() {
            let function = params["function"].as_str().unwrap();
            match function {
                "approve" => {
                    // this is a transaction that does the TRC20 approve
                    let to = params["to"].as_str().unwrap();
                    let amount = params["amount"].as_str().unwrap();
                    let contract = build_trc20_approve_contract(owner, sc, to, amount)?;
                    tx.set_contract(contract);
                }
                _ => return Err(anyhow!("Unsupported smart contract function call")),
            }
        } else {
            // this is a transaction that transfers TRC20 tokens
            let to = params["to"].as_str().unwrap();
            let amount = params["amount"].as_str().unwrap();
            let contract = build_trc20_transfer_contract(owner, sc, to, amount)?;
            tx.set_contract(contract);
        }
    } else {
        // this is a transaction that transfers TRX
        let to = params["to"].as_str().unwrap();
        let amount = params["amount"].as_str().unwrap();
        let contract = build_transfer_contract(owner, to, amount)?;
        tx.set_contract(contract);
    }

    Ok(TronTransaction::new(&tx)?)
}

pub fn generate_signing_messages(tx: String) -> Result<Value> {
    let tx = parse_tx(tx)?;
    let tx_id = tx.to_transaction_id()?;
    Ok(json!([hex::encode(tx_id.txid)]))
}

pub fn insert_signatures(signature: String, tx: String) -> Result<Value> {
    let sigs = get_signatures(signature, true)?;
    let mut tx = parse_tx(tx)?;
    let bytes = tx.sign(sigs[0][..64].to_vec(), sigs[0][64])?;
    Ok(json!(hex::encode(bytes)))
}

pub fn decode_raw_transaction(raw_tx: String) -> Result<Value> {
    let mut tx = TronTransaction::from_str(&raw_tx)?;
    let sig = tx.signature;
    tx.signature = None;
    let txid = format!("{}", tx.to_transaction_id()?);
    tx.signature = sig;

    let contract_type = tx.data.contract.type_.unwrap();
    let stream = tx.data.contract.parameter.0.unwrap().value;

    let fee_limit = tx.data.fee_limit as u64;
    let blockhash = hex::encode(&tx.data.ref_block_hash);
    let expiration = tx.data.expiration as u64;
    let timestamp = tx.data.timestamp as u64;

    let mut ret = match contract_type {
        ContractType::TransferContract => {
            let contract = TransferContract::parse_from_bytes(&stream)?;
            let from = TronAddress::from_bytes(&contract.owner_address)?;
            let to = TronAddress::from_bytes(&contract.to_address)?;
            let amount = contract.amount as u64;
            json!({
                "type": "basic",
                "from": from.to_string(),
                "to": to.to_string(),
                "amount": amount.to_string(),
            })
        }
        ContractType::FreezeBalanceV2Contract => {
            let contract = FreezeBalanceContract::parse_from_bytes(&stream)?;
            let from = TronAddress::from_bytes(&contract.owner_address)?;
            let to = TronAddress::from_bytes(&contract.receiver_address)?;
            let balance = contract.frozen_balance as u64;
            let duration = contract.frozen_duration as u64;
            let resource = contract.resource.unwrap();
            json!({
                "type": "freezeBalance",
                "from": from.to_string(),
                "to": to.to_string(),
                "balance": balance.to_string(),
                "duration": duration,
                "resource": if resource == BANDWIDTH { "bandwidth" } else { "energy" },
            })
        }
        ContractType::UnfreezeBalanceV2Contract => {
            let contract = UnfreezeBalanceV2Contract::parse_from_bytes(&stream)?;
            let from = TronAddress::from_bytes(&contract.owner_address)?;
            let balance = contract.unfreeze_balance as u64;
            let resource = contract.resource.unwrap();
            json!({
                "type": "unfreezeBalance",
                "from": from.to_string(),
                "balance": balance.to_string(),
                "resource": if resource == BANDWIDTH { "bandwidth" } else { "energy" },
            })
        }
        ContractType::DelegateResourceContract => {
            let contract = DelegateResourceContract::parse_from_bytes(&stream)?;
            let from = TronAddress::from_bytes(&contract.owner_address)?;
            let to = TronAddress::from_bytes(&contract.receiver_address)?;
            let balance = contract.balance as u64;
            let resource = contract.resource.unwrap();
            let lock = contract.lock;
            let lock_period = contract.lock_period as u64;
            json!({
                "type": "delegateResource",
                "from": from.to_string(),
                "to": to.to_string(),
                "balance": balance.to_string(),
                "resource": if resource == BANDWIDTH { "bandwidth" } else { "energy" },
                "lock": lock,
                "lockPeriod": lock_period,
            })
        }
        ContractType::UnDelegateResourceContract => {
            let contract = UnDelegateResourceContract::parse_from_bytes(&stream)?;
            let from = TronAddress::from_bytes(&contract.owner_address)?;
            let to = TronAddress::from_bytes(&contract.receiver_address)?;
            let balance = contract.balance as u64;
            let resource = contract.resource.unwrap();
            json!({
                "type": "undelegateResource",
                "from": from.to_string(),
                "to": to.to_string(),
                "balance": balance.to_string(),
                "resource": if resource == BANDWIDTH { "bandwidth" } else { "energy" },
            })
        }
        ContractType::CancelAllUnfreezeV2Contract => {
            let contract = CancelAllUnfreezeV2Contract::parse_from_bytes(&stream)?;
            let owner = TronAddress::from_bytes(&contract.owner_address)?;
            json!({
                "type": "cancelAllUnfreeze",
                "from": owner.to_string(),
            })
        }
        ContractType::WithdrawExpireUnfreezeContract => {
            let contract = WithdrawExpireUnfreezeContract::parse_from_bytes(&stream)?;
            let owner = TronAddress::from_bytes(&contract.owner_address)?;
            json!({
                "type": "withdrawUnfreezeBalance",
                "from": owner.to_string(),
            })
        }
        ContractType::VoteWitnessContract => {
            let contract = VoteWitnessContract::parse_from_bytes(&stream)?;
            let owner = TronAddress::from_bytes(&contract.owner_address)?;
            let support = contract.support;
            let mut votes = json!([]);
            for vote in contract.votes {
                let address = TronAddress::from_bytes(&vote.vote_address)?;
                let vote_count = vote.vote_count as u64;
                votes.as_array_mut().unwrap().push(json!({
                    "vote_address": address.to_string(),
                    "vote_count": vote_count,
                }));
            }
            json!({
                "type": "vote",
                "from": owner.to_string(),
                "support": support,
                "votes": votes,
            })
        }
        ContractType::WithdrawBalanceContract => {
            let contract = WithdrawBalanceContract::parse_from_bytes(&stream)?;
            let owner = TronAddress::from_bytes(&contract.owner_address)?;
            json!({
                "type": "withdrawVoteBalance",
                "from": owner.to_string(),
            })
        }
        ContractType::TriggerSmartContract => {
            let contract = TriggerSmartContract::parse_from_bytes(&stream)?;
            let from = TronAddress::from_bytes(&contract.owner_address)?;
            let smart_contract = TronAddress::from_bytes(&contract.contract_address)?;

            let params_types = [ParamType::FixedBytes(32), ParamType::Uint(256)];
            let tokens = decode(&params_types, &contract.data[4..])?;
            let to = TronAddress::from_bytes(&tokens[0].clone().into_fixed_bytes().unwrap()[11..])?
                .clone();
            let amount = tokens[1].clone().into_uint().unwrap();

            match contract.data[..4] {
                [169, 5, 156, 187] => {
                    // we are handling a trc20 transfer
                    json!({
                        "type": "contract",
                        "contract": smart_contract.to_string(),
                        "from": from.to_string(),
                        "to": to.to_string(),
                        "amount": amount.to_string(),
                    })
                }
                [9, 94, 167, 179] => {
                    // we are handling a trc20 approve
                    json!({
                        "type": "contractCall",
                        "contract": smart_contract.to_string(),
                        "from": from.to_string(),
                        "call": {
                            "function": "approve",
                            "to": to.to_string(),
                            "amount": amount.to_string(),
                        }
                    })
                }
                _ => return Err(anyhow!("Unsupported smart contract function call")),
            }
        }
        _ => return Err(anyhow!("Unsupported contract type")),
    };

    let sig = match tx.signature {
        Some(sig) => {
            let sig = sig.to_bytes();
            json!({
                "r": hex::encode(&sig[..32]),
                "s": hex::encode(&sig[32..64]),
                "recid": sig[64],
            })
        }
        None => Value::Null,
    };

    ret.as_object_mut()
        .unwrap()
        .insert("signature".to_string(), sig);

    ret.as_object_mut()
        .unwrap()
        .insert("feeLimit".to_string(), json!(fee_limit));

    ret.as_object_mut()
        .unwrap()
        .insert("reference_blockhash".to_string(), json!(blockhash));

    ret.as_object_mut()
        .unwrap()
        .insert("expiration".to_string(), json!(expiration));

    ret.as_object_mut()
        .unwrap()
        .insert("timestamp".to_string(), json!(timestamp));

    ret.as_object_mut()
        .unwrap()
        .insert("txid".to_string(), json!(txid));

    Ok(ret)
}

#[allow(clippy::unnecessary_to_owned)]
pub fn trc20_transfer_params_abi(address: &str, amount: &str) -> Result<Value> {
    // Trim the first 4 bytes which is the function selector, and
    // return the rest which is the encoding of the parameters
    Ok(json!(hex::encode(
        abi::trc20_transfer(address, amount)[4..].to_vec(),
    )))
}

#[allow(clippy::unnecessary_to_owned)]
pub fn trc20_approve_params_abi(address: &str, amount: &str) -> Result<Value> {
    // Trim the first 4 bytes which is the function selector, and
    // return the rest which is the encoding of the parameters
    Ok(json!(hex::encode(
        abi::trc20_approve(address, amount)[4..].to_vec(),
    )))
}

pub fn estimate_bandwidth(tx: String) -> Result<Value> {
    let mut tx = parse_tx(tx)?;

    let dummy_sig = [1u8; 64];
    let dummy_recid = 1u8;

    let tx = tx.sign(dummy_sig.to_vec(), dummy_recid)?;

    // Bandwidth points to consume equals the byte length of the transaction
    let bandwidth = tx.len() as u32;

    // A value added to bandwidth in tron protocol source code
    let max_result_size_in_tx = 64_u32;

    Ok(json!(bandwidth + max_result_size_in_tx))
}

#[test]
fn test() {
    let transfer = r#"{
        "owner": "TYn6xn1aY3hrsDfLzpyPQtDiKjHEU8Hsxm",
        "to": "TG7jQ7eGsns6nmQNfcKNgZKyKBFkx7CvXr",
        "amount": "1000000",
        "blockHash": "00000000029c1e638dc7c7c2800e88bb20b8f57adfc4c9f417df8d86c2e8537b",
        "blockNumber": 43785827,
        "feeLimit": 1000000,
        "now": 1719572137182
    }"#
    .to_string();

    let trc20_transfer = r#"{
        "contract": "TP31Ua3T6zYAQbcnR2vTbYGd426rouWNoD",
        "owner": "TYn6xn1aY3hrsDfLzpyPQtDiKjHEU8Hsxm",
        "to": "TG7jQ7eGsns6nmQNfcKNgZKyKBFkx7CvXr",
        "amount": "500000000000",
        "blockHash": "00000000029c1e638dc7c7c2800e88bb20b8f57adfc4c9f417df8d86c2e8537b",
        "blockNumber": 43785827,
        "feeLimit": 1000000,
        "now": 1719572137182
    }"#
    .to_string();

    let trc20_approve = r#"{
        "contract": "TP31Ua3T6zYAQbcnR2vTbYGd426rouWNoD",
        "function": "approve",
        "owner": "TYn6xn1aY3hrsDfLzpyPQtDiKjHEU8Hsxm",
        "to": "TG7jQ7eGsns6nmQNfcKNgZKyKBFkx7CvXr",
        "amount": "500000000000",
        "blockHash": "00000000029c1e638dc7c7c2800e88bb20b8f57adfc4c9f417df8d86c2e8537b",
        "blockNumber": 43785827,
        "feeLimit": 1000000,
        "now": 1719572137182
    }"#
    .to_string();

    let freeze = r#"{
        "owner": "TYn6xn1aY3hrsDfLzpyPQtDiKjHEU8Hsxm",
        "operation": {
            "freezeBalance": {
                "amount": "500000000000",
                "resource": 0
            }
        },
        "blockHash": "00000000029c1e638dc7c7c2800e88bb20b8f57adfc4c9f417df8d86c2e8537b",
        "blockNumber": 43785827,
        "feeLimit": 1000000,
        "now": 1719572137182
    }"#
    .to_string();

    let unfreeze = r#"{
        "owner": "TYn6xn1aY3hrsDfLzpyPQtDiKjHEU8Hsxm",
        "operation": {
            "unfreezeBalance": {
                "amount": "500000000000",
                "resource": 1
            }
        },
        "blockHash": "00000000029c1e638dc7c7c2800e88bb20b8f57adfc4c9f417df8d86c2e8537b",
        "blockNumber": 43785827,
        "feeLimit": 1000000,
        "now": 1719572137182
    }"#
    .to_string();

    let delegate = r#"{
        "owner": "TYn6xn1aY3hrsDfLzpyPQtDiKjHEU8Hsxm",
        "operation": {
            "delegateResource": {
                "recipient": "TG7jQ7eGsns6nmQNfcKNgZKyKBFkx7CvXr",
                "amount": "500000000000",
                "resource": 1,
                "lock": true
            }
        },
        "blockHash": "00000000029c1e638dc7c7c2800e88bb20b8f57adfc4c9f417df8d86c2e8537b",
        "blockNumber": 43785827,
        "feeLimit": 1000000,
        "now": 1719572137182
    }"#
    .to_string();

    let undelegate = r#"{
        "owner": "TYn6xn1aY3hrsDfLzpyPQtDiKjHEU8Hsxm",
        "operation": {
            "undelegateResource": {
                "recipient": "TG7jQ7eGsns6nmQNfcKNgZKyKBFkx7CvXr",
                "amount": "500000000000",
                "resource": 1
            }
        },
        "blockHash": "00000000029c1e638dc7c7c2800e88bb20b8f57adfc4c9f417df8d86c2e8537b",
        "blockNumber": 43785827,
        "feeLimit": 1000000,
        "now": 1719572137182
    }"#
    .to_string();

    let cancel = r#"{
        "owner": "TYn6xn1aY3hrsDfLzpyPQtDiKjHEU8Hsxm",
        "operation": "cancelAllUnfreeze",
        "blockHash": "00000000029c1e638dc7c7c2800e88bb20b8f57adfc4c9f417df8d86c2e8537b",
        "blockNumber": 43785827,
        "feeLimit": 1000000,
        "now": 1719572137182
    }"#
    .to_string();

    let withdraw_unfreeze = r#"{
        "owner": "TYn6xn1aY3hrsDfLzpyPQtDiKjHEU8Hsxm",
        "operation": "withdrawUnfreezeBalance",
        "blockHash": "00000000029c1e638dc7c7c2800e88bb20b8f57adfc4c9f417df8d86c2e8537b",
        "blockNumber": 43785827,
        "feeLimit": 1000000,
        "now": 1719572137182
    }"#
    .to_string();

    let vote = r#"{
        "owner": "TYn6xn1aY3hrsDfLzpyPQtDiKjHEU8Hsxm",
        "operation": {
            "vote": {
                "votes": [
                    {
                        "vote_address": "TG7jQ7eGsns6nmQNfcKNgZKyKBFkx7CvXr",
                        "vote_count": "100000000"
                    },
                    {
                        "vote_address": "TYn6xn1aY3hrsDfLzpyPQtDiKjHEU8Hsxm",
                        "vote_count": "200000000"
                    },
                    {
                        "vote_address": "TP31Ua3T6zYAQbcnR2vTbYGd426rouWNoD",
                        "vote_count": "300000000"
                    }
                ],
                "support": true
            }
        },
        "blockHash": "00000000029c1e638dc7c7c2800e88bb20b8f57adfc4c9f417df8d86c2e8537b",
        "blockNumber": 43785827,
        "feeLimit": 1000000,
        "now": 1719572137182
    }"#
    .to_string();

    let withdraw_vote = r#"{
        "owner": "TYn6xn1aY3hrsDfLzpyPQtDiKjHEU8Hsxm",
        "operation": "withdrawVoteBalance",
        "blockHash": "00000000029c1e638dc7c7c2800e88bb20b8f57adfc4c9f417df8d86c2e8537b",
        "blockNumber": 43785827,
        "feeLimit": 1000000,
        "now": 1719572137182
    }"#
    .to_string();

    let msg = generate_signing_messages(transfer).unwrap();
    println!("{}", msg);

    let msg = generate_signing_messages(trc20_transfer).unwrap();
    println!("{}", msg);

    let msg = generate_signing_messages(trc20_approve).unwrap();
    println!("{}", msg);

    let msg = generate_signing_messages(freeze).unwrap();
    println!("{}", msg);

    let msg = generate_signing_messages(unfreeze).unwrap();
    println!("{}", msg);

    let msg = generate_signing_messages(delegate).unwrap();
    println!("{}", msg);

    let msg = generate_signing_messages(undelegate).unwrap();
    println!("{}", msg);

    let msg = generate_signing_messages(cancel).unwrap();
    println!("{}", msg);

    let msg = generate_signing_messages(withdraw_unfreeze).unwrap();
    println!("{}", msg);

    let msg = generate_signing_messages(vote).unwrap();
    println!("{}", msg);

    let msg = generate_signing_messages(withdraw_vote).unwrap();
    println!("{}", msg);
}
