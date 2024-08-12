use super::util::get_signatures;
use anychain_core::transaction::Transaction;
use anychain_tron::{
    abi,
    protocol::{
        balance_contract::{
            DelegateResourceContract, FreezeBalanceContract, TransferContract,
            UnDelegateResourceContract, UnfreezeBalanceV2Contract,
        },
        common::ResourceCode::BANDWIDTH,
        smart_contract::TriggerSmartContract,
        Tron::transaction::contract::ContractType,
    },
    trx, TronAddress, TronTransaction, TronTransactionParameters,
};
use anyhow::{anyhow, Result};
use ethabi::{decode, ParamType};
use protobuf::Message;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;

#[derive(Debug, Default, Serialize, Deserialize)]
enum TrxOperation {
    #[serde(rename = "freezeBalance")]
    FreezeBalanceV2 { amount: String, resource: u8 },

    #[serde(rename = "unfreezeBalance")]
    UnfreezeBalanceV2 { amount: String, resource: u8 },

    #[serde(rename = "delegateResource")]
    DelegateResource {
        recipient: String,
        amount: String,
        resource: u8,
        lock: bool,
    },

    #[serde(rename = "undelegateResource")]
    UndelegateResource {
        recipient: String,
        amount: String,
        resource: u8,
    },

    #[default]
    None,
}

#[derive(Debug, Serialize, Deserialize)]
struct TrxParams {
    #[serde(rename = "permissionId", default)]
    pub permission_id: i32,
    #[serde(default)]
    pub operation: TrxOperation,
    #[serde(default)]
    pub contract: String,
    #[serde(default)]
    pub function: String,
    pub owner: String,
    #[serde(default)]
    pub to: String,
    #[serde(default)]
    pub amount: String,
    #[serde(rename = "blockHash")]
    pub block_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: i64,
    pub nonce: i32,
    #[serde(rename = "feeLimit", default = "TrxParams::default_fee_limit")]
    pub fee_limit: i64,
    pub now: i64,
}

impl TrxParams {
    pub fn default_fee_limit() -> i64 {
        10 * 1000000
    }
}

pub fn parse_tx(tx: String) -> Result<TronTransaction> {
    let params: TrxParams = serde_json::from_str(&tx)?;

    let mut tx_params = TronTransactionParameters::default();
    tx_params.set_fee_limit(params.fee_limit);
    tx_params.set_timestamp(params.now + (params.nonce as i64));
    tx_params.set_ref_block(params.block_number, &params.block_hash);

    if let TrxOperation::FreezeBalanceV2 { amount, resource } = params.operation {
        // this is a transaction that freezes TRX for resource
        let mut contract = trx::build_freeze_balance_v2_contract(&params.owner, &amount, resource)?;
        contract.Permission_id = params.permission_id;
        tx_params.set_contract(contract);
    } else if let TrxOperation::UnfreezeBalanceV2 { amount, resource } = params.operation {
        // this is a transaction that unfreezes TRX for resource
        let mut contract =
            trx::build_unfreeze_balance_v2_contract(&params.owner, &amount, resource)?;
        contract.Permission_id = params.permission_id;
        tx_params.set_contract(contract);
    } else if let TrxOperation::DelegateResource {
        recipient,
        amount,
        resource,
        lock,
    } = params.operation
    {
        // this is a transaction that delegates resource
        let mut contract = trx::build_delegate_resource_contract(
            &params.owner,
            &recipient,
            resource,
            &amount,
            lock,
        )?;
        contract.Permission_id = params.permission_id;
        tx_params.set_contract(contract);
    } else if let TrxOperation::UndelegateResource {
        recipient,
        amount,
        resource,
    } = params.operation
    {
        // this is a transaction that undelegates resource
        let mut contract =
            trx::build_undelegate_resource_contract(&params.owner, &recipient, resource, &amount)?;
        contract.Permission_id = params.permission_id;
        tx_params.set_contract(contract);
    } else if !params.contract.is_empty() {
        // 'contract' is not empty, indicating this is a transaction that calls contract function
        if params.function.eq("approve") {
            // 'function' is "approve", indicationg this is a transaction that calls TRC20 approve()
            let mut contract = trx::build_trc20_approve_contract(
                &params.owner,
                &params.contract,
                &params.to,
                &params.amount,
            )?;
            contract.Permission_id = params.permission_id;
            tx_params.set_contract(contract);
        } else {
            // By default, we regard it a transaction that calls TRC20 transfer()
            let mut contract = trx::build_trc20_transfer_contract(
                &params.owner,
                &params.contract,
                &params.to,
                &params.amount,
            )?;
            contract.Permission_id = params.permission_id;
            tx_params.set_contract(contract);
        }
    } else {
        // this is a transaction that transfers TRX
        let mut contract = trx::build_transfer_contract(&params.owner, &params.to, &params.amount)?;
        contract.Permission_id = params.permission_id;
        tx_params.set_contract(contract);
        // A plain TRX transfer does not consume any fee
        tx_params.set_fee_limit(0);
    }

    Ok(TronTransaction::new(&tx_params)?)
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
            let from = TronAddress::from_bytes(&contract.owner_address);
            let to = TronAddress::from_bytes(&contract.to_address);
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
            let from = TronAddress::from_bytes(&contract.owner_address);
            let to = TronAddress::from_bytes(&contract.receiver_address);
            let balance = contract.frozen_balance as u64;
            let duration = contract.frozen_duration as u64;
            let resource = contract.resource.unwrap();
            json!({
                "type": "freezeBalanceV2",
                "from": from.to_string(),
                "to": to.to_string(),
                "balance": balance.to_string(),
                "duration": duration,
                "resource": if resource == BANDWIDTH { "bandwidth" } else { "energy" },
            })
        }
        ContractType::UnfreezeBalanceV2Contract => {
            let contract = UnfreezeBalanceV2Contract::parse_from_bytes(&stream)?;
            let from = TronAddress::from_bytes(&contract.owner_address);
            let balance = contract.unfreeze_balance as u64;
            let resource = contract.resource.unwrap();
            json!({
                "type": "unfreezeBalanceV2",
                "from": from.to_string(),
                "balance": balance.to_string(),
                "resource": if resource == BANDWIDTH { "bandwidth" } else { "energy" },
            })
        }
        ContractType::DelegateResourceContract => {
            let contract = DelegateResourceContract::parse_from_bytes(&stream)?;
            let from = TronAddress::from_bytes(&contract.owner_address);
            let to = TronAddress::from_bytes(&contract.receiver_address);
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
            let from = TronAddress::from_bytes(&contract.owner_address);
            let to = TronAddress::from_bytes(&contract.receiver_address);
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
        ContractType::TriggerSmartContract => {
            let contract = TriggerSmartContract::parse_from_bytes(&stream)?;
            let from = TronAddress::from_bytes(&contract.owner_address);
            let smart_contract = TronAddress::from_bytes(&contract.contract_address);

            let params_types = [ParamType::FixedBytes(32), ParamType::Uint(256)];
            let tokens = decode(&params_types, &contract.data[4..])?;
            let to = TronAddress::from_bytes(&tokens[0].clone().into_fixed_bytes().unwrap()[11..])
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

pub fn trc20_transfer_params_abi(address: &str, amount: &str) -> Result<Value> {
    // Trim the first 4 bytes which is the function selector, and
    // return the rest which is the encoding of the parameters
    Ok(json!(hex::encode(
        &abi::trc20_transfer(address, amount)[4..]
    )))
}

pub fn trc20_approve_params_abi(address: &str, amount: &str) -> Result<Value> {
    // Trim the first 4 bytes which is the function selector, and
    // return the rest which is the encoding of the parameters
    Ok(json!(hex::encode(
        &abi::trc20_approve(address, amount)[4..]
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
    let tx = "0ad3010a02d6a92208edd32db513dae85d40d186d8e88e325aae01081f12a9010a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a15414b88a3bdde68b80b09a084f03b16c07ab190da06121541d248267c24ff51ef27c96a7ab8d9d378d08d36782244a9059cbb0000000000000000000000415083fea182cab5aa5082e5db92a5497b17a895230000000000000000000000000000000000000000000000056bc75e2d6310000070f1dec5e88e32900180c2d72f1241e8c226766bf52da7ac749d4ecb45d77b1c21bfceb546927a46cd97290f6ddb5a58ba14732954d78f971f238423837e25792c80ddd4e285b24b70d8cbe82978b101";
    let tx = decode_raw_transaction(tx.to_string()).unwrap();

    println!("{}", tx);
}

#[test]
fn test_generate_signing_messages() {
    let trx_params = TrxParams {
        permission_id: 1,
        operation: TrxOperation::None,
        contract: "TP31Ua3T6zYAQbcnR2vTbYGd426rouWNoD".to_string(),
        function: "transfer".to_string(),
        owner: "TYn6xn1aY3hrsDfLzpyPQtDiKjHEU8Hsxm".to_string(),
        to: "TG7jQ7eGsns6nmQNfcKNgZKyKBFkx7CvXr".to_string(),
        amount: "500".to_string(),
        block_hash: "00000000029c1e638dc7c7c2800e88bb20b8f57adfc4c9f417df8d86c2e8537b".to_string(),
        block_number: 43785827,
        nonce: 2,
        fee_limit: 1000000,
        now: 16157900,
    };

    let serialized = serde_json::to_string(&trx_params).unwrap();

    let messages = generate_signing_messages(serialized).unwrap();
    assert_eq!(
        messages,
        json!(["ebcb724f0b9b27881d2bd714b87a334d093fe4019cb8328dbd04a392a44cc822"])
    );
}
