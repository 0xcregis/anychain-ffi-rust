use anyhow::{anyhow, Result};
use serde_json::Value;

pub(crate) fn get_signatures(sigs: String, need_recid: bool) -> Result<Vec<Vec<u8>>> {
    let sigs = serde_json::from_str::<Value>(&sigs)?;
    if !sigs.is_array() {
        return Err(anyhow!("signatures should be a json array"));
    }

    let sigs = sigs.as_array().unwrap();
    let mut ret = vec![];

    for sig in sigs {
        let r = sig["r"].as_str().unwrap();
        let s = sig["s"].as_str().unwrap();
        let recid = sig["recid"].as_u64().unwrap() as u8;
        if r.len() != 64 || s.len() != 64 {
            return Err(anyhow!("Invaid signature length"));
        }
        let r = hex::decode(r).unwrap();
        let s = hex::decode(s).unwrap();
        if need_recid {
            ret.push([r, s, vec![recid]].concat());
        } else {
            ret.push([r, s].concat());
        }
    }

    Ok(ret)
}

pub(crate) fn insert(val: &mut Value, key: &str, value: &str) {
    val.as_object_mut()
        .unwrap()
        .insert(key.to_string(), json!(value));
}

pub(crate) fn is_1st_round_params(tx: &str) -> Result<bool> {
    let params = serde_json::from_str::<Value>(tx)?;
    let tx_type = &params["type"];
    if tx_type.is_null() {
        return Ok(false);
    }
    if !tx_type.is_string() {
        return Err(anyhow!("transaction type should be string"));
    }
    match tx_type.as_str().unwrap() {
        "eip3009_1st_round" => Ok(true),
        _ => Ok(false),
    }
}
