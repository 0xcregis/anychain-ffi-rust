use crate::core;
use anyhow::Result;
use neon::prelude::*;
use serde_json::{json, Value};

fn convert_json(feedback: Result<Value>) -> String {
    let json = match feedback {
        Ok(data) => {
            json!({
                "success": true,
                "payload": data
            })
        }
        Err(e) => {
            json!({
                "success": false,
                "payload": e.to_string()
            })
        }
    };
    json.to_string()
}

fn create_mnemonic(mut cx: FunctionContext) -> JsResult<JsString> {
    let lang_code = parse_string(&mut cx, 0)?;
    let size = parse_i32(&mut cx, 1)?;
    Ok(cx.string(convert_json(core::create_mnemonic(lang_code, size as u8))))
}

fn parse_mnemonic(mut cx: FunctionContext) -> JsResult<JsString> {
    let phrase = parse_string(&mut cx, 0)?;
    Ok(cx.string(convert_json(core::parse_mnemonic(phrase))))
}

fn generate_master_xpub(mut cx: FunctionContext) -> JsResult<JsString> {
    let public_key = parse_string_with_error(&mut cx, 0, "public key is required")?;
    let chain_code = parse_string_with_error(&mut cx, 1, "chain code is required")?;
    Ok(cx.string(convert_json(core::generate_master_xpub(
        public_key, chain_code,
    ))))
}

fn create_address(mut cx: FunctionContext) -> JsResult<JsString> {
    let xpub_bs58 = parse_string_with_error(&mut cx, 0, "xpub is required")?;
    let chain_type = parse_u32_with_error(&mut cx, 1, "chain_type is required")?;
    let index1 = parse_u32_with_error(&mut cx, 2, "path index1 is required")?;
    let index2 = parse_u32_with_error(&mut cx, 3, "path index2 is required")?;
    let format = parse_string_with_error(&mut cx, 4, "address format is required")?;
    Ok(cx.string(convert_json(core::create_address(
        xpub_bs58, chain_type, index1, index2, format,
    ))))
}

fn generate_signing_messages(mut cx: FunctionContext) -> JsResult<JsString> {
    let chain_type = parse_u32_with_error(&mut cx, 0, "chain type is required")?;
    let raw_tx_hex = parse_string(&mut cx, 1)?;
    let reserved = parse_string(&mut cx, 2)?;
    Ok(cx.string(convert_json(core::generate_signing_messages(
        chain_type, raw_tx_hex, reserved,
    ))))
}

fn insert_signatures(mut cx: FunctionContext) -> JsResult<JsString> {
    let signature = parse_string_with_error(&mut cx, 0, "signatures are required")?;
    let chain_type = parse_u32(&mut cx, 1)?;
    let raw_tx_hex = parse_string(&mut cx, 2)?;
    let reserved = parse_string_with_error(&mut cx, 3, "reserved is required")?;
    Ok(cx.string(convert_json(core::insert_signatures(
        signature, chain_type, raw_tx_hex, reserved,
    ))))
}

fn decode_raw_transaction(mut cx: FunctionContext) -> JsResult<JsString> {
    let raw_tx = parse_string_with_error(&mut cx, 0, "raw transaction stream required")?;
    let chain_type = parse_u32(&mut cx, 1)?;
    Ok(cx.string(convert_json(core::decode_raw_transaction(
        raw_tx, chain_type,
    ))))
}

fn verify_address(mut cx: FunctionContext) -> JsResult<JsString> {
    let address = parse_string_with_error(&mut cx, 0, "address is required")?;
    let chain_type = parse_u32(&mut cx, 1)?;
    Ok(cx.string(convert_json(core::verify_address(address, chain_type))))
}

fn transfer_params_abi(mut cx: FunctionContext) -> JsResult<JsString> {
    let address = parse_string_with_error(&mut cx, 0, "address is required")?;
    let amount = parse_string_with_error(&mut cx, 1, "amount is required")?;
    let chain_type = parse_u32(&mut cx, 2)?;
    Ok(cx.string(convert_json(core::transfer_params_abi(
        address, amount, chain_type,
    ))))
}

fn approve_params_abi(mut cx: FunctionContext) -> JsResult<JsString> {
    let address = parse_string_with_error(&mut cx, 0, "address is required")?;
    let amount = parse_string_with_error(&mut cx, 1, "amount is required")?;
    let chain_type = parse_u32(&mut cx, 2)?;
    Ok(cx.string(convert_json(core::approve_params_abi(
        address, amount, chain_type,
    ))))
}

fn estimate_bandwidth(mut cx: FunctionContext) -> JsResult<JsString> {
    let params = parse_string_with_error(&mut cx, 0, "params is required")?;
    let chain_type = parse_u32(&mut cx, 1)?;
    let reserved = parse_string_with_error(&mut cx, 2, "reserved is required")?;
    Ok(cx.string(convert_json(core::estimate_bandwidth(
        params, chain_type, reserved,
    ))))
}

fn keygen(mut cx: FunctionContext) -> JsResult<JsString> {
    Ok(cx.string(convert_json(core::keygen())))
}

fn sign(mut cx: FunctionContext) -> JsResult<JsString> {
    let data = parse_string_with_error(&mut cx, 0, "data is required")?;
    let sk = parse_string_with_error(&mut cx, 1, "secret key is required")?;
    Ok(cx.string(convert_json(core::sign(&data, &sk))))
}

fn verify(mut cx: FunctionContext) -> JsResult<JsString> {
    let data = parse_string_with_error(&mut cx, 0, "data is required")?;
    let sig = parse_string_with_error(&mut cx, 1, "signature is required")?;
    let pk = parse_string_with_error(&mut cx, 2, "public key is required")?;
    Ok(cx.string(convert_json(core::verify(&data, &sig, &pk))))
}

fn hash(mut cx: FunctionContext) -> JsResult<JsString> {
    let data = parse_string_with_error(&mut cx, 0, "data is required")?;
    Ok(cx.string(convert_json(core::hash(&data))))
}

fn encrypt(mut cx: FunctionContext) -> JsResult<JsString> {
    let data = parse_string_with_error(&mut cx, 0, "data is required")?;
    let sk = parse_string_with_error(&mut cx, 1, "secret key is required")?;
    Ok(cx.string(convert_json(core::encrypt(&data, &sk))))
}

fn decrypt(mut cx: FunctionContext) -> JsResult<JsString> {
    let data = parse_string_with_error(&mut cx, 0, "data is required")?;
    let sk = parse_string_with_error(&mut cx, 1, "secret key is required")?;
    Ok(cx.string(convert_json(core::decrypt(&data, &sk))))
}

fn json_digest(mut cx: FunctionContext) -> JsResult<JsString> {
    let json = parse_string_with_error(&mut cx, 0, "json string is required")?;
    Ok(cx.string(convert_json(core::json_digest(&json))))
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("createMnemonic", create_mnemonic)?;
    cx.export_function("parseMnemonic", parse_mnemonic)?;
    cx.export_function("generateMasterXpub", generate_master_xpub)?;
    cx.export_function("createAddress", create_address)?;
    cx.export_function("generateSigningMessages", generate_signing_messages)?;
    cx.export_function("insertSignatures", insert_signatures)?;
    cx.export_function("decodeRawTransaction", decode_raw_transaction)?;
    cx.export_function("verifyAddress", verify_address)?;
    cx.export_function("transferParamsAbi", transfer_params_abi)?;
    cx.export_function("approveParamsAbi", approve_params_abi)?;
    cx.export_function("estimateBandwidth", estimate_bandwidth)?;
    cx.export_function("keygen", keygen)?;
    cx.export_function("sign", sign)?;
    cx.export_function("verify", verify)?;
    cx.export_function("hash", hash)?;
    cx.export_function("encrypt", encrypt)?;
    cx.export_function("decrypt", decrypt)?;
    cx.export_function("jsonDigest", json_digest)?;
    Ok(())
}

pub fn parse_usize(cx: &mut FunctionContext, i: i32) -> NeonResult<usize> {
    let arg = cx.argument::<JsNumber>(i)?;
    let real_value: usize = arg.value(cx) as usize;
    Ok(real_value)
}

pub fn parse_i64(cx: &mut FunctionContext, i: i32) -> NeonResult<i64> {
    let arg = cx.argument::<JsNumber>(i)?;
    let real_value: i64 = arg.value(cx) as i64;
    Ok(real_value)
}

pub fn parse_i64_opt(cx: &mut FunctionContext, i: i32, default_val: i64) -> NeonResult<i64> {
    match cx.argument_opt(i) {
        Some(_) => parse_i64(cx, i),
        None => Ok(default_val),
    }
}

pub fn parse_i32(cx: &mut FunctionContext, i: i32) -> NeonResult<i32> {
    let arg = cx.argument::<JsNumber>(i)?;
    let real_value: i32 = arg.value(cx) as i32;
    Ok(real_value)
}

pub fn parse_u32(cx: &mut FunctionContext, i: i32) -> NeonResult<u32> {
    let arg = cx.argument::<JsNumber>(i)?;
    let real_value: u32 = arg.value(cx) as u32;
    Ok(real_value)
}

pub fn parse_i32_opt(cx: &mut FunctionContext, i: i32, default_val: i32) -> NeonResult<i32> {
    match cx.argument_opt(i) {
        Some(_) => parse_i32(cx, i),
        None => Ok(default_val),
    }
}

pub fn parse_i32_with_error(cx: &mut FunctionContext, i: i32, err_msg: &str) -> NeonResult<i32> {
    parse_i32(cx, i).or_else(|_| cx.throw_error(err_msg))
}

pub fn parse_u32_with_error(cx: &mut FunctionContext, i: i32, err_msg: &str) -> NeonResult<u32> {
    parse_u32(cx, i).or_else(|_| cx.throw_error(err_msg))
}

pub fn parse_string(cx: &mut FunctionContext, i: i32) -> NeonResult<String> {
    let arg = cx.argument::<JsString>(i)?;
    let real_value = arg.value(cx);
    Ok(real_value)
}

pub fn parse_string_with_error(
    cx: &mut FunctionContext,
    i: i32,
    err_msg: &str,
) -> NeonResult<String> {
    let arg = cx
        .argument::<JsString>(i)
        .or_else(|_| cx.throw_error(err_msg))?;
    let real_value = arg.value(cx);
    Ok(real_value)
}
