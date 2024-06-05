use crate::core;
use anyhow::Result;
use serde_json::Value;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

fn to_chars(content: String) -> *mut c_char {
    let c_str_content = CString::new(content).unwrap();
    c_str_content.into_raw()
}

fn to_json_string(feedback: Result<Value>) -> *mut c_char {
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
    to_chars(json.to_string())
}

macro_rules! c_char_to_string {
    ($chars: ident) => {
        unsafe {
            if $chars.is_null() {
                return error(format!("{} cannot be null", stringify!($chars)));
            }
            CStr::from_ptr($chars).to_string_lossy().into_owned()
        }
    };
}

/**
 * Return failure json message
 */
fn error(msg: String) -> *mut c_char {
    let resp = json!({
        "success": false,
        "payload": msg
    });
    to_chars(resp.to_string())
}

#[no_mangle]
pub extern "C" fn create_mnemonic(lang_code: *const c_char, size: u8) -> *mut c_char {
    let lang_code = c_char_to_string!(lang_code);
    to_json_string(core::create_mnemonic(lang_code, size))
}

#[no_mangle]
pub extern "C" fn parse_mnemonic(phrase: *const c_char) -> *mut c_char {
    let phrase = c_char_to_string!(phrase);
    to_json_string(core::parse_mnemonic(phrase))
}

#[no_mangle]
pub extern "C" fn generate_master_xpub(
    public_key: *const c_char,
    chain_code: *const c_char,
) -> *mut c_char {
    let public_key = c_char_to_string!(public_key);
    let chain_code = c_char_to_string!(chain_code);
    to_json_string(core::generate_master_xpub(public_key, chain_code))
}

#[no_mangle]
pub extern "C" fn create_address(
    xpub: *const c_char,
    chain_type: u32,
    index1: u32,
    index2: u32,
) -> *mut c_char {
    let xpub = c_char_to_string!(xpub);
    to_json_string(core::create_address(xpub, chain_type, index1, index2))
}

#[no_mangle]
pub extern "C" fn build_raw_transaction(param: *const c_char, chain_type: u32) -> *mut c_char {
    let param = c_char_to_string!(param);
    to_json_string(core::build_raw_transaction(param, chain_type))
}

#[no_mangle]
pub extern "C" fn raw_transaction_signing_hashes(
    chain_type: u32,
    raw_transaction: *const c_char,
    reserved: *const c_char,
) -> *mut c_char {
    let raw_transaction = c_char_to_string!(raw_transaction);
    let reserved = c_char_to_string!(reserved);
    to_json_string(core::raw_transaction_signing_hashes(
        chain_type,
        raw_transaction,
        reserved,
    ))
}

#[no_mangle]
pub extern "C" fn insert_signatures(
    signature: *const c_char,
    chain_type: u32,
    raw_transaction: *const c_char,
    reserved: *const c_char,
) -> *mut c_char {
    let signature = c_char_to_string!(signature);
    let raw_transaction = c_char_to_string!(raw_transaction);
    let reserved = c_char_to_string!(reserved);
    to_json_string(core::insert_signatures(
        signature,
        chain_type,
        raw_transaction,
        reserved,
    ))
}

#[no_mangle]
pub extern "C" fn decode_raw_transaction(
    raw_transaction: *const c_char,
    chain_type: u32,
) -> *mut c_char {
    let raw_transaction = c_char_to_string!(raw_transaction);
    to_json_string(core::decode_raw_transaction(raw_transaction, chain_type))
}

#[no_mangle]
pub extern "C" fn verify_address(address: *const c_char, chain_type: u32) -> *mut c_char {
    let address = c_char_to_string!(address);
    to_json_string(core::verify_address(address, chain_type))
}

#[no_mangle]
pub extern "C" fn estimate_bandwidth(
    params: *const c_char,
    chain_type: u32,
    reserved: *const c_char,
) -> *mut c_char {
    let params = c_char_to_string!(params);
    let reserved = c_char_to_string!(reserved);
    to_json_string(core::estimate_bandwidth(params, chain_type, reserved))
}

#[no_mangle]
pub extern "C" fn transaction_parameters_use_case(chain_type: u32) -> *mut c_char {
    to_json_string(core::transaction_parameters_use_case(chain_type))
}

#[no_mangle]
pub extern "C" fn cregis_keygen() -> *mut c_char {
    to_json_string(core::keygen())
}

#[no_mangle]
pub extern "C" fn cregis_sign(data: *const c_char, secret_key: *const c_char) -> *mut c_char {
    let data = c_char_to_string!(data);
    let sk = c_char_to_string!(secret_key);
    to_json_string(core::sign(&data, &sk))
}

#[no_mangle]
pub extern "C" fn cregis_verify(
    data: *const c_char,
    signature: *const c_char,
    public_key: *const c_char,
) -> *mut c_char {
    let data = c_char_to_string!(data);
    let sig = c_char_to_string!(signature);
    let pk = c_char_to_string!(public_key);
    to_json_string(core::verify(&data, &sig, &pk))
}

#[no_mangle]
pub extern "C" fn cregis_hash(data: *const c_char) -> *mut c_char {
    let data = c_char_to_string!(data);
    to_json_string(core::hash(&data))
}
