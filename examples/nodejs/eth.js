const ffi = require('ffi-napi')
const fs = require('fs')
const chainlib = new ffi.Library(
    "../../target/release/libanychain_ffi_lib.dylib",
    {
        'generate_master_xpub': ['string', ['string', 'string']],
        'create_address': ['string', ['string', 'int', 'int', 'int', 'string']],
        'generate_signing_messages': ['string', ['int', 'string', 'string']],
        'insert_signatures': ['string', ['string', 'int', 'string', 'string']],
        'verify_address': ['string', ['string', 'int']],
        'decode_raw_transaction': ['string', ['string', 'int']],
    }
)
const payload = function (arg) {
    return JSON.parse(arg).payload
}
const assert = function (left, right, msg) {
    console.assert(JSON.stringify(left) == JSON.stringify(right), msg)
}

let raw_pk = '[3,136,171,159,115,65,187,211,46,38,153,244,109,148,169,22,149,183,58,112,0,152,80,232,28,214,191,199,154,150,97,233,216]'
let chain_code = "2cf783fd09e5d80c68f8351b564ac71e5e50e1827aa03474e39b8035260532c9"
let xpub = payload(chainlib.generate_master_xpub(raw_pk, chain_code))
assert(
    'xpub661MyMwAqRbcEzQAuTRFpp8Wvo7QDHrQ4MxXMRuRSxUUXnKbUq6GdUmUfp2QY9j8Hu21juYrgQYUfd39GitgR9kKkDykohHYAjDpVVBdGjJ',
    xpub
)

let address = payload(chainlib.create_address(xpub, 60, 0, 1, ''))
assert('0x9ee9c2fc1078403a6a1368f7ec2b9dcc1a9c57fa', address)

let res = payload(chainlib.verify_address(address, 60))
assert(true, res)

let tx = JSON.stringify({
    to: "0xd62eFebf27BC254a441692BCcB7Ce1097E2e4D3a",
    amount: "10000000000000000",
    gasLimit: "21000",
    gasPrice: "100000000000",
    nonce: 7
})
let messages = chainlib.generate_signing_messages(6002, tx, '')
console.log(messages)

let sigs = JSON.stringify(
    [
        {
            r: '04dddcb39a25026d627c5b3f8d4e5aa657c0634eaac69ebb63c37af943dade06',
            recid: 1,
            s: '305a4f18d3cd3dc690a5626e6b9560dc0140d521607cd5e4c9d6955ca7f215f7'
        }
    ]
)

let signed_tx = payload(chainlib.insert_signatures(sigs, 6002, tx, ''))
assert(
    '0xf86f0785174876e80082520894d62efebf27bc254a441692bccb7ce1097e2e4d3a872386f26fc10000808401546d72a004dddcb39a25026d627c5b3f8d4e5aa657c0634eaac69ebb63c37af943dade06a0305a4f18d3cd3dc690a5626e6b9560dc0140d521607cd5e4c9d6955ca7f215f7',
    signed_tx);
let raw_tx = payload(chainlib.decode_raw_transaction(signed_tx, 6002))

console.log('eth.js passed')