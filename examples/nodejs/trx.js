const ffi = require('ffi-napi')
const chainlib = new ffi.Library(
    "../../target/release/libcregis_chainlib.so",
    {
        'generate_master_xpub': ['string', ['string', 'string']],
        'create_address': ['string', ['string', 'int', 'int', 'int']],
        'generate_signing_messages': ['string', ['int', 'string', 'string']],
        'insert_signatures': ['string', ['string', 'int', 'string', 'string']],
        'verify_address': ['string', ['string', 'int']],
        'transfer_params_abi': ['string', ['string', 'string', 'int']],
        'approve_params_abi': ['string', ['string', 'string', 'int']],
        'estimate_bandwidth': ['string', ['string', 'int', 'string']],
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


let address = payload(chainlib.create_address(xpub, 195, 0, 1))
assert('TVEqXkgEuZo9G2FiScYx4fu8KPAwHGqB9g', address)


let tx = JSON.stringify({
    contract: "TP31Ua3T6zYAQbcnR2vTbYGd426rouWNoD",
    owner: "TYn6xn1aY3hrsDfLzpyPQtDiKjHEU8Hsxm",
    to: "TG7jQ7eGsns6nmQNfcKNgZKyKBFkx7CvXr",
    amount: "500000000000",
    blockHash: "00000000029c1e638dc7c7c2800e88bb20b8f57adfc4c9f417df8d86c2e8537b",
    blockNumber: 43785827,
    nonce: 2,
    feeLimit: 1000000,
})
let messages = payload(chainlib.generate_signing_messages(195, tx, ''))
assert(['c266d2083a8ee1d3ae59cb65bcbb2c865b52df194461fc3b85d81e50e7416aae'], messages)


let sigs = JSON.stringify(
    [
        {
            r: "0732ccdf0c8a5b29bd9fd80cb9f4ef49bb01163b04189ab5ab8e78f2a718bb4e",
            s: "7c7e1b9666528dba4a583e45df730101ebdc824012cbda942771c19089be5f05",
            recid: 0,
        }
    ]
)
let signed_tx = payload(chainlib.insert_signatures(sigs, 195, tx, ''))
assert(
    '0ad2010a021e6322088dc7c7c2800e88bb40e5eea1a0f2315aae01081f12a9010a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a1541fa3146ab779ce02392d11209f524ee75d4088a451215418f51ad8aa52eab17c1cf1ed12479edac69b64b112244a9059cbb000000000000000000000041436d74fc1577266b7290b85801145d9c5287e194000000000000000000000000000000000000000000000000000000746a5288007085c78fa0f2319001c0843d12410732ccdf0c8a5b29bd9fd80cb9f4ef49bb01163b04189ab5ab8e78f2a718bb4e7c7e1b9666528dba4a583e45df730101ebdc824012cbda942771c19089be5f0500',
    signed_tx
)


let res = payload(chainlib.verify_address(address, 195))
assert(true, res)


let transfer_abi = payload(chainlib.transfer_params_abi('TVEqXkgEuZo9G2FiScYx4fu8KPAwHGqB9g', "30000", 195))
assert(
    '000000000000000000000041d35f1f541e814d8caa9e8db746844c00972dd36d0000000000000000000000000000000000000000000000000000000000007530',
    transfer_abi
)


let approve_abi = payload(chainlib.approve_params_abi('TVEqXkgEuZo9G2FiScYx4fu8KPAwHGqB9g', "30000", 195))
assert(
    '000000000000000000000041d35f1f541e814d8caa9e8db746844c00972dd36d0000000000000000000000000000000000000000000000000000000000007530',
    approve_abi
)


let bandwidth = payload(chainlib.estimate_bandwidth(tx_params, 195, ''))
assert(344, bandwidth)