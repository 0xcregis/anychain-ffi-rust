const ffi = require('ffi-napi')
const anychain_ffi_lib = new ffi.Library(
    "../../target/release/libanychain_ffi_lib.dylib",
    {
        'generate_master_xpub': ['string', ['string', 'string']],
        'create_address': ['string', ['string', 'int', 'int', 'int', 'string']],
        'generate_signing_messages': ['string', ['int', 'string', 'string']],
        'insert_signatures': ['string', ['string', 'int', 'string', 'string']],
        'verify_address': ['string', ['string', 'int']],
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
let xpub = payload(anychain_ffi_lib.generate_master_xpub(raw_pk, chain_code))
assert(
    'xpub661MyMwAqRbcEzQAuTRFpp8Wvo7QDHrQ4MxXMRuRSxUUXnKbUq6GdUmUfp2QY9j8Hu21juYrgQYUfd39GitgR9kKkDykohHYAjDpVVBdGjJ',
    xpub
)


let address = payload(anychain_ffi_lib.create_address(xpub, 0, 0, 1, '1'))
assert('1EjwNvzypjwuYuqZFcX3wSfPpPf5sNG9b5', address)


let tx = JSON.stringify({
    "inputs": [
        {
            "txid": "56091f6bbb619518dbb5789d1b20de1c96fe2ca9d931df57a1eab12a7ab61c36",
            "index": 2
        },
        {
            "txid": "ba2bcfed866d89c59110901ee513ffaba1ab6c8e3b99ab8d386c0f8fc0f8a38b",
            "index": 1
        }
    ],
    "outputs": [
        {
            "to": "1ASxbWAVJgSmECShbr7pNFhuFtbxwn7aww",
            "amount": 10000
        },
        {
            "to": "1EjwNvzypjwuYuqZFcX3wSfPpPf5sNG9b5",
            "amount": 5000
        }
    ]
})
let reserved = JSON.stringify({
    "master_xpub": xpub,
    "infos": ["m/44/0/0/0/1", "m/44/0/0/0/2"]
})
let messages = payload(anychain_ffi_lib.generate_signing_messages(0, tx, reserved))
assert(
    [
        'a664d06527b9d9a9fbc6821c6fbd673b91174ad18887e1fe21c98e44c390a93e',
        '7759eddab27becaf4252dfeeb01ded55932acf873d155545fbd4e04f1d9aa13c'
    ],
    messages
)


let sigs = JSON.stringify(
    [
        {
            r: "0732ccdf0c8a5b29bd9fd80cb9f4ef49bb01163b04189ab5ab8e78f2a718bb4e",
            s: "7c7e1b9666528dba4a583e45df730101ebdc824012cbda942771c19089be5f05",
            recid: 0,
        },
        // just for demo, so it's ok to have same signature
        {
            r: "0732ccdf0c8a5b29bd9fd80cb9f4ef49bb01163b04189ab5ab8e78f2a718bb4e",
            s: "7c7e1b9666528dba4a583e45df730101ebdc824012cbda942771c19089be5f05",
            recid: 0,
        }
    ]
)
let signed_tx = payload(anychain_ffi_lib.insert_signatures(sigs, 0, tx, reserved))
assert(
    '0200000002361cb67a2ab1eaa157df31d9a92cfe961cde201b9d78b5db189561bb6b1f0956020000006a47304402200732ccdf0c8a5b29bd9fd80cb9f4ef49bb01163b04189ab5ab8e78f2a718bb4e02207c7e1b9666528dba4a583e45df730101ebdc824012cbda942771c19089be5f0501210398a0ab654d1a0ae00224e898102e8d086b9dcdae0a49ad183382bd98b73ea66df2ffffff8ba3f8c08f0f6c388dab993b8e6caba1abff13e51e901091c5896d86edcf2bba010000006a47304402200732ccdf0c8a5b29bd9fd80cb9f4ef49bb01163b04189ab5ab8e78f2a718bb4e02207c7e1b9666528dba4a583e45df730101ebdc824012cbda942771c19089be5f0501210286afe99904a670795b0aa9b340a5c556f1b20f225da94279b8852a628eee6a7ff2ffffff0210270000000000001976a91467a1f07a2d9ad7961d7351fd1b042f305273dabd88ac88130000000000001976a91496b87f8703020642a0937a65a62e27d791f960e188ac00000000',
    signed_tx
)


let res = payload(anychain_ffi_lib.verify_address(address, 0))
assert(true, res)


let address_types = JSON.stringify(["1", "1"])
let bandwidth = payload(anychain_ffi_lib.estimate_bandwidth(tx, 0, address_types))
assert(376, bandwidth)

console.log('btc.js passed')