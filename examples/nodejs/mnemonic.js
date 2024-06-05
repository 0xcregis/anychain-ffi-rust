const ffi = require('ffi-napi')
const anychain_ffi_lib = new ffi.Library(
    "../../target/release/libanychain_ffi_lib.dylib",
    {
        'create_mnemonic': ['string', ['string', 'int']],
        'parse_mnemonic': ['string', ['string']],
    }
)

const payload = function (arg) {
    return JSON.parse(arg).payload
}
const assert = function (left, right, msg) {
    console.assert(JSON.stringify(left) == JSON.stringify(right), msg)
}


let phrase = payload(anychain_ffi_lib.create_mnemonic('en', 12))

let wallet = payload(anychain_ffi_lib.parse_mnemonic(
    'south muscle monitor lunch slam arrange antique antenna monkey stove keen favorite'
))
assert(
    {
        hash: '7604a3fc26146c813ce97749bb5444c8f0c28cd7',
        xpub: 'xpub661MyMwAqRbcEyHjkQzU1iPSjBpSnH5xuT6eTwe2k4ui9tUazyMZTWsqxDx9unXjg16mV3mgWJBgf9gsgZQzyGyaM75HVMebXxoTeTYJS4v'
    },
    wallet
)

console.log('mnemonic.js passed')
