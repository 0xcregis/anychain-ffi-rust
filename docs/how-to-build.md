### Compile Node.js native library

#### Compile native target

```
<!-- macOS -->
cargo build --release --features napi
# target/release/libanychain_ffi_lib.dylib
```

```
<!-- windows -->
cargo build --release --features napi 
# target/release/libanychain_ffi_lib.dll
```

### Compile a universal dynamic library that complies with the C ABI

#### 64-bit

```
cargo build --release
```

#### 32-bit

```
rustup target add i686-pc-windows-msvc
```

```
cargo build --target i686-pc-windows-msvc --release
```
