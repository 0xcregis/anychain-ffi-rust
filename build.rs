// extern crate cbindgen;

fn main() {
    cbindgen::Builder::new()
        .with_src("./src/cbinding.rs")
        .with_language(cbindgen::Language::C)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("anychain_ffi_lib.h");
}
