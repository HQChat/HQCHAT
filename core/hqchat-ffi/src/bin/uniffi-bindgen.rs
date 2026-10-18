//! Generates the Swift and Kotlin bindings from the built library:
//!
//! ```text
//! cargo run -p hqchat-ffi --bin uniffi-bindgen -- generate \
//!     --library target/debug/libhqchat_ffi.dylib --language swift --out-dir out
//! ```

fn main() {
    uniffi::uniffi_bindgen_main()
}
