extern crate cbindgen;

use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=rust/src/lib.rs");
    println!("cargo:rerun-if-changed=rust/wrapper.c");
    println!("cargo:rerun-if-changed=rust/wrapper.h");

    let bindings = bindgen::builder()
        .header("rust/wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("os_log_.*")
        .allowlist_function("os_release")
        .allowlist_function("os_signpost_.*")
        .generate()
        .expect("should be able to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("should be able to write bindings");

    cc::Build::new().file("rust/wrapper.c").compile("wrapper");

    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    if let Ok(b) = cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_language(cbindgen::Language::C)
        .rename_item("Account", "FfiAccount")
        .rename_item("Uuid", "FfiUuid")
        .rename_item("Accounts", "FfiAccounts")
        .rename_item("BinaryKey", "FFIBinaryKey")
        .rename_item("EncodedKey", "FFIEncodedKey")
        .rename_item("EncodedKeys", "FFIEncodedKeys")
        .rename_item("SubtreeRoot", "FfiSubtreeRoot")
        .rename_item("SubtreeRoots", "FfiSubtreeRoots")
        .rename_item("Balance", "FfiBalance")
        .rename_item("AccountBalance", "FfiAccountBalance")
        .rename_item("ScanProgress", "FfiScanProgress")
        .rename_item("WalletSummary", "FfiWalletSummary")
        .rename_item("ScanRange", "FfiScanRange")
        .rename_item("ScanRanges", "FfiScanRanges")
        .rename_item("ScanSummary", "FfiScanSummary")
        .rename_item("BlockMeta", "FFIBlockMeta")
        .rename_item("BlocksMeta", "FFIBlocksMeta")
        .rename_item("BoxedSlice", "FfiBoxedSlice")
        .rename_item("TxIds", "FfiTxIds")
        .rename_item("MaxSpendMode", "FfiMaxSpendMode")
        .rename_item("TransactionStatus", "FfiTransactionStatus")
        .rename_item("TransactionDataRequest", "FfiTransactionDataRequest")
        .rename_item("TransactionDataRequests", "FfiTransactionDataRequests")
        .rename_item("Address", "FfiAddress")
        .rename_item("AccountMetadataKey", "FfiAccountMetadataKey")
        .rename_item("SymmetricKeys", "FfiSymmetricKeys")
        .rename_item("HttpRequestHeader", "FfiHttpRequestHeader")
        .rename_item("HttpResponseBytes", "FfiHttpResponseBytes")
        .rename_item("HttpResponseHeader", "FfiHttpResponseHeader")
        .rename_item("SingleUseTaddr", "FfiSingleUseTaddr")
        .rename_item("AddressCheckResult", "FfiAddressCheckResult")
        .rename_item("ZecUsdExchange", "FfiZecUsdExchange")
        .generate()
    {
        b.write_to_file("target/Headers/zcashlc.h");
    }
}
