use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use eip681::TransactionRequest;
use ffi_helpers::panic::catch_panic;

use crate::{unwrap_exc_or, unwrap_exc_or_null};

/// The type of an EIP-681 transaction request.
///
/// cbindgen:prefix-with-name
#[repr(C)]
pub enum Eip681TransactionRequestType {
    /// A native ETH/chain token transfer (no function call).
    Native,
    /// An ERC-20 token transfer via `transfer(address,uint256)`.
    Erc20,
    /// A valid EIP-681 request that is not a recognized transfer pattern.
    Unrecognised,
}

/// An opaque parsed EIP-681 transaction request.
///
/// Obtain via [`zcashlc_eip681_parse_transaction_request`]. Free with
/// [`zcashlc_free_eip681_transaction_request`].
pub struct Eip681TransactionRequest {
    inner: TransactionRequest,
}

/// A native ETH/chain token transfer extracted from a parsed EIP-681 request.
///
/// All string fields are heap-allocated and must be freed by calling
/// [`zcashlc_free_eip681_native_request`].
///
/// # Safety
///
/// - `schema_prefix` and `recipient_address` are non-null, null-terminated UTF-8 strings.
/// - `value_hex`, `gas_limit_hex`, and `gas_price_hex` are either null (indicating the value
///   was not present in the URI) or non-null, null-terminated UTF-8 strings containing a
///   `0x`-prefixed hex-encoded `U256` value.
#[repr(C)]
pub struct Eip681NativeRequest {
    /// The URI schema prefix (e.g. "ethereum").
    schema_prefix: *mut c_char,
    /// Whether a chain ID was specified in the URI.
    has_chain_id: bool,
    /// The chain ID, if `has_chain_id` is true. Undefined otherwise.
    chain_id: u64,
    /// The recipient address (ERC-55 checksummed hex or ENS name).
    recipient_address: *mut c_char,
    /// The transfer value as a `0x`-prefixed hex string, or null if not specified.
    value_hex: *mut c_char,
    /// The gas limit as a `0x`-prefixed hex string, or null if not specified.
    gas_limit_hex: *mut c_char,
    /// The gas price as a `0x`-prefixed hex string, or null if not specified.
    gas_price_hex: *mut c_char,
}

/// An ERC-20 token transfer extracted from a parsed EIP-681 request.
///
/// All string fields are heap-allocated and must be freed by calling
/// [`zcashlc_free_eip681_erc20_request`].
///
/// # Safety
///
/// - `token_contract_address`, `recipient_address`, and `value_hex` are non-null,
///   null-terminated UTF-8 strings.
/// - `value_hex` contains a `0x`-prefixed hex-encoded `U256` value.
#[repr(C)]
pub struct Eip681Erc20Request {
    /// Whether a chain ID was specified in the URI.
    has_chain_id: bool,
    /// The chain ID, if `has_chain_id` is true. Undefined otherwise.
    chain_id: u64,
    /// The ERC-20 token contract address (ERC-55 checksummed hex or ENS name).
    token_contract_address: *mut c_char,
    /// The transfer recipient address (ERC-55 checksummed hex or ENS name).
    recipient_address: *mut c_char,
    /// The transfer value in atomic units as a `0x`-prefixed hex string.
    value_hex: *mut c_char,
}

/// Helper: convert an optional `U256` to a heap-allocated hex C string, or null if `None`.
fn u256_option_to_c_hex(value: Option<eip681::U256>) -> *mut c_char {
    match value {
        Some(v) => CString::new(format!("{:#x}", v)).unwrap().into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Helper: convert a `U256` to a heap-allocated hex C string.
fn u256_to_c_hex(value: eip681::U256) -> *mut c_char {
    CString::new(format!("{:#x}", value)).unwrap().into_raw()
}

/// Parse an EIP-681 URI string into a [`Eip681TransactionRequest`].
///
/// Returns a pointer to the parsed request on success, or null on failure.
/// On failure the error can be retrieved via `zcashlc_last_error_message`.
///
/// The returned pointer must be freed with [`zcashlc_free_eip681_transaction_request`].
///
/// # Safety
///
/// - `input` must be a non-null pointer to a null-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_eip681_parse_transaction_request(
    input: *const c_char,
) -> *mut Eip681TransactionRequest {
    let res = catch_panic(|| {
        let input_str = unsafe { CStr::from_ptr(input) }
            .to_str()
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in input: {}", e))?;

        let request = TransactionRequest::parse(input_str)
            .map_err(|e| anyhow::anyhow!("EIP-681 parse error: {}", e))?;

        Ok(Box::into_raw(Box::new(Eip681TransactionRequest {
            inner: request,
        })))
    });
    unwrap_exc_or_null(res)
}

/// Returns the type of the parsed EIP-681 transaction request.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a valid [`Eip681TransactionRequest`] as
///   returned by [`zcashlc_eip681_parse_transaction_request`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_eip681_transaction_request_type(
    ptr: *const Eip681TransactionRequest,
) -> Eip681TransactionRequestType {
    let res = catch_panic(|| {
        let request = unsafe { &*ptr };
        Ok(match &request.inner {
            TransactionRequest::NativeRequest(_) => Eip681TransactionRequestType::Native,
            TransactionRequest::Erc20Request(_) => Eip681TransactionRequestType::Erc20,
            TransactionRequest::Unrecognised(_) => Eip681TransactionRequestType::Unrecognised,
        })
    });
    unwrap_exc_or(res, Eip681TransactionRequestType::Unrecognised)
}

/// Extract the native transfer data from a parsed EIP-681 transaction request.
///
/// Returns a pointer to an [`Eip681NativeRequest`] on success, or null if the parsed
/// request is not a native transfer.
///
/// The returned pointer must be freed with [`zcashlc_free_eip681_native_request`].
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a valid [`Eip681TransactionRequest`] as
///   returned by [`zcashlc_eip681_parse_transaction_request`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_eip681_transaction_request_as_native(
    ptr: *const Eip681TransactionRequest,
) -> *mut Eip681NativeRequest {
    let res = catch_panic(|| {
        let request = unsafe { &*ptr };
        let native = match &request.inner {
            TransactionRequest::NativeRequest(n) => n,
            _ => return Ok(std::ptr::null_mut()),
        };

        let (has_chain_id, chain_id) = match native.chain_id() {
            Some(id) => (true, id),
            None => (false, 0),
        };

        Ok(Box::into_raw(Box::new(Eip681NativeRequest {
            schema_prefix: CString::new(native.schema_prefix()).unwrap().into_raw(),
            has_chain_id,
            chain_id,
            recipient_address: CString::new(native.recipient_address()).unwrap().into_raw(),
            value_hex: u256_option_to_c_hex(native.value_atomic()),
            gas_limit_hex: u256_option_to_c_hex(native.gas_limit()),
            gas_price_hex: u256_option_to_c_hex(native.gas_price()),
        })))
    });
    unwrap_exc_or_null(res)
}

/// Extract the ERC-20 transfer data from a parsed EIP-681 transaction request.
///
/// Returns a pointer to an [`Eip681Erc20Request`] on success, or null if the parsed
/// request is not an ERC-20 transfer.
///
/// The returned pointer must be freed with [`zcashlc_free_eip681_erc20_request`].
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a valid [`Eip681TransactionRequest`] as
///   returned by [`zcashlc_eip681_parse_transaction_request`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_eip681_transaction_request_as_erc20(
    ptr: *const Eip681TransactionRequest,
) -> *mut Eip681Erc20Request {
    let res = catch_panic(|| {
        let request = unsafe { &*ptr };
        let erc20 = match &request.inner {
            TransactionRequest::Erc20Request(e) => e,
            _ => return Ok(std::ptr::null_mut()),
        };

        let (has_chain_id, chain_id) = match erc20.chain_id() {
            Some(id) => (true, id),
            None => (false, 0),
        };

        Ok(Box::into_raw(Box::new(Eip681Erc20Request {
            has_chain_id,
            chain_id,
            token_contract_address: CString::new(erc20.token_contract_address())
                .unwrap()
                .into_raw(),
            recipient_address: CString::new(erc20.recipient_address()).unwrap().into_raw(),
            value_hex: u256_to_c_hex(erc20.value_atomic()),
        })))
    });
    unwrap_exc_or_null(res)
}

/// Serialize a parsed EIP-681 transaction request back to a URI string.
///
/// Returns a heap-allocated null-terminated UTF-8 string, or null on failure.
/// The returned string must be freed with [`zcashlc_string_free`](crate::zcashlc_string_free).
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a valid [`Eip681TransactionRequest`] as
///   returned by [`zcashlc_eip681_parse_transaction_request`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_eip681_transaction_request_to_uri(
    ptr: *const Eip681TransactionRequest,
) -> *mut c_char {
    let res = catch_panic(|| {
        let request = unsafe { &*ptr };
        let uri = request.inner.to_string();
        CString::new(uri)
            .map(|s| s.into_raw())
            .map_err(|e| anyhow::anyhow!("URI contains null byte: {}", e))
    });
    unwrap_exc_or_null(res)
}

/// Frees an [`Eip681TransactionRequest`] value.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of
///   [`Eip681TransactionRequest`] as returned by
///   [`zcashlc_eip681_parse_transaction_request`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_eip681_transaction_request(
    ptr: *mut Eip681TransactionRequest,
) {
    if !ptr.is_null() {
        drop(unsafe { Box::from_raw(ptr) });
    }
}

/// Frees an [`Eip681NativeRequest`] value.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of
///   [`Eip681NativeRequest`] as returned by
///   [`zcashlc_eip681_transaction_request_as_native`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_eip681_native_request(ptr: *mut Eip681NativeRequest) {
    if !ptr.is_null() {
        let req = unsafe { Box::from_raw(ptr) };
        unsafe { crate::zcashlc_string_free(req.schema_prefix) };
        unsafe { crate::zcashlc_string_free(req.recipient_address) };
        if !req.value_hex.is_null() {
            unsafe { crate::zcashlc_string_free(req.value_hex) };
        }
        if !req.gas_limit_hex.is_null() {
            unsafe { crate::zcashlc_string_free(req.gas_limit_hex) };
        }
        if !req.gas_price_hex.is_null() {
            unsafe { crate::zcashlc_string_free(req.gas_price_hex) };
        }
        drop(req);
    }
}

/// Frees an [`Eip681Erc20Request`] value.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of
///   [`Eip681Erc20Request`] as returned by
///   [`zcashlc_eip681_transaction_request_as_erc20`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_eip681_erc20_request(ptr: *mut Eip681Erc20Request) {
    if !ptr.is_null() {
        let req = unsafe { Box::from_raw(ptr) };
        unsafe { crate::zcashlc_string_free(req.token_contract_address) };
        unsafe { crate::zcashlc_string_free(req.recipient_address) };
        unsafe { crate::zcashlc_string_free(req.value_hex) };
        drop(req);
    }
}
