//! Key derivation.

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::mem::ManuallyDrop;
use std::os::raw::c_char;
use std::slice;
use zcash_client_backend::keys::UnifiedIncomingViewingKey;
use zcash_primitives::consensus::{Network, NetworkConstants};
use zip32::{arbitrary, ChildIndex, DiversifierIndex};

use zcash_address::{
    unified::{self, Container, Encoding},
    ConversionError, ToAddress, TryFromAddress, ZcashAddress,
};
use zcash_client_backend::{
    address::UnifiedAddress,
    encoding::{decode_extended_full_viewing_key, decode_extended_spending_key},
    keys::{Era, UnifiedFullViewingKey, UnifiedSpendingKey},
};
use zcash_primitives::legacy::TransparentAddress;

use crate::{
    decode_usk, free_ptr_from_vec, parse_network, unwrap_exc_or, unwrap_exc_or_null,
    zcashlc_string_free, FfiBoxedSlice,
};

enum AddressType {
    Sprout,
    P2pkh,
    P2sh,
    Sapling,
    Unified,
    Tex,
}

struct AddressMetadata {
    network: zcash_address::Network,
    addr_type: AddressType,
}

#[derive(Debug)]
enum Void {}

impl TryFromAddress for AddressMetadata {
    /// This instance produces no errors.
    type Error = Void;

    fn try_from_sprout(
        network: zcash_address::Network,
        _data: [u8; 64],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(AddressMetadata {
            network,
            addr_type: AddressType::Sprout,
        })
    }

    fn try_from_sapling(
        network: zcash_address::Network,
        _data: [u8; 43],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(AddressMetadata {
            network,
            addr_type: AddressType::Sapling,
        })
    }

    fn try_from_unified(
        network: zcash_address::Network,
        _data: unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(AddressMetadata {
            network,
            addr_type: AddressType::Unified,
        })
    }

    fn try_from_transparent_p2pkh(
        network: zcash_address::Network,
        _data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(AddressMetadata {
            network,
            addr_type: AddressType::P2pkh,
        })
    }

    fn try_from_transparent_p2sh(
        network: zcash_address::Network,
        _data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(AddressMetadata {
            network,
            addr_type: AddressType::P2sh,
        })
    }

    fn try_from_tex(
        network: zcash_address::Network,
        _data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(AddressMetadata {
            network,
            addr_type: AddressType::Tex,
        })
    }
}

fn zip32_account_index(account: i32) -> anyhow::Result<zip32::AccountId> {
    u32::try_from(account)
        .map_err(|_| ())
        .and_then(|id| zip32::AccountId::try_from(id).map_err(|_| ()))
        .map_err(|_| anyhow!("Invalid account ID"))
}

/// Returns the network type and address kind for the given address string,
/// if the address is a valid Zcash address.
///
/// Address kind codes are as follows:
/// * p2pkh: 0
/// * p2sh: 1
/// * sapling: 2
/// * unified: 3
/// * tex: 4
///
/// # Safety
///
/// - `address` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `address` must not be mutated for the duration of the function call.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_get_address_metadata(
    address: *const c_char,
    network_id_ret: *mut u32,
    addr_kind_ret: *mut u32,
) -> bool {
    let res = catch_panic(|| {
        let addr = unsafe { CStr::from_ptr(address).to_str()? };
        let zaddr = ZcashAddress::try_from_encoded(addr)?;

        // The following .unwrap is safe because address type detection
        // cannot fail for valid ZcashAddress values.
        let addr_meta: AddressMetadata = zaddr.convert().unwrap();
        unsafe {
            *network_id_ret = match addr_meta.network {
                zcash_address::Network::Main => 1,
                zcash_address::Network::Test => 0,
                zcash_address::Network::Regtest => {
                    return Err(anyhow!("Regtest addresses are not supported."));
                }
            };

            *addr_kind_ret = match addr_meta.addr_type {
                AddressType::P2pkh => 0,
                AddressType::P2sh => 1,
                AddressType::Sapling => 2,
                AddressType::Unified => 3,
                AddressType::Tex => 4,
                AddressType::Sprout => {
                    return Err(anyhow!("Sprout addresses are not supported."));
                }
            };
        }

        Ok(true)
    });
    unwrap_exc_or(res, false)
}

/// Extracts the typecodes of the receivers within the given Unified Address.
///
/// Returns a pointer to a slice of typecodes. `len_ret` is set to the length of the
/// slice.
///
/// See the following sections of ZIP 316 for details on how to interpret typecodes:
/// - [List of known typecodes](https://zips.z.cash/zip-0316#encoding-of-unified-addresses)
/// - [Adding new types](https://zips.z.cash/zip-0316#adding-new-types)
/// - [Metadata Items](https://zips.z.cash/zip-0316#metadata-items)
///
/// # Safety
///
/// - `ua` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `ua` must not be mutated for the duration of the function call.
/// - Call [`zcashlc_free_typecodes`] to free the memory associated with the returned
///   pointer when done using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_get_typecodes_for_unified_address_receivers(
    ua: *const c_char,
    len_ret: *mut usize,
) -> *mut u32 {
    let res = catch_panic(|| {
        let ua_str = unsafe { CStr::from_ptr(ua).to_str()? };

        let (_, ua) = unified::Address::decode(ua_str)
            .map_err(|e| anyhow!("Invalid Unified Address: {}", e))?;

        let typecodes = ua
            .items()
            .into_iter()
            .map(|receiver| match receiver {
                unified::Receiver::P2pkh(_) => unified::Typecode::P2pkh,
                unified::Receiver::P2sh(_) => unified::Typecode::P2sh,
                unified::Receiver::Sapling(_) => unified::Typecode::Sapling,
                unified::Receiver::Orchard(_) => unified::Typecode::Orchard,
                unified::Receiver::Unknown { typecode, .. } => unified::Typecode::Unknown(typecode),
            })
            .map(u32::from)
            .collect::<Vec<_>>();

        let mut typecodes = ManuallyDrop::new(typecodes.into_boxed_slice());
        let (ptr, len) = (typecodes.as_mut_ptr(), typecodes.len());

        unsafe { *len_ret = len };
        Ok(ptr)
    });
    unwrap_exc_or_null(res)
}

/// Frees a list of typecodes previously obtained from the FFI.
///
/// # Safety
///
/// - `data` and `len` must have been obtained from
///   [`zcashlc_get_typecodes_for_unified_address_receivers`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_typecodes(data: *mut u32, len: usize) {
    free_ptr_from_vec(data, len);
}

/// Returns true when the provided key decodes to a valid Sapling extended spending key for the
/// specified network, false in any other case.
///
/// # Safety
///
/// - `extsk` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `extsk` must not be mutated for the duration of the function call.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_is_valid_sapling_extended_spending_key(
    extsk: *const c_char,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let extsk = unsafe { CStr::from_ptr(extsk).to_str()? };

        Ok(
            decode_extended_spending_key(network.hrp_sapling_extended_spending_key(), extsk)
                .is_ok(),
        )
    });
    unwrap_exc_or(res, false)
}

/// Returns true when the provided key decodes to a valid Sapling extended full viewing key for the
/// specified network, false in any other case.
///
/// # Safety
///
/// - `key` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `key` must not be mutated for the duration of the function call.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_is_valid_viewing_key(key: *const c_char, network_id: u32) -> bool {
    let res =
        catch_panic(|| {
            let network = parse_network(network_id)?;
            let vkstr = unsafe { CStr::from_ptr(key).to_str()? };

            Ok(decode_extended_full_viewing_key(
                network.hrp_sapling_extended_full_viewing_key(),
                vkstr,
            )
            .is_ok())
        });
    unwrap_exc_or(res, false)
}

/// Returns true when the provided key decodes to a valid unified full viewing key for the
/// specified network, false in any other case.
///
/// # Safety
///
/// - `ufvk` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `ufvk` must not be mutated for the duration of the
///   function call.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_is_valid_unified_full_viewing_key(
    ufvk: *const c_char,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let ufvkstr = unsafe { CStr::from_ptr(ufvk).to_str()? };

        Ok(UnifiedFullViewingKey::decode(&network, ufvkstr).is_ok())
    });
    unwrap_exc_or(res, false)
}

/// Derives and returns a unified spending key from the given seed for the given account ID.
///
/// Returns the binary encoding of the spending key. The caller should manage the memory of (and
/// store, if necessary) the returned spending key in a secure fashion.
///
/// # Safety
///
/// - `seed` must be non-null and valid for reads for `seed_len` bytes.
/// - The memory referenced by `seed` must not be mutated for the duration of the function call.
/// - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
///   of `pointer::offset`.
/// - Call `zcashlc_free_binary_key` to free the memory associated with the returned pointer when
///   you are finished using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_derive_spending_key(
    seed: *const u8,
    seed_len: usize,
    hd_account_index: i32,
    network_id: u32,
) -> *mut FfiBoxedSlice {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let seed = unsafe { slice::from_raw_parts(seed, seed_len) };
        let account = zip32_account_index(hd_account_index)?;

        UnifiedSpendingKey::from_seed(&network, seed, account)
            .map_err(|e| anyhow!("error generating unified spending key from seed: {:?}", e))
            .map(move |usk| {
                let encoded = usk.to_bytes(Era::Orchard);
                FfiBoxedSlice::some(encoded)
            })
    });
    unwrap_exc_or_null(res)
}

/// Obtains the unified full viewing key for the given binary-encoded unified spending key
/// and returns the resulting encoded UFVK string. `usk_ptr` should point to an array of `usk_len`
/// bytes containing a unified spending key encoded as returned from the `zcashlc_create_account`
/// or `zcashlc_derive_spending_key` functions.
///
/// # Safety
///
/// - `usk_ptr` must be non-null and must point to an array of `usk_len` bytes.
/// - The memory referenced by `usk_ptr` must not be mutated for the duration of the function call.
/// - The total size `usk_len` must be no larger than `isize::MAX`. See the safety documentation
///   of `pointer::offset`.
/// - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
///   when you are done using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_spending_key_to_full_viewing_key(
    usk_ptr: *const u8,
    usk_len: usize,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        unsafe { decode_usk(usk_ptr, usk_len) }.map(|usk| {
            let ufvk = usk.to_unified_full_viewing_key();
            CString::new(ufvk.encode(&network)).unwrap().into_raw()
        })
    });
    unwrap_exc_or_null(res)
}

struct UnifiedAddressParser(UnifiedAddress);

impl zcash_address::TryFromRawAddress for UnifiedAddressParser {
    type Error = anyhow::Error;

    fn try_from_raw_unified(
        data: zcash_address::unified::Address,
    ) -> Result<Self, zcash_address::ConversionError<Self::Error>> {
        data.try_into()
            .map(UnifiedAddressParser)
            .map_err(|e| anyhow!("Invalid Unified Address: {}", e).into())
    }
}

/// A struct that contains a Zcash unified address, along with the diversifier index used to
/// generate that address.
#[repr(C)]
pub struct FfiAddress {
    address: *mut c_char,
    diversifier_index_bytes: [u8; 11],
}

impl FfiAddress {
    fn new(
        network: &Network,
        address: UnifiedAddress,
        diversifier_index: DiversifierIndex,
    ) -> Self {
        let address_str = address.encode(network);
        Self {
            address: CString::new(address_str).unwrap().into_raw(),
            diversifier_index_bytes: *diversifier_index.as_bytes(),
        }
    }
}

/// Frees a FfiAddress value
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`FfiAddress`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_ffi_address(ptr: *mut FfiAddress) {
    if !ptr.is_null() {
        let ffi_address: Box<FfiAddress> = unsafe { Box::from_raw(ptr) };
        if !(ffi_address.address.is_null()) {
            unsafe { zcashlc_string_free(ffi_address.address) }
        }
        drop(ffi_address);
    }
}

/// Derives a unified address address for the provided UFVK, along with the diversifier at which it
/// was derived; this may not be equal to the provided diversifier index if no valid Sapling
/// address could be derived at that index. If the `diversifier_index_bytes` parameter is null, the
/// default address for the UFVK is returned.
///
/// # Safety
///
/// - `ufvk` must be non-null and must point to a null-terminated UTF-8 string.
/// - `diversifier_index_bytes must either be null or be valid for reads for 11 bytes and have an
///   alignment of `1`.
/// - Call [`zcashlc_free_ffi_address`] to free the memory associated with the returned pointer
///   when done using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_derive_address_from_ufvk(
    network_id: u32,
    ufvk: *const c_char,
    diversifier_index_bytes: *const u8,
) -> *mut FfiAddress {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let ufvk_str = unsafe { CStr::from_ptr(ufvk).to_str()? };
        let ufvk = UnifiedFullViewingKey::decode(&network, ufvk_str).map_err(|e| {
            anyhow!(
                "Value \"{}\" did not decode as a valid UFVK: {}",
                ufvk_str,
                e
            )
        })?;

        let (ua, di) = if diversifier_index_bytes.is_null() {
            ufvk.default_address(None)
        } else {
            let j = DiversifierIndex::from(<[u8; 11]>::try_from(unsafe {
                slice::from_raw_parts(diversifier_index_bytes, 11)
            })?);
            ufvk.find_address(j, None)
        }?;

        Ok(Box::into_raw(Box::new(FfiAddress::new(&network, ua, di))))
    });
    unwrap_exc_or_null(res)
}

/// Derives a unified address address for the provided UIVK, along with the diversifier at which it
/// was derived; this may not be equal to the provided diversifier index if no valid Sapling
/// address could be derived at that index. If the `diversifier_index_bytes` parameter is null, the
/// default address for the UIVK is returned.
///
/// # Safety
///
/// - `uivk` must be non-null and must point to a null-terminated UTF-8 string.
/// - `diversifier_index_bytes must either be null or be valid for reads for 11 bytes and have an
///   alignment of `1`.
/// - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
///   when done using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_derive_address_from_uivk(
    network_id: u32,
    uivk: *const c_char,
    diversifier_index_bytes: *const u8,
) -> *mut FfiAddress {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let uivk_str = unsafe { CStr::from_ptr(uivk).to_str()? };
        let uivk = UnifiedIncomingViewingKey::decode(&network, uivk_str).map_err(|e| {
            anyhow!(
                "Value \"{}\" did not decode as a valid UIVK: {}",
                uivk_str,
                e
            )
        })?;

        let (ua, di) = if diversifier_index_bytes.is_null() {
            uivk.default_address(None)
        } else {
            let j = DiversifierIndex::from(<[u8; 11]>::try_from(unsafe {
                slice::from_raw_parts(diversifier_index_bytes, 11)
            })?);
            uivk.find_address(j, None)
        }?;

        Ok(Box::into_raw(Box::new(FfiAddress::new(&network, ua, di))))
    });
    unwrap_exc_or_null(res)
}

/// Returns the transparent receiver within the given Unified Address, if any.
///
/// # Safety
///
/// - `ua` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `ua` must not be mutated for the duration of the function call.
/// - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
///   when done using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_get_transparent_receiver_for_unified_address(
    ua: *const c_char,
) -> *mut c_char {
    let res = catch_panic(|| {
        let ua_str = unsafe { CStr::from_ptr(ua).to_str()? };

        let (network, ua) = match ZcashAddress::try_from_encoded(ua_str) {
            Ok(addr) => addr
                .convert::<(_, UnifiedAddressParser)>()
                .map_err(|e| anyhow!("Not a Unified Address: {}", e)),
            Err(e) => return Err(anyhow!("Invalid Zcash address: {}", e)),
        }?;

        if let Some(taddr) = ua.0.transparent() {
            let taddr = match taddr {
                TransparentAddress::PublicKeyHash(data) => {
                    ZcashAddress::from_transparent_p2pkh(network, *data)
                }
                TransparentAddress::ScriptHash(data) => {
                    ZcashAddress::from_transparent_p2sh(network, *data)
                }
            };

            Ok(CString::new(taddr.encode())?.into_raw())
        } else {
            Err(anyhow!(
                "Unified Address doesn't contain a transparent receiver"
            ))
        }
    });
    unwrap_exc_or_null(res)
}

/// Returns the Sapling receiver within the given Unified Address, if any.
///
/// # Safety
///
/// - `ua` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `ua` must not be mutated for the duration of the function call.
/// - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
///   when done using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_get_sapling_receiver_for_unified_address(
    ua: *const c_char,
) -> *mut c_char {
    let res = catch_panic(|| {
        let ua_str = unsafe { CStr::from_ptr(ua).to_str()? };

        let (network, ua) = match ZcashAddress::try_from_encoded(ua_str) {
            Ok(addr) => addr
                .convert::<(_, UnifiedAddressParser)>()
                .map_err(|e| anyhow!("Not a Unified Address: {}", e)),
            Err(e) => return Err(anyhow!("Invalid Zcash address: {}", e)),
        }?;

        if let Some(addr) = ua.0.sapling() {
            Ok(
                CString::new(ZcashAddress::from_sapling(network, addr.to_bytes()).encode())?
                    .into_raw(),
            )
        } else {
            Err(anyhow!(
                "Unified Address doesn't contain a Sapling receiver"
            ))
        }
    });
    unwrap_exc_or_null(res)
}

/// Derives and returns a ZIP 32 Arbitrary Key from the given seed at the "wallet level", i.e.
/// directly from the seed with no ZIP 32 path applied.
///
/// The resulting key will be the same across all networks (Zcash mainnet, Zcash testnet, OtherCoin
/// mainnet, and so on). You can think of it as a context-specific seed fingerprint that can be used
/// as (static) key material.
///
/// `context_string` is a globally-unique non-empty sequence of at most 252 bytes that identifies
/// the desired context.
///
/// # Safety
///
/// - `context_string` must be non-null and valid for reads for `context_string_len` bytes.
/// - The memory referenced by `context_string` must not be mutated for the duration of the function
///   call.
/// - The total size `context_string_len` must be no larger than `isize::MAX`. See the safety
///   documentation of `pointer::offset`.
/// - `seed` must be non-null and valid for reads for `seed_len` bytes.
/// - The memory referenced by `seed` must not be mutated for the duration of the function call.
/// - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
///   of `pointer::offset`.
/// - Call `zcashlc_free_boxed_slice` to free the memory associated with the returned
///   pointer when done using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_derive_arbitrary_wallet_key(
    context_string: *const u8,
    context_string_len: usize,
    seed: *const u8,
    seed_len: usize,
) -> *mut FfiBoxedSlice {
    let res = catch_panic(|| {
        let context_string = unsafe { slice::from_raw_parts(context_string, context_string_len) };
        let seed = unsafe { slice::from_raw_parts(seed, seed_len) };

        let key = arbitrary::SecretKey::from_path(context_string, seed, &[]);

        Ok(FfiBoxedSlice::some(key.data().to_vec()))
    });
    unwrap_exc_or_null(res)
}

/// Derives and returns a ZIP 32 Arbitrary Key from the given seed at the account level.
///
/// `context_string` is a globally-unique non-empty sequence of at most 252 bytes that identifies
/// the desired context.
///
/// # Safety
///
/// - `context_string` must be non-null and valid for reads for `context_string_len` bytes.
/// - The memory referenced by `context_string` must not be mutated for the duration of the function
///   call.
/// - The total size `context_string_len` must be no larger than `isize::MAX`. See the safety
///   documentation of `pointer::offset`.
/// - `seed` must be non-null and valid for reads for `seed_len` bytes`.
/// - The memory referenced by `seed` must not be mutated for the duration of the function call.
/// - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
///   of `pointer::offset`.
/// - Call `zcashlc_free_boxed_slice` to free the memory associated with the returned
///   pointer when done using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_derive_arbitrary_account_key(
    context_string: *const u8,
    context_string_len: usize,
    seed: *const u8,
    seed_len: usize,
    account: i32,
    network_id: u32,
) -> *mut FfiBoxedSlice {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let context_string = unsafe { slice::from_raw_parts(context_string, context_string_len) };
        let seed = unsafe { slice::from_raw_parts(seed, seed_len) };
        let account = zip32_account_index(account)?;

        let key = arbitrary::SecretKey::from_path(
            context_string,
            seed,
            &[
                ChildIndex::hardened(32),
                ChildIndex::hardened(network.coin_type()),
                ChildIndex::hardened(account.into()),
            ],
        );

        Ok(FfiBoxedSlice::some(key.data().to_vec()))
    });
    unwrap_exc_or_null(res)
}
