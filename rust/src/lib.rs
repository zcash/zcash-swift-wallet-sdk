use failure::format_err;
use ffi_helpers::panic::catch_panic;
use hdwallet::{
    traits::{Deserialize, Serialize},
    ExtendedPrivKey, KeyChain,
};
use secp256k1::PublicKey;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::ffi::{CStr, CString, OsStr};
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::slice;
use std::str::FromStr;

use zcash_client_backend::{
    address::RecipientAddress,
    data_api::{
        chain::{scan_cached_blocks, validate_chain},
        error::Error,
        wallet::{
            create_spend_to_address, decrypt_and_store_transaction, shield_transparent_funds,
        },
        WalletRead, WalletReadTransparent, WalletWrite, WalletWriteTransparent,
    },
    encoding::{
        decode_extended_full_viewing_key, decode_extended_spending_key,
        encode_extended_full_viewing_key, encode_extended_spending_key, encode_payment_address,
        AddressCodec,
    },
    keys::{sapling, UnifiedFullViewingKey, UnifiedSpendingKey},
    wallet::{OvkPolicy, WalletTransparentOutput},
};
#[allow(deprecated)]
use zcash_client_sqlite::wallet::{delete_utxos_above, get_rewind_height};
use zcash_client_sqlite::{
    error::SqliteClientError,
    wallet::init::{init_accounts_table, init_blocks_table, init_wallet_db},
    BlockDb, NoteId, WalletDb,
};
use zcash_primitives::consensus::Network::{MainNetwork, TestNetwork};
use zcash_primitives::{
    block::BlockHash,
    consensus::{BlockHeight, BranchId, Network, Parameters},
    legacy::{self, keys::IncomingViewingKey, TransparentAddress},
    memo::{Memo, MemoBytes},
    transaction::{
        components::{Amount, OutPoint, TxOut},
        Transaction,
    },
    zip32::{AccountId, ExtendedFullViewingKey},
};
use zcash_proofs::prover::LocalTxProver;

const ANCHOR_OFFSET: u32 = 10;

fn unwrap_exc_or<T>(exc: Result<T, ()>, def: T) -> T {
    match exc {
        Ok(value) => value,
        Err(_) => def,
    }
}

fn unwrap_exc_or_null<T>(exc: Result<T, ()>) -> T
where
    T: ffi_helpers::Nullable,
{
    match exc {
        Ok(value) => value,
        Err(_) => ffi_helpers::Nullable::NULL,
    }
}

fn wallet_db(
    db_data: *const u8,
    db_data_len: usize,
    network: Network,
) -> Result<WalletDb<Network>, failure::Error> {
    let db_data = Path::new(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(db_data, db_data_len)
    }));
    WalletDb::for_path(db_data, network)
        .map_err(|e| format_err!("Error opening wallet database connection: {}", e))
}

fn block_db(cache_db: *const u8, cache_db_len: usize) -> Result<BlockDb, failure::Error> {
    let cache_db = Path::new(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(cache_db, cache_db_len)
    }));
    BlockDb::for_path(cache_db)
        .map_err(|e| format_err!("Error opening block source database connection: {}", e))
}

/// Returns the length of the last error message to be logged.
#[no_mangle]
pub extern "C" fn zcashlc_last_error_length() -> i32 {
    ffi_helpers::error_handling::last_error_length()
}

/// Copies the last error message into the provided allocated buffer.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_error_message_utf8(buf: *mut c_char, length: i32) -> i32 {
    ffi_helpers::error_handling::error_message_utf8(buf, length)
}

/// Clears the record of the last error message.
#[no_mangle]
pub extern "C" fn zcashlc_clear_last_error() {
    ffi_helpers::error_handling::clear_last_error()
}

/// Sets up the internal structure of the data database.
#[no_mangle]
pub extern "C" fn zcashlc_init_data_database(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
) -> i32 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(db_data, db_data_len)
        }));

        WalletDb::for_path(db_data, network)
            .map(|db| init_wallet_db(&db))
            .map(|_| 1)
            .map_err(|e| format_err!("Error while initializing data DB: {}", e))
    });
    unwrap_exc_or_null(res)
}

/// Initialises the data database with the given number of accounts using the given seed.
///
/// Returns the ExtendedSpendingKeys for the accounts. The caller should store these
/// securely for use while spending.
///
/// Call `zcashlc_vec_string_free` on the returned pointer when you are finished with it.
#[no_mangle]
pub extern "C" fn zcashlc_init_accounts_table(
    db_data: *const u8,
    db_data_len: usize,
    seed: *const u8,
    seed_len: usize,
    accounts: i32,
    capacity_ret: *mut usize,
    network_id: u32,
) -> *mut *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = wallet_db(db_data, db_data_len, network)?;
        let seed = unsafe { slice::from_raw_parts(seed, seed_len) };
        let accounts = if accounts >= 0 {
            accounts as u32
        } else {
            return Err(format_err!("accounts argument must be positive"));
        };

        let usks: Vec<_> = (0..accounts)
            .map(|account| {
                let account_id = AccountId::from(account);
                UnifiedSpendingKey::from_seed(&network, &seed, account_id)
                    .map(|usk| (account_id, usk))
                    .map_err(|e| {
                        format_err!("error generating unified spending key from seed: {:?}", e)
                    })
            })
            .collect::<Result<_, _>>()?;

        let ufvks: HashMap<AccountId, UnifiedFullViewingKey> = usks
            .iter()
            .map(|(account, usk)| (*account, usk.to_unified_full_viewing_key()))
            .collect();

        init_accounts_table(&db_data, &ufvks)
            .map(|_| {
                // Return the Sapling ExtendedSpendingKeys for the created accounts.
                let mut v: Vec<_> = usks
                    .iter()
                    .map(|(_, usk)| {
                        let encoded = encode_extended_spending_key(
                            network.hrp_sapling_extended_spending_key(),
                            usk.sapling(),
                        );
                        CString::new(encoded).unwrap().into_raw()
                    })
                    .collect();
                assert!(v.len() == accounts as usize);
                unsafe { *capacity_ret.as_mut().unwrap() = v.capacity() };
                let p = v.as_mut_ptr();
                std::mem::forget(v);
                return p;
            })
            .map_err(|e| format_err!("Error while initializing accounts: {}", e))
    });
    unwrap_exc_or_null(res)
}

/// Initialises the data database with the given unified full viewing keys
/// Call `zcashlc_vec_string_free` on the returned pointer when you are finished with it.
#[no_mangle]
pub extern "C" fn zcashlc_init_accounts_table_with_keys(
    db_data: *const u8,
    db_data_len: usize,
    uvks: *mut FFIUVKBoxedSlice,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = wallet_db(db_data, db_data_len, network)?;

        let s: Box<FFIUVKBoxedSlice> = unsafe { Box::from_raw(uvks) };
        let slice: &mut [FFIUnifiedViewingKey] = unsafe { slice::from_raw_parts_mut(s.ptr, s.len) };

        let ufvks: HashMap<AccountId, UnifiedFullViewingKey> = slice
            .into_iter()
            .map(|u| {
                let ufvkstr = unsafe { CStr::from_ptr(u.encoding).to_str().unwrap() };
                UnifiedFullViewingKey::decode(&network, &ufvkstr)
                    .map(|ufvk| (AccountId::from(u.account_id), ufvk))
            })
            .collect::<Result<HashMap<_, _>, _>>()
            .map_err(|e| format_err!("Error decoding unified full viewing keys: {:?}", e))?;

        match init_accounts_table(&db_data, &ufvks) {
            Ok(()) => Ok(true),
            Err(e) => Err(format_err!("Error while initializing accounts: {}", e)),
        }
    });
    unwrap_exc_or(res, false)
}

/// Derives Extended Spending Keys from the given seed into 'accounts' number of accounts.
/// Returns the ExtendedSpendingKeys for the accounts. The caller should store these
/// securely for use while spending.
///
/// Call `zcashlc_vec_string_free` on the returned pointer when you are finished with it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_derive_extended_spending_keys(
    seed: *const u8,
    seed_len: usize,
    accounts: i32,
    capacity_ret: *mut usize,
    network_id: u32,
) -> *mut *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let seed = slice::from_raw_parts(seed, seed_len);
        let accounts = if accounts > 0 {
            accounts as u32
        } else {
            return Err(format_err!("accounts argument must be greater than zero"));
        };

        let extsks: Vec<_> = (0..accounts)
            .map(|account| {
                sapling::spending_key(&seed, network.coin_type(), AccountId::from(account))
            })
            .collect();

        // Return the Sapling ExtendedSpendingKeys for the created accounts.
        let mut v: Vec<_> = extsks
            .iter()
            .map(|extsk| {
                let encoded = encode_extended_spending_key(
                    network.hrp_sapling_extended_spending_key(),
                    extsk,
                );
                CString::new(encoded).unwrap().into_raw()
            })
            .collect();
        assert!(v.len() == accounts as usize);
        *capacity_ret.as_mut().unwrap() = v.capacity();
        let p = v.as_mut_ptr();
        std::mem::forget(v);
        Ok(p)
    });
    unwrap_exc_or_null(res)
}

#[repr(C)]
pub struct FFIUnifiedViewingKey {
    account_id: u32,
    encoding: *const c_char,
}

#[repr(C)]
pub struct FFIUVKBoxedSlice {
    ptr: *mut FFIUnifiedViewingKey,
    len: usize, // number of elems
}

fn ufvk_to_ffi(
    account_id: AccountId,
    ufvk: &UnifiedFullViewingKey,
    network: Network,
) -> FFIUnifiedViewingKey {
    let encoded_ufvk = ufvk.encode(&network);

    FFIUnifiedViewingKey {
        account_id: account_id.into(),
        encoding: CString::new(encoded_ufvk).unwrap().into_raw(),
    }
}

fn ufvk_vec_to_ffi(v: Vec<FFIUnifiedViewingKey>) -> *mut FFIUVKBoxedSlice {
    // Going from Vec<_> to Box<[_]> just drops the (extra) `capacity`
    let boxed_slice: Box<[FFIUnifiedViewingKey]> = v.into_boxed_slice();
    let len = boxed_slice.len();
    let fat_ptr: *mut [FFIUnifiedViewingKey] = Box::into_raw(boxed_slice);
    let slim_ptr: *mut FFIUnifiedViewingKey = fat_ptr as _;
    Box::into_raw(Box::new(FFIUVKBoxedSlice { ptr: slim_ptr, len }))
}

#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_uvk_array(uvks: *mut FFIUVKBoxedSlice) {
    if uvks.is_null() {
        return;
    }
    let s: Box<FFIUVKBoxedSlice> = Box::from_raw(uvks);

    let slice: &mut [FFIUnifiedViewingKey] = slice::from_raw_parts_mut(s.ptr, s.len);
    drop(Box::from_raw(slice));
    drop(s);
}

#[no_mangle]
pub unsafe extern "C" fn zcashlc_derive_unified_full_viewing_keys_from_seed(
    seed: *const u8,
    seed_len: usize,
    accounts: i32,
    network_id: u32,
) -> *mut FFIUVKBoxedSlice {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let seed = slice::from_raw_parts(seed, seed_len);
        let accounts = if accounts > 0 {
            accounts as u32
        } else {
            return Err(format_err!("accounts argument must be greater than zero"));
        };

        let uvks = (0..accounts)
            .map(|account| {
                let account_id = AccountId::from(account);
                UnifiedSpendingKey::from_seed(&network, &seed, account_id)
                    .map_err(|e| {
                        format_err!("error generating unified spending key from seed: {:?}", e)
                    })
                    .map(|usk| {
                        let ufvk = usk.to_unified_full_viewing_key();
                        ufvk_to_ffi(account_id, &ufvk, network)
                    })
            })
            .collect::<Result<_, _>>()?;
        Ok(ufvk_vec_to_ffi(uvks))
    });
    unwrap_exc_or_null(res)
}

/// Derives Extended Full Viewing Keys from the given seed into 'accounts' number of accounts.
/// Returns the Extended Full Viewing Keys for the accounts. The caller should store these
/// securely
///
/// Call `zcashlc_vec_string_free` on the returned pointer when you are finished with it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_derive_extended_full_viewing_keys(
    seed: *const u8,
    seed_len: usize,
    accounts: i32,
    capacity_ret: *mut usize,
    network_id: u32,
) -> *mut *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let seed = slice::from_raw_parts(seed, seed_len);
        let accounts = if accounts > 0 {
            accounts as u32
        } else {
            return Err(format_err!("accounts argument must be greater than zero"));
        };

        let extsks: Vec<_> = (0..accounts)
            .map(|account| {
                ExtendedFullViewingKey::from(&sapling::spending_key(
                    &seed,
                    network.coin_type(),
                    AccountId::from(account),
                ))
            })
            .collect();

        // Return the ExtendedSpendingKeys for the created accounts.
        let mut v: Vec<_> = extsks
            .iter()
            .map(|extsk| {
                let encoded = encode_extended_full_viewing_key(
                    network.hrp_sapling_extended_full_viewing_key(),
                    extsk,
                );
                CString::new(encoded).unwrap().into_raw()
            })
            .collect();
        assert!(v.len() == accounts as usize);
        *capacity_ret.as_mut().unwrap() = v.capacity();
        let p = v.as_mut_ptr();
        std::mem::forget(v);
        Ok(p)
    });
    unwrap_exc_or_null(res)
}

/// derives a unified address from the given seed.
/// call zcashlc_string_free with the returned pointer when done using it
#[no_mangle]
pub unsafe extern "C" fn zcashlc_derive_unified_address_from_seed(
    seed: *const u8,
    seed_len: usize,
    account_index: i32,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let seed = slice::from_raw_parts(seed, seed_len);
        let account_index = if account_index >= 0 {
            account_index as u32
        } else {
            return Err(format_err!("accounts argument must be greater than zero"));
        };
        let account_id = AccountId::from(account_index);
        let ufvk = UnifiedSpendingKey::from_seed(&network, &seed, account_id)
            .map_err(|e| format_err!("error generating unified spending key from seed: {:?}", e))
            .map(|usk| usk.to_unified_full_viewing_key())?;

        // Derive the default Unified Address (containing the default Sapling payment
        // address that older SDKs used).
        let (ua, _) = ufvk.default_address();
        let address_str = ua.encode(&network);
        Ok(CString::new(address_str).unwrap().into_raw())
    });
    unwrap_exc_or_null(res)
}

/// derives a shielded address from the given viewing key.
/// call zcashlc_string_free with the returned pointer when done using it
#[no_mangle]
pub unsafe extern "C" fn zcashlc_derive_transparent_address_from_public_key(
    pubkey: *const c_char,
    network_id: u32,
) -> *mut c_char {
    #[allow(deprecated)]
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let public_key_str = CStr::from_ptr(pubkey).to_str()?;
        let pk = PublicKey::from_str(&public_key_str)?;
        let taddr = legacy::keys::pubkey_to_address(&pk).encode(&network);

        Ok(CString::new(taddr).unwrap().into_raw())
    });
    unwrap_exc_or_null(res)
}

/// derives a unified address from the given viewing key.
/// call zcashlc_string_free with the returned pointer when done using it
#[no_mangle]
pub unsafe extern "C" fn zcashlc_derive_unified_address_from_viewing_key(
    ufvk: *const c_char,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let ufvk_string = CStr::from_ptr(ufvk).to_str()?;
        let ufvk = match UnifiedFullViewingKey::decode(&network, &ufvk_string) {
            Ok(ufvk) => ufvk,
            Err(e) => {
                return Err(format_err!(
                    "Error while deriving viewing key from string input: {}",
                    e
                ));
            }
        };
        // Derive the default Unified Address (containing the default Sapling payment
        // address that older SDKs used).
        let (ua, _) = ufvk.default_address();
        let address_str = ua.encode(&network);
        Ok(CString::new(address_str).unwrap().into_raw())
    });
    unwrap_exc_or_null(res)
}

/// derives a shielded address from the given extended full viewing key.
/// call zcashlc_string_free with the returned pointer when done using it
#[no_mangle]
pub unsafe extern "C" fn zcashlc_derive_extended_full_viewing_key(
    extsk: *const c_char,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let extsk = CStr::from_ptr(extsk).to_str()?;
        let extfvk = match decode_extended_spending_key(
            network.hrp_sapling_extended_spending_key(),
            &extsk,
        ) {
            Ok(Some(extsk)) => ExtendedFullViewingKey::from(&extsk),
            Ok(None) => {
                return Err(format_err!("Deriving viewing key from spending key returned no results. Encoding was valid but type was incorrect."));
            }
            Err(e) => {
                return Err(format_err!(
                    "Error while deriving viewing key from spending key: {}",
                    e
                ));
            }
        };

        let encoded = encode_extended_full_viewing_key(
            network.hrp_sapling_extended_full_viewing_key(),
            &extfvk,
        );

        Ok(CString::new(encoded).unwrap().into_raw())
    });
    unwrap_exc_or_null(res)
}

/// Initialises the data database with the given block.
///
/// This enables a newly-created database to be immediately-usable, without needing to
/// synchronise historic blocks.
#[no_mangle]
pub extern "C" fn zcashlc_init_blocks_table(
    db_data: *const u8,
    db_data_len: usize,
    height: i32,
    hash_hex: *const c_char,
    time: u32,
    sapling_tree_hex: *const c_char,
    network_id: u32,
) -> i32 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = wallet_db(db_data, db_data_len, network)?;
        let hash = {
            let mut hash = hex::decode(unsafe { CStr::from_ptr(hash_hex) }.to_str()?).unwrap();
            hash.reverse();
            BlockHash::from_slice(&hash)
        };
        let sapling_tree =
            hex::decode(unsafe { CStr::from_ptr(sapling_tree_hex) }.to_str()?).unwrap();

        match init_blocks_table(
            &db_data,
            BlockHeight::from_u32(height as u32),
            hash,
            time,
            &sapling_tree,
        ) {
            Ok(()) => Ok(1),
            Err(e) => Err(format_err!("Error while initializing blocks table: {}", e)),
        }
    });
    unwrap_exc_or_null(res)
}

/// Returns the address for the account.
///
/// Call `zcashlc_string_free` on the returned pointer when you are finished with it.
#[no_mangle]
pub extern "C" fn zcashlc_get_address(
    db_data: *const u8,
    db_data_len: usize,
    account: i32,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = wallet_db(db_data, db_data_len, network)?;
        let account = if account >= 0 {
            account as u32
        } else {
            return Err(format_err!("accounts argument must be positive"));
        };

        let account = AccountId::from(account);

        match (&db_data).get_address(account) {
            Ok(Some(addr)) => {
                let addr_str = encode_payment_address(network.hrp_sapling_payment_address(), &addr);
                let c_str_addr = CString::new(addr_str).unwrap();
                Ok(c_str_addr.into_raw())
            }
            Ok(None) => Err(format_err!(
                "No payment address was available for account {:?}",
                account
            )),
            Err(e) => Err(format_err!("Error while fetching address: {}", e)),
        }
    });
    unwrap_exc_or_null(res)
}

/// Returns true when the address is valid and shielded.
/// Returns false in any other case
/// Errors when the provided address belongs to another network
#[no_mangle]
pub unsafe extern "C" fn zcashlc_is_valid_shielded_address(
    address: *const c_char,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let addr = CStr::from_ptr(address).to_str()?;
        Ok(is_valid_shielded_address(&addr, &network))
    });
    unwrap_exc_or(res, false)
}

fn is_valid_shielded_address(address: &str, network: &Network) -> bool {
    match RecipientAddress::decode(network, &address) {
        Some(addr) => match addr {
            RecipientAddress::Shielded(_) => true,
            RecipientAddress::Transparent(_) | RecipientAddress::Unified(_) => false,
        },
        None => false,
    }
}

/// Returns true when the address is valid and transparent.
/// Returns false in any other case
#[no_mangle]
pub unsafe extern "C" fn zcashlc_is_valid_transparent_address(
    address: *const c_char,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let addr = CStr::from_ptr(address).to_str()?;
        Ok(is_valid_transparent_address(&addr, &network))
    });
    unwrap_exc_or(res, false)
}
/// returns whether the given viewing key is valid or not
#[no_mangle]
pub unsafe extern "C" fn zcashlc_is_valid_viewing_key(key: *const c_char, network_id: u32) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let vkstr = CStr::from_ptr(key).to_str()?;

        match decode_extended_full_viewing_key(
            &network.hrp_sapling_extended_full_viewing_key(),
            &vkstr,
        ) {
            Ok(s) => match s {
                None => Ok(false),
                _ => Ok(true),
            },
            Err(_) => Ok(false),
        }
    });
    unwrap_exc_or(res, false)
}

/// returns whether the given unified full viewing key is valid or not
#[no_mangle]
pub unsafe extern "C" fn zcashlc_is_valid_unified_full_viewing_key(
    ufvk: *const c_char,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let ufvkstr = CStr::from_ptr(ufvk).to_str()?;

        match UnifiedFullViewingKey::decode(&network, &ufvkstr) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    });
    unwrap_exc_or(res, false)
}

fn is_valid_transparent_address(address: &str, network: &Network) -> bool {
    match RecipientAddress::decode(network, &address) {
        Some(addr) => match addr {
            RecipientAddress::Shielded(_) | RecipientAddress::Unified(_) => false,
            RecipientAddress::Transparent(_) => true,
        },
        None => false,
    }
}

/// Returns true when the address is a valid ZIP 316 Unified Address.
/// Returns false in any other case
/// Errors when the provided address belongs to another network
#[no_mangle]
pub unsafe extern "C" fn zcashlc_is_valid_unified_address(
    address: *const c_char,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let addr = CStr::from_ptr(address).to_str()?;
        Ok(is_valid_unified_address(&addr, &network))
    });
    unwrap_exc_or(res, false)
}

fn is_valid_unified_address(address: &str, network: &Network) -> bool {
    match RecipientAddress::decode(network, &address) {
        Some(addr) => match addr {
            RecipientAddress::Unified(_) => true,
            RecipientAddress::Shielded(_) | RecipientAddress::Transparent(_) => false,
        },
        None => false,
    }
}

/// Returns the balance for the account, including all unspent notes that we know about.
#[no_mangle]
pub extern "C" fn zcashlc_get_balance(
    db_data: *const u8,
    db_data_len: usize,
    account: i32,
    network_id: u32,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = wallet_db(db_data, db_data_len, network)?;

        if account >= 0 {
            let (_, max_height) = (&db_data)
                .block_height_extrema()
                .map_err(|e| format_err!("Error while fetching max block height: {}", e))
                .and_then(|opt| {
                    opt.ok_or(format_err!(
                        "No blockchain information available; scan required."
                    ))
                })?;

            (&db_data)
                .get_balance_at(AccountId::from(account as u32), max_height)
                .map(|b| b.into())
                .map_err(|e| format_err!("Error while fetching balance: {}", e))
        } else {
            Err(format_err!("account argument must be positive"))
        }
    });
    unwrap_exc_or(res, -1)
}

/// Returns the verified balance for the account, which ignores notes that have been
/// received too recently and are not yet deemed spendable.
#[no_mangle]
pub extern "C" fn zcashlc_get_verified_balance(
    db_data: *const u8,
    db_data_len: usize,
    account: i32,
    network_id: u32,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = wallet_db(db_data, db_data_len, network)?;
        if account >= 0 {
            (&db_data)
                .get_target_and_anchor_heights(ANCHOR_OFFSET)
                .map_err(|e| format_err!("Error while fetching anchor height: {}", e))
                .and_then(|opt_anchor| {
                    opt_anchor
                        .map(|(_, a)| a)
                        .ok_or(format_err!("Anchor height not available; scan required."))
                })
                .and_then(|anchor| {
                    (&db_data)
                        .get_balance_at(AccountId::from(account as u32), anchor)
                        .map_err(|e| format_err!("Error while fetching verified balance: {}", e))
                })
                .map(|amount| amount.into())
        } else {
            Err(format_err!("account argument must be positive"))
        }
    });
    unwrap_exc_or(res, -1)
}

/// Returns the verified transparent balance for the address, which ignores utxos that have been
/// received too recently and are not yet deemed spendable.
#[no_mangle]
pub extern "C" fn zcashlc_get_verified_transparent_balance(
    db_data: *const u8,
    db_data_len: usize,
    address: *const c_char,
    network_id: u32,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = wallet_db(db_data, db_data_len, network)?;
        let addr = unsafe { CStr::from_ptr(address).to_str()? };
        let taddr = TransparentAddress::decode(&network, &addr).unwrap();
        let amount = (&db_data)
            .get_target_and_anchor_heights(ANCHOR_OFFSET)
            .map_err(|e| format_err!("Error while fetching anchor height: {}", e))
            .and_then(|opt_anchor| {
                opt_anchor
                    .map(|(h, _)| h)
                    .ok_or(format_err!("height not available; scan required."))
            })
            .and_then(|anchor| {
                (&db_data)
                    .get_unspent_transparent_outputs(&taddr, anchor)
                    .map_err(|e| {
                        format_err!("Error while fetching verified transparent balance: {}", e)
                    })
            })?
            .iter()
            .map(|utxo| utxo.txout.value)
            .sum::<Option<Amount>>()
            .ok_or_else(|| format_err!("Balance overflowed MAX_MONEY."))?;

        Ok(amount.into())
    });
    unwrap_exc_or(res, -1)
}

/// Returns the verified transparent balance for the address, which ignores utxos that have been
/// received too recently and are not yet deemed spendable.
#[no_mangle]
pub extern "C" fn zcashlc_get_total_transparent_balance(
    db_data: *const u8,
    db_data_len: usize,
    address: *const c_char,
    network_id: u32,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = wallet_db(db_data, db_data_len, network)?;
        let addr = unsafe { CStr::from_ptr(address).to_str()? };
        let taddr = TransparentAddress::decode(&network, &addr).unwrap();
        let amount = (&db_data)
            .get_target_and_anchor_heights(ANCHOR_OFFSET)
            .map_err(|e| format_err!("Error while fetching anchor height: {}", e))
            .and_then(|opt_anchor| {
                opt_anchor
                    .map(|(h, _)| h)
                    .ok_or(format_err!("height not available; scan required."))
            })
            .and_then(|anchor| {
                (&db_data)
                    .get_unspent_transparent_outputs(&taddr, anchor)
                    .map_err(|e| {
                        format_err!("Error while fetching total transparent balance: {}", e)
                    })
            })?
            .iter()
            .map(|utxo| utxo.txout.value)
            .sum::<Option<Amount>>()
            .ok_or_else(|| format_err!("Balance overflowed MAX_MONEY."))?;

        Ok(amount.into())
    });
    unwrap_exc_or(res, -1)
}

/// Returns the memo for a received note, if it is known and a valid UTF-8 string.
///
/// The note is identified by its row index in the `received_notes` table within the data
/// database.
///
/// Call `zcashlc_string_free` on the returned pointer when you are finished with it.
#[no_mangle]
pub extern "C" fn zcashlc_get_received_memo_as_utf8(
    db_data: *const u8,
    db_data_len: usize,
    id_note: i64,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = wallet_db(db_data, db_data_len, network)?;

        let memo = (&db_data)
            .get_memo(NoteId::ReceivedNoteId(id_note))
            .map_err(|e| format_err!("An error occurred retrieving the memo, {}", e))
            .and_then(|memo| match memo {
                Memo::Empty => Ok("".to_string()),
                Memo::Text(memo) => Ok(memo.into()),
                _ => Err(format_err!("This memo does not contain UTF-8 text")),
            })?;

        Ok(CString::new(memo).unwrap().into_raw())
    });
    unwrap_exc_or_null(res)
}

/// Returns the memo for a sent note, if it is known and a valid UTF-8 string.
///
/// The note is identified by its row index in the `sent_notes` table within the data
/// database.
///
/// Call `zcashlc_string_free` on the returned pointer when you are finished with it.
#[no_mangle]
pub extern "C" fn zcashlc_get_sent_memo_as_utf8(
    db_data: *const u8,
    db_data_len: usize,
    id_note: i64,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = wallet_db(db_data, db_data_len, network)?;

        let memo = (&db_data)
            .get_memo(NoteId::SentNoteId(id_note))
            .map_err(|e| format_err!("An error occurred retrieving the memo, {}", e))
            .and_then(|memo| match memo {
                Memo::Empty => Ok("".to_string()),
                Memo::Text(memo) => Ok(memo.into()),
                _ => Err(format_err!("This memo does not contain UTF-8 text")),
            })?;

        Ok(CString::new(memo).unwrap().into_raw())
    });
    unwrap_exc_or_null(res)
}

/// Checks that the scanned blocks in the data database, when combined with the recent
/// `CompactBlock`s in the cache database, form a valid chain.
///
/// This function is built on the core assumption that the information provided in the
/// cache database is more likely to be accurate than the previously-scanned information.
/// This follows from the design (and trust) assumption that the `lightwalletd` server
/// provides accurate block information as of the time it was requested.
///
/// Returns:
/// - `-1` if the combined chain is valid.
/// - `upper_bound` if the combined chain is invalid.
///   `upper_bound` is the height of the highest invalid block (on the assumption that the
///   highest block in the cache database is correct).
/// - `0` if there was an error during validation unrelated to chain validity.
///
/// This function does not mutate either of the databases.
#[no_mangle]
pub extern "C" fn zcashlc_validate_combined_chain(
    db_cache: *const u8,
    db_cache_len: usize,
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
) -> i32 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let block_db = block_db(db_cache, db_cache_len)?;
        let db_data = wallet_db(db_data, db_data_len, network)?;

        let validate_from = (&db_data)
            .get_max_height_hash()
            .map_err(|e| format_err!("Error while validating chain: {}", e))?;

        let val_res = validate_chain(&network, &block_db, validate_from);

        if let Err(e) = val_res {
            match e {
                SqliteClientError::BackendError(Error::InvalidChain(upper_bound, _)) => {
                    let upper_bound_u32 = u32::from(upper_bound);
                    Ok(upper_bound_u32 as i32)
                }
                _ => Err(format_err!("Error while validating chain: {}", e)),
            }
        } else {
            // All blocks are valid, so "highest invalid block height" is below genesis.
            Ok(-1)
        }
    });
    unwrap_exc_or_null(res)
}
#[no_mangle]
pub extern "C" fn zcashlc_get_nearest_rewind_height(
    db_data: *const u8,
    db_data_len: usize,
    height: i32,
    network_id: u32,
) -> i32 {
    #[allow(deprecated)]
    let res = catch_panic(|| {
        if height < 100 {
            Ok(height)
        } else {
            let network = parse_network(network_id)?;
            let db_data = wallet_db(db_data, db_data_len, network)?;
            let height = BlockHeight::try_from(height)?;
            match get_rewind_height(&db_data) {
                Ok(Some(best_height)) => {
                    let first_unspent_note_height = u32::from(best_height);
                    let rewind_height = u32::from(height);
                    Ok(std::cmp::min(
                        first_unspent_note_height as i32,
                        rewind_height as i32,
                    ))
                }
                Ok(None) => {
                    let rewind_height = u32::from(height);
                    Ok(rewind_height as i32)
                }
                Err(e) => Err(format_err!(
                    "Error while getting nearest rewind height for {}: {}",
                    height,
                    e
                )),
            }
        }
    });
    unwrap_exc_or(res, -1)
}
/// Rewinds the data database to the given height.
///
/// If the requested height is greater than or equal to the height of the last scanned
/// block, this function does nothing.
#[no_mangle]
pub extern "C" fn zcashlc_rewind_to_height(
    db_data: *const u8,
    db_data_len: usize,
    height: i32,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = wallet_db(db_data, db_data_len, network)?;
        let mut db_data = db_data.get_update_ops()?;

        let height = BlockHeight::try_from(height)?;
        db_data
            .rewind_to_height(height)
            .map(|_| true)
            .map_err(|e| format_err!("Error while rewinding data DB to height {}: {}", height, e))
    });
    unwrap_exc_or(res, false)
}

/// Scans new blocks added to the cache for any transactions received by the tracked
/// accounts.
///
/// This function pays attention only to cached blocks with heights greater than the
/// highest scanned block in `db_data`. Cached blocks with lower heights are not verified
/// against previously-scanned blocks. In particular, this function **assumes** that the
/// caller is handling rollbacks.
///
/// For brand-new light client databases, this function starts scanning from the Sapling
/// activation height. This height can be fast-forwarded to a more recent block by calling
/// [`zcashlc_init_blocks_table`] before this function.
///
/// Scanned blocks are required to be height-sequential. If a block is missing from the
/// cache, an error will be signalled.
#[no_mangle]
pub extern "C" fn zcashlc_scan_blocks(
    db_cache: *const u8,
    db_cache_len: usize,
    db_data: *const u8,
    db_data_len: usize,
    scan_limit: u32,
    network_id: u32,
) -> i32 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let block_db = block_db(db_cache, db_cache_len)?;
        let db_read = wallet_db(db_data, db_data_len, network)?;
        let mut db_data = db_read.get_update_ops()?;
        let limit = if scan_limit <= 0 {
            None
        } else {
            Some(scan_limit)
        };
        match scan_cached_blocks(&network, &block_db, &mut db_data, limit) {
            Ok(()) => Ok(1),
            Err(e) => Err(format_err!("Error while scanning blocks: {}", e)),
        }
    });
    unwrap_exc_or_null(res)
}

#[no_mangle]
pub extern "C" fn zcashlc_put_utxo(
    db_data: *const u8,
    db_data_len: usize,
    txid_bytes: *const u8,
    txid_bytes_len: usize,
    index: i32,
    script_bytes: *const u8,
    script_bytes_len: usize,
    value: i64,
    height: i32,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = wallet_db(db_data, db_data_len, network)?;
        let mut db_data = db_data.get_update_ops()?;

        let txid_bytes = unsafe { slice::from_raw_parts(txid_bytes, txid_bytes_len) };
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_bytes);

        let script_bytes = unsafe { slice::from_raw_parts(script_bytes, script_bytes_len) };
        let script_pubkey = legacy::Script(script_bytes.to_vec());

        let output = WalletTransparentOutput {
            outpoint: OutPoint::new(txid, index as u32),
            txout: TxOut {
                value: Amount::from_i64(value).unwrap(),
                script_pubkey,
            },
            height: BlockHeight::from(height as u32),
        };
        match db_data.put_received_transparent_utxo(&output) {
            Ok(_) => Ok(true),
            Err(e) => Err(format_err!("Error while inserting UTXO: {}", e)),
        }
    });
    unwrap_exc_or(res, false)
}

#[no_mangle]
pub unsafe extern "C" fn zcashlc_clear_utxos(
    db_data: *const u8,
    db_data_len: usize,
    taddress: *const c_char,
    above_height: i32,
    network_id: u32,
) -> i32 {
    #[allow(deprecated)]
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = wallet_db(db_data, db_data_len, network)?;
        let mut db_data = db_data.get_update_ops()?;
        let addr = CStr::from_ptr(taddress).to_str()?;
        let taddress = TransparentAddress::decode(&network, &addr).unwrap();
        let height = BlockHeight::from(above_height as u32);
        match delete_utxos_above(&mut db_data, &taddress, height) {
            Ok(rows) => Ok(rows as i32),
            Err(e) => Err(format_err!("Error while clearing UTXOs: {}", e)),
        }
    });
    unwrap_exc_or(res, -1)
}

#[no_mangle]
pub extern "C" fn zcashlc_decrypt_and_store_transaction(
    db_data: *const u8,
    db_data_len: usize,
    tx: *const u8,
    tx_len: usize,
    _mined_height: u32,
    network_id: u32,
) -> i32 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_read = wallet_db(db_data, db_data_len, network)?;
        let mut db_data = db_read.get_update_ops()?;
        let tx_bytes = unsafe { slice::from_raw_parts(tx, tx_len) };

        // The consensus branch ID passed in here does not matter:
        // - v4 and below cache it internally, but all we do with this transaction while
        //   it is in memory is decryption and serialization, neither of which use the
        //   consensus branch ID.
        // - v5 and above transactions ignore the argument, and parse the correct value
        //   from their encoding.
        let tx = Transaction::read(&tx_bytes[..], BranchId::Sapling)?;

        match decrypt_and_store_transaction(&network, &mut db_data, &tx) {
            Ok(()) => Ok(1),
            Err(e) => Err(format_err!("Error while decrypting transaction: {}", e)),
        }
    });
    unwrap_exc_or(res, -1)
}

/// Creates a transaction paying the specified address from the given account.
///
/// Returns the row index of the newly-created transaction in the `transactions` table
/// within the data database. The caller can read the raw transaction bytes from the `raw`
/// column in order to broadcast the transaction to the network.
///
/// Do not call this multiple times in parallel, or you will generate transactions that
/// double-spend the same notes.
#[no_mangle]
pub extern "C" fn zcashlc_create_to_address(
    db_data: *const u8,
    db_data_len: usize,
    account: i32,
    extsk: *const c_char,
    to: *const c_char,
    value: i64,
    memo: *const c_char,
    spend_params: *const u8,
    spend_params_len: usize,
    output_params: *const u8,
    output_params_len: usize,
    network_id: u32,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_read = wallet_db(db_data, db_data_len, network)?;
        let mut db_data = db_read.get_update_ops()?;
        let account = if account >= 0 {
            account as u32
        } else {
            return Err(format_err!("account argument must be positive"));
        };
        let extsk = unsafe { CStr::from_ptr(extsk) }.to_str()?;
        let to = unsafe { CStr::from_ptr(to) }.to_str()?;
        let value =
            Amount::from_i64(value).map_err(|()| format_err!("Invalid amount, out of range"))?;
        if value.is_negative() {
            return Err(format_err!("Amount is negative"));
        }
        let memo = unsafe { CStr::from_ptr(memo) }.to_str()?;
        let spend_params = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(spend_params, spend_params_len)
        }));
        let output_params = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(output_params, output_params_len)
        }));

        let extsk =
            match decode_extended_spending_key(network.hrp_sapling_extended_spending_key(), &extsk)
            {
                Ok(Some(extsk)) => extsk,
                Ok(None) => {
                    return Err(format_err!("ExtendedSpendingKey is for the wrong network"));
                }
                Err(e) => {
                    return Err(format_err!("Invalid ExtendedSpendingKey: {}", e));
                }
            };

        let to = match RecipientAddress::decode(&network, &to) {
            Some(to) => to,
            None => {
                return Err(format_err!("PaymentAddress is for the wrong network"));
            }
        };

        // TODO: consider warning in this case somehow, rather than swallowing this error
        let memo = match to {
            RecipientAddress::Shielded(_) | RecipientAddress::Unified(_) => {
                let memo_value = Memo::from_str(&memo).map_err(|_| format_err!("Invalid memo"))?;
                Some(MemoBytes::from(&memo_value))
            }
            RecipientAddress::Transparent(_) => None,
        };

        let prover = LocalTxProver::new(spend_params, output_params);

        create_spend_to_address(
            &mut db_data,
            &network,
            prover,
            AccountId::from(account),
            &extsk,
            &to,
            value,
            memo,
            OvkPolicy::Sender,
            ANCHOR_OFFSET,
        )
        .map_err(|e| format_err!("Error while sending funds: {}", e))
    });
    unwrap_exc_or(res, -1)
}

#[no_mangle]
pub extern "C" fn zcashlc_branch_id_for_height(height: i32, network_id: u32) -> i32 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let branch: BranchId = BranchId::for_height(&network, BlockHeight::from(height as u32));
        let branch_id: u32 = u32::from(branch);
        Ok(branch_id as i32)
    });
    unwrap_exc_or(res, -1)
}

/// Frees strings returned by other zcashlc functions.
#[no_mangle]
pub extern "C" fn zcashlc_string_free(s: *mut c_char) {
    unsafe {
        if s.is_null() {
            return;
        }
        CString::from_raw(s)
    };
}

/// Frees vectors of strings returned by other zcashlc functions.
#[no_mangle]
pub extern "C" fn zcashlc_vec_string_free(v: *mut *mut c_char, len: usize, capacity: usize) {
    unsafe {
        if v.is_null() {
            return;
        }
        assert!(len <= capacity);
        let v = Vec::from_raw_parts(v, len, capacity);
        v.into_iter().map(|s| CString::from_raw(s)).for_each(drop);
    };
}

/// Derives a transparent account private key from seed
#[no_mangle]
pub unsafe extern "C" fn zcashlc_derive_transparent_account_private_key_from_seed(
    seed: *const u8,
    seed_len: usize,
    account: i32,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let seed = slice::from_raw_parts(seed, seed_len);
        let account = if account >= 0 {
            AccountId::from(account as u32)
        } else {
            return Err(format_err!("account argument must be positive"));
        };

        // Derive the USK to ensure it exists, and fetch its transparent component.
        let usk = UnifiedSpendingKey::from_seed(&network, &seed, account)
            .map_err(|e| format_err!("error generating unified spending key from seed: {:?}", e))?;
        // Derive the corresponding BIP 32 extended privkey.
        let xprv =
            p2pkh_xprv(&network, &seed, account).expect("USK derivation should ensure this exists");
        // Verify that we did derive the same privkey.
        assert_eq!(
            usk.transparent().to_account_pubkey().serialize(),
            legacy::keys::AccountPrivKey::from_extended_privkey(xprv.extended_key.clone())
                .to_account_pubkey()
                .serialize(),
        );
        // Encode using the BIP 32 xprv serialization format.
        let xprv_str: String = xprv.serialize();

        Ok(CString::new(xprv_str).unwrap().into_raw())
    });
    unwrap_exc_or_null(res)
}

fn p2pkh_xprv<P: Parameters>(
    params: &P,
    seed: &[u8],
    account: AccountId,
) -> Result<hdwallet_bitcoin::PrivKey, hdwallet::error::Error> {
    let master_key = ExtendedPrivKey::with_seed(&seed)?;
    let key_chain = hdwallet::DefaultKeyChain::new(master_key);
    let chain_path = format!("m/44H/{}H/{}H", params.coin_type(), u32::from(account)).into();
    let (extended_key, derivation) = key_chain.derive_private_key(chain_path)?;
    Ok(hdwallet_bitcoin::PrivKey {
        network: hdwallet_bitcoin::Network::MainNet,
        derivation,
        extended_key,
    })
}

fn p2pkh_addr(
    tfvk: legacy::keys::AccountPubKey,
    index: u32,
) -> Result<TransparentAddress, hdwallet::error::Error> {
    tfvk.derive_external_ivk()
        .and_then(|tivk| tivk.derive_address(index))
}

/// Derives a transparent address from the given seed
#[no_mangle]
pub unsafe extern "C" fn zcashlc_derive_transparent_address_from_seed(
    seed: *const u8,
    seed_len: usize,
    account: i32,
    index: i32,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let seed = slice::from_raw_parts(seed, seed_len);
        let network = parse_network(network_id)?;
        let account = if account >= 0 {
            account as u32
        } else {
            return Err(format_err!("account argument must be positive"));
        };

        let index = if index >= 0 {
            index as u32
        } else {
            return Err(format_err!("index argument must be positive"));
        };
        let tfvk = UnifiedSpendingKey::from_seed(&network, &seed, AccountId::from(account))
            .map_err(|e| format_err!("error generating unified spending key from seed: {:?}", e))
            .map(|usk| usk.transparent().to_account_pubkey())?;
        let taddr = match p2pkh_addr(tfvk, index) {
            Ok(taddr) => taddr,
            Err(e) => return Err(format_err!("Couldn't derive transparent address: {:?}", e)),
        };
        let taddr = taddr.encode(&network);

        Ok(CString::new(taddr).unwrap().into_raw())
    });
    unwrap_exc_or_null(res)
}

/// Derives a transparent address from the given account private key.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_derive_transparent_address_from_account_private_key(
    xprv: *const c_char,
    index: i32,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let index = if index >= 0 {
            index as u32
        } else {
            return Err(format_err!("index argument must be positive"));
        };
        let xprv_str = CStr::from_ptr(xprv).to_str()?;

        let xprv = match hdwallet_bitcoin::PrivKey::deserialize(xprv_str.to_owned()) {
            Ok(xprv) => xprv,
            Err(e) => return Err(format_err!("Invalid transparent extended privkey: {:?}", e)),
        };

        let tfvk = legacy::keys::AccountPrivKey::from_extended_privkey(xprv.extended_key)
            .to_account_pubkey();
        let taddr = match p2pkh_addr(tfvk, index) {
            Ok(taddr) => taddr,
            Err(e) => return Err(format_err!("Couldn't derive transparent address: {:?}", e)),
        };
        let taddr = taddr.encode(&network);
        Ok(CString::new(taddr).unwrap().into_raw())
    });
    unwrap_exc_or_null(res)
}

#[no_mangle]
pub extern "C" fn zcashlc_shield_funds(
    db_data: *const u8,
    db_data_len: usize,
    account: i32,
    xprv: *const c_char,
    extsk: *const c_char,
    memo: *const c_char,
    spend_params: *const u8,
    spend_params_len: usize,
    output_params: *const u8,
    output_params_len: usize,
    network_id: u32,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = wallet_db(db_data, db_data_len, network)?;
        let mut update_ops = (&db_data)
            .get_update_ops()
            .map_err(|e| format_err!("Could not obtain a writable database connection: {}", e))?;

        let account = if account >= 0 {
            account as u32
        } else {
            return Err(format_err!("account argument must be positive"));
        };
        let xprv_str = unsafe { CStr::from_ptr(xprv) }.to_str()?;
        let extsk = unsafe { CStr::from_ptr(extsk) }.to_str()?;
        let memo = unsafe { CStr::from_ptr(memo) }.to_str()?;
        let spend_params = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(spend_params, spend_params_len)
        }));
        let output_params = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(output_params, output_params_len)
        }));

        //grab secret private key for t-funds
        let xprv = match hdwallet_bitcoin::PrivKey::deserialize(xprv_str.to_owned()) {
            Ok(xprv) => xprv,
            Err(e) => return Err(format_err!("Invalid transparent extended privkey: {:?}", e)),
        };
        let sk = legacy::keys::AccountPrivKey::from_extended_privkey(xprv.extended_key);

        let extfvk =
            match decode_extended_spending_key(network.hrp_sapling_extended_spending_key(), &extsk)
            {
                Ok(Some(extsk)) => ExtendedFullViewingKey::from(&extsk),
                Ok(None) => {
                    return Err(format_err!("ExtendedSpendingKey is for the wrong network"));
                }
                Err(e) => {
                    return Err(format_err!("Invalid ExtendedSpendingKey: {}", e));
                }
            };

        let memo = Memo::from_str(&memo).map_err(|_| format_err!("Invalid memo"))?;
        let memo_bytes = MemoBytes::from(memo);
        shield_transparent_funds(
            &mut update_ops,
            &network,
            LocalTxProver::new(spend_params, output_params),
            &sk,
            &extfvk,
            AccountId::from(account),
            &memo_bytes,
            ANCHOR_OFFSET,
        )
        .map_err(|e| format_err!("Error while shielding transaction: {}", e))
    });
    unwrap_exc_or(res, -1)
}

//
// Utility functions
//

fn parse_network(value: u32) -> Result<Network, failure::Error> {
    match value {
        0 => Ok(TestNetwork),
        1 => Ok(MainNetwork),
        _ => Err(format_err!("Invalid network type: {}. Expected either 0 or 1 for Testnet or Mainnet, respectively.", value))
    }
}
