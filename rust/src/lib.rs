#![deny(unsafe_op_in_unsafe_fn)]

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
use prost::Message;
use schemer::MigratorError;
use secrecy::Secret;
use std::convert::{TryFrom, TryInto};
use std::ffi::{CStr, CString, OsStr};
use std::mem::ManuallyDrop;
use std::num::NonZeroU32;
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::slice;
use tracing::{debug, metadata::LevelFilter};
use tracing_subscriber::prelude::*;
use zcash_client_backend::data_api::{
    chain::CommitmentTreeRoot, NoteId, ShieldedProtocol, WalletCommitmentTrees,
};
use zcash_primitives::merkle_tree::HashSer;
use zcash_primitives::sapling;
use zcash_primitives::transaction::{components::amount::NonNegativeAmount, TxId};

use zcash_address::{
    self,
    unified::{self, Container, Encoding},
    ConversionError, ToAddress, TryFromAddress, ZcashAddress,
};
use zcash_client_backend::{
    address::{RecipientAddress, UnifiedAddress},
    data_api::{
        chain::scan_cached_blocks,
        scanning::ScanPriority,
        wallet::{
            decrypt_and_store_transaction, input_selection::GreedyInputSelector,
            shield_transparent_funds, spend,
        },
        AccountBirthday, WalletRead, WalletWrite,
    },
    encoding::{decode_extended_full_viewing_key, decode_extended_spending_key, AddressCodec},
    fees::{fixed, zip317, DustOutputPolicy},
    keys::{DecodingError, Era, UnifiedFullViewingKey, UnifiedSpendingKey},
    proto::service::TreeState,
    wallet::{OvkPolicy, WalletTransparentOutput},
    zip321::{Payment, TransactionRequest},
};

use zcash_client_sqlite::{
    chain::{init::init_blockmeta_db, BlockMeta},
    wallet::init::{init_wallet_db, WalletMigrationError},
    FsBlockDb, WalletDb,
};
use zcash_primitives::consensus::Network::{MainNetwork, TestNetwork};
use zcash_primitives::{
    block::BlockHash,
    consensus::{BlockHeight, BranchId, Network, Parameters},
    legacy::{self, TransparentAddress},
    memo::{Memo, MemoBytes},
    transaction::{
        components::{Amount, OutPoint, TxOut},
        fees::fixed::FeeRule as FixedFeeRule,
        fees::zip317::FeeRule as Zip317FeeRule,
        Transaction,
    },
    zip32::fingerprint::SeedFingerprint,
    zip32::AccountId,
};
use zcash_proofs::prover::LocalTxProver;

mod ffi;
mod os_log;

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

/// Helper method for construcing a WalletDb value from path data provided over the FFI.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
unsafe fn wallet_db(
    db_data: *const u8,
    db_data_len: usize,
    network: Network,
) -> anyhow::Result<WalletDb<rusqlite::Connection, Network>> {
    let db_data = Path::new(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(db_data, db_data_len)
    }));
    WalletDb::for_path(db_data, network)
        .map_err(|e| anyhow!("Error opening wallet database connection: {}", e))
}

/// Helper method for construcing a FsBlockDb value from path data provided over the FFI.
///
/// # Safety
///
/// - `fsblock_db` must be non-null and valid for reads for `fsblock_db_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `fsblock_db` must not be mutated for the duration of the function call.
/// - The total size `fsblock_db_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
fn block_db(fsblock_db: *const u8, fsblock_db_len: usize) -> anyhow::Result<FsBlockDb> {
    let cache_db = Path::new(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(fsblock_db, fsblock_db_len)
    }));
    FsBlockDb::for_path(cache_db)
        .map_err(|e| anyhow!("Error opening block source database connection: {}", e))
}

/// Initializes global Rust state, such as the logging infrastructure and threadpools.
///
/// When `show_trace_logs` is `true`, Rust events at the `TRACE` level will be logged.
///
/// # Panics
///
/// This method panics if called more than once.
#[no_mangle]
pub extern "C" fn zcashlc_init_on_load(show_trace_logs: bool) {
    // Set up the tracing layers for the Apple OS logging framework.
    let (log_layer, signpost_layer) = os_log::layers("co.electriccoin.ios", "rust");

    // Install the `tracing` subscriber.
    tracing_subscriber::registry()
        .with(log_layer)
        .with(signpost_layer)
        .with(if show_trace_logs {
            LevelFilter::TRACE
        } else {
            LevelFilter::DEBUG
        })
        .init();

    // Log panics instead of writing them to stderr.
    log_panics::init();

    // Manually build the Rayon thread pool, so we can name the threads.
    rayon::ThreadPoolBuilder::new()
        .thread_name(|i| format!("zc-rayon-{}", i))
        .build_global()
        .expect("Only initialized once");

    debug!("Rust backend has been initialized successfully");
    cfg_if::cfg_if! {
        if #[cfg(debug_assertions)] {
            debug!("WARNING! Debugging enabled! This will likely slow things down 10X!");
        } else {
            debug!("Release enabled (congrats, this is NOT a debug build).");
        }
    }
}

/// Returns the length of the last error message to be logged.
#[no_mangle]
pub extern "C" fn zcashlc_last_error_length() -> i32 {
    ffi_helpers::error_handling::last_error_length()
}

/// Copies the last error message into the provided allocated buffer.
///
/// # Safety
///
/// - `buf` must be non-null and valid for reads for `length` bytes, and it must have an alignment
///   of `1`.
/// - The memory referenced by `buf` must not be mutated for the duration of the function call.
/// - The total size `length` must be no larger than `isize::MAX`. See the safety documentation of
///   pointer::offset.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_error_message_utf8(buf: *mut c_char, length: i32) -> i32 {
    unsafe { ffi_helpers::error_handling::error_message_utf8(buf, length) }
}

/// Clears the record of the last error message.
#[no_mangle]
pub extern "C" fn zcashlc_clear_last_error() {
    ffi_helpers::error_handling::clear_last_error()
}

/// Sets up the internal structure of the data database.  The value for `seed` may be provided as a
/// null pointer if the caller wishes to attempt migrations without providing the wallet's seed
/// value.
///
/// Returns 0 if successful, 1 if the seed must be provided in order to execute the requested
/// migrations, or -1 otherwise.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `seed` must be non-null and valid for reads for `seed_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `seed` must not be mutated for the duration of the function call.
/// - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
///   of pointer::offset.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_init_data_database(
    db_data: *const u8,
    db_data_len: usize,
    seed: *const u8,
    seed_len: usize,
    network_id: u32,
) -> i32 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let seed = if seed.is_null() {
            None
        } else {
            Some(Secret::new(
                (unsafe { slice::from_raw_parts(seed, seed_len) }).to_vec(),
            ))
        };

        match init_wallet_db(&mut db_data, seed) {
            Ok(_) => Ok(0),
            Err(MigratorError::Adapter(WalletMigrationError::SeedRequired)) => Ok(1),
            Err(e) => Err(anyhow!("Error while initializing data DB: {}", e)),
        }
    });
    unwrap_exc_or(res, -1)
}

/// A struct that contains an account identifier along with a pointer to the binary encoding
/// of an associated key.
///
/// # Safety
///
/// - `encoding` must be non-null and must point to an array of `encoding_len` bytes.
#[repr(C)]
pub struct FFIBinaryKey {
    account_id: u32,
    encoding: *mut u8,
    encoding_len: usize,
}

impl FFIBinaryKey {
    fn new(account_id: AccountId, key_bytes: Vec<u8>) -> Self {
        let mut raw_key_bytes = ManuallyDrop::new(key_bytes.into_boxed_slice());
        FFIBinaryKey {
            account_id: account_id.into(),
            encoding: raw_key_bytes.as_mut_ptr(),
            encoding_len: raw_key_bytes.len(),
        }
    }
}

/// Frees a FFIBinaryKey value
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`FFIBinaryKey`].
///   See the safety documentation of [`FFIBinaryKey`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_binary_key(ptr: *mut FFIBinaryKey) {
    if !ptr.is_null() {
        let key: Box<FFIBinaryKey> = unsafe { Box::from_raw(ptr) };
        let key_slice: &mut [u8] =
            unsafe { slice::from_raw_parts_mut(key.encoding, key.encoding_len) };
        drop(unsafe { Box::from_raw(key_slice) });
    }
}

/// Adds the next available account-level spend authority, given the current set of [ZIP 316]
/// account identifiers known, to the wallet database.
///
/// Returns the newly created [ZIP 316] account identifier, along with the binary encoding of the
/// [`UnifiedSpendingKey`] for the newly created account.  The caller should manage the memory of
/// (and store) the returned spending keys in a secure fashion.
///
/// If `seed` was imported from a backup and this method is being used to restore a
/// previous wallet state, you should use this method to add all of the desired
/// accounts before scanning the chain from the seed's birthday height.
///
/// By convention, wallets should only allow a new account to be generated after funds
/// have been received by the currently available account (in order to enable
/// automated account recovery).
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `seed` must be non-null and valid for reads for `seed_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `seed` must not be mutated for the duration of the function call.
/// - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
///   of pointer::offset.
/// - Call [`zcashlc_free_binary_key`] to free the memory associated with the returned pointer when
///   you are finished using it.
///
/// [ZIP 316]: https://zips.z.cash/zip-0316
#[no_mangle]
pub unsafe extern "C" fn zcashlc_create_account(
    db_data: *const u8,
    db_data_len: usize,
    seed: *const u8,
    seed_len: usize,
    treestate: *const u8,
    treestate_len: usize,
    recover_until: i64,
    network_id: u32,
) -> *mut FFIBinaryKey {
    use zcash_client_backend::data_api::BirthdayError;

    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let seed = Secret::new((unsafe { slice::from_raw_parts(seed, seed_len) }).to_vec());
        let treestate =
            TreeState::decode(unsafe { slice::from_raw_parts(treestate, treestate_len) })
                .map_err(|e| anyhow!("Invalid TreeState: {}", e))?;
        let recover_until = recover_until.try_into().ok();

        let birthday =
            AccountBirthday::from_treestate(treestate, recover_until).map_err(|e| match e {
                BirthdayError::HeightInvalid(e) => {
                    anyhow!("Invalid TreeState: Invalid height: {}", e)
                }
                BirthdayError::Decode(e) => {
                    anyhow!("Invalid TreeState: Invalid frontier encoding: {}", e)
                }
            })?;

        db_data
            .create_account(&seed, birthday)
            .map(|(account, usk)| {
                let encoded = usk.to_bytes(Era::Orchard);
                Box::into_raw(Box::new(FFIBinaryKey::new(account, encoded)))
            })
            .map_err(|e| anyhow!("Error while initializing accounts: {}", e))
    });
    unwrap_exc_or_null(res)
}

/// A struct that contains an account identifier along with a pointer to the string encoding
/// of an associated key.
///
/// # Safety
///
/// - `encoding` must be non-null and must point to a null-terminated UTF-8 string.
#[repr(C)]
pub struct FFIEncodedKey {
    account_id: u32,
    encoding: *mut c_char,
}

/// A struct that contains a pointer to, and length information for, a heap-allocated
/// slice of [`FFIEncodedKey`] values.
///
/// # Safety
///
/// - `ptr` must be non-null and must be valid for reads for `len * mem::size_of::<FFIEncodedKey>()`
///   many bytes, and it must be properly aligned. This means in particular:
///   - The entire memory range pointed to by `ptr` must be contained within a single allocated
///     object. Slices can never span across multiple allocated objects.
///   - `ptr` must be non-null and aligned even for zero-length slices.
///   - `ptr` must point to `len` consecutive properly initialized values of type
///     [`FFIEncodedKey`].
/// - The total size `len * mem::size_of::<FFIEncodedKey>()` of the slice pointed to
///   by `ptr` must be no larger than isize::MAX. See the safety documentation of pointer::offset.
/// - See the safety documentation of [`FFIEncodedKey`]
#[repr(C)]
pub struct FFIEncodedKeys {
    ptr: *mut FFIEncodedKey,
    len: usize, // number of elems
}

impl FFIEncodedKeys {
    pub fn ptr_from_vec(v: Vec<FFIEncodedKey>) -> *mut Self {
        // Going from Vec<_> to Box<[_]> just drops the (extra) `capacity`
        let boxed_slice: Box<[FFIEncodedKey]> = v.into_boxed_slice();
        let len = boxed_slice.len();
        let fat_ptr: *mut [FFIEncodedKey] = Box::into_raw(boxed_slice);
        // It is guaranteed to be possible to obtain a raw pointer to the start
        // of a slice by casting the pointer-to-slice, as documented e.g. at
        // <https://doc.rust-lang.org/std/primitive.pointer.html#method.as_mut_ptr>.
        // TODO: replace with `as_mut_ptr()` when that is stable.
        let slim_ptr: *mut FFIEncodedKey = fat_ptr as _;
        Box::into_raw(Box::new(FFIEncodedKeys { ptr: slim_ptr, len }))
    }
}

/// Frees an array of FFIEncodedKeys values as allocated by `zcashlc_derive_unified_viewing_keys_from_seed`
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`FFIEncodedKeys`].
///   See the safety documentation of [`FFIEncodedKeys`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_keys(ptr: *mut FFIEncodedKeys) {
    if !ptr.is_null() {
        let s: Box<FFIEncodedKeys> = unsafe { Box::from_raw(ptr) };

        let slice: &mut [FFIEncodedKey] = unsafe { slice::from_raw_parts_mut(s.ptr, s.len) };
        for k in slice.iter_mut() {
            unsafe { zcashlc_string_free(k.encoding) }
        }
        drop(s);
    }
}

/// Derives and returns a unified spending key from the given seed for the given account ID.
///
/// Returns the binary encoding of the spending key. The caller should manage the memory of (and
/// store, if necessary) the returned spending key in a secure fashion.
///
/// # Safety
///
/// - `seed` must be non-null and valid for reads for `seed_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `seed` must not be mutated for the duration of the function call.
/// - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
///   of pointer::offset.
/// - Call `zcashlc_free_binary_key` to free the memory associated with the returned pointer when
///   you are finished using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_derive_spending_key(
    seed: *const u8,
    seed_len: usize,
    account: i32,
    network_id: u32,
) -> *mut FFIBinaryKey {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let seed = unsafe { slice::from_raw_parts(seed, seed_len) };
        let account = if account >= 0 {
            account as u32
        } else {
            return Err(anyhow!("account ID argument must be nonnegative"));
        };

        let account = AccountId::from(account);
        UnifiedSpendingKey::from_seed(&network, seed, account)
            .map_err(|e| anyhow!("error generating unified spending key from seed: {:?}", e))
            .map(move |usk| {
                let encoded = usk.to_bytes(Era::Orchard);
                Box::into_raw(Box::new(FFIBinaryKey::new(account, encoded)))
            })
    });
    unwrap_exc_or_null(res)
}

/// A private utility function to reduce duplication across functions that take an USK
/// across the FFI. `usk_ptr` should point to an array of `usk_len` bytes containing
/// a unified spending key encoded as returned from the `zcashlc_create_account` or
/// `zcashlc_derive_spending_key` functions. Callers should reproduce the following
/// safety documentation.
///
/// # Safety
///
/// - `usk_ptr` must be non-null and must point to an array of `usk_len` bytes.
/// - The memory referenced by `usk_ptr` must not be mutated for the duration of the function call.
/// - The total size `usk_len` must be no larger than `isize::MAX`. See the safety documentation
///   of pointer::offset.
unsafe fn decode_usk(usk_ptr: *const u8, usk_len: usize) -> anyhow::Result<UnifiedSpendingKey> {
    let usk_bytes = unsafe { slice::from_raw_parts(usk_ptr, usk_len) };

    // The remainder of the function is safe.
    UnifiedSpendingKey::from_bytes(Era::Orchard, usk_bytes).map_err(|e| match e {
        DecodingError::EraMismatch(era) => anyhow!(
            "Spending key was from era {:?}, but {:?} was expected.",
            era,
            Era::Orchard
        ),
        e => anyhow!(
            "An error occurred decoding the provided unified spending key: {:?}",
            e
        ),
    })
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
///   of pointer::offset.
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

/// Returns the most-recently-generated unified payment address for the specified account.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
///   when done using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_get_current_address(
    db_data: *const u8,
    db_data_len: usize,
    account: i32,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let account = if account >= 0 {
            account as u32
        } else {
            return Err(anyhow!("accounts argument must be positive"));
        };

        let account = AccountId::from(account);

        match db_data.get_current_address(account) {
            Ok(Some(ua)) => {
                let address_str = ua.encode(&network);
                Ok(CString::new(address_str).unwrap().into_raw())
            }
            Ok(None) => Err(anyhow!(
                "No payment address was available for account {:?}",
                account
            )),
            Err(e) => Err(anyhow!("Error while fetching address: {}", e)),
        }
    });
    unwrap_exc_or_null(res)
}

/// Returns a newly-generated unified payment address for the specified account, with the next
/// available diversifier.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
///   when done using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_get_next_available_address(
    db_data: *const u8,
    db_data_len: usize,
    account: i32,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let account = if account >= 0 {
            account as u32
        } else {
            return Err(anyhow!("Account id must be nonnegative."));
        };

        let account = AccountId::from(account);

        match db_data.get_next_available_address(account) {
            Ok(Some(ua)) => {
                let address_str = ua.encode(&network);
                Ok(CString::new(address_str).unwrap().into_raw())
            }
            Ok(None) => Err(anyhow!(
                "No payment address was available for account {:?}",
                account
            )),
            Err(e) => Err(anyhow!("Error while fetching address: {}", e)),
        }
    });
    unwrap_exc_or_null(res)
}

/// Returns a list of the transparent receivers for the diversified unified addresses that have
/// been allocated for the provided account.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Call [`zcashlc_free_keys`] to free the memory associated with the returned pointer
///   when done using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_list_transparent_receivers(
    db_data: *const u8,
    db_data_len: usize,
    account_id: i32,
    network_id: u32,
) -> *mut FFIEncodedKeys {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let account_id = if account_id >= 0 {
            account_id as u32
        } else {
            return Err(anyhow!("Account id must be nonnegative."));
        };

        let account = AccountId::from(account_id);
        match db_data.get_transparent_receivers(account) {
            Ok(receivers) => {
                let keys = receivers
                    .keys()
                    .map(|receiver| {
                        let address_str = receiver.encode(&network);
                        FFIEncodedKey {
                            account_id,
                            encoding: CString::new(address_str).unwrap().into_raw(),
                        }
                    })
                    .collect::<Vec<_>>();

                Ok(FFIEncodedKeys::ptr_from_vec(keys))
            }
            Err(e) => Err(anyhow!("Error while fetching transparent receivers: {}", e)),
        }
    });
    unwrap_exc_or_null(res)
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
/// - `ua` must be non-null and must point to a null-terminated UTF-8 string containing an
///   encoded Unified Address.
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
    if !data.is_null() {
        let s = unsafe { Box::from_raw(slice::from_raw_parts_mut(data, len)) };
        drop(s);
    }
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

/// Returns the transparent receiver within the given Unified Address, if any.
///
/// # Safety
///
/// - `ua` must be non-null and must point to a null-terminated UTF-8 string.
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
                TransparentAddress::PublicKey(data) => {
                    ZcashAddress::from_transparent_p2pkh(network, *data)
                }
                TransparentAddress::Script(data) => {
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

/// Returns true when the provided address decodes to a valid Sapling payment address for the
/// specified network, false in any other case.
///
/// # Safety
///
/// - `address` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `address` must not be mutated for the duration of the function call.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_is_valid_shielded_address(
    address: *const c_char,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let addr = unsafe { CStr::from_ptr(address).to_str()? };
        Ok(is_valid_shielded_address(addr, &network))
    });
    unwrap_exc_or(res, false)
}

fn is_valid_shielded_address(address: &str, network: &Network) -> bool {
    match RecipientAddress::decode(network, address) {
        Some(addr) => match addr {
            RecipientAddress::Shielded(_) => true,
            RecipientAddress::Transparent(_) | RecipientAddress::Unified(_) => false,
        },
        None => false,
    }
}

enum AddressType {
    Sprout,
    P2pkh,
    P2sh,
    Sapling,
    Unified,
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
}

/// Returns the network type and address kind for the given address string,
/// if the address is a valid Zcash address.
///
/// Address kind codes are as follows:
/// * p2pkh: 0
/// * p2sh: 1
/// * sapling: 2
/// * unified: 3
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
                AddressType::Sprout => {
                    return Err(anyhow!("Sprout addresses are not supported."));
                }
            };
        }

        Ok(true)
    });
    unwrap_exc_or(res, false)
}

/// Returns true when the address is a valid transparent payment address for the specified network,
/// false in any other case.
///
/// # Safety
///
/// - `address` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `address` must not be mutated for the duration of the function call.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_is_valid_transparent_address(
    address: *const c_char,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let addr = unsafe { CStr::from_ptr(address).to_str()? };
        Ok(is_valid_transparent_address(addr, &network))
    });
    unwrap_exc_or(res, false)
}

fn is_valid_transparent_address(address: &str, network: &Network) -> bool {
    match RecipientAddress::decode(network, address) {
        Some(addr) => match addr {
            RecipientAddress::Shielded(_) | RecipientAddress::Unified(_) => false,
            RecipientAddress::Transparent(_) => true,
        },
        None => false,
    }
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

/// Returns true when the provided key decodes to a valid unified address for the
/// specified network, false in any other case.
///
/// # Safety
///
/// - `address` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `address` must not be mutated for the duration of the
///   function call.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_is_valid_unified_address(
    address: *const c_char,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let addr = unsafe { CStr::from_ptr(address).to_str()? };
        Ok(is_valid_unified_address(addr, &network))
    });
    unwrap_exc_or(res, false)
}

fn is_valid_unified_address(address: &str, network: &Network) -> bool {
    match RecipientAddress::decode(network, address) {
        Some(addr) => match addr {
            RecipientAddress::Unified(_) => true,
            RecipientAddress::Shielded(_) | RecipientAddress::Transparent(_) => false,
        },
        None => false,
    }
}

/// Returns the balance for the specified account, including all unspent notes that we know about.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_get_balance(
    db_data: *const u8,
    db_data_len: usize,
    account: i32,
    network_id: u32,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let account = AccountId::from(
            u32::try_from(account).map_err(|_| anyhow!("account argument must be positive"))?,
        );

        if let Some(wallet_summary) = db_data.get_wallet_summary(0)? {
            wallet_summary
                .account_balances()
                .get(&account)
                .ok_or_else(|| anyhow!("Unknown account"))
                .map(|balances| Amount::from(balances.sapling_balance.total()).into())
        } else {
            // `None` means that the caller has not yet called `updateChainTip` on a
            // brand-new wallet, so we can assume the balance is zero.
            Ok(0)
        }
    });
    unwrap_exc_or(res, -1)
}

/// Returns the verified balance for the account, which ignores notes that have been
/// received too recently and are not yet deemed spendable according to `min_confirmations`.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_get_verified_balance(
    db_data: *const u8,
    db_data_len: usize,
    account: i32,
    network_id: u32,
    min_confirmations: u32,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let account = AccountId::from(
            u32::try_from(account).map_err(|_| anyhow!("account argument must be positive"))?,
        );

        if let Some(wallet_summary) = db_data.get_wallet_summary(min_confirmations)? {
            wallet_summary
                .account_balances()
                .get(&account)
                .ok_or_else(|| anyhow!("Unknown account"))
                .map(|balances| Amount::from(balances.sapling_balance.spendable_value).into())
        } else {
            // `None` means that the caller has not yet called `updateChainTip` on a
            // brand-new wallet, so we can assume the balance is zero.
            Ok(0)
        }
    });
    unwrap_exc_or(res, -1)
}

/// Returns the verified transparent balance for `address`, which ignores utxos that have been
/// received too recently and are not yet deemed spendable according to `min_confirmations`.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `address` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `address` must not be mutated for the duration of the function call.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_get_verified_transparent_balance(
    db_data: *const u8,
    db_data_len: usize,
    address: *const c_char,
    network_id: u32,
    min_confirmations: u32,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let min_confirmations = NonZeroU32::new(min_confirmations)
            .ok_or(anyhow!("min_confirmations should be non-zero"))?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let addr = unsafe { CStr::from_ptr(address).to_str()? };
        let taddr = TransparentAddress::decode(&network, addr).unwrap();
        let amount = db_data
            .get_target_and_anchor_heights(min_confirmations)
            .map_err(|e| anyhow!("Error while fetching anchor height: {}", e))
            .and_then(|opt_anchor| {
                opt_anchor
                    .map(|(_, a)| a)
                    .ok_or_else(|| anyhow!("height not available; scan required."))
            })
            .and_then(|anchor| {
                db_data
                    .get_unspent_transparent_outputs(&taddr, anchor, &[])
                    .map_err(|e| {
                        anyhow!("Error while fetching verified transparent balance: {}", e)
                    })
            })?
            .iter()
            .map(|utxo| utxo.txout().value)
            .sum::<Option<Amount>>()
            .ok_or_else(|| anyhow!("Balance overflowed MAX_MONEY."))?;

        Ok(amount.into())
    });
    unwrap_exc_or(res, -1)
}

/// Returns the verified transparent balance for `account`, which ignores utxos that have been
/// received too recently and are not yet deemed spendable according to `min_confirmations`.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `address` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `address` must not be mutated for the duration of the function call.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_get_verified_transparent_balance_for_account(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
    account: i32,
    min_confirmations: u32,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let min_confirmations = NonZeroU32::new(min_confirmations)
            .ok_or(anyhow!("min_confirmations should be non-zero"))?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let account = if account >= 0 {
            AccountId::from(account as u32)
        } else {
            return Err(anyhow!("account argument must be positive"));
        };
        let amount = db_data
            .get_target_and_anchor_heights(min_confirmations)
            .map_err(|e| anyhow!("Error while fetching anchor height: {}", e))
            .and_then(|opt_anchor| {
                opt_anchor
                    .map(|(_, a)| a)
                    .ok_or_else(|| anyhow!("height not available; scan required."))
            })
            .and_then(|anchor| {
                db_data
                    .get_transparent_receivers(account)
                    .map_err(|e| {
                        anyhow!(
                            "Error while fetching transparent receivers for {:?}: {}",
                            account,
                            e,
                        )
                    })
                    .and_then(|receivers| {
                        receivers
                            .keys()
                            .map(|taddr| {
                                db_data
                                    .get_unspent_transparent_outputs(taddr, anchor, &[])
                                    .map_err(|e| {
                                        anyhow!(
                                            "Error while fetching verified transparent balance: {}",
                                            e
                                        )
                                    })
                            })
                            .collect::<Result<Vec<_>, _>>()
                    })
            })?
            .iter()
            .flatten()
            .map(|utxo| utxo.txout().value)
            .sum::<Option<Amount>>()
            .ok_or_else(|| anyhow!("Balance overflowed MAX_MONEY."))?;

        Ok(amount.into())
    });
    unwrap_exc_or(res, -1)
}

/// Returns the balance for `address`, including all UTXOs that we know about.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `address` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `address` must not be mutated for the duration of the function call.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_get_total_transparent_balance(
    db_data: *const u8,
    db_data_len: usize,
    address: *const c_char,
    network_id: u32,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let addr = unsafe { CStr::from_ptr(address).to_str()? };
        let taddr = TransparentAddress::decode(&network, addr).unwrap();
        let amount = db_data
            .get_target_and_anchor_heights(NonZeroU32::MIN)
            .map_err(|e| anyhow!("Error while fetching anchor height: {}", e))
            .and_then(|opt_anchor| {
                opt_anchor
                    .map(|(target, _)| target) // Include unconfirmed funds.
                    .ok_or_else(|| anyhow!("height not available; scan required."))
            })
            .and_then(|anchor| {
                db_data
                    .get_unspent_transparent_outputs(&taddr, anchor, &[])
                    .map_err(|e| anyhow!("Error while fetching total transparent balance: {}", e))
            })?
            .iter()
            .map(|utxo| utxo.txout().value)
            .sum::<Option<Amount>>()
            .ok_or_else(|| anyhow!("Balance overflowed MAX_MONEY."))?;

        Ok(amount.into())
    });
    unwrap_exc_or(res, -1)
}

/// Returns the balance for `account`, including all UTXOs that we know about.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `address` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `address` must not be mutated for the duration of the function call.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_get_total_transparent_balance_for_account(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
    account: i32,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let account = if account >= 0 {
            AccountId::from(account as u32)
        } else {
            return Err(anyhow!("account argument must be positive"));
        };
        let amount = db_data
            .get_target_and_anchor_heights(NonZeroU32::MIN)
            .map_err(|e| anyhow!("Error while fetching anchor height: {}", e))
            .and_then(|opt_anchor| {
                opt_anchor
                    .map(|(target, _)| target) // Include unconfirmed funds.
                    .ok_or_else(|| anyhow!("height not available; scan required."))
            })
            .and_then(|anchor| {
                db_data
                    .get_transparent_balances(account, anchor)
                    .map_err(|e| {
                        anyhow!(
                            "Error while fetching transparent balances for {:?}: {}",
                            account,
                            e,
                        )
                    })
            })?
            .values()
            .sum::<Option<Amount>>()
            .ok_or_else(|| anyhow!("Balance overflowed MAX_MONEY."))?;

        Ok(amount.into())
    });
    unwrap_exc_or(res, -1)
}

/// Returns the memo for a note by copying the corresponding bytes to the received
/// pointer in `memo_bytes_ret`.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `txid_bytes` must be non-null and valid for reads for 32 bytes, and it must have an alignment
///   of `1`.
/// - `memo_bytes_ret` must be non-null and must point to an allocated 512-byte region of memory.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_get_memo(
    db_data: *const u8,
    db_data_len: usize,
    txid_bytes: *const u8,
    output_index: u16,
    memo_bytes_ret: *mut u8,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let txid_bytes = unsafe { slice::from_raw_parts(txid_bytes, 32) };
        let txid = TxId::read(&txid_bytes[..])?;

        let memo_bytes = db_data
            .get_memo(NoteId::new(txid, ShieldedProtocol::Sapling, output_index))
            .map_err(|e| anyhow!("An error occurred retrieving the memo: {}", e))
            .and_then(|memo| memo.ok_or(anyhow!("Memo not available")))
            .map(|memo| memo.encode())?;

        unsafe { memo_bytes_ret.copy_from(memo_bytes.as_slice().as_ptr(), 512) };
        Ok(true)
    });
    unwrap_exc_or(res, false)
}

/// Returns the memo for a note, if it is known and a valid UTF-8 string.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `txid_bytes` must be non-null and valid for reads for 32 bytes, and it must have an alignment
///   of `1`.
/// - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
///   when done using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_get_memo_as_utf8(
    db_data: *const u8,
    db_data_len: usize,
    txid_bytes: *const u8,
    output_index: u16,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let txid_bytes = unsafe { slice::from_raw_parts(txid_bytes, 32) };
        let txid = TxId::read(&txid_bytes[..])?;

        let memo = db_data
            .get_memo(NoteId::new(txid, ShieldedProtocol::Sapling, output_index))
            .map_err(|e| anyhow!("An error occurred retrieving the memo: {}", e))
            .and_then(|memo| match memo {
                Some(Memo::Empty) => Ok("".to_string()),
                Some(Memo::Text(memo)) => Ok(memo.into()),
                None => Err(anyhow!("Memo not available")),
                _ => Err(anyhow!("This memo does not contain UTF-8 text")),
            })?;

        Ok(CString::new(memo).unwrap().into_raw())
    });
    unwrap_exc_or_null(res)
}

#[no_mangle]
/// Returns a ZIP-32 signature of the given seed bytes.
///
/// # Safety
/// - `seed` must be non-null and valid for reads for `seed_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `seed` must not be mutated for the duration of the function call.
/// - The total size `seed_len` must be at least 32 no larger than `252`. See the safety documentation
///   of pointer::offset.
// - `signature_bytes_ret` must be non-null and must point to an allocated 32-byte region of memory.
pub unsafe extern "C" fn zcashlc_seed_fingerprint(
    seed: *const u8,
    seed_len: usize,
    signature_bytes_ret: *mut u8,
) -> bool {
    let res = catch_panic(|| {
        if !(32..=252).contains(&seed_len) {
            return Err(anyhow!("Seed must be between 32 and 252 bytes long"));
        }

        let seed = Secret::new((unsafe { slice::from_raw_parts(seed, seed_len) }).to_vec());

        use secrecy::ExposeSecret;

        let signature = match SeedFingerprint::from_seed(seed.expose_secret()) {
            Some(fp) => fp,

            None => return Err(anyhow!("Could not create fingerprint")),
        };

        unsafe { signature_bytes_ret.copy_from(signature.to_bytes().as_ptr(), 32) }

        Ok(true)
    });
    unwrap_exc_or(res, false)
}

/// Returns the most recent block height to which it is possible to reset the state
/// of the data database.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_get_nearest_rewind_height(
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
            let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
            let height = BlockHeight::try_from(height)?;

            match db_data.get_min_unspent_height() {
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
                Err(e) => Err(anyhow!(
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
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_rewind_to_height(
    db_data: *const u8,
    db_data_len: usize,
    height: i32,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let height = BlockHeight::try_from(height)?;
        db_data
            .truncate_to_height(height)
            .map(|_| true)
            .map_err(|e| anyhow!("Error while rewinding data DB to height {}: {}", height, e))
    });
    unwrap_exc_or(res, false)
}

/// A struct that contains a subtree root.
///
/// # Safety
///
/// - `root_hash_ptr` must be non-null and must be valid for reads for `root_hash_ptr_len`
///   bytes, and it must have an alignment of `1`.
/// - The total size `root_hash_ptr_len` of the slice pointed to by `root_hash_ptr` must
///   be no larger than `isize::MAX`. See the safety documentation of `pointer::offset`.
#[repr(C)]
pub struct FfiSubtreeRoot {
    root_hash_ptr: *mut u8,
    root_hash_ptr_len: usize,
    completing_block_height: u32,
}

/// A struct that contains a pointer to, and length information for, a heap-allocated
/// slice of [`FfiSubtreeRoot`] values.
///
/// # Safety
///
/// - `ptr` must be non-null and must be valid for reads for `len * mem::size_of::<FfiSubtreeRoot>()`
///   many bytes, and it must be properly aligned. This means in particular:
///   - The entire memory range pointed to by `ptr` must be contained within a single
///     allocated object. Slices can never span across multiple allocated objects.
///   - `ptr` must be non-null and aligned even for zero-length slices.
///   - `ptr` must point to `len` consecutive properly initialized values of type
///     [`FfiSubtreeRoot`].
/// - The total size `len * mem::size_of::<FfiSubtreeRoot>()` of the slice pointed to
///   by `ptr` must be no larger than isize::MAX. See the safety documentation of
///   `pointer::offset`.
/// - See the safety documentation of [`FfiSubtreeRoot`]
#[repr(C)]
pub struct FfiSubtreeRoots {
    ptr: *mut FfiSubtreeRoot,
    len: usize, // number of elems
}

/// Adds a sequence of Sapling subtree roots to the data store.
///
/// Returns true if the subtrees could be stored, false otherwise. When false is returned,
/// caller should check for errors.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of `pointer::offset`.
/// - `roots` must be non-null and initialized.
/// - The memory referenced by `roots` must not be mutated for the duration of the function call.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_put_sapling_subtree_roots(
    db_data: *const u8,
    db_data_len: usize,
    start_index: u64,
    roots: *const FfiSubtreeRoots,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let roots = unsafe { roots.as_ref().unwrap() };
        let roots_slice: &[FfiSubtreeRoot] = unsafe { slice::from_raw_parts(roots.ptr, roots.len) };

        let roots = roots_slice
            .iter()
            .map(|r| {
                let root_hash_bytes =
                    unsafe { slice::from_raw_parts(r.root_hash_ptr, r.root_hash_ptr_len) };
                let root_hash = sapling::Node::read(root_hash_bytes)?;

                Ok(CommitmentTreeRoot::from_parts(
                    BlockHeight::from_u32(r.completing_block_height),
                    root_hash,
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        db_data
            .put_sapling_subtree_roots(start_index, &roots)
            .map(|()| true)
            .map_err(|e| anyhow!("Error while storing Sapling subtree roots: {}", e))
    });
    unwrap_exc_or(res, false)
}

/// Updates the wallet's view of the blockchain.
///
/// This method is used to provide the wallet with information about the state of the blockchain,
/// and detect any previously scanned data that needs to be re-validated before proceeding with
/// scanning. It should be called at wallet startup prior to calling `zcashlc_suggest_scan_ranges`
/// in order to provide the wallet with the information it needs to correctly prioritize scanning
/// operations.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of `pointer::offset`.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_update_chain_tip(
    db_data: *const u8,
    db_data_len: usize,
    height: i32,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let height = BlockHeight::try_from(height)?;

        db_data
            .update_chain_tip(height)
            .map(|_| true)
            .map_err(|e| anyhow!("Error while updating chain tip to height {}: {}", height, e))
    });
    unwrap_exc_or(res, false)
}

/// Returns the height to which the wallet has been fully scanned.
///
/// This is the height for which the wallet has fully trial-decrypted this and all
/// preceding blocks above the wallet's birthday height.
///
/// Returns a non-negative block height, -1 if empty, or -2 if an error occurred.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of `pointer::offset`.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_fully_scanned_height(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        match db_data.block_fully_scanned() {
            Ok(Some(metadata)) => Ok(i64::from(u32::from(metadata.block_height()))),
            Ok(None) => Ok(-1),
            Err(e) => Err(anyhow!(
                "Failed to read block metadata from WalletDb: {:?}",
                e
            )),
        }
    });

    unwrap_exc_or(res, -2)
}

/// Returns the maximum height that the wallet has scanned.
///
/// If the wallet is fully synced, this will be equivalent to `zcashlc_block_fully_scanned`;
/// otherwise the maximal scanned height is likely to be greater than the fully scanned
/// height due to the fact that out-of-order scanning can leave gaps.
///
/// Returns a non-negative block height, -1 if empty, or -2 if an error occurred.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of `pointer::offset`.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_max_scanned_height(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        match db_data.block_max_scanned() {
            Ok(Some(metadata)) => Ok(i64::from(u32::from(metadata.block_height()))),
            Ok(None) => Ok(-1),
            Err(e) => Err(anyhow!(
                "Failed to read block metadata from WalletDb: {:?}",
                e
            )),
        }
    });

    unwrap_exc_or(res, -2)
}

/// A struct that contains details about scan progress.
///
/// When `denominator` is zero, the numerator encodes a non-progress indicator:
/// - 0: progress is unknown.
/// - 1: an error occurred.
#[repr(C)]
pub struct FfiScanProgress {
    numerator: u64,
    denominator: u64,
}

/// Returns the scan progress derived from the current wallet state.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must
///   have an alignment of `1`. Its contents must be a string representing a valid system
///   path in the operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the
///   function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_get_scan_progress(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
) -> FfiScanProgress {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let progress = match db_data
            .get_wallet_summary(0)
            .map_err(|e| anyhow!("Error while fetching suggested scan ranges: {}", e))?
            .and_then(|wallet_summary| wallet_summary.scan_progress())
        {
            Some(progress) => FfiScanProgress {
                numerator: *progress.numerator(),
                denominator: *progress.denominator(),
            },
            None => FfiScanProgress {
                numerator: 0,
                denominator: 0,
            },
        };

        Ok(progress)
    });
    unwrap_exc_or(
        res,
        FfiScanProgress {
            numerator: 1,
            denominator: 0,
        },
    )
}

/// A struct that contains the start (inclusive) and end (exclusive) of a range of blocks
/// to scan.
#[repr(C)]
pub struct FfiScanRange {
    start: i32,
    end: i32,
    priority: u8,
}

/// A struct that contains a pointer to, and length information for, a heap-allocated
/// slice of [`FfiScanRange`] values.
///
/// # Safety
///
/// - `ptr` must be non-null and must be valid for reads for `len * mem::size_of::<FfiScanRange>()`
///   many bytes, and it must be properly aligned. This means in particular:
///   - The entire memory range pointed to by `ptr` must be contained within a single
///     allocated object. Slices can never span across multiple allocated objects.
///   - `ptr` must be non-null and aligned even for zero-length slices.
///   - `ptr` must point to `len` consecutive properly initialized values of type
///     [`FfiScanRange`].
/// - The total size `len * mem::size_of::<FfiScanRange>()` of the slice pointed to
///   by `ptr` must be no larger than isize::MAX. See the safety documentation of
///   `pointer::offset`.
#[repr(C)]
pub struct FfiScanRanges {
    ptr: *mut FfiScanRange,
    len: usize, // number of elems
}

impl FfiScanRanges {
    pub fn ptr_from_vec(v: Vec<FfiScanRange>) -> *mut Self {
        // Going from Vec<_> to Box<[_]> just drops the (extra) `capacity`
        let boxed_slice: Box<[FfiScanRange]> = v.into_boxed_slice();
        let len = boxed_slice.len();
        let fat_ptr: *mut [FfiScanRange] = Box::into_raw(boxed_slice);
        // It is guaranteed to be possible to obtain a raw pointer to the start
        // of a slice by casting the pointer-to-slice, as documented e.g. at
        // <https://doc.rust-lang.org/std/primitive.pointer.html#method.as_mut_ptr>.
        // TODO: replace with `as_mut_ptr()` when that is stable.
        let slim_ptr: *mut FfiScanRange = fat_ptr as _;
        Box::into_raw(Box::new(FfiScanRanges { ptr: slim_ptr, len }))
    }
}

/// Frees an array of FfiScanRanges values as allocated by `zcashlc_derive_unified_viewing_keys_from_seed`
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`FfiScanRanges`].
///   See the safety documentation of [`FfiScanRanges`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_scan_ranges(ptr: *mut FfiScanRanges) {
    if !ptr.is_null() {
        let s: Box<FfiScanRanges> = unsafe { Box::from_raw(ptr) };
        let slice: &mut [FfiScanRange] = unsafe { slice::from_raw_parts_mut(s.ptr, s.len) };
        let boxed_slice = unsafe { Box::from_raw(slice) };
        drop(boxed_slice);
        drop(s);
    }
}

/// Returns a list of suggested scan ranges based upon the current wallet state.
///
/// This method should only be used in cases where the `CompactBlock` data that will be
/// made available to `zcashlc_scan_blocks` for the requested block ranges includes note
/// commitment tree size information for each block; or else the scan is likely to fail if
/// notes belonging to the wallet are detected.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must
///   have an alignment of `1`. Its contents must be a string representing a valid system
///   path in the operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the
///   function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Call [`zcashlc_free_scan_ranges`] to free the memory associated with the returned
///   pointer when done using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_suggest_scan_ranges(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
) -> *mut FfiScanRanges {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let ranges = db_data
            .suggest_scan_ranges()
            .map_err(|e| anyhow!("Error while fetching suggested scan ranges: {}", e))?;

        let ffi_ranges = ranges
            .into_iter()
            .map(|scan_range| FfiScanRange {
                start: u32::from(scan_range.block_range().start) as i32,
                end: u32::from(scan_range.block_range().end) as i32,
                priority: match scan_range.priority() {
                    ScanPriority::Ignored => 0,
                    ScanPriority::Scanned => 10,
                    ScanPriority::Historic => 20,
                    ScanPriority::OpenAdjacent => 30,
                    ScanPriority::FoundNote => 40,
                    ScanPriority::ChainTip => 50,
                    ScanPriority::Verify => 60,
                },
            })
            .collect::<Vec<_>>();

        Ok(FfiScanRanges::ptr_from_vec(ffi_ranges))
    });
    unwrap_exc_or_null(res)
}

/// Scans new blocks added to the cache for any transactions received by the tracked
/// accounts, while checking that they form a valid chan.
///
/// This function is built on the core assumption that the information provided in the
/// block cache is more likely to be accurate than the previously-scanned information.
/// This follows from the design (and trust) assumption that the `lightwalletd` server
/// provides accurate block information as of the time it was requested.
///
/// This function **assumes** that the caller is handling rollbacks.
///
/// For brand-new light client databases, this function starts scanning from the Sapling
/// activation height. This height can be fast-forwarded to a more recent block by calling
/// [`zcashlc_init_blocks_table`] before this function.
///
/// Scanned blocks are required to be height-sequential. If a block is missing from the
/// cache, an error will be signalled.
///
/// # Safety
///
/// - `fs_block_db_root` must be non-null and valid for reads for `fs_block_db_root_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `fs_block_db_root` must not be mutated for the duration of the function call.
/// - The total size `fs_block_db_root_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_scan_blocks(
    fs_block_cache_root: *const u8,
    fs_block_cache_root_len: usize,
    db_data: *const u8,
    db_data_len: usize,
    from_height: i32,
    scan_limit: u32,
    network_id: u32,
) -> i32 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let block_db = block_db(fs_block_cache_root, fs_block_cache_root_len)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let from_height = BlockHeight::try_from(from_height)?;
        let limit = usize::try_from(scan_limit)?;
        match scan_cached_blocks(&network, &block_db, &mut db_data, from_height, limit) {
            Ok(()) => Ok(1),
            Err(e) => Err(anyhow!("Error while scanning blocks: {}", e)),
        }
    });
    unwrap_exc_or_null(res)
}

/// Inserts a UTXO into the wallet database.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `txid_bytes` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `txid_bytes_len` must not be mutated for the duration of the function call.
/// - The total size `txid_bytes_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `script_bytes` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `script_bytes_len` must not be mutated for the duration of the function call.
/// - The total size `script_bytes_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_put_utxo(
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
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let txid_bytes = unsafe { slice::from_raw_parts(txid_bytes, txid_bytes_len) };
        let mut txid = [0u8; 32];
        txid.copy_from_slice(txid_bytes);

        let script_bytes = unsafe { slice::from_raw_parts(script_bytes, script_bytes_len) };
        let script_pubkey = legacy::Script(script_bytes.to_vec());

        let output = WalletTransparentOutput::from_parts(
            OutPoint::new(txid, index as u32),
            TxOut {
                value: Amount::from_i64(value).unwrap(),
                script_pubkey,
            },
            BlockHeight::from(height as u32),
        )
        .ok_or_else(|| {
            anyhow!(
                "{:?} is not a valid P2PKH or P2SH script_pubkey",
                script_bytes
            )
        })?;
        match db_data.put_received_transparent_utxo(&output) {
            Ok(_) => Ok(true),
            Err(e) => Err(anyhow!("Error while inserting UTXO: {}", e)),
        }
    });
    unwrap_exc_or(res, false)
}

//
// FsBlock Interfaces
//

#[repr(C)]
pub struct FFIBlocksMeta {
    ptr: *mut FFIBlockMeta,
    len: usize, // number of elems
}

impl FFIBlocksMeta {
    pub fn ptr_from_vec(v: Vec<FFIBlockMeta>) -> *mut Self {
        // Going from Vec<_> to Box<[_]> just drops the (extra) `capacity`
        let boxed_slice: Box<[FFIBlockMeta]> = v.into_boxed_slice();
        let len = boxed_slice.len();
        let fat_ptr: *mut [FFIBlockMeta] = Box::into_raw(boxed_slice);
        // It is guaranteed to be possible to obtain a raw pointer to the start
        // of a slice by casting the pointer-to-slice, as documented e.g. at
        // <https://doc.rust-lang.org/std/primitive.pointer.html#method.as_mut_ptr>.
        // TODO: replace with `as_mut_ptr()` when that is stable.
        let slim_ptr: *mut FFIBlockMeta = fat_ptr as _;
        Box::into_raw(Box::new(FFIBlocksMeta { ptr: slim_ptr, len }))
    }
}

#[repr(C)]
pub struct FFIBlockMeta {
    height: u32,
    block_hash_ptr: *mut u8,
    block_hash_ptr_len: usize,
    block_time: u32,
    sapling_outputs_count: u32,
    orchard_actions_count: u32,
}

/// # Safety
/// Initializes the `FsBlockDb` sqlite database. Does nothing if already created
///
/// Returns true when successful, false otherwise. When false is returned caller
/// should check for errors.
/// - `fs_block_db_root` must be non-null and valid for reads for `fs_block_db_root_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `fs_block_db_root` must not be mutated for the duration of the function call.
/// - The total size `fs_block_db_root_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_init_block_metadata_db(
    fs_block_db_root: *const u8,
    fs_block_db_root_len: usize,
) -> bool {
    let res = catch_panic(|| {
        let mut block_db = block_db(fs_block_db_root, fs_block_db_root_len)?;

        match init_blockmeta_db(&mut block_db) {
            Ok(()) => Ok(true),
            Err(e) => Err(anyhow!("Error while initializing block metadata DB: {}", e)),
        }
    });
    unwrap_exc_or(res, false)
}

/// Writes the blocks provided in `blocks_meta` into the `BlockMeta` database
///
/// Returns true if the `blocks_meta` could be stored into the `FsBlockDb`. False
/// otherwise.
///
/// When false is returned caller should check for errors.
///
/// # Safety
///
/// - `fs_block_db_root` must be non-null and valid for reads for `fs_block_db_root_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `fs_block_db_root` must not be mutated for the duration of the function call.
/// - The total size `fs_block_db_root_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Block metadata represented in `blocks_meta` must be non-null. Caller must guarantee that the
/// memory reference by this pointer is not freed up, dereferenced or invalidated while this function
/// is invoked.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_write_block_metadata(
    fs_block_db_root: *const u8,
    fs_block_db_root_len: usize,
    blocks_meta: *mut FFIBlocksMeta,
) -> bool {
    let res = catch_panic(|| {
        let block_db = block_db(fs_block_db_root, fs_block_db_root_len)?;

        let blocks_meta: Box<FFIBlocksMeta> = unsafe { Box::from_raw(blocks_meta) };

        let blocks_metadata_slice: &mut [FFIBlockMeta] =
            unsafe { slice::from_raw_parts_mut(blocks_meta.ptr, blocks_meta.len) };

        let mut blocks = Vec::with_capacity(blocks_metadata_slice.len());

        for b in blocks_metadata_slice {
            let block_hash_bytes =
                unsafe { slice::from_raw_parts(b.block_hash_ptr, b.block_hash_ptr_len) };
            let mut hash = [0u8; 32];
            hash.copy_from_slice(block_hash_bytes);

            blocks.push(BlockMeta {
                height: BlockHeight::from_u32(b.height),
                block_hash: BlockHash(hash),
                block_time: b.block_time,
                sapling_outputs_count: b.sapling_outputs_count,
                orchard_actions_count: b.orchard_actions_count,
            });
        }

        match block_db.write_block_metadata(&blocks) {
            Ok(()) => Ok(true),
            Err(e) => Err(anyhow!(
                "Failed to write block metadata to FsBlockDb: {:?}",
                e
            )),
        }
    });
    unwrap_exc_or(res, false)
}

/// Rewinds the data database to the given height.
///
/// If the requested height is greater than or equal to the height of the last scanned
/// block, this function does nothing.
///
/// # Safety
///
/// - `fs_block_db_root` must be non-null and valid for reads for `fs_block_db_root_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `fs_block_db_root` must not be mutated for the duration of the function call.
/// - The total size `fs_block_db_root_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_rewind_fs_block_cache_to_height(
    fs_block_db_root: *const u8,
    fs_block_db_root_len: usize,
    height: i32,
) -> bool {
    let res = catch_panic(|| {
        let block_db = block_db(fs_block_db_root, fs_block_db_root_len)?;
        let height = BlockHeight::try_from(height)?;
        block_db
            .truncate_to_height(height)
            .map(|_| true)
            .map_err(|e| anyhow!("Error while rewinding data DB to height {}: {}", height, e))
    });
    unwrap_exc_or(res, false)
}

/// Get the latest cached block height in the filesystem block cache
///
/// Returns a non-negative block height, -1 if empty, or -2 if an error occurred.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `tx` must be non-null and valid for reads for `tx_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `tx` must not be mutated for the duration of the function call.
/// - The total size `tx_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_latest_cached_block_height(
    fs_block_db_root: *const u8,
    fs_block_db_root_len: usize,
) -> i32 {
    let res = catch_panic(|| {
        let block_db = block_db(fs_block_db_root, fs_block_db_root_len)?;

        match block_db.get_max_cached_height() {
            Ok(Some(block_height)) => Ok(u32::from(block_height) as i32),
            Ok(None) => Ok(-1),
            Err(e) => Err(anyhow!(
                "Failed to read block metadata from FsBlockDb: {:?}",
                e
            )),
        }
    });

    unwrap_exc_or(res, -2)
}

/// Decrypts whatever parts of the specified transaction it can and stores them in db_data.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `tx` must be non-null and valid for reads for `tx_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `tx` must not be mutated for the duration of the function call.
/// - The total size `tx_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_decrypt_and_store_transaction(
    db_data: *const u8,
    db_data_len: usize,
    tx: *const u8,
    tx_len: usize,
    _mined_height: u32,
    network_id: u32,
) -> i32 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let tx_bytes = unsafe { slice::from_raw_parts(tx, tx_len) };

        // The consensus branch ID passed in here does not matter:
        // - v4 and below cache it internally, but all we do with this transaction while
        //   it is in memory is decryption and serialization, neither of which use the
        //   consensus branch ID.
        // - v5 and above transactions ignore the argument, and parse the correct value
        //   from their encoding.
        let tx = Transaction::read(tx_bytes, BranchId::Sapling)?;

        match decrypt_and_store_transaction(&network, &mut db_data, &tx) {
            Ok(()) => Ok(1),
            Err(e) => Err(anyhow!("Error while decrypting transaction: {}", e)),
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
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `usk_ptr` must be non-null and must point to an array of `usk_len` bytes containing a unified
///   spending key encoded as returned from the `zcashlc_create_account` or
///   `zcashlc_derive_spending_key` functions.
/// - The memory referenced by `usk_ptr` must not be mutated for the duration of the function call.
/// - The total size `usk_len` must be no larger than `isize::MAX`. See the safety documentation
///   of pointer::offset.
/// - `to` must be non-null and must point to a null-terminated UTF-8 string.
/// - `memo` must either be null (indicating an empty memo or a transparent recipient) or point to a
///    512-byte array.
/// - `spend_params` must be non-null and valid for reads for `spend_params_len` bytes, and it must have an
///   alignment of `1`. Its contents must be the Sapling spend proving parameters.
/// - The memory referenced by `spend_params` must not be mutated for the duration of the function call.
/// - The total size `spend_params_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `output_params` must be non-null and valid for reads for `output_params_len` bytes, and it must have an
///   alignment of `1`. Its contents must be the Sapling output proving parameters.
/// - The memory referenced by `output_params` must not be mutated for the duration of the function call.
/// - The total size `output_params_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `txid_bytes_ret` must be non-null and must point to an allocated 32-byte region of memory.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_create_to_address(
    db_data: *const u8,
    db_data_len: usize,
    usk_ptr: *const u8,
    usk_len: usize,
    to: *const c_char,
    value: i64,
    memo: *const u8,
    spend_params: *const u8,
    spend_params_len: usize,
    output_params: *const u8,
    output_params_len: usize,
    network_id: u32,
    min_confirmations: u32,
    use_zip317_fees: bool,
    txid_bytes_ret: *mut u8,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let min_confirmations = NonZeroU32::new(min_confirmations)
            .ok_or(anyhow!("min_confirmations should be non-zero"))?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let usk = unsafe { decode_usk(usk_ptr, usk_len) }?;
        let to = unsafe { CStr::from_ptr(to) }.to_str()?;
        let value =
            Amount::from_i64(value).map_err(|()| anyhow!("Invalid amount, out of range"))?;
        if value.is_negative() {
            return Err(anyhow!("Amount is negative"));
        }
        let spend_params = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(spend_params, spend_params_len)
        }));
        let output_params = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(output_params, output_params_len)
        }));

        let to = RecipientAddress::decode(&network, to)
            .ok_or_else(|| anyhow!("PaymentAddress is for the wrong network"))?;

        let memo = match to {
            RecipientAddress::Shielded(_) | RecipientAddress::Unified(_) => {
                if memo.is_null() {
                    Ok(None)
                } else {
                    MemoBytes::from_bytes(unsafe { slice::from_raw_parts(memo, 512) })
                        .map(Some)
                        .map_err(|e| anyhow!("Invalid MemoBytes: {}", e))
                }
            }
            RecipientAddress::Transparent(_) => {
                if memo.is_null() {
                    Ok(None)
                } else {
                    Err(anyhow!(
                        "Memos are not permitted when sending to transparent recipients."
                    ))
                }
            }
        }?;

        let prover = LocalTxProver::new(spend_params, output_params);

        let req = TransactionRequest::new(vec![Payment {
            recipient_address: to,
            amount: value,
            memo,
            label: None,
            message: None,
            other_params: vec![],
        }])
        .map_err(|e| anyhow!("Error creating transaction request: {:?}", e))?;

        let txid = if use_zip317_fees {
            let input_selector = GreedyInputSelector::new(
                zip317::SingleOutputChangeStrategy::new(Zip317FeeRule::standard()),
                DustOutputPolicy::default(),
            );

            spend(
                &mut db_data,
                &network,
                prover,
                &input_selector,
                &usk,
                req,
                OvkPolicy::Sender,
                min_confirmations,
            )
            .map_err(|e| anyhow!("Error while sending funds: {}", e))
        } else {
            #[allow(deprecated)]
            let input_selector = GreedyInputSelector::new(
                fixed::SingleOutputChangeStrategy::new(FixedFeeRule::standard()),
                DustOutputPolicy::default(),
            );

            spend(
                &mut db_data,
                &network,
                prover,
                &input_selector,
                &usk,
                req,
                OvkPolicy::Sender,
                min_confirmations,
            )
            .map_err(|e| anyhow!("Error while sending funds: {}", e))
        }?;

        let txid_bytes = unsafe { slice::from_raw_parts_mut(txid_bytes_ret, 32) };
        txid.write(txid_bytes)?;

        Ok(true)
    });
    unwrap_exc_or(res, false)
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
///
/// # Safety
///
/// - `s` should be a non-null pointer returned as a string by another zcashlc function.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub unsafe extern "C" fn zcashlc_string_free(s: *mut c_char) {
    if !s.is_null() {
        let s = unsafe { CString::from_raw(s) };
        drop(s);
    }
}

/// Shield transparent UTXOs by sending them to an address associated with the specified Sapling
/// spending key.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `usk_ptr` must be non-null and must point to an array of `usk_len` bytes containing a unified
///   spending key encoded as returned from the `zcashlc_create_account` or
///   `zcashlc_derive_spending_key` functions.
/// - The memory referenced by `usk_ptr` must not be mutated for the duration of the function call.
/// - The total size `usk_len` must be no larger than `isize::MAX`. See the safety documentation
/// - `memo` must either be null (indicating an empty memo) or point to a 512-byte array.
/// - `shielding_threshold` a non-negative shielding threshold amount in zatoshi
/// - `spend_params` must be non-null and valid for reads for `spend_params_len` bytes, and it must have an
///   alignment of `1`. Its contents must be the Sapling spend proving parameters.
/// - The memory referenced by `spend_params` must not be mutated for the duration of the function call.
/// - The total size `spend_params_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `output_params` must be non-null and valid for reads for `output_params_len` bytes, and it must have an
///   alignment of `1`. Its contents must be the Sapling output proving parameters.
/// - The memory referenced by `output_params` must not be mutated for the duration of the function call.
/// - The total size `output_params_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `txid_bytes_ret` must be non-null and must point to an allocated 32-byte region of memory.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_shield_funds(
    db_data: *const u8,
    db_data_len: usize,
    usk_ptr: *const u8,
    usk_len: usize,
    memo: *const u8,
    shielding_threshold: u64,
    spend_params: *const u8,
    spend_params_len: usize,
    output_params: *const u8,
    output_params_len: usize,
    network_id: u32,
    min_confirmations: u32,
    use_zip317_fees: bool,
    txid_bytes_ret: *mut u8,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let min_confirmations = NonZeroU32::new(min_confirmations)
            .ok_or(anyhow!("min_confirmations should be non-zero"))?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let usk = unsafe { decode_usk(usk_ptr, usk_len) }?;

        let memo_bytes = if memo.is_null() {
            MemoBytes::empty()
        } else {
            MemoBytes::from_bytes(unsafe { slice::from_raw_parts(memo, 512) })
                .map_err(|e| anyhow!("Invalid MemoBytes: {}", e))?
        };

        let shielding_threshold = NonNegativeAmount::from_u64(shielding_threshold)
            .map_err(|()| anyhow!("Invalid amount, out of range"))?;

        let spend_params = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(spend_params, spend_params_len)
        }));
        let output_params = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(output_params, output_params_len)
        }));

        let account = db_data
            .get_account_for_ufvk(&usk.to_unified_full_viewing_key())?
            .ok_or_else(|| anyhow!("Spending key not recognized."))?;

        let taddrs: Vec<TransparentAddress> = db_data
            .get_target_and_anchor_heights(NonZeroU32::MIN)
            .map_err(|e| anyhow!("Error while fetching anchor height: {}", e))
            .and_then(|opt_anchor| {
                opt_anchor
                    .map(|(target, _)| target) // Include unconfirmed funds.
                    .ok_or_else(|| anyhow!("height not available; scan required."))
            })
            .and_then(|anchor| {
                db_data
                    .get_transparent_balances(account, anchor)
                    .map_err(|e| {
                        anyhow!(
                            "Error while fetching transparent balances for {:?}: {}",
                            account,
                            e,
                        )
                    })
            })?
            .keys()
            .cloned()
            .collect();

        let txid = if use_zip317_fees {
            let input_selector = GreedyInputSelector::new(
                zip317::SingleOutputChangeStrategy::new(Zip317FeeRule::standard()),
                DustOutputPolicy::default(),
            );

            shield_transparent_funds(
                &mut db_data,
                &network,
                LocalTxProver::new(spend_params, output_params),
                &input_selector,
                shielding_threshold,
                &usk,
                &taddrs,
                &memo_bytes,
                min_confirmations,
            )
            .map_err(|e| anyhow!("Error while shielding transaction: {}", e))
        } else {
            #[allow(deprecated)]
            let input_selector = GreedyInputSelector::new(
                fixed::SingleOutputChangeStrategy::new(FixedFeeRule::standard()),
                DustOutputPolicy::default(),
            );

            shield_transparent_funds(
                &mut db_data,
                &network,
                LocalTxProver::new(spend_params, output_params),
                &input_selector,
                shielding_threshold,
                &usk,
                &taddrs,
                &memo_bytes,
                min_confirmations,
            )
            .map_err(|e| anyhow!("Error while shielding transaction: {}", e))
        }?;

        let txid_bytes = unsafe { slice::from_raw_parts_mut(txid_bytes_ret, 32) };
        txid.write(txid_bytes)?;

        Ok(true)
    });
    unwrap_exc_or(res, false)
}

//
// Utility functions
//

fn parse_network(value: u32) -> anyhow::Result<Network> {
    match value {
        0 => Ok(TestNetwork),
        1 => Ok(MainNetwork),
        _ => Err(anyhow!("Invalid network type: {}. Expected either 0 or 1 for Testnet or Mainnet, respectively.", value))
    }
}
