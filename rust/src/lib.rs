#![deny(unsafe_op_in_unsafe_fn)]

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
use prost::Message;
use secrecy::Secret;
use std::convert::{Infallible, TryFrom, TryInto};
use std::error::Error;
use std::ffi::{CStr, CString, OsStr};
use std::num::NonZeroU32;
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::ptr;
use std::slice;
use tor_rtcompat::BlockOn;
use tracing::{debug, metadata::LevelFilter};
use tracing_subscriber::prelude::*;
use zcash_client_backend::data_api::TransactionStatus;
use zcash_client_sqlite::error::SqliteClientError;

use zcash_address::ZcashAddress;
use zcash_client_backend::{
    address::Address,
    data_api::{
        chain::{scan_cached_blocks, CommitmentTreeRoot, ScanSummary},
        scanning::ScanPriority,
        wallet::{
            create_proposed_transactions, decrypt_and_store_transaction,
            input_selection::GreedyInputSelector, propose_shielding, propose_transfer,
        },
        Account, AccountBalance, AccountBirthday, AccountSource, Balance, InputSource,
        SeedRelevance, TransactionDataRequest, WalletCommitmentTrees, WalletRead, WalletSummary,
        WalletWrite,
    },
    encoding::AddressCodec,
    fees::{standard::SingleOutputChangeStrategy, DustOutputPolicy},
    keys::{DecodingError, Era, UnifiedAddressRequest, UnifiedSpendingKey},
    proto::{proposal::Proposal, service::TreeState},
    tor::http::cryptex,
    wallet::{NoteId, OvkPolicy, WalletTransparentOutput},
    zip321::{Payment, TransactionRequest},
    ShieldedProtocol,
};
use zcash_client_sqlite::{
    chain::{init::init_blockmeta_db, BlockMeta},
    wallet::init::{init_wallet_db, WalletMigrationError},
    AccountId, FsBlockDb, WalletDb,
};
use zcash_primitives::consensus::Network::{MainNetwork, TestNetwork};
use zcash_primitives::{
    block::BlockHash,
    consensus::{BlockHeight, BranchId, Network, Parameters},
    legacy::{self, TransparentAddress},
    memo::{Memo, MemoBytes},
    merkle_tree::HashSer,
    transaction::{
        components::{amount::NonNegativeAmount, Amount, OutPoint, TxOut},
        fees::StandardFeeRule,
        Transaction, TxId,
    },
    zip32::{self, fingerprint::SeedFingerprint},
};
use zcash_proofs::prover::LocalTxProver;

mod derivation;
mod ffi;
mod tor;

#[cfg(target_vendor = "apple")]
mod os_log;

use crate::tor::TorRuntime;

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

fn account_id_from_i32(account: i32) -> anyhow::Result<zip32::AccountId> {
    u32::try_from(account)
        .map_err(|_| ())
        .and_then(|id| zip32::AccountId::try_from(id).map_err(|_| ()))
        .map_err(|_| anyhow!("Invalid account ID"))
}

fn account_id_from_ffi<P: Parameters>(
    db_data: &WalletDb<rusqlite::Connection, P>,
    account_index: i32,
) -> anyhow::Result<AccountId> {
    let requested_account_index = account_id_from_i32(account_index)?;

    // Find the single account matching the given ZIP 32 account index.
    let mut accounts = db_data
        .get_account_ids()?
        .into_iter()
        .filter_map(|account_id| {
            db_data
                .get_account(account_id)
                .map_err(|e| {
                    anyhow!(
                        "Database error encountered retrieving account {:?}: {}",
                        account_id,
                        e
                    )
                })
                .and_then(|acct_opt| {
                    acct_opt
                        .ok_or(anyhow!(
                            "Wallet data corrupted: unable to retrieve account data for account {:?}",
                            account_id
                        ))
                        .map(|account| match account.source() {
                            AccountSource::Derived { account_index, .. }
                                if account_index == requested_account_index =>
                            {
                                Some(account)
                            }
                            _ => None,
                        })
                })
                .transpose()
        });

    match (accounts.next(), accounts.next()) {
        (Some(account), None) => Ok(account?.id()),
        (None, None) => Err(anyhow!("Account does not exist")),
        (_, Some(_)) => Err(anyhow!("Account index matches more than one account")),
    }
}

/// Initializes global Rust state, such as the logging infrastructure and threadpools.
///
/// `log_level` defines how the Rust layer logs its events. These values are supported,
/// each level logging more information in addition to the earlier levels:
/// - `off`: The logs are completely disabled.
/// - `error`: Logs very serious errors.
/// - `warn`: Logs hazardous situations.
/// - `info`: Logs useful information.
/// - `debug`: Logs lower priority information.
/// - `trace`: Logs very low priority, often extremely verbose, information.
///
/// # Safety
///
/// - The memory pointed to by `log_level` must contain a valid nul terminator at the end
///   of the string.
/// - `log_level` must be valid for reads of bytes up to and including the nul terminator.
///   This means in particular:
///   - The entire memory range of this `CStr` must be contained within a single allocated
///     object!
/// - The memory referenced by the returned `CStr` must not be mutated for the duration of
///   the function call.
/// - The nul terminator must be within `isize::MAX` from `log_level`.
///
/// # Panics
///
/// This method panics if called more than once.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_init_on_load(log_level: *const c_char) {
    let log_filter = if log_level.is_null() {
        eprintln!("log_level not provided, falling back on 'debug' level");
        LevelFilter::DEBUG
    } else {
        unsafe { CStr::from_ptr(log_level) }
            .to_str()
            .unwrap_or_else(|_| {
                eprintln!("log_level not UTF-8, falling back on 'debug' level");
                "debug"
            })
            .parse()
            .unwrap_or_else(|_| {
                eprintln!("log_level not a valid level, falling back on 'debug' level");
                LevelFilter::DEBUG
            })
    };

    // Set up the tracing layers for the Apple OS logging framework.
    #[cfg(target_vendor = "apple")]
    let (log_layer, signpost_layer) = os_log::layers("co.electriccoin.ios", "rust");

    // Install the `tracing` subscriber.
    let registry = tracing_subscriber::registry();
    #[cfg(target_vendor = "apple")]
    let registry = registry.with(log_layer).with(signpost_layer);
    registry.with(log_filter).init();

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
/// Returns:
/// - 0 if successful.
/// - 1 if the seed must be provided in order to execute the requested migrations
/// - 2 if the provided seed is not relevant to any of the derived accounts in the wallet.
/// - -1 on error.
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
            Err(e)
                if matches!(
                    e.source().and_then(|e| e.downcast_ref()),
                    Some(&WalletMigrationError::SeedRequired),
                ) =>
            {
                Ok(1)
            }
            Err(e)
                if matches!(
                    e.source().and_then(|e| e.downcast_ref()),
                    Some(&WalletMigrationError::SeedNotRelevant),
                ) =>
            {
                Ok(2)
            }
            Err(e) => Err(anyhow!("Error while initializing data DB: {}", e)),
        }
    });
    unwrap_exc_or(res, -1)
}

/// A struct that contains details about an account in the wallet.
#[repr(C)]
pub struct FfiAccount {
    seed_fingerprint: [u8; 32],
    account_index: u32,
}

/// A struct that contains a pointer to, and length information for, a heap-allocated
/// slice of [`FfiAccount`] values.
///
/// # Safety
///
/// - `ptr` must be non-null and must be valid for reads for `len * mem::size_of::<FfiAccount>()`
///   many bytes, and it must be properly aligned. This means in particular:
///   - The entire memory range pointed to by `ptr` must be contained within a single allocated
///     object. Slices can never span across multiple allocated objects.
///   - `ptr` must be non-null and aligned even for zero-length slices.
///   - `ptr` must point to `len` consecutive properly initialized values of type
///     [`FfiAccount`].
/// - The total size `len * mem::size_of::<FfiAccount>()` of the slice pointed to
///   by `ptr` must be no larger than isize::MAX. See the safety documentation of pointer::offset.
/// - See the safety documentation of [`FfiAccount`]
#[repr(C)]
pub struct FfiAccounts {
    ptr: *mut FfiAccount,
    len: usize, // number of elems
}

impl FfiAccounts {
    pub fn ptr_from_vec(v: Vec<FfiAccount>) -> *mut Self {
        let (ptr, len) = ptr_from_vec(v);
        Box::into_raw(Box::new(FfiAccounts { ptr, len }))
    }
}

/// Frees an array of FfiAccounts values as allocated by `zcashlc_list_accounts`.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`FfiAccounts`].
///   See the safety documentation of [`FfiAccounts`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_accounts(ptr: *mut FfiAccounts) {
    if !ptr.is_null() {
        let s: Box<FfiAccounts> = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(s.ptr, s.len);
        drop(s);
    }
}

/// Returns a list of the accounts in the wallet.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Call [`zcashlc_free_accounts`] to free the memory associated with the returned pointer
///   when done using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_list_accounts(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
) -> *mut FfiAccounts {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        Ok(FfiAccounts::ptr_from_vec(
            db_data
                .get_account_ids()?
                .into_iter()
                .map(|account_id| {
                    let account = db_data.get_account(account_id)?.expect("account ID exists");

                    match account.source() {
                        AccountSource::Derived {
                            seed_fingerprint,
                            account_index,
                        } => Ok(FfiAccount {
                            seed_fingerprint: seed_fingerprint.to_bytes(),
                            account_index: account_index.into(),
                        }),
                        AccountSource::Imported { .. } => Err(anyhow!(
                            "Wallet DB contains imported accounts, which are unsuppported"
                        )),
                    }
                })
                .collect::<Result<_, _>>()?,
        ))
    });
    unwrap_exc_or_null(res)
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
    fn new(account_id: zip32::AccountId, key_bytes: Vec<u8>) -> Self {
        let (encoding, encoding_len) = ptr_from_vec(key_bytes);
        FFIBinaryKey {
            account_id: account_id.into(),
            encoding,
            encoding_len,
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
        free_ptr_from_vec(key.encoding, key.encoding_len);
        drop(key);
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

        let (account_id, usk) = db_data
            .create_account(&seed, &birthday)
            .map_err(|e| anyhow!("Error while initializing accounts: {}", e))?;

        let account = db_data.get_account(account_id)?.expect("just created");
        let account_index = match account.source() {
            AccountSource::Derived { account_index, .. } => account_index,
            AccountSource::Imported { .. } => unreachable!("just created"),
        };

        let encoded = usk.to_bytes(Era::Orchard);
        Ok(Box::into_raw(Box::new(FFIBinaryKey::new(
            account_index,
            encoded,
        ))))
    });
    unwrap_exc_or_null(res)
}

/// Checks whether the given seed is relevant to any of the accounts in the wallet.
///
/// Returns:
/// - `1` for `Ok(true)`.
/// - `0` for `Ok(false)`.
/// - `-1` for `Err(_)`.
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
pub unsafe extern "C" fn zcashlc_is_seed_relevant_to_any_derived_account(
    db_data: *const u8,
    db_data_len: usize,
    seed: *const u8,
    seed_len: usize,
    network_id: u32,
) -> i8 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let seed = Secret::new((unsafe { slice::from_raw_parts(seed, seed_len) }).to_vec());

        // Replicate the logic from `initWalletDb`.
        Ok(match db_data.seed_relevance_to_derived_accounts(&seed)? {
            SeedRelevance::Relevant { .. } | SeedRelevance::NoAccounts => 1,
            SeedRelevance::NotRelevant | SeedRelevance::NoDerivedAccounts => 0,
        })
    });
    unwrap_exc_or(res, -1)
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
        let (ptr, len) = ptr_from_vec(v);
        Box::into_raw(Box::new(FFIEncodedKeys { ptr, len }))
    }
}

/// Frees an array of `FFIEncodedKeys` values as allocated by `zcashlc_list_transparent_receivers`.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`FFIEncodedKeys`].
///   See the safety documentation of [`FFIEncodedKeys`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_keys(ptr: *mut FFIEncodedKeys) {
    if !ptr.is_null() {
        let s: Box<FFIEncodedKeys> = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec_with(s.ptr, s.len, |k| unsafe { zcashlc_string_free(k.encoding) });
        drop(s);
    }
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
        let account = account_id_from_ffi(&db_data, account)?;

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
        let account = account_id_from_ffi(&db_data, account)?;

        let request = UnifiedAddressRequest::new(true, true, true).expect("have shielded receiver");
        match db_data.get_next_available_address(account, request) {
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
        let account = account_id_from_ffi(&db_data, account_id)?;

        match db_data.get_transparent_receivers(account) {
            Ok(receivers) => {
                let keys = receivers
                    .keys()
                    .map(|receiver| {
                        let address_str = receiver.encode(&network);
                        FFIEncodedKey {
                            account_id: account_id as u32,
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
            .map_err(|e| anyhow!("Error while fetching target height: {}", e))
            .and_then(|opt_target| {
                opt_target
                    .map(|(target, _)| target)
                    .ok_or_else(|| anyhow!("Target height not available; scan required."))
            })
            .and_then(|target| {
                db_data
                    .get_spendable_transparent_outputs(&taddr, target, 0)
                    .map_err(|e| {
                        anyhow!("Error while fetching verified transparent balance: {}", e)
                    })
            })?
            .iter()
            .map(|utxo| utxo.txout().value)
            .sum::<Option<NonNegativeAmount>>()
            .ok_or_else(|| anyhow!("Balance overflowed MAX_MONEY."))?;

        Ok(Amount::from(amount).into())
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
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let account = account_id_from_ffi(&db_data, account)?;

        let amount = db_data
            .get_target_and_anchor_heights(NonZeroU32::MIN)
            .map_err(|e| anyhow!("Error while fetching anchor height: {}", e))
            .and_then(|opt_target| {
                opt_target
                    .map(|(target, _)| target)
                    .ok_or_else(|| anyhow!("Target height not available; scan required."))
            })
            .and_then(|target| {
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
                                    .get_spendable_transparent_outputs(
                                        taddr,
                                        target,
                                        min_confirmations,
                                    )
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
            .sum::<Option<NonNegativeAmount>>()
            .ok_or_else(|| anyhow!("Balance overflowed MAX_MONEY."))?;

        Ok(Amount::from(amount).into())
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
            .map_err(|e| anyhow!("Error while fetching target height: {}", e))
            .and_then(|opt_target| {
                opt_target
                    .map(|(target, _)| target)
                    .ok_or_else(|| anyhow!("Target height not available; scan required."))
            })
            .and_then(|target| {
                db_data
                    .get_spendable_transparent_outputs(&taddr, target, 0)
                    .map_err(|e| anyhow!("Error while fetching total transparent balance: {}", e))
            })?
            .iter()
            .map(|utxo| utxo.txout().value)
            .sum::<Option<NonNegativeAmount>>()
            .ok_or_else(|| anyhow!("Balance overflowed MAX_MONEY."))?;

        Ok(Amount::from(amount).into())
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
        let account = account_id_from_ffi(&db_data, account)?;

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
            .sum::<Option<NonNegativeAmount>>()
            .ok_or_else(|| anyhow!("Balance overflowed MAX_MONEY."))?;

        Ok(amount.into_u64() as i64)
    });
    unwrap_exc_or(res, -1)
}

fn parse_protocol(code: u32) -> Option<ShieldedProtocol> {
    match code {
        2 => Some(ShieldedProtocol::Sapling),
        3 => Some(ShieldedProtocol::Orchard),
        _ => None,
    }
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
    output_pool: u32,
    output_index: u16,
    memo_bytes_ret: *mut u8,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let txid_bytes = unsafe { slice::from_raw_parts(txid_bytes, 32) };
        let txid = TxId::read(txid_bytes)?;

        let protocol = parse_protocol(output_pool).ok_or(anyhow!(
            "Shielded protocol not recognized for code: {}",
            output_pool
        ))?;

        let memo_bytes = db_data
            .get_memo(NoteId::new(txid, protocol, output_index))
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
        let txid = TxId::read(txid_bytes)?;

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

/// Rewinds the data database to at most the given height.
///
/// If the requested height is greater than or equal to the height of the last scanned block, this
/// function sets the `safe_rewind_ret` output parameter to `-1` and does nothing else.
///
/// This procedure returns the height to which the database was actually rewound, or `-1` if no
/// rewind was performed.
///
/// If the requested rewind could not be performed, but a rewind to a different (greater) height
/// would be valid, the `safe_rewind_ret` output parameter will be set to that value on completion;
/// otherwise, it will be set to `-1`.
///
/// # Safety
///
/// - `safe_rewind_ret` must be non-null, aligned, and valid for writing an `int64_t`.
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
    height: u32,
    network_id: u32,
    safe_rewind_ret: *mut i64,
) -> i64 {
    unsafe {
        *safe_rewind_ret = -1;
    }
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let height = BlockHeight::from(height);
        let result_height = db_data.truncate_to_height(height);

        result_height.map_or_else(
            |err| match err {
                SqliteClientError::RequestedRewindInvalid {
                    safe_rewind_height: Some(h),
                    ..
                } => {
                    unsafe { *safe_rewind_ret = u32::from(h).into() };
                    Ok(-1)
                }
                other => Err(anyhow!(
                    "Error while rewinding data DB to height {}: {}",
                    height,
                    other
                )),
            },
            |h| Ok(u32::from(h).into()),
        )
    });
    unwrap_exc_or(res, -1)
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
                let root_hash = HashSer::read(root_hash_bytes)?;

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

/// Adds a sequence of Orchard subtree roots to the data store.
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
pub unsafe extern "C" fn zcashlc_put_orchard_subtree_roots(
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
                let root_hash = HashSer::read(root_hash_bytes)?;

                Ok(CommitmentTreeRoot::from_parts(
                    BlockHeight::from_u32(r.completing_block_height),
                    root_hash,
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        db_data
            .put_orchard_subtree_roots(start_index, &roots)
            .map(|()| true)
            .map_err(|e| anyhow!("Error while storing Orchard subtree roots: {}", e))
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

/// Balance information for a value within a single pool in an account.
#[repr(C)]
pub struct FfiBalance {
    /// The value in the account that may currently be spent; it is possible to compute witnesses
    /// for all the notes that comprise this value, and all of this value is confirmed to the
    /// required confirmation depth.
    spendable_value: i64,

    /// The value in the account of shielded change notes that do not yet have sufficient
    /// confirmations to be spendable.
    change_pending_confirmation: i64,

    /// The value in the account of all remaining received notes that either do not have sufficient
    /// confirmations to be spendable, or for which witnesses cannot yet be constructed without
    /// additional scanning.
    value_pending_spendability: i64,
}

impl FfiBalance {
    fn new(balance: &Balance) -> Self {
        Self {
            spendable_value: Amount::from(balance.spendable_value()).into(),
            change_pending_confirmation: Amount::from(balance.change_pending_confirmation()).into(),
            value_pending_spendability: Amount::from(balance.value_pending_spendability()).into(),
        }
    }
}

/// Balance information for a single account.
///
/// The sum of this struct's fields is the total balance of the account.
#[repr(C)]
pub struct FfiAccountBalance {
    account_id: u32,

    /// The value of unspent Sapling outputs belonging to the account.
    sapling_balance: FfiBalance,

    /// The value of unspent Orchard outputs belonging to the account.
    orchard_balance: FfiBalance,

    /// The value of all unspent transparent outputs belonging to the account,
    /// irrespective of confirmation depth.
    ///
    /// Unshielded balances are not subject to confirmation-depth constraints, because the
    /// only possible operation on a transparent balance is to shield it, it is possible
    /// to create a zero-conf transaction to perform that shielding, and the resulting
    /// shielded notes will be subject to normal confirmation rules.
    unshielded: i64,
}

impl FfiAccountBalance {
    fn new((account_id, balance): (&zip32::AccountId, &AccountBalance)) -> Self {
        Self {
            account_id: u32::from(*account_id),
            sapling_balance: FfiBalance::new(balance.sapling_balance()),
            orchard_balance: FfiBalance::new(balance.orchard_balance()),
            unshielded: Amount::from(balance.unshielded()).into(),
        }
    }
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

/// A type representing the potentially-spendable value of unspent outputs in the wallet.
///
/// The balances reported using this data structure may overestimate the total spendable
/// value of the wallet, in the case that the spend of a previously received shielded note
/// has not yet been detected by the process of scanning the chain. The balances reported
/// using this data structure can only be certain to be unspent in the case that
/// [`Self::is_synced`] is true, and even in this circumstance it is possible that a newly
/// created transaction could conflict with a not-yet-mined transaction in the mempool.
///
/// # Safety
///
/// - `account_balances` must be non-null and must be valid for reads for
///   `account_balances_len * mem::size_of::<FfiAccountBalance>()` many bytes, and it must
///   be properly aligned. This means in particular:
///   - The entire memory range pointed to by `account_balances` must be contained within
///     a single allocated object. Slices can never span across multiple allocated objects.
///   - `account_balances` must be non-null and aligned even for zero-length slices.
///   - `account_balances` must point to `len` consecutive properly initialized values of
///     type [`FfiAccountBalance`].
/// - The total size `account_balances_len * mem::size_of::<FfiAccountBalance>()` of the
///   slice pointed to by `account_balances` must be no larger than `isize::MAX`. See the
///   safety documentation of `pointer::offset`.
/// - `scan_progress` must, if non-null, point to a struct having the layout of
///   [`FfiScanProgress`].
#[repr(C)]
pub struct FfiWalletSummary {
    account_balances: *mut FfiAccountBalance,
    account_balances_len: usize,
    chain_tip_height: i32,
    fully_scanned_height: i32,
    scan_progress: *mut FfiScanProgress,
    next_sapling_subtree_index: u64,
    next_orchard_subtree_index: u64,
}

impl FfiWalletSummary {
    fn some<P: Parameters>(
        db_data: &WalletDb<rusqlite::Connection, P>,
        summary: WalletSummary<AccountId>,
    ) -> anyhow::Result<*mut Self> {
        let (account_balances, account_balances_len) = {
            let account_balances: Vec<FfiAccountBalance> = summary
                .account_balances()
                .iter()
                .map(|(account_id, balance)| {
                    let account_index = match db_data
                        .get_account(*account_id)?
                        .expect("the account exists in the wallet")
                        .source()
                    {
                        AccountSource::Derived { account_index, .. } => account_index,
                        AccountSource::Imported { .. } => {
                            unreachable!("Imported accounts are unimplemented")
                        }
                    };

                    Ok::<_, anyhow::Error>(FfiAccountBalance::new((&account_index, balance)))
                })
                .collect::<Result<_, _>>()?;

            ptr_from_vec(account_balances)
        };

        let scan_progress = if let Some(scan_progress) = summary.scan_progress() {
            if let Some(recovery_progress) = summary.recovery_progress() {
                Box::into_raw(Box::new(FfiScanProgress {
                    numerator: *scan_progress.numerator() + *recovery_progress.numerator(),
                    denominator: *scan_progress.denominator() + *recovery_progress.denominator(),
                }))
            } else {
                Box::into_raw(Box::new(FfiScanProgress {
                    numerator: *scan_progress.numerator(),
                    denominator: *scan_progress.denominator(),
                }))
            }
        } else {
            ptr::null_mut()
        };

        Ok(Box::into_raw(Box::new(Self {
            account_balances,
            account_balances_len,
            chain_tip_height: u32::from(summary.chain_tip_height()) as i32,
            fully_scanned_height: u32::from(summary.fully_scanned_height()) as i32,
            scan_progress,
            next_sapling_subtree_index: summary.next_sapling_subtree_index(),
            next_orchard_subtree_index: summary.next_orchard_subtree_index(),
        })))
    }

    fn none() -> *mut Self {
        Box::into_raw(Box::new(Self {
            account_balances: ptr::null_mut(),
            account_balances_len: 0,
            chain_tip_height: 0,
            fully_scanned_height: -1,
            scan_progress: ptr::null_mut(),
            next_sapling_subtree_index: 0,
            next_orchard_subtree_index: 0,
        }))
    }
}

/// Returns the account balances and sync status given the specified minimum number of
/// confirmations.
///
/// Returns `fully_scanned_height = -1` if the wallet has no balance data available.
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
pub unsafe extern "C" fn zcashlc_get_wallet_summary(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
    min_confirmations: u32,
) -> *mut FfiWalletSummary {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        match db_data
            .get_wallet_summary(min_confirmations)
            .map_err(|e| anyhow!("Error while fetching wallet summary: {}", e))?
        {
            Some(summary) => FfiWalletSummary::some(&db_data, summary),
            None => Ok(FfiWalletSummary::none()),
        }
    });
    unwrap_exc_or(res, ptr::null_mut())
}

/// Frees an [`FfiWalletSummary`] value.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`FfiWalletSummary`].
///   See the safety documentation of [`FfiWalletSummary`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_wallet_summary(ptr: *mut FfiWalletSummary) {
    if !ptr.is_null() {
        let summary = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(summary.account_balances, summary.account_balances_len);
        if !summary.scan_progress.is_null() {
            let progress = unsafe { Box::from_raw(summary.scan_progress) };
            drop(progress);
        }
        drop(summary);
    }
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
        let (ptr, len) = ptr_from_vec(v);
        Box::into_raw(Box::new(FfiScanRanges { ptr, len }))
    }
}

/// Frees an array of `FfiScanRanges` values as allocated by `zcashlc_suggest_scan_ranges`.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`FfiScanRanges`].
///   See the safety documentation of [`FfiScanRanges`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_scan_ranges(ptr: *mut FfiScanRanges) {
    if !ptr.is_null() {
        let s: Box<FfiScanRanges> = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(s.ptr, s.len);
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

/// Metadata about modifications to the wallet state made in the course of scanning a set
/// of blocks.
#[repr(C)]
pub struct FfiScanSummary {
    scanned_start: i32,
    scanned_end: i32,
    spent_sapling_note_count: u64,
    received_sapling_note_count: u64,
}

impl FfiScanSummary {
    fn new(scan_summary: ScanSummary) -> *mut Self {
        let scanned_range = scan_summary.scanned_range();

        Box::into_raw(Box::new(Self {
            scanned_start: u32::from(scanned_range.start) as i32,
            scanned_end: u32::from(scanned_range.end) as i32,
            spent_sapling_note_count: scan_summary.spent_sapling_note_count() as u64,
            received_sapling_note_count: scan_summary.received_sapling_note_count() as u64,
        }))
    }
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
    from_state: *const u8,
    from_state_len: usize,
    scan_limit: u32,
    network_id: u32,
) -> *mut FfiScanSummary {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let block_db = block_db(fs_block_cache_root, fs_block_cache_root_len)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let from_height = BlockHeight::try_from(from_height)?;
        let from_state =
            TreeState::decode(unsafe { slice::from_raw_parts(from_state, from_state_len) })
                .map_err(|e| anyhow!("Invalid TreeState: {}", e))?
                .to_chain_state()?;
        let limit = usize::try_from(scan_limit)?;
        match scan_cached_blocks(
            &network,
            &block_db,
            &mut db_data,
            from_height,
            &from_state,
            limit,
        ) {
            Ok(scan_summary) => Ok(FfiScanSummary::new(scan_summary)),
            Err(e) => Err(anyhow!("Error while scanning blocks: {}", e)),
        }
    });
    unwrap_exc_or_null(res)
}

/// Frees an [`FfiScanSummary`] value.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`FfiScanSummary`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_scan_summary(ptr: *mut FfiScanSummary) {
    if !ptr.is_null() {
        let summary = unsafe { Box::from_raw(ptr) };
        drop(summary);
    }
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
                value: NonNegativeAmount::from_nonnegative_i64(value)
                    .map_err(|_| anyhow!("Invalid UTXO value"))?,
                script_pubkey,
            },
            Some(BlockHeight::from(height as u32)),
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
        let (ptr, len) = ptr_from_vec(v);
        Box::into_raw(Box::new(FFIBlocksMeta { ptr, len }))
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
    mined_height: i64,
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

        // Following the conventions of the `zcashd` `getrawtransaction` RPC method,
        // negative values (specifically -1) indicate that the transaction may have been
        // mined, but in a fork of the chain rather than the main chain, whereas a value
        // of zero indicates that the transaction is in the mempool. We do not distinguish
        // between these in `librustzcash`, and so both cases are mapped to `None`,
        // indicating that the mined height of the transaction is simply unknown.
        let mined_height = if mined_height > 0 {
            let h = u32::try_from(mined_height)
                .map_err(|e| anyhow!("Block height outside valid range: {}", e))?;
            Some(h.into())
        } else {
            // We do not provide a mined height to `decrypt_and_store_transaction` for either
            // transactions in the mempool or for transactions that have been mined on a fork
            // but not in the main chain.
            None
        };

        match decrypt_and_store_transaction(&network, &mut db_data, &tx, mined_height) {
            Ok(()) => Ok(1),
            Err(e) => Err(anyhow!("Error while decrypting transaction: {}", e)),
        }
    });
    unwrap_exc_or(res, -1)
}

fn zip317_helper<DbT>(
    change_memo: Option<MemoBytes>,
    use_zip317_fees: bool,
) -> GreedyInputSelector<DbT, SingleOutputChangeStrategy> {
    let fee_rule = if use_zip317_fees {
        StandardFeeRule::Zip317
    } else {
        #[allow(deprecated)]
        StandardFeeRule::PreZip313
    };
    GreedyInputSelector::new(
        SingleOutputChangeStrategy::new(fee_rule, change_memo, ShieldedProtocol::Orchard),
        DustOutputPolicy::default(),
    )
}

/// A struct that optionally contains a pointer to, and length information for, a
/// heap-allocated boxed slice.
///
/// This is an FFI representation of `Option<Box<[u8]>>`.
///
/// # Safety
///
/// - If `ptr` is non-null, it must be valid for reads for `len` bytes, and it must have
///   an alignment of `1`.
/// - The memory referenced by `ptr` must not be mutated for the lifetime of the struct
///   (up until [`zcashlc_free_boxed_slice`] is called with it).
/// - The total size `len` must be no larger than `isize::MAX`. See the safety
///   documentation of `pointer::offset`.
///   - When `ptr` is null, `len` should be zero.
#[repr(C)]
pub struct FfiBoxedSlice {
    ptr: *mut u8,
    len: usize,
}

impl FfiBoxedSlice {
    fn some(v: Vec<u8>) -> *mut Self {
        let (ptr, len) = ptr_from_vec(v);
        Box::into_raw(Box::new(FfiBoxedSlice { ptr, len }))
    }

    fn none() -> *mut Self {
        Box::into_raw(Box::new(Self {
            ptr: ptr::null_mut(),
            len: 0,
        }))
    }
}

/// Frees an [`FfiBoxedSlice`].
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of
///   [`FfiBoxedSlice`]. See the safety documentation of [`FfiBoxedSlice`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_boxed_slice(ptr: *mut FfiBoxedSlice) {
    if !ptr.is_null() {
        let s: Box<FfiBoxedSlice> = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(s.ptr, s.len);
        drop(s);
    }
}

/// Select transaction inputs, compute fees, and construct a proposal for a transaction
/// that can then be authorized and made ready for submission to the network with
/// `zcashlc_create_proposed_transaction`.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `to` must be non-null and must point to a null-terminated UTF-8 string.
/// - `memo` must either be null (indicating an empty memo or a transparent recipient) or point to a
///    512-byte array.
/// - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
///   pointer when done using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_propose_transfer(
    db_data: *const u8,
    db_data_len: usize,
    account: i32,
    to: *const c_char,
    value: i64,
    memo: *const u8,
    network_id: u32,
    min_confirmations: u32,
    use_zip317_fees: bool,
) -> *mut FfiBoxedSlice {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let min_confirmations = NonZeroU32::new(min_confirmations)
            .ok_or(anyhow!("min_confirmations should be non-zero"))?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let account = account_id_from_ffi(&db_data, account)?;
        let to = unsafe { CStr::from_ptr(to) }.to_str()?;
        let value = NonNegativeAmount::from_nonnegative_i64(value)
            .map_err(|_| anyhow!("Invalid amount, out of range"))?;

        let to: ZcashAddress = to
            .parse()
            .map_err(|e| anyhow!("Can't parse recipient address: {}", e))?;

        let memo = if memo.is_null() {
            Ok(None)
        } else {
            MemoBytes::from_bytes(unsafe { slice::from_raw_parts(memo, 512) })
                .map(Some)
                .map_err(|e| anyhow!("Invalid MemoBytes: {}", e))
        }?;

        let input_selector = zip317_helper(None, use_zip317_fees);

        let req = TransactionRequest::new(vec![Payment::new(to, value, memo, None, None, vec![])
            .ok_or_else(|| {
                anyhow!("Memos are not permitted when sending to transparent recipients.")
            })?])
        .map_err(|e| anyhow!("Error creating transaction request: {:?}", e))?;

        let proposal = propose_transfer::<_, _, _, Infallible>(
            &mut db_data,
            &network,
            account,
            &input_selector,
            req,
            min_confirmations,
        )
        .map_err(|e| anyhow!("Error while sending funds: {}", e))?;

        let encoded = Proposal::from_standard_proposal(&proposal).encode_to_vec();

        Ok(FfiBoxedSlice::some(encoded))
    });
    unwrap_exc_or_null(res)
}

/// Select transaction inputs, compute fees, and construct a proposal for a transaction
/// from a ZIP-321 payment URI that can then be authorized and made ready for submission to the
/// network with `zcashlc_create_proposed_transaction`.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `payment_uri` must be non-null and must point to a null-terminated UTF-8 string.
/// - `network_id` a u32. 0 for Testnet and 1 for Mainnet
/// - `min_confirmations` number of confirmations of the funds to spend
/// - `use_zip317_fees` `true` to use ZIP-317 fees.
/// - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
///   pointer when done using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_propose_transfer_from_uri(
    db_data: *const u8,
    db_data_len: usize,
    account: i32,
    payment_uri: *const c_char,
    network_id: u32,
    min_confirmations: u32,
    use_zip317_fees: bool,
) -> *mut FfiBoxedSlice {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let min_confirmations = NonZeroU32::new(min_confirmations)
            .ok_or(anyhow!("min_confirmations should be non-zero"))?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let account = account_id_from_ffi(&db_data, account)?;
        let payment_uri_str = unsafe { CStr::from_ptr(payment_uri) }.to_str()?;

        let input_selector = zip317_helper(None, use_zip317_fees);

        let req = TransactionRequest::from_uri(payment_uri_str)
            .map_err(|e| anyhow!("Error creating transaction request: {:?}", e))?;

        let proposal = propose_transfer::<_, _, _, Infallible>(
            &mut db_data,
            &network,
            account,
            &input_selector,
            req,
            min_confirmations,
        )
        .map_err(|e| anyhow!("Error while sending funds: {}", e))?;

        let encoded = Proposal::from_standard_proposal(&proposal).encode_to_vec();

        Ok(FfiBoxedSlice::some(encoded))
    });
    unwrap_exc_or_null(res)
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

/// Select transaction inputs, compute fees, and construct a proposal for a shielding
/// transaction that can then be authorized and made ready for submission to the network
/// with `zcashlc_create_proposed_transaction`.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `shielding_threshold` a non-negative shielding threshold amount in zatoshi
/// - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
///   pointer when done using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_propose_shielding(
    db_data: *const u8,
    db_data_len: usize,
    account: i32,
    memo: *const u8,
    shielding_threshold: u64,
    transparent_receiver: *const c_char,
    network_id: u32,
    min_confirmations: u32,
    use_zip317_fees: bool,
) -> *mut FfiBoxedSlice {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let account = account_id_from_ffi(&db_data, account)?;

        let memo_bytes = if memo.is_null() {
            MemoBytes::empty()
        } else {
            MemoBytes::from_bytes(unsafe { slice::from_raw_parts(memo, 512) })
                .map_err(|e| anyhow!("Invalid MemoBytes: {}", e))?
        };

        let shielding_threshold = NonNegativeAmount::from_u64(shielding_threshold)
            .map_err(|_| anyhow!("Invalid amount, out of range"))?;

        let transparent_receiver = if transparent_receiver.is_null() {
            Ok(None)
        } else {
            match Address::decode(
                &network,
                unsafe { CStr::from_ptr(transparent_receiver) }.to_str()?,
            ) {
                None => Err(anyhow!("Transparent receiver is for the wrong network")),
                Some(addr) => match addr {
                    Address::Sapling(_) | Address::Unified(_) | Address::Tex(_) => {
                        Err(anyhow!("Transparent receiver is not a transparent address"))
                    }
                    Address::Transparent(addr) => {
                        if db_data
                            .get_transparent_receivers(account)?
                            .contains_key(&addr)
                        {
                            Ok(Some(addr))
                        } else {
                            Err(anyhow!("Transparent receiver does not belong to account"))
                        }
                    }
                },
            }
        }?;

        let account_receivers = db_data
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
            })?;

        let from_addrs = if let Some((addr, _)) = transparent_receiver.map_or_else(||
            if account_receivers.len() > 1 {
                Err(anyhow!(
                    "Account has more than one transparent receiver with funds to shield; this is not yet supported by the SDK. Provide a specific transparent receiver to shield funds from."
                ))
            } else {
                Ok(account_receivers.iter().next().map(|(a, v)| (*a, *v)))
            },
            |addr| Ok(account_receivers.get(&addr).map(|value| (addr, *value)))
        )?.filter(|(_, value)| *value >= shielding_threshold) {
            [addr]
        } else {
            // There are no transparent funds to shield; don't create a proposal.
            return Ok(FfiBoxedSlice::none());
        };

        let input_selector = zip317_helper(Some(memo_bytes), use_zip317_fees);

        let proposal = propose_shielding::<_, _, _, Infallible>(
            &mut db_data,
            &network,
            &input_selector,
            shielding_threshold,
            &from_addrs,
            min_confirmations,
        )
        .map_err(|e| anyhow!("Error while shielding transaction: {}", e))?;

        let encoded = Proposal::from_standard_proposal(&proposal).encode_to_vec();

        Ok(FfiBoxedSlice::some(encoded))
    });
    unwrap_exc_or_null(res)
}

/// A struct that contains a pointer to, and length information for, a heap-allocated
/// slice of `[u8; 32]` arrays.
///
/// # Safety
///
/// - `ptr` must be non-null and must be valid for reads for `len * mem::size_of::<[u8; 32]>()`
///   many bytes, and it must be properly aligned. This means in particular:
///   - The entire memory range pointed to by `ptr` must be contained within a single
///     allocated object. Slices can never span across multiple allocated objects.
///   - `ptr` must be non-null and aligned even for zero-length slices.
///   - `ptr` must point to `len` consecutive properly initialized values of type
///     `[u8; 32]`.
/// - The total size `len * mem::size_of::<[u8; 32]>()` of the slice pointed to
///   by `ptr` must be no larger than isize::MAX. See the safety documentation of
///   `pointer::offset`.
#[repr(C)]
pub struct FfiTxIds {
    ptr: *mut [u8; 32],
    len: usize, // number of elems
}

impl FfiTxIds {
    pub fn ptr_from_vec(v: Vec<[u8; 32]>) -> *mut Self {
        let (ptr, len) = ptr_from_vec(v);
        Box::into_raw(Box::new(FfiTxIds { ptr, len }))
    }
}

/// Frees an array of FfiTxIds values as allocated by `zcashlc_create_proposed_transactions`.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`FfiTxIds`].
///   See the safety documentation of [`FfiTxIds`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_txids(ptr: *mut FfiTxIds) {
    if !ptr.is_null() {
        let s: Box<FfiTxIds> = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(s.ptr, s.len);
        drop(s);
    }
}

/// Creates a transaction from the given proposal.
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
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must
///   have an alignment of `1`. Its contents must be a string representing a valid system
///   path in the operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the
///   function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of `pointer::offset`.
/// - `proposal_ptr` must be non-null and valid for reads for `proposal_len` bytes, and it
///   must have an alignment of `1`. Its contents must be an encoded Proposal protobuf.
/// - The memory referenced by `proposal_ptr` must not be mutated for the duration of the
///   function call.
/// - The total size `proposal_len` must be no larger than `isize::MAX`. See the safety
///   documentation of `pointer::offset`.
/// - `usk_ptr` must be non-null and must point to an array of `usk_len` bytes containing
///   a unified spending key encoded as returned from the `zcashlc_create_account` or
///   `zcashlc_derive_spending_key` functions.
/// - The memory referenced by `usk_ptr` must not be mutated for the duration of the
///   function call.
/// - The total size `usk_len` must be no larger than `isize::MAX`. See the safety
///   documentation of `pointer::offset`.
/// - `to` must be non-null and must point to a null-terminated UTF-8 string.
/// - `memo` must either be null (indicating an empty memo or a transparent recipient) or
///   point to a 512-byte array.
/// - `spend_params` must be non-null and valid for reads for `spend_params_len` bytes,
///   and it must have an alignment of `1`. Its contents must be the Sapling spend proving
///   parameters.
/// - The memory referenced by `spend_params` must not be mutated for the duration of the
///   function call.
/// - The total size `spend_params_len` must be no larger than `isize::MAX`. See the safety
///   documentation of `pointer::offset`.
/// - `output_params` must be non-null and valid for reads for `output_params_len` bytes,
///   and it must have an alignment of `1`. Its contents must be the Sapling output
///   proving parameters.
/// - The memory referenced by `output_params` must not be mutated for the duration of the
///   function call.
/// - The total size `output_params_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_create_proposed_transactions(
    db_data: *const u8,
    db_data_len: usize,
    proposal_ptr: *const u8,
    proposal_len: usize,
    usk_ptr: *const u8,
    usk_len: usize,
    spend_params: *const u8,
    spend_params_len: usize,
    output_params: *const u8,
    output_params_len: usize,
    network_id: u32,
) -> *mut FfiTxIds {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let proposal =
            Proposal::decode(unsafe { slice::from_raw_parts(proposal_ptr, proposal_len) })
                .map_err(|e| anyhow!("Invalid proposal: {}", e))?
                .try_into_standard_proposal(&db_data)?;
        let usk = unsafe { decode_usk(usk_ptr, usk_len) }?;
        let spend_params = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(spend_params, spend_params_len)
        }));
        let output_params = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(output_params, output_params_len)
        }));

        let prover = LocalTxProver::new(spend_params, output_params);

        let txids = create_proposed_transactions::<_, _, Infallible, _, _>(
            &mut db_data,
            &network,
            &prover,
            &prover,
            &usk,
            OvkPolicy::Sender,
            &proposal,
        )
        .map_err(|e| anyhow!("Error while sending funds: {}", e))?;

        Ok(FfiTxIds::ptr_from_vec(
            txids.into_iter().map(|txid| *txid.as_ref()).collect(),
        ))
    });
    unwrap_exc_or_null(res)
}

/// Metadata about the status of a transaction obtained by inspecting the chain state.
#[repr(C, u8)]
pub enum FfiTransactionStatus {
    /// The requested transaction ID was not recognized by the node.
    TxidNotRecognized,
    /// The requested transaction ID corresponds to a transaction that is recognized by the node,
    /// but is in the mempool or is otherwise not mined in the main chain (but may have been mined
    /// on a fork that was reorged away).
    NotInMainChain,
    /// The requested transaction ID corresponds to a transaction that has been included in the
    /// block at the provided height.
    Mined(u32),
}

/// Sets the transaction status to the provided value.
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
/// - `txid_bytes` must be non-null and valid for reads for `db_data_len` bytes, and it must have
///   an alignment of `1`.
/// - The memory referenced by `txid_bytes_len` must not be mutated for the duration of the
///   function call.
/// - The total size `txid_bytes_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_set_transaction_status(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
    txid_bytes: *const u8,
    txid_bytes_len: usize,
    status: FfiTransactionStatus,
) {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let txid_bytes = unsafe { slice::from_raw_parts(txid_bytes, txid_bytes_len) };
        let txid = TxId::read(&txid_bytes[..])?;

        let status = match status {
            FfiTransactionStatus::TxidNotRecognized => TransactionStatus::TxidNotRecognized,
            FfiTransactionStatus::NotInMainChain => TransactionStatus::NotInMainChain,
            FfiTransactionStatus::Mined(h) => TransactionStatus::Mined(BlockHeight::from(h)),
        };

        db_data
            .set_transaction_status(txid, status)
            .map_err(|e| anyhow!("Error setting transaction status for txid {}: {}", txid, e))
    });

    unwrap_exc_or(res, ())
}

/// A request for transaction data enhancement, spentness check, or discovery
/// of spends from a given transparent address within a specific block range.
#[repr(C, u8)]
pub enum FfiTransactionDataRequest {
    /// Information about the chain's view of a transaction is requested.
    ///
    /// The caller evaluating this request on behalf of the wallet backend should respond to this
    /// request by determining the status of the specified transaction with respect to the main
    /// chain; if using `lightwalletd` for access to chain data, this may be obtained by
    /// interpreting the results of the [`GetTransaction`] RPC method. It should then call
    /// [`WalletWrite::set_transaction_status`] to provide the resulting transaction status
    /// information to the wallet backend.
    ///
    /// [`GetTransaction`]: crate::proto::service::compact_tx_streamer_client::CompactTxStreamerClient::get_transaction
    GetStatus([u8; 32]),
    /// Transaction enhancement (download of complete raw transaction data) is requested.
    ///
    /// The caller evaluating this request on behalf of the wallet backend should respond to this
    /// request by providing complete data for the specified transaction to
    /// [`wallet::decrypt_and_store_transaction`]; if using `lightwalletd` for access to chain
    /// state, this may be obtained via the [`GetTransaction`] RPC method. If no data is available
    /// for the specified transaction, this should be reported to the backend using
    /// [`WalletWrite::set_transaction_status`]. A [`TransactionDataRequest::Enhancement`] request
    /// subsumes any previously existing [`TransactionDataRequest::GetStatus`] request.
    ///
    /// [`GetTransaction`]: crate::proto::service::compact_tx_streamer_client::CompactTxStreamerClient::get_transaction
    Enhancement([u8; 32]),
    /// Information about transactions that receive or spend funds belonging to the specified
    /// transparent address is requested.
    ///
    /// Fully transparent transactions, and transactions that do not contain either shielded inputs
    /// or shielded outputs belonging to the wallet, may not be discovered by the process of chain
    /// scanning; as a consequence, the wallet must actively query to find transactions that spend
    /// such funds. Ideally we'd be able to query by [`OutPoint`] but this is not currently
    /// functionality that is supported by the light wallet server.
    ///
    /// The caller evaluating this request on behalf of the wallet backend should respond to this
    /// request by detecting transactions involving the specified address within the provided block
    /// range; if using `lightwalletd` for access to chain data, this may be performed using the
    /// [`GetTaddressTxids`] RPC method. It should then call [`wallet::decrypt_and_store_transaction`]
    /// for each transaction so detected.
    ///
    /// [`GetTaddressTxids`]: crate::proto::service::compact_tx_streamer_client::CompactTxStreamerClient::get_taddress_txids
    SpendsFromAddress {
        address: *mut c_char,
        block_range_start: u32,
        /// An optional end height; no end height is represented as `-1`
        block_range_end: i64,
    },
}

/// A struct that contains a pointer to, and length information for, a heap-allocated
/// slice of [`FfiTransactionDataRequest`] values.
///
/// # Safety
///
/// - `ptr` must be non-null and must be valid for reads for `len * mem::size_of::<FfiTransactionDataRequest>()`
///   many bytes, and it must be properly aligned. This means in particular:
///   - The entire memory range pointed to by `ptr` must be contained within a single allocated
///     object. Slices can never span across multiple allocated objects.
///   - `ptr` must be non-null and aligned even for zero-length slices.
///   - `ptr` must point to `len` consecutive properly initialized values of type
///     [`FfiTransactionDataRequest`].
/// - The total size `len * mem::size_of::<FfiTransactionDataRequest>()` of the slice pointed to
///   by `ptr` must be no larger than isize::MAX. See the safety documentation of pointer::offset.
/// - See the safety documentation of [`FfiTransactionDataRequest`]
#[repr(C)]
pub struct FfiTransactionDataRequests {
    ptr: *mut FfiTransactionDataRequest,
    len: usize, // number of elems
}

impl FfiTransactionDataRequests {
    pub fn ptr_from_vec(v: Vec<FfiTransactionDataRequest>) -> *mut Self {
        let (ptr, len) = ptr_from_vec(v);
        Box::into_raw(Box::new(FfiTransactionDataRequests { ptr, len }))
    }
}

/// Frees an array of FfiTransactionDataRequest values as allocated by `zcashlc_transaction_data_requests`.
///
/// # Safety
///
/// - `ptr` if `ptr` is non-null it must point to a struct having the layout of [`FfiTransactionDataRequests`].
///   See the safety documentation of [`FfiTransactionDataRequests`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_transaction_data_requests(
    ptr: *mut FfiTransactionDataRequests,
) {
    if !ptr.is_null() {
        let s: Box<FfiTransactionDataRequests> = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec_with(s.ptr, s.len, |req| match req {
            FfiTransactionDataRequest::SpendsFromAddress { address, .. } => unsafe {
                zcashlc_string_free(*address)
            },
            _ => (),
        });
        drop(s);
    }
}

/// Returns a list of transaction data requests that the network client should satisfy.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Call [`zcashlc_free_transaction_data_requests`] to free the memory associated with the
///   returned pointer when done using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_transaction_data_requests(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
) -> *mut FfiTransactionDataRequests {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        Ok(FfiTransactionDataRequests::ptr_from_vec(
            db_data
                .transaction_data_requests()?
                .into_iter()
                .map(|req| match req {
                    TransactionDataRequest::GetStatus(txid) => {
                        FfiTransactionDataRequest::GetStatus(txid.into())
                    }
                    TransactionDataRequest::Enhancement(txid) => {
                        FfiTransactionDataRequest::Enhancement(txid.into())
                    }
                    TransactionDataRequest::SpendsFromAddress {
                        address,
                        block_range_start,
                        block_range_end,
                    } => FfiTransactionDataRequest::SpendsFromAddress {
                        address: CString::new(address.encode(&network)).unwrap().into_raw(),
                        block_range_start: block_range_start.into(),
                        block_range_end: block_range_end.map_or(-1, |h| u32::from(h).into()),
                    },
                })
                .collect(),
        ))
    });
    unwrap_exc_or_null(res)
}

//
// Tor support
//

/// Creates a Tor runtime.
///
/// # Safety
///
/// - `tor_dir` must be non-null and valid for reads for `tor_dir_len` bytes, and it must
///   have an alignment of `1`. Its contents must be a string representing a valid system
///   path in the operating system's preferred representation.
/// - The memory referenced by `tor_dir` must not be mutated for the duration of the
///   function call.
/// - The total size `tor_dir_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Call [`zcashlc_free_tor_runtime`] to free the memory associated with the returned
///   pointer when done using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_create_tor_runtime(
    tor_dir: *const u8,
    tor_dir_len: usize,
) -> *mut TorRuntime {
    let res = catch_panic(|| {
        let tor_dir = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(tor_dir, tor_dir_len)
        }));

        let tor = crate::tor::TorRuntime::create(tor_dir)?;

        Ok(Box::into_raw(Box::new(tor)))
    });
    unwrap_exc_or_null(res)
}

/// Frees a Tor runtime.
///
/// # Safety
///
/// - If `ptr` is non-null, it must point to a struct having the layout of [`TorRuntime`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_tor_runtime(ptr: *mut TorRuntime) {
    if !ptr.is_null() {
        let s: Box<TorRuntime> = unsafe { Box::from_raw(ptr) };
        drop(s);
    }
}

/// A decimal suitable for converting into an `NSDecimalNumber`.
#[repr(C)]
pub struct Decimal {
    mantissa: u64,
    exponent: i16,
    is_sign_negative: bool,
}

impl Decimal {
    fn from_rust(d: rust_decimal::Decimal) -> Option<Self> {
        d.mantissa().abs().try_into().ok().map(|mantissa| Self {
            mantissa,
            exponent: -(d.scale() as i16),
            is_sign_negative: d.is_sign_negative(),
        })
    }
}

/// Fetches the current ZEC-USD exchange rate over Tor.
///
/// The result is a [`Decimal`] struct containing the fields necessary to construct an
/// [`NSDecimalNumber`](https://developer.apple.com/documentation/foundation/nsdecimalnumber/1416003-init).
///
/// Returns a negative value on error.
///
/// # Safety
///
/// - `tor_runtime` must be non-null and point to a struct having the layout of
///   [`TorRuntime`].
/// - `tor_runtime` must not be passed to two FFI calls at the same time.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_get_exchange_rate_usd(tor_runtime: *mut TorRuntime) -> Decimal {
    // SAFETY: We ensure unwind safety by:
    // - using `*mut TorRuntime` and respecting mutability rules on the Swift side, to
    //   avoid observing the effects of a panic in another thread.
    // - discarding the `TorRuntime` whenever we get an error that is due to a panic.
    let tor_runtime = AssertUnwindSafe(tor_runtime);

    let res = catch_panic(|| {
        let tor_runtime =
            unsafe { tor_runtime.as_mut() }.ok_or_else(|| anyhow!("A Tor runtime is required"))?;

        let exchanges = cryptex::Exchanges::unauthenticated_known_with_gemini_trusted();

        let rate = tor_runtime.runtime().block_on(async {
            tor_runtime
                .client()
                .get_latest_zec_to_usd_rate(&exchanges)
                .await
        })?;

        Decimal::from_rust(rate)
            .ok_or_else(|| anyhow!("Exchange rate has too many significant figures: {}", rate))
    });
    unwrap_exc_or(
        res,
        Decimal::from_rust(rust_decimal::Decimal::NEGATIVE_ONE).expect("fits"),
    )
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

/// Converts the given vector into a raw pointer and length.
///
/// # Safety
///
/// The memory associated with the returned pointer must be freed with an appropriate
/// method ([`free_ptr_from_vec`] or [`free_ptr_from_vec_with`]).
fn ptr_from_vec<T>(v: Vec<T>) -> (*mut T, usize) {
    // Going from Vec<_> to Box<[_]> drops the (extra) `capacity`, subject to memory
    // fitting <https://doc.rust-lang.org/nightly/std/alloc/trait.Allocator.html#memory-fitting>.
    // However, the guarantee for this was reverted in 1.77.0; we need to keep an eye on
    // <https://github.com/rust-lang/rust/issues/125941>.
    let boxed_slice: Box<[T]> = v.into_boxed_slice();
    let len = boxed_slice.len();
    let fat_ptr: *mut [T] = Box::into_raw(boxed_slice);
    // It is guaranteed to be possible to obtain a raw pointer to the start
    // of a slice by casting the pointer-to-slice, as documented e.g. at
    // <https://doc.rust-lang.org/std/primitive.pointer.html#method.as_mut_ptr>.
    // TODO: replace with `as_mut_ptr()` when that is stable.
    let slim_ptr: *mut T = fat_ptr as _;
    (slim_ptr, len)
}

/// Frees vectors that had been converted into raw pointers.
///
/// # Safety
///
/// - `ptr` and `len` must have been returned from the same call to `ptr_from_vec`.
fn free_ptr_from_vec<T>(ptr: *mut T, len: usize) {
    free_ptr_from_vec_with(ptr, len, |_| ());
}

/// Frees vectors that had been converted into raw pointers, the elements of which
/// themselves contain raw pointers that need freeing.
///
/// # Safety
///
/// - `ptr` and `len` must have been returned from the same call to `ptr_from_vec`.
fn free_ptr_from_vec_with<T>(ptr: *mut T, len: usize, f: impl Fn(&mut T)) {
    if !ptr.is_null() {
        let mut s = unsafe { Box::from_raw(slice::from_raw_parts_mut(ptr, len)) };
        for k in s.iter_mut() {
            f(k);
        }
        drop(s);
    }
}
