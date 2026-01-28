#![deny(unsafe_op_in_unsafe_fn)]

use anyhow::{Context, anyhow};
use bitflags::bitflags;
use ffi_helpers::panic::catch_panic;
use http_body_util::BodyExt;
use nonempty::NonEmpty;
use pczt::{
    Pczt,
    roles::{combiner::Combiner, prover::Prover, redactor::Redactor},
};
use prost::Message;
use rand::rngs::OsRng;
use secrecy::Secret;
use transparent::{
    address::TransparentAddress,
    bundle::{OutPoint, TxOut},
    keys::TransparentKeyScope,
};
use zcash_script::script;

use std::collections::HashSet;
use std::convert::{Infallible, TryFrom, TryInto};
use std::error::Error;
use std::ffi::{CStr, CString, OsStr};
use std::num::{NonZeroU32, NonZeroUsize};
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::slice;
use std::time::UNIX_EPOCH;
use std::{array::TryFromSliceError, time::SystemTime};

use tor_rtcompat::ToplevelBlockOn as _;
use tracing::{debug, metadata::LevelFilter};
use tracing_subscriber::prelude::*;
use uuid::Uuid;
use zcash_client_backend::{
    data_api::{
        AccountPurpose, MaxSpendMode, TransactionStatus, Zip32Derivation,
        wallet::{self, SpendingKeys, extract_and_store_transaction_from_pczt},
    },
    fees::{SplitPolicy, StandardFeeRule, zip317::MultiOutputChangeStrategy},
    keys::{ReceiverRequirement, UnifiedAddressRequest, UnifiedFullViewingKey},
    tor::http::HttpError,
    wallet::{Exposure, GapMetadata},
};
use zcash_client_sqlite::{error::SqliteClientError, util::SystemClock};

use zcash_address::ZcashAddress;
use zcash_client_backend::{
    address::Address,
    data_api::{
        Account, AccountBirthday, InputSource, SeedRelevance, TransactionDataRequest,
        WalletCommitmentTrees, WalletRead, WalletWrite,
        chain::{CommitmentTreeRoot, scan_cached_blocks},
        scanning::ScanPriority,
        wallet::{
            create_pczt_from_proposal, create_proposed_transactions, decrypt_and_store_transaction,
            input_selection::GreedyInputSelector, propose_send_max_transfer, propose_shielding,
            propose_transfer,
        },
    },
    encoding::AddressCodec,
    fees::DustOutputPolicy,
    keys::{DecodingError, Era, UnifiedSpendingKey},
    proto::{proposal::Proposal, service::TreeState},
    tor::http::cryptex,
    wallet::{NoteId, OvkPolicy, WalletTransparentOutput},
    zip321::{Payment, TransactionRequest},
};
use zcash_client_sqlite::{
    AccountUuid, FsBlockDb, WalletDb,
    chain::{BlockMeta, init::init_blockmeta_db},
    wallet::init::{WalletMigrationError, init_wallet_db},
};
use zcash_primitives::{
    block::BlockHash,
    merkle_tree::HashSer,
    transaction::{Transaction, TxId},
};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{
    ShieldedProtocol,
    consensus::{
        BlockHeight, BranchId, Network,
        Network::{MainNetwork, TestNetwork},
    },
    memo::MemoBytes,
    value::{ZatBalance, Zatoshis},
};
use zip32::fingerprint::SeedFingerprint;

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

/// A handle to the wallet database connection.
///
/// This struct holds a persistent database connection that can be reused across
/// multiple FFI calls, reducing connection overhead during wallet sync operations.
pub struct WalletDbHandle {
    db: WalletDb<rusqlite::Connection, Network, SystemClock, OsRng>,
    network: Network,
}

impl WalletDbHandle {
    fn new(db_path: &Path, network: Network) -> anyhow::Result<Self> {
        let db = WalletDb::for_path(db_path, network, SystemClock, OsRng)
            .map_err(|e| anyhow!("Error opening wallet database: {}", e))?;
        Ok(Self { db, network })
    }

    pub fn db(&self) -> &WalletDb<rusqlite::Connection, Network, SystemClock, OsRng> {
        &self.db
    }

    pub fn db_mut(&mut self) -> &mut WalletDb<rusqlite::Connection, Network, SystemClock, OsRng> {
        &mut self.db
    }

    pub fn network(&self) -> Network {
        self.network
    }
}

/// A handle to the filesystem block database connection.
///
/// This struct holds a persistent database connection that can be reused across
/// multiple FFI calls, reducing connection overhead during wallet sync operations.
pub struct FsBlockDbHandle {
    db: FsBlockDb,
}

impl FsBlockDbHandle {
    fn new(db_root: &Path) -> anyhow::Result<Self> {
        let db = FsBlockDb::for_path(db_root)
            .map_err(|e| anyhow!("Error opening block database: {}", e))?;
        Ok(Self { db })
    }

    pub fn db(&self) -> &FsBlockDb {
        &self.db
    }

    pub fn db_mut(&mut self) -> &mut FsBlockDb {
        &mut self.db
    }
}

/// Opens a handle to the wallet database.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Call [`zcashlc_free_wallet_db_handle`] to free the memory associated with the returned pointer
///   when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_open_wallet_db(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
) -> *mut WalletDbHandle {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(db_data, db_data_len)
        }));

        let handle = WalletDbHandle::new(db_data, network)?;
        Ok(Box::into_raw(Box::new(handle)))
    });
    unwrap_exc_or_null(res)
}

/// Frees a wallet database handle.
///
/// # Safety
///
/// - If `ptr` is non-null, it must be a pointer returned by [`zcashlc_open_wallet_db`]
///   that has not previously been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_wallet_db_handle(ptr: *mut WalletDbHandle) {
    if !ptr.is_null() {
        let handle: Box<WalletDbHandle> = unsafe { Box::from_raw(ptr) };
        drop(handle);
    }
}

/// Opens a handle to the filesystem block database.
///
/// # Safety
///
/// - `fs_block_db_root` must be non-null and valid for reads for `fs_block_db_root_len` bytes,
///   and it must have an alignment of `1`. Its contents must be a string representing a valid
///   system path in the operating system's preferred representation.
/// - The memory referenced by `fs_block_db_root` must not be mutated for the duration of the
///   function call.
/// - The total size `fs_block_db_root_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Call [`zcashlc_free_fs_block_db_handle`] to free the memory associated with the returned pointer
///   when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_open_fs_block_db(
    fs_block_db_root: *const u8,
    fs_block_db_root_len: usize,
) -> *mut FsBlockDbHandle {
    let res = catch_panic(|| {
        let fs_block_db_root = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(fs_block_db_root, fs_block_db_root_len)
        }));

        let handle = FsBlockDbHandle::new(fs_block_db_root)?;
        Ok(Box::into_raw(Box::new(handle)))
    });
    unwrap_exc_or_null(res)
}

/// Frees a filesystem block database handle.
///
/// # Safety
///
/// - If `ptr` is non-null, it must be a pointer returned by [`zcashlc_open_fs_block_db`]
///   that has not previously been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_fs_block_db_handle(ptr: *mut FsBlockDbHandle) {
    if !ptr.is_null() {
        let handle: Box<FsBlockDbHandle> = unsafe { Box::from_raw(ptr) };
        drop(handle);
    }
}

fn account_uuid_from_bytes(uuid_bytes: *const u8) -> Result<AccountUuid, TryFromSliceError> {
    let uuid_bytes = unsafe { slice::from_raw_parts(uuid_bytes, 16) };
    Ok(AccountUuid::from_uuid(Uuid::from_bytes(
        <[u8; 16]>::try_from(uuid_bytes)?,
    )))
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_error_message_utf8(buf: *mut c_char, length: i32) -> i32 {
    unsafe { ffi_helpers::error_handling::error_message_utf8(buf, length) }
}

/// Clears the record of the last error message.
#[unsafe(no_mangle)]
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
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - `seed` must be non-null and valid for reads for `seed_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `seed` must not be mutated for the duration of the function call.
/// - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
///   of pointer::offset.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_init_data_database(
    wallet_db_handle: *mut WalletDbHandle,
    seed: *const u8,
    seed_len: usize,
) -> i32 {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;

        let seed = if seed.is_null() {
            None
        } else {
            Some(Secret::new(
                (unsafe { slice::from_raw_parts(seed, seed_len) }).to_vec(),
            ))
        };

        match init_wallet_db(wallet_db_handle.db_mut(), seed) {
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

/// Returns a list of the accounts in the wallet.
///
/// # Safety
///
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - Call [`zcashlc_free_accounts`] to free the memory associated with the returned pointer
///   when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_list_accounts(
    wallet_db_handle: *mut WalletDbHandle,
) -> *mut ffi::Accounts {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_ref() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;

        Ok(ffi::Accounts::ptr_from_vec(
            wallet_db_handle
                .db()
                .get_account_ids()?
                .into_iter()
                .map(ffi::Uuid::new)
                .collect::<Vec<_>>(),
        ))
    });
    unwrap_exc_or_null(res)
}

/// Returns the account data for the specified account identifier, or the [`ffi::Account::NOT_FOUND`]
/// sentinel value if the account id does not correspond to an account in the wallet.
///
/// # Safety
///
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
///   function call.
/// - Call [`zcashlc_free_account`] to free the memory associated with the returned pointer
///   when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_get_account(
    wallet_db_handle: *mut WalletDbHandle,
    account_uuid_bytes: *const u8,
) -> *mut ffi::Account {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_ref() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;

        Ok(Box::into_raw(Box::new(
            wallet_db_handle
                .db()
                .get_account(account_uuid)?
                .map_or(ffi::Account::NOT_FOUND, |account| {
                    ffi::Account::from_account(&account, &wallet_db_handle.network())
                }),
        )))
    });
    unwrap_exc_or_null(res)
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
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - `seed` must be non-null and valid for reads for `seed_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `seed` must not be mutated for the duration of the function call.
/// - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
///   of pointer::offset.
/// - `treestate` must be non-null and valid for reads for `treestate_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `treestate` must not be mutated for the duration of the function call.
/// - The total size `treestate_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Call [`zcashlc_free_binary_key`] to free the memory associated with the returned pointer when
///   you are finished using it.
///
/// [ZIP 316]: https://zips.z.cash/zip-0316
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_create_account(
    wallet_db_handle: *mut WalletDbHandle,
    seed: *const u8,
    seed_len: usize,
    treestate: *const u8,
    treestate_len: usize,
    recover_until: i64,
    account_name: *const c_char,
    key_source: *const c_char,
) -> *mut ffi::BinaryKey {
    use zcash_client_backend::data_api::BirthdayError;

    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
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

        let account_name = unsafe { CStr::from_ptr(account_name).to_str()? };
        let key_source = (!key_source.is_null())
            .then(|| unsafe { CStr::from_ptr(key_source).to_str() })
            .transpose()?;

        let (account_uuid, usk) = wallet_db_handle
            .db_mut()
            .create_account(account_name, &seed, &birthday, key_source)
            .map_err(|e| anyhow!("Error while initializing accounts: {}", e))?;

        let encoded = usk.to_bytes(Era::Orchard);
        Ok(Box::into_raw(Box::new(ffi::BinaryKey::new(
            account_uuid,
            encoded,
        ))))
    });
    unwrap_exc_or_null(res)
}

/// Adds a new account to the wallet by importing the UFVK that will be used to detect incoming
/// payments.
///
/// Derivation metadata may optionally be included. To indicate that no derivation metadata is
/// available, the `seed_fingerprint` argument should be set to the null pointer and
/// `hd_account_index` should be set to the value `u32::MAX`. Derivation metadata will not be
/// stored unless both the seed fingerprint and the HD account index are provided.
///
/// Returns the globally unique identifier for the account.
///
/// # Safety
///
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - `ufvk` must be non-null and must point to a null-terminated UTF-8 string.
/// - `treestate` must be non-null and valid for reads for `treestate_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `treestate` must not be mutated for the duration of the function call.
/// - The total size `treestate_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `seed_fingerprint` must either be either null or valid for reads for 32 bytes, and it must
///   have an alignment of `1`.
///
/// - Call [`zcashlc_free_ffi_uuid`] to free the memory associated with the returned pointer when
///   you are finished using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_import_account_ufvk(
    wallet_db_handle: *mut WalletDbHandle,
    ufvk: *const c_char,
    treestate: *const u8,
    treestate_len: usize,
    recover_until: i64,
    purpose: u32,
    account_name: *const c_char,
    key_source: *const c_char,
    seed_fingerprint: *const u8,
    hd_account_index_raw: u32,
) -> *mut ffi::Uuid {
    use zcash_client_backend::data_api::BirthdayError;

    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let network = wallet_db_handle.network();
        let ufvk_str = unsafe { CStr::from_ptr(ufvk).to_str()? };
        let ufvk = UnifiedFullViewingKey::decode(&network, ufvk_str).map_err(|e| {
            anyhow!(
                "Value \"{}\" did not decode as a valid UFVK: {}",
                ufvk_str,
                e
            )
        })?;
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

        let hd_account_index = zip32::AccountId::try_from(hd_account_index_raw).ok();
        let seed_fp = (!seed_fingerprint.is_null())
            .then(|| {
                <[u8; 32]>::try_from(unsafe { slice::from_raw_parts(seed_fingerprint, 32) })
                    .ok()
                    .map(SeedFingerprint::from_bytes)
            })
            .flatten();

        if hd_account_index.is_some() != seed_fp.is_some() {
            return Err(anyhow!(
                "Seed fingerprint and ZIP 32 account index must either both be valid or both be absent/invalid."
            ));
        }

        let derivation = seed_fp
            .zip(hd_account_index)
            .map(|(fp, idx)| Zip32Derivation::new(fp, idx));

        let purpose = match purpose {
            0 => Ok(AccountPurpose::Spending { derivation }),
            1 => Ok(AccountPurpose::ViewOnly),
            _ => Err(anyhow!(
                "Account purpose must be either 0 (Spending) or 1 (ViewOnly)"
            )),
        }?;

        let account_name = unsafe { CStr::from_ptr(account_name).to_str()? };
        let key_source = (!key_source.is_null())
            .then(|| unsafe { CStr::from_ptr(key_source).to_str() })
            .transpose()?;

        let account = wallet_db_handle
            .db_mut()
            .import_account_ufvk(account_name, &ufvk, &birthday, purpose, key_source)
            .map_err(|e| anyhow!("Error while initializing accounts: {}", e))?;

        Ok(Box::into_raw(Box::new(ffi::Uuid::new(account.id()))))
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
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - `seed` must be non-null and valid for reads for `seed_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `seed` must not be mutated for the duration of the function call.
/// - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
///   of pointer::offset.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_is_seed_relevant_to_any_derived_account(
    wallet_db_handle: *mut WalletDbHandle,
    seed: *const u8,
    seed_len: usize,
) -> i8 {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_ref() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let seed = Secret::new((unsafe { slice::from_raw_parts(seed, seed_len) }).to_vec());

        // Replicate the logic from `initWalletDb`.
        Ok(
            match wallet_db_handle
                .db()
                .seed_relevance_to_derived_accounts(&seed)?
            {
                SeedRelevance::Relevant { .. } | SeedRelevance::NoAccounts => 1,
                SeedRelevance::NotRelevant | SeedRelevance::NoDerivedAccounts => 0,
            },
        )
    });
    unwrap_exc_or(res, -1)
}

/// Deletes the specified account, and all transactions that exclusively involve it, from the
/// wallet database.
///
/// WARNING: This is a destructive operation and may result in the permanent loss of
/// potentially important information that is not recoverable from chain data, including:
/// * Data about transactions sent by the account for which [`OvkPolicy::Discard`] (or
///   [`OvkPolicy::Custom`] with random OVKs) was used;
/// * Data related to transactions that the account attempted to send that expired or were
///   otherwise invalidated without having been mined in the main chain;
/// * Data related to transactions that were observed in the mempool as having inputs or
///   outputs that involved the account, but that were never mined in the main chain;
/// * Data related to transactions that were received by the wallet in a mined block, where
///   that block was later un-mined in a chain reorg and the transaction was either invalidated
///   or was never re-mined.
///
/// Returns `true` on success, or `false` if an error is raised.
///
/// # Safety
///
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
///   alignment of `1`.
///
/// [`OvkPolicy::Discard`]: zcash_client_backend::wallet::OvkPolicy::Discard
/// [`OvkPolicy::Custom`]: zcash_client_backend::wallet::OvkPolicy::Custom
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_delete_account(
    wallet_db_handle: *mut WalletDbHandle,
    account_uuid_bytes: *const u8,
) -> bool {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;

        wallet_db_handle.db_mut().delete_account(account_uuid)?;

        Ok(true)
    });

    unwrap_exc_or(res, false)
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
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
///   function call.
/// - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
///   when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_get_current_address(
    wallet_db_handle: *mut WalletDbHandle,
    account_uuid_bytes: *const u8,
) -> *mut c_char {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_ref() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;
        let network = wallet_db_handle.network();

        match wallet_db_handle.db().get_last_generated_address_matching(
            account_uuid,
            UnifiedAddressRequest::AllAvailableKeys,
        ) {
            Ok(Some(ua)) => {
                let address_str = ua.encode(&network);
                Ok(CString::new(address_str).unwrap().into_raw())
            }
            Ok(None) => Err(anyhow!(
                "No payment address was available for account {:?}",
                account_uuid
            )),
            Err(e) => Err(anyhow!("Error while fetching address: {}", e)),
        }
    });
    unwrap_exc_or_null(res)
}

/// Generates and returns an ephemeral address for one-time use, such as when receiving a swap from
/// a decentralized exchange.
///
/// # Safety
///
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
///   function call.
/// - Call [`zcashlc_free_single_use_address`] to free the memory associated with the returned pointer
///   when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_get_single_use_taddr(
    wallet_db_handle: *mut WalletDbHandle,
    account_uuid_bytes: *const u8,
) -> *mut ffi::SingleUseTaddr {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let network = wallet_db_handle.network();
        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;

        match wallet_db_handle
            .db_mut()
            .reserve_next_n_ephemeral_addresses(account_uuid, 1)
        {
            Ok(addrs) => {
                if let Some((addr, meta)) = addrs.first() {
                    match meta.exposure() {
                        Exposure::Exposed {
                            gap_metadata:
                                GapMetadata::InGap {
                                    gap_position,
                                    gap_limit,
                                },
                            ..
                        } => Ok(ffi::SingleUseTaddr::from_rust(
                            &network,
                            addr,
                            gap_position,
                            gap_limit,
                        )),
                        _ => Err(anyhow!(
                            "Exposure metadata invalid for a newly generated address."
                        )),
                    }
                } else {
                    Err(anyhow!("Unable to reserve a new one-time-use address"))
                }
            }
            Err(e) => Err(anyhow!(
                "Error while generating one-time-use address: {}",
                e
            )),
        }
    });
    unwrap_exc_or_null(res)
}

bitflags! {
    /// A set of bitflags used to specify the types of receivers a unified address can contain. The
    /// flag bits chosen here for each receiver type are incidentally the same as those used for
    /// serialization in `zcash_client_sqlite`; consistency here isn't really meaningful but is
    /// less confusing than letting them diverge.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct ReceiverFlags: u32 {
        /// The requested address can receive transparent p2pkh outputs.
        const P2PKH = 0b00000001;
        /// The requested address can receive Sapling outputs.
        const SAPLING = 0b00000100;
        /// The requested address can receive Orchard outputs.
        const ORCHARD = 0b00001000;
    }
}

impl ReceiverFlags {
    fn to_address_request(self) -> Result<UnifiedAddressRequest, ()> {
        UnifiedAddressRequest::custom(
            if self.contains(ReceiverFlags::ORCHARD) {
                ReceiverRequirement::Require
            } else {
                ReceiverRequirement::Omit
            },
            if self.contains(ReceiverFlags::SAPLING) {
                ReceiverRequirement::Require
            } else {
                ReceiverRequirement::Omit
            },
            if self.contains(ReceiverFlags::P2PKH) {
                ReceiverRequirement::Require
            } else {
                ReceiverRequirement::Omit
            },
        )
    }
}

/// Returns a newly-generated unified payment address for the specified account, with the next
/// available diversifier and the specified set of receivers.
///
/// The set of receivers to include in the generated address is specified by a byte which may have
/// any of the following bits set:
/// * P2PKH = 0b00000001
/// * SAPLING = 0b00000100
/// * ORCHARD = 0b00001000
///
/// For each bit set, a corresponding receiver will be required to be generated. If no
/// corresponding viewing key exists in the wallet for a required receiver, this will return an
/// error. At present, p2pkh-only unified addresses are not supported.
///
/// # Safety
///
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
///   function call.
/// - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
///   when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_get_next_available_address(
    wallet_db_handle: *mut WalletDbHandle,
    account_uuid_bytes: *const u8,
    receiver_flags: u32,
) -> *mut c_char {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let network = wallet_db_handle.network();
        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;
        let receiver_flags = ReceiverFlags::from_bits(receiver_flags)
            .ok_or_else(|| anyhow!("Invalid unified address receiver flags {}", receiver_flags))?;
        let address_request = receiver_flags.to_address_request().map_err(|_| {
            anyhow!(
                "Could not generate a valid unified address for flags {}",
                receiver_flags.bits()
            )
        })?;

        match wallet_db_handle
            .db_mut()
            .get_next_available_address(account_uuid, address_request)
        {
            Ok(Some((ua, _))) => {
                let address_str = ua.encode(&network);
                Ok(CString::new(address_str).unwrap().into_raw())
            }
            Ok(None) => Err(anyhow!(
                "No payment address was available for account {:?}",
                account_uuid
            )),
            Err(e) => Err(anyhow!("Error while fetching address: {}", e)),
        }
    });
    unwrap_exc_or_null(res)
}

/// Returns a list of the transparent addresses that have been allocated for the provided account,
/// including potentially-unrevealed public-scope and private-scope (change) addresses within the
/// gap limit, which is currently set to 10 for public-scope addresses and 5 for change addresses.
///
/// # Safety
///
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
///   function call.
/// - Call [`zcashlc_free_keys`] to free the memory associated with the returned pointer
///   when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_list_transparent_receivers(
    wallet_db_handle: *mut WalletDbHandle,
    account_uuid_bytes: *const u8,
) -> *mut ffi::EncodedKeys {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_ref() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let network = wallet_db_handle.network();
        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;

        // Zashi does not support standalone keys, so we do not request standalone receivers.
        match wallet_db_handle
            .db()
            .get_transparent_receivers(account_uuid, true, false)
        {
            Ok(receivers) => {
                let keys = receivers
                    .keys()
                    .map(|receiver| {
                        let address_str = receiver.encode(&network);
                        ffi::EncodedKey::new(account_uuid, &address_str)
                    })
                    .collect::<Vec<_>>();

                Ok(ffi::EncodedKeys::ptr_from_vec(keys))
            }
            Err(e) => Err(anyhow!("Error while fetching transparent receivers: {}", e)),
        }
    });
    unwrap_exc_or_null(res)
}

/// Returns the verified transparent balance for `address`, which ignores utxos that have been
/// received too recently and are not yet deemed spendable according to `confirmations_policy`.
///
/// # Safety
///
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - `address` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `address` must not be mutated for the duration of the function call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_get_verified_transparent_balance(
    wallet_db_handle: *mut WalletDbHandle,
    address: *const c_char,
    confirmations_policy: ffi::ConfirmationsPolicy,
) -> i64 {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_ref() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let network = wallet_db_handle.network();
        let addr = unsafe { CStr::from_ptr(address).to_str()? };
        let taddr = TransparentAddress::decode(&network, addr)?;
        let confirmations_policy = wallet::ConfirmationsPolicy::try_from(confirmations_policy)?;
        let (target, _) = wallet_db_handle
            .db()
            .get_target_and_anchor_heights(confirmations_policy.untrusted())
            .map_err(|e| anyhow!("Error while fetching target height: {}", e))?
            .context("Target height not available; scan required.")?;
        let utxos = wallet_db_handle
            .db()
            .get_spendable_transparent_outputs(&taddr, target, confirmations_policy)
            .map_err(|e| anyhow!("Error while fetching verified transparent balance: {}", e))?;
        let amount = utxos
            .iter()
            .map(|utxo| utxo.txout().value())
            .sum::<Option<Zatoshis>>()
            .ok_or_else(|| anyhow!("Balance overflowed MAX_MONEY."))?;
        Ok(ZatBalance::from(amount).into())
    });
    unwrap_exc_or(res, -1)
}

/// Returns the verified transparent balance for `account`, which ignores utxos that have been
/// received too recently and are not yet deemed spendable according to `confirmations_policy`.
///
/// # Safety
///
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
///   function call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_get_verified_transparent_balance_for_account(
    wallet_db_handle: *mut WalletDbHandle,
    account_uuid_bytes: *const u8,
    confirmations_policy: ffi::ConfirmationsPolicy,
) -> i64 {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_ref() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;

        let (target, _) = wallet_db_handle
            .db()
            .get_target_and_anchor_heights(NonZeroU32::MIN)
            .map_err(|e| anyhow!("Error while fetching anchor height: {}", e))?
            .context("Target height not available; scan required.")?;
        // Zashi does not support standalone keys, so we do not request standalone receivers.
        let receivers = wallet_db_handle
            .db()
            .get_transparent_receivers(account_uuid, true, false)
            .map_err(|e| {
                anyhow!(
                    "Error while fetching transparent receivers for {:?}: {}",
                    account_uuid,
                    e,
                )
            })?;
        let confirmations_policy = wallet::ConfirmationsPolicy::try_from(confirmations_policy)?;
        let amount = receivers
            .keys()
            .map(|taddr| {
                wallet_db_handle
                    .db()
                    .get_spendable_transparent_outputs(taddr, target, confirmations_policy)
                    .map_err(|e| {
                        anyhow!("Error while fetching verified transparent balance: {}", e)
                    })
            })
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .flatten()
            .map(|utxo| utxo.txout().value())
            .sum::<Option<Zatoshis>>()
            .ok_or_else(|| anyhow!("Balance overflowed MAX_MONEY."))?;

        Ok(ZatBalance::from(amount).into())
    });
    unwrap_exc_or(res, -1)
}

/// Returns the balance for `address`, including all UTXOs that we know about.
///
/// # Safety
///
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - `address` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `address` must not be mutated for the duration of the function call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_get_total_transparent_balance(
    wallet_db_handle: *mut WalletDbHandle,
    address: *const c_char,
) -> i64 {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_ref() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let network = wallet_db_handle.network();
        let addr = unsafe { CStr::from_ptr(address).to_str()? };
        let taddr = TransparentAddress::decode(&network, addr)?;
        let (target, _) = wallet_db_handle
            .db()
            .get_target_and_anchor_heights(NonZeroU32::MIN)
            .map_err(|e| anyhow!("Error while fetching target height: {}", e))?
            .context("Target height not available; scan required.")?;
        let amount = wallet_db_handle
            .db()
            .get_spendable_transparent_outputs(
                &taddr,
                target,
                wallet::ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, true),
            )
            .map_err(|e| anyhow!("Error while fetching total transparent balance: {}", e))?
            .iter()
            .map(|utxo| utxo.txout().value())
            .sum::<Option<Zatoshis>>()
            .ok_or_else(|| anyhow!("Balance overflowed MAX_MONEY."))?;

        Ok(ZatBalance::from(amount).into())
    });
    unwrap_exc_or(res, -1)
}

/// Returns the balance for `account`, including all UTXOs that we know about.
///
/// # Safety
///
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
///   function call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_get_total_transparent_balance_for_account(
    wallet_db_handle: *mut WalletDbHandle,
    account_uuid_bytes: *const u8,
) -> i64 {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_ref() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;

        let (target, _) = wallet_db_handle
            .db()
            .get_target_and_anchor_heights(NonZeroU32::MIN)
            .map_err(|e| anyhow!("Error while fetching anchor height: {}", e))?
            .context("height not available; scan required.")?;
        let confirmations_policy =
            wallet::ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, true);
        let balances = wallet_db_handle
            .db()
            .get_transparent_balances(account_uuid, target, confirmations_policy)
            .map_err(|e| {
                anyhow!(
                    "Error while fetching transparent balances for {:?}: {}",
                    account_uuid,
                    e,
                )
            })?;
        let amount = balances
            .values()
            .map(|(_, balance)| balance.total())
            .sum::<Option<Zatoshis>>()
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
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - `txid_bytes` must be non-null and valid for reads for 32 bytes, and it must have an alignment
///   of `1`.
/// - `memo_bytes_ret` must be non-null and must point to an allocated 512-byte region of memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_get_memo(
    wallet_db_handle: *mut WalletDbHandle,
    txid_bytes: *const u8,
    output_pool: u32,
    output_index: u16,
    memo_bytes_ret: *mut u8,
) -> bool {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_ref() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;

        let txid_bytes = unsafe { slice::from_raw_parts(txid_bytes, 32) };
        let txid = TxId::read(txid_bytes)?;

        let protocol = parse_protocol(output_pool).ok_or(anyhow!(
            "Shielded protocol not recognized for code: {}",
            output_pool
        ))?;

        let memo_bytes = wallet_db_handle
            .db()
            .get_memo(NoteId::new(txid, protocol, output_index))
            .map_err(|e| anyhow!("An error occurred retrieving the memo: {}", e))
            .and_then(|memo| memo.ok_or(anyhow!("Memo not available")))
            .map(|memo| memo.encode())?;

        unsafe { memo_bytes_ret.copy_from(memo_bytes.as_slice().as_ptr(), 512) };
        Ok(true)
    });
    unwrap_exc_or(res, false)
}

#[unsafe(no_mangle)]
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
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_rewind_to_height(
    wallet_db_handle: *mut WalletDbHandle,
    height: u32,
    safe_rewind_ret: *mut i64,
) -> i64 {
    unsafe {
        *safe_rewind_ret = -1;
    }
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;

        let height = BlockHeight::from(height);
        let result_height = wallet_db_handle.db_mut().truncate_to_height(height);

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

/// Adds a sequence of Sapling subtree roots to the data store.
///
/// Returns true if the subtrees could be stored, false otherwise. When false is returned,
/// caller should check for errors.
///
/// # Safety
///
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - `roots` must be non-null and initialized.
/// - The memory referenced by `roots` must not be mutated for the duration of the function call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_put_sapling_subtree_roots(
    wallet_db_handle: *mut WalletDbHandle,
    start_index: u64,
    roots: *const ffi::SubtreeRoots,
) -> bool {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;

        let roots = unsafe { roots.as_ref().unwrap() };
        let roots_slice: &[ffi::SubtreeRoot] =
            unsafe { slice::from_raw_parts(roots.ptr, roots.len) };

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

        wallet_db_handle
            .db_mut()
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
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - `roots` must be non-null and initialized.
/// - The memory referenced by `roots` must not be mutated for the duration of the function call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_put_orchard_subtree_roots(
    wallet_db_handle: *mut WalletDbHandle,
    start_index: u64,
    roots: *const ffi::SubtreeRoots,
) -> bool {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;

        let roots = unsafe { roots.as_ref().unwrap() };
        let roots_slice: &[ffi::SubtreeRoot] =
            unsafe { slice::from_raw_parts(roots.ptr, roots.len) };

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

        wallet_db_handle
            .db_mut()
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
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_update_chain_tip(
    wallet_db_handle: *mut WalletDbHandle,
    height: i32,
) -> bool {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let height = BlockHeight::try_from(height)?;

        wallet_db_handle
            .db_mut()
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
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_fully_scanned_height(
    wallet_db_handle: *mut WalletDbHandle,
) -> i64 {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_ref() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;

        match wallet_db_handle.db().block_fully_scanned() {
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
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_max_scanned_height(wallet_db_handle: *mut WalletDbHandle) -> i64 {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_ref() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;

        match wallet_db_handle.db().block_max_scanned() {
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

/// Returns the account balances and sync status given the specified minimum number of
/// confirmations.
///
/// Returns `fully_scanned_height = -1` if the wallet has no balance data available.
///
/// # Safety
///
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - Call [`zcashlc_free_wallet_summary`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_get_wallet_summary(
    wallet_db_handle: *mut WalletDbHandle,
    confirmations_policy: ffi::ConfirmationsPolicy,
) -> *mut ffi::WalletSummary {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_ref() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let confirmations_policy = wallet::ConfirmationsPolicy::try_from(confirmations_policy)?;

        match wallet_db_handle
            .db()
            .get_wallet_summary(confirmations_policy)
            .map_err(|e| anyhow!("Error while fetching wallet summary: {}", e))?
        {
            Some(summary) => ffi::WalletSummary::some(summary),
            None => Ok(ffi::WalletSummary::none()),
        }
    });
    unwrap_exc_or_null(res)
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
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - Call [`zcashlc_free_scan_ranges`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_suggest_scan_ranges(
    wallet_db_handle: *mut WalletDbHandle,
) -> *mut ffi::ScanRanges {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_ref() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;

        let ranges = wallet_db_handle
            .db()
            .suggest_scan_ranges()
            .map_err(|e| anyhow!("Error while fetching suggested scan ranges: {}", e))?;

        let ffi_ranges = ranges
            .into_iter()
            .map(|scan_range| ffi::ScanRange {
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

        Ok(ffi::ScanRanges::ptr_from_vec(ffi_ranges))
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
/// - `wallet_db_handle` must be a non-null pointer returned by [`zcashlc_open_wallet_db`] that has not
///   previously been freed.
/// - `wallet_db_handle` must not be passed to two FFI calls at the same time.
/// - `fs_block_db_handle` must be a non-null pointer returned by [`zcashlc_open_fs_block_db`] that has not
///   previously been freed.
/// - `fs_block_db_handle` must not be passed to two FFI calls at the same time.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_scan_blocks(
    wallet_db_handle: *mut WalletDbHandle,
    fs_block_db_handle: *mut FsBlockDbHandle,
    from_height: i32,
    from_state: *const u8,
    from_state_len: usize,
    scan_limit: u32,
) -> *mut ffi::ScanSummary {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let fs_block_db_handle = AssertUnwindSafe(fs_block_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Wallet database handle is required"))?;
        let fs_block_db_handle = unsafe { fs_block_db_handle.as_ref() }
            .ok_or_else(|| anyhow!("Block database handle is required"))?;
        let network = wallet_db_handle.network();
        let from_height = BlockHeight::try_from(from_height)?;
        let from_state =
            TreeState::decode(unsafe { slice::from_raw_parts(from_state, from_state_len) })
                .map_err(|e| anyhow!("Invalid TreeState: {}", e))?
                .to_chain_state()?;
        let limit = usize::try_from(scan_limit)?;
        match scan_cached_blocks(
            &network,
            fs_block_db_handle.db(),
            wallet_db_handle.db_mut(),
            from_height,
            &from_state,
            limit,
        ) {
            Ok(scan_summary) => Ok(ffi::ScanSummary::new(scan_summary)),
            Err(e) => Err(anyhow!("Error while scanning blocks: {}", e)),
        }
    });
    unwrap_exc_or_null(res)
}

/// Inserts a UTXO into the wallet database.
///
/// # Safety
///
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - `txid_bytes` must be non-null and valid for reads for `txid_bytes_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `txid_bytes` must not be mutated for the duration of the function call.
/// - The total size `txid_bytes_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `script_bytes` must be non-null and valid for reads for `script_bytes_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `script_bytes` must not be mutated for the duration of the function call.
/// - The total size `script_bytes_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_put_utxo(
    wallet_db_handle: *mut WalletDbHandle,
    txid_bytes: *const u8,
    txid_bytes_len: usize,
    index: i32,
    script_bytes: *const u8,
    script_bytes_len: usize,
    value: i64,
    height: i32,
) -> bool {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;

        let txid_bytes = unsafe { slice::from_raw_parts(txid_bytes, txid_bytes_len) };
        let mut txid = [0u8; 32];
        txid.copy_from_slice(txid_bytes);

        let script_bytes = unsafe { slice::from_raw_parts(script_bytes, script_bytes_len) };
        let script_pubkey = transparent::address::Script(script::Code(script_bytes.to_vec()));

        let output = WalletTransparentOutput::from_parts(
            OutPoint::new(txid, index as u32),
            TxOut::new(
                Zatoshis::from_nonnegative_i64(value).map_err(|_| anyhow!("Invalid UTXO value"))?,
                script_pubkey,
            ),
            Some(BlockHeight::from(height as u32)),
        )
        .ok_or_else(|| {
            anyhow!(
                "{:?} is not a valid P2PKH or P2SH script_pubkey",
                script_bytes
            )
        })?;
        match wallet_db_handle
            .db_mut()
            .put_received_transparent_utxo(&output)
        {
            Ok(_) => Ok(true),
            Err(e) => Err(anyhow!("Error while inserting UTXO: {}", e)),
        }
    });
    unwrap_exc_or(res, false)
}

//
// FsBlock Interfaces
//

/// # Safety
/// Initializes the `FsBlockDb` sqlite database. Does nothing if already created
///
/// Returns true when successful, false otherwise. When false is returned caller
/// should check for errors.
///
/// - `fs_block_db_handle` must be a non-null pointer returned by [`zcashlc_open_fs_block_db`] that has not
///   previously been freed.
/// - `fs_block_db_handle` must not be passed to two FFI calls at the same time.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_init_block_metadata_db(
    fs_block_db_handle: *mut FsBlockDbHandle,
) -> bool {
    let fs_block_db_handle = AssertUnwindSafe(fs_block_db_handle);
    let res = catch_panic(|| {
        let fs_block_db_handle = unsafe { fs_block_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Block database handle is required"))?;

        match init_blockmeta_db(fs_block_db_handle.db_mut()) {
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
/// - `fs_block_db_handle` must be a non-null pointer returned by [`zcashlc_open_fs_block_db`] that has not
///   previously been freed.
/// - `fs_block_db_handle` must not be passed to two FFI calls at the same time.
/// - Block metadata represented in `blocks_meta` must be non-null. Caller must guarantee that the
///   memory reference by this pointer is not freed up, dereferenced or invalidated while this
///   function is invoked.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_write_block_metadata(
    fs_block_db_handle: *mut FsBlockDbHandle,
    blocks_meta: *mut ffi::BlocksMeta,
) -> bool {
    let fs_block_db_handle = AssertUnwindSafe(fs_block_db_handle);
    let res = catch_panic(|| {
        let fs_block_db_handle = unsafe { fs_block_db_handle.as_ref() }
            .ok_or_else(|| anyhow!("Block database handle is required"))?;

        let blocks_meta: Box<ffi::BlocksMeta> = unsafe { Box::from_raw(blocks_meta) };

        let blocks_metadata_slice: &mut [ffi::BlockMeta] =
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

        match fs_block_db_handle.db().write_block_metadata(&blocks) {
            Ok(()) => Ok(true),
            Err(e) => Err(anyhow!(
                "Failed to write block metadata to FsBlockDb: {:?}",
                e
            )),
        }
    });
    unwrap_exc_or(res, false)
}

/// Rewinds the block cache to the given height.
///
/// If the requested height is greater than or equal to the height of the last scanned
/// block, this function does nothing.
///
/// # Safety
///
/// - `fs_block_db_handle` must be a non-null pointer returned by [`zcashlc_open_fs_block_db`] that has not
///   previously been freed.
/// - `fs_block_db_handle` must not be passed to two FFI calls at the same time.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_rewind_fs_block_cache_to_height(
    fs_block_db_handle: *mut FsBlockDbHandle,
    height: i32,
) -> bool {
    let fs_block_db_handle = AssertUnwindSafe(fs_block_db_handle);
    let res = catch_panic(|| {
        let fs_block_db_handle = unsafe { fs_block_db_handle.as_ref() }
            .ok_or_else(|| anyhow!("Block database handle is required"))?;
        let height = BlockHeight::try_from(height)?;
        fs_block_db_handle
            .db()
            .truncate_to_height(height)
            .map(|_| true)
            .map_err(|e| {
                anyhow!(
                    "Error while rewinding block cache to height {}: {}",
                    height,
                    e
                )
            })
    });
    unwrap_exc_or(res, false)
}

/// Get the latest cached block height in the filesystem block cache
///
/// Returns a non-negative block height, -1 if empty, or -2 if an error occurred.
///
/// # Safety
///
/// - `fs_block_db_handle` must be a non-null pointer returned by [`zcashlc_open_fs_block_db`] that has not
///   previously been freed.
/// - `fs_block_db_handle` must not be passed to two FFI calls at the same time.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_latest_cached_block_height(
    fs_block_db_handle: *mut FsBlockDbHandle,
) -> i32 {
    let fs_block_db_handle = AssertUnwindSafe(fs_block_db_handle);
    let res = catch_panic(|| {
        let fs_block_db_handle = unsafe { fs_block_db_handle.as_ref() }
            .ok_or_else(|| anyhow!("Block database handle is required"))?;

        match fs_block_db_handle.db().get_max_cached_height() {
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

/// Decrypts whatever parts of the specified transaction it can and stores them in the wallet database.
///
/// # Safety
///
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - `tx` must be non-null and valid for reads for `tx_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `tx` must not be mutated for the duration of the function call.
/// - The total size `tx_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `txid_ret` must be non-null and valid for writes of 32 bytes with an alignment of 1.
///   On successful execution this will contain the txid of the decrypted transaction.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_decrypt_and_store_transaction(
    wallet_db_handle: *mut WalletDbHandle,
    tx: *const u8,
    tx_len: usize,
    mined_height: i64,
    txid_ret: *mut u8,
) -> i32 {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let network = wallet_db_handle.network();
        let tx_bytes = unsafe { slice::from_raw_parts(tx, tx_len) };

        // The consensus branch ID passed in here does not matter:
        // - v4 and below cache it internally, but all we do with this transaction while
        //   it is in memory is decryption, serialization, and calculating the txid, none
        //   of which use the consensus branch ID.
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

        match decrypt_and_store_transaction(&network, wallet_db_handle.db_mut(), &tx, mined_height)
        {
            Ok(()) => {
                unsafe { txid_ret.copy_from(tx.txid().as_ref().as_ptr(), 32) };
                Ok(1)
            }
            Err(e) => Err(anyhow!("Error while decrypting transaction: {}", e)),
        }
    });
    unwrap_exc_or(res, -1)
}

fn zip317_helper<DbT>(
    change_memo: Option<MemoBytes>,
) -> (
    MultiOutputChangeStrategy<StandardFeeRule, DbT>,
    GreedyInputSelector<DbT>,
) {
    (
        MultiOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            change_memo,
            ShieldedProtocol::Orchard,
            DustOutputPolicy::default(),
            SplitPolicy::with_min_output_value(
                NonZeroUsize::new(4).unwrap(),
                Zatoshis::const_from_u64(1000_0000),
            ),
        ),
        GreedyInputSelector::new(),
    )
}

/// Select transaction inputs, compute fees, and construct a proposal for a transaction
/// that can then be authorized and made ready for submission to the network with
/// `zcashlc_create_proposed_transaction`.
///
/// # Safety
///
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an alignment
///   of `1`.
/// - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
///   function call.
/// - `to` must be non-null and must point to a null-terminated UTF-8 string.
/// - `memo` must either be null (indicating an empty memo or a transparent recipient) or point to a
///   512-byte array.
/// - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_propose_transfer(
    wallet_db_handle: *mut WalletDbHandle,
    account_uuid_bytes: *const u8,
    to: *const c_char,
    value: i64,
    memo: *const u8,
    confirmations_policy: ffi::ConfirmationsPolicy,
) -> *mut ffi::BoxedSlice {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let network = wallet_db_handle.network();

        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;
        let to = unsafe { CStr::from_ptr(to) }.to_str()?;
        let value = Zatoshis::from_nonnegative_i64(value)
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

        let (change_strategy, input_selector) = zip317_helper(None);

        let req = TransactionRequest::new(vec![
            Payment::new(to, value, memo, None, None, vec![]).ok_or_else(|| {
                anyhow!("Memos are not permitted when sending to transparent recipients.")
            })?,
        ])
        .map_err(|e| anyhow!("Error creating transaction request: {:?}", e))?;

        let proposal = propose_transfer::<_, _, _, _, Infallible>(
            wallet_db_handle.db_mut(),
            &network,
            account_uuid,
            &input_selector,
            &change_strategy,
            req,
            wallet::ConfirmationsPolicy::try_from(confirmations_policy)?,
        )
        .map_err(|e| anyhow!("Error while sending funds: {}", e))?;

        let encoded = Proposal::from_standard_proposal(&proposal).encode_to_vec();

        Ok(ffi::BoxedSlice::some(encoded))
    });
    unwrap_exc_or_null(res)
}

/// Selects all spendable transaction inputs, computes fees, and constructs a proposal for a transaction
/// that can then be authorized and made ready for submission to the network with
/// `zcashlc_create_proposed_transaction`.
///
/// # Safety
///
/// - `db_handle` must be a non-null pointer returned by [`zcashlc_open_db`] that has not
///   previously been freed.
/// - `db_handle` must not be passed to two FFI calls at the same time.
/// - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an alignment
///   of `1`.
/// - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
///   function call.
/// - `to` must be non-null and must point to a null-terminated UTF-8 string.
/// - `memo` must either be null (indicating an empty memo or a transparent recipient) or point to a
///   512-byte array.
/// - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_propose_send_max_transfer(
    wallet_db_handle: *mut WalletDbHandle,
    account_uuid_bytes: *const u8,
    to: *const c_char,
    memo: *const u8,
    mode: ffi::MaxSpendMode,
    confirmations_policy: ffi::ConfirmationsPolicy,
) -> *mut ffi::BoxedSlice {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let network = wallet_db_handle.network();

        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;
        let to = unsafe { CStr::from_ptr(to) }.to_str()?;

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

        let mode = match mode {
            ffi::MaxSpendMode::MaxSpendable => MaxSpendMode::MaxSpendable,
            ffi::MaxSpendMode::Everything => MaxSpendMode::Everything,
        };

        let confirmation_policy = wallet::ConfirmationsPolicy::try_from(confirmations_policy)?;

        let proposal = propose_send_max_transfer::<_, _, _, Infallible>(
            wallet_db_handle.db_mut(),
            &network,
            account_uuid,
            &[ShieldedProtocol::Sapling, ShieldedProtocol::Orchard],
            &StandardFeeRule::Zip317,
            to,
            memo,
            mode,
            confirmation_policy,
        )
        .map_err(|e| anyhow!("Error while sending funds: {}", e))?;

        let encoded = Proposal::from_standard_proposal(&proposal).encode_to_vec();

        Ok(ffi::BoxedSlice::some(encoded))
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
/// - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an alignment
///   of `1`.
/// - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
///   function call.
/// - `payment_uri` must be non-null and must point to a null-terminated UTF-8 string.
/// - `network_id` a u32. 0 for Testnet and 1 for Mainnet
/// - `confirmations_policy` number of trusted/untrusted confirmations of the funds to spend
/// - `use_zip317_fees` `true` to use ZIP-317 fees.
/// - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_propose_transfer_from_uri(
    wallet_db_handle: *mut WalletDbHandle,
    account_uuid_bytes: *const u8,
    payment_uri: *const c_char,
    confirmations_policy: ffi::ConfirmationsPolicy,
) -> *mut ffi::BoxedSlice {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;

        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;
        let payment_uri_str = unsafe { CStr::from_ptr(payment_uri) }.to_str()?;

        let (change_strategy, input_selector) = zip317_helper(None);

        let req = TransactionRequest::from_uri(payment_uri_str)
            .map_err(|e| anyhow!("Error creating transaction request: {:?}", e))?;

        let network = wallet_db_handle.network();
        let proposal = propose_transfer::<_, _, _, _, Infallible>(
            wallet_db_handle.db_mut(),
            &network,
            account_uuid,
            &input_selector,
            &change_strategy,
            req,
            wallet::ConfirmationsPolicy::try_from(confirmations_policy)?,
        )
        .map_err(|e| anyhow!("Error while sending funds: {}", e))?;

        let encoded = Proposal::from_standard_proposal(&proposal).encode_to_vec();

        Ok(ffi::BoxedSlice::some(encoded))
    });
    unwrap_exc_or_null(res)
}

#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub unsafe extern "C" fn zcashlc_string_free(s: *mut c_char) {
    if !s.is_null() {
        let s = unsafe { CString::from_raw(s) };
        drop(s);
    }
}

/// Select transaction inputs, compute fees, and construct a proposal for a shielding
/// transaction that can then be authorized and made ready for submission to the network
/// with `zcashlc_create_proposed_transaction`. If there are no receivers (as selected
/// by `transparent_receiver`) for which at least `shielding_threshold` of value is
/// available to shield, fail with an error.
///
/// # Parameters
///
/// - db_data: A string represented as a sequence of UTF-8 bytes.
/// - db_data_len: The length of `db_data`, in bytes.
/// - account_uuid_bytes: a 16-byte array representing the UUID for an account
/// - memo: `null` to represent "no memo", or a pointer to an array containing exactly 512 bytes.
/// - shielding_threshold: the minimum value to be shielded for each receiver.
/// - transparent_receiver: `null` to represent "all receivers with shieldable funds", or a single
///   transparent address for which to shield funds. WARNING: Note that calling this with `null`
///   will leak the fact that all the addresses from which funds are drawn in the shielding
///   transaction belong to the same wallet *ON CHAIN*. This immutably reveals the shared ownership
///   of these addresses to all blockchain observers. If a caller wishes to avoid such linkability,
///   they should not pass `null` for this parameter; however, note that temporal correlations can
///   also heuristically be used to link addresses on-chain if funds from multiple addresses are
///   individually shielded in transactions that may be temporally clustered. Keeping transparent
///   activity private is very difficult; caveat emptor.
/// - network_id: The identifier for the network in use: 0 for testnet, 1 for mainnet.
/// - confirmations_policy: The minimum number of confirmations that are required for a UTXO to be considered
///   for shielding.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an alignment
///   of `1`.
/// - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
///   function call.
/// - `shielding_threshold` a non-negative shielding threshold amount in zatoshi
/// - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_propose_shielding(
    wallet_db_handle: *mut WalletDbHandle,
    account_uuid_bytes: *const u8,
    memo: *const u8,
    shielding_threshold: u64,
    transparent_receiver: *const c_char,
    confirmations_policy: ffi::ConfirmationsPolicy,
) -> *mut ffi::BoxedSlice {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let network = wallet_db_handle.network();

        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;

        let memo_bytes = if memo.is_null() {
            MemoBytes::empty()
        } else {
            MemoBytes::from_bytes(unsafe { slice::from_raw_parts(memo, 512) })
                .map_err(|e| anyhow!("Invalid MemoBytes: {}", e))?
        };

        let shielding_threshold = Zatoshis::from_u64(shielding_threshold)
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
                        // Zashi does not support standalone keys, so we do not request standalone receivers.
                        if wallet_db_handle
                            .db()
                            .get_transparent_receivers(account_uuid, true, false)?
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

        let confirmations_policy = wallet::ConfirmationsPolicy::try_from(confirmations_policy)?;

        let account_receivers = wallet_db_handle
            .db()
            .get_target_and_anchor_heights(NonZeroU32::MIN)
            .map_err(|e| anyhow!("Error while fetching anchor height: {}", e))
            .and_then(|opt| {
                opt.map(|(target, _)| target) // Include unconfirmed funds.
                    .ok_or_else(|| anyhow!("height not available; scan required."))
            })
            .and_then(|target_height| {
                wallet_db_handle
                    .db()
                    .get_transparent_balances(account_uuid, target_height, confirmations_policy)
                    .map_err(|e| {
                        anyhow!(
                            "Error while fetching transparent balances for {:?}: {}",
                            account_uuid,
                            e,
                        )
                    })
            })?;

        // If a specific address is specified, or balance only exists for one address, select the
        // value for that address.
        //
        // Otherwise, if there are any non-ephemeral addresses, select value for all those
        // addresses. See the warnings associated with the documentation of the
        // `transparent_receiver` argument in the method documentation for privacy considerations.
        //
        // Finally, if there are only ephemeral addresses, select value for exactly one of those
        // addresses.
        let from_addrs: Vec<TransparentAddress> = match transparent_receiver {
            Some(addr) => account_receivers
                .get(&addr)
                .and_then(|(_, balance)| {
                    (balance.spendable_value() >= shielding_threshold).then_some(addr)
                })
                .into_iter()
                .collect(),
            None => {
                let (ephemeral, non_ephemeral): (Vec<_>, Vec<_>) = account_receivers
                    .into_iter()
                    .filter(|(_, (_, balance))| balance.spendable_value() >= shielding_threshold)
                    .partition(|(_, (scope, _))| *scope == TransparentKeyScope::EPHEMERAL);

                if non_ephemeral.is_empty() {
                    ephemeral
                        .into_iter()
                        .take(1)
                        .map(|(addr, _)| addr)
                        .collect()
                } else {
                    non_ephemeral.into_iter().map(|(addr, _)| addr).collect()
                }
            }
        };

        if from_addrs.is_empty() {
            return Ok(ffi::BoxedSlice::none());
        };

        let (change_strategy, input_selector) = zip317_helper(Some(memo_bytes));
        let proposal = propose_shielding::<_, _, _, _, Infallible>(
            wallet_db_handle.db_mut(),
            &network,
            &input_selector,
            &change_strategy,
            shielding_threshold,
            &from_addrs,
            account_uuid,
            confirmations_policy,
        )
        .map_err(|e| anyhow!("Error while shielding transaction: {}", e))?;

        let encoded = Proposal::from_standard_proposal(&proposal).encode_to_vec();

        Ok(ffi::BoxedSlice::some(encoded))
    });
    unwrap_exc_or_null(res)
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
/// # Parameters
/// - `spend_params`: A pointer to a buffer containing the operating system path of the Sapling
///   spend proving parameters, in the operating system's preferred path representation.
/// - `spend_params_len`: the length of the `spend_params` buffer.
/// - `output_params`: A pointer to a buffer containing the operating system path of the Sapling
///   output proving parameters, in the operating system's preferred path representation.
/// - `output_params_len`: the length of the `output_params` buffer.
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
/// - `spend_params` must be non-null and valid for reads for `spend_params_len` bytes,
///   and it must have an alignment of `1`.
/// - The memory referenced by `spend_params` must not be mutated for the duration of the
///   function call.
/// - The total size `spend_params_len` must be no larger than `isize::MAX`. See the safety
///   documentation of `pointer::offset`.
/// - `output_params` must be non-null and valid for reads for `output_params_len` bytes,
///   and it must have an alignment of `1`.
/// - The memory referenced by `output_params` must not be mutated for the duration of the
///   function call.
/// - The total size `output_params_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_create_proposed_transactions(
    wallet_db_handle: *mut WalletDbHandle,
    proposal_ptr: *const u8,
    proposal_len: usize,
    usk_ptr: *const u8,
    usk_len: usize,
    spend_params: *const u8,
    spend_params_len: usize,
    output_params: *const u8,
    output_params_len: usize,
) -> *mut ffi::TxIds {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;

        let proposal =
            Proposal::decode(unsafe { slice::from_raw_parts(proposal_ptr, proposal_len) })
                .map_err(|e| anyhow!("Invalid proposal: {}", e))?
                .try_into_standard_proposal(wallet_db_handle.db())?;
        let usk = unsafe { decode_usk(usk_ptr, usk_len) }?;
        let spend_params = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(spend_params, spend_params_len)
        }));
        let output_params = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(output_params, output_params_len)
        }));

        let prover = LocalTxProver::new(spend_params, output_params);
        let network = wallet_db_handle.network();

        let txids = create_proposed_transactions::<_, _, Infallible, _, Infallible, _>(
            wallet_db_handle.db_mut(),
            &network,
            &prover,
            &prover,
            &SpendingKeys::from_unified_spending_key(usk),
            OvkPolicy::Sender,
            &proposal,
        )
        .map_err(|e| anyhow!("Error while sending funds: {}", e))?;

        Ok(ffi::TxIds::ptr_from_vec(
            txids.into_iter().map(|txid| *txid.as_ref()).collect(),
        ))
    });
    unwrap_exc_or_null(res)
}

/// Creates a partially-constructed (unsigned without proofs) transaction from the given proposal.
///
/// Returns the partially constructed transaction in the `postcard` format generated by the `pczt`
/// crate.
///
/// Do not call this multiple times in parallel, or you will generate pczt instances that, if
/// finalized, would double-spend the same notes.
///
/// # Parameters
/// - `db_data`: A pointer to a buffer containing the operating system path of the wallet database,
///   in the operating system's preferred path representation.
/// - `db_data_len`: The length of the `db_data` buffer.
/// - `proposal_ptr`: A pointer to a buffer containing an encoded `Proposal` protobuf.
/// - `proposal_len`: The length of the `proposal_ptr` buffer.
/// - `account_uuid_bytes`: A pointer to the 16-byte representaion of the account UUID.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of `pointer::offset`.
/// - `proposal_ptr` must be non-null and valid for reads for `proposal_len` bytes, and it
///   must have an alignment of `1`.
/// - The memory referenced by `proposal_ptr` must not be mutated for the duration of the
///   function call.
/// - The total size `proposal_len` must be no larger than `isize::MAX`. See the safety
///   documentation of `pointer::offset`.
/// - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
///   function call.
/// - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_create_pczt_from_proposal(
    wallet_db_handle: *mut WalletDbHandle,
    proposal_ptr: *const u8,
    proposal_len: usize,
    account_uuid_bytes: *const u8,
) -> *mut ffi::BoxedSlice {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;

        let proposal =
            Proposal::decode(unsafe { slice::from_raw_parts(proposal_ptr, proposal_len) })
                .map_err(|e| anyhow!("Invalid proposal: {}", e))?
                .try_into_standard_proposal(wallet_db_handle.db())?;

        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;
        let network = wallet_db_handle.network();

        if proposal.steps().len() == 1 {
            let pczt = create_pczt_from_proposal::<_, _, Infallible, _, Infallible, _>(
                wallet_db_handle.db_mut(),
                &network,
                account_uuid,
                OvkPolicy::Sender,
                &proposal,
            )
            .map_err(|e| anyhow!("Error creating PCZT from single-step proposal: {}", e))?;

            Ok(ffi::BoxedSlice::some(pczt.serialize()))
        } else {
            Err(anyhow!(
                "Multi-step proposals are not yet supported for PCZT generation."
            ))
        }
    });
    unwrap_exc_or_null(res)
}

/// Redacts information from the given PCZT that is unnecessary for the Signer role.
///
/// Returns the updated PCZT in its serialized format.
///
/// # Parameters
/// - `pczt_ptr`: A pointer to a byte array containing the encoded partially-constructed
///   transaction to be redacted.
/// - `pczt_len`: The length of the `pczt_ptr` buffer.
///
/// # Safety
///
/// - `pczt_ptr` must be non-null and valid for reads for `pczt_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `pczt_ptr` must not be mutated for the duration of the function
///   call.
/// - The total size `pczt_len` must be no larger than `isize::MAX`. See the safety documentation
///   of `pointer::offset`.
/// - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_redact_pczt_for_signer(
    pczt_ptr: *const u8,
    pczt_len: usize,
) -> *mut ffi::BoxedSlice {
    let res = catch_panic(|| {
        let pczt_bytes = unsafe { slice::from_raw_parts(pczt_ptr, pczt_len) };
        let pczt = Pczt::parse(pczt_bytes).map_err(|e| anyhow!("Invalid PCZT: {:?}", e))?;

        let redacted_pczt = Redactor::new(pczt)
            .redact_global_with(|mut r| r.redact_proprietary("zcash_client_backend:proposal_info"))
            .redact_orchard_with(|mut r| {
                r.redact_actions(|mut ar| {
                    ar.clear_spend_witness();
                    ar.redact_output_proprietary("zcash_client_backend:output_info");
                })
            })
            .redact_sapling_with(|mut r| {
                r.redact_spends(|mut sr| sr.clear_witness());
                r.redact_outputs(|mut or| {
                    or.redact_proprietary("zcash_client_backend:output_info")
                });
            })
            .redact_transparent_with(|mut r| {
                r.redact_outputs(|mut or| {
                    or.redact_proprietary("zcash_client_backend:output_info")
                });
            })
            .finish();

        Ok(ffi::BoxedSlice::some(redacted_pczt.serialize()))
    });
    unwrap_exc_or_null(res)
}

/// Returns `true` if this PCZT requires Sapling proofs (and thus the caller needs to have
/// downloaded them). If the PCZT is invalid, `false` will be returned.
///
/// # Parameters
/// - `pczt_ptr`: A pointer to a byte array containing the encoded partially-constructed
///   transaction to be redacted.
/// - `pczt_len`: The length of the `pczt_ptr` buffer.
///
/// # Safety
///
/// - `pczt_ptr` must be non-null and valid for reads for `pczt_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `pczt_ptr` must not be mutated for the duration of the function
///   call.
/// - The total size `pczt_len` must be no larger than `isize::MAX`. See the safety documentation
///   of `pointer::offset`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_pczt_requires_sapling_proofs(
    pczt_ptr: *const u8,
    pczt_len: usize,
) -> bool {
    let res = catch_panic(|| {
        let pczt_bytes = unsafe { slice::from_raw_parts(pczt_ptr, pczt_len) };
        let pczt = Pczt::parse(pczt_bytes).map_err(|e| anyhow!("Invalid PCZT: {:?}", e))?;

        let prover = Prover::new(pczt);

        Ok(prover.requires_sapling_proofs())
    });

    // The only error we can encounter here is an invalid PCZT. Pretend we don't need
    // Sapling proofs so the caller doesn't block on Sapling parameter fetching, and
    // instead calls `zcashlc_add_proofs_to_pczt` which will report the same error
    // correctly.
    unwrap_exc_or(res, false)
}

/// Adds proofs to the given PCZT.
///
/// Returns the updated PCZT in its serialized format.
///
/// # Parameters
/// - `pczt_ptr`: A pointer to a byte array containing the encoded partially-constructed
///   transaction for which proofs will be computed.
/// - `pczt_len`: The length of the `pczt_ptr` buffer.
/// - `spend_params`: A pointer to a buffer containing the operating system path of the Sapling
///   spend proving parameters, in the operating system's preferred path representation.
/// - `spend_params_len`: the length of the `spend_params` buffer.
/// - `output_params`: A pointer to a buffer containing the operating system path of the Sapling
///   output proving parameters, in the operating system's preferred path representation.
/// - `output_params_len`: the length of the `output_params` buffer.
///
/// # Safety
///
/// - `pczt_ptr` must be non-null and valid for reads for `pczt_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `pczt_ptr` must not be mutated for the duration of the function
///   call.
/// - The total size `pczt_len` must be no larger than `isize::MAX`. See the safety documentation
///   of `pointer::offset`.
/// - `spend_params` must be non-null and valid for reads for `spend_params_len` bytes, and it must
///   have an alignment of `1`.
/// - The memory referenced by `spend_params` must not be mutated for the duration of the function
///   call.
/// - The total size `spend_params_len` must be no larger than `isize::MAX`. See the safety
///   documentation of `pointer::offset`.
/// - `output_params` must be non-null and valid for reads for `output_params_len` bytes, and it
///   must have an alignment of `1`.
/// - The memory referenced by `output_params` must not be mutated for the duration of the function
///   call.
/// - The total size `output_params_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_add_proofs_to_pczt(
    pczt_ptr: *const u8,
    pczt_len: usize,
    spend_params: *const u8,
    spend_params_len: usize,
    output_params: *const u8,
    output_params_len: usize,
) -> *mut ffi::BoxedSlice {
    let res = catch_panic(|| {
        let pczt_bytes = unsafe { slice::from_raw_parts(pczt_ptr, pczt_len) };
        let pczt = Pczt::parse(pczt_bytes).map_err(|e| anyhow!("Invalid PCZT: {:?}", e))?;

        let mut prover = Prover::new(pczt);

        if prover.requires_orchard_proof() {
            prover = prover
                .create_orchard_proof(&orchard::circuit::ProvingKey::build())
                .map_err(|e| anyhow!("Failed to create Orchard proof for PCZT: {:?}", e))?;
        }
        assert!(!prover.requires_orchard_proof());

        if prover.requires_sapling_proofs() {
            if spend_params.is_null() {
                return Err(anyhow!("Sapling Spend parameters are required"));
            }
            if output_params.is_null() {
                return Err(anyhow!("Sapling Output parameters are required"));
            }

            let spend_params = Path::new(OsStr::from_bytes(unsafe {
                slice::from_raw_parts(spend_params, spend_params_len)
            }));
            let output_params = Path::new(OsStr::from_bytes(unsafe {
                slice::from_raw_parts(output_params, output_params_len)
            }));
            let local_prover = LocalTxProver::new(spend_params, output_params);

            prover = prover
                .create_sapling_proofs(&local_prover, &local_prover)
                .map_err(|e| anyhow!("Failed to create Sapling proofs for PCZT: {:?}", e))?;
        }
        assert!(!prover.requires_sapling_proofs());

        let pczt_with_proofs = prover.finish();

        Ok(ffi::BoxedSlice::some(pczt_with_proofs.serialize()))
    });
    unwrap_exc_or_null(res)
}

/// Takes a PCZT that has been separately proven and signed, finalizes it, and stores it
/// in the wallet.
///
/// Returns the txid of the completed transaction as a byte array.
///
/// # Parameters
/// - `db_data`: A pointer to a buffer containing the operating system path of the wallet database,
///   in the operating system's preferred path representation.
/// - `db_data_len`: The length of the `db_data` buffer.
/// - `pczt_with_proofs`: A pointer to a byte array containing the encoded partially-constructed
///   transaction to which proofs have been added.
/// - `pczt_with_proofs_len`: The length of the `pczt_with_proofs` buffer.
/// - `pczt_with_sigs_ptr`: A pointer to a byte array containing the encoded partially-constructed
///   transaction to which signatures have been added.
/// - `pczt_with_sigs_len`: The length of the `pczt_with_sigs` buffer.
/// - `spend_params`: A pointer to a buffer containing the operating system path of the Sapling
///   spend proving parameters, in the operating system's preferred path representation.
/// - `spend_params_len`: the length of the `spend_params` buffer.
/// - `output_params`: A pointer to a buffer containing the operating system path of the Sapling
///   output proving parameters, in the operating system's preferred path representation.
/// - `output_params_len`: the length of the `output_params` buffer.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of `pointer::offset`.
/// - `pczt_with_proofs_ptr` must be non-null and valid for reads for `pczt_with_proofs_len` bytes,
///   and it must have an alignment of `1`.
/// - The memory referenced by `pczt_with_proofs_ptr` must not be mutated for the duration of the
///   function call.
/// - The total size `pczt_with_proofs_len` must be no larger than `isize::MAX`. See the safety
///   documentation of `pointer::offset`.
/// - `pczt_with_sigs_ptr` must be non-null and valid for reads for `pczt_with_sigs_len` bytes, and
///   it must have an alignment of `1`.
/// - The memory referenced by `pczt_with_sigs_ptr` must not be mutated for the duration of the
///   function call.
/// - The total size `pczt_with_sigs_len` must be no larger than `isize::MAX`. See the safety
///   documentation of `pointer::offset`.
/// - `spend_params` must either be null, or it must be valid for reads for `spend_params_len` bytes
///   and have an alignment of `1`.
/// - The memory referenced by `spend_params` must not be mutated for the duration of the function
///   call.
/// - The total size `spend_params_len` must be no larger than `isize::MAX`. See the safety
///   documentation of `pointer::offset`.
/// - `output_params` must either be null, or it must be valid for reads for `output_params_len`
///   bytes and have an alignment of `1`.
/// - The memory referenced by `output_params` must not be mutated for the duration of the function
///   call.
/// - The total size `output_params_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned pointer
///   when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_extract_and_store_from_pczt(
    wallet_db_handle: *mut WalletDbHandle,
    pczt_with_proofs_ptr: *const u8,
    pczt_with_proofs_len: usize,
    pczt_with_sigs_ptr: *const u8,
    pczt_with_sigs_len: usize,
    spend_params: *const u8,
    spend_params_len: usize,
    output_params: *const u8,
    output_params_len: usize,
) -> *mut ffi::BoxedSlice {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;

        let pczt_with_proofs_bytes =
            unsafe { slice::from_raw_parts(pczt_with_proofs_ptr, pczt_with_proofs_len) };
        let pczt_with_proofs =
            Pczt::parse(pczt_with_proofs_bytes).map_err(|e| anyhow!("Invalid PCZT: {:?}", e))?;

        let pczt_with_sigs_bytes =
            unsafe { slice::from_raw_parts(pczt_with_sigs_ptr, pczt_with_sigs_len) };
        let pczt_with_sigs =
            Pczt::parse(pczt_with_sigs_bytes).map_err(|e| anyhow!("Invalid PCZT: {:?}", e))?;

        let sapling_vk = (!spend_params.is_null() && !output_params.is_null()).then(|| {
            let spend_params = Path::new(OsStr::from_bytes(unsafe {
                slice::from_raw_parts(spend_params, spend_params_len)
            }));
            let output_params = Path::new(OsStr::from_bytes(unsafe {
                slice::from_raw_parts(output_params, output_params_len)
            }));

            let prover = LocalTxProver::new(spend_params, output_params);
            prover.verifying_keys()
        });

        let pczt = Combiner::new(vec![pczt_with_proofs, pczt_with_sigs])
            .combine()
            .map_err(|e| anyhow!("Failed to combine PCZTs: {:?}", e))?;

        let txid = extract_and_store_transaction_from_pczt::<_, ()>(
            wallet_db_handle.db_mut(),
            pczt,
            sapling_vk.as_ref().map(|(s, o)| (s, o)),
            None,
        )
        .map_err(|e| anyhow!("Failed to extract transaction from PCZT: {:?}", e))?;

        Ok(ffi::BoxedSlice::some(txid.as_ref().to_vec()))
    });
    unwrap_exc_or_null(res)
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_set_transaction_status(
    wallet_db_handle: *mut WalletDbHandle,
    txid_bytes: *const u8,
    txid_bytes_len: usize,
    status: ffi::TransactionStatus,
) {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;

        let txid_bytes = unsafe { slice::from_raw_parts(txid_bytes, txid_bytes_len) };
        let txid = TxId::read(txid_bytes)?;

        let status = match status {
            ffi::TransactionStatus::TxidNotRecognized => TransactionStatus::TxidNotRecognized,
            ffi::TransactionStatus::NotInMainChain => TransactionStatus::NotInMainChain,
            ffi::TransactionStatus::Mined(h) => TransactionStatus::Mined(BlockHeight::from(h)),
        };

        wallet_db_handle
            .db_mut()
            .set_transaction_status(txid, status)
            .map_err(|e| anyhow!("Error setting transaction status for txid {}: {}", txid, e))
    });

    unwrap_exc_or(res, ())
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_transaction_data_requests(
    wallet_db_handle: *mut WalletDbHandle,
) -> *mut ffi::TransactionDataRequests {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_ref() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let network = wallet_db_handle.network();

        Ok(ffi::TransactionDataRequests::ptr_from_vec(
            wallet_db_handle
                .db()
                .transaction_data_requests()?
                .into_iter()
                .map(|req| match req {
                    TransactionDataRequest::GetStatus(txid) => {
                        ffi::TransactionDataRequest::GetStatus(txid.into())
                    }
                    TransactionDataRequest::Enhancement(txid) => {
                        ffi::TransactionDataRequest::Enhancement(txid.into())
                    }
                    TransactionDataRequest::TransactionsInvolvingAddress(v) => {
                        ffi::TransactionDataRequest::TransactionsInvolvingAddress {
                            address: CString::new(v.address().encode(&network))
                                .unwrap()
                                .into_raw(),
                            block_range_start: v.block_range_start().into(),
                            block_range_end: v
                                .block_range_end()
                                .map_or(-1, |h| u32::from(h).into()),
                            request_at: v.request_at().map_or(-1, |t| {
                                t.duration_since(UNIX_EPOCH)
                                    .expect("SystemTime should never be before the epoch")
                                    .as_secs()
                                    .try_into()
                                    .expect("we have time before a SystemTime overflows i64")
                            }),
                            tx_status_filter: ffi::TransactionStatusFilter::from_rust(
                                v.tx_status_filter().clone(),
                            ),
                            output_status_filter: ffi::OutputStatusFilter::from_rust(
                                v.output_status_filter().clone(),
                            ),
                        }
                    }
                })
                .collect(),
        ))
    });
    unwrap_exc_or_null(res)
}

/// Detects notes with corrupt witnesses, and adds the block ranges corresponding to the corrupt
/// ranges to the scan queue so that the ordinary scanning process will re-scan these ranges to fix
/// the corruption in question.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_fix_witnesses(wallet_db_handle: *mut WalletDbHandle) {
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);
    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;

        let corrupt_ranges = wallet_db_handle.db_mut().check_witnesses()?;
        if let Some(nel_ranges) = NonEmpty::from_vec(corrupt_ranges) {
            wallet_db_handle
                .db_mut()
                .queue_rescans(nel_ranges, ScanPriority::FoundNote)?;
        }

        Ok(())
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_create_tor_runtime(
    tor_dir: *const u8,
    tor_dir_len: usize,
) -> *mut TorRuntime {
    let res = catch_panic(|| {
        let tor_dir = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(tor_dir, tor_dir_len)
        }));

        // iOS apps are run in sandboxes, so we can rely on them for enforcing that only
        // the app can access its Tor data.
        #[cfg(target_os = "ios")]
        let dangerously_trust_everyone = true;

        // On other platforms, have Tor manage its own file permissions.
        #[cfg(not(target_os = "ios"))]
        let dangerously_trust_everyone = false;

        let tor = crate::tor::TorRuntime::create(tor_dir, dangerously_trust_everyone)?;

        Ok(Box::into_raw(Box::new(tor)))
    });
    unwrap_exc_or_null(res)
}

/// Frees a Tor runtime.
///
/// # Safety
///
/// - If `ptr` is non-null, it must be a pointer returned by a `zcashlc_*` method with
///   return type `*mut TorRuntime` that has not previously been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_tor_runtime(ptr: *mut TorRuntime) {
    if !ptr.is_null() {
        let s: Box<TorRuntime> = unsafe { Box::from_raw(ptr) };
        drop(s);
    }
}

/// Returns a new isolated `TorRuntime` handle.
///
/// The two `TorRuntime`s will share internal state and configuration, but their streams
/// will never share circuits with one another.
///
/// Use this method when you want separate parts of your program to each have a
/// `TorRuntime` handle, but where you don't want their activities to be linkable to one
/// another over the Tor network.
///
/// Calling this method is usually preferable to creating a completely separate
/// `TorRuntime` instance, since it can share its internals with the existing `TorRuntime`.
///
/// # Safety
///
/// - `tor_runtime` must be a non-null pointer returned by a `zcashlc_*` method with
///   return type `*mut TorRuntime` that has not previously been freed.
/// - `tor_runtime` must not be passed to two FFI calls at the same time.
/// - Call [`zcashlc_free_tor_runtime`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_tor_isolated_client(
    tor_runtime: *mut TorRuntime,
) -> *mut TorRuntime {
    // SAFETY: Callers would have to do the following for unwind safety (#194):
    // - using `*mut TorRuntime` and respecting mutability rules on the Swift side, to
    //   avoid observing the effects of a panic in another thread.
    // - discarding the `TorRuntime` whenever we get an error that is due to a panic.
    let tor_runtime = AssertUnwindSafe(tor_runtime);

    let res = catch_panic(|| {
        let tor_runtime =
            unsafe { tor_runtime.as_mut() }.ok_or_else(|| anyhow!("A Tor runtime is required"))?;

        let isolated_client = tor_runtime.isolated_client();

        Ok(Box::into_raw(Box::new(isolated_client)))
    });
    unwrap_exc_or_null(res)
}

/// Changes the client's current dormant mode, putting background tasks to sleep or waking
/// them up as appropriate.
///
/// This can be used to conserve CPU usage if you aren’t planning on using the client for
/// a while, especially on mobile platforms.
///
/// See the [`ffi::TorDormantMode`] documentation for more details.
///
/// # Safety
///
/// - `tor_runtime` must be a non-null pointer returned by a `zcashlc_*` method with
///   return type `*mut TorRuntime` that has not previously been freed.
/// - `tor_runtime` must not be passed to two FFI calls at the same time.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_tor_set_dormant(
    tor_runtime: *mut TorRuntime,
    mode: ffi::TorDormantMode,
) -> bool {
    // SAFETY: Callers would have to do the following for unwind safety (#194):
    // - using `*mut TorRuntime` and respecting mutability rules on the Swift side, to
    //   avoid observing the effects of a panic in another thread.
    // - discarding the `TorRuntime` whenever we get an error that is due to a panic.
    let tor_runtime = AssertUnwindSafe(tor_runtime);

    let res = catch_panic(|| {
        let tor_runtime =
            unsafe { tor_runtime.as_mut() }.ok_or_else(|| anyhow!("A Tor runtime is required"))?;

        tor_runtime.set_dormant(mode);

        Ok(true)
    });
    unwrap_exc_or(res, false)
}

/// Makes an HTTP GET request over Tor.
///
/// `retry_limit` is the maximum number of times that a failed request should be retried.
/// You can disable retries by setting this to 0.
///
/// # Safety
///
/// - `tor_runtime` must be a non-null pointer returned by a `zcashlc_*` method with
///   return type `*mut TorRuntime` that has not previously been freed.
/// - `tor_runtime` must not be passed to two FFI calls at the same time.
/// - `url` must be non-null and must point to a null-terminated UTF-8 string.
/// - `headers` must be non-null and valid for reads for
///   `headers_len * size_of::<ffi::HttpRequestHeader>()` bytes, and it must be properly
///   aligned. This means in particular:
///   - The entire memory range of this slice must be contained within a single allocated
///     object! Slices can never span across multiple allocated objects.
///   - `headers` must be non-null and aligned even for zero-length slices.
/// - `headers` must point to `headers_len` consecutive properly initialized values of
///   type `ffi::HttpRequestHeader`.
/// - The memory referenced by `headers` must not be mutated for the duration of the function
///   call.
/// - The total size `headers_len * size_of::<ffi::HttpRequestHeader>()` of the slice must
///   be no larger than `isize::MAX`, and adding that size to `headers` must not "wrap
///   around" the address space.  See the safety documentation of pointer::offset.
/// - Call [`zcashlc_free_http_response_bytes`] to free the memory associated with the
///   returned pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_tor_http_get(
    tor_runtime: *mut TorRuntime,
    url: *const c_char,
    headers: *const ffi::HttpRequestHeader,
    headers_len: usize,
    retry_limit: u8,
) -> *mut ffi::HttpResponseBytes {
    // SAFETY: Callers would have to do the following for unwind safety (#194):
    // - using `*mut TorRuntime` and respecting mutability rules on the Swift side, to
    //   avoid observing the effects of a panic in another thread.
    // - discarding the `TorRuntime` whenever we get an error that is due to a panic.
    let tor_runtime = AssertUnwindSafe(tor_runtime);

    let res = catch_panic(|| {
        let tor_runtime =
            unsafe { tor_runtime.as_mut() }.ok_or_else(|| anyhow!("A Tor runtime is required"))?;

        let url = unsafe { CStr::from_ptr(url).to_str()? }
            .try_into()
            .map_err(|e| anyhow!("Invalid URL: {e}"))?;

        let headers = unsafe { slice::from_raw_parts(headers, headers_len) }
            .iter()
            .map(|header| {
                anyhow::Ok((
                    unsafe { CStr::from_ptr(header.name) }.to_str()?,
                    unsafe { CStr::from_ptr(header.value) }.to_str()?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let response = tor_runtime.runtime().block_on(async {
            tor_runtime
                .client()
                .http_get(
                    url,
                    |builder| {
                        headers.iter().fold(builder, |builder, (key, value)| {
                            builder.header(*key, *value)
                        })
                    },
                    |body| async { Ok(body.collect().await.map_err(HttpError::from)?.to_bytes()) },
                    retry_limit,
                    |res| {
                        res.is_err()
                            .then_some(zcash_client_backend::tor::http::Retry::Same)
                    },
                )
                .await
        })?;

        ffi::HttpResponseBytes::from_rust(response)
    });
    unwrap_exc_or_null(res)
}

/// Makes an HTTP POST request over Tor.
///
/// `retry_limit` is the maximum number of times that a failed request should be retried.
/// You can disable retries by setting this to 0.
///
/// # Safety
///
/// - `tor_runtime` must be a non-null pointer returned by a `zcashlc_*` method with
///   return type `*mut TorRuntime` that has not previously been freed.
/// - `tor_runtime` must not be passed to two FFI calls at the same time.
/// - `url` must be non-null and must point to a null-terminated UTF-8 string.
/// - `headers` must be non-null and valid for reads for
///   `headers_len * size_of::<ffi::HttpRequestHeader>()` bytes, and it must be properly
///   aligned. This means in particular:
///   - The entire memory range of this slice must be contained within a single allocated
///     object! Slices can never span across multiple allocated objects.
///   - `headers` must be non-null and aligned even for zero-length slices.
/// - `headers` must point to `headers_len` consecutive properly initialized values of
///   type `ffi::HttpRequestHeader`.
/// - The memory referenced by `headers` must not be mutated for the duration of the function
///   call.
/// - The total size `headers_len * size_of::<ffi::HttpRequestHeader>()` of the slice must
///   be no larger than `isize::MAX`, and adding that size to `headers` must not "wrap
///   around" the address space.  See the safety documentation of pointer::offset.
/// - `body` must be non-null and valid for reads for `body_len` bytes, and it must have
///   an alignment of `1`.
/// - The memory referenced by `body` must not be mutated for the duration of the function
///   call.
/// - The total size `body_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Call [`zcashlc_free_http_response_bytes`] to free the memory associated with the
///   returned pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_tor_http_post(
    tor_runtime: *mut TorRuntime,
    url: *const c_char,
    headers: *const ffi::HttpRequestHeader,
    headers_len: usize,
    body: *const u8,
    body_len: usize,
    retry_limit: u8,
) -> *mut ffi::HttpResponseBytes {
    // SAFETY: Callers would have to do the following for unwind safety (#194):
    // - using `*mut TorRuntime` and respecting mutability rules on the Swift side, to
    //   avoid observing the effects of a panic in another thread.
    // - discarding the `TorRuntime` whenever we get an error that is due to a panic.
    let tor_runtime = AssertUnwindSafe(tor_runtime);

    let res = catch_panic(|| {
        let tor_runtime =
            unsafe { tor_runtime.as_mut() }.ok_or_else(|| anyhow!("A Tor runtime is required"))?;

        let url = unsafe { CStr::from_ptr(url).to_str()? }
            .try_into()
            .map_err(|e| anyhow!("Invalid URL: {e}"))?;

        let headers = unsafe { slice::from_raw_parts(headers, headers_len) }
            .iter()
            .map(|header| {
                anyhow::Ok((
                    unsafe { CStr::from_ptr(header.name) }.to_str()?,
                    unsafe { CStr::from_ptr(header.value) }.to_str()?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let body = unsafe { slice::from_raw_parts(body, body_len) };

        let response = tor_runtime.runtime().block_on(async {
            tor_runtime
                .client()
                .http_post(
                    url,
                    |builder| {
                        headers.iter().fold(builder, |builder, (key, value)| {
                            builder.header(*key, *value)
                        })
                    },
                    http_body_util::Full::new(body),
                    |body| async { Ok(body.collect().await.map_err(HttpError::from)?.to_bytes()) },
                    retry_limit,
                    |res| {
                        res.is_err()
                            .then_some(zcash_client_backend::tor::http::Retry::Same)
                    },
                )
                .await
        })?;

        ffi::HttpResponseBytes::from_rust(response)
    });
    unwrap_exc_or_null(res)
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
/// - `tor_runtime` must be a non-null pointer returned by a `zcashlc_*` method with
///   return type `*mut TorRuntime` that has not previously been freed.
/// - `tor_runtime` must not be passed to two FFI calls at the same time.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_get_exchange_rate_usd(
    tor_runtime: *mut TorRuntime,
) -> ffi::Decimal {
    // SAFETY: Callers would have to do the following for unwind safety (#194):
    // - using `*mut TorRuntime` and respecting mutability rules on the Swift side, to
    //   avoid observing the effects of a panic in another thread.
    // - discarding the `TorRuntime` whenever we get an error that is due to a panic.
    let tor_runtime = AssertUnwindSafe(tor_runtime);

    let res = catch_panic(|| {
        let tor_runtime =
            unsafe { tor_runtime.as_mut() }.ok_or_else(|| anyhow!("A Tor runtime is required"))?;

        let exchanges = cryptex::Exchanges::builder(cryptex::exchanges::Gemini::unauthenticated())
            .with(cryptex::exchanges::Binance::unauthenticated())
            .with(cryptex::exchanges::Coinbase::unauthenticated())
            .with(cryptex::exchanges::Kraken::unauthenticated())
            .with(cryptex::exchanges::KuCoin::unauthenticated())
            .with(cryptex::exchanges::Mexc::unauthenticated())
            .build();

        let rate = tor_runtime.runtime().block_on(async {
            tor_runtime
                .client()
                .get_latest_zec_to_usd_rate(&exchanges)
                .await
        })?;

        ffi::Decimal::from_rust(rate)
            .ok_or_else(|| anyhow!("Exchange rate has too many significant figures: {}", rate))
    });
    unwrap_exc_or(
        res,
        ffi::Decimal::from_rust(rust_decimal::Decimal::NEGATIVE_ONE).expect("fits"),
    )
}

/// Fetches the current ZEC-USD exchange rate over Tor from the specified exchanges.
///
/// The result is a [`Decimal`] struct containing the fields necessary to construct an
/// [`NSDecimalNumber`](https://developer.apple.com/documentation/foundation/nsdecimalnumber/1416003-init).
///
/// Returns a negative value on error.
///
/// # Safety
///
/// - `tor_runtime` must be a non-null pointer returned by a `zcashlc_*` method with
///   return type `*mut TorRuntime` that has not previously been freed.
/// - `tor_runtime` must not be passed to two FFI calls at the same time.
/// - `exchanges` must be non-null and valid for reads for
///   `exchanges_len * size_of::<ffi::ZecUsdExchange>()` bytes, and it must be properly
///   aligned. This means in particular:
///   - The entire memory range of this slice must be contained within a single allocated
///     object! Slices can never span across multiple allocated objects.
///   - `exchanges` must be non-null and aligned even for zero-length slices.
/// - `exchanges` must point to `exchanges_len` consecutive properly initialized values of
///   type `ffi::ZecUsdExchange`.
/// - The memory referenced by `exchanges` must not be mutated for the duration of the function
///   call.
/// - The total size `exchanges_len * size_of::<ffi::ZecUsdExchange>()` of the slice must
///   be no larger than `isize::MAX`, and adding that size to `exchanges` must not "wrap
///   around" the address space.  See the safety documentation of `pointer::offset`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_get_exchange_rate_usd_from(
    tor_runtime: *mut TorRuntime,
    trusted_exchange: ffi::ZecUsdExchange,
    exchanges: *const ffi::ZecUsdExchange,
    exchanges_len: usize,
) -> ffi::Decimal {
    // SAFETY: Callers would have to do the following for unwind safety (#194):
    // - using `*mut TorRuntime` and respecting mutability rules on the Swift side, to
    //   avoid observing the effects of a panic in another thread.
    // - discarding the `TorRuntime` whenever we get an error that is due to a panic.
    let tor_runtime = AssertUnwindSafe(tor_runtime);

    let res = catch_panic(|| {
        let tor_runtime =
            unsafe { tor_runtime.as_mut() }.ok_or_else(|| anyhow!("A Tor runtime is required"))?;

        let exchanges = unsafe { slice::from_raw_parts(exchanges, exchanges_len) }
            .iter()
            .collect::<HashSet<_>>();
        if exchanges.contains(&trusted_exchange) {
            return Err(anyhow!(
                "Cannot use an exchange as both trusted and untrusted"
            ));
        }

        let exchanges = {
            let mut builder = match trusted_exchange {
                ffi::ZecUsdExchange::Binance => {
                    cryptex::Exchanges::builder(cryptex::exchanges::Binance::unauthenticated())
                }
                ffi::ZecUsdExchange::CoinEx => {
                    cryptex::Exchanges::builder(cryptex::exchanges::CoinEx::unauthenticated())
                }
                ffi::ZecUsdExchange::Coinbase => {
                    cryptex::Exchanges::builder(cryptex::exchanges::Coinbase::unauthenticated())
                }
                ffi::ZecUsdExchange::DigiFinex => {
                    cryptex::Exchanges::builder(cryptex::exchanges::DigiFinex::unauthenticated())
                }
                ffi::ZecUsdExchange::Gemini => {
                    cryptex::Exchanges::builder(cryptex::exchanges::Gemini::unauthenticated())
                }
                ffi::ZecUsdExchange::Kraken => {
                    cryptex::Exchanges::builder(cryptex::exchanges::Kraken::unauthenticated())
                }
                ffi::ZecUsdExchange::KuCoin => {
                    cryptex::Exchanges::builder(cryptex::exchanges::KuCoin::unauthenticated())
                }
                ffi::ZecUsdExchange::Mexc => {
                    cryptex::Exchanges::builder(cryptex::exchanges::Mexc::unauthenticated())
                }
                ffi::ZecUsdExchange::Xt => {
                    cryptex::Exchanges::builder(cryptex::exchanges::Xt::unauthenticated())
                }
            };

            for exchange in exchanges {
                builder = match exchange {
                    ffi::ZecUsdExchange::Binance => {
                        builder.with(cryptex::exchanges::Binance::unauthenticated())
                    }
                    ffi::ZecUsdExchange::CoinEx => {
                        builder.with(cryptex::exchanges::CoinEx::unauthenticated())
                    }
                    ffi::ZecUsdExchange::Coinbase => {
                        builder.with(cryptex::exchanges::Coinbase::unauthenticated())
                    }
                    ffi::ZecUsdExchange::DigiFinex => {
                        builder.with(cryptex::exchanges::DigiFinex::unauthenticated())
                    }
                    ffi::ZecUsdExchange::Gemini => {
                        builder.with(cryptex::exchanges::Gemini::unauthenticated())
                    }
                    ffi::ZecUsdExchange::Kraken => {
                        builder.with(cryptex::exchanges::Kraken::unauthenticated())
                    }
                    ffi::ZecUsdExchange::KuCoin => {
                        builder.with(cryptex::exchanges::KuCoin::unauthenticated())
                    }
                    ffi::ZecUsdExchange::Mexc => {
                        builder.with(cryptex::exchanges::Mexc::unauthenticated())
                    }
                    ffi::ZecUsdExchange::Xt => {
                        builder.with(cryptex::exchanges::Xt::unauthenticated())
                    }
                };
            }
            builder.build()
        };

        let rate = tor_runtime.runtime().block_on(async {
            tor_runtime
                .client()
                .get_latest_zec_to_usd_rate(&exchanges)
                .await
        })?;

        ffi::Decimal::from_rust(rate)
            .ok_or_else(|| anyhow!("Exchange rate has too many significant figures: {}", rate))
    });
    unwrap_exc_or(
        res,
        ffi::Decimal::from_rust(rust_decimal::Decimal::NEGATIVE_ONE).expect("fits"),
    )
}

/// Connects to the lightwalletd server at the given endpoint.
///
/// Each connection returned by this method is isolated from any other Tor usage.
///
/// # Safety
///
/// - `tor_runtime` must be a non-null pointer returned by a `zcashlc_*` method with
///   return type `*mut TorRuntime` that has not previously been freed.
/// - `tor_runtime` must not be passed to two FFI calls at the same time.
/// - `endpoint` must be non-null and must point to a null-terminated UTF-8 string.
/// - Call [`zcashlc_free_tor_lwd_conn`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_tor_connect_to_lightwalletd(
    tor_runtime: *mut TorRuntime,
    endpoint: *const c_char,
) -> *mut tor::LwdConn {
    // SAFETY: Callers would have to do the following for unwind safety (#194):
    // - using `*mut TorRuntime` and respecting mutability rules on the Swift side, to
    //   avoid observing the effects of a panic in another thread.
    // - discarding the `TorRuntime` whenever we get an error that is due to a panic.
    let tor_runtime = AssertUnwindSafe(tor_runtime);

    let res = catch_panic(|| {
        let tor_runtime =
            unsafe { tor_runtime.as_mut() }.ok_or_else(|| anyhow!("A Tor runtime is required"))?;

        let endpoint = unsafe { CStr::from_ptr(endpoint).to_str()? }
            .try_into()
            .map_err(|e| anyhow!("Invalid lightwalletd endpoint: {e}"))?;

        let lwd_conn = tor_runtime.connect_to_lightwalletd(endpoint)?;

        Ok(Box::into_raw(Box::new(lwd_conn)))
    });
    unwrap_exc_or_null(res)
}

/// Frees a Tor lightwalletd connection.
///
/// # Safety
///
/// - If `ptr` is non-null, it must be a pointer returned by a `zcashlc_*` method with
///   return type `*mut tor::LwdConn` that has not previously been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_tor_lwd_conn(ptr: *mut tor::LwdConn) {
    if !ptr.is_null() {
        let s: Box<tor::LwdConn> = unsafe { Box::from_raw(ptr) };
        drop(s);
    }
}

/// Returns information about this lightwalletd instance and the blockchain.
///
/// # Safety
///
/// - `lwd_conn` must be a non-null pointer returned by a `zcashlc_*` method with
///   return type `*mut tor::LwdConn` that has not previously been freed.
/// - `lwd_conn` must not be passed to two FFI calls at the same time.
/// - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_tor_lwd_conn_get_info(
    lwd_conn: *mut tor::LwdConn,
) -> *mut ffi::BoxedSlice {
    // SAFETY: We ensure unwind safety by:
    // - using `*mut tor::LwdConn` and respecting mutability rules on the Swift side, to
    //   avoid observing the effects of a panic in another thread.
    // - discarding the `tor::LwdConn` whenever we get an error that is due to a panic.
    let lwd_conn = AssertUnwindSafe(lwd_conn);

    let res = catch_panic(|| {
        let lwd_conn = unsafe { lwd_conn.as_mut() }
            .ok_or_else(|| anyhow!("A Tor lightwalletd connection is required"))?;

        let info = lwd_conn.get_lightd_info()?;

        Ok(ffi::BoxedSlice::some(info.encode_to_vec()))
    });
    unwrap_exc_or_null(res)
}

/// Fetches the height and hash of the block at the tip of the best chain.
///
/// # Safety
///
/// - `lwd_conn` must be a non-null pointer returned by a `zcashlc_*` method with
///   return type `*mut tor::LwdConn` that has not previously been freed.
/// - `lwd_conn` must not be passed to two FFI calls at the same time.
/// - `height_ret` must be non-null and valid for writes for 4 bytes, and it must have an
///   alignment of `1`.
/// - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_tor_lwd_conn_latest_block(
    lwd_conn: *mut tor::LwdConn,
    height_ret: *mut u32,
) -> *mut ffi::BoxedSlice {
    // SAFETY: We ensure unwind safety by:
    // - using `*mut tor::LwdConn` and respecting mutability rules on the Swift side, to
    //   avoid observing the effects of a panic in another thread.
    // - discarding the `tor::LwdConn` whenever we get an error that is due to a panic.
    let lwd_conn = AssertUnwindSafe(lwd_conn);

    let res = catch_panic(|| {
        let lwd_conn = unsafe { lwd_conn.as_mut() }
            .ok_or_else(|| anyhow!("A Tor lightwalletd connection is required"))?;

        let height_ret = unsafe { height_ret.as_mut() }.ok_or_else(|| {
            anyhow!("A mutable pointer to a UInt32 is required to return the height")
        })?;

        let (height, hash) = lwd_conn.get_latest_block()?;

        *height_ret = height.into();

        Ok(ffi::BoxedSlice::some(hash.0.to_vec()))
    });
    unwrap_exc_or_null(res)
}

/// Fetches the transaction with the given ID.
///
/// # Safety
///
/// - `lwd_conn` must be a non-null pointer returned by a `zcashlc_*` method with
///   return type `*mut tor::LwdConn` that has not previously been freed.
/// - `lwd_conn` must not be passed to two FFI calls at the same time.
/// - `txid_bytes` must be non-null and valid for reads for 32 bytes, and it must have an
///   alignment of `1`.
/// - `height_ret` must be non-null and valid for writes for 8 bytes, and it must have an
///   alignment of `1`.
/// - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_tor_lwd_conn_fetch_transaction(
    lwd_conn: *mut tor::LwdConn,
    txid_bytes: *const u8,
    height_ret: *mut u64,
) -> *mut ffi::BoxedSlice {
    // SAFETY: Callers would have to do the following for unwind safety (#194):
    // - using `*mut tor::LwdConn` and respecting mutability rules on the Swift side, to
    //   avoid observing the effects of a panic in another thread.
    // - discarding the `tor::LwdConn` whenever we get an error that is due to a panic.
    let lwd_conn = AssertUnwindSafe(lwd_conn);

    let res = catch_panic(|| {
        let lwd_conn = unsafe { lwd_conn.as_mut() }
            .ok_or_else(|| anyhow!("A Tor lightwalletd connection is required"))?;

        let txid_bytes = unsafe { slice::from_raw_parts(txid_bytes, 32) };
        let txid = TxId::from_bytes(txid_bytes.try_into().unwrap());

        let height_ret = unsafe { height_ret.as_mut() }.ok_or_else(|| {
            anyhow!("A mutable pointer to a UInt64 is required to return the height")
        })?;

        let (tx, height) = lwd_conn.get_transaction(txid)?;

        *height_ret = height;

        Ok(ffi::BoxedSlice::some(tx))
    });
    unwrap_exc_or_null(res)
}

/// Submits a transaction to the Zcash network via the given lightwalletd connection.
///
/// # Safety
///
/// - `lwd_conn` must be a non-null pointer returned by a `zcashlc_*` method with
///   return type `*mut tor::LwdConn` that has not previously been freed.
/// - `lwd_conn` must not be passed to two FFI calls at the same time.
/// - `tx` must be non-null and valid for reads for `tx_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `tx` must not be mutated for the duration of the function call.
/// - The total size `tx_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_tor_lwd_conn_submit_transaction(
    lwd_conn: *mut tor::LwdConn,
    tx: *const u8,
    tx_len: usize,
) -> bool {
    // SAFETY: Callers would have to do the following for unwind safety (#194):
    // - using `*mut tor::LwdConn` and respecting mutability rules on the Swift side, to
    //   avoid observing the effects of a panic in another thread.
    // - discarding the `tor::LwdConn` whenever we get an error that is due to a panic.
    let lwd_conn = AssertUnwindSafe(lwd_conn);

    let res = catch_panic(|| {
        let lwd_conn = unsafe { lwd_conn.as_mut() }
            .ok_or_else(|| anyhow!("A Tor lightwalletd connection is required"))?;

        let tx_bytes = unsafe { slice::from_raw_parts(tx, tx_len) };

        lwd_conn.send_transaction(tx_bytes.to_vec())?;

        Ok(true)
    });
    unwrap_exc_or(res, false)
}

/// Fetches the note commitment tree state corresponding to the given block height.
///
/// # Safety
///
/// - `lwd_conn` must be a non-null pointer returned by a `zcashlc_*` method with
///   return type `*mut tor::LwdConn` that has not previously been freed.
/// - `lwd_conn` must not be passed to two FFI calls at the same time.
/// - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_tor_lwd_conn_get_tree_state(
    lwd_conn: *mut tor::LwdConn,
    height: u32,
) -> *mut ffi::BoxedSlice {
    // SAFETY: We ensure unwind safety by:
    // - using `*mut tor::LwdConn` and respecting mutability rules on the Swift side, to
    //   avoid observing the effects of a panic in another thread.
    // - discarding the `tor::LwdConn` whenever we get an error that is due to a panic.
    let lwd_conn = AssertUnwindSafe(lwd_conn);

    let res = catch_panic(|| {
        let lwd_conn = unsafe { lwd_conn.as_mut() }
            .ok_or_else(|| anyhow!("A Tor lightwalletd connection is required"))?;

        let height = BlockHeight::from(height);

        let treestate = lwd_conn.get_tree_state(height)?;

        Ok(ffi::BoxedSlice::some(treestate.encode_to_vec()))
    });
    unwrap_exc_or_null(res)
}

/// Finds all transactions associated with the given transparent address within the given block
/// range, and calls [`decrypt_and_store_transaction`] with each such transaction.
///
/// The query to the light wallet server will cover the provided block range. The end height is
/// optional; to omit the end height for the query range use the sentinel value `-1`. If any other
/// value is specified, it must be in the range of a valid u32. Note that older versions of
/// `lightwalletd` will return an error if the end height is not specified.
///
/// Returns an [`ffi::AddressCheckResult`] if successful, or a null pointer in the case of an
/// error.
///
/// # Safety
///
/// - `lwd_conn` must be a non-null pointer returned by a `zcashlc_*` method with
///   return type `*mut tor::LwdConn` that has not previously been freed.
/// - `lwd_conn` must not be passed to two FFI calls at the same time.
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Call [`zcashlc_free_address_check_result`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_tor_lwd_conn_update_transparent_address_transactions(
    lwd_conn: *mut tor::LwdConn,
    wallet_db_handle: *mut WalletDbHandle,
    address: *const c_char,
    start: u32,
    end: i64,
) -> *mut ffi::AddressCheckResult {
    // SAFETY: We ensure unwind safety by:
    // - using `*mut tor::LwdConn` and respecting mutability rules on the Swift side, to
    //   avoid observing the effects of a panic in another thread.
    // - discarding the `tor::LwdConn` whenever we get an error that is due to a panic.
    let lwd_conn = AssertUnwindSafe(lwd_conn);
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);

    let res = catch_panic(|| {
        let lwd_conn = unsafe { lwd_conn.as_mut() }
            .ok_or_else(|| anyhow!("A Tor lightwalletd connection is required"))?;

        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let network = wallet_db_handle.network();

        let addr_str = unsafe { CStr::from_ptr(address).to_str()? };
        let addr = TransparentAddress::decode(&network, addr_str)?;

        let cur_height = wallet_db_handle
            .db()
            .chain_height()?
            .ok_or(SqliteClientError::ChainHeightUnknown)?;

        let mut found = None;
        lwd_conn.with_taddress_transactions(
            &network,
            addr,
            BlockHeight::from(start),
            parse_optional_height(end)?,
            |tx_data, mined_height| {
                found = Some(addr);
                let consensus_branch_id =
                    BranchId::for_height(&network, mined_height.unwrap_or(cur_height + 1));

                let tx = Transaction::read(&tx_data[..], consensus_branch_id)?;
                decrypt_and_store_transaction(
                    &network,
                    wallet_db_handle.db_mut(),
                    &tx,
                    mined_height,
                )?;

                Ok(())
            },
        )?;

        Ok(ffi::AddressCheckResult::from_rust(&network, found))
    });

    unwrap_exc_or_null(res)
}

/// Checks to find any UTXOs associated with the given transparent address.
///
/// This check will cover the block range starting at the exposure height for that address, if
/// known, or otherwise at the birthday height of the specified account.
///
/// Returns an [`ffi::AddressCheckResult`] if successful, or a null pointer in the case of an
/// error.
///
/// # Safety
///
/// - `lwd_conn` must be a non-null pointer returned by a `zcashlc_*` method with
///   return type `*mut tor::LwdConn` that has not previously been freed.
/// - `lwd_conn` must not be passed to two FFI calls at the same time.
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Call [`zcashlc_free_address_check_result`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_tor_lwd_conn_fetch_utxos_by_address(
    lwd_conn: *mut tor::LwdConn,
    wallet_db_handle: *mut WalletDbHandle,
    account_uuid_bytes: *const u8,
    address: *const c_char,
) -> *mut ffi::AddressCheckResult {
    // SAFETY: We ensure unwind safety by:
    // - using `*mut tor::LwdConn` and respecting mutability rules on the Swift side, to
    //   avoid observing the effects of a panic in another thread.
    // - discarding the `tor::LwdConn` whenever we get an error that is due to a panic.
    let lwd_conn = AssertUnwindSafe(lwd_conn);
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);

    let res = catch_panic(|| {
        let lwd_conn = unsafe { lwd_conn.as_mut() }
            .ok_or_else(|| anyhow!("A Tor lightwalletd connection is required"))?;

        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let network = wallet_db_handle.network();
        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;

        let addr_str = unsafe { CStr::from_ptr(address).to_str()? };
        let addr = TransparentAddress::decode(&network, addr_str)?;

        let mut found = None;
        if let Some(meta) = wallet_db_handle
            .db()
            .get_transparent_address_metadata(account_uuid, &addr)?
        {
            lwd_conn.with_taddress_utxos(
                &network,
                addr,
                match meta.exposure() {
                    Exposure::Exposed { at_height, .. } => Some(at_height),
                    Exposure::Unknown | Exposure::CannotKnow => {
                        Some(wallet_db_handle.db().get_account_birthday(account_uuid)?)
                    }
                },
                None,
                |output| {
                    found = Some(addr);
                    wallet_db_handle
                        .db_mut()
                        .put_received_transparent_utxo(&output)?;
                    Ok(())
                },
            )?;
        }

        Ok(ffi::AddressCheckResult::from_rust(&network, found))
    });

    unwrap_exc_or_null(res)
}

/// Checks to find any single-use ephemeral addresses exposed in the past day that have not yet
/// received funds, excluding any whose next check time is in the future. This will then choose the
/// address that is most overdue for checking, retrieve any UTXOs for that address over Tor, and
/// add them to the wallet database. If no such UTXOs are found, the check will be rescheduled
/// following an expoential-backoff-with-jitter algorithm.
///
/// Returns an [`ffi::AddressCheckResult`] if successful, or a null pointer in the case of an
/// error.
///
/// # Safety
///
/// - `lwd_conn` must be a non-null pointer returned by a `zcashlc_*` method with
///   return type `*mut tor::LwdConn` that has not previously been freed.
/// - `lwd_conn` must not be passed to two FFI calls at the same time.
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Call [`zcashlc_free_address_check_result`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_tor_lwd_conn_check_single_use_taddr(
    lwd_conn: *mut tor::LwdConn,
    wallet_db_handle: *mut WalletDbHandle,
    account_uuid_bytes: *const u8,
) -> *mut ffi::AddressCheckResult {
    // SAFETY: We ensure unwind safety by:
    // - using `*mut tor::LwdConn` and respecting mutability rules on the Swift side, to
    //   avoid observing the effects of a panic in another thread.
    // - discarding the `tor::LwdConn` whenever we get an error that is due to a panic.
    let lwd_conn = AssertUnwindSafe(lwd_conn);
    let wallet_db_handle = AssertUnwindSafe(wallet_db_handle);

    let res = catch_panic(|| {
        let wallet_db_handle = unsafe { wallet_db_handle.as_mut() }
            .ok_or_else(|| anyhow!("Database handle is required"))?;
        let network = wallet_db_handle.network();
        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;

        let lwd_conn = unsafe { lwd_conn.as_mut() }
            .ok_or_else(|| anyhow!("A Tor lightwalletd connection is required"))?;

        // one day's worth of blocks.
        let max_exposure_depth = (24 * 60 * 60) / 75;
        let addrs = wallet_db_handle.db().get_ephemeral_transparent_receivers(
            account_uuid,
            max_exposure_depth,
            true,
        )?;

        // pick the address with the minimum check time that is less than or equal to now (or
        // absent)
        let now = SystemTime::now();
        let selected_addr_meta = addrs
            .into_iter()
            .filter(|(_, meta)| {
                meta.next_check_time().iter().all(|t| t <= &now)
                    && matches!(meta.exposure(), Exposure::Exposed { .. })
            })
            .min_by_key(|(_, meta)| meta.next_check_time());

        let cur_height = wallet_db_handle
            .db()
            .chain_height()?
            .ok_or(SqliteClientError::ChainHeightUnknown)?;

        let mut found = None;
        if let Some((addr, meta)) = selected_addr_meta {
            lwd_conn.with_taddress_transactions(
                &network,
                addr,
                match meta.exposure() {
                    Exposure::Exposed { at_height, .. } => at_height,
                    Exposure::Unknown | Exposure::CannotKnow => {
                        panic!("unexposed addresses should have already been filtered out");
                    }
                },
                Some(cur_height + 1),
                |tx_data, mined_height| {
                    found = Some(addr);
                    let consensus_branch_id =
                        BranchId::for_height(&network, mined_height.unwrap_or(cur_height + 1));

                    let tx = Transaction::read(&tx_data[..], consensus_branch_id)?;
                    decrypt_and_store_transaction(
                        &network,
                        wallet_db_handle.db_mut(),
                        &tx,
                        mined_height,
                    )?;

                    Ok(())
                },
            )?;

            if found.is_none() {
                let blocks_since_exposure = match meta.exposure() {
                    Exposure::Exposed { at_height, .. } => {
                        f64::from(std::cmp::max(cur_height - at_height, 1))
                    }
                    Exposure::Unknown => 1.0,
                    Exposure::CannotKnow => 1.0,
                };

                // We will schedule the next check to occur after approximately
                // log2(blocks_since_exposure) additional blocks.
                let offset_blocks = blocks_since_exposure.log2();
                // Convert the offset in blocks to an offset in seconds; this will always fit in a
                // u32.
                let offset_seconds = (offset_blocks * 75.0).round() as u32;
                wallet_db_handle
                    .db_mut()
                    .schedule_next_check(&addr, offset_seconds)?;
            }
        }

        Ok(ffi::AddressCheckResult::from_rust(&network, found))
    });

    unwrap_exc_or_null(res)
}

//
// Utility functions
//

fn parse_network(value: u32) -> anyhow::Result<Network> {
    match value {
        0 => Ok(TestNetwork),
        1 => Ok(MainNetwork),
        _ => Err(anyhow!(
            "Invalid network type: {}. Expected either 0 or 1 for Testnet or Mainnet, respectively.",
            value
        )),
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
        let mut s = unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) };
        for k in s.iter_mut() {
            f(k);
        }
        drop(s);
    }
}

pub(crate) fn parse_optional_height(value: i64) -> anyhow::Result<Option<BlockHeight>> {
    Ok(match value {
        -1 => None,
        _ => Some(BlockHeight::try_from(value)?),
    })
}
