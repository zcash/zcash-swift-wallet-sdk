#![deny(unsafe_op_in_unsafe_fn)]

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

use anyhow::{Context, anyhow};
use bitflags::bitflags;
use ffi_helpers::panic::catch_panic;
use http_body_util::BodyExt;
use nonempty::NonEmpty;
use pczt::{
    Pczt,
    roles::{combiner::Combiner, prover::Prover},
};
use prost::Message;
use rand::rngs::OsRng;
use secrecy::Secret;
use tor_rtcompat::ToplevelBlockOn as _;
use tracing::{debug, metadata::LevelFilter};
use tracing_subscriber::prelude::*;
use uuid::Uuid;

use transparent::{
    address::TransparentAddress,
    bundle::{OutPoint, TxOut},
    keys::TransparentKeyScope,
};
use zcash_address::ZcashAddress;
use zcash_client_backend::{
    address::Address,
    data_api::{
        Account, AccountBirthday, AccountPurpose, CoinbaseFilter, InputSource, MaxSpendMode,
        SeedRelevance, TransactionDataRequest, TransactionStatus, TransparentKeyOrigin,
        WalletCommitmentTrees, WalletRead, WalletWrite, Zip32Derivation,
        anchor_retention::AnchorRetentionInterval,
        chain::{CommitmentTreeRoot, scan_cached_blocks},
        scanning::ScanPriority,
        wallet::{
            self, SignerView, SpendingKeys, create_pczt_from_proposal,
            create_proposed_transactions, decrypt_and_store_transaction,
            extract_and_store_transaction_from_pczt,
            input_selection::{GreedyInputSelector, LockFilter, LockedInputPolicy, SpendPolicy},
            propose_send_max_transfer, propose_shielding, propose_transfer, redact_pczt_for_signer,
        },
    },
    encoding::AddressCodec,
    fees::{DustOutputPolicy, SplitPolicy, StandardFeeRule, zip317::MultiOutputChangeStrategy},
    keys::{
        DecodingError, Era, ReceiverRequirement, ReceiverRequirementError, UnifiedAddressRequest,
        UnifiedFullViewingKey, UnifiedSpendingKey,
    },
    proto::{proposal::Proposal, service::TreeState},
    tor::http::{HttpError, cryptex},
    wallet::{Exposure, GapMetadata, NoteId, OvkPolicy, WalletTransparentOutput},
    zip321::{Payment, TransactionRequest},
};
use zcash_client_sqlite::{
    AccountUuid, FsBlockDb, WalletDb,
    chain::{BlockMeta, init::init_blockmeta_db},
    error::SqliteClientError,
    util::SystemClock,
    wallet::init::{WalletMigrationError, WalletMigrator},
};
use zcash_primitives::{
    block::BlockHash,
    merkle_tree::HashSer,
    transaction::builder::BundlePadding,
    transaction::{Transaction, TxId},
};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{
    ShieldedPool,
    consensus::{
        BlockHeight, BranchId, Network,
        Network::{MainNetwork, TestNetwork},
        NetworkType, NetworkUpgrade, Parameters,
    },
    local_consensus::LocalNetwork,
    memo::MemoBytes,
    value::{ZatBalance, Zatoshis},
};
use zcash_script::script;
use zip32::fingerprint::SeedFingerprint;

mod derivation;
mod eip681;
mod ext_schema;
mod ffi;
mod migration;
mod migration_engine;
mod migration_finalize;
mod migration_keystone;
mod migration_plan_cache;
mod migration_turnstile;
mod retained_marks;
mod tor;
mod voting;

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

/// The anchor bucket interval used on every network other than production mainnet: 12 blocks, so
/// that a ZIP 318 pool migration passes through enough anchor boundaries to be exercised end to
/// end in a test run instead of over days of chain.
///
/// Shortening the grid also shortens the transfer and preparation delays, which the migration
/// backend derives from it, so this is the only value to choose.
const TEST_ANCHOR_RETENTION_INTERVAL: AnchorRetentionInterval =
    AnchorRetentionInterval::custom(NonZeroU32::new(12).expect("12 is nonzero"));

/// The grid on which a wallet on `network` retains note commitment tree checkpoints as durable
/// anchors, and correspondingly the grid its pool migrations anchor their transfers to.
///
/// Production mainnet gets the ZIP 318 interval, which every wallet on that network must share:
/// the anonymity set a boundary anchor provides is exactly the set of transfers that chose the same
/// boundary, so a wallet retaining a different grid than its peers is distinguishable from them.
/// Testnet and custom-parameter networks — which exist to exercise the migration, not to hide in a
/// crowd — get [`TEST_ANCHOR_RETENTION_INTERVAL`].
pub(crate) fn anchor_retention_interval(network: NetworkParams) -> AnchorRetentionInterval {
    match network {
        NetworkParams::Standard(MainNetwork) => AnchorRetentionInterval::ZIP_318,
        NetworkParams::Standard(TestNetwork) | NetworkParams::Custom { .. } => {
            TEST_ANCHOR_RETENTION_INTERVAL
        }
    }
}

/// The busy_timeout every connection onto the wallet database file must use while the slipstream
/// engine is a potential concurrent writer. Upstream sets none; a host write (or a migration-store
/// call, see `migration::open_store_conn`) landing while the engine's writer holds the lock
/// (`deleteAccount`/`importAccount` mid-pass, or a write-behind commit) would otherwise die with an
/// instant SQLITE_BUSY instead of waiting. 15 s matches the engine's main-connection posture
/// (wallet_session.rs). Behavior-neutral for the legacy engine: it has no concurrent writer to wait
/// on, so the timeout never engages.
pub(crate) const WALLET_DB_BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Helper method for construcing a WalletDb value from path data provided over the FFI.
///
/// The returned handle retains its durable anchor checkpoints on the interval
/// [`anchor_retention_interval`] selects for `network`, which is also the grid the next pool
/// migration planned over this wallet will anchor to. Every wallet handle the FFI hands out is
/// built here, so the two cannot be configured inconsistently.
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
    network: NetworkParams,
) -> anyhow::Result<WalletDb<rusqlite::Connection, NetworkParams, SystemClock, OsRng>> {
    let db_data = Path::new(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(db_data, db_data_len)
    }));
    // Mirror `WalletDb::for_path` (open + array vtab + wrap) but give the connection
    // a busy_timeout first — see `WALLET_DB_BUSY_TIMEOUT` above for the rationale.
    let conn = rusqlite::Connection::open(db_data)
        .map_err(|e| anyhow!("Error opening wallet database connection: {}", e))?;
    conn.busy_timeout(WALLET_DB_BUSY_TIMEOUT)
        .map_err(|e| anyhow!("Error setting wallet database busy_timeout: {}", e))?;
    rusqlite::vtab::array::load_module(&conn)
        .map_err(|e| anyhow!("Error loading wallet database array module: {}", e))?;
    Ok(WalletDb::from_connection(conn, network, SystemClock, OsRng)
        .with_anchor_retention_interval(anchor_retention_interval(network)))
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

pub(crate) fn account_uuid_from_bytes(
    uuid_bytes: *const u8,
) -> Result<AccountUuid, TryFromSliceError> {
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

    // Per-target filter instead of a bare global level:
    // upstream `zcash_client_backend` #[instrument]s every block and batch
    // (~600k spans per fresh restore) at INFO, and through the os_log +
    // signpost layers each span costs syscalls on the scan producer thread
    // — measured as production pass1 3.4 s vs 0.5 s in the filtered
    // CLI/probe (2026-07-08 A18 seal log). Cap that crate at WARN; the
    // host-chosen level still governs everything else (engine logs
    // unchanged). Mirrors the filter the CLI and bench probe ship since
    // v0.6 P6.
    let log_filter = tracing_subscriber::filter::Targets::new()
        .with_default(log_filter)
        .with_target("zcash_client_backend", LevelFilter::WARN);

    // Set up the tracing layers for the Apple OS logging framework.
    #[cfg(target_vendor = "apple")]
    let (log_layer, signpost_layer) = os_log::layers("co.electriccoin.ios", "rust");

    // Install the `tracing` subscriber.
    let registry = tracing_subscriber::registry();
    #[cfg(target_vendor = "apple")]
    let registry = registry.with(log_layer).with(signpost_layer);
    registry.with(log_filter).init();

    // Freshness marker for the FFI layer itself (the engine's ENGINE_BUILD
    // can't see rust/ changes — this line is the slice-staleness truth for
    // the subscriber): greppable in device logs AND via `strings` on the
    // built slice.
    tracing::info!(
        zcashlc_build = "2026-08-02.v0.13-proved-tx-wallet-persistence",
        "tracing initialized (zcash_client_backend capped at WARN)"
    );

    // Log panics instead of writing them to stderr.
    log_panics::init();

    // Manually build the Rayon thread pool, so we can name the threads — and, on Apple
    // platforms, drop every worker to UTILITY QoS. Halo2 proving saturates all cores through
    // this pool for seconds per proof; at default priority that starves the UI (an app-open
    // prove sweep froze interactive screens for the sweep's whole duration). UTILITY keeps
    // full-width proving when the device is idle (the overnight BGTask path) while letting
    // user-interactive work preempt it. Thread count is deliberately unchanged.
    #[cfg(target_vendor = "apple")]
    unsafe extern "C" {
        fn pthread_set_qos_class_self_np(
            qos_class: core::ffi::c_uint,
            relative_priority: core::ffi::c_int,
        ) -> core::ffi::c_int;
    }
    #[cfg(target_vendor = "apple")]
    const QOS_CLASS_UTILITY: core::ffi::c_uint = 0x11;

    let pool_builder = rayon::ThreadPoolBuilder::new().thread_name(|i| format!("zc-rayon-{}", i));
    #[cfg(target_vendor = "apple")]
    let pool_builder = pool_builder.start_handler(|_| unsafe {
        let _ = pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, 0);
    });
    pool_builder.build_global().expect("Only initialized once");

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
#[unsafe(no_mangle)]
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

        let migrator =
            WalletMigrator::new().with_external_migrations(ext_schema::external_migrations());
        let migrator = match seed {
            Some(seed) => migrator.with_seed(seed),
            None => migrator,
        };
        match migrator.init_or_migrate(&mut db_data) {
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
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Call [`zcashlc_free_accounts`] to free the memory associated with the returned pointer
///   when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_list_accounts(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
) -> *mut ffi::Accounts {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        Ok(ffi::Accounts::ptr_from_vec(
            db_data
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
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
///   function call.
/// - Call [`zcashlc_free_account`] to free the memory associated with the returned pointer
///   when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_get_account(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
    account_uuid_bytes: *const u8,
) -> *mut ffi::Account {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;

        Ok(Box::into_raw(Box::new(
            db_data
                .get_account(account_uuid)?
                .map_or(ffi::Account::NOT_FOUND, |account| {
                    ffi::Account::from_account(&account, &network)
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
    db_data: *const u8,
    db_data_len: usize,
    seed: *const u8,
    seed_len: usize,
    treestate: *const u8,
    treestate_len: usize,
    recover_until: i64,
    network_id: u32,
    account_name: *const c_char,
    key_source: *const c_char,
) -> *mut ffi::BinaryKey {
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
                // `BirthdayError` is `#[non_exhaustive]`; this arm is unreachable
                // against enum versions that expose only the variants above.
                #[allow(unreachable_patterns)]
                _ => anyhow!("Invalid TreeState: unrecognized birthday error"),
            })?;

        let account_name = unsafe { CStr::from_ptr(account_name).to_str()? };
        let key_source = (!key_source.is_null())
            .then(|| unsafe { CStr::from_ptr(key_source).to_str() })
            .transpose()?;

        let (account_uuid, usk) = db_data
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
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
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
    db_data: *const u8,
    db_data_len: usize,
    ufvk: *const c_char,
    treestate: *const u8,
    treestate_len: usize,
    recover_until: i64,
    network_id: u32,
    purpose: u32,
    account_name: *const c_char,
    key_source: *const c_char,
    seed_fingerprint: *const u8,
    hd_account_index_raw: u32,
) -> *mut ffi::Uuid {
    use zcash_client_backend::data_api::BirthdayError;

    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
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
                // `BirthdayError` is `#[non_exhaustive]`; this arm is unreachable
                // against enum versions that expose only the variants above.
                #[allow(unreachable_patterns)]
                _ => anyhow!("Invalid TreeState: unrecognized birthday error"),
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

        let account = db_data
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
#[unsafe(no_mangle)]
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

        // Replicate the logic from `initWalletDb`. `NoDerivedAccounts` (the
        // wallet has accounts but all are imported, e.g. hardware-wallet UFVKs)
        // is treated as relevant like `NoAccounts`: there is no seed-derived
        // account for the seed to conflict with, so opening must not be blocked.
        // Only `NotRelevant` — the seed derives none of the existing *derived*
        // accounts — is a genuine mismatch.
        Ok(match db_data.seed_relevance_to_derived_accounts(&seed)? {
            SeedRelevance::Relevant { .. }
            | SeedRelevance::NoAccounts
            | SeedRelevance::NoDerivedAccounts => 1,
            SeedRelevance::NotRelevant => 0,
        })
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
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `seed` must be non-null and valid for reads for `seed_len` bytes, and it must have an
///   alignment of `1`.
///
/// [`OvkPolicy::Discard`]: zcash_client_backend::wallet::OvkPolicy::Discard
/// [`OvkPolicy::Custom`]: zcash_client_backend::wallet::OvkPolicy::Custom
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_delete_account(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
    account_uuid_bytes: *const u8,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;

        db_data.delete_account(account_uuid)?;

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
pub(crate) unsafe fn decode_usk(
    usk_ptr: *const u8,
    usk_len: usize,
) -> anyhow::Result<UnifiedSpendingKey> {
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
/// - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
///   function call.
/// - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
///   when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_get_current_address(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;

        match db_data.get_last_generated_address_matching(
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
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
///   function call.
/// - Call [`zcashlc_free_single_use_address`] to free the memory associated with the returned pointer
///   when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_get_single_use_taddr(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
    account_uuid_bytes: *const u8,
) -> *mut ffi::SingleUseTaddr {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;

        match db_data.reserve_next_n_ephemeral_addresses(account_uuid, 1) {
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
    fn to_address_request(self) -> Result<UnifiedAddressRequest, ReceiverRequirementError> {
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
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
///   function call.
/// - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
///   when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_get_next_available_address(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    receiver_flags: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;
        let receiver_flags = ReceiverFlags::from_bits(receiver_flags)
            .ok_or_else(|| anyhow!("Invalid unified address receiver flags {}", receiver_flags))?;
        let address_request = receiver_flags.to_address_request().map_err(|e| {
            anyhow!(
                "Could not generate a valid unified address for flags {}: {}",
                receiver_flags.bits(),
                e
            )
        })?;

        match db_data.get_next_available_address(account_uuid, address_request) {
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
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
///   function call.
/// - Call [`zcashlc_free_keys`] to free the memory associated with the returned pointer
///   when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_list_transparent_receivers(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> *mut ffi::EncodedKeys {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;

        // Zashi does not support standalone keys, so we do not request standalone receivers.
        match db_data.get_transparent_receivers(account_uuid, true, false) {
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
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `address` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `address` must not be mutated for the duration of the function call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_get_verified_transparent_balance(
    db_data: *const u8,
    db_data_len: usize,
    address: *const c_char,
    network_id: u32,
    confirmations_policy: ffi::ConfirmationsPolicy,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let addr = unsafe { CStr::from_ptr(address).to_str()? };
        let taddr = TransparentAddress::decode(&network, addr)?;
        let confirmations_policy = wallet::ConfirmationsPolicy::try_from(confirmations_policy)?;
        let (target, _) = db_data
            .get_target_and_anchor_heights(confirmations_policy.untrusted())
            .map_err(|e| anyhow!("Error while fetching target height: {}", e))?
            .context("Target height not available; scan required.")?;
        let utxos = db_data
            .get_spendable_transparent_outputs(
                &taddr,
                target,
                confirmations_policy,
                CoinbaseFilter::AllTransparentOutputs,
                LockFilter::Policy(&LockedInputPolicy::Exclude),
            )
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
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
///   function call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_get_verified_transparent_balance_for_account(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
    account_uuid_bytes: *const u8,
    confirmations_policy: ffi::ConfirmationsPolicy,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;

        let (target, _) = db_data
            .get_target_and_anchor_heights(NonZeroU32::MIN)
            .map_err(|e| anyhow!("Error while fetching anchor height: {}", e))?
            .context("Target height not available; scan required.")?;
        // Zashi does not support standalone keys, so we do not request standalone receivers.
        let receivers = db_data
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
                db_data
                    .get_spendable_transparent_outputs(
                        taddr,
                        target,
                        confirmations_policy,
                        CoinbaseFilter::AllTransparentOutputs,
                        LockFilter::Policy(&LockedInputPolicy::Exclude),
                    )
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
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `address` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `address` must not be mutated for the duration of the function call.
#[unsafe(no_mangle)]
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
        let taddr = TransparentAddress::decode(&network, addr)?;
        let (target, _) = db_data
            .get_target_and_anchor_heights(NonZeroU32::MIN)
            .map_err(|e| anyhow!("Error while fetching target height: {}", e))?
            .context("Target height not available; scan required.")?;
        let amount = db_data
            .get_spendable_transparent_outputs(
                &taddr,
                target,
                wallet::ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, true),
                CoinbaseFilter::AllTransparentOutputs,
                LockFilter::Policy(&LockedInputPolicy::Exclude),
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
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
///   function call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_get_total_transparent_balance_for_account(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
    account_uuid_bytes: *const u8,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;

        let (target, _) = db_data
            .get_target_and_anchor_heights(NonZeroU32::MIN)
            .map_err(|e| anyhow!("Error while fetching anchor height: {}", e))?
            .context("height not available; scan required.")?;
        let confirmations_policy =
            wallet::ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, true);
        let balances = db_data
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

/// Decodes a wallet-database pool code (`zcash_client_sqlite`'s `pool_code`) into its shielded
/// protocol. Transparent (0) has no shielded protocol and yields `None`, as does any code the
/// wallet database does not use.
fn parse_protocol(code: u32) -> Option<ShieldedPool> {
    match code {
        2 => Some(ShieldedPool::Sapling),
        3 => Some(ShieldedPool::Orchard),
        4 => Some(ShieldedPool::Ironwood),
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
#[unsafe(no_mangle)]
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
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[unsafe(no_mangle)]
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

/// Truncates the data database to the specified chain state.
///
/// In contrast to [`zcashlc_rewind_to_height`], this function allows the caller to truncate the
/// wallet database to a precise height by providing additional chain state information needed for
/// note commitment tree maintenance after the truncation.
///
/// The `chain_state` parameter is a protobuf-encoded `TreeState` value representing the chain
/// state at the height to which the database should be truncated.
///
/// Returns `true` if the truncation succeeded, or `false` if an error occurred. When `false` is
/// returned, the caller should check for errors.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `chain_state` must be non-null and valid for reads for `chain_state_len` bytes, and it must
///   have an alignment of `1`. Its contents must be a protobuf-encoded `TreeState` value.
/// - The memory referenced by `chain_state` must not be mutated for the duration of the function
///   call.
/// - The total size `chain_state_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_truncate_to_chain_state(
    db_data: *const u8,
    db_data_len: usize,
    chain_state: *const u8,
    chain_state_len: usize,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let chain_state =
            TreeState::decode(unsafe { slice::from_raw_parts(chain_state, chain_state_len) })
                .map_err(|e| anyhow!("Invalid TreeState: {}", e))?
                .to_chain_state()?;

        db_data
            .truncate_to_chain_state(chain_state)
            .map_err(|e| anyhow!("Error while truncating to chain state: {}", e))?;

        Ok(true)
    });
    unwrap_exc_or(res, false)
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_put_sapling_subtree_roots(
    db_data: *const u8,
    db_data_len: usize,
    start_index: u64,
    roots: *const ffi::SubtreeRoots,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_put_orchard_subtree_roots(
    db_data: *const u8,
    db_data_len: usize,
    start_index: u64,
    roots: *const ffi::SubtreeRoots,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

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

        db_data
            .put_orchard_subtree_roots(start_index, &roots)
            .map(|()| true)
            .map_err(|e| anyhow!("Error while storing Orchard subtree roots: {}", e))
    });
    unwrap_exc_or(res, false)
}

/// Adds a sequence of Ironwood subtree roots to the data store.
///
/// Ironwood is Orchard note-version V3 and shares Orchard's commitment-tree machinery, so the roots
/// are Orchard-shaped; they are tracked in a dedicated Ironwood commitment tree.
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_put_ironwood_subtree_roots(
    db_data: *const u8,
    db_data_len: usize,
    start_index: u64,
    roots: *const ffi::SubtreeRoots,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

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

        db_data
            .put_ironwood_subtree_roots(start_index, &roots)
            .map(|()| true)
            .map_err(|e| anyhow!("Error while storing Ironwood subtree roots: {}", e))
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
/// - Call [`zcashlc_free_wallet_summary`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_get_wallet_summary(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
    confirmations_policy: ffi::ConfirmationsPolicy,
) -> *mut ffi::WalletSummary {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let confirmations_policy = wallet::ConfirmationsPolicy::try_from(confirmations_policy)?;

        match db_data
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
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must
///   have an alignment of `1`. Its contents must be a string representing a valid system
///   path in the operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the
///   function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Call [`zcashlc_free_scan_ranges`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_suggest_scan_ranges(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
) -> *mut ffi::ScanRanges {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let ranges = db_data
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
#[unsafe(no_mangle)]
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
) -> *mut ffi::ScanSummary {
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
#[unsafe(no_mangle)]
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
        let script_pubkey = transparent::address::Script(script::Code(script_bytes.to_vec()));

        // The ironwood-era API adds optional recipient/funding attribution
        // params — `None` defers to the store's own address→account resolution
        // (the pre-existing behavior of this ingest path).
        let recipient_account = None;
        let key_scope = None;
        let funding_account = None;
        let output = WalletTransparentOutput::from_parts(
            OutPoint::new(txid, index as u32),
            TxOut::new(
                Zatoshis::from_nonnegative_i64(value).map_err(|_| anyhow!("Invalid UTXO value"))?,
                script_pubkey,
            ),
            Some(BlockHeight::from(height as u32)),
            recipient_account,
            key_scope,
            funding_account,
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
#[unsafe(no_mangle)]
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
///   memory reference by this pointer is not freed up, dereferenced or invalidated while this
///   function is invoked.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_write_block_metadata(
    fs_block_db_root: *const u8,
    fs_block_db_root_len: usize,
    blocks_meta: *mut ffi::BlocksMeta,
) -> bool {
    let res = catch_panic(|| {
        let block_db = block_db(fs_block_db_root, fs_block_db_root_len)?;

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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
/// - `txid_ret` must be non-null and valid for writes of 32 bytes with an alignment of 1.
///   On successful execution this will contain the txid of the decrypted transaction.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_decrypt_and_store_transaction(
    db_data: *const u8,
    db_data_len: usize,
    tx: *const u8,
    tx_len: usize,
    mined_height: i64,
    network_id: u32,
    txid_ret: *mut u8,
) -> i32 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
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

        match decrypt_and_store_transaction(&network, &mut db_data, &tx, mined_height) {
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
            ShieldedPool::Orchard,
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
/// - `to` must be non-null and must point to a null-terminated UTF-8 string.
/// - `memo` must either be null (indicating an empty memo or a transparent recipient) or point to a
///   512-byte array.
/// - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_propose_transfer(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    to: *const c_char,
    value: i64,
    memo: *const u8,
    network_id: u32,
    confirmations_policy: ffi::ConfirmationsPolicy,
) -> *mut ffi::BoxedSlice {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

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
            Payment::new(to, Some(value), memo, None, None, vec![])
                .map_err(|e| anyhow!("Unable to construct payment: {}.", e))?,
        ])
        .map_err(|e| anyhow!("Error creating transaction request: {:?}", e))?;

        let spend_policy = SpendPolicy::default();
        let lock_inputs = None;
        let proposed_version = None;
        let proposal = propose_transfer::<_, _, _, _, Infallible>(
            &mut db_data,
            &network,
            account_uuid,
            &input_selector,
            &change_strategy,
            req,
            wallet::ConfirmationsPolicy::try_from(confirmations_policy)?,
            &spend_policy,
            lock_inputs,
            proposed_version,
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
/// - `to` must be non-null and must point to a null-terminated UTF-8 string.
/// - `memo` must either be null (indicating an empty memo or a transparent recipient) or point to a
///   512-byte array.
/// - `orchard_only`: when `true`, restricts the spendable pools to Orchard alone (the Orchard→
///   Ironwood immediate migration lane's sweep, which must not draw on Sapling funds); when
///   `false`, spends from both Sapling and Orchard (pre-existing behavior).
/// - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_propose_send_max_transfer(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
    account_uuid_bytes: *const u8,
    to: *const c_char,
    memo: *const u8,
    mode: ffi::MaxSpendMode,
    confirmations_policy: ffi::ConfirmationsPolicy,
    orchard_only: bool,
) -> *mut ffi::BoxedSlice {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

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
        let locked_input_policy = LockedInputPolicy::Exclude;
        let lock_inputs = None;

        // Send-max draws the entire spendable balance across every shielded pool,
        // so Ironwood is included alongside Sapling and Orchard; omitting it would
        // silently leave a post-NU6.3 wallet's Ironwood funds behind. Including it
        // is a no-op when the account holds no Ironwood notes.
        //
        // `orchard_only` narrows that to Orchard alone: the immediate migration lane
        // sweeps what the turnstile is for, and must not drag Sapling value (or value
        // already sitting in Ironwood) along with it.
        let spend_pools: &[ShieldedPool] = if orchard_only {
            &[ShieldedPool::Orchard]
        } else {
            &[
                ShieldedPool::Sapling,
                ShieldedPool::Orchard,
                ShieldedPool::Ironwood,
            ]
        };

        let proposal = propose_send_max_transfer::<_, _, _, Infallible>(
            &mut db_data,
            &network,
            account_uuid,
            spend_pools,
            &StandardFeeRule::Zip317,
            to,
            memo,
            mode,
            confirmation_policy,
            &locked_input_policy,
            lock_inputs,
        )
        .map_err(|e| anyhow!("Error while sending funds: {}", e))?;

        let encoded = Proposal::from_standard_proposal(&proposal).encode_to_vec();

        Ok(ffi::BoxedSlice::some(encoded))
    });
    unwrap_exc_or_null(res)
}

/// Proposes migrating the account's entire Orchard balance into the Ironwood pool.
///
/// Sends the maximum from Orchard to the account's own internal Orchard receiver,
/// with the fee computed so nothing is left over. Fails unless NU6.3 is active at
/// the chain tip. See [`crate::migration_turnstile::propose_orchard_to_ironwood`].
///
/// This is the single-transaction sweep released in 2.8.0-rc.1, NOT the staged migration
/// engine (`zcashlc_migration_*`), which is what migrates a real Orchard balance.
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
/// - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_propose_orchard_to_ironwood_migration(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> *mut ffi::BoxedSlice {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;

        let proposal =
            migration_turnstile::propose_orchard_to_ironwood(&mut db_data, &network, account_uuid)?;

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
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    payment_uri: *const c_char,
    network_id: u32,
    confirmations_policy: ffi::ConfirmationsPolicy,
) -> *mut ffi::BoxedSlice {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;
        let payment_uri_str = unsafe { CStr::from_ptr(payment_uri) }.to_str()?;

        let (change_strategy, input_selector) = zip317_helper(None);

        let req = TransactionRequest::from_uri(payment_uri_str)
            .map_err(|e| anyhow!("Error creating transaction request: {:?}", e))?;

        let spend_policy = SpendPolicy::default();
        let lock_inputs = None;
        let proposed_version = None;
        let proposal = propose_transfer::<_, _, _, _, Infallible>(
            &mut db_data,
            &network,
            account_uuid,
            &input_selector,
            &change_strategy,
            req,
            wallet::ConfirmationsPolicy::try_from(confirmations_policy)?,
            &spend_policy,
            lock_inputs,
            proposed_version,
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
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    memo: *const u8,
    shielding_threshold: u64,
    transparent_receiver: *const c_char,
    network_id: u32,
    confirmations_policy: ffi::ConfirmationsPolicy,
) -> *mut ffi::BoxedSlice {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

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
                        if db_data
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

        let account_receivers = db_data
            .get_target_and_anchor_heights(NonZeroU32::MIN)
            .map_err(|e| anyhow!("Error while fetching anchor height: {}", e))
            .and_then(|opt| {
                opt.map(|(target, _)| target) // Include unconfirmed funds.
                    .ok_or_else(|| anyhow!("height not available; scan required."))
            })
            .and_then(|target_height| {
                db_data
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
                    .partition(|(_, (origin, _))| {
                        matches!(
                            origin,
                            TransparentKeyOrigin::Derived { scope } if *scope
                                == TransparentKeyScope::EPHEMERAL
                        )
                    });

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
        let lock_inputs = None;
        let proposal = propose_shielding::<_, _, _, _, Infallible>(
            &mut db_data,
            &network,
            &input_selector,
            &change_strategy,
            shielding_threshold,
            &from_addrs,
            account_uuid,
            confirmations_policy,
            CoinbaseFilter::AllTransparentOutputs,
            lock_inputs,
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
) -> *mut ffi::TxIds {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let proposal =
            Proposal::decode(unsafe { slice::from_raw_parts(proposal_ptr, proposal_len) })
                .map_err(|e| anyhow!("Invalid proposal: {}", e))?
                .try_into_standard_proposal(&network, &db_data)?;
        let usk = unsafe { decode_usk(usk_ptr, usk_len) }?;
        let spend_params = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(spend_params, spend_params_len)
        }));
        let output_params = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(output_params, output_params_len)
        }));

        let prover = LocalTxProver::new(spend_params, output_params);
        let expiry_height = None;

        let txids = create_proposed_transactions::<_, _, Infallible, _, Infallible, _>(
            &mut db_data,
            &network,
            &prover,
            &prover,
            &SpendingKeys::from_unified_spending_key(usk),
            OvkPolicy::Sender,
            &proposal,
            expiry_height,
        )
        .map_err(|e| anyhow!("Error while sending funds: {}", e))?;

        Ok(ffi::TxIds::ptr_from_vec(
            txids.into_iter().map(|txid| *txid.as_ref()).collect(),
        ))
    });
    unwrap_exc_or_null(res)
}

/// Returns transaction data directly from the wallet store.
///
/// This works for any stored transaction, including received transactions. It deliberately does
/// not depend on wallet history views, which may omit a stored transaction until all of the view's
/// derived relations are populated. If the transaction is unknown or its raw bytes are not
/// available, the returned [`ffi::TransactionData`] has a null `raw` pointer.
///
/// Parsing an unmined transaction requires a known consensus branch. Consequently, an
/// expiry-disabled unmined transaction whose branch cannot be inferred is reported through the
/// last-error channel instead of being returned as unavailable.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and must contain a
///   valid operating-system path.
/// - `txid_bytes` must be non-null and valid for reads for exactly 32 bytes.
/// - Call [`ffi::zcashlc_free_transaction_data`] to free the returned pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_get_transaction(
    db_data: *const u8,
    db_data_len: usize,
    txid_bytes: *const u8,
    network_id: u32,
) -> *mut ffi::TransactionData {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let txid_bytes = unsafe { *(txid_bytes.cast::<[u8; 32]>()) };
        let txid = TxId::from_bytes(txid_bytes);
        let Some(transaction) = db_data
            .get_transaction(txid)
            .map_err(|e| anyhow!("Failed to read transaction {txid}: {e:?}"))?
        else {
            return Ok(ffi::TransactionData::unavailable(txid_bytes));
        };

        let expiry_height = u32::from(transaction.expiry_height());
        let mut raw = Vec::new();
        transaction
            .write(&mut raw)
            .map_err(|e| anyhow!("Failed to encode transaction {txid}: {e}"))?;

        Ok(ffi::TransactionData::from_parts(
            *transaction.txid().as_ref(),
            raw,
            expiry_height,
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
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
    proposal_ptr: *const u8,
    proposal_len: usize,
    account_uuid_bytes: *const u8,
) -> *mut ffi::BoxedSlice {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let proposal =
            Proposal::decode(unsafe { slice::from_raw_parts(proposal_ptr, proposal_len) })
                .map_err(|e| anyhow!("Invalid proposal: {}", e))?
                .try_into_standard_proposal(&network, &db_data)?;

        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;

        if proposal.steps().len() == 1 {
            let target_expiry_height = None;
            let orchard_pool_padding = BundlePadding::DEFAULT;
            let pczt = create_pczt_from_proposal::<_, _, Infallible, _, Infallible, _>(
                &mut db_data,
                &network,
                account_uuid,
                OvkPolicy::Sender,
                &proposal,
                target_expiry_height,
                orchard_pool_padding,
            )
            .map_err(|e| anyhow!("Error creating PCZT from single-step proposal: {}", e))?;

            Ok(ffi::BoxedSlice::some(pczt.serialize().map_err(|e| {
                anyhow!("Failed to serialize PCZT: {:?}", e)
            })?))
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

        // Keystone's ordinary send flow signs the full (non-compacted) signer
        // view: deployed firmware predates the compact view and, for v5
        // transactions, the v2 PCZT encoding (which `Pczt::serialize` only
        // selects when the content requires it). Do not switch this to
        // `SignerView::Compact` without confirming the target signer supports
        // it — the compact view here caused missing-signature failures at
        // extraction (#1863 regression).
        let redacted_pczt = redact_pczt_for_signer(&pczt, SignerView::Full);

        Ok(ffi::BoxedSlice::some(redacted_pczt.serialize().map_err(
            |e| anyhow!("Failed to serialize redacted PCZT: {:?}", e),
        )?))
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

        // The Orchard proving key must be built for the circuit governing the Orchard pool
        // under the consensus branch this PCZT was created for; derive it from the PCZT's
        // consensus branch id before the PCZT is consumed by the prover.
        let pczt_branch_id = BranchId::try_from(*pczt.global().consensus_branch_id())
            .map_err(|_| anyhow!("PCZT has an invalid consensus branch id"))?;

        let mut prover = Prover::new(pczt);

        // Orchard and Ironwood share the Orchard-family proving system. The circuit
        // governing each pool under this PCZT's consensus branch selects the proving
        // key; derive it from the branch id per pool. `cached_orchard_proving_key`
        // returns a shared key per circuit version, so the Orchard and Ironwood
        // proofs reuse one key once NU6.3 collapses both onto the PostNu6_3 circuit.
        let circuit_version_for = |pool| {
            zcash_primitives::transaction::components::orchard::bundle_version_for_branch(
                pczt_branch_id,
                pool,
            )
            .map(|v| v.circuit_version())
        };

        if prover.requires_orchard_proof() {
            let circuit_version =
                circuit_version_for(orchard::ValuePool::Orchard).ok_or_else(|| {
                    anyhow!("PCZT's consensus branch does not support the Orchard pool")
                })?;
            prover = prover
                .create_orchard_proof(
                    zcash_primitives::transaction::builder::cached_orchard_proving_key(
                        circuit_version,
                    ),
                )
                .map_err(|e| anyhow!("Failed to create Orchard proof for PCZT: {:?}", e))?;
        }
        assert!(!prover.requires_orchard_proof());

        if prover.requires_ironwood_proof() {
            // Post-NU6.3 proposals route orchard-receiver outputs and change
            // into Ironwood bundles (the Orchard turnstile forbids adding value
            // to Orchard once NU6.3 is active), so any PCZT built after
            // activation can carry an Ironwood bundle that must be proven before
            // extraction — otherwise a hardware-signed transaction fails at
            // extract with MissingProof. The Ironwood bundle uses the PostNu6_3
            // circuit (the fixed circuit plus the `disableCrossAddress`
            // constraint), a distinct proving key from the Orchard pool's.
            let circuit_version =
                circuit_version_for(orchard::ValuePool::Ironwood).ok_or_else(|| {
                    anyhow!("PCZT's consensus branch does not support the Ironwood pool")
                })?;
            prover = prover
                .create_ironwood_proof(
                    zcash_primitives::transaction::builder::cached_orchard_proving_key(
                        circuit_version,
                    ),
                )
                .map_err(|e| anyhow!("Failed to create Ironwood proof for PCZT: {:?}", e))?;
        }
        assert!(!prover.requires_ironwood_proof());

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

        Ok(ffi::BoxedSlice::some(
            pczt_with_proofs
                .serialize()
                .map_err(|e| anyhow!("Failed to serialize proven PCZT: {:?}", e))?,
        ))
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
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
    pczt_with_proofs_ptr: *const u8,
    pczt_with_proofs_len: usize,
    pczt_with_sigs_ptr: *const u8,
    pczt_with_sigs_len: usize,
    spend_params: *const u8,
    spend_params_len: usize,
    output_params: *const u8,
    output_params_len: usize,
) -> *mut ffi::BoxedSlice {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

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
            &mut db_data,
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
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
    txid_bytes: *const u8,
    txid_bytes_len: usize,
    status: ffi::TransactionStatus,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let txid_bytes = unsafe { slice::from_raw_parts(txid_bytes, txid_bytes_len) };
        let txid = TxId::read(txid_bytes)?;

        let status = match status {
            ffi::TransactionStatus::TxidNotRecognized => TransactionStatus::TxidNotRecognized,
            ffi::TransactionStatus::NotInMainChain => TransactionStatus::NotInMainChain,
            ffi::TransactionStatus::Mined(h) => TransactionStatus::Mined(BlockHeight::from(h)),
        };

        db_data
            .set_transaction_status(txid, status)
            .map_err(|e| anyhow!("Error setting transaction status for txid {}: {}", txid, e))?;

        Ok(true)
    });

    unwrap_exc_or(res, false)
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
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
) -> *mut ffi::TransactionDataRequests {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        Ok(ffi::TransactionDataRequests::ptr_from_vec(
            db_data
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
pub unsafe extern "C" fn zcashlc_fix_witnesses(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
) {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let corrupt_ranges = db_data.check_witnesses()?;
        if let Some(nel_ranges) = NonEmpty::from_vec(corrupt_ranges) {
            db_data.queue_rescans(nel_ranges, ScanPriority::FoundNote)?;
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
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
    address: *const c_char,
    start: u32,
    end: i64,
) -> *mut ffi::AddressCheckResult {
    // SAFETY: We ensure unwind safety by:
    // - using `*mut tor::LwdConn` and respecting mutability rules on the Swift side, to
    //   avoid observing the effects of a panic in another thread.
    // - discarding the `tor::LwdConn` whenever we get an error that is due to a panic.
    let lwd_conn = AssertUnwindSafe(lwd_conn);

    let res = catch_panic(|| {
        let lwd_conn = unsafe { lwd_conn.as_mut() }
            .ok_or_else(|| anyhow!("A Tor lightwalletd connection is required"))?;

        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let addr_str = unsafe { CStr::from_ptr(address).to_str()? };
        let addr = TransparentAddress::decode(&network, addr_str)?;

        let cur_height = db_data
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
                decrypt_and_store_transaction(&network, &mut db_data, &tx, mined_height)?;

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
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
    account_uuid_bytes: *const u8,
    address: *const c_char,
) -> *mut ffi::AddressCheckResult {
    // SAFETY: We ensure unwind safety by:
    // - using `*mut tor::LwdConn` and respecting mutability rules on the Swift side, to
    //   avoid observing the effects of a panic in another thread.
    // - discarding the `tor::LwdConn` whenever we get an error that is due to a panic.
    let lwd_conn = AssertUnwindSafe(lwd_conn);

    let res = catch_panic(|| {
        let lwd_conn = unsafe { lwd_conn.as_mut() }
            .ok_or_else(|| anyhow!("A Tor lightwalletd connection is required"))?;

        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;

        let addr_str = unsafe { CStr::from_ptr(address).to_str()? };
        let addr = TransparentAddress::decode(&network, addr_str)?;

        let mut found = None;
        if let Some(meta) = db_data.get_transparent_address_metadata(account_uuid, &addr)? {
            lwd_conn.with_taddress_utxos(
                &network,
                addr,
                match meta.exposure() {
                    Exposure::Exposed { at_height, .. } => Some(at_height),
                    Exposure::Unknown | Exposure::CannotKnow => {
                        Some(db_data.get_account_birthday(account_uuid)?)
                    }
                },
                None,
                |output| {
                    found = Some(addr);
                    db_data.put_received_transparent_utxo(&output)?;
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
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
    account_uuid_bytes: *const u8,
) -> *mut ffi::AddressCheckResult {
    // SAFETY: We ensure unwind safety by:
    // - using `*mut tor::LwdConn` and respecting mutability rules on the Swift side, to
    //   avoid observing the effects of a panic in another thread.
    // - discarding the `tor::LwdConn` whenever we get an error that is due to a panic.
    let lwd_conn = AssertUnwindSafe(lwd_conn);

    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let account_uuid = account_uuid_from_bytes(account_uuid_bytes)?;

        let lwd_conn = unsafe { lwd_conn.as_mut() }
            .ok_or_else(|| anyhow!("A Tor lightwalletd connection is required"))?;

        // one day's worth of blocks.
        let max_exposure_depth = (24 * 60 * 60) / 75;
        let addrs =
            db_data.get_ephemeral_transparent_receivers(account_uuid, max_exposure_depth, true)?;

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

        let cur_height = db_data
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
                    decrypt_and_store_transaction(&network, &mut db_data, &tx, mined_height)?;

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
                db_data.schedule_next_check(&addr, offset_seconds)?;
            }
        }

        Ok(ffi::AddressCheckResult::from_rust(&network, found))
    });

    unwrap_exc_or_null(res)
}

//
// Utility functions
//

/// `network_id` value for Testnet, accepted by [`parse_network`] and every
/// `zcashlc_*` FFI that takes a `network_id` parameter.
pub(crate) const NETWORK_ID_TESTNET: u32 = 0;

/// `network_id` value for Mainnet, accepted by [`parse_network`] and every
/// `zcashlc_*` FFI that takes a `network_id` parameter.
pub(crate) const NETWORK_ID_MAINNET: u32 = 1;

/// `network_id` value for a custom-parameter network. Its base identity + per-NU activation heights must
/// be registered once via [`zcashlc_set_custom_network`] before any `zcashlc_*` call uses it.
pub(crate) const NETWORK_ID_REGTEST: u32 = 2;

/// Consensus parameters passed across the FFI: either a standard [`Network`] (Mainnet/Testnet, with
/// activation heights baked into librustzcash) or a **custom network** — a chosen base identity
/// (`base`, which determines address encoding and `chainName`) combined with per-NU activation heights
/// ([`LocalNetwork`]) configured at runtime. This is how the SDK connects to a custom-parameter node
/// (e.g. a modified-mainnet Ironwood backend: `base = Main`, NU6.3 at a custom height). Implements
/// [`Parameters`] purely by delegation, so it is a drop-in replacement for the concrete `Network`
/// everywhere the FFI threads network parameters.
#[derive(Clone, Copy)]
pub(crate) enum NetworkParams {
    Standard(Network),
    Custom {
        base: NetworkType,
        local: LocalNetwork,
    },
}

impl Parameters for NetworkParams {
    fn network_type(&self) -> NetworkType {
        match self {
            NetworkParams::Standard(network) => network.network_type(),
            // Identity (address HRPs, chainName) comes from the chosen base network, not from
            // `LocalNetwork` (whose `network_type()` is always Regtest).
            NetworkParams::Custom { base, .. } => *base,
        }
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match self {
            NetworkParams::Standard(network) => network.activation_height(nu),
            NetworkParams::Custom { local, .. } => local.activation_height(nu),
        }
    }
}

/// The custom network's base identity + per-NU activation heights, configured once via
/// [`zcashlc_set_custom_network`] and read back by [`parse_network`] for `network_id`
/// [`NETWORK_ID_REGTEST`]. `None` until set.
static CUSTOM_PARAMS: std::sync::RwLock<Option<(NetworkType, LocalNetwork)>> =
    std::sync::RwLock::new(None);

/// Maps an FFI `network_id` to its [`NetworkType`], used to select the base identity of a custom network.
fn network_type_for_id(network_id: u32) -> Option<NetworkType> {
    match network_id {
        NETWORK_ID_TESTNET => Some(NetworkType::Test),
        NETWORK_ID_MAINNET => Some(NetworkType::Main),
        NETWORK_ID_REGTEST => Some(NetworkType::Regtest),
        _ => None,
    }
}

/// Registers the **custom network** resolved for `network_id` [`NETWORK_ID_REGTEST`], which every
/// subsequent `zcashlc_*` call resolves through [`parse_network`]. `base_network_id` selects the base
/// identity — address encoding and `chainName` — as mainnet (1), testnet (0), or regtest (2); the
/// activation heights are custom regardless. Each height argument is a block height, or a negative value
/// meaning "not activated on this network"; set them to mirror the `nuparams` of the node /
/// `lightwalletd` being connected to. Idempotent; intended to be called once at init.
///
/// Returns `true` on a fresh registration or an identical re-registration. Returns `false` on an
/// invalid `base_network_id`, a poisoned lock, or when the call **replaced a different existing
/// configuration** — the replacement is still applied (last writer wins, since per-instance state
/// such as checkpoint sources follows the newest `Initializer`), but the caller should treat a
/// conflicting re-registration as a host configuration bug: the parameters are process-global, so
/// two live instances with different custom networks cannot both be honored.
#[unsafe(no_mangle)]
pub extern "C" fn zcashlc_set_custom_network(
    base_network_id: u32,
    overwinter: i64,
    sapling: i64,
    blossom: i64,
    heartwood: i64,
    canopy: i64,
    nu5: i64,
    nu6: i64,
    nu6_1: i64,
    nu6_2: i64,
    nu6_3: i64,
) -> bool {
    fn height(value: i64) -> Option<BlockHeight> {
        u32::try_from(value).ok().map(BlockHeight::from_u32)
    }

    let Some(base) = network_type_for_id(base_network_id) else {
        return false;
    };

    let local = LocalNetwork {
        overwinter: height(overwinter),
        sapling: height(sapling),
        blossom: height(blossom),
        heartwood: height(heartwood),
        canopy: height(canopy),
        nu5: height(nu5),
        nu6: height(nu6),
        nu6_1: height(nu6_1),
        nu6_2: height(nu6_2),
        nu6_3: height(nu6_3),
    };

    match CUSTOM_PARAMS.write() {
        Ok(mut guard) => {
            let replaced_different = matches!(*guard, Some(existing) if existing != (base, local));
            *guard = Some((base, local));
            !replaced_different
        }
        Err(_) => false,
    }
}

pub(crate) fn parse_network(value: u32) -> anyhow::Result<NetworkParams> {
    match value {
        NETWORK_ID_TESTNET => Ok(NetworkParams::Standard(TestNetwork)),
        NETWORK_ID_MAINNET => Ok(NetworkParams::Standard(MainNetwork)),
        NETWORK_ID_REGTEST => {
            let guard = CUSTOM_PARAMS
                .read()
                .map_err(|_| anyhow!("custom network params lock is poisoned"))?;
            // `Option<(NetworkType, LocalNetwork)>` is `Copy`, so deref-copy out of the read guard.
            let (base, local) = (*guard).ok_or_else(|| {
                anyhow!(
                    "custom network (id {}) used before it was configured; call \
                     zcashlc_set_custom_network first",
                    NETWORK_ID_REGTEST,
                )
            })?;
            Ok(NetworkParams::Custom { base, local })
        }
        _ => Err(anyhow!(
            "Invalid network type: {}. Expected {}, {}, or {} for Testnet, Mainnet, or a custom network, respectively.",
            value,
            NETWORK_ID_TESTNET,
            NETWORK_ID_MAINNET,
            NETWORK_ID_REGTEST,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the production network gets the ZIP 318 grid, whose anonymity set depends on every
    /// wallet sharing it. Testnet gets the shortened grid, so a migration passes through anchor
    /// boundaries fast enough to be exercised.
    #[test]
    fn only_mainnet_retains_anchors_on_the_zip_318_grid() {
        assert_eq!(
            anchor_retention_interval(NetworkParams::Standard(MainNetwork)),
            AnchorRetentionInterval::ZIP_318,
        );
        assert_eq!(
            anchor_retention_interval(NetworkParams::Standard(TestNetwork)),
            TEST_ANCHOR_RETENTION_INTERVAL,
        );
        assert_eq!(TEST_ANCHOR_RETENTION_INTERVAL.block_count().get(), 12);
    }

    /// A custom-parameter network is a test deployment even when it borrows mainnet's address
    /// encoding, so it must not inherit the production grid along with that identity.
    #[test]
    fn a_mainnet_based_custom_network_is_not_the_production_network() {
        let height = Some(BlockHeight::from_u32(1));
        let custom = NetworkParams::Custom {
            base: NetworkType::Main,
            local: LocalNetwork {
                overwinter: height,
                sapling: height,
                blossom: height,
                heartwood: height,
                canopy: height,
                nu5: height,
                nu6: height,
                nu6_1: height,
                nu6_2: height,
                nu6_3: height,
            },
        };
        assert_eq!(
            anchor_retention_interval(custom),
            TEST_ANCHOR_RETENTION_INTERVAL,
        );
    }
}

// ── Slipstream FFI surface ────────────────────────────────────────────────────
//
// These functions are ADDITIVE — they do not modify any existing item above.
// Pattern mirrors `zcashlc_create_tor_runtime` / `zcashlc_free_tor_runtime`
// (lib.rs:3157-3195): Box::into_raw / Box::from_raw, catch_panic, unwrap_exc_or_null.
// D7 deviation: the tokio runtime is created at `open` and lives for the full
// handle lifetime (dropped at `free`), not created per-start. This mirrors the
// TorRuntime precedent where the runtime is owned by the handle.
//
// cbindgen note (C4/C12): cbindgen only parses the root crate. `FfiSlipstreamSnapshot`
// and `FfiSlipstreamEvent` are therefore defined directly here so they appear in the
// generated `zcashlc.h`.
//
// `SlipstreamHandle` MUST also be defined here (not imported from the dep crate) so
// cbindgen emits `typedef struct SlipstreamHandle SlipstreamHandle;` in the header.
// Without it the ObjC module fails to compile with "unknown type name 'SlipstreamHandle'".
// This is the TorRuntime pattern: `TorRuntime` is defined in rust/src/tor.rs (crate-local)
// so cbindgen can see and emit its opaque typedef. We wrap the core handle in a thin
// crate-local newtype here — the wrapper owns the core handle via `inner`.

use slipstream_core::ffi_handle::SyncState;

/// Opaque handle to a Slipstream engine instance.
///
/// Wraps [`slipstream_core::ffi_handle::SlipstreamHandle`] as a crate-local newtype so
/// that cbindgen (which only parses the root crate) emits the required opaque typedef
/// `typedef struct SlipstreamHandle SlipstreamHandle;` in the generated `zcashlc.h`.
///
/// All state is stored in `inner`; the six `zcashlc_slipstream_*` functions delegate
/// directly to it.
pub struct SlipstreamHandle {
    inner: slipstream_core::ffi_handle::SlipstreamHandle,
    /// [API v2.1 E-1] Upstream-summary cache: the expensive `get_wallet_summary` walk is
    /// rationed HERE (engine-side), so hosts may call the unified summary whenever they
    /// like. Arc'd because the background refresh thread outlives the FFI call.
    summary_cache: std::sync::Arc<std::sync::Mutex<Option<SummaryCacheEntry>>>,
    /// [API v2.1 E-1] One background refresh in flight at a time.
    summary_refresh_inflight: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// [#1806] Last successfully-read recovery-balance nets (account-uuid bytes → reconciled
    /// net zatoshi), used ONLY as a fallback when the bounded (250 ms) read of
    /// `ext_slipstream_v_recovery_balance` is contended — so a momentarily-locked view never
    /// nulls the whole summary. `None` until the first successful read; see
    /// [`zcashlc_slipstream_wallet_summary`].
    recovery_nets_cache: std::sync::Mutex<Option<std::collections::HashMap<[u8; 16], i64>>>,
    /// [API v2.1 E-2] Tip-freshness for the [#1591] stale-tip spendable mask — the engine
    /// owns the FACT (it is the thing refreshing the tip); hosts apply the mask transform.
    /// `shouldMarkChainTipUpdated` semantics at the source: fresh once THIS run has
    /// persisted a freshly-fetched server tip (`Progress::tip_refreshes` advanced past the
    /// baseline captured at `start()` — the engine bumps it only after `update_chain_tip`
    /// succeeds), or when a pass reaches Done. Counter-based (not tip-value-based) so the
    /// E-3 DB-seeded tip can neither fake freshness nor suppress a genuine refresh that
    /// happens to fetch the same height.
    tip_refreshes_at_run_start: std::sync::atomic::AtomicU64,
    tip_fresh: std::sync::atomic::AtomicBool,
    /// [API v2.1 E-2] `stop()` timestamp: freshness survives a stop→start hop shorter than
    /// 120 s (the SDK's `SDKFlags.sdkStarted` quick-background parity).
    last_stop_at: std::sync::Mutex<Option<std::time::Instant>>,
    /// [v0.7 P1b] Alternate lightwalletd servers for probe-then-commit + wire
    /// failover. Set via [`zcashlc_slipstream_set_alternate_servers`]; each
    /// `start()` merges them into the pass config, deduped against the
    /// handle's primary (hosts pass their FULL server list — the selected
    /// server is usually in it). Empty = pre-v0.7 single-server behavior.
    alternate_servers: std::sync::Mutex<Vec<slipstream_core::config::Endpoint>>,
    /// [#1806] Post-restore balance-hold state (latch + last-observed recovery flag + last real
    /// heights). See [`PostFlipHold`] and [`zcashlc_slipstream_wallet_summary`].
    post_flip_hold: std::sync::Mutex<PostFlipHold>,
}

/// [API v2.1 E-1] One cached upstream wallet summary + the engine facts it was captured
/// under. Refresh triggers: the pass crossed a range boundary (`ranges_completed` moved),
/// the engine state changed (e.g. Syncing → Done), or — outside a scan — the idle TTL
/// elapsed. While Syncing between boundaries the cache is served as-is: this is the T5.5
/// no-walk-while-scanning invariant, now engine-owned.
struct SummaryCacheEntry {
    captured_at: std::time::Instant,
    ranges_completed: u64,
    state: u8,
    /// [#1806] `None` = a walked "no balance data yet" result, cached like any other so a
    /// fresh / just-imported wallet does not re-walk synchronously on every poll tick.
    summary: Option<zcash_client_backend::data_api::WalletSummary<AccountUuid>>,
    /// [#1806] The `is_recovering` flag captured when THIS entry's walk STARTED. A `Some`
    /// walked while recovering predates the `is_recovering 1→0` flip, so it is a STALE pre-flip
    /// summary (see [`classify_upstream`] / C1): the post-restore hold must not release on it or
    /// serve it raw. `false` for a walk that ran outside recovery (post-flip → fresh).
    walked_while_recovering: bool,
}

/// [API v2.1 E-1] Idle refresh TTL — matches the SDK's historical idle/error refetch cadence.
const SUMMARY_IDLE_TTL: std::time::Duration = std::time::Duration::from_secs(2);
/// [API v2.1 E-2] Freshness survives stop→start hops shorter than this (SDKFlags parity).
const TIP_FRESH_STOP_WINDOW: std::time::Duration = std::time::Duration::from_secs(120);

/// C-compatible snapshot of Slipstream engine progress. Returned by
/// [`zcashlc_slipstream_snapshot`] (by value — no heap allocation).
///
/// Sync state codes: 0 = idle, 1 = syncing, 2 = error, 3 = done.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct FfiSlipstreamSnapshot {
    /// Current chain tip height as reported by the server (0 = not yet fetched).
    pub chain_tip: u64,
    /// Number of compact blocks fetched in the current/last sync pass.
    pub fetched_blocks: u64,
    /// Number of compact blocks scanned in the current/last sync pass.
    pub scanned_blocks: u64,
    /// Number of transactions enhanced in the current/last sync pass.
    pub enhanced_txs: u64,
    /// End height of the block range currently being processed.
    pub current_range_end: u64,
    /// Sync state: 0 = idle, 1 = syncing, 2 = error, 3 = done.
    pub state: u8,
    // ── T5.5 counter-based progress fields (appended at END for padding stability) ──
    /// Total blocks in the current pass. Set (not accumulated) by the scheduler each time
    /// suggest_scan_ranges returns: value = scanned_so_far + sum(all returned ranges).
    /// Denominator for counter-based progress: scanned_blocks / pass_total_blocks.
    pub pass_total_blocks: u64,
    /// Spendable hint: 0 = not yet spendable; 1 = a ChainTip-priority range has completed
    /// scanning (≈ SBS funds-spendable semantics). Latches to 1; never resets within a pass.
    pub spendable_hint: u8,
    // ── T5.6 range-boundary signals (appended at END for padding stability) ──
    /// Number of suggested ranges whose scan+enhancement has completed in the current pass.
    /// Swift observes this counter and triggers ONE balance-summary fetch per boundary.
    pub ranges_completed: u64,
    // ── API v2 fields (appended at END for padding stability) ──
    /// 1 while the wallet is inside its recovery (restore backfill) window; engine-computed
    /// with the fail-safe latch built in (terminal Done/Error force 0).
    pub is_recovering: u8,
    /// Blessed progress, 0..=1000, session-monotonic (never regresses while the handle
    /// lives; Done forces 1000). Replaces host-side progress math.
    pub progress_permille: u16,
    /// Seconds since last forward progress while syncing; 0 otherwise.
    pub stalled_seconds: u32,
    // ── API v2.1 fields (appended at END for padding stability) ──
    /// [E-2] 1 once the CURRENT run has refreshed the wallet-DB chain tip (the [#1591]
    /// stale-tip fact, engine-owned): the engine's tip-refresh counter advanced past its
    /// `start()` baseline (bumped only after `update_chain_tip` succeeds), or a pass
    /// reached Done. Survives stop→start hops shorter than 120 s. While 0, hosts must
    /// mask spendable balances (the mask transform stays host-side because the C
    /// `AccountBalance` cannot express the awaiting-resolution shift).
    pub tip_fresh: u8,
    /// [E-4] Monotonic version of the wallet's stored transaction set: bumps exactly when
    /// enhancement stores/updates a tx, the mempool monitor stores a 0-conf hit, a range
    /// boundary detects a reconcile-linkage transition, or the host pokes
    /// [`zcashlc_slipstream_notify_tx_change`] after a submit. Host rule (one line):
    /// version moved since the last poll → re-fetch transactions + publish
    /// `foundTransactions`. Never reset while the handle lives.
    pub tx_set_version: u64,
}

/// [API v2.1 E-6] C-compatible wallet-provisioning anchor. Returned by
/// [`zcashlc_slipstream_restore_anchor`]; free with
/// [`zcashlc_slipstream_free_restore_anchor`].
///
/// RESTORE intent: `height` = the recover_until height (always valid by policy — live tip
/// or the offline `max(checkpoint, birthday+1)` fallback); `treestate` null.
/// NEW intent: `height` + serialized `TreeState` protobuf bytes = the reorg-safe recent
/// tree state; `height` 0 + null `treestate` when offline (host keeps its checkpoint).
#[repr(C)]
pub struct FfiRestoreAnchor {
    /// See the type docs — recover_until (restore) or the anchor height (new).
    pub height: u64,
    /// Serialized `TreeState` protobuf bytes, or null (see the type docs).
    pub treestate: *mut u8,
    /// Length of `treestate` (0 when null).
    pub treestate_len: usize,
}

/// C-compatible Slipstream engine event record. Returned by
/// [`zcashlc_slipstream_drain_events`] in a caller-allocated buffer.
///
/// Event tags: 1 = SyncStarted, 2 = SyncProgress, 3 = SyncDone,
/// 4 = SyncError, 5 = FoundTransactions.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FfiSlipstreamEvent {
    /// Event tag (see type documentation for values).
    pub tag: u8,
    /// For SyncDone: transactions stored. For SyncError: error code. Others: 0.
    pub value: u64,
}

/// Installs (once per process) a chaining panic hook that reports every Rust panic
/// through `tracing::error!` before delegating to the previously-installed hook.
///
/// `zcashlc_init_on_load` installs `log_panics`,
/// which reports panics via the `log` facade — that reaches os_log only through the
/// `tracing-log` bridge AND only when the app initialized logging at a level that
/// admits it. This hook reports directly through `tracing` so device logs always
/// carry the panic message and backtrace location, no matter how the `log` facade
/// is configured. Chaining preserves `log_panics` (and any test-harness hook).
static SLIPSTREAM_PANIC_HOOK: std::sync::Once = std::sync::Once::new();

fn install_slipstream_panic_hook() {
    SLIPSTREAM_PANIC_HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            tracing::error!(panic = %info, "rust panic");
            previous(info);
        }));
    });
}

/// Opens a Slipstream engine handle.
///
/// - `db_data`/`db_data_len`: path to the wallet data.db (UTF-8 bytes, no NUL terminator).
/// - `server_host`/`server_host_len`: lightwalletd hostname (UTF-8 bytes).
/// - `server_port`: lightwalletd port.
/// - `use_tls`: `true` for TLS (mainnet), `false` for plaintext.
/// - `network_id`: `1` for mainnet, `0` for testnet.
/// - `total_memory_bytes`: host physical memory in bytes (Swift passes
///   `ProcessInfo.processInfo.physicalMemory`); `0` = unknown. Drives device-memory
///   budget derating at start for <3 GiB devices (T8.4); `0`/big devices keep defaults.
///
/// Returns an opaque handle pointer, or null on failure.
/// Free with [`zcashlc_slipstream_free`] when done.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, with
///   alignment of `1`. Its contents must be a valid system path in the OS's preferred
///   representation.
/// - `server_host` must be non-null and valid for reads for `server_host_len` bytes,
///   with alignment of `1`. Its contents must be valid UTF-8.
/// - Neither pointer's memory must be mutated for the duration of the call.
/// - `db_data_len` and `server_host_len` must each be no larger than `isize::MAX`.
/// - Call [`zcashlc_slipstream_free`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_open(
    db_data: *const u8,
    db_data_len: usize,
    server_host: *const u8,
    server_host_len: usize,
    server_port: u16,
    use_tls: bool,
    network_id: u32,
    total_memory_bytes: u64,
) -> *mut SlipstreamHandle {
    let res = catch_panic(|| {
        // B1 : make sure every panic is visible in device logs (os_log via
        // the tracing layers) — see install_slipstream_panic_hook.
        install_slipstream_panic_hook();

        let db_path = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(db_data, db_data_len)
        }));
        let host =
            std::str::from_utf8(unsafe { slice::from_raw_parts(server_host, server_host_len) })
                .map_err(|e| anyhow!("server_host UTF-8: {e}"))?;
        let network = if network_id == 1 {
            MainNetwork
        } else {
            TestNetwork
        };

        // [B6, second half] Persist the anchor-retention marks the engine's in-memory trees
        // draw but its flush never writes: the open-time deep-history heal spares only ids
        // present in the SQLITE store's retained set, so reconcile the marks BEFORE any
        // engine session (and with it the heal) exists — including the E-3 snapshot seed's
        // own `WalletSession::open` a few lines below, which already runs that heal on
        // every open. Non-fatal by design — a wallet that cannot be marked must still open
        // and sync.
        let network_params = NetworkParams::Standard(network);
        match unsafe { wallet_db(db_data, db_data_len, network_params) }.and_then(|mut wallet| {
            retained_marks::reconcile_retained_anchor_marks(&mut wallet, &network_params)
        }) {
            Ok(0) => {}
            Ok(n) => {
                tracing::info!(
                    marks = n,
                    "retained anchor marks reconciled into the wallet store"
                )
            }
            Err(e) => {
                tracing::warn!(%e, "retained anchor-mark reconcile failed (non-fatal) — continuing")
            }
        }

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .map_err(|e| anyhow!("tokio runtime: {e}"))?;

        let inner = slipstream_core::ffi_handle::SlipstreamHandle {
            runtime,
            progress: std::sync::Arc::new(slipstream_core::events::Progress::default()),
            state: std::sync::Arc::new(std::sync::Mutex::new(SyncState::Idle)),
            events: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            task: None,
            pass_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            endpoint: slipstream_core::config::Endpoint {
                host: host.to_string(),
                port: server_port,
                tls: use_tls,
            },
            wallet_db_path: db_path.to_path_buf(),
            network,
            total_memory_bytes,
        };

        // [API v2.1 E-3] Truthful-from-open snapshot: seed the progress atomics from the
        // persisted wallet DB (the same inputs the first suggest round would use), so a
        // pre-pass snapshot never lies — `is_recovering` is correct on a mid-restore
        // relaunch, the permille floor holds a 99%-synced wallet's real position, and
        // `chain_tip` reports the last persisted tip. Hosts must NOT compensate.
        // Failures degrade to the zero snapshot (truthful for a fresh wallet) — the seed
        // is presentation state and must never fail `open()`. NOTE: the Swift host always
        // runs `Initializer.initialize` (DB create + migrations) before `open()`, so this
        // does not race wallet creation.
        match slipstream_core::wallet_session::WalletSession::open(network, db_path) {
            Ok(session) => {
                if let Err(e) =
                    slipstream_core::scheduler::seed_progress_from_wallet(&inner.progress, &session)
                {
                    tracing::warn!(error = %e, "E-3 open-time snapshot seed failed — snapshot starts cold");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "E-3 seed skipped (wallet not openable) — snapshot starts cold");
            }
        }
        tracing::info!(total_memory_bytes, "slipstream handle opened");

        Ok(Box::into_raw(Box::new(SlipstreamHandle {
            inner,
            summary_cache: std::sync::Arc::new(std::sync::Mutex::new(None)),
            summary_refresh_inflight: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                false,
            )),
            // [#1806] Empty until the first successful recovery-balance read fills it.
            recovery_nets_cache: std::sync::Mutex::new(None),
            // Freshness baseline = the refresh COUNTER (0 on a fresh handle; the E-3 seed
            // above never bumps it) — a DB-seeded tip is persisted state, not freshness.
            tip_refreshes_at_run_start: std::sync::atomic::AtomicU64::new(0),
            tip_fresh: std::sync::atomic::AtomicBool::new(false),
            last_stop_at: std::sync::Mutex::new(None),
            alternate_servers: std::sync::Mutex::new(Vec::new()),
            post_flip_hold: std::sync::Mutex::new(PostFlipHold::default()),
        })))
    });
    unwrap_exc_or_null(res)
}

/// [v0.7 P1b] Sets the alternate lightwalletd servers for wire resilience.
///
/// - `handle`: non-null pointer returned by [`zcashlc_slipstream_open`].
/// - `uris`/`uris_len`: newline-separated `http(s)://host:port` list (UTF-8
///   bytes, no NUL terminator). Blank lines are ignored. Pass null/0 to clear.
///
/// The list is stored on the handle and merged into the engine config by every
/// subsequent [`zcashlc_slipstream_start`] (deduped against the primary — hosts
/// pass their FULL server list, selected server included). With a non-empty
/// list a pass opens with the ~1 s parallel probe (commit to the healthiest
/// server) and arms mid-pass wire-collapse failover. Tor passes ignore the list
/// inside the engine: probe and failover dial direct, which would bypass the
/// circuit. All-or-nothing: on any parse failure the stored list is unchanged
/// and `false` is returned (check [`zcashlc_get_last_error_message`]).
///
/// # Safety
///
/// - `handle` must be a non-null pointer returned by [`zcashlc_slipstream_open`] that
///   has not previously been freed.
/// - `handle` must not be passed to two FFI calls at the same time.
/// - If `uris` is non-null, it must be valid for reads for `uris_len` bytes (UTF-8,
///   alignment `1`), and its memory must not be mutated for the duration of the call.
/// - `uris_len` must be no larger than `isize::MAX`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_set_alternate_servers(
    handle: *mut SlipstreamHandle,
    uris: *const u8,
    uris_len: usize,
) -> bool {
    let handle = AssertUnwindSafe(handle);
    let res = catch_panic(|| {
        let handle = unsafe { handle.as_mut() }.ok_or_else(|| anyhow!("null handle"))?;
        let parsed: Vec<slipstream_core::config::Endpoint> = if uris.is_null() || uris_len == 0 {
            Vec::new()
        } else {
            std::str::from_utf8(unsafe { slice::from_raw_parts(uris, uris_len) })
                .map_err(|e| anyhow!("alternate servers UTF-8: {e}"))?
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(|l| {
                    slipstream_core::config::Endpoint::parse_uri(l).map_err(|e| anyhow!("{e}"))
                })
                .collect::<Result<_, _>>()?
        };
        tracing::info!(count = parsed.len(), "v0.7 P1b alternate servers set");
        *handle
            .alternate_servers
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = parsed;
        Ok(true)
    });
    unwrap_exc_or(res, false)
}

/// [B6] The anchor-retention floor for the slipstream engine: the NU6.3 activation
/// height, exactly the floor upstream's own `WalletDb::put_blocks` caller passes
/// (`zcash_client_sqlite`), so checkpoints on the 144-block anchor grid from
/// activation onward survive the engine's checkpoint downgrade/dooming/pruning.
/// The pool-migration engine pre-signs every transfer against a drawn boundary
/// anchor on that grid and proves it hours later — without this floor the
/// engine's persist path retains nothing (`EngineConfig.anchor_retention_height`
/// defaults to `None`) and the boundary checkpoint is pruned ~100 blocks behind
/// the tip, leaving `prove_transfer` in a permanent transient `AnchorNotFound`
/// retry and the scheduled migration stalled until expiry.
///
/// `None` (a network without NU6.3, e.g. a custom regtest without the upgrade)
/// keeps retention off — there are no boundary anchors to retain for. Generic
/// over [`Parameters`] (the slipstream handle stores the plain [`Network`]).
fn slipstream_anchor_retention_floor<P: Parameters>(network: &P) -> Option<u32> {
    network
        .activation_height(NetworkUpgrade::Nu6_3)
        .map(u32::from)
}

/// Starts a Slipstream sync pass.
///
/// - `handle`: non-null pointer returned by [`zcashlc_slipstream_open`].
/// - `ufvk`/`ufvk_len`: UFVK string (UTF-8 bytes), or null/0 for a keyless update
///   (birthday is ignored when ufvk is null — account must already be imported).
/// - `birthday_height`: wallet birthday height (ignored when ufvk is null).
/// - `tor_dir`/`tor_dir_len`: dedicated Tor state directory (UTF-8 bytes) for the engine's
///   isolated circuits. Pass null/0 to sync directly (Tor off). When non-empty, the engine
///   bootstraps an arti client from it — a subdir SEPARATE from the old SDK's `TorClient`
///   directory (arti holds a state lock). Metadata calls then use isolated Tor circuits;
///   bulk block fetch stays direct (mirrors the old SDK's per-call Tor policy).
///
/// Can be called after [`zcashlc_slipstream_stop`] to restart. Cancels any in-flight
/// sync before spawning the new one.
/// Returns `true` on success, `false` on error
/// (check [`zcashlc_get_last_error_message`] for the error text).
///
/// # Safety
///
/// - `handle` must be a non-null pointer returned by [`zcashlc_slipstream_open`] that
///   has not previously been freed.
/// - `handle` must not be passed to two FFI calls at the same time.
/// - If `ufvk` is non-null, it must be valid for reads for `ufvk_len` bytes (UTF-8,
///   alignment `1`), and its memory must not be mutated for the duration of the call.
/// - If `tor_dir` is non-null, it must be valid for reads for `tor_dir_len` bytes (UTF-8,
///   alignment `1`), and its memory must not be mutated for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_start(
    handle: *mut SlipstreamHandle,
    ufvk: *const u8,
    ufvk_len: usize,
    birthday_height: u64,
    tor_dir: *const u8,
    tor_dir_len: usize,
) -> bool {
    // SAFETY: callers must respect mutability rules on the Swift side so that observing
    // a panic from another thread does not leave the handle in an inconsistent state.
    let handle = AssertUnwindSafe(handle);
    let res = catch_panic(|| {
        let handle = unsafe { handle.as_mut() }.ok_or_else(|| anyhow!("null handle"))?;

        // [API v2.1 E-2] Tip-freshness bookkeeping (shouldMarkChainTipUpdated parity):
        // capture the refresh-counter baseline BEFORE the pass starts — a later advance
        // proves THIS run persisted a freshly-fetched tip (even when the fetched height
        // equals the E-3 DB-seeded one). Freshness survives a stop→start hop < 120 s
        // (quick background hop); a longer gap re-masks until the new pass proves the tip.
        let refreshes_now = handle.inner.progress.tip_refreshes();
        handle
            .tip_refreshes_at_run_start
            .store(refreshes_now, std::sync::atomic::Ordering::Relaxed);
        let stale_stop = handle
            .last_stop_at
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .map(|t| t.elapsed() >= TIP_FRESH_STOP_WINDOW)
            .unwrap_or(false);
        if stale_stop {
            handle
                .tip_fresh
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }

        let h = &mut handle.inner;

        // Cancel any in-flight task before spawning a new one.
        if let Some(task) = h.task.take() {
            task.abort();
            join_aborted_slipstream_task(&task);
        }
        // [B4-16 drain] The aborted pass's write-behind commit may still be running
        // (`spawn_blocking` — uncancellable); wait it out BEFORE spawning the new
        // session, so the new pass's first writes never collide with an orphan
        // ("database is locked" at pass start) and no orphan Scanned-mark can land
        // after this point. Kills the B4-12 orphan-overlap class at the root.
        drain_slipstream_wallet_writers(&h.progress);
        *h.state.lock().unwrap_or_else(|p| p.into_inner()) = SyncState::Syncing;

        let ufvk_str: Option<String> = if ufvk.is_null() || ufvk_len == 0 {
            None
        } else {
            Some(
                std::str::from_utf8(unsafe { slice::from_raw_parts(ufvk, ufvk_len) })
                    .map_err(|e| anyhow!("ufvk UTF-8: {e}"))?
                    .to_string(),
            )
        };

        // ── T-Tor.3: engine-owned Tor (mirrors the old SDK's per-call Tor setup) ──
        // Swift passes a non-empty `tor_dir` — a DEDICATED slipstream Tor state subdir,
        // separate from the old SDK's TorRuntime dir to avoid an arti state-lock clash —
        // ONLY when Tor is enabled at start() time; empty/null = Tor off (direct).
        let tor_dir_opt: Option<std::path::PathBuf> = if tor_dir.is_null() || tor_dir_len == 0 {
            None
        } else {
            Some(
                Path::new(OsStr::from_bytes(unsafe {
                    slice::from_raw_parts(tor_dir, tor_dir_len)
                }))
                .to_path_buf(),
            )
        };

        #[allow(unused_mut)] // `mut` is only used under the `gpu` feature below.
        let mut cfg = slipstream_core::config::EngineConfig::new(
            h.network,
            h.wallet_db_path.clone(),
            h.endpoint.clone(),
        )
        // T8.4: derate fetch/split budgets on <3 GiB devices from the open-time
        // physical-memory hint (0 = unknown → defaults). Explicit field overrides win.
        .scaled_for_device_memory(h.total_memory_bytes);

        // [B6] Anchor-retention policy — see `slipstream_anchor_retention_floor`:
        // without it the engine retains no anchor checkpoints and every scheduled
        // migration transfer's drawn boundary is pruned before proving time.
        //
        // The grid is the one this crate configures on the wallet itself (see
        // `anchor_retention_interval`), NOT a value chosen here. The engine runs its
        // own tree-update path rather than calling `ll::wallet::put_blocks`, so it
        // does not see the wallet's setting: passing the same interval is what keeps
        // the two from retaining different grids, which on a test network would
        // otherwise leave every transfer anchored to a boundary the engine drops.
        cfg.anchor_retention = slipstream_anchor_retention_floor(&h.network).map(|floor| {
            slipstream_core::AnchorRetention::new(
                BlockHeight::from(floor),
                anchor_retention_interval(NetworkParams::Standard(h.network)),
            )
        });

        // v0.3 : GPU Orchard subtree offload. Compiled only with `--features gpu`;
        // opt in at runtime via the ZCASH_GPU_SUBTREE env var (the dev A/B for the device
        // matrix — set it in the Xcode scheme for v0.3, unset for v0.2). The capability
        // auto-gate (calibration probe) supersedes this once tuned. No-op without the
        // feature (build_orchard_subtrees falls back to CPU regardless).
        #[cfg(feature = "gpu")]
        {
            cfg.gpu_subtree = std::env::var("ZCASH_GPU_SUBTREE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            tracing::info!(
                gpu_subtree = cfg.gpu_subtree,
                "v0.3 GPU offload config (feature=gpu)"
            );
        }

        // v0.4 : Plan A graft + Plan B batch — DEFAULT ON since 2026-07-05
        // (P3 gates passed 100%). The env toggles are now KILL SWITCHES
        // (`=0` disables) and the dev A/B lever. Mirrors ZCASH_GPU_SUBTREE.
        cfg.graft_subtree = std::env::var("ZCASH_GRAFT_SUBTREE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(cfg.graft_subtree);
        cfg.batch_combine = std::env::var("ZCASH_BATCH_COMBINE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(cfg.batch_combine);
        // [#1806] ZCASH_BATCH_DECRYPT / ZCASH_ENDO_MUL removed: the zodl-inc/slipstream
        // repoint dropped `EngineConfig::batch_decrypt`/`endo_mul` — upstream adopted
        // batched-trial-decryption GLV unconditionally and retired the vendored orchard
        // fork these knobs configured. No replacement field exists; the env vars are now
        // inert (left unhandled intentionally rather than silently repurposed).
        // v0.5 scan-pacer lever : local chunk-boundary treestates
        // (one seed fetch per range instead of one RPC per boundary).
        // Default OFF until the A/B + audit gates.
        cfg.local_treestate = std::env::var("ZCASH_LOCAL_TREESTATE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(cfg.local_treestate);
        tracing::info!(
            graft_subtree = cfg.graft_subtree,
            batch_combine = cfg.batch_combine,
            local_treestate = cfg.local_treestate,
            "v0.4/v0.5 lever config"
        );

        // v0.7 P1b : alternate servers → probe-then-commit + wire failover.
        // Deduped against the CURRENT primary (hosts pass their full server list;
        // the selected server is usually in it — after a switchTo the filter
        // re-derives against the new primary automatically). Tor passes ignore
        // these inside the engine: probe/failover dial direct, which would
        // bypass the circuit.
        {
            let alternates = handle
                .alternate_servers
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            cfg.alternate_endpoints = alternates
                .into_iter()
                .filter(|e| *e != cfg.endpoint)
                .collect();
            tracing::info!(
                alternates = cfg.alternate_endpoints.len(),
                wire_failover = cfg.wire_failover,
                "v0.7 wire config"
            );
        }

        // ── Build the session config + reporting sink, then spawn the engine session ──────
        // The orchestration (resilient Tor bootstrap + initial pass + tip-following + mempool)
        // now lives in slipstream_core::session::run_session. This FFI only marshals C args,
        // builds the config + the reporting sink (the handle's existing progress/state/event
        // Arcs), and spawns the engine's session on the handle runtime.
        // [#1806] `SessionConfig.account` was retyped to `accounts: Vec<(UnifiedFullViewingKey,
        // BlockHeight)>` (typed multi-account sync_once) by the zodl-inc/slipstream repoint.
        // This FFI still exposes single-account semantics: parse the raw ufvk/birthday into
        // the typed pair and wrap it in a one-element Vec (empty = keyless follow-up call,
        // ufvk was null) — no multi-account surface added upward.
        let accounts: Vec<(UnifiedFullViewingKey, BlockHeight)> = match ufvk_str {
            Some(ufvk_str) => {
                let ufvk = UnifiedFullViewingKey::decode(&h.network, &ufvk_str).map_err(|e| {
                    anyhow!(
                        "Value \"{}\" did not decode as a valid UFVK: {}",
                        ufvk_str,
                        e
                    )
                })?;
                let birthday = BlockHeight::try_from(birthday_height)
                    .map_err(|e| anyhow!("invalid birthday_height {}: {}", birthday_height, e))?;
                vec![(ufvk, birthday)]
            }
            None => Vec::new(),
        };
        // iOS sandboxes the app dir so fs-mistrust can trust it (mirrors the old SDK's
        // zcashlc_create_tor_runtime); elsewhere let Tor manage permissions. The engine stays
        // host-agnostic — a future Android FFI sets this field too.
        let tor = tor_dir_opt.map(|dir| slipstream_core::session::TorSessionConfig {
            dir,
            dangerously_trust_everyone: cfg!(target_os = "ios"),
        });
        let session_config = slipstream_core::session::SessionConfig {
            engine: cfg,
            accounts,
            tor,
        };
        let reporter = slipstream_core::session::SessionReporter {
            progress: std::sync::Arc::clone(&h.progress),
            state: std::sync::Arc::clone(&h.state),
            events: std::sync::Arc::clone(&h.events),
        };

        // B1 : spawn SUPERVISED — a panic in the session body becomes SyncState::Error(2)
        // + a tag=4/value=2 event instead of a silent death stuck at "Syncing" forever.
        let sup_state = std::sync::Arc::clone(&h.state);
        let sup_events = std::sync::Arc::clone(&h.events);
        h.task = Some(slipstream_core::ffi_handle::spawn_supervised(
            &h.runtime,
            slipstream_core::session::run_session(
                session_config,
                reporter,
                std::sync::Arc::clone(&h.pass_lock),
            ),
            sup_state,
            sup_events,
        ));
        Ok(true)
    });
    unwrap_exc_or(res, false)
}

/// Stops any in-flight Slipstream sync (non-blocking — task abort is async).
///
/// Returns `true` immediately. The handle remains live; poll
/// [`zcashlc_slipstream_snapshot`] to confirm state transitions to idle.
///
/// # Safety
///
/// - `handle` must be a non-null pointer returned by [`zcashlc_slipstream_open`] that
///   has not previously been freed.
/// - `handle` must not be passed to two FFI calls at the same time.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_stop(handle: *mut SlipstreamHandle) -> bool {
    let handle = AssertUnwindSafe(handle);
    let res = catch_panic(|| {
        let handle = unsafe { handle.as_mut() }.ok_or_else(|| anyhow!("null handle"))?;
        // [API v2.1 E-2] Stamp the stop: a start() within 120 s keeps tip freshness
        // (quick background hop, SDKFlags parity); a longer gap re-masks.
        *handle
            .last_stop_at
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(std::time::Instant::now());
        let h = &mut handle.inner;
        if let Some(task) = h.task.take() {
            task.abort();
            join_aborted_slipstream_task(&task);
        }
        // [B4-16 drain] abort() cannot cancel an in-flight write-behind commit
        // (`spawn_blocking`) — drain it so a returned stop means the wallet file is
        // QUIESCENT: the host's next write (deleteAccount / importAccount / rewind
        // truncate) can no longer interleave with an orphan commit. Swift hops this
        // call off the cooperative pool (the drain is a real, bounded wait).
        drain_slipstream_wallet_writers(&h.progress);
        *h.state.lock().unwrap_or_else(|p| p.into_inner()) = SyncState::Idle;
        Ok(true)
    });
    unwrap_exc_or(res, false)
}

/// [B4-16 drain] Bounded wait for the engine's in-flight wallet-file writer — the
/// write-behind lane's deferred commit, a `spawn_blocking` closure `task.abort()` cannot
/// cancel. Field evidence (2026-07-04): an orphan commit outlived an `importAccount`
/// restart, collided with the new pass's first writes ("database is locked" →
/// non-transient failure, absorbed by the revival loop) and — worse — landed its
/// Scanned-mark AFTER the import's force-rescan re-queue, silently shrinking the new
/// account's scan scope. Called by stop() and start() right after aborting the task.
/// 10 s cap ≫ the worst observed device commit (a few seconds, A10); on timeout we
/// proceed with a warning — the busy_timeouts remain the backstop.
/// [B4-16 drain] `abort()` is ASYNCHRONOUS — the task keeps running until its next await
/// point, so a synchronous in-flight wallet write (an enhance `decrypt_and_store`, a
/// chain-tip or subtree-roots update — field evidence: a `deleteAccount` landing in that
/// window failed its read→write lock upgrade, "error + try again") can land AFTER
/// `abort()` returns. Wait (bounded) for the task to finish unwinding. Combined with
/// `drain_slipstream_wallet_writers` (the persist lane's `spawn_blocking` commit — the
/// engine's ONLY detached writer), a completed stop/start-abort means the wallet file is
/// FULLY quiescent.
fn join_aborted_slipstream_task(task: &tokio::task::AbortHandle) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !task.is_finished() {
        if std::time::Instant::now() >= deadline {
            tracing::warn!(
                "slipstream stop/start: aborted pass still unwinding after 10 s — proceeding"
            );
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn drain_slipstream_wallet_writers(progress: &slipstream_core::ProgressArc) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut waited = false;
    while progress.wallet_writers() > 0 {
        if std::time::Instant::now() >= deadline {
            tracing::warn!(
                "slipstream stop/start: in-flight wallet commit still running after 10 s — proceeding (busy_timeouts remain the backstop)"
            );
            return;
        }
        waited = true;
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if waited {
        tracing::info!("slipstream stop/start: drained in-flight wallet commit");
    }
}

/// Reads a snapshot of current Slipstream progress atomics (non-blocking, poll-based — D8).
///
/// Returns a zero-filled struct on null handle.
///
/// # Safety
///
/// - `handle` must be a non-null pointer returned by [`zcashlc_slipstream_open`] that
///   has not previously been freed, or null (in which case a zeroed struct is returned).
/// - `handle` must not be passed to two FFI calls at the same time.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_snapshot(
    handle: *const SlipstreamHandle,
) -> FfiSlipstreamSnapshot {
    let handle = AssertUnwindSafe(handle);
    let res = catch_panic(|| {
        let handle = unsafe { handle.as_ref() }.ok_or_else(|| anyhow!("null handle"))?;
        // Delegate to the inner handle's snapshot() and copy fields into the
        // cbindgen-visible FfiSlipstreamSnapshot defined in this file.
        let s = handle.inner.snapshot();
        Ok(FfiSlipstreamSnapshot {
            chain_tip: s.chain_tip,
            fetched_blocks: s.fetched_blocks,
            scanned_blocks: s.scanned_blocks,
            enhanced_txs: s.enhanced_txs,
            current_range_end: s.current_range_end,
            state: s.state,
            pass_total_blocks: s.pass_total_blocks,
            spendable_hint: s.spendable_hint,
            ranges_completed: s.ranges_completed,
            is_recovering: s.is_recovering,
            progress_permille: s.progress_permille,
            stalled_seconds: s.stalled_seconds,
            tip_fresh: if handle.tip_fresh_now(s.state) { 1 } else { 0 },
            tx_set_version: s.tx_set_version,
        })
    });
    unwrap_exc_or(res, FfiSlipstreamSnapshot::default())
}

impl SlipstreamHandle {
    /// [API v2.1 E-2] Lazily evaluates + latches tip freshness — the exact
    /// `shouldMarkChainTipUpdated` semantics the SDK derived host-side:
    /// - already fresh → stays fresh (until a >120 s stop→start gap re-masks in `start()`);
    /// - the refresh counter advanced past its `start()` baseline → the engine bumps it
    ///   only AFTER `session.update_chain_tip` succeeds, so an advance proves THIS run
    ///   refreshed the wallet-DB tip (counter-based so the E-3 DB-seeded tip can neither
    ///   fake freshness nor mask a refresh that fetched the same height);
    /// - otherwise → trust only a pass that reached Done (state 3): `sync_once` cannot
    ///   complete without `update_chain_tip` having succeeded.
    fn tip_fresh_now(&self, state: u8) -> bool {
        use std::sync::atomic::Ordering;
        if self.tip_fresh.load(Ordering::Relaxed) {
            return true;
        }
        let advanced = self.inner.progress.tip_refreshes()
            > self.tip_refreshes_at_run_start.load(Ordering::Relaxed);
        if advanced || state == 3 {
            self.tip_fresh.store(true, Ordering::Relaxed);
            return true;
        }
        false
    }
}

/// [API v2 §4.5] Notifies the engine that the HOST changed the wallet's transaction set
/// outside a sync pass — e.g. it stored a just-broadcast transaction. The engine responds by
/// emitting a FoundTransactions event (tag 5) through its normal event channel, so every
/// host's single event loop sees the pending transaction immediately and uniformly instead of
/// waiting for the next mempool/scan round. Returns `true` on success, `false` on a null
/// handle or internal panic.
///
/// # Safety
///
/// - `handle` must be a non-null pointer returned by [`zcashlc_slipstream_open`] that
///   has not previously been freed.
/// - `handle` must not be passed to two FFI calls at the same time.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_notify_tx_change(
    handle: *mut SlipstreamHandle,
) -> bool {
    let handle = AssertUnwindSafe(handle);
    let res = catch_panic(|| {
        let handle = unsafe { handle.as_ref() }.ok_or_else(|| anyhow!("null handle"))?;
        // [E-4] The version counter is the primary signal (snapshot-carried, loss-proof);
        // the tag-5 event stays for hosts that consume the ring.
        handle.inner.progress.bump_tx_set_version();
        handle
            .inner
            .push_event(slipstream_core::ffi_handle::FfiSlipstreamEvent { tag: 5, value: 0 });
        Ok(true)
    });
    unwrap_exc_or(res, false)
}

/// [API v2.1 E-6] The engine-owned wallet-provisioning anchor (policy in slipstream-core
/// `anchor.rs`): the chain facts a host needs BEFORE creating/restoring a wallet, with the
/// offline fallback policy INSIDE — no host re-implements provisioning math.
///
/// - `intent` = 1 (RESTORE, with `birthday`): `height` = the live chain tip to provision as
///   `recover_until`; offline ⇒ `max(fallback_checkpoint_height, birthday + 1)` (a restore
///   must NEVER get a NULL recover_until — the syncLogsMac9 rule). `treestate` is null (the
///   host keeps its birthday checkpoint).
/// - `intent` = 0 (NEW wallet): `height` + serialized `TreeState` protobuf = the reorg-safe
///   recent tree state (`tip − 100`, floored at Sapling activation); offline ⇒ `height` 0 +
///   null `treestate` (the host keeps its bundled checkpoint defaults).
///
/// Handle-less by design: provisioning happens BEFORE [`zcashlc_slipstream_open`] in the
/// host init flow, and `importAccount` must not serialize against the live handle. Creates
/// a short-lived runtime and blocks until resolved (typically one round-trip; the direct
/// path is a SINGLE attempt — the offline fallback IS the retry policy). When `tor_dir` is
/// non-empty the identifying fetches ride an isolated Tor circuit; a requested-but-failed
/// Tor bootstrap resolves OFFLINE — never a de-anonymising direct retry.
///
/// Returns null only on invalid arguments or an internal panic. Free with
/// [`zcashlc_slipstream_free_restore_anchor`].
///
/// # Safety
///
/// - `server_host` must be non-null and valid for reads for `server_host_len` bytes (UTF-8).
/// - If `tor_dir` is non-null, it must be valid for reads for `tor_dir_len` bytes (UTF-8).
/// - Neither buffer may be mutated for the duration of the call.
/// - Call [`zcashlc_slipstream_free_restore_anchor`] to free the returned pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_restore_anchor(
    server_host: *const u8,
    server_host_len: usize,
    server_port: u16,
    use_tls: bool,
    network_id: u32,
    intent: u8,
    birthday: u64,
    fallback_checkpoint_height: u64,
    tor_dir: *const u8,
    tor_dir_len: usize,
) -> *mut FfiRestoreAnchor {
    let res = catch_panic(|| {
        let host =
            std::str::from_utf8(unsafe { slice::from_raw_parts(server_host, server_host_len) })
                .map_err(|e| anyhow!("server_host UTF-8: {e}"))?;
        let network = if network_id == 1 {
            MainNetwork
        } else {
            TestNetwork
        };
        let endpoint = slipstream_core::config::Endpoint {
            host: host.to_string(),
            port: server_port,
            tls: use_tls,
        };
        let tor_dir_opt: Option<std::path::PathBuf> = if tor_dir.is_null() || tor_dir_len == 0 {
            None
        } else {
            Some(
                Path::new(OsStr::from_bytes(unsafe {
                    slice::from_raw_parts(tor_dir, tor_dir_len)
                }))
                .to_path_buf(),
            )
        };
        let intent = if intent == 1 {
            slipstream_core::anchor::AnchorIntent::Restore {
                birthday,
                fallback_checkpoint: fallback_checkpoint_height,
            }
        } else {
            slipstream_core::anchor::AnchorIntent::New
        };

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| anyhow!("tokio runtime: {e}"))?;
        let anchor = runtime.block_on(async {
            let tor_conn = match &tor_dir_opt {
                Some(dir) => {
                    match slipstream_core::connector::TorConn::bootstrap(dir, false).await {
                        Ok(t) => Some(t),
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "anchor: Tor bootstrap failed — resolving OFFLINE (no direct fallback)"
                            );
                            return slipstream_core::anchor::offline_anchor(intent);
                        }
                    }
                }
                None => None,
            };
            slipstream_core::anchor::restore_anchor(&endpoint, network.into(), intent, tor_conn.as_ref())
                .await
        });

        let (ts_ptr, ts_len) = match anchor.treestate {
            Some(ts) => ptr_from_vec(ts.encode_to_vec()),
            None => (std::ptr::null_mut(), 0),
        };
        Ok(Box::into_raw(Box::new(FfiRestoreAnchor {
            height: anchor.height,
            treestate: ts_ptr,
            treestate_len: ts_len,
        })))
    });
    unwrap_exc_or_null(res)
}

/// Frees an [`FfiRestoreAnchor`] returned by [`zcashlc_slipstream_restore_anchor`].
///
/// # Safety
///
/// - If `ptr` is non-null, it must be a pointer returned by
///   [`zcashlc_slipstream_restore_anchor`] that has not previously been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_free_restore_anchor(ptr: *mut FfiRestoreAnchor) {
    if !ptr.is_null() {
        let anchor = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(anchor.treestate, anchor.treestate_len);
        drop(anchor);
    }
}

/// [#1806] Upper bound on the post-restore balance hold (see [`PostFlipHold`] and
/// [`zcashlc_slipstream_wallet_summary`]). Generous relative to the observed ~30 s
/// summary-availability gap after a restore completes, but bounded so a wedged engine can never
/// hold a stale balance indefinitely.
const POST_FLIP_HOLD_CAP: std::time::Duration = std::time::Duration::from_secs(120);

/// [#1806] The post-restore balance-hold latch. Right after a restore finishes, the engine flips
/// `is_recovering` 1→0 while the upstream `get_wallet_summary` still returns `None` for ~30 s
/// (scan-progress for the just-finalized range is not yet computable). Without intervention the
/// FFI serves EMPTY balances for that window and the just-restored funds visibly vanish
/// (MOB-1513 E2-FIX). This latch lets the summary path keep serving the engine-owned recovery
/// view across that gap, under strict safety gates. One-shot: `Idle → Engaged → Released`, and
/// `Released` is terminal for the handle's life (a second restore in the same session does not
/// re-arm it).
#[derive(Debug, Default, Clone, Copy, PartialEq)]
enum HoldLatch {
    /// No qualifying `is_recovering 1→0` flip has engaged the hold yet.
    #[default]
    Idle,
    /// A flip whose recovery override was serving a non-zero value engaged the hold at `flip_at`.
    Engaged { flip_at: std::time::Instant },
    /// The hold is permanently consumed: either the first upstream `Some` after the flip won
    /// (upstream truth thereafter), or an unmined outgoing spend was detected. Never re-engages.
    Released,
}

/// [#1806] Per-handle post-restore hold state: the latch, the last-observed recovery flag (for
/// 1→0 edge detection), and the heights of the most recent non-`None` upstream summary (reused
/// when the hold synthesizes its balance-only summary, since the Swift bridge drops any summary
/// with `fully_scanned_height < 0`). Guarded by the handle's `post_flip_hold` mutex — the same
/// synchronization the sibling caches use. See [`zcashlc_slipstream_wallet_summary`] for the full
/// policy and its bounds.
///
/// Cold-start edge (ACCEPTED, documented here per the E2-FIX spec): if the PROCESS restarts
/// during the ~30 s post-flip window, no `1→0` flip is observed on the fresh handle, so the latch
/// never engages and the pre-hold behavior (serve the transient empty summary until upstream
/// returns `Some`) applies. That is the same brief exposure a host tolerated before this fix, and
/// far rarer than the steady-state flip the hold covers. The durable fix is slipstream-core
/// finalizing the restore handoff before it flips `is_recovering` (MOB-1513 E2-FIX spec).
#[derive(Debug, Default)]
struct PostFlipHold {
    /// Last observed `is_recovering` flag, for 1→0 edge detection. `None` until the first
    /// summary call on this handle observes a snapshot.
    last_is_recovering: Option<bool>,
    /// The hold latch.
    latch: HoldLatch,
    /// `(chain_tip_height, fully_scanned_height)` from the most recent non-`None` upstream
    /// summary. `None` until the first `Some` upstream summary resolves.
    last_heights: Option<(i32, i32)>,
}

/// [#1806] Per-account unmined-outgoing-spend status for the post-restore hold's safety gate.
/// The recovery view counts only MINED reconciled deltas, so it does not subtract a pending
/// (unmined) outgoing spend — holding across one would over-show a stale-high balance. `Unknown`
/// (the spend query failed / was contended) is treated as "cannot verify": the hold is suspended
/// for this tick WITHOUT releasing the latch, so a later successful check can resume it.
#[derive(Debug, Clone, Copy, PartialEq)]
enum UnminedSpendStatus {
    Absent,
    Present,
    Unknown,
}

/// [#1806] What the summary path serves for this tick, decided by [`decide_summary_serving`].
#[derive(Debug, Clone, Copy, PartialEq)]
enum SummaryServe {
    /// Serve the resolved upstream summary unchanged (a real `Some` → real balances; a `None`
    /// → the empty `none()` sentinel). No recovery override — the pre-hold behavior.
    Upstream,
    /// Recovering (`is_recovering == 1`): replace every account balance with the recovery-view
    /// net (the pre-existing unconditional override).
    RecoveringOverride,
    /// Post-restore hold: the upstream summary is transiently `None` but the latch is engaged,
    /// within the cap, and no unmined outgoing spend is pending — synthesize a balance-only
    /// summary from the recovery-view nets so the restored funds do not vanish.
    HoldOverride,
}

/// [#1806] Freshness-tagged classification of the resolved upstream summary. The summary served
/// to hosts comes from a RATIONED cache, so a `Some` observed at a given tick may be STALE — its
/// walk started before the `is_recovering 1→0` flip and therefore predates the restored notes.
/// Releasing the hold on such a stale `Some` (or serving it raw) would re-expose the very ~30 s
/// empty/regressed window the hold exists to cover (MOB-1513 E2-FIX / C1). The latch may be
/// released only by a `Some` KNOWN to be post-flip (`FreshSome`).
#[derive(Debug, Clone, Copy, PartialEq)]
enum UpstreamKind {
    /// The cache walked to `None` (no balance data) — regardless of when the walk ran.
    None,
    /// A `Some` whose walk STARTED while the engine was still recovering (pre-flip). Not yet
    /// trustworthy: treated exactly like `None` by the hold (do not serve it, do not release).
    StaleSome,
    /// A `Some` whose walk started while NOT recovering (post-flip) — real, current balances.
    FreshSome,
}

/// [#1806] Classify the resolved upstream summary by presence + the recovery state its walk ran
/// under. `walked_while_recovering` is the `is_recovering` flag captured when the cache entry's
/// walk started; a `Some` produced during recovery is `StaleSome` (pre-flip), otherwise
/// `FreshSome`.
fn classify_upstream(summary_is_some: bool, walked_while_recovering: bool) -> UpstreamKind {
    if !summary_is_some {
        UpstreamKind::None
    } else if walked_while_recovering {
        UpstreamKind::StaleSome
    } else {
        UpstreamKind::FreshSome
    }
}

/// [#1806] Pure post-restore-hold state-machine step for the unified wallet summary. Factored out
/// of [`zcashlc_slipstream_wallet_summary`] so the whole serving policy — engage-on-flip,
/// first-`Some`-wins, cap expiry, and the unmined-spend safety gate — is exhaustively unit
/// testable with no engine, DB, or clock. Returns the next latch and the serve decision.
///
/// Inputs (this tick's observed facts):
/// - `is_recovering`: the engine snapshot's recovery flag.
/// - `last_is_recovering`: the previous tick's flag (for 1→0 edge detection); `None` on the
///   first observation on this handle.
/// - `upstream`: freshness-tagged classification of the resolved summary (see [`UpstreamKind`]);
///   only a `FreshSome` (post-flip) releases the latch.
/// - `prior_recovery_nonzero`: whether the recovery override had been serving a non-zero value
///   just before the flip (only consulted AT the flip; guards case (f) — nothing to hold).
/// - `spend`: per-account unmined-outgoing-spend status (only consulted while holding).
/// - `latch`: the current latch.
/// - `now`: the current instant (engages the latch at `flip_at = now`, and measures the cap).
/// - `cap`: the hold's upper time bound.
fn decide_summary_serving(
    is_recovering: bool,
    last_is_recovering: Option<bool>,
    upstream: UpstreamKind,
    prior_recovery_nonzero: bool,
    spend: UnminedSpendStatus,
    latch: HoldLatch,
    now: std::time::Instant,
    cap: std::time::Duration,
) -> (HoldLatch, SummaryServe) {
    // Recovering: the pre-existing unconditional override. The latch only ever engages at the
    // 1→0 edge below, so while recovering it passes through untouched.
    if is_recovering {
        return (latch, SummaryServe::RecoveringOverride);
    }

    // Not recovering.
    // (1) Engage on a 1→0 edge whose recovery override had been serving a non-zero value. One-
    //     shot: only `Idle` can engage, so a second restore in the same session never re-arms it,
    //     and case (f) (prior override was zero → nothing worth holding) is filtered out here.
    let mut latch = latch;
    let flipped = last_is_recovering == Some(true);
    if flipped && latch == HoldLatch::Idle && prior_recovery_nonzero {
        latch = HoldLatch::Engaged { flip_at: now };
    }

    // (2) Only a FRESH post-flip `Some` releases the latch: upstream truth wins thereafter, even if
    //     lower than the recovery view. A STALE cached `Some` (its walk started pre-flip, so it
    //     predates the restored notes — C1) is NOT trustworthy yet: treat it exactly like `None`
    //     below and keep holding, covering the window where the rationed cache still serves the
    //     pre-flip `Some`.
    if matches!(upstream, UpstreamKind::FreshSome) {
        if matches!(latch, HoldLatch::Engaged { .. }) {
            latch = HoldLatch::Released;
        }
        return (latch, SummaryServe::Upstream);
    }

    // (3) Upstream is `None` or `StaleSome` — evaluate the hold.
    match latch {
        HoldLatch::Engaged { flip_at } => {
            if now.saturating_duration_since(flip_at) > cap {
                // Cap expired: suspend the hold, serve empty (pre-hold behavior). The latch stays
                // Engaged-but-inert — `flip_at` is fixed so it never serves again and, being
                // non-`Idle`, never re-engages.
                (latch, SummaryServe::Upstream)
            } else {
                match spend {
                    // No pending spend: safe to surface the recovery-view balances.
                    UnminedSpendStatus::Absent => (latch, SummaryServe::HoldOverride),
                    // A pending unmined outgoing spend would make the mined-only recovery view
                    // over-show. End the hold PERMANENTLY (do not re-engage) and serve empty.
                    UnminedSpendStatus::Present => (HoldLatch::Released, SummaryServe::Upstream),
                    // Could not verify: suspend this tick but keep the latch, so a later
                    // successful check resumes — never hold on an unverified spend state.
                    UnminedSpendStatus::Unknown => (latch, SummaryServe::Upstream),
                }
            }
        }
        // Never engaged (cold start / case (e)) or already released: pre-hold behavior.
        HoldLatch::Idle | HoldLatch::Released => (latch, SummaryServe::Upstream),
    }
}

/// [#1806] The `v_transactions` query behind [`read_unmined_spend_accounts`], split out so it can
/// be unit-tested against an in-memory `v_transactions`-shaped table. Returns the set of accounts
/// with an UNMINED, UNEXPIRED, outgoing (note-spending) transaction — the post-restore hold's
/// safety gate. Derived from `v_transactions` (the same view family the recovery balance reads):
/// an outgoing spend is `spent_note_count > 0` (mirrors librustzcash's spent-notes clause),
/// unmined is `mined_height IS NULL`, and the view's own `expired_unmined` flag supplies
/// tx-expiry (mirrors `tx_unexpired_condition`). The returned UUIDs match the account keys of
/// `ext_slipstream_v_recovery_balance`.
fn read_unmined_spend_accounts_conn(
    conn: &rusqlite::Connection,
) -> anyhow::Result<std::collections::HashSet<[u8; 16]>> {
    let mut accounts = std::collections::HashSet::new();
    let mut stmt = conn
        .prepare(
            // `COALESCE(expired_unmined, 0) = 0`, NOT `expired_unmined = 0`: `expired_unmined` is
            // NULL when the tx's `expiry_height` is unknown (e.g. an un-enhanced pending tx), and a
            // bare `= 0` silently drops NULL rows — letting such a hazard slip the gate (M1). NULL
            // ⇒ treat as not-yet-expired ⇒ a hazard the hold must respect.
            "SELECT DISTINCT account_uuid FROM v_transactions \
             WHERE mined_height IS NULL AND spent_note_count > 0 \
             AND COALESCE(expired_unmined, 0) = 0",
        )
        .map_err(|e| anyhow!("unmined-spend prepare: {}", e))?;
    let mut rows = stmt
        .query([])
        .map_err(|e| anyhow!("unmined-spend query: {}", e))?;
    while let Some(row) = rows
        .next()
        .map_err(|e| anyhow!("unmined-spend row: {}", e))?
    {
        let uuid: Vec<u8> = row
            .get(0)
            .map_err(|e| anyhow!("unmined-spend uuid: {}", e))?;
        if let Ok(uuid16) = <[u8; 16]>::try_from(uuid.as_slice()) {
            accounts.insert(uuid16);
        }
    }
    Ok(accounts)
}

/// [#1806] Open `db_path` with the same 250 ms busy timeout as the recovery-balance read and run
/// [`read_unmined_spend_accounts_conn`]. Errors (including busy contention) propagate so the
/// caller can treat them as [`UnminedSpendStatus::Unknown`] — never as "no spend".
fn read_unmined_spend_accounts(
    db_path: &std::path::Path,
) -> anyhow::Result<std::collections::HashSet<[u8; 16]>> {
    let conn =
        rusqlite::Connection::open(db_path).map_err(|e| anyhow!("unmined-spend open: {}", e))?;
    conn.busy_timeout(std::time::Duration::from_millis(250))
        .map_err(|e| anyhow!("unmined-spend busy_timeout: {}", e))?;
    read_unmined_spend_accounts_conn(&conn)
}

/// [#1806] The testable core of [`zcashlc_slipstream_wallet_summary`]'s serve path: given this
/// tick's classified upstream, the hold state, and DB access, it runs the I1 gates and the
/// [`decide_summary_serving`] state machine, then builds the summary to serve. Extracted so the
/// WIRING (classify → gate → decide → build) can be driven in tests with a fabricated cache
/// classification + a real fixture DB — the seam the pure-function tests alone cannot cover (C1).
///
/// `build_upstream` marshals the resolved upstream summary (a real `Some`, or the empty `none()`
/// sentinel) and is invoked ONLY for the `Upstream`/`RecoveringOverride` decisions — never for a
/// synthesized hold. The DB reads (recovery-view nets, unmined-spend gate) run against `db_path`.
///
/// `ironwood_active` says whether NU6.3 is active at the chain tip; it selects which pool carries
/// the collapsed recovery net (see [`ffi::AccountBalance::override_with_recovery_net`]).
///
/// I1: the unmined-spend query and the `prior_recovery_nonzero` scan run ONLY when the hold could
/// actually serve this tick (engaged-or-engaging, within cap, upstream not `FreshSome`) — never on
/// an ordinary `None`-serving tick with an idle/released latch — so there is no per-tick DB hit or
/// warn spam on a wallet that is merely between balances, and the warn is bounded by the 120 s cap.
#[allow(clippy::too_many_arguments)]
fn serve_wallet_summary(
    is_recovering: bool,
    ironwood_active: bool,
    upstream: UpstreamKind,
    hold_heights: Option<(i32, i32)>,
    last_is_recovering: Option<bool>,
    latch_in: HoldLatch,
    now: std::time::Instant,
    cap: std::time::Duration,
    db_path: &std::path::Path,
    recovery_nets_cache: &std::sync::Mutex<Option<std::collections::HashMap<[u8; 16], i64>>>,
    build_upstream: impl FnOnce() -> anyhow::Result<*mut ffi::WalletSummary>,
) -> anyhow::Result<(HoldLatch, *mut ffi::WalletSummary)> {
    // `prior_recovery_nonzero` is consulted only at the flip (Idle + flipped), so gate the
    // in-memory scan there — it must not run on every tick (I1).
    let flipped = !is_recovering && last_is_recovering == Some(true);
    let prior_recovery_nonzero = if flipped && latch_in == HoldLatch::Idle {
        recovery_nets_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|m| m.values().any(|&v| v > 0))
            .unwrap_or(false)
    } else {
        false
    };

    // Whether the hold could serve `HoldOverride` this tick — this gates the unmined-spend DB read
    // (I1). `FreshSome` is excluded: it releases rather than holds, so its gate never runs.
    let engaging = flipped && latch_in == HoldLatch::Idle && prior_recovery_nonzero;
    let engaged_now = matches!(latch_in, HoldLatch::Engaged { .. }) || engaging;
    let within_cap = match latch_in {
        HoldLatch::Engaged { flip_at } => now.saturating_duration_since(flip_at) <= cap,
        _ => true,
    };
    let hold_window =
        !is_recovering && engaged_now && within_cap && !matches!(upstream, UpstreamKind::FreshSome);
    let spend_status = if hold_window {
        match read_unmined_spend_accounts(db_path) {
            Ok(set) if set.is_empty() => UnminedSpendStatus::Absent,
            Ok(_) => UnminedSpendStatus::Present,
            Err(e) => {
                tracing::warn!(error = %e, "unmined-spend gate read failed; suspending hold this tick");
                UnminedSpendStatus::Unknown
            }
        }
    } else {
        UnminedSpendStatus::Absent
    };

    let (latch_after, decision) = decide_summary_serving(
        is_recovering,
        last_is_recovering,
        upstream,
        prior_recovery_nonzero,
        spend_status,
        latch_in,
        now,
        cap,
    );

    // The bounded recovery-balance read + last-good fallback, shared by the recovering override and
    // the hold synthesis. 250 ms busy timeout (NOT the 5 s used elsewhere): under mid-restore write
    // contention a longer wait would pin the Swift engine actor. On ANY failure, fall back to the
    // last successfully-read nets (or an empty map, which zeroes every balance — safe).
    let resolve_recovery_nets = || -> std::collections::HashMap<[u8; 16], i64> {
        let read = || -> anyhow::Result<std::collections::HashMap<[u8; 16], i64>> {
            let conn = rusqlite::Connection::open(db_path)
                .map_err(|e| anyhow!("recovery balance open: {}", e))?;
            conn.busy_timeout(std::time::Duration::from_millis(250))
                .map_err(|e| anyhow!("recovery balance busy_timeout: {}", e))?;
            let mut nets: std::collections::HashMap<[u8; 16], i64> =
                std::collections::HashMap::new();
            let mut stmt = conn
                .prepare("SELECT account_uuid, balance_zat FROM ext_slipstream_v_recovery_balance")
                .map_err(|e| anyhow!("recovery balance prepare: {}", e))?;
            let mut rows = stmt
                .query([])
                .map_err(|e| anyhow!("recovery balance query: {}", e))?;
            while let Some(row) = rows
                .next()
                .map_err(|e| anyhow!("recovery balance row: {}", e))?
            {
                let uuid: Vec<u8> = row
                    .get(0)
                    .map_err(|e| anyhow!("recovery balance uuid: {}", e))?;
                let net: i64 = row
                    .get(1)
                    .map_err(|e| anyhow!("recovery balance net: {}", e))?;
                if let Ok(uuid16) = <[u8; 16]>::try_from(uuid.as_slice()) {
                    nets.insert(uuid16, net);
                }
            }
            Ok(nets)
        };
        match read() {
            Ok(fresh) => {
                *recovery_nets_cache
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = Some(fresh.clone());
                fresh
            }
            Err(e) => {
                tracing::warn!(error = %e, "recovery balance read failed; using cached/zero fallback");
                recovery_nets_cache
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone()
                    .unwrap_or_default()
            }
        }
    };

    let summary_ptr = match decision {
        // Serve the resolved upstream summary unchanged (real `Some` balances, or the empty
        // `none()` sentinel). A `StaleSome` reaches here only in a non-hold latch state, where
        // serving today's cache is correct.
        SummaryServe::Upstream => build_upstream()?,
        // Recovering: marshal upstream, then REPLACE every slot with the recovery-view net.
        SummaryServe::RecoveringOverride => {
            let ptr = build_upstream()?;
            let nets = resolve_recovery_nets();
            let summary_mut = unsafe { &mut *ptr };
            for balance in summary_mut.account_balances_mut() {
                let net = nets.get(balance.uuid_bytes()).copied().unwrap_or(0);
                balance.override_with_recovery_net(net, ironwood_active);
            }
            ptr
        }
        // Post-restore hold: synthesize a balance-only summary from the FRESH recovery-view nets.
        // Needs real heights (Swift drops `fully_scanned_height < 0`); lacking them, serve the
        // empty sentinel — never the stale raw upstream, and never fabricate a height.
        // (M2) The synthesis carries one slot per recovery-view row, so an account with no recovery
        // row is present-as-ABSENT during the hold (reads 0 via the SDK's `?? .zero`), not
        // present-as-zero. Benign for the host's migration read (it only asks whether Orchard > 0
        // — which the collapsed net deliberately does not answer post-activation), so the hold
        // does not re-plumb full account enumeration.
        SummaryServe::HoldOverride => match hold_heights {
            Some((chain_tip_h, fully_scanned_h)) => {
                let nets = resolve_recovery_nets();
                let entries: Vec<ffi::AccountBalance> = nets
                    .iter()
                    .map(|(uuid, net)| {
                        ffi::AccountBalance::recovery_only(*uuid, *net, ironwood_active)
                    })
                    .collect();
                ffi::WalletSummary::recovery_hold(entries, chain_tip_h, fully_scanned_h)
            }
            None => ffi::WalletSummary::none(),
        },
    };
    Ok((latch_after, summary_ptr))
}

/// [API v2 §0-5] The unified, PHASE-RESOLVING wallet summary for Slipstream hosts: one call
/// that is correct at every phase, so no host ever re-implements restore balance math.
///
/// - **Not recovering** → the upstream wallet summary, unchanged (identical to
///   [`zcashlc_get_wallet_summary`]).
/// - **Recovering** (the recent-first restore backfill; `snapshot.is_recovering == 1`) →
///   the upstream summary's per-account balances are REPLACED, because upstream balances
///   "may overestimate" mid-restore by documented design (a receipt is counted before its
///   spend is scanned). The replacement is the engine-owned `ext_slipstream_v_recovery_balance`
///   (Σ of FINAL, reconciled tx deltas — never over-shows, converges to the true total),
///   surfaced per the SDK's field-validated Direction-B mapping: the whole clamped net as
///   orchard spendable, everything else zero. Progress/heights fields pass through.
///
/// Returns null on error; a summary with `fully_scanned_height == -1` when the wallet has
/// no balance data yet.
///
/// # Safety
///
/// - `handle` must be a non-null pointer returned by [`zcashlc_slipstream_open`] that
///   has not previously been freed, and must not be passed to two FFI calls at once.
/// - Call [`zcashlc_free_wallet_summary`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_wallet_summary(
    handle: *const SlipstreamHandle,
    confirmations_policy: ffi::ConfirmationsPolicy,
) -> *mut ffi::WalletSummary {
    let handle = AssertUnwindSafe(handle);
    let res = catch_panic(|| {
        let handle = unsafe { handle.as_ref() }.ok_or_else(|| anyhow!("null handle"))?;
        let network = handle.inner.network;
        let db_path = handle.inner.wallet_db_path.clone();
        let snap = handle.inner.snapshot();

        // ── [API v2.1 E-1] Serve-cached + refresh policy — the walk is rationed HERE, so
        // hosts may call this whenever they like (per poll tick included):
        //   • no cache yet → ONE synchronous walk (in practice: the host's prepare/open-time
        //     call, when the engine is quiet);
        //   • cache exists → serve it immediately, and — when the pass crossed a range
        //     boundary, the state changed, or (outside a scan) the idle TTL elapsed — spawn
        //     ONE background walk (plain thread; owns only clones + Arcs, so it is safe
        //     against `free()` racing it) that swaps the cache for later calls.
        // Between boundaries while Syncing, NO walk ever runs: the T5.5
        // no-summary-while-scanning invariant, now engine-owned. The recovery-balance
        // REPLACEMENT below still re-reads the cheap view on every call, so a recovering
        // host sees the per-tick climb; [#1806] only bounds that read and adds a
        // contended-read fallback cache — it is not a serve-cached policy.
        let cached: Option<SummaryCacheEntry> = {
            let guard = handle
                .summary_cache
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            guard.as_ref().map(|e| SummaryCacheEntry {
                captured_at: e.captured_at,
                ranges_completed: e.ranges_completed,
                state: e.state,
                summary: e.summary.clone(),
                walked_while_recovering: e.walked_while_recovering,
            })
        };

        // [#1806 / C1] Resolve the served summary AND the recovery state its walk ran under, so a
        // stale (pre-flip) cached `Some` can be told from a fresh (post-flip) one below.
        let (resolved, walked_while_recovering): (
            Option<zcash_client_backend::data_api::WalletSummary<AccountUuid>>,
            bool,
        ) = match cached {
            None => {
                // First call on this handle: walk synchronously and prime the cache with the
                // walked Option in BOTH arms. [#1806] A None walk ("no balance data yet" on a
                // fresh / just-imported wallet) is cached too, so later poll ticks serve that
                // cached None instead of repeating this synchronous walk; the boundary/TTL
                // refresh below then replaces it once the first scan commits real balances.
                let path_bytes = db_path.as_os_str().as_bytes();
                let db_data = unsafe {
                    wallet_db(
                        path_bytes.as_ptr(),
                        path_bytes.len(),
                        NetworkParams::Standard(network),
                    )?
                };
                let policy = wallet::ConfirmationsPolicy::try_from(confirmations_policy)?;
                let walked = db_data
                    .get_wallet_summary(policy)
                    .map_err(|e| anyhow!("Error while fetching wallet summary: {}", e))?;
                let recovering_at = snap.is_recovering == 1;
                *handle
                    .summary_cache
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = Some(SummaryCacheEntry {
                    captured_at: std::time::Instant::now(),
                    ranges_completed: snap.ranges_completed,
                    state: snap.state,
                    summary: walked.clone(),
                    walked_while_recovering: recovering_at,
                });
                (walked, recovering_at)
            }
            Some(entry) => {
                let boundary_crossed =
                    snap.ranges_completed != entry.ranges_completed || snap.state != entry.state;
                let idle_ttl_due =
                    snap.state != 1 && entry.captured_at.elapsed() >= SUMMARY_IDLE_TTL;
                if (boundary_crossed || idle_ttl_due)
                    && !handle
                        .summary_refresh_inflight
                        .swap(true, std::sync::atomic::Ordering::SeqCst)
                {
                    let cache = std::sync::Arc::clone(&handle.summary_cache);
                    let inflight = std::sync::Arc::clone(&handle.summary_refresh_inflight);
                    let thread_db_path = db_path.clone();
                    let thread_policy = confirmations_policy;
                    let (ranges_at, state_at, recovering_at) =
                        (snap.ranges_completed, snap.state, snap.is_recovering == 1);
                    std::thread::spawn(move || {
                        let walk = || -> anyhow::Result<
                            Option<zcash_client_backend::data_api::WalletSummary<AccountUuid>>,
                        > {
                            let path_bytes = thread_db_path.as_os_str().as_bytes();
                            let db_data = unsafe {
                                wallet_db(
                                    path_bytes.as_ptr(),
                                    path_bytes.len(),
                                    NetworkParams::Standard(network),
                                )?
                            };
                            let policy =
                                wallet::ConfirmationsPolicy::try_from(thread_policy)?;
                            db_data
                                .get_wallet_summary(policy)
                                .map_err(|e| anyhow!("summary refresh: {}", e))
                        };
                        // [#1806] Store the whole walked Option: a refresh that walks to None
                        // caches None (later ticks then serve that cached None). Only an Err
                        // leaves the cache untouched — a contended refresh must not clobber a
                        // good entry with nothing.
                        if let Ok(walked) = walk() {
                            *cache.lock().unwrap_or_else(|p| p.into_inner()) =
                                Some(SummaryCacheEntry {
                                    captured_at: std::time::Instant::now(),
                                    ranges_completed: ranges_at,
                                    state: state_at,
                                    summary: walked,
                                    walked_while_recovering: recovering_at,
                                });
                        }
                        // Always clears — on the stored, walked-None, and Err paths alike.
                        inflight.store(false, std::sync::atomic::Ordering::SeqCst);
                    });
                }
                (entry.summary, entry.walked_while_recovering)
            }
        };

        // [#1806 / C1] Classify the resolved summary by presence + the recovery state its walk ran
        // under, then serve via the extracted, unit-tested [`serve_wallet_summary`]. A `Some` whose
        // walk started pre-flip is `StaleSome` — the hold must not release on it or serve it raw
        // (the cache lags the flip, so the first post-flip tick still holds the pre-flip `Some`).
        let upstream_kind = classify_upstream(resolved.is_some(), walked_while_recovering);
        // Heights of a real (Some) upstream summary — the hold reuses them so its synthesized
        // summary carries a real, ≥0 scanned height (the Swift bridge drops `< 0` as "no data").
        let resolved_heights: Option<(i32, i32)> = resolved.as_ref().map(|s| {
            (
                u32::from(s.chain_tip_height()) as i32,
                u32::from(s.fully_scanned_height()) as i32,
            )
        });
        let is_recovering = snap.is_recovering == 1;

        let (latch_before, last_is_recovering, last_heights) = {
            let g = handle
                .post_flip_hold
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            (g.latch, g.last_is_recovering, g.last_heights)
        };
        // Synthesize from this tick's real heights when present, else the last-known ones.
        let hold_heights = resolved_heights.or(last_heights);
        let now = std::time::Instant::now();

        // NU6.3 active at the tip decides which pool the collapsed recovery net lands in.
        let ironwood_active = network
            .activation_height(NetworkUpgrade::Nu6_3)
            .is_some_and(|h| snap.chain_tip >= u64::from(u32::from(h)));

        let (latch_after, summary_ptr) = serve_wallet_summary(
            is_recovering,
            ironwood_active,
            upstream_kind,
            hold_heights,
            last_is_recovering,
            latch_before,
            now,
            POST_FLIP_HOLD_CAP,
            &db_path,
            &handle.recovery_nets_cache,
            || match resolved {
                Some(s) => ffi::WalletSummary::some(s),
                None => Ok(ffi::WalletSummary::none()),
            },
        )?;

        // Persist the latch, the observed recovery flag, and (from a real summary) the heights.
        {
            let mut g = handle
                .post_flip_hold
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            g.latch = latch_after;
            g.last_is_recovering = Some(is_recovering);
            if let Some(h) = resolved_heights {
                g.last_heights = Some(h);
            }
        }

        Ok(summary_ptr)
    });
    unwrap_exc_or_null(res)
}

/// Drains all queued Slipstream events into a caller-allocated buffer.
///
/// - `handle`: non-null pointer returned by [`zcashlc_slipstream_open`].
/// - `buf`: caller-allocated array of [`FfiSlipstreamEvent`]; must be valid for writes
///   for `buf_len` elements.
/// - `buf_len`: length of `buf` (maximum events to drain in this call).
///
/// Returns the number of events written (≤ `buf_len`). Events are drained atomically
/// — after this call returns, the drained events are removed from the internal ring.
///
/// # Safety
///
/// - `handle` must be a non-null pointer returned by [`zcashlc_slipstream_open`] that
///   has not previously been freed.
/// - `handle` must not be passed to two FFI calls at the same time.
/// - `buf` must be non-null and valid for writes for `buf_len` elements of
///   [`FfiSlipstreamEvent`], with alignment of `1`.
/// - `buf_len` must be no larger than `isize::MAX`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_drain_events(
    handle: *mut SlipstreamHandle,
    buf: *mut FfiSlipstreamEvent,
    buf_len: usize,
) -> usize {
    let handle = AssertUnwindSafe(handle);
    let buf = AssertUnwindSafe(buf);
    let res = catch_panic(|| {
        let handle = unsafe { handle.as_mut() }.ok_or_else(|| anyhow!("null handle"))?;
        let mut ring = handle
            .inner
            .events
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let to_copy = ring.len().min(buf_len);
        // Convert from the ffi_handle event type to the cbindgen-visible
        // FfiSlipstreamEvent (defined in this file). Both are repr(C); copy fields.
        let drained: Vec<FfiSlipstreamEvent> = ring
            .drain(..to_copy)
            .map(|e| FfiSlipstreamEvent {
                tag: e.tag,
                value: e.value,
            })
            .collect();
        // SAFETY: buf is valid for writes for buf_len elements (caller contract above).
        unsafe { std::ptr::copy_nonoverlapping(drained.as_ptr(), *buf, to_copy) };
        Ok(to_copy)
    });
    unwrap_exc_or(res, 0)
}

/// Frees a Slipstream handle.
///
/// Cancels any in-flight sync and drops the tokio runtime. After this call, `handle`
/// must not be used.
///
/// # Safety
///
/// - If `handle` is non-null, it must be a pointer returned by [`zcashlc_slipstream_open`]
///   that has not previously been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_free(handle: *mut SlipstreamHandle) {
    if !handle.is_null() {
        // SAFETY: handle is non-null and was returned by zcashlc_slipstream_open (caller
        // contract). We take ownership here and drop it at end of scope.
        let mut h: Box<SlipstreamHandle> = unsafe { Box::from_raw(handle) };
        // Abort the in-flight task before dropping the runtime; dropping a Runtime with
        // live tasks causes a panic on some platforms.
        if let Some(task) = h.inner.task.take() {
            task.abort();
        }
        drop(h);
    }
}

#[cfg(test)]
mod post_flip_hold_tests {
    use super::{
        HoldLatch, POST_FLIP_HOLD_CAP, SummaryServe, UnminedSpendStatus, UpstreamKind,
        classify_upstream, decide_summary_serving, read_unmined_spend_accounts_conn,
    };
    use std::time::{Duration, Instant};

    /// `base + secs` — build a later instant without `Instant` subtraction (panic-free).
    fn at(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    // ── classify_upstream ──────────────────────────────────────────────────────────────────

    #[test]
    fn classify_none_is_none() {
        assert_eq!(classify_upstream(false, false), UpstreamKind::None);
        assert_eq!(classify_upstream(false, true), UpstreamKind::None);
    }

    #[test]
    fn classify_some_walked_recovering_is_stale() {
        assert_eq!(classify_upstream(true, true), UpstreamKind::StaleSome);
    }

    #[test]
    fn classify_some_walked_not_recovering_is_fresh() {
        assert_eq!(classify_upstream(true, false), UpstreamKind::FreshSome);
    }

    // ── decide_summary_serving: the post-restore hold state machine ────────────────────────

    #[test]
    fn recovering_always_overrides_and_leaves_latch_untouched() {
        let now = Instant::now();
        let (latch, serve) = decide_summary_serving(
            true,
            Some(true),
            UpstreamKind::FreshSome,
            true,
            UnminedSpendStatus::Absent,
            HoldLatch::Idle,
            now,
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::RecoveringOverride);
        assert_eq!(latch, HoldLatch::Idle);
    }

    /// (a) None + engaged hold + gates pass → recovery values served, and it keeps holding
    /// across later ticks still inside the cap.
    #[test]
    fn none_with_engaged_hold_and_no_spend_serves_recovery() {
        let base = Instant::now();
        // Flip tick: recovering last tick, not now; prior override non-zero; upstream None.
        let (latch, serve) = decide_summary_serving(
            false,
            Some(true),
            UpstreamKind::None,
            true,
            UnminedSpendStatus::Absent,
            HoldLatch::Idle,
            base,
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::HoldOverride);
        assert!(matches!(latch, HoldLatch::Engaged { .. }));

        // A later tick, still within the cap, keeps holding with the same flip_at.
        let (latch2, serve2) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::None,
            false,
            UnminedSpendStatus::Absent,
            latch,
            at(base, 30),
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve2, SummaryServe::HoldOverride);
        assert_eq!(latch2, latch);
    }

    /// C1 (pure): a STALE cached `Some` at the flip tick engages the hold and serves recovery —
    /// it must NOT be treated as the first post-flip truth (which would release + serve stale).
    #[test]
    fn stale_some_at_flip_engages_and_holds() {
        let base = Instant::now();
        let (latch, serve) = decide_summary_serving(
            false,
            Some(true),
            UpstreamKind::StaleSome,
            true,
            UnminedSpendStatus::Absent,
            HoldLatch::Idle,
            base,
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::HoldOverride);
        assert!(matches!(latch, HoldLatch::Engaged { .. }));
    }

    /// C1 (pure): while engaged, a still-stale cached `Some` keeps holding and never releases.
    #[test]
    fn stale_some_while_engaged_keeps_holding() {
        let base = Instant::now();
        let engaged = HoldLatch::Engaged { flip_at: base };
        let (latch, serve) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::StaleSome,
            false,
            UnminedSpendStatus::Absent,
            engaged,
            at(base, 30),
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::HoldOverride);
        assert_eq!(latch, engaged);
    }

    /// A stale `Some` in a NON-hold latch state (never engaged) serves today's cache unchanged —
    /// the fix must not disturb non-hold serving paths.
    #[test]
    fn stale_some_in_idle_serves_upstream_unchanged() {
        let now = Instant::now();
        let (latch, serve) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::StaleSome,
            false,
            UnminedSpendStatus::Absent,
            HoldLatch::Idle,
            now,
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::Upstream);
        assert_eq!(latch, HoldLatch::Idle);
    }

    /// (b) None + unmined outgoing spend → empty, and the latch is permanently released (no
    /// re-engage even once the spend later reads as absent within the cap).
    #[test]
    fn none_with_unmined_spend_serves_empty_and_releases_permanently() {
        let base = Instant::now();
        let engaged = HoldLatch::Engaged { flip_at: base };
        let (latch, serve) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::None,
            false,
            UnminedSpendStatus::Present,
            engaged,
            at(base, 10),
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::Upstream);
        assert_eq!(latch, HoldLatch::Released);

        let (latch2, serve2) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::None,
            false,
            UnminedSpendStatus::Absent,
            latch,
            at(base, 20),
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve2, SummaryServe::Upstream);
        assert_eq!(latch2, HoldLatch::Released);
    }

    /// (c) The first FRESH post-flip `Some` releases the latch permanently: upstream truth wins
    /// thereafter, even a subsequent `None` within the cap does not resurrect the hold.
    #[test]
    fn fresh_upstream_some_releases_latch_permanently() {
        let base = Instant::now();
        let engaged = HoldLatch::Engaged { flip_at: base };
        let (latch, serve) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::FreshSome,
            false,
            UnminedSpendStatus::Absent,
            engaged,
            at(base, 5),
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::Upstream);
        assert_eq!(latch, HoldLatch::Released);

        let (latch2, serve2) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::None,
            false,
            UnminedSpendStatus::Absent,
            latch,
            at(base, 6),
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve2, SummaryServe::Upstream);
        assert_eq!(latch2, HoldLatch::Released);
    }

    /// (d) Cap expired → empty.
    #[test]
    fn cap_expiry_serves_empty() {
        let base = Instant::now();
        let engaged = HoldLatch::Engaged { flip_at: base };
        let (_latch, serve) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::None,
            false,
            UnminedSpendStatus::Absent,
            engaged,
            at(base, 121),
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::Upstream);
    }

    /// (e) None with NO prior flip (cold start) → empty; the hold never engages without the
    /// 1→0 flip precondition (neither a first-observation `None` nor a not-recovering last tick).
    #[test]
    fn cold_start_none_never_engages() {
        let now = Instant::now();
        let (latch, serve) = decide_summary_serving(
            false,
            None,
            UpstreamKind::None,
            true,
            UnminedSpendStatus::Absent,
            HoldLatch::Idle,
            now,
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::Upstream);
        assert_eq!(latch, HoldLatch::Idle);

        let (latch2, serve2) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::None,
            true,
            UnminedSpendStatus::Absent,
            HoldLatch::Idle,
            now,
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve2, SummaryServe::Upstream);
        assert_eq!(latch2, HoldLatch::Idle);
    }

    /// (f) Flip observed but the recovery override was serving zero → the hold never engages.
    #[test]
    fn flip_with_zero_prior_override_never_engages() {
        let now = Instant::now();
        let (latch, serve) = decide_summary_serving(
            false,
            Some(true),
            UpstreamKind::None,
            false,
            UnminedSpendStatus::Absent,
            HoldLatch::Idle,
            now,
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::Upstream);
        assert_eq!(latch, HoldLatch::Idle);
    }

    /// An `Unknown` spend status (contended/failed query) suspends the hold for the tick WITHOUT
    /// releasing the latch, so a later successful `Absent` check resumes holding.
    #[test]
    fn unknown_spend_suspends_without_release_then_resumes() {
        let base = Instant::now();
        let engaged = HoldLatch::Engaged { flip_at: base };
        let (latch, serve) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::None,
            false,
            UnminedSpendStatus::Unknown,
            engaged,
            at(base, 10),
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::Upstream);
        assert_eq!(latch, engaged);

        let (latch2, serve2) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::None,
            false,
            UnminedSpendStatus::Absent,
            latch,
            at(base, 12),
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve2, SummaryServe::HoldOverride);
        assert!(matches!(latch2, HoldLatch::Engaged { .. }));
    }

    // ── read_unmined_spend_accounts_conn: the v_transactions safety-gate query ──────────────

    fn setup_v_transactions(conn: &rusqlite::Connection) {
        conn.execute_batch(
            "CREATE TABLE v_transactions (
                account_uuid BLOB,
                mined_height INTEGER,
                spent_note_count INTEGER,
                expired_unmined INTEGER
            );",
        )
        .unwrap();
    }

    fn uuid(n: u8) -> [u8; 16] {
        [n; 16]
    }

    fn insert_tx(
        conn: &rusqlite::Connection,
        acct: [u8; 16],
        mined: Option<i64>,
        spent: i64,
        expired: Option<i64>,
    ) {
        conn.execute(
            "INSERT INTO v_transactions (account_uuid, mined_height, spent_note_count, expired_unmined) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![acct.to_vec(), mined, spent, expired],
        )
        .unwrap();
    }

    #[test]
    fn unmined_unexpired_spend_is_detected() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        setup_v_transactions(&conn);
        insert_tx(&conn, uuid(1), None, 1, Some(0));
        let set = read_unmined_spend_accounts_conn(&conn).unwrap();
        assert_eq!(set, std::collections::HashSet::from([uuid(1)]));
    }

    #[test]
    fn mined_spend_is_ignored() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        setup_v_transactions(&conn);
        insert_tx(&conn, uuid(1), Some(100), 1, Some(0));
        let set = read_unmined_spend_accounts_conn(&conn).unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn unmined_receive_only_is_ignored() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        setup_v_transactions(&conn);
        insert_tx(&conn, uuid(1), None, 0, Some(0));
        let set = read_unmined_spend_accounts_conn(&conn).unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn expired_unmined_spend_is_ignored() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        setup_v_transactions(&conn);
        insert_tx(&conn, uuid(1), None, 1, Some(1));
        let set = read_unmined_spend_accounts_conn(&conn).unwrap();
        assert!(set.is_empty());
    }

    /// M1: a pending unmined spend whose tx has UNKNOWN expiry (`expired_unmined IS NULL`, e.g. an
    /// un-enhanced tx) is a hazard and must be detected — the `= 0` comparison silently dropped
    /// NULL rows, letting such a spend slip the gate.
    #[test]
    fn null_expiry_unmined_spend_is_detected() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        setup_v_transactions(&conn);
        insert_tx(&conn, uuid(1), None, 1, None);
        let set = read_unmined_spend_accounts_conn(&conn).unwrap();
        assert_eq!(set, std::collections::HashSet::from([uuid(1)]));
    }

    #[test]
    fn per_account_only_hazardous_accounts_returned() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        setup_v_transactions(&conn);
        insert_tx(&conn, uuid(1), None, 1, Some(0)); // acct1: unmined spend, unexpired → hazardous
        insert_tx(&conn, uuid(2), Some(50), 1, Some(0)); // acct2: mined → safe
        insert_tx(&conn, uuid(3), None, 0, Some(0)); // acct3: pure receive → safe
        let set = read_unmined_spend_accounts_conn(&conn).unwrap();
        assert_eq!(set, std::collections::HashSet::from([uuid(1)]));
    }
}

#[cfg(test)]
mod slipstream_anchor_retention_tests {
    use super::slipstream_anchor_retention_floor;
    use zcash_protocol::consensus::{Network, NetworkUpgrade, Parameters};
    use zcash_protocol::local_consensus::LocalNetwork;

    /// [B6] The slipstream engine's anchor-retention floor is the NU6.3 activation
    /// height — the exact floor upstream's own `put_blocks` caller passes — so every
    /// drawn boundary anchor a migration pre-signed against stays witnessable. The
    /// handle stores the plain [`Network`], so the floor is exercised on it directly.
    #[test]
    fn floor_is_nu63_activation_on_standard_networks() {
        for network in [Network::MainNetwork, Network::TestNetwork] {
            let expected = network
                .activation_height(NetworkUpgrade::Nu6_3)
                .map(u32::from);
            assert_eq!(slipstream_anchor_retention_floor(&network), expected);
            // The pin must define NU6.3 on both standard networks — a `None` here
            // would silently disable anchor retention and stall scheduled transfers.
            assert!(
                slipstream_anchor_retention_floor(&network).is_some(),
                "NU6.3 activation must be defined for {network:?}"
            );
        }
    }

    /// A network without NU6.3 has nothing to retain for: floor off (`None`),
    /// matching the engine's documented pre-B6 default behavior.
    #[test]
    fn floor_is_none_without_nu63() {
        let no_nu63 = LocalNetwork {
            overwinter: None,
            sapling: None,
            blossom: None,
            heartwood: None,
            canopy: None,
            nu5: None,
            nu6: None,
            nu6_1: None,
            nu6_2: None,
            nu6_3: None,
        };
        assert_eq!(slipstream_anchor_retention_floor(&no_nu63), None);
    }
}

/// Guards the engine-owned view names this crate and the Swift layer hard-code.
///
/// Both read paths fail SILENTLY by design — the recovery-balance read below falls back to
/// an empty map ("zeroes every balance — safe") and Swift's reconcile read swallows a missing
/// view as the legitimate non-engine case. So a view rename in the engine does not surface as
/// an error; it surfaces as zeroed balances and phantom transactions. That is precisely how
/// the pre-`ext_` names survived unnoticed once the engine's `ExtSchemaInit` migration renamed
/// them. These assertions turn the next such rename into a failing test naming the file to fix.
#[cfg(test)]
mod engine_schema_names_tests {
    /// The view `TransactionSQLDAO.unreconciledTxids()` reads from Swift. The engine exports
    /// this name, so bind to it rather than trusting our copy of the string.
    #[test]
    fn reconcile_view_name_matches_the_swift_query() {
        assert_eq!(
            slipstream_core::reconcile::RECONCILE_VIEW_NAME,
            "ext_slipstream_v_tx_reconciled",
            "the engine renamed the reconciliation view; update the query in \
             Sources/ZcashLightClientKit/DAO/TransactionDao.swift to match"
        );
    }

    /// The view `serve_wallet_summary` reads for recovery nets. The engine exports no name
    /// constant for it, so assert against the DDL it does export.
    #[test]
    fn recovery_balance_view_name_matches_our_query() {
        assert!(
            slipstream_core::reconcile::RECOVERY_BALANCE_VIEW_SQL
                .contains("ext_slipstream_v_recovery_balance"),
            "the engine renamed the recovery-balance view; update the query in \
             resolve_recovery_nets to match. Engine DDL: {}",
            slipstream_core::reconcile::RECOVERY_BALANCE_VIEW_SQL
        );
    }
}
