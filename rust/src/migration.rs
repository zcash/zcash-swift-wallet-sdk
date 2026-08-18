//! FFI over the final Orchard→Ironwood pool-migration engine
//! ([`zcash_pool_migration`] + the `zcash_client_sqlite::pool_migration` store).
//!
//! The engine is a set of free functions over traits — upstream's own `wallet::WalletMigration`
//! adapter and `zcash_client_sqlite`'s account-scoped store implement them, wired to this SDK's
//! wallet database by [`crate::migration_engine`]'s two constructors
//! ([`account_migration`] for the calls that need a backend and viewing key,
//! [`account_store`] for the ones that are purely store operations);
//! [`crate::migration_finalize`] proves transactions as soon as they become provable (ZIP 374
//! deferred anchors/witnesses, resolved through the upstream prover — transfers against their
//! drawn ZIP 318 boundary anchor, preparations against the wallet's scanned tip; see its module
//! doc), driven by [`zcashlc_migration_prove_transactions`] rather than by the broadcast path;
//! [`crate::migration_plan_cache`] carries the previewed plan from propose to commit.
//! This module keeps the platform-facing C ABI of the v1 integration: the same entry points, the
//! same `#[repr(C)]` DTOs, the same sentinels — the engine swap is absorbed here, with two
//! deliberate exceptions (the external-signer note-split pair went plural, because the engine
//! builds N preparation transactions rather than one split transaction).
//!
//! Semantics that moved into this layer (the v1 crate did them internally):
//! - There is NO derived state machine anymore: [`zcashlc_migration_advance_step`] drives the
//!   engine's public `advance_migration` API and marshals its answer into the stable FFI shape.
//!   `Complete` is
//!   PER-RUN — "the stored run is fully mined (or terminal)", never "nothing left to migrate".
//!   After completion the platform asks `zcashlc_migration_propose_transfers` whether anything
//!   remains (an empty schedule means no).
//! - Mined-ness is DERIVED, never reported: this layer never marks a transaction mined. The
//!   engine promotes every in-flight transaction its scan has seen mine, inside
//!   `advance_migration` — including one whose broadcast THIS process failed to record, which it
//!   identifies by the id stored on the row. The read-only entry points ask the same question
//!   through [`reconcile_mined`], so a standalone read is not answered from a state the scan has
//!   already moved past.
//! - Node rejection is recorded as testimony via `report_broadcast_failure`; the sqlite-backed
//!   satisfiability oracle adjudicates it after sufficient scanning and independently discovers
//!   scan-visible spends. The SDK makes no invalidity determination of its own: it has no way to
//!   date a verdict against the scanned region, so a reorg could never withdraw one. (Earlier
//!   versions kept an SDK-owned `ext_zcashlc_orchard_ironwood_migration_invalid_marks` side table
//!   the engine could not consult; [`migrate_legacy_invalid_marks`] folds any surviving rows into
//!   the engine state once, on open, and drops the table.)
//! - The immediate lane (an ordinary send-max sweep, entirely outside the engine) is tracked in
//!   its own SDK-owned `sdk_immediate_runs` side table and surfaces ONLY through
//!   [`zcashlc_migration_progress`]: while unmined it reports a 0-of-1 progress snapshot (flagged
//!   `is_immediate`); once mined or expired it reports nothing. See that function's contract.
//!
//! Consent contract: plan details never cross the FFI boundary inward. Each propose/prepare call
//! caches its plan under an opaque [`migration_plan_cache::PlanHandle`] (returned to the platform
//! as the proposal DTO's `proposal_handle` field, `0` reserved for "no cached plan"), and the
//! commit functions take ONLY that handle back — `commit_or_resume`/`migration_plan_cache` then
//! sign exactly the identified plan, or fail with `MIGRATION_PLAN_STALE` when it is missing
//! (process restart) or superseded (a later propose replaced what the platform displayed). This
//! replaces the earlier "verified consent echo" (F4) contract, which had the platform echo the
//! displayed schedule fields back for comparison against a byte-for-byte reproduction of the
//! preview DTO; the handle identifies the plan object itself, covering every field (including
//! ones the DTO never displayed) with none of the echo path's reproduce-exactly bookkeeping.
//!
//! Error channel: failures land in the thread-local last-error message. Three stable prefixes let
//! the Swift layer surface dedicated errors: `MIGRATION_PLAN_STALE:` (commit whose handle does
//! not identify the currently cached proposal — re-propose), `MIGRATION_PROVING_UNAVAILABLE:`
//! (proving failed hard), and `MIGRATION_WAKEUP_INFEASIBLE:<id>` (a stored transfer admits no
//! valid sync wake-up height — see [`zcashlc_migration_sync_wakeups`]). Pointer-returning
//! functions yield NULL on error, `bool`-returning functions `false`, and the `i64` sentinels are
//! documented per function.
//!
//! Heap ownership: every function that returns a `*mut Ffi*` (or a [`crate::ffi::BoxedSlice`])
//! transfers ownership to the caller, who must free it with the matching
//! `zcashlc_free_migration_*` (or `zcashlc_free_boxed_slice`) function.

use std::collections::HashSet;
use std::ffi::{CStr, CString, OsStr};
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::slice;

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
use orchard::keys::SpendingKey;
use rand::rngs::OsRng;
use rusqlite::{Connection, OptionalExtension};
use zcash_client_backend::data_api::wallet::{
    TargetHeight,
    input_selection::{LockFilter, LockedInputPolicy},
};
use zcash_client_backend::data_api::{InputSource, OutputLockStore, WalletRead};
use zcash_client_backend::wallet::{LockOwner, OutputRef};
use zcash_client_sqlite::AccountUuid;
use zcash_client_sqlite::pool_migration::orchard_ironwood::{
    Error as PoolMigrationStoreError, PoolMigrations,
};
use zcash_client_sqlite::util::SystemClock;
use zcash_protocol::consensus::{
    BLOCKS_PER_HOUR, BlockHeight, Network, NetworkUpgrade, Parameters,
};
use zcash_protocol::value::Zatoshis;
use zcash_protocol::{PoolType, ShieldedPool, TxId};

use zcash_pool_migration::engine::{
    self, MigrationBackend, MigrationPlan, MigrationState, MigrationTransaction,
    MigrationTransferId, MigrationTxKind, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
};
use zcash_pool_migration::satisfiability::{
    Advance, AdvanceConfig, DuenessTargets, ReorgSettleDepth, ReplanThreshold, UnsatisfiableKind,
    advance_migration,
};
use zcash_pool_migration::scheduling::{WakeupParams, WakeupScheduleError};
use zcash_pool_migration::signing_rounds::{
    NextFit, PREPARATION_ACTIONS, PlannedTx, SigningRoundBudget, SigningRoundStrategy,
    TRANSFER_ACTIONS, action_weight,
};
use zcash_pool_migration::state::{
    AdvanceStep, Blocker, NextAction, ProveTarget, StepKind, TransactionStatus,
};
use zcash_pool_migration::wallet::WalletMigrationProver;

use crate::migration_engine::{
    AdapterError, MigrationWallet, account_migration, account_store, stored_orchard_fvk,
};
use crate::migration_finalize;
use crate::migration_plan_cache;
use crate::{
    NETWORK_ID_MAINNET, NETWORK_ID_TESTNET, NetworkParams, account_uuid_from_bytes,
    free_ptr_from_vec, free_ptr_from_vec_with, parse_network, ptr_from_vec, unwrap_exc_or,
    unwrap_exc_or_null, zcashlc_string_free,
};

// ----- error / value marshaling -----

/// The stable prefix the Swift layer maps to `ZcashError.migrationPlanStale` (ZRUST0128).
const PLAN_STALE_PREFIX: &str = "MIGRATION_PLAN_STALE";
/// The stable prefix the Swift layer maps to `ZcashError.migrationProvingUnavailable` (ZRUST0127).
const PROVING_UNAVAILABLE_PREFIX: &str = "MIGRATION_PROVING_UNAVAILABLE";

/// A commit was requested without a matching previewed plan (process restart between propose and
/// confirm, or the wallet changed underneath the preview). The platform re-proposes.
fn plan_stale(detail: &str) -> anyhow::Error {
    anyhow!("{PLAN_STALE_PREFIX}: {detail}")
}

/// Proving a migration transaction failed hard (as opposed to the transient "not witnessable yet"
/// state, which is reported as "nothing due"). Shared with [`crate::migration_finalize`], where
/// the prove dispatch classifies prover failures onto the two lanes.
pub(crate) fn proving_unavailable(detail: impl std::fmt::Display) -> anyhow::Error {
    anyhow!("{PROVING_UNAVAILABLE_PREFIX}: {detail}")
}

/// Classifies a failure of the store's broadcast seam
/// (`PoolMigrations::take_transaction_for_broadcast`, reached from [`serve_for_broadcast`]) onto
/// the delivery lane's error channel.
///
/// The split is the one the pre-drive serve path established, and the Swift layer still routes on
/// it: a stored artifact that cannot be turned into servable bytes right now carries
/// [`PROVING_UNAVAILABLE_PREFIX`] (there, a PCZT that failed to re-parse or to extract), while a
/// question about WHICH row was named — an unknown id, or a row that is not `Proved` — stays bare
/// and reaches the platform as the lane's generic failure. That failure class did not disappear
/// when the seam replaced the hand-rolled parse-and-extract; it simply arrives as
/// `Error::Finalize` now, which additionally covers the spend-finalization and fee stages the
/// seam performs and the old path did not.
///
/// Every other store failure — the database itself, the wallet-side write, a missing account or
/// viewing key, corrupt or unrepresentable stored data — is bare: none of them says anything
/// about whether this transaction's proofs exist.
fn broadcast_seam_error(id: MigrationTransferId, e: PoolMigrationStoreError) -> anyhow::Error {
    let detail = format!(
        "taking migration transaction {} for broadcast failed: {e}",
        u32::from(id)
    );
    if matches!(e, PoolMigrationStoreError::Finalize(_)) {
        proving_unavailable(detail)
    } else {
        anyhow!(detail)
    }
}

/// The stable prefix the Swift layer maps to a typed "sync wake-up schedule infeasible" error
/// carrying the offending transfer id. Unlike the sibling prefixes the id follows the colon
/// DIRECTLY (no space, no prose) so the Swift side can parse it back out:
/// `MIGRATION_WAKEUP_INFEASIBLE:<id>`.
const WAKEUP_INFEASIBLE_PREFIX: &str = "MIGRATION_WAKEUP_INFEASIBLE";

/// A stored transfer admits no valid sync wake-up height (its broadcast height is not at least two
/// blocks above its anchor boundary) — an inconsistent stored schedule, surfaced as a typed error
/// naming the transfer (see [`zcashlc_migration_sync_wakeups`]).
fn wakeup_infeasible(id: MigrationTransferId) -> anyhow::Error {
    anyhow!("{WAKEUP_INFEASIBLE_PREFIX}:{}", u32::from(id))
}

/// A spendable-value amount as a signed 64-bit integer (zatoshi). Every migration amount is a
/// valid [`Zatoshis`] (`<= MAX_MONEY`, ~2.1e15), well within `i64`.
fn zat_to_i64(z: Zatoshis) -> i64 {
    u64::from(z) as i64
}

/// An optional block height as an `i64`, with `-1` standing for "none".
fn height_opt_to_i64(h: Option<BlockHeight>) -> i64 {
    h.map_or(-1, |h| i64::from(u32::from(h)))
}

/// A count as a `u32`, erroring (rather than truncating) on overflow. The engine's per-run counts
/// (crossings, layers, transactions) are bounded by the note cap, so overflow never happens in
/// practice; this keeps the marshaling honest anyway.
fn count_to_u32(v: usize, what: &str) -> anyhow::Result<u32> {
    u32::try_from(v).map_err(|_| anyhow!("{what} count {v} exceeds u32"))
}

/// Borrow an FFI array as a slice, tolerating a null pointer when `len == 0` (calling
/// `slice::from_raw_parts` with a null pointer is undefined behaviour even for a zero length).
///
/// # Safety
/// When `len > 0`, `ptr` must be non-null and valid for reads of `len` elements of `T`.
unsafe fn slice_or_empty<'a, T>(ptr: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(ptr, len) }
    }
}

/// The engine's target height for a given chain tip: `tip + 1`, the height of the next block.
/// Every [`MigrationState`] query (`transaction_statuses`, `expired_transactions`, and the
/// drive's own `advance_migration`) is defined over this height, never the raw tip — see
/// [`CallCtx::target`], the primary way callers reach this from a live wallet handle. Exposed as
/// a pure function too for the callers (like the estimated-tip due-ness split) that already hold
/// a `tip` value rather than a [`CallCtx`].
fn target_from_tip(tip: BlockHeight) -> BlockHeight {
    BlockHeight::from(u32::from(tip) + 1)
}

/// The common per-call context: the network parameters, the wallet handle, the migration-store
/// connection (a second, independent connection to the same wallet database file — the
/// account-keyed migration tables live inside it), and the raw path/account for the plan cache.
struct CallCtx {
    network: NetworkParams,
    wallet: MigrationWallet,
    store_conn: Connection,
    db_path: PathBuf,
    account: AccountUuid,
    account_bytes: [u8; 16],
}

/// Open the migration store connection: a second, independent connection into the same wallet
/// database file as the wallet handle (`crate::wallet_db`), which the account-keyed migration
/// tables live inside. Set to the same [`crate::WALLET_DB_BUSY_TIMEOUT`] the wallet handle uses --
/// the slipstream engine's writer (write-behind commits, `deleteAccount`/`importAccount` mid-pass)
/// can hold the file lock for seconds, and a migration call racing it must wait as long as the
/// wallet handle would rather than failing fast on rusqlite's 5 s default.
fn open_store_conn(db_path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open(db_path)
        .map_err(|e| anyhow!("Error opening migration store connection: {e}"))?;
    conn.busy_timeout(crate::WALLET_DB_BUSY_TIMEOUT)
        .map_err(|e| anyhow!("Error setting migration store busy_timeout: {e}"))?;
    Ok(conn)
}

/// Read-only twin of [`open_store_conn`]: same busy_timeout, but the connection can neither
/// write nor create the database file. This is the Q2-1 enforcement layer — the pure read
/// entry points open through this, so an accidental write anywhere down their call graph
/// fails loudly with `SQLITE_READONLY` instead of silently reclassifying the call.
fn open_store_conn_read_only(db_path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open_with_flags(
        db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| anyhow!("Error opening read-only migration store connection: {e}"))?;
    conn.busy_timeout(crate::WALLET_DB_BUSY_TIMEOUT)
        .map_err(|e| anyhow!("Error setting read-only migration store busy_timeout: {e}"))?;
    Ok(conn)
}

/// Read-only twin of [`crate::wallet_db`] (lib.rs): open + array vtab + wrap, with
/// `SQLITE_OPEN_READ_ONLY` so the wallet handle cannot write either. The vtab module load is
/// connection-local registration, not a database write.
unsafe fn wallet_db_read_only(
    db_data: *const u8,
    db_data_len: usize,
    network: NetworkParams,
) -> anyhow::Result<MigrationWallet> {
    let db_data = Path::new(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(db_data, db_data_len)
    }));
    let conn = Connection::open_with_flags(
        db_data,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| anyhow!("Error opening read-only wallet database connection: {e}"))?;
    conn.busy_timeout(crate::WALLET_DB_BUSY_TIMEOUT)
        .map_err(|e| anyhow!("Error setting read-only wallet database busy_timeout: {e}"))?;
    rusqlite::vtab::array::load_module(&conn)
        .map_err(|e| anyhow!("Error loading wallet database array module: {e}"))?;
    Ok(
        MigrationWallet::from_connection(conn, network, SystemClock, OsRng)
            .with_anchor_retention_interval(crate::anchor_retention_interval(network)),
    )
}

/// Open the per-call context from the common FFI arguments. Every entry point calls this fresh and
/// drops it at the end (no persistent handle). All tables are created by the wallet schema
/// migrations during `init_data_db`: the engine's store tables by `zcash_client_sqlite`'s own
/// migration graph (`zcash_client_sqlite::pool_migration` registers them), and the SDK's extension
/// tables by the external migrations in [`crate::ext_schema`].
///
/// # Safety
/// - `db_data` must be valid for reads of `db_data_len` bytes and encode a filesystem path.
/// - `account_uuid_bytes` must be valid for reads of 16 bytes.
unsafe fn open(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> anyhow::Result<CallCtx> {
    let network = parse_network(network_id)?;
    let db_path = PathBuf::from(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(db_data, db_data_len)
    }));
    let wallet = unsafe { crate::wallet_db(db_data, db_data_len, network.clone())? };
    let mut store_conn = open_store_conn(&db_path)?;
    init_immediate_runs(&store_conn)
        .map_err(|e| anyhow!("Error initializing immediate-run table: {e}"))?;
    // One-time: fold any legacy invalid-marks rows into the engine state and drop their table
    // (a no-op existence probe once done — see the function's doc).
    let fully_scanned_height = wallet
        .block_fully_scanned()
        .map_err(|e| anyhow!("Error reading fully-scanned height: {e}"))?
        .map(|metadata| metadata.block_height())
        .unwrap_or(BlockHeight::from(0));
    migrate_legacy_invalid_marks(&mut store_conn, network, fully_scanned_height)?;
    let account = account_uuid_from_bytes(account_uuid_bytes)
        .map_err(|e| anyhow!("account uuid must be 16 bytes: {e}"))?;
    let account_bytes = *account.expose_uuid().as_bytes();
    Ok(CallCtx {
        network,
        wallet,
        store_conn,
        db_path,
        account,
        account_bytes,
    })
}

/// Read-only twin of [`open`]: both connections opened `SQLITE_OPEN_READ_ONLY`, and the two
/// preamble writers deliberately skipped — `init_immediate_runs` (its table is created by any
/// rw migration call; pure readers tolerate its absence via
/// [`immediate_run_row_if_table_exists`]) and `migrate_legacy_invalid_marks` (a one-time fold
/// only rw callers may perform). The pure read entry points open through this; see
/// `open_store_conn_read_only` for what that enforces.
///
/// # Safety
/// Same contract as [`open`].
unsafe fn open_read(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> anyhow::Result<CallCtx> {
    let network = parse_network(network_id)?;
    let db_path = PathBuf::from(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(db_data, db_data_len)
    }));
    let wallet = unsafe { wallet_db_read_only(db_data, db_data_len, network.clone())? };
    let store_conn = open_store_conn_read_only(&db_path)?;
    let account = account_uuid_from_bytes(account_uuid_bytes)
        .map_err(|e| anyhow!("account uuid must be 16 bytes: {e}"))?;
    let account_bytes = *account.expose_uuid().as_bytes();
    Ok(CallCtx {
        network,
        wallet,
        store_conn,
        db_path,
        account,
        account_bytes,
    })
}

impl CallCtx {
    /// The wallet's current chain tip.
    fn tip(&self) -> anyhow::Result<BlockHeight> {
        self.wallet
            .chain_height()
            .map_err(|e| anyhow!("chain height lookup failed: {e}"))?
            .ok_or_else(|| anyhow!("the wallet has no chain tip yet; sync first"))
    }

    /// The engine's target height (`tip + 1`; see [`target_from_tip`]): a transaction may be
    /// mined only in a block at or below its expiry (ZIP 203), so it first becomes un-mineable in
    /// the NEXT block once the tip reaches its expiry height, and a scheduled transaction first
    /// becomes due once the NEXT block reaches its scheduled height. Every call that feeds a
    /// [`MigrationState`] query (`transaction_statuses`, `expired_transactions`,
    /// `commit_preparation`, `build_preparation_unsigned`, and the drive's own
    /// `advance_migration`) must use this, never `tip()` directly.
    /// SDK-owned, tip-based policy (the immediate lane's fallback expiry bound, display-only "now"
    /// references) keeps using `tip()`.
    fn target(&self) -> anyhow::Result<BlockHeight> {
        Ok(target_from_tip(self.tip()?))
    }
}

// ----- one-time legacy invalid-marks migration -----
//
// Terminal rejection classifications used to live in an SDK-owned
// `ext_zcashlc_orchard_ironwood_migration_invalid_marks` extension table, because the engine had
// no failure states. The engine now records rejection evidence as a broadcast failure and
// determines whether a transaction is unsatisfiable when the migration is advanced. The helper
// below replays surviving rejection rows, discards funding-spent rows for the oracle to
// rediscover, and drops the table; fresh wallets never create it (its
// `schemerz` migration is no longer registered — see [`crate::ext_schema`]).

/// The legacy marks table's name. Only the one-time migration below refers to it now.
const LEGACY_INVALID_MARKS_TABLE: &str = "ext_zcashlc_orchard_ironwood_migration_invalid_marks";

/// Folds any surviving legacy invalid-marks rows into the engine state and drops the table.
/// Runs at the head of [`open`] (the path that previously consulted the table), so it happens
/// before the calling entry point reads the migration state. Idempotent: the first successful
/// pass drops the table, so the cheap existence probe is all a second open pays.
///
/// The table is keyed by account, and one pass migrates EVERY account's rows (an `open` for
/// account A must not strand — or worse, drop — account B's evidence). Per account:
/// - no `accounts` row (the account was deleted): its run was cascade-deleted with it, so there
///   is nothing to carry the evidence onto — the rows drop with the table;
/// - no stored run, or a TERMINAL one: skipped. A terminal run surfaces no attention anyway
///   (`next_step` answers `Complete` and `zcashlc_migration_has_invalid_transfers` answers
///   `false` for it), so carrying stale verdicts onto its rows would change nothing observable;
/// - `funding_spent` rows are discarded for the satisfiability oracle to rediscover;
/// - other rejection rows are replayed with `report_broadcast_failure` at the current scanned
///   height. Unknown and already-mined transactions remain unchanged.
///
/// Runs on the SDK's own store connection: the extension-transaction API's authorizer denies
/// DDL, so the final `DROP TABLE` could never go through it — and the table being dropped is the
/// SDK's own, in the namespace the wallet promises never to touch.
fn migrate_legacy_invalid_marks(
    conn: &mut Connection,
    network: NetworkParams,
    fully_scanned_height: BlockHeight,
) -> anyhow::Result<()> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            rusqlite::params![LEGACY_INVALID_MARKS_TABLE],
            |row| row.get(0),
        )
        .map_err(|e| anyhow!("legacy marks probe failed: {e}"))?;
    if !exists {
        return Ok(());
    }

    // All rows, grouped per account (BTreeMap for a deterministic account order). A row whose
    // account_uuid blob is not 16 bytes cannot name an account and is dropped with the table.
    let rows: Vec<(Vec<u8>, u32, String)> = {
        let mut stmt = conn
            .prepare(&format!(
                "SELECT account_uuid, tx_id, reason FROM {LEGACY_INVALID_MARKS_TABLE}"
            ))
            .map_err(|e| anyhow!("legacy marks read failed: {e}"))?;
        let mapped = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|e| anyhow!("legacy marks read failed: {e}"))?;
        mapped
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow!("legacy marks read failed: {e}"))?
    };
    let mut per_account: std::collections::BTreeMap<[u8; 16], Vec<(u32, String)>> =
        std::collections::BTreeMap::new();
    for (account_bytes, tx_id, reason) in rows {
        let Ok(account) = <[u8; 16]>::try_from(account_bytes) else {
            continue;
        };
        per_account
            .entry(account)
            .or_default()
            .push((tx_id, reason));
    }

    for (account_bytes, marks) in per_account {
        let account = AccountUuid::from_uuid(uuid::Uuid::from_bytes(account_bytes));
        let mut store = match PoolMigrations::for_account(network, SystemClock, &mut *conn, account)
        {
            Ok(store) => store,
            Err(PoolMigrationStoreError::AccountUnknown) => continue,
            Err(e) => return Err(anyhow!("legacy marks: store open failed: {e}")),
        };
        let Some(mut state) = store
            .get_migration()
            .map_err(|e| anyhow!("legacy marks: migration read failed: {e}"))?
        else {
            continue;
        };
        if state.is_terminal() {
            continue;
        }
        for (tx_id, reason) in marks {
            // Scan-discovered spends are deliberately dropped: the sqlite oracle rediscovers
            // them with a correct evidence height on the next drive call.
            if matches!(reason.as_str(), "foreign_spent" | "funding_spent") {
                continue;
            }
            let id = MigrationTransferId::new(tx_id);
            state.report_broadcast_failure(id, fully_scanned_height);
        }
        store
            .replace_migration(&state)
            .map_err(|e| anyhow!("legacy marks: migration persist failed: {e}"))?;
    }

    conn.execute(&format!("DROP TABLE {LEGACY_INVALID_MARKS_TABLE}"), [])
        .map_err(|e| anyhow!("legacy marks drop failed: {e}"))?;
    Ok(())
}

// ----- SDK-owned immediate-migration-run record -----
//
// The immediate lane (an ordinary send-max sweep to the account's own unified address, built
// entirely outside the engine — see `zcashlc_propose_send_max_transfer`) has no engine-tracked
// plan, preparation, or schedule at all: from the engine's point of view nothing happened. This
// one-row-per-account table is the SDK's own record that a sweep was broadcast, so
// `zcashlc_migration_progress` can still report its progress the way an engine-tracked transfer
// would: the stored txid is resolved against the wallet database's own transaction history by
// `resolve_immediate_run` (mined or expired -> no progress, unmined -> pending 0 of 1) — the same
// kind of wallet-DB access `reconcile_mined` uses to advance an engine-tracked transaction from
// `Broadcast` to `Mined`, here extended to also read the expiry height that `WalletRead` does not
// expose on its own. See `zcashlc_migration_progress`'s contract for how this interacts with an
// engine-tracked run (an active engine run always wins; a terminal or absent one defers here).

fn init_immediate_runs(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sdk_immediate_runs (
            account_uuid BLOB NOT NULL PRIMARY KEY,
            txid BLOB NOT NULL,
            recorded_at_height INTEGER NOT NULL
        )",
    )
}

/// One stored immediate-run record: the account's swept txid and the wallet's tip height at
/// record time (the fallback expiry bound [`ImmediateRunLookup::expiry_bound`] uses when the
/// wallet database does not know, or no longer knows, the transaction's real expiry height).
struct ImmediateRunRow {
    txid: [u8; 32],
    recorded_at_height: BlockHeight,
}

/// Persists the account's immediate-run record, replacing any previous one: only the most
/// recently broadcast immediate sweep is ever tracked (one row per account).
fn record_immediate_run(
    conn: &Connection,
    account: &[u8; 16],
    txid: [u8; 32],
    recorded_at_height: BlockHeight,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO sdk_immediate_runs (account_uuid, txid, recorded_at_height)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![&account[..], &txid[..], u32::from(recorded_at_height)],
    )?;
    Ok(())
}

/// The account's raw immediate-run row, if any. Cheap (touches only this SDK-owned table), so
/// callers can check for a row's existence before paying for a wallet-database chain-tip lookup
/// (which errors on a not-yet-synced wallet — see the caller in `zcashlc_migration_progress`).
fn immediate_run_row(
    conn: &Connection,
    account: &[u8; 16],
) -> rusqlite::Result<Option<ImmediateRunRow>> {
    conn.query_row(
        "SELECT txid, recorded_at_height FROM sdk_immediate_runs WHERE account_uuid = ?1",
        rusqlite::params![&account[..]],
        |row| {
            Ok(ImmediateRunRow {
                txid: row.get(0)?,
                recorded_at_height: BlockHeight::from(row.get::<_, u32>(1)?),
            })
        },
    )
    .optional()
}

/// [`immediate_run_row`] for the READ-ONLY paths: `sdk_immediate_runs` is created lazily by the
/// rw [`open`], so a wallet whose migration surface has only ever been READ (fresh install,
/// UI-before-first-drive) legitimately lacks the table — that is the "no immediate run recorded"
/// answer, not an error.
fn immediate_run_row_if_table_exists(
    conn: &Connection,
    account: &[u8; 16],
) -> rusqlite::Result<Option<ImmediateRunRow>> {
    match immediate_run_row(conn, account) {
        Err(rusqlite::Error::SqliteFailure(e, Some(ref msg)))
            if msg.contains("no such table: sdk_immediate_runs") =>
        {
            let _ = e;
            Ok(None)
        }
        other => other,
    }
}

/// Resolves an immediate-run row against the wallet database's own `transactions` table: the same
/// underlying table [`reconcile_mined`] reads (via `WalletRead::get_tx_height`) to advance
/// engine-tracked transactions from `Broadcast` to `Mined`, queried directly here because
/// `WalletRead` does not expose the expiry height the immediate-run derivation also needs. A
/// mined height beyond the current tip is filtered out (a stale/optimistic row), mirroring
/// `zcash_client_sqlite::wallet::get_tx_height`'s own guard; an `expiry_height` of exactly zero
/// (the wire convention for "no real expiry") is treated the same as a missing one, so it falls
/// back to the recorded-height bound below rather than reading as "expired since block zero".
fn resolve_immediate_run(
    conn: &Connection,
    row: ImmediateRunRow,
    tip: BlockHeight,
) -> rusqlite::Result<ImmediateRunLookup> {
    let found = conn
        .query_row(
            "SELECT mined_height, expiry_height FROM transactions WHERE txid = ?1",
            rusqlite::params![&row.txid[..]],
            |r| {
                let mined: Option<u32> = r.get(0)?;
                let expiry: Option<u32> = r.get(1)?;
                Ok((mined.map(BlockHeight::from), expiry.map(BlockHeight::from)))
            },
        )
        .optional()?;
    let (mined_height, expiry_height) = found.unwrap_or((None, None));
    Ok(ImmediateRunLookup {
        recorded_at_height: row.recorded_at_height,
        mined_height: mined_height.filter(|h| *h <= tip),
        expiry_height: expiry_height.filter(|h| u32::from(*h) > 0),
    })
}

// ----- reconciliation, planning, committing -----

/// Loads the stored run — TERMINAL RUNS INCLUDED, via the store's own `latest_migration`, since
/// upstream's `get_migration` went pending-only and the reads built on this must keep serving a
/// completed, failed, or cancelled run (progress, statuses, history) — with its `Broadcast`
/// transactions promoted to `Mined` wherever the wallet's scan has since seen them, persisting
/// once if anything changed. `None` means no migration was ever stored.
///
/// The promotion itself is the ENGINE's — [`PoolMigrationRead::mined_height`], the same query
/// `advance_migration` sweeps with, bounded by the wallet's fully-scanned height rather than by
/// the chain tip `WalletRead::get_tx_height` uses. What remains SDK-side is only WHEN to ask: the
/// drive path gets the promotion inside `advance_migration` and does not call this, while the
/// read-only entry points (progress, statuses, the delivery queries) run it so a standalone read
/// is not answered from a state the wallet's own scan has already moved past.
fn reconcile_mined(ctx: &mut CallCtx) -> anyhow::Result<Option<MigrationState>> {
    let mut store = account_store(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
    let Some(mut state) = store
        .latest_migration()
        .map_err(|e| anyhow!("migration store read failed: {e}"))?
    else {
        return Ok(None);
    };
    if state.is_terminal() {
        return Ok(Some(state));
    }
    let broadcast: Vec<(MigrationTransferId, TxId)> = state
        .transactions()
        .iter()
        .filter_map(|t| match t.state() {
            MigrationTxState::Broadcast { txid } => Some((t.id(), txid)),
            _ => None,
        })
        .collect();
    let mut changed = false;
    for (id, txid) in broadcast {
        if let Some(height) = store
            .mined_height(txid)
            .map_err(|e| anyhow!("mined-height lookup failed: {e}"))?
        {
            state.mark_mined(id, height);
            changed = true;
        }
    }
    if changed {
        store
            .replace_migration(&state)
            .map_err(|e| anyhow!("migration store write failed: {e}"))?;
    }
    Ok(Some(state))
}

/// Computes a fresh preview plan against the account's live balance and caches it under a fresh
/// [`migration_plan_cache::PlanHandle`] (a later commit echoes the handle back and signs exactly
/// this plan, not an independently re-randomized one). `immediate` records that the preview came
/// through the immediate lane, so the commit rewrites the transfer schedule to "all due at once".
///
/// Returns the plan alongside the tip at plan time (the "now" reference the schedule encoders
/// stamp into `FfiTransferProposal::anchor_height` and measure durations from) and the handle
/// that now identifies the cached plan.
///
/// Returns `Ok(None)` when there is nothing to migrate (the balance is zero, or entirely below the
/// dust floor) — the "ask rust whether anything remains" answer after a completed run.
fn plan_and_cache(
    ctx: &mut CallCtx,
    immediate: bool,
) -> anyhow::Result<Option<(MigrationPlan, BlockHeight, migration_plan_cache::PlanHandle)>> {
    match compute_plan(ctx)? {
        Some((plan, reference_height)) => {
            let handle = migration_plan_cache::set(
                ctx.db_path.clone(),
                ctx.account_bytes,
                plan.clone(),
                immediate,
            );
            Ok(Some((plan, reference_height, handle)))
        }
        None => Ok(None),
    }
}

/// Computes a fresh preview plan WITHOUT caching it — the read-only building block behind
/// [`plan_and_cache`], used directly by pure peek queries (`zcashlc_migration_is_note_split_needed`,
/// `zcashlc_migration_residual_after_migration`'s pre-commit branch) that must NOT cache:
/// replacing the cached plan would invalidate the handle of a proposal the user is currently
/// reviewing, failing its later commit with `MIGRATION_PLAN_STALE` for no user-visible reason.
fn compute_plan(ctx: &mut CallCtx) -> anyhow::Result<Option<(MigrationPlan, BlockHeight)>> {
    let backend = account_migration(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
    let mut rng = OsRng;
    match engine::plan_migration(&ctx.network, &backend, &mut rng) {
        Ok(plan) => {
            // `plan_migration` itself just resolved the tip internally (`chain_tip_height`) to
            // plan against, so this can't newly fail here; it just makes the same value available
            // to every caller that encodes from the plan.
            let reference_height = ctx.tip()?;
            Ok(Some((plan, reference_height)))
        }
        Err(engine::MigrationError::NothingToMigrate) => Ok(None),
        Err(e) => Err(anyhow!("Error planning migration: {e}")),
    }
}

/// The row set the platform sees for a plan's transfer schedule: `(engine tx id, crossing amount,
/// broadcast height, expiry height)`, sorted chronologically by broadcast height.
///
/// `planned` is the engine's own enumeration of the run
/// ([`MigrationPlan::planned_transactions`]) — the very rows `commit_preparation` builds from — so
/// each transfer's id and broadcast height are READ off it rather than worked out again here. The
/// id is the ordinal the built transaction will carry (the engine numbers every preparation
/// transaction first, then transfers in crossing order), and `scheduled_height` is the height the
/// commit will stamp on the row, so a previewed timeline and the committed one cannot disagree.
///
/// - Amounts are what each transfer CROSSES, straight from the engine's `crossing_values()`
///   indexed by the row's OWN crossing: index-aligned with `funding_notes()` and with
///   `schedule()`, and already net of the fee buffer that pays each transfer's own fee. Serving
///   the funding note instead would overstate every row by one transfer fee and show a value that
///   is not a round denomination the user approved.
/// - The expiry comes from `schedule()`: it is the one field of a transfer's timeline the
///   enumeration does not publish.
/// - A row carrying no scheduled height (the malformed-plan case the enumeration reports as
///   `None`, which `commit_preparation` likewise refuses to build), or a crossing with no
///   schedule entry or crossing value, is the same invariant-violation error style used elsewhere
///   in this module.
/// - The sort makes the platform's row order chronological: ZIP 318 SHUFFLE deliberately makes
///   funding-note order differ from broadcast order.
fn schedule_rows(
    planned: &[PlannedTx],
    crossing_values: &[Zatoshis],
    schedule: &[zcash_pool_migration::scheduling::Schedule],
) -> anyhow::Result<Vec<(MigrationTransferId, Zatoshis, BlockHeight, BlockHeight)>> {
    if crossing_values.len() != schedule.len() {
        return Err(anyhow!(
            "migration plan invariant violated: {} crossing values but {} schedule entries",
            crossing_values.len(),
            schedule.len()
        ));
    }
    let mut rows = Vec::new();
    for tx in planned {
        let MigrationTxKind::Transfer { crossing } = tx.kind() else {
            continue;
        };
        let amount = *crossing_values.get(crossing).ok_or_else(|| {
            anyhow!("migration plan invariant violated: no crossing value for transfer {crossing}")
        })?;
        let expiry = schedule
            .get(crossing)
            .ok_or_else(|| {
                anyhow!(
                    "migration plan invariant violated: no schedule entry for transfer {crossing}"
                )
            })?
            .expiry_height();
        let broadcast = tx.scheduled_height().ok_or_else(|| {
            anyhow!(
                "migration plan invariant violated: no scheduled height for transfer {crossing}"
            )
        })?;
        rows.push((tx.id(), amount, broadcast, expiry));
    }
    rows.sort_by_key(|(_, _, broadcast, _)| *broadcast);
    Ok(rows)
}

/// The schedule's duration in hours, measured from `now` — the same reference height the
/// encoder stamps into each row's `anchor_height` (`now_reference`) — to the LAST scheduled
/// broadcast (#1806: was the first-to-last broadcast span, which structurally excluded the wait
/// until the first transfer fires). Empty schedule, or every height at/behind `now`, is `0`
/// (saturating, never underflows).
fn estimated_duration_hours(
    broadcast_heights: impl Iterator<Item = BlockHeight>,
    now: BlockHeight,
) -> u32 {
    let now = u32::from(now);
    broadcast_heights
        .map(u32::from)
        .max()
        .map_or(0, |max| max.saturating_sub(now) / BLOCKS_PER_HOUR)
}

/// The number of preparation transactions a plan commits (across all layers). Delegates to the
/// engine's own [`MigrationPlan::preparation_tx_count`], the source of truth the preview's own
/// row count is cross-checked against.
fn prep_tx_count(plan: &MigrationPlan) -> anyhow::Result<u32> {
    count_to_u32(plan.preparation_tx_count(), "preparation transaction count")
}

/// The plan's preparation transactions as schedule-preview rows — the PROPOSE-path derivation,
/// read-only over a not-yet-committed [`MigrationPlan`]. Every field is read off
/// [`MigrationPlan::planned_transactions`], the engine's own enumeration of the run: the STABLE
/// ordinals `zcash_pool_migration::engine::commit_preparation` will assign, each row's
/// `depends_on`, and each row's `scheduled_height`. Nothing here re-derives any of them, which is
/// the point — the enumeration is what the commit itself builds from, so a previewed row and the
/// committed transaction it becomes cannot describe different things. (The dependency rule is
/// therefore the engine's: a layer waits on the WHOLE layer before it, never narrowed to the
/// specific producer(s) its inputs spend.)
///
/// The two invariant violations this can report are the ones the enumeration itself surfaces as
/// absences: a row holding no scheduled height (`None`, unconstructible through the engine's
/// public API and refused by `commit_preparation`), and an emitted count disagreeing with
/// [`prep_tx_count`].
fn preparation_steps_from_plan(
    plan: &MigrationPlan,
) -> anyhow::Result<Vec<FfiMigrationPreparationStep>> {
    // Phase 1: derive every step's plain-data fields, including everything fallible (the
    // scheduled-height read, the final count cross-check below) — no `Vec` is leaked into a
    // raw pointer yet, so an early `?` return here cannot leak one (A15; see
    // `encode_schedule_from_plan`'s caller-side comment for the same discipline one level up).
    let mut rows: Vec<(u32, u32, u32, i64, Vec<u32>)> = Vec::new();
    for tx in plan.planned_transactions() {
        let (layer, index) = match tx.kind() {
            MigrationTxKind::Preparation { layer, index } => (layer, index),
            MigrationTxKind::Transfer { .. } => continue,
        };
        let broadcast_height = tx.scheduled_height().ok_or_else(|| {
            anyhow!(
                "migration plan invariant violated: no scheduled height for preparation \
                 layer {layer} index {index}"
            )
        })?;
        rows.push((
            u32::from(tx.id()),
            layer as u32,
            index as u32,
            i64::from(u32::from(broadcast_height)),
            tx.depends_on().iter().map(|id| u32::from(*id)).collect(),
        ));
    }

    let expected = prep_tx_count(plan)?;
    if rows.len() != expected as usize {
        return Err(anyhow!(
            "migration plan invariant violated: derived {} preparation steps but the plan \
             reports {expected}",
            rows.len()
        ));
    }

    // Phase 2: every remaining step is infallible marshaling, so `ptr_from_vec` (each row's
    // `depends_on`) only ever runs after every `?` above has already succeeded.
    Ok(rows
        .into_iter()
        .map(|(id, layer, index, broadcast_height, depends_on)| {
            let (depends_on, depends_on_len) = ptr_from_vec(depends_on);
            FfiMigrationPreparationStep {
                id,
                layer,
                index,
                broadcast_height,
                depends_on,
                depends_on_len,
            }
        })
        .collect())
}

/// The stored run's preparation transactions as schedule-preview rows — the RE-SERVE-path
/// derivation: every field is already exactly what commit produced, so this is a direct field
/// mapping, no re-derivation (contrast [`preparation_steps_from_plan`]).
fn preparation_steps_from_state(state: &MigrationState) -> Vec<FfiMigrationPreparationStep> {
    state
        .transactions()
        .iter()
        .filter_map(|t| match t.kind() {
            MigrationTxKind::Preparation { layer, index } => {
                let depends_on: Vec<u32> = t.depends_on().iter().map(|id| u32::from(*id)).collect();
                let (depends_on, depends_on_len) = ptr_from_vec(depends_on);
                Some(FfiMigrationPreparationStep {
                    id: u32::from(t.id()),
                    layer: layer as u32,
                    index: index as u32,
                    broadcast_height: i64::from(u32::from(t.scheduled_height())),
                    depends_on,
                    depends_on_len,
                })
            }
            MigrationTxKind::Transfer { .. } => None,
        })
        .collect()
}

/// Marshal a plan into the platform's schedule DTO. `now_reference` (the tip at encode time) fills
/// the DTO's `anchor_height` field: with ZIP 374 the real anchor is drawn per transfer and
/// installed at proving time, so the field now carries the "now" height the platform's duration
/// math measures waits from — it is NOT a commitment-tree anchor.
fn encode_schedule_from_plan(
    plan: &MigrationPlan,
    now_reference: BlockHeight,
    plan_handle: migration_plan_cache::PlanHandle,
) -> anyhow::Result<*mut FfiMigrationSchedule> {
    let rows = schedule_rows(
        &plan.planned_transactions(),
        plan.crossing_values(),
        plan.schedule(),
    )?;
    let transfers = rows
        .into_iter()
        .map(|(id, amount, broadcast, expiry)| {
            Ok(FfiTransferProposal {
                id: u32::from(id),
                amount: zat_to_i64(amount),
                anchor_height: i64::from(u32::from(now_reference)),
                next_executable_after_height: i64::from(u32::from(broadcast)),
                expiry_height: i64::from(u32::from(expiry)),
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let estimated = estimated_duration_hours(
        plan.schedule().iter().map(|e| e.broadcast_height()),
        now_reference,
    );
    // Every fallible step happens BEFORE any Vec is leaked into a raw pointer (A15): once
    // `ptr_from_vec` runs, an early `?` return would leak the leaked-on-purpose heap array, so
    // the preparation rows are computed first and the `?`-free marshaling goes last.
    let preparation_steps = preparation_steps_from_plan(plan)?;
    let (transfers, transfers_len) = ptr_from_vec(transfers);
    let (preparations, preparations_len) = ptr_from_vec(preparation_steps);
    Ok(Box::into_raw(Box::new(FfiMigrationSchedule {
        transfers,
        transfers_len,
        estimated_duration_hours: estimated,
        proposal_handle: plan_handle,
        preparations,
        preparations_len,
    })))
}

/// An empty schedule: the "nothing to migrate" answer (also the post-completion "nothing remains"
/// answer the platform's sequential-run check consumes). Carries the `0` "no plan" handle —
/// nothing was cached, so there is nothing a commit could reference.
fn encode_empty_schedule() -> *mut FfiMigrationSchedule {
    Box::into_raw(Box::new(FfiMigrationSchedule {
        transfers: ptr::null_mut(),
        transfers_len: 0,
        estimated_duration_hours: 0,
        proposal_handle: 0,
        preparations: ptr::null_mut(),
        preparations_len: 0,
    }))
}

// ----- consent gating -----
//
// The commit functions take back ONLY the opaque `proposal_handle` the propose/prepare DTO
// carried (see the module doc's "Consent contract" paragraph and `migration_plan_cache`):
// `commit_or_resume` signs exactly the cached plan the handle identifies, or fails with the
// `MIGRATION_PLAN_STALE:` prefix (the app's existing recovery — re-propose and re-display).

/// The stored run's TRANSFER subset, in engine order.
fn stored_transfers(state: &MigrationState) -> Vec<&MigrationTransaction> {
    state
        .transactions()
        .iter()
        .filter(|t| matches!(t.kind(), MigrationTxKind::Transfer { .. }))
        .collect()
}

/// The schedule-duration estimate derived from STORED transfer rows, in hours, measured from
/// `now` to the LATEST stored `scheduled_height` — the state-side counterpart of
/// [`estimated_duration_hours`], used by the state-encoded schedule DTO
/// ([`encode_schedule_from_state`]) to compute the value the platform displays. Empty, or every
/// height at/behind `now`, is `0` (saturating, never underflows).
fn stored_duration_hours(transfers: &[&MigrationTransaction], now: BlockHeight) -> u32 {
    let now = u32::from(now);
    transfers
        .iter()
        .map(|t| u32::from(t.scheduled_height()))
        .max()
        .map_or(0, |max| max.saturating_sub(now) / BLOCKS_PER_HOUR)
}

/// Marshal the STORED run's full transfer subset into the platform's schedule DTO — the
/// post-commit counterpart of [`encode_schedule_from_plan`], read from persisted state instead of
/// a previewed plan. Every transfer of the run is included (mined ones too — this DTO is what the
/// host re-displays), sorted chronologically by stored scheduled height; `anchor_height` carries
/// the same display-only "now" reference as the plan-side encoding, and the duration is derived
/// from `now_reference` and the stored scheduled heights via [`stored_duration_hours`] —
/// re-serving later naturally reports a smaller duration; that is intended (see
/// [`stored_duration_hours`]'s doc). The DTO carries the `0` "no plan" handle: this schedule is
/// backed by durable, already-committed state, not by a cached proposal, and the commit-shaped
/// calls resume that stored state without consulting a handle.
fn encode_schedule_from_state(
    state: &MigrationState,
    now_reference: BlockHeight,
) -> anyhow::Result<*mut FfiMigrationSchedule> {
    let mut transfers = stored_transfers(state);
    let estimated = stored_duration_hours(&transfers, now_reference);
    transfers.sort_by_key(|t| t.scheduled_height());
    let rows = transfers
        .into_iter()
        .map(|t| {
            let amount = transfer_amount(state, t)
                .ok_or_else(|| anyhow!("stored transfer has no funding-note amount"))?;
            Ok(FfiTransferProposal {
                id: u32::from(t.id()),
                amount: zat_to_i64(amount),
                anchor_height: i64::from(u32::from(now_reference)),
                next_executable_after_height: i64::from(u32::from(t.scheduled_height())),
                expiry_height: i64::from(u32::from(t.expiry_height())),
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let (transfers, transfers_len) = ptr_from_vec(rows);
    let (preparations, preparations_len) = ptr_from_vec(preparation_steps_from_state(state));
    Ok(Box::into_raw(Box::new(FfiMigrationSchedule {
        transfers,
        transfers_len,
        estimated_duration_hours: estimated,
        proposal_handle: 0,
        preparations,
        preparations_len,
    })))
}

/// Returns the already-committed migration state if a non-terminal one exists (resume — never
/// rebuild over pre-signed, possibly broadcast transactions), otherwise commits the cached plan
/// that `plan_handle` identifies — erroring with the `MIGRATION_PLAN_STALE:` prefix when no plan
/// is cached (process restart between propose and confirm) or when a later propose/prepare call
/// superseded the plan the platform displayed (see `migration_plan_cache`: the handle gate is
/// what guarantees a commit can only sign the exact plan the user reviewed). On the resume path
/// the handle is not consulted: the commitment already happened — with a handle-verified plan —
/// and is durable, so there is nothing left the handle could protect. `unsigned_out` picks the
/// `build_preparation_unsigned` / `commit_preparation` variant; `sk` is the account's Orchard
/// spending key, required by (and live only for) the second — the engine derives its full viewing
/// key and checks it against the account's before building anything, so a foreign key is refused
/// as [`engine::CommitError::WrongSpendAuthority`] rather than silently signing nothing. A
/// terminal stored run (a completed or cancelled previous migration) is REPLACED — that is the
/// sequential-runs path. When the cached preview came through the immediate lane, the committed
/// transfers' scheduled heights are rewritten to the commit tip (everything due at once;
/// preparation mining order still gates transfers via their dependencies).
fn commit_or_resume(
    ctx: &mut CallCtx,
    sk: Option<&SpendingKey>,
    unsigned_out: bool,
    plan_handle: migration_plan_cache::PlanHandle,
) -> anyhow::Result<(MigrationState, Vec<(MigrationTransferId, Vec<u8>, u32)>)> {
    {
        let store = account_store(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
        if let Some(state) = store
            .get_migration()
            .map_err(|e| anyhow!("migration store read failed: {e}"))?
        {
            if !state.is_terminal() {
                // Re-serve path: the row's own kind carries its action weight (the same weight
                // the plan's now-consumed signing-rounds preview used), never re-derived from the
                // PCZT bytes.
                let unsigned = state
                    .transactions()
                    .iter()
                    .filter(|t| matches!(t.state(), MigrationTxState::AwaitingSignature))
                    .map(|t| (t.id(), t.pczt().clone(), action_weight(t.kind())))
                    .collect();
                return Ok((state, unsigned));
            }
        }
    }

    let cached = migration_plan_cache::get(&ctx.db_path, ctx.account_bytes, plan_handle)
        .map_err(|e| plan_stale(&e.to_string()))?;

    let target = ctx.target()?;
    let mut rng = OsRng;
    let mut backend = account_migration(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
    let (state, unsigned) = if unsigned_out {
        let (state, unsigned) = engine::build_preparation_unsigned(
            &ctx.network,
            target,
            &mut backend,
            &cached.plan,
            &mut rng,
            ReplanThreshold::DEFAULT,
        )
        .map_err(map_commit_err)?;
        let unsigned = unsigned
            .into_iter()
            .map(|tx| {
                // `actions()` needs `&tx`, so it must be read before `into_parts()` consumes it.
                let actions = count_to_u32(tx.actions(), "unsigned tx actions")?;
                let (id, bytes) = tx.into_parts();
                Ok((id, bytes, actions))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        (state, unsigned)
    } else {
        let sk = sk.ok_or_else(|| anyhow!("signing requires the account's spending key"))?;
        let state = engine::commit_preparation(
            &ctx.network,
            target,
            &mut backend,
            sk,
            &cached.plan,
            &mut rng,
            ReplanThreshold::DEFAULT,
        )
        .map_err(map_commit_err)?;
        (state, Vec::new())
    };

    migration_plan_cache::clear(&ctx.db_path, ctx.account_bytes);
    Ok((state, unsigned))
}

/// Map a commit error, routing `StalePlan` through the stable plan-stale prefix (the actionable
/// "re-propose" signal). `WrongSpendAuthority` — the spending key passed in does not derive to the
/// account's stored viewing key — is a caller-contract violation, not a wallet-state condition the
/// platform recovers from by retrying the same call, so it gets no dedicated prefix: the generic
/// arm's message (from the engine's own `Display`) already names the mismatch plainly.
fn map_commit_err(e: engine::CommitError<AdapterError>) -> anyhow::Error {
    match e {
        engine::CommitError::StalePlan => {
            plan_stale("the previewed plan no longer matches the wallet or the build height")
        }
        other => anyhow!("Error committing migration: {other}"),
    }
}

/// Map a rebuild-on-expiry error. `FundingNoteUnavailable` gets the actionable message: the
/// expired transfer's EXACT funding note (matched by nullifier identity — the engine deliberately
/// never substitutes an equal-value note, which could be a sibling transfer's) was spent outside
/// the migration, so the remaining balance must be re-planned via the restart lane.
/// `WrongSpendAuthority` — as with [`map_commit_err`] — is a caller-contract violation and gets no
/// dedicated prefix. Everything else is a hard error carrying the engine's detail.
fn map_rebuild_err(e: engine::RebuildError<AdapterError>) -> anyhow::Error {
    match e {
        engine::RebuildError::FundingNoteUnavailable(value) => anyhow!(
            "the expired transfer's funding note ({} zatoshi) is gone — it was spent outside the \
             migration, so the rebuilt transfer cannot re-spend it; cancel and re-plan the \
             remaining balance via restartCurrentMigrationStep (zcashlc_migration_restart_step)",
            u64::from(value)
        ),
        other => anyhow!("Error rebuilding expired migration transfer: {other}"),
    }
}

/// Serves the stored `Proved` transaction `id` through the store's atomic broadcast seam, as
/// `(finalized transaction bytes, the row's stored txid)`.
///
/// The seam (`PoolMigrations::take_transaction_for_broadcast`) finalizes, extracts and records the
/// transaction in the wallet's own tables in one database transaction with handing the bytes back,
/// so the wallet's record binds at the broadcast ATTEMPT. It is idempotent: a retry after a failed
/// submission re-serves exactly the same transaction over the same record.
///
/// The txid is the row's STORED one — fixed when the transaction was built, before its authorizing
/// data — because that is the identity the engine keys `mark_broadcast` and mining promotion on,
/// so it is what the platform must submit-and-record under.
///
/// The seam's own refusal of a non-`Proved` row is the STALENESS GUARD for both callers: neither
/// re-asks the engine what to serve, so an instruction that has gone stale between the advance
/// that issued it and the serve that discharges it is refused here rather than acted on.
fn serve_for_broadcast(
    ctx: &mut CallCtx,
    state: &MigrationState,
    id: MigrationTransferId,
) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
    let txid = state
        .transactions()
        .iter()
        .find(|t| t.id() == id)
        .map(|t| <[u8; 32]>::from(t.txid()))
        .ok_or_else(|| anyhow!("no migration transaction with id {}", u32::from(id)))?;
    let mut store = account_store(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
    let tx = store
        .take_transaction_for_broadcast(state, id)
        .map_err(|e| broadcast_seam_error(id, e))?;
    let mut raw = Vec::new();
    tx.write(&mut raw)
        .map_err(|e| anyhow!("encoding the broadcastable transaction failed: {e}"))?;
    Ok((raw, txid))
}

/// Proves ONE `Signed` row through the upstream engine prover
/// ([`migration_finalize::prove_due_transaction`] driving a `WalletMigrationProver`): a transfer
/// against the boundary anchor persisted on its row, a preparation against the anchor resolved
/// from the wallet's scanned tip. The proven bytes are persisted (`Signed -> Proved`) before
/// returning.
///
/// `Ok(true)` when the row is now `Proved`; `Ok(false)` when the wallet has not scanned/retained
/// the needed anchor yet (a restored wallet mid-sync, a boundary not yet scanned past), the
/// ordinary transient outcome that leaves the row `Signed` for a later attempt. An already-`Proved`
/// row is a no-op `Ok(true)`, so callers may prove idempotently.
fn prove_one(
    ctx: &mut CallCtx,
    state: &mut MigrationState,
    id: MigrationTransferId,
) -> anyhow::Result<bool> {
    let tx = state
        .transactions()
        .iter()
        .find(|t| t.id() == id)
        .ok_or_else(|| anyhow!("no migration transaction with id {}", u32::from(id)))?;

    match tx.state() {
        MigrationTxState::Proved => Ok(true),
        MigrationTxState::Signed => {
            // The preparation anchor is resolved LAZILY, only for the kind that proves against it:
            // a transfer proves against its persisted boundary and must not fail just because the
            // wallet's anchor height is not resolvable yet (a wallet with a chain tip but no
            // scanned blocks — e.g. a restored wallet whose proving sweep runs before its first
            // scan — has none, and `preparation_anchor_height` hard-errors there, without the
            // proving-unavailable prefix).
            let preparation_anchor = match tx.kind() {
                MigrationTxKind::Preparation { .. } => {
                    Some(migration_finalize::preparation_anchor_height(&ctx.wallet)?)
                }
                MigrationTxKind::Transfer { .. } => None,
            };
            // The scanned tip bounds the engine's proving-time boundary re-draw: a re-drawn
            // boundary must be one the wallet can actually witness at. A wallet with nothing
            // fully scanned yet (a restore mid-sync) falls back to its chain tip — the draw may
            // then land past the scan, but the only consumer is the re-draw, and the prover's own
            // not-scanned-yet answer defers the row exactly as it would any unscanned anchor.
            let scanned_tip = ctx
                .wallet
                .block_fully_scanned()
                .map_err(|e| anyhow!("fully-scanned height lookup failed: {e}"))?
                .map(|meta| meta.block_height())
                .map_or_else(|| ctx.tip(), Ok)?;
            let network = ctx.network;
            let fvk = stored_orchard_fvk(&ctx.wallet, ctx.account)?;
            let mut prover = WalletMigrationProver::new(&mut ctx.wallet, ctx.account, fvk);
            let Some(proved) = migration_finalize::prove_due_transaction(
                &network,
                &mut prover,
                state,
                id,
                preparation_anchor,
                scanned_tip,
                &mut OsRng,
            )?
            else {
                // Not scanned/retained yet — transient, retry on a later sweep.
                return Ok(false);
            };
            // The store method is the ONLY consumer of the proof: it flips the row `Proved` and
            // persists the state atomically with the wallet's own record of the finalized
            // transaction (inputs marked spent), closing the prove-to-broadcast window in which
            // the wallet's own spends could double-spend a migration input. It persists the
            // whole state, so the proving-time boundary re-draw's mutation rides along — the
            // separate `replace_migration` this replaces is no longer needed here.
            let mut store = account_store(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
            store
                .store_proved_transaction(state, proved)
                .map_err(|e| anyhow!("migration store proved-transaction write failed: {e}"))?;
            Ok(true)
        }
        other => Err(anyhow!(
            "migration transaction {} cannot be proved (state {})",
            u32::from(id),
            other.as_ref()
        )),
    }
}

/// What one prove sweep accomplished: how many rows it proved, and the txids of the PREPARATIONS
/// among them.
///
/// ONLY PREPARATIONS ARE LISTED. A proved preparation is a complete PCZT (signatures and proofs),
/// it is ZIP 318-exempt, and the engine's own contract is that a preparation is broadcast as soon
/// as it is proved — so its submission is the platform's ORDINARY path: retrieve it by txid
/// through [`zcashlc_migration_take_preparation_by_txid`] and submit it like any other raw
/// transaction. A transfer is delivered by the drive's BROADCAST instruction alone, so naming one
/// here would imply a retrievability it deliberately does not have.
#[derive(Debug, Default, PartialEq, Eq)]
struct ProveOutcome {
    /// How many of the named rows this call proved — preparations AND transfers.
    total_proved: u32,
    /// The proved preparations' stored txids, in the order they were proved.
    preparation_txids: Vec<[u8; 32]>,
}

/// Proves the NAMED rows, persisting each, and returns what was proved (see [`ProveOutcome`]).
///
/// The ids are an instruction, not a query: they are the batch a prior
/// [`zcashlc_migration_advance_step`] returned as its `Prove` step, already verified against the
/// store's satisfiability oracle and ordered oldest-anchor-first by the drive that produced them.
/// THIS FUNCTION NEVER CRANKS THE DRIVE — see [`drive_advance`]'s invariant. Which rows are worth
/// proving, and whether a due broadcast outranks proving at all, are the advance's decisions; the
/// sweep only executes what it was told.
///
/// This is the opportunistic seam: a transaction's anchor becomes witnessable long before its
/// broadcast schedule arrives, so proofs are produced as the wallet scans rather than on the
/// delivery path — by broadcast time there is nothing left to do but broadcast.
///
/// TWO KINDS OF SKIP, neither fatal and neither a reason to stop — the rows behind still prove:
///
/// - A row that is no longer `Signed` (already `Proved` by an earlier chunk, broadcast, mined, or
///   awaiting a signature) is passed over. A STALE INSTRUCTION IS THEREFORE SAFE: the engine
///   re-offers work it has not recorded on the next crank, so acting on an out-of-date batch can
///   at worst do nothing.
/// - A row the wallet cannot prove YET (its anchor witness not scanned/retained) is left `Signed`
///   for a later call, which the next crank re-offers among the still-unproved remainder.
///
/// A row that only becomes provable BECAUSE an earlier member proved is NOT picked up here: the
/// ids are a snapshot, not re-derived mid-call. The caller advances again to collect it.
///
/// `prove` is [`prove_one`] in production; tests substitute the generic
/// [`migration_finalize::prove_due_transaction`] seam with a recording/failing test prover plus a
/// fixture-store persist. It takes `ctx` as a parameter rather than capturing it, so the caller
/// keeps the sole borrow.
fn prove_named_rows(
    ctx: &mut CallCtx,
    state: &mut MigrationState,
    ids: &[MigrationTransferId],
    max_proofs: Option<u32>,
    mut prove: impl FnMut(
        &mut CallCtx,
        &mut MigrationState,
        MigrationTransferId,
    ) -> anyhow::Result<bool>,
) -> anyhow::Result<ProveOutcome> {
    let mut outcome = ProveOutcome::default();
    for &id in ids {
        // `max_proofs` caps SUCCESSFUL proofs per call so an FFI caller can chunk a sweep:
        // each proof is seconds of CPU, and a platform serializing DB access behind one
        // actor needs a seam between proofs for interactive reads to interleave. A skip
        // below doesn't count against the cap — it costs no proving time, which is what lets a
        // cap-1 caller re-pass the WHOLE batch each chunk and still make progress.
        if max_proofs.is_some_and(|max| outcome.total_proved >= max) {
            break;
        }
        // The staleness skip. Only a `Signed` row is proving work; anything else the instruction
        // still names has been overtaken, and re-proving it would be wasted CPU at best.
        let still_signed = state
            .transactions()
            .iter()
            .any(|t| t.id() == id && matches!(t.state(), MigrationTxState::Signed));
        if !still_signed {
            continue;
        }
        if prove(ctx, state, id)? {
            // Guarded above as `Signed`, so a successful prove must have advanced this one; were
            // that ever untrue a cap-1 caller's loop would re-select it forever, which as an FFI
            // call means a hung app. Fail loudly instead.
            let row = state.transactions().iter().find(|t| t.id() == id);
            let advanced = row.is_none_or(|t| !matches!(t.state(), MigrationTxState::Signed));
            if !advanced {
                return Err(anyhow!(
                    "migration transaction {} reported a successful prove but is still Signed",
                    u32::from(id)
                ));
            }
            // Preparations only — see [`ProveOutcome`]. The txid is the row's STORED one, the
            // identity [`serve_for_broadcast`] serves under and the engine keys `mark_broadcast`
            // on, so what the platform retrieves by is exactly what it submits and records under.
            if let Some(txid) = row
                .filter(|t| matches!(t.kind(), MigrationTxKind::Preparation { .. }))
                .map(|t| <[u8; 32]>::from(t.txid()))
            {
                outcome.preparation_txids.push(txid);
            }
            outcome.total_proved += 1;
        }
        // A `false` (transient) result — the anchor not yet witnessable — moves on without
        // marking anything: the next crank re-offers this row among the still-unproved remainder.
    }
    Ok(outcome)
}

// ----- estimated-tip due-ness (M2, upstream `DuenessTargets`) -----
//
// `zcashlc_migration_has_overdue_transfers` and `zcashlc_migration_advance_step` accept an
// OPTIONAL estimated chain tip (a wall-clock projection past the scanned tip, computed by the
// platform from `zcashlc_migration_block_rate_samples`). The estimate/scanned split is OWNED
// UPSTREAM now:
// `zcash_pool_migration::state::DuenessTargets` encodes the rule (the estimate may only
// ACCELERATE schedule due-ness; expiry, boundary settledness, and every destructive decision
// evaluate on the scanned target — plus the doomed-broadcast withhold, where an expiry the
// EFFECTIVE target has passed keeps a broadcast from being served without ever counting as
// expired), and the public transaction-status and advance APIs evaluate it. This module only
// converts the FFI's `estimated_tip: i64` into the estimated-target side of
// [`DuenessTargets::new`] — see [`dueness_targets`].
//
// WHICH ROW is next is upstream's call too, not just the heights it is judged against, and among
// the ACTION lanes it is the CONDUIT's alone to ask: [`zcashlc_migration_advance_step`] cranks
// [`drive_advance`], and the two executors — [`zcashlc_migration_take_broadcast_transaction`] and
// [`zcashlc_migration_prove_transactions`] — discharge the instruction it returned without asking
// again (a due broadcast outranks proving exactly as the engine documents, and that precedence is
// therefore decided once, in the advance). The READ-ONLY REPORTING query — [`due_assuming_proving`],
// behind [`zcashlc_migration_has_overdue_transfers`] — cannot drive anything (it opens a read-only
// connection and must not mutate), so it reads the engine's public PER-ROW status view,
// `MigrationState::transaction_statuses`. That view agrees with the kernel's queues by
// construction: `ready && action == Broadcast` holds exactly when `advance_migration` would offer
// the broadcast, and the doomed-broadcast withhold is rendered as neither ready nor actionable.
// What that query does compose here is the ORDER among several actionable rows — the
// `(scheduled_height, id)`-min re-derived in [`due_assuming_proving`] — which is the module's one
// accepted drift risk (recorded on librustzcash #2938, 2026-08-06); and being unverified, a
// display read can still disagree with what the drive, having consulted the store's oracle, would
// actually serve.

/// The estimated TARGET height (`estimated tip + 1`) for an FFI-supplied `estimated_tip`
/// (`-1`, or any negative, = no estimate) — the `estimated_target` input of
/// [`DuenessTargets::new`].
///
/// The tip value SATURATES at `u32::MAX - 1` before the `+ 1` target conversion (A14): the
/// predecessor clamped to `u32::MAX` and then computed `tip + 1` in `u32`, which wraps a
/// nonsensically large estimate to target 0 in release builds (and panics in debug) instead of
/// keeping it "maximally far ahead". Clamping below the ceiling keeps the conversion total; the
/// `>= scanned` floor (the old `max(scanned, estimated)` rule) is [`DuenessTargets::new`]'s own
/// clamp, not re-implemented here.
fn estimated_target_from_tip(estimated_tip: i64) -> Option<BlockHeight> {
    (estimated_tip >= 0).then(|| {
        let tip = estimated_tip.min(i64::from(u32::MAX - 1)) as u32;
        target_from_tip(BlockHeight::from(tip))
    })
}

/// The [`DuenessTargets`] for a scanned tip plus the FFI's optional estimated tip — the ONE
/// construction site (U4: `DuenessTargets::new`'s two same-typed parameters invite transposition;
/// funneling every caller through here means the scanned/estimated order is written once).
fn dueness_targets(scanned_tip: BlockHeight, estimated_tip: i64) -> DuenessTargets {
    let scanned = target_from_tip(scanned_tip);
    DuenessTargets::new(
        scanned,
        estimated_target_from_tip(estimated_tip).unwrap_or(scanned),
    )
}

/// The id the delivery lane WOULD be driven toward once every outstanding proof exists, derived
/// over upstream's public status view ([`MigrationState::transaction_statuses`]). `None` when the
/// delivery lane has nothing actionable: nothing schedule-due yet, dependencies unmined, rows
/// awaiting an external signature (the signing ceremony, not the delivery lane, advances those),
/// or everything already broadcast/mined.
///
/// TWO TIERS, mirroring the drive's own precedence (upstream `MigrationState::next_step` consults
/// its broadcast queue FIRST and reaches its prove queue only when that queue is empty — a due
/// broadcast outranks all proving, whatever the two rows' relative schedules):
///
/// 1. The broadcast-queue min: the `(scheduled_height, id)`-min among rows reported `ready` with
///    [`NextAction::Broadcast`].
/// 2. Only if that tier is empty, the earliest-scheduled row still awaiting its proof: the
///    `(scheduled_height, id)`-min among rows reported `ready` with [`NextAction::Prove`] whose
///    schedule the effective target has already reached. Prove-readiness arrives long before the
///    broadcast window — that head start is the whole point of the prove/broadcast split — so an
///    undue prove-ready row is not delivery work and is excluded.
///
/// ONE PASS PER TIER suffices, with no virtual-prove closure to drive and no scratch clone to
/// drive it over: dependency readiness is keyed on `Mined`, never `Proved`, so proving a row
/// cannot make any OTHER row actionable. The transitive "once every proof exists" answer is
/// therefore exactly these two filters over the statuses as they already stand.
///
/// The per-row predicates are upstream's by construction: a row is `ready` with
/// [`NextAction::Broadcast`] exactly when the drive would offer its broadcast, and a
/// doomed-broadcast withhold ([`Blocker::ExpiryImminent`]) is reported as neither `ready` nor
/// carrying an action, so this query honours the withhold without restating it. What is RE-DERIVED
/// here, the queues themselves not being exported, is the ORDER within each tier — the
/// `(scheduled_height, id)`-min — which is this module's accepted drift risk, recorded on
/// librustzcash #2938 (2026-08-06).
///
/// ADVISORY, exactly as the exported queue reads it replaces were: a status carries no
/// store-oracle verification. [`zcashlc_migration_advance_step`] is the verified drive, which puts
/// each candidate to the store's satisfiability oracle and may re-spread a slept-through backlog
/// before answering, so a row named here can still come back as a `Prove` step, or (once
/// re-spread) as not due yet, or be set aside entirely — and where the drive would answer `Replan`
/// (a slot that sits BETWEEN the two tiers above, preempting proving but not a due broadcast) this
/// query still names a row while the delivery lane has nothing to serve, a divergence by design.
/// What this DOES separate, for the display query built on it
/// ([`zcashlc_migration_has_overdue_transfers`]), is "nothing is due" from "due, but its proof has
/// not been produced yet": it reports due work whether or not its proof exists, because the work
/// exists either way and proving is [`zcashlc_migration_prove_transactions`]' job, not the
/// reporting path's.
///
/// `targets` carries the scanned/estimated due-ness pair (coincident when no estimate is in
/// play) — see the section comment above [`estimated_target_from_tip`].
fn due_assuming_proving(
    state: &MigrationState,
    targets: DuenessTargets,
) -> Option<MigrationTransferId> {
    let statuses = state.transaction_statuses(targets);
    statuses
        .iter()
        .filter(|s| s.ready() && s.action() == Some(NextAction::Broadcast))
        .min_by_key(|s| (s.scheduled_height(), s.id()))
        .or_else(|| {
            statuses
                .iter()
                .filter(|s| {
                    s.ready()
                        && s.action() == Some(NextAction::Prove)
                        && s.scheduled_height() <= targets.effective()
                })
                .min_by_key(|s| (s.scheduled_height(), s.id()))
        })
        .map(|s| s.id())
}

/// The PREPARATION [`zcashlc_migration_sign_note_split`] proves now and hands back for the
/// platform's immediate broadcast, as a pure function of stored state. `None` only when the run
/// holds no unbroadcast preparation at all, which the caller reports as an error.
///
/// RESUME FIRST. A resumed ceremony must re-serve a preparation that is already `Proved` and due
/// rather than prove another one: the artifact exists, re-proving it is seconds of wasted CPU,
/// and it is the row the engine's own broadcast queue is holding right now. Those rows are
/// exactly the ones upstream's status view reports `ready` with [`NextAction::Broadcast`]
/// (`Proved`, schedule-due, dependency-mined, unexpired, unmarked), and the
/// `(scheduled_height, id)`-min among them mirrors that queue's order.
///
/// FRESH COMMIT otherwise, which is also the ordinary path: nothing is broadcast-ready yet,
/// because the first preparation's drawn window opens a few blocks ahead — the engine will not
/// offer it until then, and this lane must still hand it back NOW, which is the whole reason the
/// ceremony does not simply defer to the delivery lane. The `(scheduled_height, id)`-min over the
/// run's own unbroadcast preparation rows is what the engine itself picks once that window opens:
/// preparation layers are serialized in schedule order (a later layer starts past the previous
/// layer's last scheduled height), so the earliest-scheduled row is also the one whose
/// dependencies mine first.
fn ceremony_preparation_pick(
    state: &MigrationState,
    targets: DuenessTargets,
) -> Option<MigrationTransferId> {
    let resume_pick = state
        .transaction_statuses(targets)
        .iter()
        .filter(|s| {
            s.ready()
                && s.action() == Some(NextAction::Broadcast)
                && matches!(s.kind(), MigrationTxKind::Preparation { .. })
        })
        .min_by_key(|s| (s.scheduled_height(), s.id()))
        .map(|s| s.id());
    resume_pick.or_else(|| {
        state
            .transactions()
            .iter()
            .filter(|t| {
                matches!(t.kind(), MigrationTxKind::Preparation { .. })
                    && matches!(
                        t.state(),
                        MigrationTxState::Signed | MigrationTxState::Proved
                    )
            })
            // Ties (equal `scheduled_height`) break by `id`, mirroring the engine's own ordering
            // key: deterministic on equal heights.
            .min_by_key(|t| (t.scheduled_height(), t.id()))
            .map(|t| t.id())
    })
}

// ----- progress derivation (pure; unit-tested) -----

/// The fallback bound (blocks past `recorded_at_height`) an unmined immediate run is treated as
/// pending until, when the wallet database does not know (or no longer knows) the transaction's
/// real expiry height: the typical wallet transaction-expiry delta, so a run that the wallet's own
/// history never corroborates does not linger forever before the banner re-offers.
const IMMEDIATE_RUN_FALLBACK_EXPIRY_DELTA: u32 = 40;

/// An immediate-run row resolved against the wallet database (see [`resolve_immediate_run`]),
/// pre-computed by the caller so [`immediate_run_pending`] stays pure and unit-testable without a
/// wallet database.
struct ImmediateRunLookup {
    /// The tip height at which the run was recorded — the fallback expiry bound used when the
    /// wallet database does not know the transaction's real expiry height.
    recorded_at_height: BlockHeight,
    /// The txid's mined height, if the wallet has observed it mined.
    mined_height: Option<BlockHeight>,
    /// The txid's expiry height, as recorded by the wallet (`None` when the wallet has never
    /// observed the transaction, or recorded no real expiry for it).
    expiry_height: Option<BlockHeight>,
}

impl ImmediateRunLookup {
    /// The height beyond which this run, if still unmined, is treated as expired: the wallet's own
    /// recorded expiry when known, otherwise the fallback delta past the record height.
    fn expiry_bound(&self) -> BlockHeight {
        self.expiry_height.unwrap_or_else(|| {
            BlockHeight::from(
                u32::from(self.recorded_at_height) + IMMEDIATE_RUN_FALLBACK_EXPIRY_DELTA,
            )
        })
    }
}

/// The progress counters of an ACTIVE (stored, non-terminal) engine run, as
/// `(completed, total, next_transfer_ready_at_height)`: `completed` is the count of Transfer rows
/// `Mined`, `total` the count of Transfer rows, and the next-ready height the minimum
/// `scheduled_height` over transfers still AWAITING BROADCAST. Preparations count toward none of
/// the three. Pure over the state so it unit-tests without a wallet database; the caller
/// guarantees `!state.is_terminal()` (a terminal run reports NO progress — see
/// [`zcashlc_migration_progress`]).
fn active_run_progress(state: &MigrationState) -> (u32, u32, Option<BlockHeight>) {
    let transfers: Vec<&MigrationTransaction> = state
        .transactions()
        .iter()
        .filter(|t| matches!(t.kind(), MigrationTxKind::Transfer { .. }))
        .collect();
    let completed = transfers
        .iter()
        .filter(|t| matches!(t.state(), MigrationTxState::Mined { .. }))
        .count() as u32;
    // F6: min over transfers still AWAITING BROADCAST only (`AwaitingSignature`/`Signed`/
    // `Proved`) — NOT merely "not yet mined". A `Broadcast` transfer is already in the mempool;
    // there is nothing left for the platform to prepare for it, so its height must not surface
    // here even when it is numerically the smallest (see `next_transfer_ready_at_height`'s doc).
    let next_ready = transfers
        .iter()
        .filter(|t| {
            matches!(
                t.state(),
                MigrationTxState::AwaitingSignature
                    | MigrationTxState::Signed
                    | MigrationTxState::Proved
            )
        })
        .map(|t| t.scheduled_height())
        .min();
    (completed, transfers.len() as u32, next_ready)
}

/// Whether an immediate-run row still counts as PENDING at `tip`: unmined and not past its expiry
/// bound (the wallet's own recorded expiry when known, otherwise the fallback delta past the
/// record height — see [`ImmediateRunLookup::expiry_bound`]). A mined run is CONSUMED (the sweep
/// zeroed the balance; nothing to report) and an expired unmined one is ignored (the banner
/// re-offers) — both report NO progress.
fn immediate_run_pending(run: &ImmediateRunLookup, tip: BlockHeight) -> bool {
    run.mined_height.is_none() && tip <= run.expiry_bound()
}

/// The amount a stored transfer CROSSES into Ironwood, or `None` for a preparation transaction
/// (which crosses nothing). Thin wrapper over the engine's own accessor, which is net of the fee
/// buffer that pays the transfer's own fee — never the larger funding note it spends.
fn transfer_amount(state: &MigrationState, tx: &MigrationTransaction) -> Option<Zatoshis> {
    state.transfer_crossing_value(tx)
}

// ============================================================================================
// #[repr(C)] return DTOs
//
// These are named `Ffi*` in Rust because the base names would collide with the engine types this
// module marshals from; the prefix also lands the `Ffi*` C names the header convention wants
// without any `build.rs` `rename_item` entry.
// ============================================================================================

/// Live migration progress (returned by `zcashlc_migration_progress`); `is_present` is `false`
/// when no progress is reportable (no stored run, a terminal run, and no pending immediate run —
/// see that function's contract).
#[repr(C)]
pub struct FfiMigrationProgress {
    /// Whether the remaining fields carry a real progress snapshot.
    pub is_present: bool,
    /// The number of scheduled transfers confirmed on-chain so far.
    pub completed_transfers: u32,
    /// The total number of transfers in the current schedule.
    pub total_transfers: u32,
    /// The Orchard-pool value (zatoshi) not yet migrated to Ironwood — the account's live
    /// spendable Orchard balance.
    pub remaining_orchard_value: i64,
    /// The height at which the next transfer becomes broadcastable, or `-1` if none is scheduled.
    /// Only transfers still AWAITING broadcast count (F6): one already `Broadcast` (in the
    /// mempool, awaiting mining) has nothing left to prepare for, so it never sets this field,
    /// even when its own scheduled height is lower than another transfer's.
    pub next_transfer_ready_at_height: i64,
    /// Whether this progress belongs to the immediate (single-transaction) send-max migration lane
    /// rather than an engine-tracked schedule. The app uses it to keep the immediate aftermath
    /// quiet (no per-transfer UI). Engine-tracked runs report `false`.
    pub is_immediate: bool,
}

impl FfiMigrationProgress {
    fn absent() -> Self {
        FfiMigrationProgress {
            is_present: false,
            completed_transfers: 0,
            total_transfers: 0,
            remaining_orchard_value: 0,
            next_transfer_ready_at_height: -1,
            is_immediate: false,
        }
    }
}

/// The step discriminants of [`FfiMigrationAdvanceStep::step`], exported into the generated
/// header so the Swift layer and the marshal share one set of names instead of re-hardcoding the
/// numbers on each side (U3).
pub const ZCASHLC_ADVANCE_STEP_PROVE: u32 = 0;
pub const ZCASHLC_ADVANCE_STEP_BROADCAST: u32 = 1;
pub const ZCASHLC_ADVANCE_STEP_REBUILD: u32 = 2;
pub const ZCASHLC_ADVANCE_STEP_WAITING: u32 = 3;
pub const ZCASHLC_ADVANCE_STEP_COMPLETE: u32 = 4;
// 5 was ZCASHLC_ADVANCE_STEP_ATTEND — the collapsed Reevaluate/Replan projection (with a
// synthesised transaction id neither upstream step carries), retired 2026-08-08 when the two
// steps gained their own bare discriminants below. The value stays a HOLE on purpose: reusing
// it would let a stale header decode one vocabulary as the other.
pub const ZCASHLC_ADVANCE_STEP_REPLAN: u32 = 6;
pub const ZCASHLC_ADVANCE_STEP_REEVALUATE: u32 = 7;

/// The step-kind discriminants of [`FfiMigrationAdvanceStep::next_kind`], a verbatim export of
/// upstream `state::StepKind` (the outlook's kind — WHICH transaction a wake-up serves is decided
/// by the `advance_migration` call that serves it). Only Prove, Broadcast, Rebuild and Replan are
/// constructible outlooks today (upstream's `upcoming_step` maps the rest to "no outlook"), but
/// the export mirrors the full enum so the marshal never invents a projection.
pub const ZCASHLC_STEP_KIND_PROVE: u32 = 0;
pub const ZCASHLC_STEP_KIND_BROADCAST: u32 = 1;
pub const ZCASHLC_STEP_KIND_REBUILD: u32 = 2;
pub const ZCASHLC_STEP_KIND_REPLAN: u32 = 3;
pub const ZCASHLC_STEP_KIND_REEVALUATE: u32 = 4;
pub const ZCASHLC_STEP_KIND_WAITING: u32 = 5;
pub const ZCASHLC_STEP_KIND_COMPLETE: u32 = 6;

/// Marshals upstream `state::StepKind` into the [`ZCASHLC_STEP_KIND_*`] discriminants — the
/// [`FfiMigrationAdvanceStep::next_kind`] counterpart of the step discriminants above. Exhaustive
/// (no wildcard arm): a new upstream variant must be assigned an explicit number here rather than
/// silently falling into whatever the last arm was.
fn step_kind_to_ffi(kind: StepKind) -> u32 {
    match kind {
        StepKind::Prove => ZCASHLC_STEP_KIND_PROVE,
        StepKind::Broadcast => ZCASHLC_STEP_KIND_BROADCAST,
        StepKind::Rebuild => ZCASHLC_STEP_KIND_REBUILD,
        StepKind::Replan => ZCASHLC_STEP_KIND_REPLAN,
        StepKind::Reevaluate => ZCASHLC_STEP_KIND_REEVALUATE,
        StepKind::Waiting => ZCASHLC_STEP_KIND_WAITING,
        StepKind::Complete => ZCASHLC_STEP_KIND_COMPLETE,
    }
}

/// The outlook pair as the FFI carries it: `(-1, 0)` for "no outlook", else the target height
/// widened to `i64` beside the kind discriminant — one encoding, shared by every constructor.
fn outlook_to_ffi(next: Option<(BlockHeight, StepKind)>) -> (i64, u32) {
    (
        next.map_or(-1, |(h, _)| i64::from(u32::from(h))),
        next.map_or(0, |(_, k)| step_kind_to_ffi(k)),
    )
}

/// One transaction of a Prove batch (element of [`FfiMigrationAdvanceStep::prove_targets`]): the
/// transaction to prove, with the kind that routes it (a preparation proves against the tip anchor
/// and may broadcast at the same wake-up; a transfer proves against its drawn boundary and
/// broadcasts in its own later session), plus whether its broadcast window has already opened.
///
/// The kind fields are a verbatim marshal of upstream `state::ProveTarget`; `schedule_due` is not
/// an upstream field but this conduit's own reading of the row against the very
/// [`DuenessTargets`] the drive that produced the batch judged with — see
/// [`FfiMigrationAdvanceStep::prove`].
#[repr(C)]
pub struct FfiProveTarget {
    /// The engine's raw transaction id.
    pub id: u32,
    /// Whether the transaction is a preparation (`true`) or a transfer (`false`).
    pub kind_is_preparation: bool,
    /// The preparation's layer, when `kind_is_preparation`; `0` otherwise.
    pub kind_layer: u32,
    /// The preparation's index within its layer, when `kind_is_preparation`; `0` otherwise.
    pub kind_index: u32,
    /// The transfer's crossing index, when `!kind_is_preparation`; `0` otherwise.
    pub kind_crossing: u32,
    /// Whether the effective dueness target has already reached this transaction's scheduled
    /// height — i.e. whether its missing proof is what stands between the run and a broadcast the
    /// platform could otherwise make right now.
    ///
    /// A transaction becomes provable long BEFORE it comes due — that head start is the whole
    /// point of the prove/broadcast split — so most of a batch is ordinarily `false`, meaning
    /// "proving is opportunistic work for the next sync wake-up". A `true` entry means the
    /// delivery lane is blocked on this proof, so a platform that skipped its sweep should sweep
    /// and re-advance instead of sleeping until the next scheduled wake.
    pub schedule_due: bool,
}

/// The engine's next-step decision for the stored run (returned by
/// [`zcashlc_migration_advance_step`]) — a verbatim marshal of upstream
/// the public satisfiability advance API's [`AdvanceStep`].
#[repr(C)]
pub struct FfiMigrationAdvanceStep {
    /// The step discriminant (see the `ZCASHLC_ADVANCE_STEP_*` constants).
    pub step: u32,
    /// The engine's raw transaction id for Broadcast/Rebuild/Attend; `0` for Prove (the batch
    /// entries carry their own ids) and for Waiting/Complete.
    pub id: u32,
    /// Heap array of `prove_targets_len` batch entries when `step == 0` (Prove) — the WHOLE
    /// provable set, earliest-ready first, never empty for a served Prove; null/0 otherwise.
    pub prove_targets: *mut FfiProveTarget,
    /// Length of `prove_targets`.
    pub prove_targets_len: usize,
    /// The OUTLOOK (upstream #2936, `Advance::next`): the earliest target height (`tip + 1`
    /// convention, directly comparable with the drive's own targets) at which the migration next
    /// has serviceable work, assuming this step is executed and recorded; `-1` when nothing is
    /// height-schedulable (chain- or user-driven followers, terminal runs — upstream documents
    /// the cases). ADVISORY: a floor, not an appointment; the serving call re-verifies.
    pub next_height: i64,
    /// The kind of that upcoming work (see the `ZCASHLC_STEP_KIND_*` constants); meaningful only
    /// when `next_height >= 0`.
    pub next_kind: u32,
}

impl FfiMigrationAdvanceStep {
    /// A step that names a transaction but carries no batch payload (Broadcast/Rebuild/Attend).
    fn with_id(
        step: u32,
        id: MigrationTransferId,
        next: Option<(BlockHeight, StepKind)>,
    ) -> *mut Self {
        let (next_height, next_kind) = outlook_to_ffi(next);
        Box::into_raw(Box::new(FfiMigrationAdvanceStep {
            step,
            id: u32::from(id),
            prove_targets: ptr::null_mut(),
            prove_targets_len: 0,
            next_height,
            next_kind,
        }))
    }

    /// A payload-free step (Waiting/Complete).
    fn bare(step: u32, next: Option<(BlockHeight, StepKind)>) -> *mut Self {
        let (next_height, next_kind) = outlook_to_ffi(next);
        Box::into_raw(Box::new(FfiMigrationAdvanceStep {
            step,
            id: 0,
            prove_targets: ptr::null_mut(),
            prove_targets_len: 0,
            next_height,
            next_kind,
        }))
    }

    /// The Prove step, carrying the whole provable set (upstream #2939): each entry's kind lets the
    /// platform route it without a lookup, and its `schedule_due` says whether the delivery lane is
    /// blocked on that proof.
    ///
    /// `schedule_due` is read off the stored row's scheduled height against
    /// [`DuenessTargets::effective`] — schedule dueness is the wall-clock estimate's to accelerate
    /// (see the section comment above [`estimated_target_from_tip`]) — using the SAME `targets` the
    /// [`drive_advance`] call that produced `transactions` judged with, so the flag can never
    /// disagree with the batch it annotates. A row the batch names but the stored run does not
    /// contain cannot happen (the engine draws the batch from that run); it reads as not due, which
    /// is the answer that asks the platform for nothing.
    fn prove(
        state: &MigrationState,
        transactions: &[ProveTarget],
        targets: DuenessTargets,
        next: Option<(BlockHeight, StepKind)>,
    ) -> *mut Self {
        let targets_ffi: Vec<FfiProveTarget> = transactions
            .iter()
            .map(|t| {
                let (kind_is_preparation, kind_layer, kind_index, kind_crossing) = match t.kind() {
                    MigrationTxKind::Preparation { layer, index } => {
                        (true, layer as u32, index as u32, 0)
                    }
                    MigrationTxKind::Transfer { crossing } => (false, 0, 0, crossing as u32),
                };
                let schedule_due = state
                    .transactions()
                    .iter()
                    .any(|row| row.id() == t.id() && row.scheduled_height() <= targets.effective());
                FfiProveTarget {
                    id: u32::from(t.id()),
                    kind_is_preparation,
                    kind_layer,
                    kind_index,
                    kind_crossing,
                    schedule_due,
                }
            })
            .collect();
        let (prove_targets, prove_targets_len) = ptr_from_vec(targets_ffi);
        let (next_height, next_kind) = outlook_to_ffi(next);
        Box::into_raw(Box::new(FfiMigrationAdvanceStep {
            step: ZCASHLC_ADVANCE_STEP_PROVE,
            id: 0,
            prove_targets,
            prove_targets_len,
            next_height,
            next_kind,
        }))
    }
}

/// One sync/proving wake-up of the schedule returned by [`zcashlc_migration_sync_wakeups`]: the
/// block height at which the wallet should wake, sync, and prove, plus the ids of the transfers
/// this wake-up is responsible for proving (a verbatim marshal of upstream
/// `scheduling::SyncWakeup`).
#[repr(C)]
pub struct FfiMigrationSyncWakeup {
    /// The block height at which to wake, sync, and prove.
    pub height: i64,
    /// Heap array of `covers_len` engine transaction ids this wake-up is responsible for proving.
    pub covers: *mut u32,
    pub covers_len: usize,
}

/// The full sync-wakeup schedule (see [`zcashlc_migration_sync_wakeups`]). `len == 0` (with a
/// valid pointer) is the benign "no schedule" answer: no stored run, a terminal run, or no
/// transfer still needing a proof.
#[repr(C)]
pub struct FfiMigrationSyncWakeups {
    pub rows: *mut FfiMigrationSyncWakeup,
    pub len: usize,
}

/// One scanned-block sample (element of [`FfiBlockRateSamples`]): the block's height and its
/// header time as Unix epoch seconds.
#[repr(C)]
pub struct FfiBlockRateSample {
    pub height: i64,
    pub unix_time: i64,
}

/// The most recently scanned blocks' `(height, time)` samples, ASCENDING by height (see
/// [`zcashlc_migration_block_rate_samples`]). `len == 0` (with a valid pointer) means the wallet
/// has scanned no blocks yet.
#[repr(C)]
pub struct FfiBlockRateSamples {
    pub rows: *mut FfiBlockRateSample,
    pub len: usize,
}

/// A planned note split: the per-note output values (zatoshi) and the preparation fees.
#[repr(C)]
pub struct FfiNoteSplitProposal {
    /// Heap array of `output_values_len` output-note values (zatoshi).
    pub output_values: *mut i64,
    pub output_values_len: usize,
    /// The total fees (zatoshi) paid by the preparation (note-split) transactions.
    pub fee: i64,
    /// Opaque identifier of the cached plan this proposal was rendered from. Commit calls pass
    /// it back, and the rust side refuses to sign any plan other than the one it identifies
    /// (`MIGRATION_PLAN_STALE` when missing or superseded). `0` means no plan was cached (the
    /// empty nothing-to-migrate proposal).
    pub proposal_handle: u64,
}

/// One transaction handed to the platform, always populated; a NULL return signals an error.
///
/// There is no "nothing due" or "awaiting proof" shape here any more. Those were the answers of a
/// lane that ASKED the engine what to deliver; the executors that replaced it are told what to
/// deliver by a prior [`zcashlc_migration_advance_step`], so a call that reaches this type has an
/// instruction to serve and either serves it or fails.
///
/// WHAT THE ARTIFACT IS depends on which entry point produced the value, because the producers
/// hand back different stages of the same transaction:
/// - `zcashlc_migration_take_broadcast_transaction` (the drive's BROADCAST instruction) and
///   `zcashlc_migration_sign_note_split` (the ceremony handback) both serve through the store's
///   atomic broadcast seam, so their artifact is the FINALIZED CONSENSUS TRANSACTION — submit it
///   as-is.
/// - The storage receipt `zcashlc_migration_store_signed_note_split_pczts` returns is a serialized
///   PCZT, not submittable until the engine has proved it and a later
///   `zcashlc_migration_take_broadcast_transaction` serves the broadcastable, proven value once a
///   crank names it.
#[repr(C)]
pub struct FfiPreparedTransfer {
    /// The transaction's id (the engine's raw id).
    pub id: u32,
    /// The finalized transaction's id, as raw (internal-order) 32-byte value (zeroed when the
    /// value is a storage receipt whose transaction has not been proven yet).
    pub txid: [u8; 32],
    /// The heap `pczt_len`-byte artifact — a finalized transaction or a serialized PCZT per the
    /// producer, as the type doc above spells out. The field keeps its historical name for ABI
    /// compatibility.
    pub pczt: *mut u8,
    pub pczt_len: usize,
}

impl FfiPreparedTransfer {
    fn from_parts(
        id: MigrationTransferId,
        txid: [u8; 32],
        pczt_bytes: Vec<u8>,
    ) -> anyhow::Result<*mut Self> {
        let id = u32::from(id);
        let (pczt, pczt_len) = ptr_from_vec(pczt_bytes);
        Ok(Box::into_raw(Box::new(FfiPreparedTransfer {
            id,
            txid,
            pczt,
            pczt_len,
        })))
    }
}

/// What one [`zcashlc_migration_prove_transactions`] call proved: the total count, and the txids
/// of the PREPARATIONS among them. Always populated; a NULL return signals an error.
///
/// `total_proved == 0` with an empty `preparation_txids` is the ordinary "nothing in this batch is
/// provable right now" answer (also: no stored run, or a terminal one).
///
/// THE TXIDS ARE PREPARATIONS' AND NOTHING ELSE. A proved preparation is a complete PCZT whose
/// submission is the platform's ORDINARY path — retrieve it with
/// [`zcashlc_migration_take_preparation_by_txid`] and submit it like any other raw transaction —
/// whereas a transfer crosses the turnstile on the drive's own schedule and is served by a
/// BROADCAST instruction alone. A transfer's txid therefore never appears here, because appearing
/// here means "retrievable".
#[repr(C)]
pub struct FfiMigrationProveOutcome {
    /// How many of the named transactions this call proved — preparations AND transfers.
    pub total_proved: u32,
    /// Heap array of `preparation_txids_len` raw (internal-order) 32-byte txids: the preparations
    /// this call proved, in the order it proved them.
    pub preparation_txids: *mut [u8; 32],
    pub preparation_txids_len: usize,
}

impl FfiMigrationProveOutcome {
    fn from_outcome(outcome: ProveOutcome) -> *mut Self {
        let (preparation_txids, preparation_txids_len) = ptr_from_vec(outcome.preparation_txids);
        Box::into_raw(Box::new(FfiMigrationProveOutcome {
            total_proved: outcome.total_proved,
            preparation_txids,
            preparation_txids_len,
        }))
    }
}

/// A single scheduled Orchard→Ironwood transfer (element of [`FfiMigrationSchedule`]).
#[repr(C)]
pub struct FfiTransferProposal {
    /// The transfer's id (the engine's raw id).
    pub id: u32,
    /// The value (zatoshi) that crosses the turnstile.
    pub amount: i64,
    /// The "now" reference height at encode time (the chain tip). With ZIP 374 the real anchor is
    /// drawn per transfer and installed at proving time; this field is NOT a commitment-tree
    /// anchor and callers must not treat it as one.
    pub anchor_height: i64,
    /// The height after which the platform may broadcast this transfer.
    pub next_executable_after_height: i64,
    /// The height after which this transfer is no longer valid.
    pub expiry_height: i64,
}

/// A single note-preparation transaction in a schedule preview (element of
/// [`FfiMigrationSchedule::preparations`]) — Android parity: the transfer rows alone do not
/// surface the preparations that mint their funding notes (see [`FfiTransferProposal`]).
/// Populated either from a fresh [`MigrationPlan`] (mirroring EXACTLY how the engine's commit
/// path — `zcash_pool_migration::engine::commit_preparation`'s `Committer` — will number and
/// schedule these once committed) or, once a run is stored, read straight off its persisted
/// rows — see [`encode_schedule_from_plan`] / [`encode_schedule_from_state`].
#[repr(C)]
pub struct FfiMigrationPreparationStep {
    /// This transaction's stable id (`MigrationTransferId`'s raw ordinal).
    pub id: u32,
    /// The dependency-layer index this preparation belongs to.
    pub layer: u32,
    /// This preparation's index within `layer`.
    pub index: u32,
    /// The height at or after which this preparation is due to broadcast.
    pub broadcast_height: i64,
    /// Heap array of `depends_on_len` ids of the transactions that must mine before this one may
    /// broadcast: the WHOLE preceding layer's ids (empty for layer 0) — the commit path does not
    /// narrow this to the specific producer(s) a layer's inputs spend.
    pub depends_on: *mut u32,
    pub depends_on_len: usize,
}

/// A full migration schedule presented to the user for one-time confirmation, in chronological
/// broadcast order. An empty schedule means there is nothing to migrate.
#[repr(C)]
pub struct FfiMigrationSchedule {
    /// Heap array of `transfers_len` scheduled transfers, in execution order.
    pub transfers: *mut FfiTransferProposal,
    pub transfers_len: usize,
    /// A rough estimate of how long the schedule takes to fully execute, in hours — measured
    /// from the encode-time chain tip to the last scheduled broadcast (#1806).
    pub estimated_duration_hours: u32,
    /// Opaque identifier of the cached plan this schedule was rendered from — see
    /// [`FfiNoteSplitProposal::proposal_handle`] for the contract. `0` means no cached plan
    /// backs this schedule: the empty nothing-to-migrate answer, or a schedule encoded from
    /// already-committed STORED state (which commit-shaped calls resume without a handle).
    pub proposal_handle: u64,
    /// Heap array of `preparations_len` preparation-transaction rows (Android parity — plan data
    /// at propose time, stored rows on re-serve; see [`FfiMigrationPreparationStep`]).
    pub preparations: *mut FfiMigrationPreparationStep,
    pub preparations_len: usize,
}

/// A single run's estimate (element of [`FfiMigrationRunEstimate`]): what one migration run
/// migrates (the note-split side) and what preparing it costs (the note-preparation side), so
/// the two can be compared.
#[repr(C)]
pub struct FfiRunEstimate {
    /// The total value (zatoshi) that crosses the turnstile in this run.
    pub migratable: i64,
    /// The number of pool-crossing transfers this run makes: one per self-funding note.
    pub crossings: u32,
    /// The number of sequential note-preparation layers this run needs — its wall-clock depth,
    /// since each layer waits for the previous one to mine before it can be broadcast.
    pub prep_layers: u32,
    /// The number of note-preparation transactions this run builds across all its layers.
    pub prep_transactions: u32,
    /// The total Orchard-family actions a signer processes for this run: 16 per preparation
    /// transaction, 3 per transfer (`zcash_pool_migration::signing_rounds`). The signing
    /// WORKLOAD, a proxy for signing time — distinct from `keystone_rounds`, which counts signer
    /// INTERACTIONS, not actions.
    pub actions: u32,
    /// The number of signing ROUNDS this run needs from a Keystone-class external signer (96
    /// total actions per round, `SigningRoundBudget::KEYSTONE`), computed by the optimal
    /// `MinRounds` packing. Count-based `ceil(transaction_count / max_transactions_per_session)`
    /// UNDERCOUNTS this: 6 preparations (96 actions) plus 1 transfer (3 actions) is 99 actions —
    /// one Keystone round over — so it needs 2 rounds, not 1.
    pub keystone_rounds: u32,
}

/// An estimate of migrating the account's whole spendable balance across successive migration
/// RUNS ("rounds"): one [`FfiRunEstimate`] per run, plus the value left un-migrated at the end.
/// `runs_len == 0` means nothing migrates (a zero or fully sub-quantum balance) — a legitimate
/// estimate, not an error.
#[repr(C)]
pub struct FfiMigrationRunEstimate {
    /// Heap array of `runs_len` per-run estimates, in run order.
    pub runs: *mut FfiRunEstimate,
    pub runs_len: usize,
    /// The value (zatoshi) left in the source pool after the last run — below the smallest
    /// self-funding note, so it never migrates. Zero when the balance divides exactly into
    /// self-funding notes and fees.
    pub final_residual: i64,
}

/// An unsigned PCZT awaiting an external signer (element of [`FfiUnsignedTransferPczts`]).
#[repr(C)]
pub struct FfiUnsignedTransferPczt {
    /// The transaction's id (the engine's raw id).
    pub id: u32,
    /// Heap `pczt_len`-byte serialized unsigned PCZT.
    pub pczt: *mut u8,
    pub pczt_len: usize,
    /// The Orchard-family actions a signer processes for this transaction
    /// (`zcash_pool_migration::signing_rounds::action_weight`), so a caller can split a batch
    /// into device-sized signing sessions before dispatching it (see
    /// `zcashlc_migration_batch_pczts_by_actions`). `0` on the Keystone apply-signatures path
    /// (see [`FfiUnsignedTransferPczts`]'s doc): that call has no stored `kind` to weigh — batching
    /// happens before signing, over this same DTO's CREATE/RE-SERVE rows, never over its result.
    pub actions: u32,
}

/// A set of unsigned PCZTs to route to an external signer. Despite the name, this is really a
/// generic `(id, PCZT bytes, actions)` row set: [`zcashlc_migration_keystone_apply_batch_signatures`]
/// also returns its batch-SIGNED PCZTs through this same type, positionally paired back up with
/// the ids the caller passed in (with `actions` unpopulated — see
/// [`FfiUnsignedTransferPczt::actions`]).
#[repr(C)]
pub struct FfiUnsignedTransferPczts {
    pub ptr: *mut FfiUnsignedTransferPczt,
    pub len: usize,
}

impl FfiUnsignedTransferPczts {
    fn from_pairs(pairs: Vec<(MigrationTransferId, Vec<u8>, u32)>) -> anyhow::Result<*mut Self> {
        let items = pairs
            .into_iter()
            .map(|(id, bytes, actions)| {
                let id = u32::from(id);
                let (pczt, pczt_len) = ptr_from_vec(bytes);
                Ok(FfiUnsignedTransferPczt {
                    id,
                    pczt,
                    pczt_len,
                    actions,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let (ptr, len) = ptr_from_vec(items);
        Ok(Box::into_raw(Box::new(FfiUnsignedTransferPczts {
            ptr,
            len,
        })))
    }
}

/// The per-session transaction COUNTS [`zcashlc_migration_batch_pczts_by_actions`] splits an
/// action-weighted, ordered PCZT list into: element `i` is how many consecutive input rows landed
/// in session `i` (summing to the input length). No ids or bytes cross back over that call, only
/// these split points — the caller re-slices its own ordered PCZT list by them.
#[repr(C)]
pub struct FfiMigrationBatchSizes {
    /// Heap array of `len` per-session transaction counts, in session order.
    pub ptr: *mut u32,
    pub len: usize,
}

/// One migration transaction's LIVE status, as the engine computes it — an element of
/// [`FfiMigrationTransactionStatuses`]. Mirrors [`zcash_pool_migration::state::TransactionStatus`]
/// field-for-field, PLUS `anchor_boundary` (joined in from the stored `MigrationTransaction` row
/// by id — `TransactionStatus` itself carries no boundary; see
/// [`zcash_pool_migration::engine::MigrationTransaction::anchor_boundary`]) — nothing here is
/// derived independently of the engine's own view (see
/// [`zcashlc_migration_transaction_statuses`]).
#[repr(C)]
pub struct FfiMigrationTransactionStatus {
    /// This transaction's stable id (`MigrationTransferId`'s raw ordinal). Stable across reads and
    /// across a stale-transfer rebuild (a rebuilt transfer keeps its id; only its PCZT and
    /// heights change), so a wallet may use it as a durable row key.
    pub id: u32,
    /// The transaction's kind: `true` for a phase-2 pool-crossing TRANSFER, `false` for a
    /// note-PREPARATION. See `prep_layer`/`prep_index`/`crossing` for the per-kind payload
    /// (`MigrationTxKind::Preparation { layer, index }` / `MigrationTxKind::Transfer { crossing }`).
    pub is_transfer: bool,
    /// For a preparation: its dependency-layer index. `-1` when `is_transfer` is `true`.
    pub prep_layer: i64,
    /// For a preparation: its index within `prep_layer`. `-1` when `is_transfer` is `true`.
    pub prep_index: i64,
    /// For a transfer: the funding-note crossing index. `-1` when `is_transfer` is `false`.
    pub crossing: i64,
    /// Lifecycle discriminant: `0` = AwaitingSignature, `1` = Signed, `2` = Proved,
    /// `3` = Broadcast, `4` = Mined, `5` = Invalid (dead by observed event — see
    /// `invalid_reason` for which one; resolved out-of-band via the Attend step).
    pub state: u8,
    /// The height at or after which this transaction is due to broadcast.
    pub scheduled_height: i64,
    /// The height after which this transaction can no longer be mined (ZIP 203); `0` means it
    /// never expires (the engine's own sentinel, carried through unchanged).
    pub expiry_height: i64,
    /// The height it was mined at, once `state == 4` (Mined). `-1` otherwise.
    pub mined_height: i64,
    /// The transaction id (raw internal-order bytes), meaningful only when `has_txid` is `true`.
    pub txid: [u8; 32],
    /// Whether `txid` is populated. Set only while `state == 3` (Broadcast): the engine's own
    /// [`MigrationTxState::Mined`] carries just the mined height, not a txid, so once mined this
    /// goes back to `false` — a verbatim mirror of the engine's own view, not a gap in this
    /// marshaling (see [`zcashlc_migration_transaction_statuses`]'s doc).
    pub has_txid: bool,
    /// Whether the wallet can act on this transaction right now.
    pub ready: bool,
    /// The action available now, when `ready` is `true`: `0` = none, `1` = prove, `2` = broadcast.
    pub action: u8,
    /// Why it is not yet actionable, when waiting (and not already broadcast or mined): `0` =
    /// none, `1` = dependencies, `2` = schedule, `3` = anchor_boundary, `4` = signature,
    /// `5` = expired, `6` = invalid (marked dead by observed event; no chain condition makes it
    /// actionable again).
    pub blocked_on: u8,
    /// Heap array of `depends_on_len` ids of the transactions that must mine before this one can
    /// be built or broadcast (`TransactionStatus::depends_on`).
    pub depends_on: *mut u32,
    pub depends_on_len: usize,
    /// The boundary height this transaction's anchor was drawn against
    /// (`MigrationTransaction::anchor_boundary`), or `-1`. Only ever set for a TRANSFER — a
    /// PREPARATION carries no drawn boundary (it anchors to the wallet's scanned tip at proving
    /// time instead; see `crate::migration_finalize`'s module doc), so this is always `-1` when
    /// `is_transfer` is `false`.
    pub anchor_boundary: i64,
    /// Why the transaction was marked invalid, once `state == 5`: `0` = funding_spent (a funding
    /// note was spent outside the migration), `1` = rejected_invalid (a node rejected the
    /// submission as invalid), `2` = rejected_expired (a node rejected it as expired). `-1`
    /// otherwise — the Invalid state's payload, mirroring how `mined_height`/`txid` carry the
    /// Mined/Broadcast payloads.
    pub invalid_reason: i32,
}

/// A snapshot of every committed migration transaction's LIVE status (element type
/// [`FfiMigrationTransactionStatus`]), as returned by [`zcashlc_migration_transaction_statuses`].
/// `len == 0` means no stored run, or a stored run with no transactions — not an error.
#[repr(C)]
pub struct FfiMigrationTransactionStatuses {
    /// Heap array of `len` rows, in the engine's own `transaction_statuses` order (dependency
    /// order: preparation layers first, then transfers).
    pub ptr: *mut FfiMigrationTransactionStatus,
    pub len: usize,
}

/// A set of animated multi-part QR frame strings for a Keystone batch-signing request. Element
/// order is the wire fragment order — display/scan them in that order.
///
/// This crate's first string-array FFI output type: kept intentionally minimal (unlike
/// [`FfiUnsignedTransferPczts`], there is no paired per-element id or byte blob here, just
/// strings), rather than generalizing [`crate::ffi::BoxedSlice`] (a single binary blob, not an array) or
/// inventing a shared generic array wrapper for a need that has arisen exactly once so far.
#[repr(C)]
pub struct FfiKeystoneQrParts {
    /// Heap array of `len` owned, NUL-terminated UTF-8 strings.
    pub ptr: *mut *mut c_char,
    pub len: usize,
}

impl FfiKeystoneQrParts {
    fn from_parts(parts: Vec<String>) -> anyhow::Result<*mut Self> {
        let items = parts
            .into_iter()
            .map(|part| cstring_raw(&part, "keystone QR part"))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let (ptr, len) = ptr_from_vec(items);
        Ok(Box::into_raw(Box::new(FfiKeystoneQrParts { ptr, len })))
    }
}

/// The result of feeding one scanned QR frame to
/// `zcashlc_migration_keystone_decode_sign_batch_part`, mirroring
/// [`crate::migration_keystone::DecodePartResult`].
///
/// `complete == false` means more frames are needed: `progress` is the 0-100 completion
/// percentage so far, and `data`/the firmware fields are unset (null / `false` / zeroed).
/// `complete == true` means `data` holds the serialized `BatchSignResponse` bytes to pass to
/// `zcashlc_migration_keystone_apply_batch_signatures`, and — when `has_firmware_version` — the
/// signing device's own reported firmware version is in `firmware_major`/`firmware_minor`/
/// `firmware_build`.
#[repr(C)]
pub struct FfiKeystoneBatchDecodeResult {
    pub complete: bool,
    pub progress: u32,
    /// Heap `data_len`-byte serialized `BatchSignResponse` (null unless `complete`).
    pub data: *mut u8,
    pub data_len: usize,
    pub has_firmware_version: bool,
    pub firmware_major: u8,
    pub firmware_minor: u8,
    pub firmware_build: u8,
}

impl FfiKeystoneBatchDecodeResult {
    fn from_parts(result: crate::migration_keystone::DecodePartResult) -> *mut Self {
        let (data, data_len) = match result.data {
            Some(bytes) => ptr_from_vec(bytes),
            None => (ptr::null_mut(), 0),
        };
        let (has_firmware_version, firmware_major, firmware_minor, firmware_build) =
            match result.firmware_version {
                Some([major, minor, build]) => (true, major, minor, build),
                None => (false, 0, 0, 0),
            };
        Box::into_raw(Box::new(FfiKeystoneBatchDecodeResult {
            complete: result.complete,
            progress: result.progress,
            data,
            data_len,
            has_firmware_version,
            firmware_major,
            firmware_minor,
            firmware_build,
        }))
    }
}

/// Build an owned C string from `s`, erroring (rather than panicking across the FFI) if it
/// contains an interior NUL byte.
fn cstring_raw(s: &str, what: &str) -> anyhow::Result<*mut c_char> {
    Ok(CString::new(s)
        .map_err(|_| anyhow!("{what} contains an interior NUL byte"))?
        .into_raw())
}

// ----- free functions -----

/// Frees a [`FfiMigrationAdvanceStep`], including its `prove_targets` batch array (if any).
///
/// # Safety
/// `ptr` must be null or point to a [`FfiMigrationAdvanceStep`] handed out by this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_migration_advance_step(ptr: *mut FfiMigrationAdvanceStep) {
    if !ptr.is_null() {
        let boxed = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(boxed.prove_targets, boxed.prove_targets_len);
        drop(boxed);
    }
}

/// Frees a [`FfiMigrationSyncWakeups`], including every row's `covers` array.
///
/// # Safety
/// `ptr` must be null or point to a [`FfiMigrationSyncWakeups`] handed out by this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_migration_sync_wakeups(ptr: *mut FfiMigrationSyncWakeups) {
    if !ptr.is_null() {
        let boxed = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec_with(boxed.rows, boxed.len, |row| {
            free_ptr_from_vec(row.covers, row.covers_len);
        });
        drop(boxed);
    }
}

/// Frees a [`FfiBlockRateSamples`], including its rows array.
///
/// # Safety
/// `ptr` must be null or point to a [`FfiBlockRateSamples`] handed out by this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_block_rate_samples(ptr: *mut FfiBlockRateSamples) {
    if !ptr.is_null() {
        let boxed = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(boxed.rows, boxed.len);
        drop(boxed);
    }
}

/// Frees a [`FfiMigrationProgress`].
///
/// # Safety
/// `ptr` must be null or point to a [`FfiMigrationProgress`] handed out by this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_migration_progress(ptr: *mut FfiMigrationProgress) {
    if !ptr.is_null() {
        drop(unsafe { Box::from_raw(ptr) });
    }
}

/// Frees a [`FfiNoteSplitProposal`], including its output-values array.
///
/// # Safety
/// `ptr` must be null or point to a [`FfiNoteSplitProposal`] handed out by this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_migration_note_split_proposal(
    ptr: *mut FfiNoteSplitProposal,
) {
    if !ptr.is_null() {
        let boxed = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(boxed.output_values, boxed.output_values_len);
        drop(boxed);
    }
}

/// Frees a [`FfiPreparedTransfer`], including its id string and PCZT bytes.
///
/// # Safety
/// `ptr` must be null or point to a [`FfiPreparedTransfer`] handed out by this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_migration_prepared_transfer(ptr: *mut FfiPreparedTransfer) {
    if !ptr.is_null() {
        let boxed = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(boxed.pczt, boxed.pczt_len);
        drop(boxed);
    }
}

/// Frees a [`FfiMigrationProveOutcome`], including its preparation-txid array.
///
/// # Safety
/// `ptr` must be null or point to a [`FfiMigrationProveOutcome`] handed out by this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_migration_prove_outcome(ptr: *mut FfiMigrationProveOutcome) {
    if !ptr.is_null() {
        let boxed = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(boxed.preparation_txids, boxed.preparation_txids_len);
        drop(boxed);
    }
}

/// Frees a [`FfiMigrationSchedule`], its transfer rows, and its preparation rows (including each
/// preparation's own `depends_on` array).
///
/// # Safety
/// `ptr` must be null or point to a [`FfiMigrationSchedule`] handed out by this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_migration_schedule(ptr: *mut FfiMigrationSchedule) {
    if !ptr.is_null() {
        let boxed = unsafe { Box::from_raw(ptr) };
        // Every transfer row is plain data (ids are `u32`), so freeing the row vector is enough.
        free_ptr_from_vec(boxed.transfers, boxed.transfers_len);
        free_ptr_from_vec_with(boxed.preparations, boxed.preparations_len, |p| {
            free_ptr_from_vec(p.depends_on, p.depends_on_len);
        });
        drop(boxed);
    }
}

/// Frees a [`FfiMigrationRunEstimate`], including its runs array.
///
/// # Safety
/// `ptr` must be null or point to a [`FfiMigrationRunEstimate`] handed out by this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_migration_run_estimate(ptr: *mut FfiMigrationRunEstimate) {
    if !ptr.is_null() {
        let boxed = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(boxed.runs, boxed.runs_len);
        drop(boxed);
    }
}

/// Frees a [`FfiUnsignedTransferPczts`], including every element's id string and PCZT bytes.
///
/// # Safety
/// `ptr` must be null or point to a [`FfiUnsignedTransferPczts`] handed out by this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_migration_unsigned_transfer_pczts(
    ptr: *mut FfiUnsignedTransferPczts,
) {
    if !ptr.is_null() {
        let boxed = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec_with(boxed.ptr, boxed.len, |u| {
            free_ptr_from_vec(u.pczt, u.pczt_len);
        });
        drop(boxed);
    }
}

/// Frees a [`FfiMigrationBatchSizes`].
///
/// # Safety
/// `ptr` must be null or point to a [`FfiMigrationBatchSizes`] handed out by this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_migration_batch_sizes(ptr: *mut FfiMigrationBatchSizes) {
    if !ptr.is_null() {
        let boxed = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(boxed.ptr, boxed.len);
        drop(boxed);
    }
}

/// Frees a [`FfiMigrationTransactionStatuses`] container, including every row's `depends_on`
/// array (the `txid` is an inline `[u8; 32]`, not a heap pointer, so it needs no per-row
/// cleanup of its own).
///
/// # Safety
/// `ptr` must be null or point to a [`FfiMigrationTransactionStatuses`] handed out by this
/// module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_migration_transaction_statuses(
    ptr: *mut FfiMigrationTransactionStatuses,
) {
    if !ptr.is_null() {
        let boxed = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec_with(boxed.ptr, boxed.len, |row| {
            free_ptr_from_vec(row.depends_on, row.depends_on_len);
        });
        drop(boxed);
    }
}

/// Frees a [`FfiKeystoneQrParts`], including every element string.
///
/// # Safety
/// `ptr` must be null or point to a [`FfiKeystoneQrParts`] handed out by this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_migration_keystone_qr_parts(ptr: *mut FfiKeystoneQrParts) {
    if !ptr.is_null() {
        let boxed = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec_with(boxed.ptr, boxed.len, |s| {
            if !s.is_null() {
                unsafe { zcashlc_string_free(*s) }
            }
        });
        drop(boxed);
    }
}

/// Frees a [`FfiKeystoneBatchDecodeResult`], including its data bytes.
///
/// # Safety
/// `ptr` must be null or point to a [`FfiKeystoneBatchDecodeResult`] handed out by this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_migration_keystone_batch_decode_result(
    ptr: *mut FfiKeystoneBatchDecodeResult,
) {
    if !ptr.is_null() {
        let boxed = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(boxed.data, boxed.data_len);
        drop(boxed);
    }
}

// ============================================================================================
// Advance step / progress
// ============================================================================================

/// The account's live spendable Orchard balance (what is still in the old pool).
fn remaining_orchard(ctx: &mut CallCtx) -> anyhow::Result<Zatoshis> {
    let backend = account_migration(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
    use zcash_pool_migration::engine::MigrationBackend;
    let values = backend
        .spendable_orchard_note_values()
        .map_err(|e| anyhow!("reading the account's spendable Orchard notes failed: {e}"))?;
    values
        .into_iter()
        .try_fold(Zatoshis::ZERO, |acc, v| acc + v)
        .ok_or_else(|| anyhow!("spendable Orchard balance overflows"))
}

/// One verified crank of the engine's drive: builds the store adapter, judges dueness at the
/// scanned target plus the FFI's optional `estimated_tip` (`-1` = none), and returns the
/// engine's `Advance` with every determination it made already persisted.
///
/// # Invariant: this is the CONDUIT's crank, and nothing else's
///
/// [`zcashlc_migration_advance_step`] is its only caller, and must stay so. By design,
/// `advance_migration` is the top-level call and every invocation is subservient to it: there is
/// no invocation to prove without *first* having called `advance_migration` — which gives the
/// caller the instruction of what must be proved — and `advance_migration` is never used as an
/// internal call of a more specialized operation.
///
/// So the specialized operations — [`zcashlc_migration_prove_transactions`] and
/// [`zcashlc_migration_take_broadcast_transaction`] — take the instruction the platform already
/// holds and execute it. Cranking from inside one of them would both invert that relationship and
/// double-crank whenever the platform had already advanced to learn what to do: each crank
/// persists the engine's determinations, including the ZIP 318 overdue re-spread, so a hidden
/// second one is not free.
fn drive_advance(
    ctx: &mut CallCtx,
    state: &mut MigrationState,
    estimated_tip: i64,
) -> anyhow::Result<Advance> {
    let targets = dueness_targets(ctx.tip()?, estimated_tip);
    let mut store = account_store(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
    advance_migration(
        &mut store,
        state,
        targets,
        &AdvanceConfig::new(ReorgSettleDepth::new(
            zcash_pool_migration::scheduling::PROVABLE_ANCHOR_DEPTH,
        )),
        // librustzcash #2910: re-spreading a missed broadcast schedule draws fresh
        // inter-broadcast gaps, so advancing needs entropy.
        &mut OsRng,
    )
    .map_err(|e| anyhow!("advancing the migration failed: {e}"))
}

/// Advances the stored run with upstream's public satisfiability API, using scanned and estimated
/// targets plus the provable-anchor reorg-settle depth. Every upstream step marshals onto its own
/// discriminant — Reevaluate and Replan included (bare, as upstream carries them; the collapsed
/// Attend projection is retired).
///
/// Returns NULL **with no error recorded** when `get_migration()` returns `None` — no run is
/// stored, so there is nothing to advance and no step to report. Distinguish that benign NULL
/// from an error NULL via `zcashlc_last_error_length`. A stored TERMINAL run (Complete, or
/// Failed/cancelled) reports the `Complete` step VERBATIM, exactly as upstream's `next_step`
/// does — a cancelled run is never driven further, and is NEVER remapped to any other step; it
/// also carries no outlook (`next_height = -1`), same as every other terminal answer below.
/// (The terminal check here is upstream's own first check, hoisted only so the answer needs no
/// chain-tip lookup — the same answer `next_step` would give, available on a wallet that never
/// saw a chain tip.)
///
/// # Safety
/// See [`open`]. Free the returned pointer with [`zcashlc_free_migration_advance_step`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_advance_step(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    estimated_tip: i64,
) -> *mut FfiMigrationAdvanceStep {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        // A plain load, NOT `reconcile_mined`: `advance_migration` sweeps every in-flight
        // transaction and promotes the ones the wallet's scan has seen mine, so reconciling first
        // would only ask the same question twice.
        let Some(mut state) = ({
            let store = account_store(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
            // `latest_migration`, not the trait's `get_migration`: upstream made the latter
            // PENDING-ONLY, and this conduit's contract still reports `Complete` (below) for a
            // terminal stored run rather than "no run".
            store
                .latest_migration()
                .map_err(|e| anyhow!("migration store read failed: {e}"))?
        }) else {
            // No stored run: NULL with NO error (see the function doc). Returned before any
            // chain-tip lookup, so it holds even before the wallet ever saw a chain tip.
            return Ok(ptr::null_mut());
        };
        // Upstream `next_step`'s own first check, hoisted ahead of the target lookup (not a
        // carve-out — identical answers): a cancelled or failed run reports Complete even on a
        // wallet with no chain tip, and is never driven further. No outlook is knowable either
        // (no targets were even looked up), so this hoisted answer carries `None`, same as every
        // other Complete below.
        if state.is_terminal() {
            return Ok(FfiMigrationAdvanceStep::bare(
                ZCASHLC_ADVANCE_STEP_COMPLETE,
                None,
            ));
        }
        let targets = dueness_targets(ctx.tip()?, estimated_tip);
        // librustzcash #2936: the advance returns the verified step plus a next-wake OUTLOOK
        // (`Advance::next`) — this conduit marshals both, the step via the borrow `.step()`
        // returns and the outlook via `.next()`, onto every arm below.
        let advance = drive_advance(&mut ctx, &mut state, estimated_tip)?;
        let next = advance.next();
        Ok(match advance.step() {
            // Both are BARE: neither upstream step names a transaction — Replan is a verdict
            // about the RUN (its unsatisfiable share passed the committed threshold), Reevaluate
            // asks for a sync and nothing else — and the retired Attend collapse synthesised an
            // id at least one of them never had. The platform's per-row detail, when it wants
            // one, is `transaction_statuses`' own blockers, not this step.
            AdvanceStep::Replan => FfiMigrationAdvanceStep::bare(ZCASHLC_ADVANCE_STEP_REPLAN, next),
            AdvanceStep::Reevaluate => {
                FfiMigrationAdvanceStep::bare(ZCASHLC_ADVANCE_STEP_REEVALUATE, next)
            }
            AdvanceStep::Prove { transactions } => {
                FfiMigrationAdvanceStep::prove(&state, transactions, targets, next)
            }
            AdvanceStep::Broadcast { id } => {
                FfiMigrationAdvanceStep::with_id(ZCASHLC_ADVANCE_STEP_BROADCAST, *id, next)
            }
            AdvanceStep::Rebuild { id } => {
                FfiMigrationAdvanceStep::with_id(ZCASHLC_ADVANCE_STEP_REBUILD, *id, next)
            }
            AdvanceStep::Waiting => {
                FfiMigrationAdvanceStep::bare(ZCASHLC_ADVANCE_STEP_WAITING, next)
            }
            AdvanceStep::Complete => {
                FfiMigrationAdvanceStep::bare(ZCASHLC_ADVANCE_STEP_COMPLETE, next)
            }
        })
    });
    unwrap_exc_or_null(res)
}

/// Migration progress. On success the returned pointer is non-null; a NULL return signals an
/// error. The contract:
///
/// - A stored run that is NOT terminal → present: `completed` = its Transfer rows `Mined`,
///   `total` = its Transfer rows, `next_transfer_ready_at_height` = the minimum scheduled height
///   over transfers still awaiting broadcast (`AwaitingSignature`/`Signed`/`Proved` ONLY — a
///   `Broadcast` row is already in the mempool and never sets this field, the F6 rule),
///   `is_immediate` = `false`.
/// - No stored run, OR a terminal one (`Complete` or `Failed`) → the account's immediate-run row
///   is consulted instead: unmined and not past its expiry bound → present as `0` of `1` with
///   `is_immediate` = `true` (and no next-ready height); mined, expired, or no row at all →
///   ABSENT (`is_present == false`). A terminal engine run therefore reports absent.
///
/// `remaining_orchard_value` carries the account's live spendable Orchard balance whenever the
/// snapshot is present.
///
/// # Safety
/// See [`open`]. Free the returned pointer with [`zcashlc_free_migration_progress`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_progress(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> *mut FfiMigrationProgress {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open_read(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let engine_state = {
            let store = account_store(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
            store
                .get_migration()
                .map_err(|e| anyhow!("migration store read failed: {e}"))?
        };
        if let Some(state) = engine_state.as_ref().filter(|state| !state.is_terminal()) {
            let (completed, total, next_ready) = active_run_progress(state);
            return Ok(Box::into_raw(Box::new(FfiMigrationProgress {
                is_present: true,
                completed_transfers: completed,
                total_transfers: total,
                remaining_orchard_value: zat_to_i64(remaining_orchard(&mut ctx)?),
                next_transfer_ready_at_height: height_opt_to_i64(next_ready),
                is_immediate: false,
            })));
        }
        // No active engine run (none stored, or terminal): the immediate lane is the only thing
        // left that could report progress.
        let immediate_row = immediate_run_row_if_table_exists(&ctx.store_conn, &ctx.account_bytes)
            .map_err(|e| anyhow!("immediate run read failed: {e}"))?;
        let Some(row) = immediate_row else {
            // No row either: absent, and (crucially) with no chain-tip lookup, which a
            // not-yet-synced wallet lacks.
            return Ok(Box::into_raw(Box::new(FfiMigrationProgress::absent())));
        };
        let tip = ctx.tip()?;
        let run = resolve_immediate_run(&ctx.store_conn, row, tip)
            .map_err(|e| anyhow!("wallet transaction lookup failed: {e}"))?;
        let value = if immediate_run_pending(&run, tip) {
            FfiMigrationProgress {
                is_present: true,
                completed_transfers: 0,
                total_transfers: 1,
                remaining_orchard_value: zat_to_i64(remaining_orchard(&mut ctx)?),
                next_transfer_ready_at_height: -1,
                is_immediate: true,
            }
        } else {
            FfiMigrationProgress::absent()
        };
        Ok(Box::into_raw(Box::new(value)))
    });
    unwrap_exc_or_null(res)
}

/// The stored run's minimal sync/proving wake-up schedule, as of the SCANNED chain tip — a
/// verbatim marshal of upstream `MigrationState::sync_wakeup_schedule(current_tip,
/// &WakeupParams::DEFAULT, OsRng)`: each row is a height at which to wake, sync, and prove, plus
/// the transfer ids it is responsible for proving. Wake-up heights are floored at the tip (a row
/// at exactly the tip means "right now"); jitter is re-drawn on every call, so two calls may
/// legitimately differ — recompute (and re-register with the OS) after any state change rather
/// than caching. Pure read of the PERSISTED run (read-only connections; no reconcile): a Broadcast
/// row the wallet has since scanned as mined is reported Mined only after a write lane — the
/// advance-step engine sweep, the prove sweep, or a delivery serve — persists the promotion; a
/// platform drives one of those on its open-lane passes, sync edges, and UI-refresh passes, so a
/// live run's reads trail a just-mined broadcast by at most one such pass.
///
/// No stored run, a terminal run, or no transfer still needing a proof returns the EMPTY schedule
/// (`len == 0`, valid pointer) — not an error. A stored transfer that admits NO valid wake-up
/// height (broadcast not at least two blocks above its anchor boundary — an inconsistent stored
/// schedule) errors with the stable `MIGRATION_WAKEUP_INFEASIBLE:<id>` message.
///
/// # Safety
/// See [`open`]. Free the returned pointer with [`zcashlc_free_migration_sync_wakeups`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_sync_wakeups(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> *mut FfiMigrationSyncWakeups {
    let res = catch_panic(|| {
        let empty = || {
            Box::into_raw(Box::new(FfiMigrationSyncWakeups {
                rows: ptr::null_mut(),
                len: 0,
            }))
        };
        let mut ctx = unsafe { open_read(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let Some(state) = ({
            let store = account_store(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
            store
                .get_migration()
                .map_err(|e| anyhow!("migration store read failed: {e}"))?
        }) else {
            return Ok(empty());
        };
        if state.is_terminal() {
            return Ok(empty());
        }
        // Upstream's contract: unlike the sibling queries (which take `target = tip + 1`),
        // `sync_wakeup_schedule` takes the TIP itself — wake-up heights are floored at the tip,
        // and expiry is judged at `tip + 1` internally.
        let tip = ctx.tip()?;
        let wakeups = state
            .sync_wakeup_schedule(tip, &WakeupParams::DEFAULT, &mut OsRng)
            .map_err(|e| match e {
                WakeupScheduleError::InfeasibleTransfer(id) => wakeup_infeasible(id),
            })?;
        let rows: Vec<FfiMigrationSyncWakeup> = wakeups
            .into_iter()
            .map(|wakeup| {
                let covers: Vec<u32> = wakeup.covers().iter().map(|id| u32::from(*id)).collect();
                let (covers, covers_len) = ptr_from_vec(covers);
                FfiMigrationSyncWakeup {
                    height: i64::from(u32::from(wakeup.height())),
                    covers,
                    covers_len,
                }
            })
            .collect();
        let (rows, len) = ptr_from_vec(rows);
        Ok(Box::into_raw(Box::new(FfiMigrationSyncWakeups {
            rows,
            len,
        })))
    });
    unwrap_exc_or_null(res)
}

/// The most recently scanned blocks' `(height, header time)` samples from the wallet database's
/// `blocks` table, at most `window` rows, returned ASCENDING by height — the raw inputs the
/// platform's measured-block-rate estimator projects an ESTIMATED chain tip from (fed back into
/// [`zcashlc_migration_has_overdue_transfers`] / [`zcashlc_migration_advance_step`] as
/// `estimated_tip`). A read-only, best-effort read of scanned-block metadata, mirroring the
/// Android SDK's `blockRateSamplesNative`: a wallet with no scanned blocks yet — no readable
/// `blocks` table, or no wallet-database file at all (the read-only open cannot create one) —
/// returns the EMPTY list (`len == 0`, valid pointer), never an error. A read that fails for any
/// other reason is coerced to the same empty answer but logged (`tracing::warn!`), so it cannot
/// silently starve the platform's estimator forever.
///
/// # Safety
/// - `db_data` must be valid for reads of `db_data_len` bytes and encode a filesystem path.
///
/// Free the returned pointer with [`zcashlc_free_block_rate_samples`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_block_rate_samples(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
    window: u32,
) -> *mut FfiBlockRateSamples {
    let res = catch_panic(|| {
        let _network = parse_network(network_id)?;
        let db_path = PathBuf::from(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(db_data, db_data_len)
        }));
        let empty = || {
            let (rows, len) = ptr_from_vec(Vec::new());
            Box::into_raw(Box::new(FfiBlockRateSamples { rows, len }))
        };
        let conn = match Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) {
            Ok(conn) => conn,
            // A missing wallet-DB file is the same benign "no scanned blocks yet" answer as a
            // missing `blocks` table (A12): a read-only open cannot create the file, so a wallet
            // that was never initialized here answers EMPTY, not error. Every other open failure
            // is real and still errors.
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::CannotOpen =>
            {
                return Ok(empty());
            }
            Err(e) => return Err(anyhow!("block-rate read-only open failed: {e}")),
        };
        conn.busy_timeout(crate::WALLET_DB_BUSY_TIMEOUT)
            .map_err(|e| anyhow!("block-rate busy_timeout failed: {e}"))?;
        // Best-effort projection input, never load-bearing (matching Android): a failing read (no
        // `blocks` table on a fresh wallet, a transient lock) maps to "no samples", not an error
        // — but logged (A12), so a persistently failing read shows up in diagnostics instead of
        // presenting as a wallet that simply never scanned.
        let samples: Vec<FfiBlockRateSample> = conn
            .prepare(
                "SELECT height, time FROM (
                    SELECT height, time FROM blocks ORDER BY height DESC LIMIT ?1
                 ) ORDER BY height ASC",
            )
            .and_then(|mut stmt| {
                stmt.query_map([i64::from(window)], |row| {
                    Ok(FfiBlockRateSample {
                        height: row.get(0)?,
                        unix_time: row.get(1)?,
                    })
                })
                .and_then(Iterator::collect)
            })
            .unwrap_or_else(|e| {
                tracing::warn!("block-rate sample read failed; answering no samples: {e}");
                Vec::new()
            });
        let (rows, len) = ptr_from_vec(samples);
        Ok(Box::into_raw(Box::new(FfiBlockRateSamples { rows, len })))
    });
    unwrap_exc_or_null(res)
}

/// An empty transaction-statuses container: the "no stored run" / "stored run with no
/// transactions" answer (mirrors [`encode_empty_schedule`]'s convention for the schedule DTO).
fn encode_empty_transaction_statuses() -> *mut FfiMigrationTransactionStatuses {
    Box::into_raw(Box::new(FfiMigrationTransactionStatuses {
        ptr: ptr::null_mut(),
        len: 0,
    }))
}

/// Preserve the existing Swift-facing reason vocabulary while upstream models the determination
/// orthogonally to lifecycle state. A directly or transitively spent input remains
/// `funding_spent`; other unsatisfiable causes map to the generic invalid-artifact case.
fn unsatisfiable_kind_to_legacy_reason(kind: UnsatisfiableKind) -> i32 {
    match kind {
        UnsatisfiableKind::InputsSpent | UnsatisfiableKind::Inherited => 0,
        UnsatisfiableKind::InputsInvalidated | UnsatisfiableKind::AnchorInvalidated => 1,
        _ => 1,
    }
}

/// Marshal one engine [`TransactionStatus`] row verbatim into the FFI DTO, joining in
/// `anchor_boundary` from `stored_rows` — the caller's id-keyed map over the stored
/// [`MigrationTransaction`] rows, built ONCE per call (U2; `TransactionStatus` itself carries no
/// boundary — only the stored row does) — see [`zcashlc_migration_transaction_statuses`] for the
/// field-by-field contract.
fn encode_transaction_status(
    ts: &TransactionStatus,
    stored_rows: &std::collections::HashMap<MigrationTransferId, &MigrationTransaction>,
) -> FfiMigrationTransactionStatus {
    let (is_transfer, prep_layer, prep_index, crossing) = match ts.kind() {
        MigrationTxKind::Preparation { layer, index } => (false, layer as i64, index as i64, -1i64),
        MigrationTxKind::Transfer { crossing } => (true, -1i64, -1i64, crossing as i64),
    };
    let needs_attention = matches!(
        ts.blocked_on(),
        Some(Blocker::Unsatisfiable | Blocker::AwaitingReevaluation)
    );
    let state = if needs_attention {
        5
    } else {
        match ts.state() {
            MigrationTxState::AwaitingSignature => 0,
            MigrationTxState::Signed => 1,
            MigrationTxState::Proved => 2,
            MigrationTxState::Broadcast { .. } => 3,
            MigrationTxState::Mined { .. } => 4,
        }
    };
    // The Invalid state's payload, marshaled like the other per-state payloads (`mined_height`
    // for Mined, `txid` for Broadcast).
    let invalid_reason = ts
        .unsatisfiable_kind()
        .map(unsatisfiable_kind_to_legacy_reason)
        .unwrap_or_else(|| {
            if ts.blocked_on() == Some(Blocker::AwaitingReevaluation) {
                1
            } else {
                -1
            }
        });
    let action = match ts.action() {
        None => 0,
        Some(NextAction::Prove) => 1,
        Some(NextAction::Broadcast) => 2,
    };
    let blocked_on = match ts.blocked_on() {
        None => 0,
        Some(Blocker::Dependencies) => 1,
        Some(Blocker::Schedule) => 2,
        Some(Blocker::AnchorBoundary) => 3,
        Some(Blocker::Signature) => 4,
        Some(Blocker::Expired) => 5,
        Some(Blocker::Unsatisfiable | Blocker::AwaitingReevaluation) => 6,
        Some(Blocker::ExpiryImminent) => 2,
    };
    let (txid, has_txid) = match ts.txid() {
        Some(txid) => (<[u8; 32]>::from(txid), true),
        None => ([0u8; 32], false),
    };
    let depends_on: Vec<u32> = ts.depends_on().iter().map(|id| u32::from(*id)).collect();
    let (depends_on, depends_on_len) = ptr_from_vec(depends_on);
    let anchor_boundary =
        height_opt_to_i64(stored_rows.get(&ts.id()).and_then(|t| t.anchor_boundary()));
    FfiMigrationTransactionStatus {
        id: u32::from(ts.id()),
        is_transfer,
        prep_layer,
        prep_index,
        crossing,
        state,
        scheduled_height: i64::from(u32::from(ts.scheduled_height())),
        expiry_height: i64::from(u32::from(ts.expiry_height())),
        mined_height: height_opt_to_i64(ts.mined_height()),
        txid,
        has_txid,
        ready: ts.ready(),
        action,
        blocked_on,
        depends_on,
        depends_on_len,
        anchor_boundary,
        invalid_reason,
    }
}

/// The LIVE status of every committed migration transaction, keyed by its stable id — a verbatim
/// marshal of `MigrationState::transaction_statuses(target)` at `target = tip + 1` (see
/// [`CallCtx::target`]), the engine's own per-transaction view a wallet renders progress from and
/// decides what to sign/prove/broadcast next. Pure read of the PERSISTED run (read-only
/// connections; no reconcile): a Broadcast row the wallet has since scanned as mined is reported
/// Mined only after a write lane — the advance-step engine sweep, the prove sweep, or a delivery
/// serve — persists the promotion; a platform drives one of those on its open-lane passes, sync
/// edges, and UI-refresh passes, so a live run's reads trail a just-mined broadcast by at most one
/// such pass. No stored run, or a stored run with no transactions, returns an EMPTY container
/// (`len == 0`) — not an error, the same convention as [`encode_empty_schedule`].
///
/// This is a pure read: unlike [`zcashlc_migration_advance_step`] it never drives anything — a
/// `Signed` row ready to prove is reported via `ready`/`action` (`action == 1`), not silently
/// advanced to `Proved`.
///
/// # Safety
/// See [`open`]. Free the returned pointer with [`zcashlc_free_migration_transaction_statuses`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_transaction_statuses(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> *mut FfiMigrationTransactionStatuses {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open_read(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let Some(state) = ({
            let store = account_store(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
            // `latest_migration`, not the pending-only `get_migration`: unlike the sibling reads
            // (whose terminal answer equals their no-run answer), this view keeps rendering a
            // TERMINAL run's rows — a completed migration's mined transfers stay listed.
            store
                .latest_migration()
                .map_err(|e| anyhow!("migration store read failed: {e}"))?
        }) else {
            return Ok(encode_empty_transaction_statuses());
        };
        if state.transactions().is_empty() {
            return Ok(encode_empty_transaction_statuses());
        }
        let targets = DuenessTargets::at(ctx.target()?);
        // The id-keyed row map the per-status encoding joins `anchor_boundary` from — built once
        // (U2), not re-searched linearly per row.
        let stored_rows: std::collections::HashMap<MigrationTransferId, &MigrationTransaction> =
            state.transactions().iter().map(|t| (t.id(), t)).collect();
        let rows: Vec<FfiMigrationTransactionStatus> = state
            .transaction_statuses(targets)
            .iter()
            .map(|ts| encode_transaction_status(ts, &stored_rows))
            .collect();
        let (ptr, len) = ptr_from_vec(rows);
        Ok(Box::into_raw(Box::new(FfiMigrationTransactionStatuses {
            ptr,
            len,
        })))
    });
    unwrap_exc_or_null(res)
}

/// Whether the account's balance needs preparation (note-split) transactions before it can
/// migrate. Plans fresh against the live balance (and caches the preview). Returns `false` both
/// when no split is needed and when there is nothing to migrate at all; returns `false` on error
/// too (see `zcashlc_last_error_message` — the Swift layer disambiguates).
///
/// # Safety
/// See [`open`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_is_note_split_needed(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        // `compute_plan`, NOT `plan_and_cache`: this is a pure peek — caching its throwaway plan
        // would supersede the handle of a proposal the user is currently reviewing.
        Ok(match compute_plan(&mut ctx)? {
            Some((plan, _)) => plan.preparation().transaction_count() > 0,
            None => false,
        })
    });
    unwrap_exc_or(res, false)
}

/// Whether any transaction of the stored run is due-and-unbroadcast — that is, whether the
/// delivery lane has actionable work: an already-`Proved` transaction due for broadcast, or a
/// due, dependency-satisfied, prove-ready `Signed` one whose proof the platform's sweep
/// ([`zcashlc_migration_prove_transactions`]) is expected to produce. Proofs are assumed to
/// succeed: a transiently unwitnessable anchor defers the delivery, not this report. A row
/// awaiting an EXTERNAL signature is not delivery work (the signing ceremony advances it). Returns
/// `false` on error (see `zcashlc_last_error_message`).
///
/// A display read over upstream's public status view (see [`due_assuming_proving`]), not a
/// prediction of the lane: [`zcashlc_migration_advance_step`] is the verified drive, which
/// additionally consults the store's oracle and may re-spread a slept-through backlog, so `true`
/// here means "the run has work the platform owes it", not "the next advance will name that
/// row".
///
/// NOT a sync gate: a `Signed` row it counts (due, but its proof not produced yet) must never
/// hold sync hostage — it needs MORE syncing and proving, not a broadcast session, so a gate keyed
/// on this query would wedge.
///
/// `estimated_tip` (`-1` = disabled) is the platform's wall-clock chain-tip projection (from
/// [`zcashlc_migration_block_rate_samples`]). Its handling is upstream's
/// [`DuenessTargets`] rule — the estimate may only ACCELERATE scheduled-height due-ness, never
/// decide expiry or boundary settledness (both stay on the SCANNED tip) — see the section
/// comment above [`estimated_target_from_tip`].
///
/// # Safety
/// See [`open`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_has_overdue_transfers(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    estimated_tip: i64,
) -> bool {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open_read(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let Some(state) = ({
            let store = account_store(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
            store
                .get_migration()
                .map_err(|e| anyhow!("migration store read failed: {e}"))?
        }) else {
            return Ok(false);
        };
        if state.is_terminal() {
            return Ok(false);
        }
        let targets = dueness_targets(ctx.tip()?, estimated_tip);
        Ok(due_assuming_proving(&state, targets).is_some())
    });
    unwrap_exc_or(res, false)
}

/// Whether the stored, NON-TERMINAL run has a transaction that cannot proceed: one the engine
/// reports unsatisfiable or awaiting reevaluation (a spend of its inputs discovered by the store's
/// satisfiability oracle from scanned wallet data, or a broadcast rejection reported by
/// [`zcashlc_migration_record_transfer_result`]), or an expired, unmined one. A terminal run
/// (Complete, or Failed/cancelled) answers `false`: its attention lifecycle is over — cancelling
/// IS the out-of-band resolution the invalid state asks for. Returns `false` on error (see
/// `zcashlc_last_error_message`).
///
/// # Safety
/// See [`open`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_has_invalid_transfers(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open_read(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let Some(state) = ({
            let store = account_store(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
            store
                .get_migration()
                .map_err(|e| anyhow!("migration store read failed: {e}"))?
        }) else {
            return Ok(false);
        };
        if state.is_terminal() {
            return Ok(false);
        }
        // Derived from the engine state itself — the same rows `AdvanceStep::Attend` is
        // surfaced from, so this answer and the drive loop's cannot disagree.
        let target = ctx.target()?;
        if state
            .transaction_statuses(DuenessTargets::at(target))
            .iter()
            .any(|status| {
                matches!(
                    status.blocked_on(),
                    Some(Blocker::Unsatisfiable | Blocker::AwaitingReevaluation)
                )
            })
        {
            return Ok(true);
        }
        // The engine's expiry predicate is defined over `target = tip + 1`, not the raw tip (see
        // `CallCtx::target`); membership in `expired_transactions` already excludes `Mined` (and
        // `Invalid`) rows and treats `expiry_height == 0` as "never expires".
        Ok(!state
            .expired_transactions(DuenessTargets::at(target))
            .is_empty())
    });
    unwrap_exc_or(res, false)
}

/// The note-split preview for the account's live balance: the preparation output values and the
/// preparation fees. Plans fresh (and caches the preview for the later commit). An empty proposal
/// (zero outputs) means there is nothing to migrate.
///
/// # Safety
/// See [`open`]. Free the returned pointer with [`zcashlc_free_migration_note_split_proposal`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_prepare_note_split(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> *mut FfiNoteSplitProposal {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let (values, fee, proposal_handle) = match plan_and_cache(&mut ctx, false)? {
            Some((plan, _, handle)) => {
                let split = plan.denominations();
                let values: Vec<i64> = split
                    .migration_outputs()
                    .iter()
                    .map(|v| zat_to_i64(*v))
                    .collect();
                (values, zat_to_i64(split.prep_fees()), handle)
            }
            None => (Vec::new(), 0, 0),
        };
        let (output_values, output_values_len) = ptr_from_vec(values);
        Ok(Box::into_raw(Box::new(FfiNoteSplitProposal {
            output_values,
            output_values_len,
            fee,
            proposal_handle,
        })))
    });
    unwrap_exc_or_null(res)
}

/// Commits the previewed migration (signing EVERY transaction — preparation and transfers — in
/// one pass with the spending key), then proves and returns the first preparation transaction for
/// immediate broadcast. If a matching non-terminal run is already stored, resumes it instead of
/// recommitting (the retry path); a terminal stored run is replaced (the sequential-runs path).
///
/// `proposal_handle` identifies the cached plan to commit — the one whose proposal
/// (`FfiNoteSplitProposal::proposal_handle`) the platform displayed. A fresh commit fails with
/// `MIGRATION_PLAN_STALE` when that plan is missing or superseded, so this can only ever sign
/// exactly what the user reviewed; the resume path does not consult the handle (see
/// [`commit_or_resume`]).
///
/// # Safety
/// See [`open`]; `usk_ptr` must be valid for reads of `usk_len` bytes.
/// Free the returned pointer with [`zcashlc_free_migration_prepared_transfer`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_sign_note_split(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    proposal_handle: u64,
    usk_ptr: *const u8,
    usk_len: usize,
) -> *mut FfiPreparedTransfer {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        // The decoded spending key is handed straight to the engine's signing entry point, which
        // derives its own full viewing key and checks it against the account's before building
        // anything. It never reaches the adapter: no migration type holds spend authority, so the
        // key is live only for this call.
        let usk = unsafe { crate::decode_usk(usk_ptr, usk_len)? };

        let (mut state, _) =
            commit_or_resume(&mut ctx, Some(usk.orchard()), false, proposal_handle)?;

        // The preparation transaction to prove now and return for immediate broadcast (see
        // [`ceremony_preparation_pick`] for which row and why). Proven now, against the wallet's
        // scanned-tip anchor, and returned for the platform's immediate broadcast — this lane
        // exists to hand back something to broadcast, so its proof cannot wait for a sweep.
        // Remaining preparation transactions are proved by
        // `zcashlc_migration_prove_transactions` and
        // ride the normal delivery lane as they come due.
        let target = ctx.target()?;
        let first_prep =
            ceremony_preparation_pick(&state, DuenessTargets::at(target)).ok_or_else(|| {
                anyhow!("the committed migration has no broadcastable preparation transaction")
            })?;
        if !prove_one(&mut ctx, &mut state, first_prep)? {
            return Err(anyhow!(
                "the note split is not yet finalizable — its funding note is not witnessable; sync first"
            ));
        }
        // Through the SAME broadcast seam the delivery executor uses, so the ceremony's handback is
        // a finalized consensus transaction the platform submits as-is and the wallet's own record
        // of it binds here rather than after the submit. This lane is deliberately pre-schedule —
        // the commit persists the run, the prove above stores the wallet record of the proof, and
        // the platform records the broadcast — which is why it hands a transaction back at all
        // instead of deferring to the drive, whose window for this preparation opens a few blocks
        // ahead.
        let (raw, txid) = serve_for_broadcast(&mut ctx, &state, first_prep)?;
        FfiPreparedTransfer::from_parts(first_prep, txid, raw)
    });
    unwrap_exc_or_null(res)
}

/// The residual (zatoshi) that stays in Orchard after the migration: the note split's change,
/// below the migratable dust floor. Pre-commit this is read from a fresh preview; post-commit
/// from the stored run. Returns `-1` for "none" (and on error — see `zcashlc_last_error_message`;
/// the Swift layer disambiguates).
///
/// # Safety
/// See [`open`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_residual_after_migration(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> i64 {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        {
            let store = account_store(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
            if let Some(state) = store
                .get_migration()
                .map_err(|e| anyhow!("migration store read failed: {e}"))?
            {
                if !state.is_terminal() {
                    return Ok(state.denominations().change().map_or(-1, zat_to_i64));
                }
            }
        }
        // `compute_plan`, NOT `plan_and_cache`: this is a pure peek — caching its throwaway plan
        // would supersede the handle of a proposal the user is currently reviewing.
        Ok(match compute_plan(&mut ctx)? {
            Some((plan, _)) => plan.denominations().change().map_or(-1, zat_to_i64),
            None => -1,
        })
    });
    unwrap_exc_or(res, -1)
}

/// Locks EVERY currently-spendable, not-already-locked legacy-Orchard note of the account until
/// explicit unlock, and returns the TOTAL LOCKED VALUE in zatoshi. `0` is a legitimate result
/// (nothing was spendable, or everything spendable is already locked); `-1` signals an error (see
/// `zcashlc_last_error_message`).
///
/// Intended to be called when a migration run reaches `Complete` to lock the sub-threshold
/// residual that stays in Orchard (the "Lock balance" choice): the lock expiry is permanent
/// (`u32::MAX`), so no chain height ever releases it — only an explicit
/// `zcashlc_migration_unlock_residual` does. Note selection excludes already-locked notes, so
/// repeating the call is idempotent-additive: it locks only notes that became spendable since
/// (and returns only their value). Locks are keyed to the deterministic per-account
/// [`residual_lock_owner`], so a retry after a crash between selection and locking re-locks
/// under the same owner instead of conflicting with itself. A concurrent-lock race (another
/// caller locked one of the selected notes between selection and locking) surfaces as an error
/// (`LockError::LockFailure`); nothing is partially locked and the caller may retry.
///
/// # Safety
/// See [`open`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_lock_residual(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> i64 {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        // Selection targets the next block, mirroring the adapter's own selection target.
        let target = TargetHeight::from(u32::from(ctx.tip()?) + 1);
        let received = ctx
            .wallet
            .select_unspent_notes(
                ctx.account,
                &[ShieldedPool::Orchard],
                target,
                &[],
                LockFilter::Policy(&LockedInputPolicy::Exclude),
            )
            .map_err(|e| anyhow!("spendable-note selection failed: {e}"))?;
        let mut refs = Vec::new();
        let mut total = Zatoshis::ZERO;
        for rn in received.orchard() {
            refs.push(OutputRef::new(
                *rn.txid(),
                PoolType::Shielded(ShieldedPool::Orchard),
                u32::from(rn.output_index()),
            ));
            let value = Zatoshis::from_u64(rn.note().value().inner())
                .map_err(|_| anyhow!("a spendable note has an out-of-range value"))?;
            total = (total + value).ok_or_else(|| anyhow!("locked Orchard balance overflows"))?;
        }
        if refs.is_empty() {
            return Ok(0);
        }
        ctx.wallet
            .lock_outputs(
                &refs,
                residual_lock_owner(ctx.account),
                BlockHeight::from(u32::MAX),
            )
            .map_err(|e| anyhow!("locking the migration residual failed: {e}"))?;
        Ok(zat_to_i64(total))
    });
    unwrap_exc_or(res, -1)
}

/// The deterministic [`LockOwner`] under which [`zcashlc_migration_lock_residual`] locks the
/// account's residual notes: the 16 account-UUID bytes followed by a fixed 16-byte tag. A
/// stable owner keeps re-locking idempotent across retries (a same-owner re-lock refreshes the
/// permanent expiry instead of failing as a conflict), and cannot collide with a txid-derived
/// owner, which occupies all 32 bytes with a transaction hash.
fn residual_lock_owner(account: AccountUuid) -> LockOwner {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&account.expose_uuid().into_bytes());
    bytes[16..].copy_from_slice(b"zodl.residual.lk");
    LockOwner::new(bytes)
}

/// Unlocks the account's locked outputs — the release half of
/// `zcashlc_migration_lock_residual` — and returns the number of outputs unlocked (`0` when
/// nothing was locked; `-1` signals an error, see `zcashlc_last_error_message`).
///
/// Clears ALL locks held for the account, regardless of expiry or owner. That blanket clear is
/// safe here because this SDK still creates no proposal- or transfer-scoped output locks (every
/// propose path here runs with locking off, and engine-built migration transactions carry no
/// lock owner): the only locks an account can hold are the permanent residual locks placed by
/// `zcashlc_migration_lock_residual`. Revisit this if any propose path ever starts passing a
/// lock request — a blanket clear would then release in-flight proposal locks too.
///
/// # Safety
/// See [`open`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_unlock_residual(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> i64 {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let cleared = ctx
            .wallet
            .clear_locked_outputs(ctx.account)
            .map_err(|e| anyhow!("unlocking the migration residual failed: {e}"))?;
        Ok(cleared as i64)
    });
    unwrap_exc_or(res, -1)
}

/// Estimates how the account migrates its whole spendable balance: the number of migration RUNS
/// ("rounds") it takes, and for each run BOTH what it migrates (the note-split crossings) and
/// what preparing it costs (the note-preparation layers and transactions), so the platform can
/// preview and compare the two before anything is planned or committed. A balance beyond one
/// run's capacity migrates over several runs; the estimate depends on the wallet's NOTE
/// STRUCTURE, not just its total value (each run is decomposed with the real planners, and the
/// notes a run spends plus the residuals it leaves form the next run's structure).
///
/// An external signer's per-session capacity is NOT part of the estimate: the SDK evaluates
/// signing sessions from the returned per-run transaction counts for any signer capacity,
/// without re-running the planners. A zero (or fully sub-quantum) balance yields the ZERO-RUN
/// estimate (`runs_len == 0`) — a legitimate result, not an error. NULL signals an error (see
/// `zcashlc_last_error_message`).
///
/// # Safety
/// See [`open`]. Free the returned pointer with [`zcashlc_free_migration_run_estimate`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_estimate_runs(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> *mut FfiMigrationRunEstimate {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let backend = account_migration(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
        let mut rng = OsRng;
        let estimate = match engine::estimate_migration_runs(&ctx.network, &backend, &mut rng) {
            Ok(estimate) => Some(estimate),
            // The estimator answers a zero balance with the zero-run estimate rather than this
            // error, so this arm should never fire; map it to the same zero-run answer anyway,
            // for symmetry with the propose path's empty schedule.
            Err(engine::MigrationError::NothingToMigrate) => None,
            Err(e) => return Err(anyhow!("Error estimating migration runs: {e}")),
        };
        let (runs, final_residual) = match &estimate {
            Some(est) => (
                est.runs()
                    .iter()
                    .map(|run| {
                        Ok(FfiRunEstimate {
                            migratable: zat_to_i64(run.migratable()),
                            crossings: count_to_u32(run.crossings(), "crossings")?,
                            prep_layers: count_to_u32(run.prep_layers(), "prep-layers")?,
                            prep_transactions: count_to_u32(
                                run.prep_transactions(),
                                "prep-transactions",
                            )?,
                            actions: run.actions(),
                            keystone_rounds: count_to_u32(
                                run.signing_rounds(SigningRoundBudget::KEYSTONE),
                                "keystone signing rounds",
                            )?,
                        })
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?,
                zat_to_i64(est.final_residual()),
            ),
            None => (Vec::new(), 0),
        };
        let (runs, runs_len) = ptr_from_vec(runs);
        Ok(Box::into_raw(Box::new(FfiMigrationRunEstimate {
            runs,
            runs_len,
            final_residual,
        })))
    });
    unwrap_exc_or_null(res)
}

/// The migration schedule preview for the account's live balance, in chronological broadcast
/// order. Plans fresh (drawing new ZIP 318 randomness) and caches the preview — a later commit
/// signs exactly this plan. An EMPTY schedule means there is nothing to migrate: after a
/// completed run this is the "does anything remain" answer.
///
/// # Safety
/// See [`open`]. Free the returned pointer with [`zcashlc_free_migration_schedule`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_propose_transfers(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> *mut FfiMigrationSchedule {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        match plan_and_cache(&mut ctx, false)? {
            Some((plan, reference_height, handle)) => {
                encode_schedule_from_plan(&plan, reference_height, handle)
            }
            None => Ok(encode_empty_schedule()),
        }
    });
    unwrap_exc_or_null(res)
}

/// Commits the previewed migration with the spending key if nothing is committed yet (covering
/// the no-split lane); when a matching non-terminal run is already stored (the normal case — the
/// note-split submission committed it), succeeds as a no-op.
///
/// `proposal_handle` identifies the cached plan to commit — the one whose schedule
/// (`FfiMigrationSchedule::proposal_handle`) the platform displayed. No schedule fields cross
/// the boundary: a fresh commit fails with `MIGRATION_PLAN_STALE` when the identified plan is
/// missing or superseded, so it can only ever sign exactly the schedule the user reviewed. The
/// resume/no-op case does not consult the handle — the stored run is durable, already
/// handle-verified state (see [`commit_or_resume`]).
///
/// # Safety
/// See [`open`]; `usk_ptr` must be valid for reads of `usk_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_sign_and_store_schedule(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    proposal_handle: u64,
    usk_ptr: *const u8,
    usk_len: usize,
) -> bool {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let usk = unsafe { crate::decode_usk(usk_ptr, usk_len)? };
        commit_or_resume(&mut ctx, Some(usk.orchard()), false, proposal_handle)?;
        Ok(true)
    });
    unwrap_exc_or(res, false)
}

/// Proves the NAMED migration transactions — the instruction a prior
/// [`zcashlc_migration_advance_step`] call returned as its PROVE step — persisting each proof, and
/// returns a [`FfiMigrationProveOutcome`]: how many were proved, and THE TXIDS OF THE PREPARATIONS
/// IT PROVED. A `total_proved` of `0` with no txids is the ordinary "nothing left to prove NOW"
/// answer; NULL signals an error (see `zcashlc_last_error_message`).
///
/// THE TXIDS ARE THE HANDOFF. A proved preparation is a complete PCZT and the engine's contract is
/// that it is broadcast as soon as it is proved, so the platform takes each returned txid to
/// [`zcashlc_migration_take_preparation_by_txid`] and submits the bytes through its ordinary
/// raw-transaction machinery. Transfers are NEVER named: they are delivered by the drive's
/// BROADCAST instruction alone.
///
/// THIS EXECUTOR NEVER ASKS THE ENGINE WHAT TO PROVE. `advance_migration` is the top-level call
/// and every invocation is subservient to it: there is no proving to do without first having been
/// instructed what to prove, so this takes the ids it was told and does not crank the drive to
/// second-guess them (see [`drive_advance`]). Whether a candidate is worth proving at all — the
/// store's satisfiability verification — and whether a due broadcast outranks proving this session
/// are the advance's decisions, made before the batch was handed out.
///
/// PER ROW (see [`prove_named_rows`]): a transaction that is no longer `Signed` is a SKIP, so a
/// stale instruction is safe (the engine re-offers un-recorded work on the next crank); a
/// transaction whose anchor is not scanned/retained yet is likewise skipped and retried later; and
/// a successful proof persists through the store seam before this returns.
///
/// `max_proofs <= 0` means unlimited. A platform whose database access serializes behind one actor
/// should pass `1` and loop with a yield between calls, re-passing the SAME ids: the rows it
/// already proved skip for free, so the chunking works without re-cranking the drive between
/// chunks.
///
/// Call this opportunistically as the wallet scans (proofs are wanted long before their
/// transactions come due), not on the broadcast path: proving needs the wallet's commitment tree
/// and takes real time, while the broadcast executor must only broadcast.
///
/// # Safety
/// See [`open`]; `ids` must be valid for reads of `ids_len` `u32` values. Free the returned
/// pointer with [`zcashlc_free_migration_prove_outcome`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_prove_transactions(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    ids: *const u32,
    ids_len: usize,
    max_proofs: i64,
) -> *mut FfiMigrationProveOutcome {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let ids: Vec<MigrationTransferId> = unsafe { slice_or_empty(ids, ids_len) }
            .iter()
            .map(|id| MigrationTransferId::new(*id))
            .collect();
        // A plain load, NOT `reconcile_mined`: the advance that issued this instruction already
        // swept in-flight transactions and promoted the ones the wallet's scan had seen mine, so
        // reconciling here would ask the same `mined_height` question twice. A row promoted since
        // is simply no longer `Signed`, which the per-row skip handles.
        let Some(mut state) = ({
            let store = account_store(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
            store
                .latest_migration()
                .map_err(|e| anyhow!("migration store read failed: {e}"))?
        }) else {
            return Ok(FfiMigrationProveOutcome::from_outcome(
                ProveOutcome::default(),
            ));
        };
        if state.is_terminal() {
            return Ok(FfiMigrationProveOutcome::from_outcome(
                ProveOutcome::default(),
            ));
        }
        let cap = u32::try_from(max_proofs).ok().filter(|&n| n > 0);
        let outcome = prove_named_rows(&mut ctx, &mut state, &ids, cap, |ctx, state, id| {
            prove_one(ctx, state, id)
        })?;
        Ok(FfiMigrationProveOutcome::from_outcome(outcome))
    });
    unwrap_exc_or_null(res)
}

/// Serves the named transaction for broadcast — the instruction a prior
/// [`zcashlc_migration_advance_step`] call returned as its BROADCAST step.
///
/// THIS EXECUTOR NEVER ASKS THE ENGINE WHAT TO SERVE. `advance_migration` is the top-level call
/// and every invocation is subservient to it: there is no broadcast to make without first having
/// been instructed to make it, so this takes the id it was told and does not crank the drive to
/// second-guess it (see [`drive_advance`]). The re-spread, the satisfiability verification and the
/// dueness judgement all happened in the advance that issued the instruction.
///
/// The serve goes through the store's atomic broadcast seam
/// (`PoolMigrations::take_transaction_for_broadcast` via [`serve_for_broadcast`]): finalize, extract,
/// and record the transaction in the wallet's own tables, in one database transaction with handing
/// the bytes back — so the wallet's record of a transaction the platform is about to submit binds
/// at the attempt rather than after it. Retrying a failed submission re-serves the same
/// transaction over the same record.
///
/// STALENESS is the seam's own refusal of a non-`Proved` row: an instruction that has gone stale
/// between the advance and this call fails here rather than being acted on, with the
/// `MIGRATION_PROVING_UNAVAILABLE` prefix reserved for "the stored artifact cannot be turned into
/// servable bytes" and lifecycle refusals left bare (see [`broadcast_seam_error`]). The returned
/// artifact is the FINALIZED CONSENSUS TRANSACTION, submittable as-is, paired with the row's
/// stored txid to submit-and-record under.
///
/// # Safety
/// See [`open`]. Free the returned pointer with [`zcashlc_free_migration_prepared_transfer`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_take_broadcast_transaction(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    id: u32,
) -> *mut FfiPreparedTransfer {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let id = MigrationTransferId::new(id);
        // A plain load, NOT `reconcile_mined`: the advance that issued this instruction already
        // swept in-flight transactions and promoted the ones the wallet's scan had seen mine, so
        // reconciling here would ask the same `mined_height` question twice.
        let Some(state) = ({
            let store = account_store(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
            store
                .latest_migration()
                .map_err(|e| anyhow!("migration store read failed: {e}"))?
        }) else {
            return Err(anyhow!(
                "no migration run is stored, so transaction {} cannot be served for broadcast",
                u32::from(id)
            ));
        };
        let (raw, txid) = serve_for_broadcast(&mut ctx, &state, id)?;
        FfiPreparedTransfer::from_parts(id, txid, raw)
    });
    unwrap_exc_or_null(res)
}

/// Serves the PROVED PREPARATION with the given txid for submission — the retrieval half of the
/// handoff [`zcashlc_migration_prove_transactions`] opens by returning the preparations' txids.
///
/// THE RULING THIS IMPLEMENTS. A proved preparation is a complete PCZT (signatures and proofs);
/// its submission is the ORDINARY path, not the engine's delivery ceremony — preparations are
/// ZIP 318-exempt, and the engine's own contract is that a preparation is broadcast as soon as it
/// is proved. So the platform submits it through whatever machinery it already uses for raw
/// transactions, and records the outcome through the standard
/// [`zcashlc_migration_record_transfer_result`] path.
///
/// THIS ACCESSOR IS THE TAKE SEAM, NOT A BYTE READ. `txid -> row -> take_transaction_for_broadcast`
/// (via [`serve_for_broadcast`]) in ONE database transaction: the wallet's own record of the
/// transaction binds AT RETRIEVAL, so a platform can never hold submittable bytes the wallet knows
/// nothing about. It is idempotent — a consumer that crashed between retrieving and submitting
/// re-retrieves exactly the same bytes over the same record.
///
/// PREPARATION-GATED. A txid naming a TRANSFER is refused: transfers are served by the drive's
/// broadcast instruction alone. The refusal is bare, as an unknown txid is, because both are
/// questions about WHICH row was named rather than about whether an artifact can be made servable
/// — the distinction [`broadcast_seam_error`] draws, and the one the
/// `MIGRATION_PROVING_UNAVAILABLE` prefix is reserved for. The seam's own refusal of a
/// non-`Proved` row is what remains as the READINESS gate: a preparation whose proof this process
/// has not persisted is not servable, and the caller proves again rather than retrying here.
///
/// TAKEN BUT NEVER SUBMITTED is a bounded, engine-modelled state, not a leak: the record is
/// idempotent, the preparation carries a ZIP 203 expiry, and an unsubmitted row surfaces through
/// the ordinary attention path once it expires. SUBMITTED BUT NEVER MARKED is likewise bounded:
/// the platform reports the landed submission through
/// [`zcashlc_migration_record_transfer_result`] as the ordinary close of the loop, and a platform
/// that crashed before doing so still converges — the engine promotes any in-flight transaction
/// its scan sees mine, by the id it stored when it BUILT the transaction.
///
/// The returned DTO carries the ENGINE TRANSFER ID alongside the finalized transaction bytes and
/// the row's stored txid, so the platform records the submission's outcome through the standard
/// record path with no identity of its own to keep.
///
/// # Safety
/// See [`open`]; `txid_ptr` must be non-null and valid for reads of 32 bytes (a null pointer is
/// refused rather than read). Free the returned pointer with
/// [`zcashlc_free_migration_prepared_transfer`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_take_preparation_by_txid(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    txid_ptr: *const u8,
) -> *mut FfiPreparedTransfer {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        // Checked, not coerced: `slice_or_empty` only tolerates NULL at length 0, and reading 32
        // bytes from a null pointer is undefined behaviour — which a public C ABI symbol must
        // refuse rather than risk. Mirrors `zcashlc_migration_record_transfer_result`'s own
        // null-check on the txid it takes.
        if txid_ptr.is_null() {
            return Err(anyhow!(
                "txid_ptr is null; a preparation txid must be 32 bytes"
            ));
        }
        let txid: [u8; 32] = unsafe { slice::from_raw_parts(txid_ptr, 32) }
            .try_into()
            .expect("length 32 by construction");
        // A plain load, NOT `reconcile_mined`: this is a retrieval against the run as the last
        // advance left it, and a row promoted since is simply no longer `Proved`, which the seam's
        // own refusal handles.
        let Some(state) = ({
            let store = account_store(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
            store
                .latest_migration()
                .map_err(|e| anyhow!("migration store read failed: {e}"))?
        }) else {
            return Err(anyhow!(
                "no migration run is stored, so no preparation with txid {} can be served",
                TxId::from_bytes(txid)
            ));
        };
        let row = state
            .transactions()
            .iter()
            .find(|t| <[u8; 32]>::from(t.txid()) == txid)
            .ok_or_else(|| {
                anyhow!(
                    "no migration transaction with txid {}",
                    TxId::from_bytes(txid)
                )
            })?;
        let id = row.id();
        if !matches!(row.kind(), MigrationTxKind::Preparation { .. }) {
            return Err(anyhow!(
                "migration transaction {} is a transfer, not a preparation: transfers are served \
                 by the drive's broadcast instruction alone",
                u32::from(id)
            ));
        }
        let (raw, served_txid) = serve_for_broadcast(&mut ctx, &state, id)?;
        FfiPreparedTransfer::from_parts(id, served_txid, raw)
    });
    unwrap_exc_or_null(res)
}

/// Records a broadcast outcome for the identified transaction. `result_tag`: 0 = success (with
/// `txid_bytes`, 32 raw bytes) — the transaction is marked broadcast, to be reconciled to mined
/// as the wallet scans; 1 = network error (retryable — nothing is recorded, the transaction stays
/// offered); 2 = invalid note, 3 = expired — each rejection is reported to the engine at the
/// wallet's observed chain tip. The next advance reevaluates satisfiability and surfaces any
/// resulting Reevaluate/Replan step on its own discriminant.
///
/// An unknown id or already-mined transaction is left untouched; both still answer `true`, since
/// the reported outcome was consumed.
///
/// # Safety
/// See [`open`]; for tag 0, `txid_bytes` must be valid for reads of 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_record_transfer_result(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    transfer_id: u32,
    result_tag: i32,
    txid_bytes: *const u8,
) -> bool {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let id = MigrationTransferId::new(transfer_id);
        match result_tag {
            0 => {
                if txid_bytes.is_null() {
                    return Err(anyhow!("txid_bytes is null for a success result"));
                }
                let txid: [u8; 32] = unsafe { slice::from_raw_parts(txid_bytes, 32) }
                    .try_into()
                    .expect("length 32 by construction");
                let mut store = account_store(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
                let mut state = store
                    .get_migration()
                    .map_err(|e| anyhow!("migration store read failed: {e}"))?
                    .ok_or_else(|| anyhow!("no migration is stored"))?;
                // The engine records the broadcast under the id it derived when it BUILT the
                // transaction, so the reported one is no longer an input. It is still checked:
                // the two can only differ if the platform submitted something other than the
                // artifact the engine handed it, which is worth naming rather than silently
                // recording a broadcast of a transaction that was never sent.
                if let Some(stored) = state.transactions().iter().find(|t| t.id() == id)
                    && <[u8; 32]>::from(stored.txid()) != txid
                {
                    return Err(anyhow!(
                        "the reported broadcast txid does not match transfer {}'s own transaction",
                        u32::from(id)
                    ));
                }
                state.mark_broadcast(id);
                store
                    .replace_migration(&state)
                    .map_err(|e| anyhow!("migration store write failed: {e}"))?;
                Ok(true)
            }
            1 => Ok(true),
            2 | 3 => {
                // The adapter, not the bare store: this arm dates its testimony against the
                // ENGINE's chain tip (`MigrationBackend::chain_tip_height`), which is the
                // backend's question, not the store's.
                let mut backend = account_migration(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
                let mut state = backend
                    .get_migration()
                    .map_err(|e| anyhow!("migration store read failed: {e}"))?
                    .ok_or_else(|| anyhow!("no migration is stored"))?;
                if state
                    .transactions()
                    .iter()
                    .any(|tx| tx.id() == id && matches!(tx.state(), MigrationTxState::Proved))
                {
                    let observed_tip = backend
                        .chain_tip_height()
                        .map_err(|e| anyhow!("chain height lookup failed: {e}"))?;
                    state.report_broadcast_failure(id, observed_tip);
                    backend
                        .replace_migration(&state)
                        .map_err(|e| anyhow!("migration store write failed: {e}"))?;
                }
                Ok(true)
            }
            other => Err(anyhow!("unknown TransferResult tag: {other}")),
        }
    });
    unwrap_exc_or(res, false)
}

/// Records a broadcast immediate-migration sweep (an ordinary send-max transaction proposed via
/// `zcashlc_propose_send_max_transfer(orchard_only: true)`, built entirely outside the engine's
/// plan cache). The immediate lane surfaces ONLY through [`zcashlc_migration_progress`]: a
/// pending (unmined, unexpired) recorded sweep reports a `0` of `1` snapshot flagged
/// `is_immediate`; once mined or expired it reports nothing (mined = consumed, expired = the
/// banner re-offers). One row per account: a new record supersedes any previous one (INSERT OR
/// REPLACE).
///
/// # Safety
/// See [`open`]; `txid_bytes` must be valid for reads of 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_record_immediate_run(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    txid_bytes: *const u8,
) -> bool {
    let res = catch_panic(|| {
        let ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        if txid_bytes.is_null() {
            return Err(anyhow!("txid_bytes is null"));
        }
        let txid: [u8; 32] = unsafe { slice::from_raw_parts(txid_bytes, 32) }
            .try_into()
            .expect("length 32 by construction");
        let tip = ctx.tip()?;
        record_immediate_run(&ctx.store_conn, &ctx.account_bytes, txid, tip)
            .map_err(|e| anyhow!("immediate run record failed: {e}"))?;
        Ok(true)
    });
    unwrap_exc_or(res, false)
}

/// Cancels the stored run through the engine's own cancel (persisting it as `Cancelled` and
/// releasing every note reservation its never-broadcast transactions hold — its pre-signed
/// transactions are abandoned; already-broadcast ones are unaffected on-chain) and previews a
/// fresh plan against the live balance for the platform's re-confirm lane.
///
/// Cancelling is also what clears the attention state: a terminal run surfaces neither
/// `AdvanceStep::Attend` (upstream `next_step` answers `Complete` for it) nor
/// `zcashlc_migration_has_invalid_transfers` (which answers `false` for a terminal run), so any
/// `Invalid` rows the run carried simply retire with it — no separate clearing step exists or is
/// needed.
///
/// # Safety
/// See [`open`]. Free the returned pointer with [`zcashlc_free_migration_schedule`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_restart_step(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> *mut FfiMigrationSchedule {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        {
            let mut store = account_store(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
            // The engine's own cancel: releases every note reservation the pending run's
            // never-broadcast transactions hold and records the terminal `Cancelled` status, in
            // one store transaction. Hand-writing `Failed` (the pre-locking behavior) would
            // leave those reservations standing, and the fresh plan below would select around
            // notes the abandoned run still holds.
            store
                .cancel_migration()
                .map(|_outcome| ())
                .map_err(|e| anyhow!("cancelling the migration failed: {e}"))?;
        }
        match plan_and_cache(&mut ctx, false)? {
            Some((plan, reference_height, handle)) => {
                encode_schedule_from_plan(&plan, reference_height, handle)
            }
            None => Ok(encode_empty_schedule()),
        }
    });
    unwrap_exc_or_null(res)
}

/// Rebuilds every EXPIRED migration transfer of the stored run in place through the engine
/// (`rebuild_expired_transfer` / `rebuild_expired_transfer_unsigned`): each rebuilt transfer
/// re-spends exactly the SAME funding note — recovered from the expired PCZT by nullifier
/// identity, never an equal-value substitute — rescheduled from the current tip with a fresh
/// memoryless delay, a fresh canonical expiry, and a freshly drawn ZIP 318 boundary anchor
/// (anchors and witnesses stay deferred and are installed at proving time, ZIP 374). This is
/// ZIP 318's expired-transaction handling: a new transaction for the affected part, denomination
/// unchanged.
///
/// The spending key selects the signing lane. With `usk_ptr`/`usk_len` the rebuilt transfer is
/// signed anew in-process (back to `Signed`, served by the normal proving/delivery lane).
/// `usk_ptr == NULL` with `usk_len == 0` is the legitimate external-signer lane: the rebuilt
/// transfer is left `AwaitingSignature`, so the resume path of
/// `zcashlc_migration_create_unsigned_transfer_pczts` re-serves it to the signing ceremony and
/// `zcashlc_migration_store_signed_schedule_pczts` completes it (`apply_signature`), exactly like
/// an originally committed transfer.
///
/// Returns the stored run's FULL, freshly persisted transfer schedule (the same DTO
/// `zcashlc_migration_restart_step` returns, here encoded from the post-refresh STORED state):
/// after a rebuild the host has no other way to learn the fresh scheduled/expiry values, and its
/// stale copy would fail the state-side consent echo forever — the returned schedule is the
/// atomically-persisted truth to re-display and echo. With nothing rebuilt the CURRENT stored
/// schedule is returned unchanged; with no stored migration, or a terminal stored run (a
/// completed or cancelled run has nothing to refresh and nothing the echo lane compares
/// against), the EMPTY schedule. The rebuilt state persists once, all-or-nothing: on any rebuild
/// error nothing is persisted and NULL is returned (see `zcashlc_last_error_message`). A gone
/// funding note (spent outside the migration) is a hard error naming
/// `restartCurrentMigrationStep` (`zcashlc_migration_restart_step`) as the remedy — the
/// remaining balance must be re-planned. An expired PREPARATION transaction also surfaces as a
/// hard error: the engine rebuilds only transfers (leaves of the dependency graph; an expired
/// preparation invalidates its dependents' pre-signatures), and its remediation is the same
/// restart.
///
/// # Safety
/// See [`open`]; `usk_ptr` must be null (with `usk_len == 0`) or valid for reads of `usk_len`
/// bytes. Free the returned pointer with [`zcashlc_free_migration_schedule`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_refresh_stale_transfers(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    usk_ptr: *const u8,
    usk_len: usize,
) -> *mut FfiMigrationSchedule {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        // As on the commit lane: the decoded key is handed to the engine's signing entry point
        // here and nowhere else, and `None` is the external-signer lane that never had one.
        let usk = if usk_ptr.is_null() {
            if usk_len != 0 {
                return Err(anyhow!("usk_len must be 0 when usk_ptr is null"));
            }
            None
        } else {
            Some(unsafe { crate::decode_usk(usk_ptr, usk_len)? })
        };

        // Reconcile before judging expiry: a Broadcast transfer the wallet has since observed
        // on-chain must count as Mined here, or it would look expired and be rebuilt into a
        // double spend of its own mined copy. The no-run and terminal answers come before any
        // tip lookup, so they hold even before the wallet ever saw a chain tip.
        let Some(mut state) = reconcile_mined(&mut ctx)? else {
            return Ok(encode_empty_schedule());
        };
        if state.is_terminal() {
            return Ok(encode_empty_schedule());
        }
        let tip = ctx.tip()?;
        let target = target_from_tip(tip);
        let expired = state.expired_transactions(DuenessTargets::at(target));
        if expired.is_empty() {
            // Nothing to rebuild: the stored schedule IS current — serve it for re-display.
            return encode_schedule_from_state(&state, tip);
        }

        let mut rng = OsRng;
        let mut backend = account_migration(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
        for id in &expired {
            if let Some(sk) = usk.as_ref().map(|usk| usk.orchard()) {
                engine::rebuild_expired_transfer(
                    &ctx.network,
                    &backend,
                    sk,
                    &mut state,
                    *id,
                    &mut rng,
                )
                .map_err(map_rebuild_err)?;
            } else {
                // The returned UnsignedMigrationTx is deliberately dropped: the rebuilt transfer
                // is persisted `AwaitingSignature` below, and the ceremony re-serves those bytes
                // through `zcashlc_migration_create_unsigned_transfer_pczts`.
                engine::rebuild_expired_transfer_unsigned(
                    &ctx.network,
                    &backend,
                    &mut state,
                    *id,
                    &mut rng,
                )
                .map_err(map_rebuild_err)?;
            }
        }
        backend
            .replace_migration(&state)
            .map_err(|e| anyhow!("migration store write failed: {e}"))?;
        encode_schedule_from_state(&state, tip)
    });
    unwrap_exc_or_null(res)
}

/// Builds the whole migration UNSIGNED (external-signer lane): every transaction is persisted
/// `AwaitingSignature`, and the preparation (note-split) subset is returned for the signing
/// ceremony. The run is created HERE; the transfer subset of the same build is served by
/// `zcashlc_migration_create_unsigned_transfer_pczts`. Resumes a stored non-terminal run
/// (re-serving its still-unsigned preparation transactions); replaces a terminal one.
///
/// `proposal_handle` identifies the cached plan the run is built from — the one whose schedule
/// the platform displayed. A fresh build fails with `MIGRATION_PLAN_STALE` when that plan is
/// missing or superseded; the resume path does not consult the handle (see [`commit_or_resume`]).
///
/// Every returned PCZT already carries the account's ZIP 32 spend derivation, so an external
/// signer (Keystone) can identify which of its accounts each spend belongs to: the engine stamps
/// it during the build (see [`crate::migration_keystone`]'s module doc), on the freshly built and
/// the resumed (already-committed) run alike.
///
/// # Safety
/// See [`open`]. Free the returned pointer with
/// [`zcashlc_free_migration_unsigned_transfer_pczts`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_create_unsigned_note_split_pczts(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    proposal_handle: u64,
) -> *mut FfiUnsignedTransferPczts {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let (state, unsigned) = commit_or_resume(&mut ctx, None, true, proposal_handle)?;
        let prep_ids: HashSet<MigrationTransferId> = state
            .transactions()
            .iter()
            .filter(|t| matches!(t.kind(), MigrationTxKind::Preparation { .. }))
            .map(|t| t.id())
            .collect();
        let preps: Vec<_> = unsigned
            .into_iter()
            .filter(|(id, _, _)| prep_ids.contains(id))
            .collect();
        FfiUnsignedTransferPczts::from_pairs(preps)
    });
    unwrap_exc_or_null(res)
}

/// Applies the ceremony's signatures to the run's preparation (note-split) transactions,
/// all-or-nothing: every `(id, pczt)` pair must land on a stored transaction awaiting its
/// signature, or nothing is persisted. Returns a STORAGE RECEIPT for the first preparation
/// transaction (its id and signed bytes; the txid is zeroed — the broadcastable, proven value is
/// served by the delivery lane).
///
/// # Safety
/// See [`open`]; `ids`/`pczts`/`pczt_lens` must be valid for reads of `ids_len` elements, and
/// each `pczts[i]` for `pczt_lens[i]` bytes. Free the returned pointer with
/// [`zcashlc_free_migration_prepared_transfer`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_store_signed_note_split_pczts(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    ids: *const u32,
    ids_len: usize,
    pczts: *const *const u8,
    pczt_lens: *const usize,
) -> *mut FfiPreparedTransfer {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let signed = unsafe { decode_signed_pairs(ids, ids_len, pczts, pczt_lens)? };
        let mut store = account_store(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
        let mut state = store
            .get_migration()
            .map_err(|e| anyhow!("migration store read failed: {e}"))?
            .ok_or_else(|| anyhow!("no migration is committed yet"))?;
        let mut first: Option<(MigrationTransferId, Vec<u8>)> = None;
        for (id, bytes) in signed {
            if first.is_none() {
                first = Some((id, bytes.clone()));
            }
            if !state.apply_signature(id, bytes) {
                return Err(anyhow!(
                    "signature for transaction {} does not match a stored transaction awaiting \
                     one; nothing was persisted",
                    u32::from(id)
                ));
            }
        }
        let (first_id, first_bytes) =
            first.ok_or_else(|| anyhow!("no signed note-split PCZTs were provided"))?;
        store
            .replace_migration(&state)
            .map_err(|e| anyhow!("migration store write failed: {e}"))?;
        FfiPreparedTransfer::from_parts(first_id, [0u8; 32], first_bytes)
    });
    unwrap_exc_or_null(res)
}

/// Serves the TRANSFER subset of the unsigned build for the signing ceremony (see
/// `zcashlc_migration_create_unsigned_note_split_pczts` — the run and every unsigned transaction
/// already exist, so the normal path here is the handle-free resume; `proposal_handle` only
/// gates the fresh-build case where this call is the one creating the run — see
/// [`commit_or_resume`]).
///
/// Every returned PCZT already carries the account's ZIP 32 spend derivation, stamped by the
/// engine during the build — see `zcashlc_migration_create_unsigned_note_split_pczts`'s doc.
///
/// # Safety
/// See [`open`]. Free the returned pointer with
/// [`zcashlc_free_migration_unsigned_transfer_pczts`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_create_unsigned_transfer_pczts(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    proposal_handle: u64,
) -> *mut FfiUnsignedTransferPczts {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let (state, unsigned) = commit_or_resume(&mut ctx, None, true, proposal_handle)?;
        let transfer_ids: HashSet<MigrationTransferId> = state
            .transactions()
            .iter()
            .filter(|t| matches!(t.kind(), MigrationTxKind::Transfer { .. }))
            .map(|t| t.id())
            .collect();
        let transfers: Vec<_> = unsigned
            .into_iter()
            .filter(|(id, _, _)| transfer_ids.contains(id))
            .collect();
        FfiUnsignedTransferPczts::from_pairs(transfers)
    });
    unwrap_exc_or_null(res)
}

/// Splits an ORDERED list of transaction action-weights (the `actions` field
/// [`zcashlc_migration_create_unsigned_note_split_pczts`]/`_transfer_pczts` populate per row)
/// into signer sessions bounded by `max_actions_per_session`, preserving order: the platform
/// re-slices its own ordered PCZT list by the returned per-session counts. A pure marshal over
/// the upstream `NextFit` strategy (order-preserving greedy, matching the CREATE-time PCZT
/// order the caller already streams in) — NOT the optimal `MinRounds` packing a migration's own
/// signing-ROUND preview uses (`FfiRunEstimate::keystone_rounds`), which is free to reorder
/// because every transaction of one run is independent at signing time; this call's caller
/// generally cannot reorder (a partially-signed batch already dispatched to a device).
///
/// Every element of `actions` must equal exactly `PREPARATION_ACTIONS` (16) or `TRANSFER_ACTIONS`
/// (3) — the two weights a migration transaction ever carries; any other value is a hard error (a
/// caller bug, not a signer condition — see `zcashlc_last_error_message`).
/// `max_actions_per_session` below the minimum any signer must support
/// (`SigningRoundBudget::minimum_feasible`, 16 — a single preparation transaction) is also a hard
/// error, rather than silently returning a technically-valid but useless one-oversized-row-per-
/// session split.
///
/// NULL signals an error; a `len == 0` input returns an empty (`len == 0`) result, not an error.
///
/// # Safety
/// `actions` must be valid for reads of `len` elements. Free the returned pointer with
/// [`zcashlc_free_migration_batch_sizes`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_batch_pczts_by_actions(
    actions: *const u32,
    len: usize,
    max_actions_per_session: u32,
) -> *mut FfiMigrationBatchSizes {
    let res = catch_panic(|| {
        let actions = unsafe { slice_or_empty(actions, len) };
        let minimum = SigningRoundBudget::minimum_feasible().get();
        let budget = std::num::NonZeroU32::new(max_actions_per_session)
            .filter(|b| b.get() >= minimum)
            .ok_or_else(|| {
                anyhow!(
                    "max_actions_per_session ({max_actions_per_session}) is below the minimum \
                     any signer must support ({minimum})"
                )
            })?;
        let planned: Vec<PlannedTx> = actions
            .iter()
            .enumerate()
            .map(|(i, &weight)| {
                let kind = if weight == PREPARATION_ACTIONS {
                    MigrationTxKind::Preparation { layer: 0, index: 0 }
                } else if weight == TRANSFER_ACTIONS {
                    MigrationTxKind::Transfer { crossing: 0 }
                } else {
                    return Err(anyhow!(
                        "action weight {weight} at index {i} is neither a preparation \
                         ({PREPARATION_ACTIONS}) nor a transfer ({TRANSFER_ACTIONS}) weight"
                    ));
                };
                // `layer`/`index`/`crossing`, and likewise the empty dependency set and absent
                // scheduled height, are dummies (see the doc above): the packer never reads
                // them, only each entry's action weight.
                Ok(PlannedTx::new(
                    MigrationTransferId::new(i as u32),
                    kind,
                    Vec::new(),
                    None,
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let sizes = NextFit
            .pack(&planned, SigningRoundBudget::new(budget))
            .iter()
            .map(|round| count_to_u32(round.len(), "signing session size"))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let (ptr, len) = ptr_from_vec(sizes);
        Ok(Box::into_raw(Box::new(FfiMigrationBatchSizes { ptr, len })))
    });
    unwrap_exc_or_null(res)
}

/// Applies the ceremony's signatures to the run's transfer transactions, all-or-nothing (see
/// `zcashlc_migration_store_signed_note_split_pczts`).
///
/// # Safety
/// See [`open`]; `ids`/`pczts`/`pczt_lens` must be valid for reads of `ids_len` elements, and
/// each `pczts[i]` for `pczt_lens[i]` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_store_signed_schedule_pczts(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    ids: *const u32,
    ids_len: usize,
    pczts: *const *const u8,
    pczt_lens: *const usize,
) -> bool {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let signed = unsafe { decode_signed_pairs(ids, ids_len, pczts, pczt_lens)? };
        let mut store = account_store(&ctx.wallet, ctx.account, &mut ctx.store_conn)?;
        let mut state = store
            .get_migration()
            .map_err(|e| anyhow!("migration store read failed: {e}"))?
            .ok_or_else(|| anyhow!("no migration is committed yet"))?;
        for (id, bytes) in signed {
            if !state.apply_signature(id, bytes) {
                return Err(anyhow!(
                    "signature for transaction {} does not match a stored transaction awaiting \
                     one; nothing was persisted",
                    u32::from(id)
                ));
            }
        }
        store
            .replace_migration(&state)
            .map_err(|e| anyhow!("migration store write failed: {e}"))?;
        Ok(true)
    });
    unwrap_exc_or(res, false)
}

/// Decode the platform's parallel `(id, pczt)` arrays into owned pairs, parsing every id as an
/// engine [`MigrationTransferId`].
///
/// The two store externs ([`zcashlc_migration_store_signed_note_split_pczts`] and
/// [`zcashlc_migration_store_signed_schedule_pczts`]) look transactions up by that id;
/// [`zcashlc_migration_keystone_apply_batch_signatures`] never does — it only echoes each id back
/// onto the returned pair positionally, so there an id is a caller-side correlation label that
/// happens to share the engine's `u32` type.
///
/// # Safety
/// `ids`/`pczts`/`pczt_lens` must be valid for reads of `len` elements, and every `pczts[i]` valid
/// for `pczt_lens[i]` bytes.
unsafe fn decode_signed_pairs(
    ids: *const u32,
    len: usize,
    pczts: *const *const u8,
    pczt_lens: *const usize,
) -> anyhow::Result<Vec<(MigrationTransferId, Vec<u8>)>> {
    let ids = unsafe { slice_or_empty(ids, len) };
    let pczt_ptrs = unsafe { slice_or_empty(pczts, len) };
    let lens = unsafe { slice_or_empty(pczt_lens, len) };
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        let id = MigrationTransferId::new(ids[i]);
        if pczt_ptrs[i].is_null() {
            return Err(anyhow!("signed pczt at index {i} is null"));
        }
        let bytes = unsafe { slice::from_raw_parts(pczt_ptrs[i], lens[i]) }.to_vec();
        out.push((id, bytes));
    }
    Ok(out)
}

// ----- Keystone batch-signing UR bridge (crate::migration_keystone) -----
//
// Pure PCZT/UR operations over caller-held bytes — no wallet database, no migration engine.

/// Decode the platform's parallel `(pczt, pczt_len)` arrays into owned PCZT byte vectors.
///
/// # Safety
/// `pczts`/`pczt_lens` must be valid for reads of `len` elements; every `pczts[i]` must be valid
/// for `pczt_lens[i]` bytes.
unsafe fn decode_pczt_list(
    pczts: *const *const u8,
    pczt_lens: *const usize,
    len: usize,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let pczt_ptrs = unsafe { slice_or_empty(pczts, len) };
    let lens = unsafe { slice_or_empty(pczt_lens, len) };
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        if pczt_ptrs[i].is_null() {
            return Err(anyhow!("pczt at index {i} is null"));
        }
        out.push(unsafe { slice::from_raw_parts(pczt_ptrs[i], lens[i]) }.to_vec());
    }
    Ok(out)
}

/// Builds the animated multi-part QR frames for a Keystone batch-signing request covering every
/// PCZT in `pczts`, in the given order (preparation PCZTs first, then transfer PCZTs — see
/// [`crate::migration_keystone`]'s module doc). `ids` is deliberately NOT a parameter: the build
/// step has no use for them — only [`zcashlc_migration_keystone_apply_batch_signatures`] echoes
/// ids back out, since that is what the caller matches signed PCZTs to stored transactions by.
///
/// # Safety
/// `request_id` must be valid for reads of `request_id_len` bytes. `pczts`/`pczt_lens` must be
/// valid for reads of `pczts_len` elements, and each `pczts[i]` valid for `pczt_lens[i]` bytes.
/// Free the returned pointer with [`zcashlc_free_migration_keystone_qr_parts`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_keystone_build_sign_batch_qr_parts(
    request_id: *const u8,
    request_id_len: usize,
    pczts: *const *const u8,
    pczt_lens: *const usize,
    pczts_len: usize,
    max_fragment_len: usize,
) -> *mut FfiKeystoneQrParts {
    let res = catch_panic(|| {
        let request_id = unsafe { slice_or_empty(request_id, request_id_len) }.to_vec();
        let pczts = unsafe { decode_pczt_list(pczts, pczt_lens, pczts_len)? };
        let parts = crate::migration_keystone::build_sign_batch_qr_parts(
            request_id,
            &pczts,
            max_fragment_len,
        )
        .map_err(|e| anyhow!("Error building Keystone sign-batch QR parts: {e}"))?;
        FfiKeystoneQrParts::from_parts(parts)
    });
    unwrap_exc_or_null(res)
}

/// Discards any in-flight multi-part Keystone sign-batch-response scan session. Callers should
/// invoke this on scan-screen entry so a new attempt always starts from a clean slate regardless
/// of how a previous attempt ended (cancel, back button, mid-stream error). Void and infallible.
#[unsafe(no_mangle)]
pub extern "C" fn zcashlc_migration_keystone_reset_sign_batch_decoder() {
    crate::migration_keystone::reset_sign_batch_decoder();
}

/// Feeds one scanned QR frame into the active (or a freshly started) Keystone sign-batch-response
/// decode session, pinned to the `"zcash-batch-sig-result"` UR type. `expected_request_id` must
/// match the decoded response's own request id once complete, or this errors (a scan of an
/// unrelated/stale response) instead of silently accepting it. See
/// [`crate::migration_keystone::decode_sign_batch_part`].
///
/// # Safety
/// `part` must be a valid, NUL-terminated C string. `expected_request_id` must be valid for reads
/// of `expected_request_id_len` bytes. Free the returned pointer with
/// [`zcashlc_free_migration_keystone_batch_decode_result`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_keystone_decode_sign_batch_part(
    part: *const c_char,
    expected_request_id: *const u8,
    expected_request_id_len: usize,
) -> *mut FfiKeystoneBatchDecodeResult {
    let res = catch_panic(|| {
        if part.is_null() {
            return Err(anyhow!("part is null"));
        }
        let part = unsafe { CStr::from_ptr(part) }
            .to_str()
            .map_err(|e| anyhow!("part is not valid UTF-8: {e}"))?;
        let expected_request_id =
            unsafe { slice_or_empty(expected_request_id, expected_request_id_len) };
        let result = crate::migration_keystone::decode_sign_batch_part(part, expected_request_id)
            .map_err(|e| anyhow!("Error decoding Keystone sign-batch QR part: {e}"))?;
        Ok(FfiKeystoneBatchDecodeResult::from_parts(result))
    });
    unwrap_exc_or_null(res)
}

/// Applies the ceremony's Keystone batch signatures to the caller-held unsigned PCZTs,
/// positionally (see [`crate::migration_keystone::apply_batch_signatures`]) — `ids`/`pczts` must
/// be the SAME PCZTs, in the SAME order, passed to
/// [`zcashlc_migration_keystone_build_sign_batch_qr_parts`]. `ids` are caller-side correlation
/// labels here: nothing is looked up by them, they only ride positionally onto the returned
/// signed PCZTs, reusing [`FfiUnsignedTransferPczts`] as a generic `(id, PCZT bytes)` pair set
/// (see its doc). A caller that needs to tell a preparation PCZT from a schedule transfer keeps
/// that mapping itself: the batch is positional, and the engine numbers every preparation
/// transaction before the transfers (MOB-1513 R8 finding 1, whose sentinel-prefixed ids the
/// former decimal-string id decode rejected — there is no id parse left to fail).
///
/// # Safety
/// See [`decode_signed_pairs`]. `response` must be valid for reads of `response_len`
/// bytes. Free the returned pointer with [`zcashlc_free_migration_unsigned_transfer_pczts`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_keystone_apply_batch_signatures(
    ids: *const u32,
    ids_len: usize,
    pczts: *const *const u8,
    pczt_lens: *const usize,
    response: *const u8,
    response_len: usize,
) -> *mut FfiUnsignedTransferPczts {
    let res = catch_panic(|| {
        let unsigned = unsafe { decode_signed_pairs(ids, ids_len, pczts, pczt_lens)? };
        let (ids, pczts): (Vec<MigrationTransferId>, Vec<Vec<u8>>) = unsigned.into_iter().unzip();
        let response = unsafe { slice_or_empty(response, response_len) };
        let signed = crate::migration_keystone::apply_batch_signatures(&pczts, response)
            .map_err(|e| anyhow!("Error applying Keystone batch signatures: {e}"))?;
        // No stored `kind` at this position (this call takes no db/account — see the module
        // doc), so `actions` cannot be weighed here; `0` (see `FfiUnsignedTransferPczt::actions`).
        FfiUnsignedTransferPczts::from_pairs(
            ids.into_iter()
                .zip(signed)
                .map(|(id, bytes)| (id, bytes, 0))
                .collect(),
        )
    });
    unwrap_exc_or_null(res)
}

/// The Ironwood (NU6.3) activation height for a standard network, or `-1` when unset/unknown (and
/// on error — see `zcashlc_last_error_message`).
#[unsafe(no_mangle)]
pub extern "C" fn zcashlc_ironwood_activation_height(network_id: u32) -> i64 {
    let res = catch_panic(|| {
        let network = match network_id {
            NETWORK_ID_TESTNET => Network::TestNetwork,
            NETWORK_ID_MAINNET => Network::MainNetwork,
            other => {
                return Err(anyhow!(
                    "Invalid network id for Ironwood activation height: {other}. Expected {NETWORK_ID_TESTNET} (testnet) or {NETWORK_ID_MAINNET} (mainnet)."
                ));
            }
        };
        Ok(height_opt_to_i64(
            network.activation_height(NetworkUpgrade::Nu6_3),
        ))
    });
    unwrap_exc_or(res, -1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use zcash_client_backend::data_api::WalletWrite;
    use zcash_pool_migration::denomination::DenominationPlan;
    use zcash_pool_migration::engine::{MigrationLockOwner, MigrationStatus};
    use zcash_pool_migration::preparation::PreparationPlan;
    use zcash_pool_migration::scheduling::{self, AnchorBucketInterval, SchedulingParams};
    use zcash_pool_migration::signing_rounds::min_signing_rounds;

    use crate::migration_engine::ZODL_MAX_PREPARED_NOTES_PER_RUN;
    use zcash_pool_migration::engine::RunSizing;
    use zcash_pool_migration::signing_rounds::RunSigningCapacity;

    fn zat(v: u64) -> Zatoshis {
        Zatoshis::from_u64(v).unwrap()
    }

    fn h(v: u32) -> BlockHeight {
        BlockHeight::from_u32(v)
    }

    #[allow(clippy::too_many_arguments)]
    fn test_transaction_from_parts(
        id: MigrationTransferId,
        kind: MigrationTxKind,
        pczt: Vec<u8>,
        depends_on: Vec<MigrationTransferId>,
        scheduled_height: BlockHeight,
        expiry_height: BlockHeight,
        anchor_boundary: Option<BlockHeight>,
        state: MigrationTxState,
        lock_owner: Option<MigrationLockOwner>,
    ) -> MigrationTransaction {
        MigrationTransaction::from_parts(
            id,
            kind,
            pczt,
            depends_on,
            scheduled_height,
            expiry_height,
            anchor_boundary,
            // The row's own id. Where the lifecycle state carries a copy, that IS this value: the
            // engine writes one id per transaction, so a fixture stating two different ones would
            // describe a row no store can represent.
            match state {
                MigrationTxState::Broadcast { txid } | MigrationTxState::Mined { txid, .. } => txid,
                _ => TxId::from_bytes([u32::from(id) as u8; 32]),
            },
            state,
            lock_owner,
            None,
            if matches!(state, MigrationTxState::Mined { .. }) {
                Vec::new()
            } else {
                vec![[0u8; 32]]
            },
            None,
        )
    }

    fn test_state_from_parts(
        status: MigrationStatus,
        denominations: DenominationPlan,
        preparation: PreparationPlan,
        transactions: Vec<MigrationTransaction>,
        anchor_bucket_interval: AnchorBucketInterval,
    ) -> MigrationState {
        MigrationState::from_parts(
            status,
            denominations,
            preparation,
            transactions,
            anchor_bucket_interval,
            ReplanThreshold::DEFAULT,
        )
    }

    // ----- Keystone batch-apply id contract (MOB-1513 R8 finding 1) -----

    /// The apply lane never looks an id up: ids ride positionally onto the returned pairs, so a
    /// batch reaches the apply step whatever its ids are. With an empty (zero-signature-set)
    /// response the apply step then fails its OWN count check — the failure the caller sees is
    /// about signatures, never about an id. (The PCZT bytes are never parsed on this path:
    /// `apply_batch_signatures` checks the response's set count before touching any PCZT.)
    ///
    /// The defect this pins was a decimal-string id decode that rejected the app's
    /// `note-split#<engine id>` preparation sentinels and aborted every ceremony carrying a
    /// preparation transaction. Ids now cross the FFI as the engine's own `u32`, so there is no
    /// parse left to reject anything — a caller that needs to tell a preparation PCZT from a
    /// schedule transfer keeps that mapping itself.
    #[test]
    fn keystone_apply_extern_reaches_the_apply_step_without_looking_ids_up() {
        use pczt::roles::signer::batch::BatchSignResponse;

        let ids = [3u32];
        let pczts = [vec![0xDEu8, 0xAD]];
        let pczt_ptrs: Vec<*const u8> = pczts.iter().map(|bytes| bytes.as_ptr()).collect();
        let pczt_lens: Vec<usize> = pczts.iter().map(Vec::len).collect();
        let response = BatchSignResponse::new(Vec::new())
            .serialize()
            .expect("serialize empty batch sign response");

        let result = unsafe {
            zcashlc_migration_keystone_apply_batch_signatures(
                ids.as_ptr(),
                ids.len(),
                pczt_ptrs.as_ptr(),
                pczt_lens.as_ptr(),
                response.as_ptr(),
                response.len(),
            )
        };

        assert!(
            result.is_null(),
            "an empty response must still fail the apply step"
        );
        let err = ffi_helpers::error_handling::take_last_error()
            .expect("the failed extern must record a last-error");
        let message = err.to_string();
        assert!(
            message.contains("expected 1"),
            "the failure must come from the apply step's signature-set count check: {message}"
        );
    }

    // ----- action-budget batching (`zcashlc_migration_batch_pczts_by_actions`) -----

    /// Order-preserving `NextFit` packing, exercised through the FFI: six preparation
    /// transactions (16 actions each) fill a 96-action Keystone round exactly, so the seventh
    /// entry (a 3-action transfer) starts a new session.
    #[test]
    fn batch_pczts_by_actions_packs_next_fit_order_preserving() {
        let actions: Vec<u32> = vec![16, 16, 16, 16, 16, 16, 3];
        let ptr = unsafe {
            zcashlc_migration_batch_pczts_by_actions(actions.as_ptr(), actions.len(), 96)
        };
        assert!(!ptr.is_null(), "a valid batch must not error");
        let sizes = unsafe { &*ptr };
        let got = unsafe { std::slice::from_raw_parts(sizes.ptr, sizes.len) };
        assert_eq!(
            got,
            &[6, 1],
            "six 16s fill one round exactly; the 3 starts the next"
        );
        unsafe { zcashlc_free_migration_batch_sizes(ptr) };
    }

    /// Exactly-fitting totals land in ONE session (the packer's `<=` boundary, not `<`): 32
    /// transfer-weight (3-action) entries sum to exactly 96.
    #[test]
    fn batch_pczts_by_actions_exact_fit_is_one_session() {
        let actions: Vec<u32> = vec![3; 32];
        let ptr = unsafe {
            zcashlc_migration_batch_pczts_by_actions(actions.as_ptr(), actions.len(), 96)
        };
        assert!(!ptr.is_null(), "a valid batch must not error");
        let sizes = unsafe { &*ptr };
        let got = unsafe { std::slice::from_raw_parts(sizes.ptr, sizes.len) };
        assert_eq!(got, &[32], "32 * 3 == 96 must fit in a single session");
        unsafe { zcashlc_free_migration_batch_sizes(ptr) };
    }

    /// A budget below the minimum any signer must support (16, a single preparation transaction)
    /// is a hard error, not a degenerate one-row-per-session split.
    #[test]
    fn batch_pczts_by_actions_rejects_a_budget_below_the_minimum() {
        let actions: Vec<u32> = vec![16, 3];
        let ptr = unsafe {
            zcashlc_migration_batch_pczts_by_actions(actions.as_ptr(), actions.len(), 15)
        };
        assert!(
            ptr.is_null(),
            "a sub-minimum budget must error, not pack degenerately"
        );
        let err = ffi_helpers::error_handling::take_last_error()
            .expect("the failed extern must record a last-error");
        assert!(
            err.to_string().contains("below the minimum"),
            "unexpected error message: {err}"
        );
    }

    /// An action weight that is neither the preparation nor the transfer constant is a caller
    /// bug, not a signer condition — a hard error, never silently coerced to one or the other.
    #[test]
    fn batch_pczts_by_actions_rejects_an_unknown_action_weight() {
        let actions: Vec<u32> = vec![16, 7, 3];
        let ptr = unsafe {
            zcashlc_migration_batch_pczts_by_actions(actions.as_ptr(), actions.len(), 96)
        };
        assert!(ptr.is_null(), "an unrecognized action weight must error");
        let err = ffi_helpers::error_handling::take_last_error()
            .expect("the failed extern must record a last-error");
        assert!(
            err.to_string().contains("neither a preparation"),
            "unexpected error message: {err}"
        );
    }

    /// A zero-length input is the benign empty answer, not an error.
    #[test]
    fn batch_pczts_by_actions_empty_input_is_an_empty_result() {
        let ptr = unsafe { zcashlc_migration_batch_pczts_by_actions(std::ptr::null(), 0, 96) };
        assert!(!ptr.is_null(), "an empty batch must not error");
        let sizes = unsafe { &*ptr };
        assert_eq!(sizes.len, 0, "no input actions must yield no sessions");
        unsafe { zcashlc_free_migration_batch_sizes(ptr) };
    }

    /// Creates a real account in the initialized wallet database at `path` and returns its uuid
    /// bytes plus its unified spending key encoded for the FFI (`Era::Orchard`, the encoding
    /// `decode_usk` expects). The account-keyed migration store resolves the account row up front
    /// (`PoolMigrations::for_account` errors on an unknown uuid), so fixtures must register the
    /// account they query — exactly like a real caller, where the uuid always comes from a
    /// previously created account.
    fn create_fixture_account_with_usk(path: &std::path::Path) -> ([u8; 16], Vec<u8>) {
        create_fixture_account_with_usk_and_key_source(path, None)
    }

    /// [`create_fixture_account_with_usk`] with the account row's `key_source` set to
    /// `key_source` — the tag [`crate::migration_engine::run_sizing`] reads (`"keystone"` marks a
    /// Keystone-signed account). The seed-derived account stands in for the UFVK-imported one a
    /// real Keystone account is: sizing consults the tag alone, and holding a spending key is what
    /// lets the fixture fund the account through [`fund_fixture_account_with_orchard_notes`].
    fn create_fixture_account_with_usk_and_key_source(
        path: &std::path::Path,
        key_source: Option<&str>,
    ) -> ([u8; 16], Vec<u8>) {
        use secrecy::SecretVec;
        use zcash_client_backend::data_api::AccountBirthday;
        use zcash_client_backend::proto::service::TreeState;
        use zcash_client_sqlite::WalletDb;
        use zcash_client_sqlite::util::SystemClock;
        use zcash_keys::keys::Era;
        use zcash_protocol::consensus::MAIN_NETWORK;

        let mut db = WalletDb::for_path(path, MAIN_NETWORK, SystemClock, OsRng)
            .expect("the wallet database must open");
        let seed = SecretVec::new(vec![7u8; 32]);
        let treestate = TreeState {
            // `to_chain_state` requires a valid 32-byte block hash; everything else can stay
            // at the proto defaults (height 0, empty tree frontiers).
            hash: "00".repeat(32),
            ..TreeState::default()
        };
        let birthday = match AccountBirthday::from_treestate(treestate, None) {
            Ok(birthday) => birthday,
            Err(_) => panic!("the fixture treestate must convert to a birthday"),
        };
        let (account, usk) = db
            .create_account("fixture", &seed, &birthday, key_source)
            .expect("account creation must succeed");
        (
            account.expose_uuid().into_bytes(),
            usk.to_bytes(Era::Orchard),
        )
    }

    /// [`create_fixture_account_with_usk`] for the fixtures that never sign.
    fn create_fixture_account(path: &std::path::Path) -> [u8; 16] {
        create_fixture_account_with_usk(path).0
    }

    /// Marks the fixture wallet fully scanned through `height`, by writing the `Scanned`
    /// (priority 10) scan-queue range from the account birthday that
    /// `zcash_client_sqlite`'s `fully_scanned_height` derives its answer from.
    ///
    /// Needed by any fixture that hand-inserts a `transactions` row and expects the migration
    /// layer to act on its mined height: promotion is bounded by the FULLY-SCANNED height, not
    /// the chain tip, so an unscanned wallet reports nothing mined however many rows its
    /// `transactions` table holds. That bound is not an artifact — a real wallet learns a
    /// migration transaction's height BY scanning, so the two always move together outside a
    /// fixture — and it is the same bound `advance_migration`'s own sweep promotes under, which
    /// is what keeps a status read from reporting `Mined` for a row the drive path would refuse.
    fn mark_fixture_scanned_through(path: &std::path::Path, height: u32) {
        let conn = Connection::open(path).expect("the wallet connection opens");
        let birthday: u32 = conn
            .query_row("SELECT MIN(birthday_height) FROM accounts", [], |row| {
                row.get(0)
            })
            .expect("the fixture account has a birthday");
        // `zcashlc_update_chain_tip` has already queued the birthday-to-tip range as UNSCANNED,
        // and the table's start/end uniqueness constraints leave no room to add beside it. The
        // whole queue is replaced rather than amended: this fixture asserts about scan RESULTS,
        // never about what remains to scan.
        conn.execute("DELETE FROM scan_queue", [])
            .expect("the existing scan queue clears");
        conn.execute(
            "INSERT INTO scan_queue (block_range_start, block_range_end, priority) \
             VALUES (?1, ?2, 10)",
            rusqlite::params![birthday, height + 1],
        )
        .expect("the scanned range inserts");
    }

    /// Seeds a synthetic RECEIVED Orchard note whose nullifier is `nf`, so the satisfiability
    /// oracle's per-nullifier input observation resolves a fixture migration transaction's
    /// `spend_nullifiers` to "known, unspent" rather than `Unknown` — an unknown nullifier defers
    /// the candidate silently (`Waiting`) rather than ever offering it as `Prove`.
    /// [`test_transaction_from_parts`] gives every non-`Mined` fixture transaction the SAME
    /// placeholder nullifier (`[0u8; 32]`), so one seeded row here covers every `Signed` row a
    /// fixture adds. The note's other fields are meaningless placeholders — the oracle's
    /// observation query joins only on `nf`/`account_id` and whether a MINED spend exists (there
    /// is none here), never touching diversifier/rho/rseed.
    fn seed_placeholder_received_note(path: &std::path::Path, nf: [u8; 32]) {
        let conn = Connection::open(path).expect("the wallet connection opens");
        let account_id: i64 = conn
            .query_row("SELECT id FROM accounts", [], |row| row.get(0))
            .expect("the fixture account exists");
        conn.execute(
            "INSERT INTO transactions (txid, min_observed_height) VALUES (?1, ?2)",
            rusqlite::params![&[0xABu8; 32][..], 0],
        )
        .expect("the placeholder receiving-transaction row inserts");
        let transaction_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO orchard_received_notes \
             (transaction_id, action_index, account_id, diversifier, value, rho, rseed, nf, is_change) \
             VALUES (?1, 0, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
            rusqlite::params![
                transaction_id,
                account_id,
                &[0u8; 11][..],
                100_000_000i64,
                &[0u8; 32][..],
                &[0u8; 32][..],
                &nf[..],
            ],
        )
        .expect("the placeholder received-note row inserts");
    }

    /// A minimal stored migration: `n_preps` preparation transactions then `n_transfers`
    /// transfers, all ids engine-ordered (preps first), with the given lifecycle states.
    fn test_state(
        status: MigrationStatus,
        prep_states: &[MigrationTxState],
        transfer_states: &[MigrationTxState],
        scheduled: u32,
        expiry: u32,
    ) -> MigrationState {
        let mut transactions = Vec::new();
        for (i, s) in prep_states.iter().enumerate() {
            transactions.push(test_transaction_from_parts(
                MigrationTransferId::new(i as u32),
                MigrationTxKind::Preparation { layer: 0, index: i },
                vec![0u8],
                Vec::new(),
                h(scheduled),
                h(expiry),
                None,
                s.clone(),
                None,
            ));
        }
        let offset = prep_states.len() as u32;
        for (i, s) in transfer_states.iter().enumerate() {
            transactions.push(test_transaction_from_parts(
                MigrationTransferId::new(offset + i as u32),
                MigrationTxKind::Transfer { crossing: i },
                vec![0u8],
                Vec::new(),
                h(scheduled),
                h(expiry),
                Some(h(scheduled)),
                s.clone(),
                None,
            ));
        }
        let funding: Vec<Zatoshis> = transfer_states.iter().map(|_| zat(100_000_000)).collect();
        test_state_from_parts(
            status,
            DenominationPlan::from_stored_parts(
                funding.clone(),
                zat(10_000),
                None,
                zat(20_000),
                zat(1_000_000_000),
                zat(999_000_000),
            )
            .unwrap(),
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            transactions,
            AnchorBucketInterval::ZIP_318,
        )
    }

    const MINED: MigrationTxState = MigrationTxState::Mined {
        txid: TxId::from_bytes([0u8; 32]),
        height: BlockHeight::from_u32(100),
    };

    // ----- progress derivation (`active_run_progress` / `immediate_run_pending`) -----

    #[test]
    fn active_run_progress_counts_mined_transfers() {
        // Preparations count toward none of the three fields; transfers count whatever their
        // lifecycle state (2 preps + 3 transfers, 1 of them mined).
        let state = test_state(
            MigrationStatus::InProgress,
            &[MINED, MINED],
            &[MINED, MigrationTxState::Signed, MigrationTxState::Signed],
            50,
            10_000,
        );
        let (completed, total, next_ready) = active_run_progress(&state);
        assert_eq!(completed, 1);
        assert_eq!(total, 3);
        assert_eq!(next_ready, Some(h(50)));
    }

    /// The progress snapshot is present for ANY active (non-terminal) run — including one whose
    /// preparations have not mined yet (the old 5-state machine's SplitPendingConfirmation gate
    /// is gone): the counters simply report 0 completed.
    #[test]
    fn active_run_progress_reports_during_unmined_preparation() {
        let state = test_state(
            MigrationStatus::InProgress,
            &[MigrationTxState::Signed],
            &[MigrationTxState::Signed],
            50,
            10_000,
        );
        let (completed, total, next_ready) = active_run_progress(&state);
        assert_eq!(completed, 0);
        assert_eq!(total, 1);
        assert_eq!(next_ready, Some(h(50)));
    }

    /// F6: `next_transfer_ready_at_height` must be the min `scheduled_height()` over transfers
    /// that are still awaiting broadcast (`AwaitingSignature`/`Signed`/`Proved`), not merely "not
    /// yet mined". A `Broadcast` transfer is already in the mempool — there is nothing left for
    /// the platform to prepare or broadcast for it — so its height must not win even when it is
    /// numerically the smallest. Two transfers at DIFFERENT scheduled heights (the low one
    /// `Broadcast`, the high one `Signed`) pin the exact bug a `!= Mined` filter would have: it
    /// would still count the `Broadcast` row, reporting its LOWER height instead of the `Signed`
    /// row's.
    #[test]
    fn active_run_progress_next_ready_excludes_already_broadcast_transfers() {
        let transactions = vec![
            // Broadcast (in-mempool) at the LOW height — must be excluded.
            test_transaction_from_parts(
                MigrationTransferId::new(0),
                MigrationTxKind::Transfer { crossing: 0 },
                vec![0u8],
                Vec::new(),
                h(50),
                h(10_000),
                Some(h(50)),
                MigrationTxState::Broadcast {
                    txid: TxId::from_bytes([0u8; 32]),
                },
                None,
            ),
            // Signed (still awaiting broadcast) at the HIGHER height — must win.
            test_transaction_from_parts(
                MigrationTransferId::new(1),
                MigrationTxKind::Transfer { crossing: 1 },
                vec![0u8],
                Vec::new(),
                h(150),
                h(10_000),
                Some(h(150)),
                MigrationTxState::Signed,
                None,
            ),
        ];
        let state = test_state_from_parts(
            MigrationStatus::InProgress,
            DenominationPlan::from_stored_parts(
                vec![zat(100_000_000), zat(100_000_000)],
                zat(10_000),
                None,
                zat(20_000),
                zat(1_000_000_000),
                zat(999_000_000),
            )
            .unwrap(),
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            transactions,
            AnchorBucketInterval::ZIP_318,
        );
        let (_, _, next_ready) = active_run_progress(&state);
        assert_eq!(
            next_ready,
            Some(h(150)),
            "a Broadcast (in-mempool) transfer must not count as 'next ready' even when its \
             scheduled height is numerically lower than a not-yet-broadcast transfer's"
        );
    }

    /// F6: once every transfer is `Broadcast` or `Mined`, nothing remains awaiting broadcast, so
    /// there is no "next ready" height at all (the field's `-1`/`None` sentinel).
    #[test]
    fn active_run_progress_next_ready_none_when_all_transfers_broadcast_or_mined() {
        let transactions = vec![
            test_transaction_from_parts(
                MigrationTransferId::new(0),
                MigrationTxKind::Transfer { crossing: 0 },
                vec![0u8],
                Vec::new(),
                h(50),
                h(10_000),
                Some(h(50)),
                MigrationTxState::Broadcast {
                    txid: TxId::from_bytes([0u8; 32]),
                },
                None,
            ),
            test_transaction_from_parts(
                MigrationTransferId::new(1),
                MigrationTxKind::Transfer { crossing: 1 },
                vec![0u8],
                Vec::new(),
                h(150),
                h(10_000),
                Some(h(150)),
                MINED,
                None,
            ),
        ];
        let state = test_state_from_parts(
            MigrationStatus::InProgress,
            DenominationPlan::from_stored_parts(
                vec![zat(100_000_000), zat(100_000_000)],
                zat(10_000),
                None,
                zat(20_000),
                zat(1_000_000_000),
                zat(999_000_000),
            )
            .unwrap(),
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            transactions,
            AnchorBucketInterval::ZIP_318,
        );
        let (completed, total, next_ready) = active_run_progress(&state);
        assert_eq!((completed, total), (1, 2));
        assert_eq!(next_ready, None);
    }

    /// Builds an [`ImmediateRunLookup`] directly (bypassing the wallet-DB lookup), for exercising
    /// [`immediate_run_pending`] in isolation.
    fn immediate_lookup(
        recorded_at: u32,
        mined: Option<u32>,
        expiry: Option<u32>,
    ) -> ImmediateRunLookup {
        ImmediateRunLookup {
            recorded_at_height: h(recorded_at),
            mined_height: mined.map(h),
            expiry_height: expiry.map(h),
        }
    }

    #[test]
    fn immediate_run_unmined_within_expiry_is_pending() {
        let run = immediate_lookup(100, None, Some(500));
        assert!(immediate_run_pending(&run, h(300)));
    }

    #[test]
    fn immediate_run_mined_is_not_pending() {
        // A mined immediate sweep is CONSUMED — the swept balance is zero and there is nothing
        // for the app to acknowledge, so it reports no progress at all.
        let run = immediate_lookup(100, Some(250), Some(500));
        assert!(!immediate_run_pending(&run, h(300)));
    }

    #[test]
    fn immediate_run_expired_unmined_is_not_pending() {
        let run = immediate_lookup(100, None, Some(200));
        assert!(!immediate_run_pending(&run, h(300)));
    }

    #[test]
    fn immediate_run_unknown_expiry_uses_fallback_bound() {
        let run = immediate_lookup(100, None, None);
        // Still within the fallback bound (100 + 40 = 140).
        assert!(immediate_run_pending(&run, h(140)));
        // Past the fallback bound: expired.
        assert!(!immediate_run_pending(&run, h(141)));
    }

    #[test]
    fn transfer_amount_is_net_of_fee_buffer() {
        let state = test_state(
            MigrationStatus::InProgress,
            &[MINED],
            &[MigrationTxState::Signed],
            50,
            10_000,
        );
        let tx = state
            .transactions()
            .iter()
            .find(|t| matches!(t.kind(), MigrationTxKind::Transfer { .. }))
            .unwrap();
        // test_state's note split stores zat(100_000_000) CROSSING (net) values against a
        // zat(10_000) fee buffer; `funding_notes()` derives the gross 100_010_000 note and
        // `transfer_amount` nets the buffer back off, landing on the stored crossing value.
        assert_eq!(transfer_amount(&state, tx), Some(zat(100_000_000)));
    }

    /// The TRANSFER rows of a plan's enumeration as [`MigrationPlan::planned_transactions`]
    /// emits them for `schedule`: `prep_tx_count` preparation transactions are numbered first, so
    /// crossing `i` carries id `prep_tx_count + i` and the broadcast height its schedule entry
    /// drew. `schedule_rows` reads exactly these two fields off the row, so this is what a real
    /// plan hands it.
    fn planned_transfers(
        prep_tx_count: u32,
        schedule: &[zcash_pool_migration::scheduling::Schedule],
    ) -> Vec<PlannedTx> {
        schedule
            .iter()
            .enumerate()
            .map(|(crossing, entry)| {
                PlannedTx::new(
                    MigrationTransferId::new(prep_tx_count + crossing as u32),
                    MigrationTxKind::Transfer { crossing },
                    Vec::new(),
                    Some(entry.broadcast_height()),
                )
            })
            .collect()
    }

    #[test]
    fn schedule_rows_sort_chronologically_with_prep_offset() {
        let mut rng = StdRng::seed_from_u64(7);
        let schedule = scheduling::schedule(&SchedulingParams::ZIP_318, h(1_000), 5, &mut rng);
        // The engine hands the crossing values straight over; they are already net of the fee
        // buffer that pays each transfer's own fee.
        let crossing_values: Vec<Zatoshis> = (1..=5).map(|i| zat(i * 100_000_000)).collect();
        let rows = schedule_rows(
            &planned_transfers(3, &schedule),
            &crossing_values,
            &schedule,
        )
        .unwrap();
        assert_eq!(rows.len(), 5);
        // Chronological by broadcast height.
        for pair in rows.windows(2) {
            assert!(pair[0].2 <= pair[1].2);
        }
        // Ids are offset by the preparation count and cover exactly the transfer range.
        let mut ids: Vec<u32> = rows.iter().map(|(id, _, _, _)| u32::from(*id)).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![3, 4, 5, 6, 7]);
        // Amount pairing survives the sort: each id maps back to the crossing value at the same
        // index — the engine's authoritative NET value, not a re-derived one.
        for (id, amount, _, _) in &rows {
            let crossing = u32::from(*id) - 3;
            assert_eq!(*amount, crossing_values[crossing as usize]);
        }
    }

    #[test]
    fn schedule_rows_net_amounts_are_stable_across_reshuffled_schedules() {
        // Two different draws (different rng seeds -> different shuffled broadcast order) of the
        // same crossing values must still report the same total (and the same multiset) of NET
        // amounts, even though the rows themselves may come back in a different order.
        let crossing_values: Vec<Zatoshis> = (1..=5).map(|i| zat(i * 100_000_000)).collect();
        let expected_total: u64 = crossing_values.iter().map(|z| u64::from(*z)).sum();

        let mut rng_a = StdRng::seed_from_u64(1);
        let schedule_a = scheduling::schedule(&SchedulingParams::ZIP_318, h(1_000), 5, &mut rng_a);
        let rows_a = schedule_rows(
            &planned_transfers(0, &schedule_a),
            &crossing_values,
            &schedule_a,
        )
        .unwrap();

        let mut rng_b = StdRng::seed_from_u64(99);
        let schedule_b = scheduling::schedule(&SchedulingParams::ZIP_318, h(1_000), 5, &mut rng_b);
        let rows_b = schedule_rows(
            &planned_transfers(0, &schedule_b),
            &crossing_values,
            &schedule_b,
        )
        .unwrap();

        let total_a: u64 = rows_a
            .iter()
            .map(|(_, amount, _, _)| u64::from(*amount))
            .sum();
        let total_b: u64 = rows_b
            .iter()
            .map(|(_, amount, _, _)| u64::from(*amount))
            .sum();
        assert_eq!(total_a, expected_total);
        assert_eq!(total_b, expected_total);

        let mut sorted_a: Vec<u64> = rows_a
            .iter()
            .map(|(_, amount, _, _)| u64::from(*amount))
            .collect();
        let mut sorted_b: Vec<u64> = rows_b
            .iter()
            .map(|(_, amount, _, _)| u64::from(*amount))
            .collect();
        sorted_a.sort_unstable();
        sorted_b.sort_unstable();
        assert_eq!(sorted_a, sorted_b);
    }

    #[test]
    fn schedule_rows_reject_length_mismatch() {
        let mut rng = StdRng::seed_from_u64(7);
        let schedule = scheduling::schedule(&SchedulingParams::ZIP_318, h(1_000), 3, &mut rng);
        let crossing_values = vec![zat(100)];
        assert!(
            schedule_rows(
                &planned_transfers(0, &schedule),
                &crossing_values,
                &schedule
            )
            .is_err()
        );
    }

    /// F3 pin: `schedule_rows`' amount is BOTH the engine's authoritative
    /// `note_split().crossing_values()[crossing]` (trivially — that is now its input) AND the
    /// legacy `funding_notes()[crossing] - note_fee_buffer` computation it replaces, proven equal
    /// for a real `DenominationPlan`. Pure refactor: values are identical, so this is green
    /// immediately (no red phase — see F3's task doc).
    #[test]
    fn schedule_rows_amount_matches_engine_crossing_values_and_legacy_subtraction() {
        let mut rng = StdRng::seed_from_u64(11);
        let crossing_values = vec![zat(100_000_000), zat(250_000_000), zat(40_000_000)];
        let note_split = DenominationPlan::from_stored_parts(
            crossing_values.clone(),
            zat(10_000),
            None,
            zat(20_000),
            zat(1_000_000_000),
            zat(999_000_000),
        )
        .unwrap();
        let schedule = scheduling::schedule(
            &SchedulingParams::ZIP_318,
            h(1_000),
            crossing_values.len(),
            &mut rng,
        );
        let rows = schedule_rows(
            &planned_transfers(0, &schedule),
            note_split.crossing_values(),
            &schedule,
        )
        .unwrap();
        assert_eq!(rows.len(), crossing_values.len());
        for (id, amount, _, _) in &rows {
            let crossing = u32::from(*id) as usize;
            // Side 1 of the identity: the engine's authoritative crossing value.
            assert_eq!(*amount, note_split.crossing_values()[crossing]);
            // Side 2: the legacy `funding_notes()[crossing] - note_fee_buffer` computation F3
            // replaced — provably the same value, never re-derived at runtime anymore.
            let legacy = (note_split.migration_outputs()[crossing] - note_split.note_fee_buffer())
                .expect("a real plan's funding note is never smaller than its own fee buffer");
            assert_eq!(*amount, legacy);
        }
    }

    // ----- schedule-duration semantics (#1806): from `now` to the LAST scheduled broadcast -----

    /// The headline case: `now` before both broadcast heights, so the wait until the FIRST
    /// transfer fires is included — the old first-to-last span math would have said
    /// `(1_000_432 - 1_000_336) / 48 == 2`; measuring from `now` instead gives `9`.
    #[test]
    fn estimated_duration_hours_is_measured_from_now_to_the_last_broadcast() {
        let heights = [h(1_000_336), h(1_000_432)];
        assert_eq!(
            estimated_duration_hours(heights.into_iter(), h(1_000_000)),
            9
        );
    }

    #[test]
    fn estimated_duration_hours_empty_schedule_is_zero() {
        assert_eq!(
            estimated_duration_hours(std::iter::empty(), h(1_000_000)),
            0
        );
    }

    #[test]
    fn estimated_duration_hours_all_overdue_is_zero() {
        // Every broadcast height is at or behind `now`: the saturating subtraction must clamp to
        // `0` rather than underflowing.
        let heights = [h(900_000), h(950_000), h(1_000_000)];
        assert_eq!(
            estimated_duration_hours(heights.into_iter(), h(1_000_000)),
            0
        );
    }

    /// The state-side counterpart, over hand-built `MigrationTransaction` rows: only
    /// `scheduled_height()` is read, so a minimal Transfer-kind row with placeholder PCZT bytes
    /// suffices.
    fn transfer_at(id: u32, scheduled: u32) -> MigrationTransaction {
        test_transaction_from_parts(
            MigrationTransferId::new(id),
            MigrationTxKind::Transfer { crossing: 0 },
            vec![0u8],
            Vec::new(),
            h(scheduled),
            h(scheduled + 10_000),
            Some(h(scheduled)),
            MigrationTxState::Signed,
            None,
        )
    }

    #[test]
    fn stored_duration_hours_is_measured_from_now_to_the_last_scheduled_height() {
        let a = transfer_at(0, 1_000_336);
        let b = transfer_at(1, 1_000_432);
        assert_eq!(stored_duration_hours(&[&a, &b], h(1_000_000)), 9);
    }

    #[test]
    fn stored_duration_hours_empty_is_zero() {
        assert_eq!(stored_duration_hours(&[], h(1_000_000)), 0);
    }

    #[test]
    fn stored_duration_hours_all_overdue_is_zero() {
        let a = transfer_at(0, 900_000);
        let b = transfer_at(1, 950_000);
        assert_eq!(stored_duration_hours(&[&a, &b], h(1_000_000)), 0);
    }

    /// The DTO-constructing encode path end to end: `encode_schedule_from_state` must thread its
    /// `now_reference` into the SAME `max - now` math as the pure helper above, not silently keep
    /// the old first-to-last span (old math here would have said `2`, not `9`).
    #[test]
    fn encode_schedule_from_state_measures_duration_from_now_reference() {
        let transactions = vec![
            test_transaction_from_parts(
                MigrationTransferId::new(0),
                MigrationTxKind::Transfer { crossing: 0 },
                vec![0u8],
                Vec::new(),
                h(1_000_336),
                h(1_100_000),
                Some(h(1_000_336)),
                MigrationTxState::Signed,
                None,
            ),
            test_transaction_from_parts(
                MigrationTransferId::new(1),
                MigrationTxKind::Transfer { crossing: 1 },
                vec![0u8],
                Vec::new(),
                h(1_000_432),
                h(1_100_000),
                Some(h(1_000_432)),
                MigrationTxState::Signed,
                None,
            ),
        ];
        let state = test_state_from_parts(
            MigrationStatus::InProgress,
            DenominationPlan::from_stored_parts(
                vec![zat(100_000_000), zat(100_000_000)],
                zat(0),
                None,
                zat(20_000),
                zat(1_000_000_000),
                zat(999_000_000),
            )
            .unwrap(),
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            transactions,
            AnchorBucketInterval::ZIP_318,
        );

        let schedule_ptr =
            encode_schedule_from_state(&state, h(1_000_000)).expect("encoding must succeed");
        let schedule = unsafe { &*schedule_ptr };
        assert_eq!(schedule.estimated_duration_hours, 9);
        assert_eq!(
            schedule.preparations_len, 0,
            "no preparation-kind transaction is stored in this fixture"
        );
        unsafe { zcashlc_free_migration_schedule(schedule_ptr) };
    }

    /// A comparable snapshot of one [`FfiMigrationPreparationStep`] row, for
    /// [`migration_schedule_preparations_agree_between_propose_and_re_serve`].
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct PreparationStepSnapshot {
        id: u32,
        layer: u32,
        index: u32,
        broadcast_height: i64,
        depends_on: Vec<u32>,
    }

    /// Reads every `preparations` row of `schedule` into an order-independent, comparable
    /// snapshot (sorted, so incidental traversal-order differences between the two encoders
    /// cannot hide — or manufacture — a mismatch; CONTENT agreement is what is under test, not
    /// row order).
    ///
    /// # Safety
    /// `schedule` must be a live [`FfiMigrationSchedule`] whose `preparations` array (and each
    /// row's `depends_on` array) has not been freed.
    unsafe fn snapshot_preparation_steps(
        schedule: &FfiMigrationSchedule,
    ) -> Vec<PreparationStepSnapshot> {
        let rows =
            unsafe { std::slice::from_raw_parts(schedule.preparations, schedule.preparations_len) };
        let mut out: Vec<PreparationStepSnapshot> = rows
            .iter()
            .map(|r| PreparationStepSnapshot {
                id: r.id,
                layer: r.layer,
                index: r.index,
                broadcast_height: r.broadcast_height,
                depends_on: unsafe { std::slice::from_raw_parts(r.depends_on, r.depends_on_len) }
                    .to_vec(),
            })
            .collect();
        out.sort();
        out
    }

    /// G (item 11r): the PROPOSE-path preview's `preparations` — derived read-only from the
    /// `MigrationPlan`, mirroring the engine's own commit-time numbering (see
    /// [`preparation_steps_from_plan`]) — agree EXACTLY with the RE-SERVE-path preview's
    /// `preparations` — read straight off the committed rows (see
    /// [`preparation_steps_from_state`]) — for the SAME plan, once committed. This is the
    /// strongest test of the PROPOSE-path derivation: a wrong id numbering, a wrong `depends_on`,
    /// or a stale broadcast height would show up as a disagreement with what the engine itself
    /// actually stored, not just an internally-consistent-but-wrong answer.
    #[test]
    fn migration_schedule_preparations_agree_between_propose_and_re_serve() {
        let path = init_fixture_db("zcashlc_migration_schedule_preparations_propose_vs_reserve");
        let (account_bytes, usk_bytes) = create_fixture_account_with_usk(&path);
        // A near-`MAX_MONEY` note (20,000,000 ZEC): the balanced fan-out tree
        // (`zcash_pool_migration::preparation`'s `whale_fan_out_layer_counts`) needs more than
        // `FUNDING_OUTPUTS_PER_TX` funding notes at this scale, so the plan gets a SECOND
        // preparation layer — empirically confirmed (`layers == {0, 1}`) — which is what exercises
        // `preparation_steps_from_plan`'s `depends_on` branch for `layer > 0` end-to-end, not just
        // the trivial empty-`depends_on` layer-0 case a smaller fixture value would give.
        fund_fixture_account_with_orchard_note(&path, &usk_bytes, 2_000_000_000_000_000);
        let path_bytes = path.to_str().unwrap().as_bytes();
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_600_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );

        let propose_ptr = unsafe {
            zcashlc_migration_propose_transfers(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account_bytes.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert!(
            !propose_ptr.is_null(),
            "a funded account must propose a real schedule"
        );
        let proposed = unsafe { &*propose_ptr };
        assert!(
            proposed.preparations_len > 0,
            "a funded account needing a split must preview preparation steps"
        );
        let propose_snapshot = unsafe { snapshot_preparation_steps(proposed) };
        assert!(
            propose_snapshot.iter().any(|s| s.layer > 0),
            "the fixture value must actually reach a second preparation layer, or this test \
             would not exercise the layer > 0 depends_on branch at all: {propose_snapshot:?}"
        );
        let handle = proposed.proposal_handle;
        unsafe { zcashlc_free_migration_schedule(propose_ptr) };

        let committed = unsafe {
            zcashlc_migration_sign_and_store_schedule(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account_bytes.as_ptr(),
                NETWORK_ID_MAINNET,
                handle,
                usk_bytes.as_ptr(),
                usk_bytes.len(),
            )
        };
        assert!(committed, "committing the previewed plan must succeed");

        // `usk_ptr = NULL` (the external-signer lane's "not signing here" convention — see
        // `zcashlc_migration_refresh_stale_transfers`'s doc): nothing is expired yet, so this
        // reads the just-committed schedule back via `encode_schedule_from_state` without
        // needing a spending key.
        let reserve_ptr = unsafe {
            zcashlc_migration_refresh_stale_transfers(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account_bytes.as_ptr(),
                NETWORK_ID_MAINNET,
                std::ptr::null(),
                0,
            )
        };
        assert!(
            !reserve_ptr.is_null(),
            "re-serving the committed schedule must succeed"
        );
        let reserved = unsafe { &*reserve_ptr };
        let reserve_snapshot = unsafe { snapshot_preparation_steps(reserved) };

        assert_eq!(
            propose_snapshot, reserve_snapshot,
            "the propose-path preview must agree exactly with the committed, re-served rows"
        );

        unsafe { zcashlc_free_migration_schedule(reserve_ptr) };
        let _ = std::fs::remove_file(&path);
    }

    /// Safety net for #1806 (audit item 2): pins that this module's plan preview reports the
    /// engine's own [`MigrationPlan::planned_transactions`] enumeration. It was written while
    /// [`preparation_steps_from_plan`] and [`schedule_rows`] still RE-DERIVED those numbers, to
    /// catch the rewrite that made them read the enumeration directly changing any answer; it
    /// passed unmodified across that rewrite, and now guards the marshalling on top — that no id
    /// is renumbered, dropped or reordered between the enumeration and the DTO rows.
    ///
    /// (a) `preparation_steps_from_plan`'s `(id, layer, index)` triples, in order, against the
    /// same triples read off `planned_transactions()`'s preparation-kind entries.
    /// (b) `schedule_rows`' emitted ids, as a SET, against `planned_transactions()`'s
    /// transfer-kind ids, also as a set (chosen over comparing the first/MIN row id: this
    /// fixture's chronological re-sort makes "first row" not a stable comparison point, and the
    /// set form is a strictly stronger check anyway — it pins every id, not just the smallest).
    #[test]
    fn preview_ids_come_from_the_engines_planned_enumeration() {
        let path = init_fixture_db("zcashlc_migration_preview_ids_match_planned_enumeration");
        let (account_bytes, usk_bytes) = create_fixture_account_with_usk(&path);
        // Same near-`MAX_MONEY` fixture value as
        // `migration_schedule_preparations_agree_between_propose_and_re_serve`: forces a SECOND
        // preparation layer, so assertion (a) below exercises more than the trivial
        // single-layer case.
        fund_fixture_account_with_orchard_note(&path, &usk_bytes, 2_000_000_000_000_000);
        let path_bytes = path.to_str().unwrap().as_bytes();
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_600_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );

        let mut ctx = unsafe {
            open(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account_bytes.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        }
        .expect("the fixture context opens");

        let (plan, _reference_height, _handle) = plan_and_cache(&mut ctx, false)
            .expect("planning must succeed")
            .expect("the funded account has a real migration plan");

        let planned = plan.planned_transactions();
        assert!(
            planned
                .iter()
                .filter(|t| t.is_preparation())
                .any(|t| matches!(
                    t.kind(),
                    MigrationTxKind::Preparation { layer, .. } if layer > 0
                )),
            "the fixture value must actually reach a second preparation layer, or this test \
             would not exercise the multi-layer case at all"
        );

        // (a)
        let expected_preparations: Vec<(u32, u32, u32)> = planned
            .iter()
            .filter_map(|t| match t.kind() {
                MigrationTxKind::Preparation { layer, index } => {
                    Some((u32::from(t.id()), layer as u32, index as u32))
                }
                MigrationTxKind::Transfer { .. } => None,
            })
            .collect();
        let steps = preparation_steps_from_plan(&plan).expect("preparation steps must compute");
        let actual_preparations: Vec<(u32, u32, u32)> =
            steps.iter().map(|s| (s.id, s.layer, s.index)).collect();
        assert_eq!(
            actual_preparations, expected_preparations,
            "preparation_steps_from_plan's (id, layer, index) triples must match the engine's \
             own planned enumeration, in order"
        );
        for step in &steps {
            free_ptr_from_vec(step.depends_on, step.depends_on_len);
        }

        // (b)
        let expected_transfer_ids: HashSet<MigrationTransferId> = planned
            .iter()
            .filter(|t| t.is_transfer())
            .map(|t| t.id())
            .collect();
        let rows = schedule_rows(&planned, plan.crossing_values(), plan.schedule())
            .expect("schedule rows must compute");
        let actual_transfer_ids: HashSet<MigrationTransferId> =
            rows.iter().map(|(id, _, _, _)| *id).collect();
        assert_eq!(
            actual_transfer_ids, expected_transfer_ids,
            "schedule_rows' ids must be exactly the engine's own planned Transfer-kind ids"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The handle gate's miss behavior: an empty cache reports `Missing` for ANY handle,
    /// including the `0` "no plan" sentinel a state-encoded or empty schedule carries. A real
    /// plan is unconstructible here (no public constructor), so the `Superseded` arm — a cached
    /// plan under a DIFFERENT handle — is pinned structurally by `migration_plan_cache::get`'s
    /// three-arm match here, and end-to-end (a real plan, genuinely superseded by a later one)
    /// by [`commit_or_resume_rejects_a_superseded_handle_with_plan_stale`] below.
    #[test]
    fn plan_cache_lookup_misses_and_clear() {
        use migration_plan_cache::PlanLookupError;

        let path = PathBuf::from("/tmp/zcashlc-plan-cache-test");
        let account = [3u8; 16];
        // (`matches!`, not `unwrap_err`: the Ok side holds a `MigrationPlan`, which has no
        // `Debug` impl.)
        assert!(matches!(
            migration_plan_cache::get(&path, account, 0),
            Err(PlanLookupError::Missing)
        ));
        assert!(matches!(
            migration_plan_cache::get(&path, account, 0xDEAD_BEEF),
            Err(PlanLookupError::Missing)
        ));
        migration_plan_cache::clear(&path, account);
        assert!(matches!(
            migration_plan_cache::get(&path, account, 1),
            Err(PlanLookupError::Missing)
        ));
        // The stable recovery signal: both lookup failures route through the
        // `MIGRATION_PLAN_STALE` prefix at the FFI boundary (`commit_or_resume`), so the
        // Display text is the platform-visible remediation message.
        assert!(
            PlanLookupError::Missing
                .to_string()
                .contains("propose again")
        );
        assert!(
            PlanLookupError::Superseded
                .to_string()
                .contains("superseded")
        );
    }

    // ----- plan-cache supersession contract, end-to-end against a REALLY funded wallet
    // (#1806 / MOB-1458): `plan_and_cache`'s only input is `engine::plan_migration`, which has
    // no test-only backdoor (see `plan_cache_lookup_misses_and_clear`'s doc: the plan type has
    // no public constructor), so pinning the handle contract against a genuine plan means the
    // fixture wallet must hold a genuine spendable Orchard note. `zcash_client_backend`'s own
    // `TestBuilder` harness (the `test-dependencies` feature) would normally build one, but this
    // crate does not enable that feature (and its `WalletDb<_, LocalNetwork, FixedClock,
    // ChaChaRng>` is a different concrete type than this crate's own `MigrationWallet` /
    // `NetworkParams` anyway) — so [`fund_fixture_account_with_orchard_note`] below drives the
    // SAME production `scan_cached_blocks` entry point `zcashlc_scan_blocks` wraps, fed one
    // in-memory synthetic compact block instead of the filesystem block cache, exactly mirroring
    // (with only non-test-gated `orchard`/`zcash_client_backend` APIs) the `compact_orchard_action`
    // recipe `zcash_client_backend::data_api::testing` itself uses under `test-dependencies`.

    /// A [`chain::BlockSource`] over an in-memory list of compact blocks — the funding-fixture
    /// counterpart of the filesystem-backed cache the real sync pipeline reads from
    /// (`zcashlc_scan_blocks` / `crate::block_db`), avoiding that filesystem/metadata-db setup
    /// for what is here a single synthetic block.
    struct FixtureBlockSource(Vec<zcash_client_backend::proto::compact_formats::CompactBlock>);

    impl zcash_client_backend::data_api::chain::BlockSource for FixtureBlockSource {
        type Error = std::convert::Infallible;

        fn with_blocks<F, WalletErrT>(
            &self,
            from_height: Option<BlockHeight>,
            limit: Option<usize>,
            mut with_block: F,
        ) -> Result<(), zcash_client_backend::data_api::chain::error::Error<WalletErrT, Self::Error>>
        where
            F: FnMut(
                zcash_client_backend::proto::compact_formats::CompactBlock,
            ) -> Result<
                (),
                zcash_client_backend::data_api::chain::error::Error<WalletErrT, Self::Error>,
            >,
        {
            let from = from_height.map(u32::from).unwrap_or(0);
            let take = limit.unwrap_or(usize::MAX);
            for block in self.0.iter().filter(|b| b.height as u32 >= from).take(take) {
                with_block(block.clone())?;
            }
            Ok(())
        }
    }

    /// A single real, trial-decryptable Orchard `CompactOrchardAction` paying `value_zat` to the
    /// external address (diversifier index 0) of `usk`'s Orchard full viewing key — built
    /// directly with `orchard`'s note-encryption primitives. Mirrors librustzcash's own
    /// `compact_orchard_action` test helper (`zcash_client_backend::data_api::testing`, gated
    /// behind the `test-dependencies` feature this crate does not enable) using only the
    /// non-test-gated `orchard`/`zcash_note_encryption` APIs that helper itself is built from —
    /// the same relationship [`fixture_transfer_pczt_bytes`] already has to a hand-built PCZT.
    /// `seed_offset` displaces the deterministic RNG seed, so [`fund_fixture_account_with_orchard_notes`]
    /// can fund several distinct notes (distinct nullifier/rho/rseed) in one call; `0` reproduces
    /// the single-note fixture's original, byte-for-byte fixed output.
    fn fixture_orchard_compact_action(
        usk: &zcash_keys::keys::UnifiedSpendingKey,
        value_zat: u64,
        seed_offset: u64,
    ) -> zcash_client_backend::proto::compact_formats::CompactOrchardAction {
        use orchard::keys::{FullViewingKey, Scope};
        use orchard::note::{ExtractedNoteCommitment, Note, NoteVersion, RandomSeed, Rho};
        use orchard::note_encryption::{OrchardDomain, OrchardNoteEncryption};
        use orchard::value::NoteValue;
        use rand::RngCore;
        use zcash_client_backend::proto::compact_formats::CompactOrchardAction;
        use zcash_note_encryption::Domain;

        let fvk = FullViewingKey::from(usk.orchard());
        let recipient = fvk.address_at(0u32, Scope::External);

        let mut rng = StdRng::seed_from_u64(0x1806_0002 + seed_offset);
        // The wire `nullifier` field IS the spend half of this same action: by construction the
        // new note's `rho` always equals the nullifier revealed by the action's spend
        // (`Rho::from_nf_old(nf) == Rho(nf.inner())` -- same underlying field element, just
        // distinct newtypes), and the compact plaintext deliberately omits `rho` because it is
        // always recoverable this way. The scanner reconstructs `rho` from the wire nullifier and
        // recomputes the commitment to verify the decrypted plaintext, so an unrelated random
        // nullifier (independent of the note's actual `rho`) makes that recomputed commitment
        // never match `cmx` -- silently dropping the note instead of erroring.
        let mut nf_old = [0u8; 32];
        let rho = loop {
            rng.fill_bytes(&mut nf_old);
            if let Some(rho) = Rho::from_bytes(&nf_old).into_option() {
                break rho;
            }
        };
        let rseed = loop {
            let mut draw = [0u8; 32];
            rng.fill_bytes(&mut draw);
            if let Some(rseed) = RandomSeed::from_bytes(draw, &rho).into_option() {
                break rseed;
            }
        };
        let note = Note::from_parts(
            recipient,
            NoteValue::from_raw(value_zat),
            rho,
            rseed,
            NoteVersion::V2,
        )
        .into_option()
        .expect("valid fixture note parts");

        // No outgoing viewing key: the wallet detects this note via its OWN incoming viewing
        // key on trial decryption, which the compact ciphertext supports independent of OVK.
        let encryptor = OrchardNoteEncryption::new(None, note, [0u8; 512]);
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        let ephemeral_key = OrchardDomain::epk_bytes(encryptor.epk());
        let enc_ciphertext = encryptor.encrypt_note_plaintext();

        CompactOrchardAction {
            nullifier: nf_old.to_vec(),
            cmx: cmx.to_bytes().to_vec(),
            ephemeral_key: ephemeral_key.0.to_vec(),
            ciphertext: enc_ciphertext[..52].to_vec(),
        }
    }

    /// [`fund_fixture_account_with_orchard_notes`] for exactly one note — the common case nearly
    /// every fixture wallet wants. `value_zat` should be an amount that is not itself a single
    /// canonical ZIP 318 denomination (e.g. not an exact `{1,2,5}·10^k` ZEC amount), so the note
    /// actually needs splitting — exercising preparation transactions, not just a transfer.
    fn fund_fixture_account_with_orchard_note(
        path: &std::path::Path,
        usk_bytes: &[u8],
        value_zat: u64,
    ) {
        fund_fixture_account_with_orchard_notes(path, usk_bytes, &[value_zat]);
    }

    /// Funds the account whose spending key is `usk_bytes` ([`Era::Orchard`]-encoded exactly as
    /// [`create_fixture_account_with_usk`] returns it) with one real, spendable Orchard note per
    /// entry of `values_zat`, by scanning ONE synthetic compact block at height 1 — right after
    /// the empty birthday frontier every [`create_fixture_account_with_usk`] fixture starts from
    /// — through the production [`scan_cached_blocks`] entry point: the same trial-decryption and
    /// commitment-tree insert the real sync pipeline runs, just fed an in-memory block instead of
    /// the filesystem cache `zcashlc_scan_blocks` reads from (so no FS block-metadata-db setup is
    /// needed for one block). Each note is its own transaction (txid tag byte `0xAC` plus a
    /// little-endian `u16` index at bytes 1-2 over a zero background, disjoint from
    /// `seed_placeholder_received_note`'s `[0xAB; 32]`, and distinct nullifier/rho/rseed via
    /// [`fixture_orchard_compact_action`]'s `seed_offset = i`), so the wallet ends up with
    /// `values_zat.len()` independently addressable spendable notes after the one scan — needed to
    /// exercise ordering/snapshot behavior a single note cannot.
    fn fund_fixture_account_with_orchard_notes(
        path: &std::path::Path,
        usk_bytes: &[u8],
        values_zat: &[u64],
    ) {
        use zcash_client_backend::data_api::chain::scan_cached_blocks;
        use zcash_client_backend::proto::compact_formats::{
            ChainMetadata, CompactBlock, CompactTx,
        };
        use zcash_client_backend::proto::service::TreeState;
        use zcash_client_sqlite::WalletDb;
        use zcash_client_sqlite::util::SystemClock;
        use zcash_protocol::consensus::MAIN_NETWORK;

        let usk = unsafe { crate::decode_usk(usk_bytes.as_ptr(), usk_bytes.len()) }
            .expect("the fixture usk decodes");

        let vtx: Vec<CompactTx> = values_zat
            .iter()
            .enumerate()
            .map(|(i, &value_zat)| {
                let action = fixture_orchard_compact_action(&usk, value_zat, i as u64);
                CompactTx {
                    index: (i + 1) as u64,
                    txid: {
                        // Disjoint from `seed_placeholder_received_note`'s [0xAB; 32] by the tag
                        // byte, and unique for arbitrary i via the two-byte index — the old
                        // `0xAB + i` scheme overflowed u8 at i = 85 and collided with the
                        // placeholder at i = 0.
                        let mut txid = vec![0u8; 32];
                        txid[0] = 0xAC;
                        txid[1..3].copy_from_slice(&(i as u16).to_le_bytes());
                        txid
                    },
                    actions: vec![action],
                    ..Default::default()
                }
            })
            .collect();
        let block = CompactBlock {
            height: 1,
            hash: vec![0x11u8; 32],
            prev_hash: vec![0x00u8; 32],
            vtx,
            chain_metadata: Some(ChainMetadata {
                sapling_commitment_tree_size: 0,
                orchard_commitment_tree_size: values_zat.len() as u32,
                ironwood_commitment_tree_size: 0,
            }),
            ..Default::default()
        };

        let mut wallet = WalletDb::for_path(path, MAIN_NETWORK, SystemClock, OsRng)
            .expect("the fixture wallet database must reopen");

        // Height 0, empty frontier: the exact chain state `create_fixture_account_with_usk`'s
        // all-default birthday treestate already commits the account to.
        let from_state = TreeState {
            hash: "00".repeat(32),
            ..TreeState::default()
        }
        .to_chain_state()
        .expect("the empty birthday treestate converts to a chain state");

        let block_source = FixtureBlockSource(vec![block]);
        let summary = scan_cached_blocks(
            &MAIN_NETWORK,
            &block_source,
            &mut wallet,
            h(1),
            &from_state,
            10,
        )
        .expect("scanning the one fixture block must succeed");
        assert_eq!(
            summary.received_orchard_note_count(),
            values_zat.len(),
            "every funded action must be detected as belonging to this wallet"
        );
    }

    /// #1806 / MOB-1466 (librustzcash #2946): the migration adapter must serve every read from a
    /// snapshot taken on first use, never re-running the wallet's full note selection per call.
    /// The snapshot is upstream's own now — this SDK's fork of the adapter is gone — so what is
    /// pinned here is the SDK's side of that contract: [`account_migration`] hands out an adapter
    /// whose index space is fixed for its lifetime over THIS wallet handle, and a fresh one sees
    /// the wallet as it now is.
    ///
    /// The mutation locks both funded notes through a SECOND wallet connection
    /// (`zcashlc_migration_lock_residual`, the same kind of reservation a real migration commit
    /// takes over the notes it is about to spend) — exactly the sort of wallet change a per-call
    /// re-selection is unsafe against: a plan's `PrepInput::Wallet { index }` names a position in
    /// the FIRST read's selection, so a later read observing a different set would resolve the
    /// wrong note (or none) for an index the plan already committed to. The adapter under test
    /// must not observe the lock: a second read through the SAME adapter stays identical to the
    /// first. A FRESH adapter, constructed after the lock, must observe it.
    #[test]
    fn spendable_orchard_notes_snapshots_per_backend_not_per_call() {
        use crate::migration_engine::AccountMigration;
        use orchard::note::ExtractedNoteCommitment;
        use zcash_pool_migration::engine::{MigrationBackend, MigrationCrypto};

        let path = init_fixture_db("zcashlc_migration_spendable_snapshot");
        let (account_bytes, usk_bytes) = create_fixture_account_with_usk(&path);
        fund_fixture_account_with_orchard_notes(&path, &usk_bytes, &[1_000_000_000, 2_000_000_000]);
        let path_bytes = path.to_str().unwrap().as_bytes();
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_600_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );

        let mut ctx = unsafe {
            open(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account_bytes.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        }
        .expect("the fixture context opens");

        // The adapter's index space as the ENGINE addresses it: one entry per selected note, in
        // selection order, each read through BOTH public accessors — the value from
        // `spendable_orchard_note_values` and the note itself from `resolve_wallet_note(i)`,
        // asserted to agree. That agreement is the index-space stability the engine's
        // `PrepInput::Wallet { index }` depends on.
        let snapshot = |backend: &AccountMigration<'_>| -> Vec<(u64, [u8; 32])> {
            let values = backend
                .spendable_orchard_note_values()
                .expect("selection must succeed");
            values
                .iter()
                .enumerate()
                .map(|(i, value)| {
                    let note = backend
                        .resolve_wallet_note(i)
                        .unwrap_or_else(|e| panic!("resolve_wallet_note({i}) must succeed: {e}"));
                    assert_eq!(
                        note.value().inner(),
                        u64::from(*value),
                        "resolve_wallet_note({i})'s value must match the selection's own"
                    );
                    (
                        u64::from(*value),
                        ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
                    )
                })
                .collect()
        };

        let backend = account_migration(&ctx.wallet, ctx.account, &mut ctx.store_conn)
            .expect("adapter construction must succeed");

        let first_snapshot = snapshot(&backend);
        assert_eq!(
            first_snapshot.len(),
            2,
            "the fixture funds exactly two spendable notes"
        );

        // Mutate the wallet through a SECOND connection: lock every currently-spendable note,
        // exactly what a real migration commit does when it reserves the notes it is about to
        // spend.
        let locked = unsafe {
            zcashlc_migration_lock_residual(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account_bytes.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert_eq!(
            locked, 3_000_000_000,
            "locking must report both notes' total value"
        );

        // SAME adapter: a second read must be served from the snapshot, unaffected by the lock
        // the second connection just took.
        let second_snapshot = snapshot(&backend);
        assert_eq!(
            first_snapshot, second_snapshot,
            "a second read through the SAME adapter must be unchanged by the second \
             connection's note lock"
        );

        // A FRESH adapter (same wallet connection, new instance) must observe the mutation.
        drop(backend);
        let fresh = account_migration(&ctx.wallet, ctx.account, &mut ctx.store_conn)
            .expect("adapter construction must succeed");
        let third = snapshot(&fresh);
        assert!(
            third.is_empty(),
            "a fresh adapter must see every note the second connection locked, got {} notes",
            third.len()
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Item 1 of the plan-cache supersession contract: `plan_and_cache` → `commit_or_resume`
    /// with the SAME returned handle signs exactly the cached plan and succeeds, committing the
    /// plan's preparation and transfer transactions. This is the happy path `commit_or_resume`'s
    /// doc promises ("signs exactly the identified plan") and the one every propose/commit FFI
    /// pair (`zcashlc_migration_propose_transfers` + `zcashlc_migration_sign_and_store_schedule`,
    /// `zcashlc_migration_prepare_note_split` + `zcashlc_migration_sign_note_split`) relies on.
    #[test]
    fn commit_or_resume_succeeds_with_the_cached_plans_own_handle() {
        let path = init_fixture_db("zcashlc_migration_commit_with_own_handle");
        let (account_bytes, usk_bytes) = create_fixture_account_with_usk(&path);
        fund_fixture_account_with_orchard_note(&path, &usk_bytes, 1_234_567_890);
        let path_bytes = path.to_str().unwrap().as_bytes();
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_600_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );

        let mut ctx = unsafe {
            open(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account_bytes.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        }
        .expect("the fixture context opens");

        let (plan, _reference_height, handle) = plan_and_cache(&mut ctx, false)
            .expect("planning must succeed")
            .expect("the funded account has a real migration plan");
        assert_ne!(handle, 0, "a real cached plan must mint a non-zero handle");
        assert!(
            !plan.schedule().is_empty(),
            "a funded account's plan must schedule at least one transfer"
        );

        let usk = unsafe { crate::decode_usk(usk_bytes.as_ptr(), usk_bytes.len()) }
            .expect("the fixture usk decodes");
        let (state, unsigned) = commit_or_resume(&mut ctx, Some(usk.orchard()), false, handle)
            .expect("commit with the plan's own handle must succeed");
        assert!(
            unsigned.is_empty(),
            "an in-process signed commit (usk present) returns no pending-signature pczts"
        );
        assert!(
            !state.transactions().is_empty(),
            "the committed state must carry the plan's preparation and transfer transactions"
        );
        assert!(
            !state.is_terminal(),
            "a freshly committed run is in progress, neither complete nor failed"
        );

        // The handle is consumed: `commit_or_resume` clears the slot, so the cache no longer
        // answers for it (a repeat commit with the same handle would now be `Missing`, not a
        // silent re-sign of an already-committed plan).
        assert!(matches!(
            migration_plan_cache::get(&ctx.db_path, ctx.account_bytes, handle),
            Err(migration_plan_cache::PlanLookupError::Missing)
        ));

        let _ = std::fs::remove_file(&path);
    }

    /// Item 2: a later `plan_and_cache` call replaces the cached slot and mints a fresh handle,
    /// superseding the earlier one. `zcashlc_migration_prepare_note_split` and
    /// `zcashlc_migration_propose_transfers` both call this exact function with `immediate =
    /// false`, so two calls in a row is precisely the cache-contract event either pairing
    /// produces (propose-then-prepare, or a second propose): the FIRST handle's commit must fail
    /// with the stable `MIGRATION_PLAN_STALE` prefix and `Superseded` semantics — the actual
    /// MOB-1458 app bug is a UI restart replaying a stale first handle after the wallet has since
    /// re-proposed.
    #[test]
    fn commit_or_resume_rejects_a_superseded_handle_with_plan_stale() {
        let path = init_fixture_db("zcashlc_migration_commit_with_superseded_handle");
        let (account_bytes, usk_bytes) = create_fixture_account_with_usk(&path);
        fund_fixture_account_with_orchard_note(&path, &usk_bytes, 1_234_567_890);
        let path_bytes = path.to_str().unwrap().as_bytes();
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_600_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );

        let mut ctx = unsafe {
            open(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account_bytes.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        }
        .expect("the fixture context opens");

        let (_plan1, _ref1, handle1) = plan_and_cache(&mut ctx, false)
            .expect("the first planning call must succeed")
            .expect("the funded account has a real migration plan");
        let (_plan2, _ref2, handle2) = plan_and_cache(&mut ctx, false)
            .expect("the second planning call must succeed")
            .expect("the funded account still has a real migration plan (nothing was spent)");
        assert_ne!(
            handle1, handle2,
            "each cached plan draws a fresh, distinct handle"
        );

        let usk = unsafe { crate::decode_usk(usk_bytes.as_ptr(), usk_bytes.len()) }
            .expect("the fixture usk decodes");
        let err = commit_or_resume(&mut ctx, Some(usk.orchard()), false, handle1)
            .expect_err("committing with the SUPERSEDED first handle must fail");
        let message = err.to_string();
        assert!(
            message.starts_with(PLAN_STALE_PREFIX),
            "the error must carry the stable MIGRATION_PLAN_STALE prefix: {message}"
        );
        assert!(
            message.contains("superseded"),
            "the detail must be the Superseded arm's message, not Missing's: {message}"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// A spending key that does not belong to the committing account is refused before anything
    /// is built or persisted: the engine derives the key's own full viewing key and checks it
    /// against the account's stored one ([`engine::CommitError::WrongSpendAuthority`], mirroring
    /// upstream librustzcash PR #2951's signing-boundary fix). Constructing the foreign key is a
    /// bare ZIP 32 derivation from an unrelated seed — no second wallet account, and nothing this
    /// test does ever reaches storage.
    #[test]
    fn commit_or_resume_rejects_a_spending_key_that_is_not_the_accounts() {
        let path = init_fixture_db("zcashlc_migration_commit_rejects_foreign_key");
        let (account_bytes, usk_bytes) = create_fixture_account_with_usk(&path);
        fund_fixture_account_with_orchard_note(&path, &usk_bytes, 1_234_567_890);
        let path_bytes = path.to_str().unwrap().as_bytes();
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_600_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );

        let mut ctx = unsafe {
            open(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account_bytes.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        }
        .expect("the fixture context opens");

        let (plan, _reference_height, handle) = plan_and_cache(&mut ctx, false)
            .expect("planning must succeed")
            .expect("the funded account has a real migration plan");
        assert_ne!(handle, 0, "a real cached plan must mint a non-zero handle");
        assert!(
            !plan.schedule().is_empty(),
            "a funded account's plan must schedule at least one transfer"
        );

        // A spending key for a wholly unrelated seed — never registered as any account in this
        // wallet, so its full viewing key cannot match the one the committing account stores.
        let foreign_usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &zcash_protocol::consensus::MAIN_NETWORK,
            &[9u8; 32],
            zip32::AccountId::ZERO,
        )
        .expect("the foreign usk must derive");

        let err = commit_or_resume(&mut ctx, Some(foreign_usk.orchard()), false, handle)
            .expect_err("committing with a foreign spending key must fail");
        let message = err.to_string();
        assert!(
            !message.starts_with(PLAN_STALE_PREFIX),
            "a wrong key is a caller-contract violation, not a stale-plan condition: {message}"
        );
        assert!(
            message.contains("spending key is not the account's"),
            "the error must name the spend-authority mismatch: {message}"
        );

        // The plan handle survives: `commit_or_resume` never reached `migration_plan_cache::clear`,
        // so the SAME handle can still commit with the account's own key.
        assert!(matches!(
            migration_plan_cache::get(&ctx.db_path, ctx.account_bytes, handle),
            Ok(_)
        ));

        let _ = std::fs::remove_file(&path);
    }

    /// Item 3: a stored NON-terminal migration state takes the resume branch in
    /// `commit_or_resume` BEFORE the handle is ever consulted, so a bogus (never-minted, and for
    /// an account whose plan cache was never populated) handle does not stop the resume. This is
    /// the retry path's whole point (see `commit_or_resume`'s doc): once anything is committed
    /// the durable stored run is the truth, and the handle only ever protects the FIRST commit of
    /// a fresh plan.
    #[test]
    fn commit_or_resume_resumes_a_stored_non_terminal_run_without_consulting_the_handle() {
        let path = init_fixture_db("zcashlc_migration_commit_resumes_stored_run");
        let account = create_fixture_account(&path);
        let state = test_state(
            MigrationStatus::InProgress,
            &[],
            &[
                MigrationTxState::AwaitingSignature,
                MigrationTxState::Signed,
            ],
            50,
            10_000,
        );
        store_fixture_state(&path, &account, &state);

        let path_bytes = path.to_str().unwrap().as_bytes();
        let mut ctx = unsafe {
            open(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        }
        .expect("the fixture context opens");

        // Never minted by `migration_plan_cache::set` for this or any account -- the cache is
        // empty here (no `plan_and_cache` call ever ran), so this would fail with
        // `PlanLookupError::Missing` if the handle were consulted at all.
        let bogus_handle: u64 = 0xDEAD_BEEF_DEAD_BEEF;
        let (resumed, unsigned) = commit_or_resume(&mut ctx, None, false, bogus_handle)
            .expect("a stored non-terminal run resumes regardless of the handle");

        assert_eq!(
            resumed.status(),
            MigrationStatus::InProgress,
            "resume returns the STORED state, untouched"
        );
        assert_eq!(
            unsigned.len(),
            1,
            "resume surfaces the stored AwaitingSignature transaction's (id, pczt) pair"
        );

        let _ = std::fs::remove_file(&path);
    }

    // ----- unsigned-PCZT action marshal (item 9r: CREATE vs RE-SERVE) -----

    /// `commit_or_resume`'s unsigned-PCZT triples carry the right action weight on BOTH serve
    /// paths — the CREATE path (`unsigned_out: true` on a fresh commit, from upstream
    /// `UnsignedMigrationTx::actions()`) and the RE-SERVE path (a second call against the
    /// now-stored, non-terminal run, from `action_weight(kind)`) — and the two paths AGREE per
    /// id.
    #[test]
    fn commit_or_resume_unsigned_actions_agree_between_create_and_re_serve() {
        let path = init_fixture_db("zcashlc_migration_commit_or_resume_unsigned_actions");
        let (account_bytes, usk_bytes) = create_fixture_account_with_usk(&path);
        fund_fixture_account_with_orchard_note(&path, &usk_bytes, 1_234_567_890);
        let path_bytes = path.to_str().unwrap().as_bytes();
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_600_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );

        let mut ctx = unsafe {
            open(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account_bytes.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        }
        .expect("the fixture context opens");

        let (_plan, _reference_height, handle) = plan_and_cache(&mut ctx, false)
            .expect("planning must succeed")
            .expect("the funded account has a real migration plan");

        // CREATE path: fresh commit, unsigned.
        let (state, created) = commit_or_resume(&mut ctx, None, true, handle)
            .expect("the fresh unsigned commit must succeed");
        assert!(
            !created.is_empty(),
            "a funded account's commit must build real transactions"
        );
        let expected_kind = |id: MigrationTransferId| {
            state
                .transactions()
                .iter()
                .find(|t| t.id() == id)
                .map(|t| t.kind())
                .expect("every created id must be a stored transaction")
        };
        for (id, _, actions) in &created {
            assert_eq!(
                *actions,
                action_weight(expected_kind(*id)),
                "CREATE-path actions must equal the row's own kind weight"
            );
        }

        // RE-SERVE path: a second call against the SAME now-stored, non-terminal run (the handle
        // is irrelevant here — see
        // `commit_or_resume_resumes_a_stored_non_terminal_run_without_consulting_the_handle`).
        let (_, reserved) = commit_or_resume(&mut ctx, None, true, handle)
            .expect("resuming the stored run must succeed");
        assert_eq!(
            reserved.len(),
            created.len(),
            "re-serve must return the same still-unsigned rows"
        );
        let created_by_id: std::collections::HashMap<u32, u32> = created
            .iter()
            .map(|(id, _, actions)| (u32::from(*id), *actions))
            .collect();
        for (id, _, actions) in &reserved {
            assert_eq!(
                Some(*actions),
                created_by_id.get(&u32::from(*id)).copied(),
                "RE-SERVE-path actions must agree with the CREATE-path actions for the same id"
            );
        }

        let _ = std::fs::remove_file(&path);
    }

    /// The public entry points (`zcashlc_migration_create_unsigned_note_split_pczts` /
    /// `_transfer_pczts`) surface `actions` on the marshaled FFI DTO too — not just internally on
    /// `commit_or_resume`'s tuples. The first call taken here commits the WHOLE run (CREATE); the
    /// second resumes it (RE-SERVE), since a run now exists.
    #[test]
    fn create_unsigned_pczts_marshal_actions_onto_the_ffi_dto() {
        let path = init_fixture_db("zcashlc_migration_create_unsigned_pczts_actions_dto");
        let (account_bytes, usk_bytes) = create_fixture_account_with_usk(&path);
        fund_fixture_account_with_orchard_note(&path, &usk_bytes, 1_234_567_890);
        let path_bytes = path.to_str().unwrap().as_bytes();
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_600_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );

        let schedule_ptr = unsafe {
            zcashlc_migration_propose_transfers(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account_bytes.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert!(
            !schedule_ptr.is_null(),
            "a funded account must propose a real schedule"
        );
        let handle = unsafe { &*schedule_ptr }.proposal_handle;
        unsafe { zcashlc_free_migration_schedule(schedule_ptr) };

        // CREATE branch: whichever of the two functions is called first commits the whole run.
        let preps_ptr = unsafe {
            zcashlc_migration_create_unsigned_note_split_pczts(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account_bytes.as_ptr(),
                NETWORK_ID_MAINNET,
                handle,
            )
        };
        assert!(!preps_ptr.is_null(), "the CREATE commit must succeed");
        let preps = unsafe { &*preps_ptr };
        assert!(
            preps.len > 0,
            "a funded account needing a split must build preparation transactions"
        );
        for row in unsafe { std::slice::from_raw_parts(preps.ptr, preps.len) } {
            assert_eq!(
                row.actions, PREPARATION_ACTIONS,
                "every preparation row must carry the preparation weight"
            );
        }
        unsafe { zcashlc_free_migration_unsigned_transfer_pczts(preps_ptr) };

        // RE-SERVE branch: the run now exists, so this second call resumes it.
        let transfers_ptr = unsafe {
            zcashlc_migration_create_unsigned_transfer_pczts(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account_bytes.as_ptr(),
                NETWORK_ID_MAINNET,
                handle,
            )
        };
        assert!(!transfers_ptr.is_null(), "the re-serve read must succeed");
        let transfers = unsafe { &*transfers_ptr };
        assert!(
            transfers.len > 0,
            "a funded account needing a split must schedule transfers"
        );
        for row in unsafe { std::slice::from_raw_parts(transfers.ptr, transfers.len) } {
            assert_eq!(
                row.actions, TRANSFER_ACTIONS,
                "every transfer row must carry the transfer weight"
            );
        }
        unsafe { zcashlc_free_migration_unsigned_transfer_pczts(transfers_ptr) };

        let _ = std::fs::remove_file(&path);
    }

    /// The ENGINE, not this SDK, stamps the ZIP 32 spend derivation an external signer (Keystone)
    /// needs in order to recognize a migration spend as the account's. `Committer::start` resolves
    /// it once from `MigrationBackend::account_derivation` (upstream's `WalletMigration` answers
    /// it from the account record) and hands it to both builders; their shared `build::finalize_pczt`
    /// runs an `Updater` pass AFTER IO finalization that stamps every action whose spend carries
    /// no `spend_auth_sig`, across the Orchard and Ironwood bundles alike.
    ///
    /// This asserts that on the engine's OWN output — `commit_or_resume`'s return value, which is
    /// what `zcashlc_migration_create_unsigned_note_split_pczts` and `_transfer_pczts` marshal —
    /// every spend still awaiting a signature already resolves to this account's
    /// `m/32'/coin_type'/account'` path. `Zip32Derivation::extract_account_index` checks the seed
    /// fingerprint and the path shape together against values derived from the fixture's own seed,
    /// so a derivation naming a different seed, coin type, or account fails here rather than
    /// passing as merely "present".
    ///
    /// Regression guard for a re-stamp this SDK used to apply on top: an
    /// `annotate_spend_zip32_derivation` pass over each PCZT the two create-unsigned entry points
    /// returned, which recomputed the identical path under the identical predicate with the
    /// identical setter. Should the engine ever stop stamping, that duplication is gone, so this
    /// test is what fails — instead of the failure surfacing only on-device, as Keystone's "None
    /// of inputs belongs to the provided account".
    #[test]
    fn the_engine_stamps_the_spend_zip32_derivation_on_every_unsigned_pczt() {
        use zcash_protocol::consensus::NetworkConstants;

        /// Checks one bundle's still-unsigned spends, adding each to `checked`. Shared by the
        /// Orchard and Ironwood arms, which the engine stamps identically.
        fn check_bundle(
            bundle: &orchard::pczt::Bundle,
            seed_fingerprint: &zip32::fingerprint::SeedFingerprint,
            coin_type: zip32::ChildIndex,
            account_index: zip32::AccountId,
            label: &str,
            seen: &mut usize,
            checked: &mut usize,
        ) {
            *seen += bundle.actions().len();
            for (index, action) in bundle.actions().iter().enumerate() {
                // An already-signed action is a protocol padding dummy the IO Finalizer signed
                // with its own throwaway key: it needs no derivation, and the engine's predicate
                // deliberately skips it.
                if action.spend().spend_auth_sig().is_some() {
                    continue;
                }
                let derivation = action
                    .spend()
                    .zip32_derivation()
                    .as_ref()
                    .unwrap_or_else(|| {
                        panic!(
                            "{label} action {index} awaits a signature but carries no ZIP 32 \
                         derivation, so no external signer can identify it as the account's",
                        )
                    });
                assert_eq!(
                    derivation.extract_account_index(seed_fingerprint, coin_type),
                    Some(account_index),
                    "{label} action {index} must be stamped with this account's own \
                     m/32'/coin_type'/account' path",
                );
                *checked += 1;
            }
        }

        let path = init_fixture_db("zcashlc_migration_engine_stamps_spend_zip32_derivation");
        let (account_bytes, usk_bytes) = create_fixture_account_with_usk(&path);
        fund_fixture_account_with_orchard_note(&path, &usk_bytes, 1_234_567_890);
        let path_bytes = path.to_str().unwrap().as_bytes();
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_600_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );

        let mut ctx = unsafe {
            open(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account_bytes.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        }
        .expect("the fixture context opens");
        let (_plan, _reference_height, handle) = plan_and_cache(&mut ctx, false)
            .expect("planning must succeed")
            .expect("the funded account has a real migration plan");

        // The EXTERNAL-SIGNER lane, exactly as the two create-unsigned entry points drive it: no
        // spending key, `unsigned_out` set. The returned PCZTs are the engine's own bytes, with no
        // SDK post-processing between the builder and this assertion.
        let (_state, unsigned) = commit_or_resume(&mut ctx, None, true, handle)
            .expect("the unsigned external-signer commit must succeed");
        assert!(
            !unsigned.is_empty(),
            "a funded account's unsigned run must serve at least one PCZT"
        );

        // Derived from the fixture's own seed rather than read back out of the wallet record the
        // engine itself consulted, so this pins the VALUE, not just the round-trip.
        let expected_seed_fingerprint = zip32::fingerprint::SeedFingerprint::from_seed(&[7u8; 32])
            .expect("the fixture seed has a valid ZIP 32 fingerprint");
        let expected_coin_type = zip32::ChildIndex::hardened(ctx.network.coin_type());
        let expected_account_index = zip32::AccountId::ZERO;

        let (mut orchard_seen, mut orchard_checked) = (0usize, 0usize);
        let (mut ironwood_seen, mut ironwood_checked) = (0usize, 0usize);
        for (id, pczt_bytes, _actions) in &unsigned {
            let label = format!("transaction {}", u32::from(*id));
            let pczt = pczt::parse(pczt_bytes)
                .unwrap_or_else(|e| panic!("{label} must parse as a PCZT: {e:?}"));
            pczt::roles::verifier::Verifier::new(pczt)
                .with_orchard::<core::convert::Infallible, _>(|bundle| {
                    check_bundle(
                        bundle,
                        &expected_seed_fingerprint,
                        expected_coin_type,
                        expected_account_index,
                        &format!("{label} Orchard"),
                        &mut orchard_seen,
                        &mut orchard_checked,
                    );
                    Ok(())
                })
                .expect("the Orchard bundle parses")
                .with_ironwood::<core::convert::Infallible, _>(|bundle| {
                    check_bundle(
                        bundle,
                        &expected_seed_fingerprint,
                        expected_coin_type,
                        expected_account_index,
                        &format!("{label} Ironwood"),
                        &mut ironwood_seen,
                        &mut ironwood_checked,
                    );
                    Ok(())
                })
                .expect("the Ironwood bundle parses");
        }

        // Guards against a vacuous pass: a run of nothing but pre-signed padding dummies would
        // satisfy every assertion above while exercising the stamping not at all. The funded
        // fixture builds one preparation transaction plus six transfers, whose Orchard spends are
        // what the signer has to authorize.
        assert!(
            orchard_checked > 0,
            "the run must contain Orchard spends awaiting a signature \
             (Orchard actions seen: {orchard_seen})"
        );
        // The Ironwood arm is walked over real actions, not skipped over an absent bundle: each
        // transfer carries one, holding the Ironwood output it crosses value into. That action's
        // spend half is a padding dummy the IO Finalizer already signed, so a migration run has no
        // Ironwood spend awaiting a signature — it is Orchard notes a migration spends, and the
        // account owns no Ironwood note to spend until one of these transfers is mined. So
        // `ironwood_checked` is legitimately 0 today; it is deliberately not asserted to stay 0,
        // because the per-action assertion above is what must hold if that ever changes.
        assert!(
            ironwood_seen > 0,
            "each transfer must carry an Ironwood action, so the Ironwood arm is not vacuous \
             (Ironwood spends awaiting a signature: {ironwood_checked})"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Regression pin: the migration store connection (a second, independent connection into the
    /// same wallet database file the slipstream engine writes from) must wait for a held sqlite
    /// lock exactly as long as the wallet handle does -- `crate::wallet_db` (lib.rs) sets
    /// `crate::WALLET_DB_BUSY_TIMEOUT` (15 s, currently) because the engine's write-behind commits
    /// can hold the file lock for seconds; upstream sets none. Before the fix, [`open`]'s store
    /// connection was a bare `Connection::open` with no explicit timeout, silently falling back to
    /// rusqlite's 5 s default -- a migration call racing a long engine write could hit
    /// `database is locked` a full 10 s earlier than the wallet handle would have given up.
    #[test]
    fn store_conn_matches_wallet_db_busy_timeout() {
        let path = std::env::temp_dir().join(format!(
            "zcashlc_migration_store_conn_busy_timeout_{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let conn = open_store_conn(&path).expect("the store connection must open");
        let busy_timeout: u32 = conn
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .expect("PRAGMA busy_timeout must be readable");
        // The literal (rather than comparing against `crate::WALLET_DB_BUSY_TIMEOUT` itself) is
        // deliberate: this pins the actual wait time a caller experiences, so a future edit that
        // changes the constant's value without meaning to still fails this test instead of
        // silently redefining "correct".
        assert_eq!(
            busy_timeout, 15_000,
            "the migration store connection must wait as long as the wallet handle \
             (crate::WALLET_DB_BUSY_TIMEOUT in lib.rs, currently 15 s) before giving up on a held lock"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// On a freshly initialized wallet database with a chain tip but no spendable notes, locking
    /// the residual locks nothing (returns `0`, not an error) and unlocking clears nothing
    /// (returns `0`). The fixture mirrors `migration_state_on_fresh_db_is_not_started`
    /// (`zcashlc_init_data_database` first), plus `zcashlc_update_chain_tip` — the lock path
    /// selects notes against the tip + 1, so it needs a chain tip to exist, exactly like a real
    /// post-sync caller.
    #[test]
    fn migration_lock_and_unlock_residual_on_fresh_db_are_zero() {
        let path = std::env::temp_dir().join(format!(
            "zcashlc_migration_lock_residual_{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let path_bytes = path.to_str().unwrap().as_bytes();
        let init = unsafe {
            crate::zcashlc_init_data_database(
                path_bytes.as_ptr(),
                path_bytes.len(),
                std::ptr::null(),
                0,
                NETWORK_ID_MAINNET,
            )
        };
        assert!(init >= 0, "wallet-db initialization must succeed");
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_000_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );
        let account = [7u8; 16];
        let locked = unsafe {
            zcashlc_migration_lock_residual(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert_eq!(locked, 0, "no spendable notes exist, so nothing locks");
        let unlocked = unsafe {
            zcashlc_migration_unlock_residual(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert_eq!(unlocked, 0, "no locks exist, so nothing clears");
        let _ = std::fs::remove_file(&path);
    }

    /// On a freshly initialized wallet database with a chain tip but no spendable notes, the
    /// run-count estimate is the ZERO-RUN estimate (`runs_len == 0`, `final_residual == 0`) —
    /// a legitimate answer marshaled as a non-null pointer, not an error — and the free
    /// function round-trips it (the empty runs array uses the null-for-empty `ptr_from_vec`
    /// convention, which `free_ptr_from_vec` handles).
    #[test]
    fn migration_estimate_runs_on_fresh_db_is_zero_runs() {
        let path = std::env::temp_dir().join(format!(
            "zcashlc_migration_estimate_runs_{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let path_bytes = path.to_str().unwrap().as_bytes();
        let init = unsafe {
            crate::zcashlc_init_data_database(
                path_bytes.as_ptr(),
                path_bytes.len(),
                std::ptr::null(),
                0,
                NETWORK_ID_MAINNET,
            )
        };
        assert!(init >= 0, "wallet-db initialization must succeed");
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_000_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );
        let account = create_fixture_account(&path);
        let ptr = unsafe {
            zcashlc_migration_estimate_runs(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert!(
            !ptr.is_null(),
            "estimate pointer must be non-null on success"
        );
        let est = unsafe { &*ptr };
        assert_eq!(est.runs_len, 0, "nothing to migrate estimates zero runs");
        assert_eq!(est.final_residual, 0, "a zero balance leaves no residual");
        unsafe { zcashlc_free_migration_run_estimate(ptr) };
        let _ = std::fs::remove_file(&path);
    }

    /// A funded account needing note-preparation splitting (per
    /// [`fund_fixture_account_with_orchard_note`]'s doc) estimates at least one real run whose
    /// `actions`/`keystone_rounds` match the ACTION-weighted formula
    /// (`prep_transactions * PREPARATION_ACTIONS + crossings * TRANSFER_ACTIONS`;
    /// `min_signing_rounds(prep_transactions, crossings, KEYSTONE)`) rather than the deleted
    /// count-based ceil-division, which undercounts whenever a run's action total crosses a round
    /// boundary its transaction COUNT alone would not (see
    /// [`keystone_min_signing_rounds_needs_two_for_six_preps_and_one_transfer`]).
    #[test]
    fn migration_estimate_runs_actions_and_keystone_rounds_match_the_action_weighted_formula() {
        let path = init_fixture_db("zcashlc_migration_estimate_runs_actions");
        let (account_bytes, usk_bytes) = create_fixture_account_with_usk(&path);
        fund_fixture_account_with_orchard_note(&path, &usk_bytes, 1_234_567_890);
        let path_bytes = path.to_str().unwrap().as_bytes();
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_600_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );

        let ptr = unsafe {
            zcashlc_migration_estimate_runs(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account_bytes.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert!(
            !ptr.is_null(),
            "estimate pointer must be non-null on success"
        );
        let est = unsafe { &*ptr };
        assert!(
            est.runs_len > 0,
            "a funded account needing a split must estimate at least one run"
        );
        let runs = unsafe { std::slice::from_raw_parts(est.runs, est.runs_len) };
        for run in runs {
            let expected_actions =
                run.prep_transactions * PREPARATION_ACTIONS + run.crossings * TRANSFER_ACTIONS;
            assert_eq!(
                run.actions, expected_actions,
                "actions must be action-weighted, not count-based"
            );
            let expected_rounds = min_signing_rounds(
                run.prep_transactions as usize,
                run.crossings as usize,
                SigningRoundBudget::KEYSTONE,
            ) as u32;
            assert_eq!(
                run.keystone_rounds, expected_rounds,
                "keystone_rounds must equal the optimal MinRounds packing under the Keystone \
                 budget, not a count-based ceil-division"
            );
        }
        unsafe { zcashlc_free_migration_run_estimate(ptr) };
        let _ = std::fs::remove_file(&path);
    }

    /// Pins the wired math to the exact counter-example that exposed the count-based bug: 6
    /// preparation transactions (96 actions) plus 1 transfer (3 actions) totals 99 actions — one
    /// over a single Keystone round (96) — so it needs 2 rounds. Count-based
    /// `ceil(7 transactions / max_transactions_per_session)` said 1 round for any
    /// `max_transactions_per_session >= 7`, silently under-preparing the signing ceremony.
    #[test]
    fn keystone_min_signing_rounds_needs_two_for_six_preps_and_one_transfer() {
        assert_eq!(
            min_signing_rounds(6, 1, SigningRoundBudget::KEYSTONE),
            2,
            "6 preparations + 1 transfer = 99 actions, one Keystone round (96) short"
        );
    }

    // ----- Per-account run sizing (MOB-1732: Keystone runs sized by signing-round capacity) -----

    /// Opens the fixture wallet at `path` exactly as an FFI entry point does and answers
    /// [`crate::migration_engine::run_sizing`] for `account_bytes`.
    fn fixture_run_sizing(
        path: &std::path::Path,
        account_bytes: &[u8; 16],
    ) -> anyhow::Result<RunSizing> {
        let path_bytes = path.to_str().unwrap().as_bytes();
        let ctx = unsafe {
            open(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account_bytes.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        }
        .expect("the fixture wallet opens");
        crate::migration_engine::run_sizing(&ctx.wallet, ctx.account)
    }

    /// The tag is matched case-insensitively: it is what the platform layer stamps on a Keystone
    /// import, and a wallet that capitalizes it differently is still signing through a Keystone.
    #[test]
    fn run_sizing_is_one_keystone_round_for_a_keystone_tagged_account() {
        for (i, tag) in ["keystone", "Keystone", "KEYSTONE"].into_iter().enumerate() {
            let path = init_fixture_db(&format!("zcashlc_run_sizing_keystone_{i}"));
            let (account_bytes, _usk) =
                create_fixture_account_with_usk_and_key_source(&path, Some(tag));
            assert_eq!(
                fixture_run_sizing(&path, &account_bytes).expect("the sizing resolves"),
                RunSizing::Signer(RunSigningCapacity::KEYSTONE),
                "a `{tag}` account must be sized to one Keystone signing round"
            );
            let _ = std::fs::remove_file(&path);
        }
    }

    /// Everything that is not Keystone-tagged — no tag, the platform's own `zashi` tag, an
    /// unrelated tag — is signed in process, where a signing round has no per-interaction cost to
    /// bound, so it keeps note-cap sizing at the raised in-process cap.
    #[test]
    fn run_sizing_is_the_in_process_note_cap_for_every_other_account() {
        for (i, tag) in [None, Some("zashi"), Some("ledger")]
            .into_iter()
            .enumerate()
        {
            let path = init_fixture_db(&format!("zcashlc_run_sizing_in_process_{i}"));
            let (account_bytes, _usk) = create_fixture_account_with_usk_and_key_source(&path, tag);
            assert_eq!(
                fixture_run_sizing(&path, &account_bytes).expect("the sizing resolves"),
                RunSizing::Notes(ZODL_MAX_PREPARED_NOTES_PER_RUN),
                "an account tagged {tag:?} signs in process and keeps note-cap sizing"
            );
            let _ = std::fs::remove_file(&path);
        }
    }

    /// An account the wallet does not know cannot be sized: a hard error, like every other
    /// account-row read in the migration layer, never a silent default that would plan a run for
    /// nobody.
    #[test]
    fn run_sizing_rejects_an_unknown_account() {
        let path = init_fixture_db("zcashlc_run_sizing_unknown_account");
        let _known = create_fixture_account(&path);
        let unknown = [0xEEu8; 16];
        let err = fixture_run_sizing(&path, &unknown)
            .expect_err("an account the wallet does not know must not be sized");
        assert!(
            err.to_string().contains("unknown account"),
            "unexpected error message: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The in-process cap is deliberately far above the crate's Keystone-oriented default: that
    /// default bounds a run for a signer with a per-round budget, which an in-process signer does
    /// not have, so a larger cap only means fewer runs for the same wallet.
    #[test]
    fn in_process_note_cap_is_two_hundred_and_above_the_crate_default() {
        assert_eq!(ZODL_MAX_PREPARED_NOTES_PER_RUN.get(), 200);
        assert!(
            ZODL_MAX_PREPARED_NOTES_PER_RUN
                > zcash_pool_migration::denomination::MIGRATION_MAX_PREPARED_NOTES_PER_RUN,
            "the in-process cap must exceed the crate's per-run default"
        );
    }

    /// Both locking entry points report `-1` (with the last-error channel set) on a wallet
    /// database that was never initialized: the error-path smoke for the `i64` sentinel.
    #[test]
    fn migration_lock_and_unlock_residual_on_uninitialized_db_are_errors() {
        let path = std::env::temp_dir().join(format!(
            "zcashlc_migration_lock_residual_uninit_{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = [7u8; 16];
        let locked = unsafe {
            zcashlc_migration_lock_residual(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert_eq!(locked, -1, "an uninitialized database must error");
        let unlocked = unsafe {
            zcashlc_migration_unlock_residual(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert_eq!(unlocked, -1, "an uninitialized database must error");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn immediate_run_row_round_trip() {
        let conn = Connection::open_in_memory().unwrap();
        init_immediate_runs(&conn).unwrap();
        let account = [9u8; 16];
        assert!(immediate_run_row(&conn, &account).unwrap().is_none());
        record_immediate_run(&conn, &account, [1u8; 32], h(100)).unwrap();
        let row = immediate_run_row(&conn, &account).unwrap().unwrap();
        assert_eq!(row.txid, [1u8; 32]);
        assert_eq!(row.recorded_at_height, h(100));
    }

    #[test]
    fn immediate_run_record_replaces_the_previous_one() {
        let conn = Connection::open_in_memory().unwrap();
        init_immediate_runs(&conn).unwrap();
        let account = [9u8; 16];
        record_immediate_run(&conn, &account, [1u8; 32], h(100)).unwrap();
        record_immediate_run(&conn, &account, [2u8; 32], h(150)).unwrap();
        // One row per account: the second record supersedes the first entirely.
        let row = immediate_run_row(&conn, &account).unwrap().unwrap();
        assert_eq!(row.txid, [2u8; 32]);
        assert_eq!(row.recorded_at_height, h(150));
    }

    #[test]
    fn immediate_run_rows_are_isolated_per_account() {
        let conn = Connection::open_in_memory().unwrap();
        init_immediate_runs(&conn).unwrap();
        let account = [9u8; 16];
        let other = [8u8; 16];
        record_immediate_run(&conn, &account, [1u8; 32], h(100)).unwrap();
        record_immediate_run(&conn, &other, [2u8; 32], h(200)).unwrap();
        assert_eq!(
            immediate_run_row(&conn, &account).unwrap().unwrap().txid,
            [1u8; 32]
        );
        assert_eq!(
            immediate_run_row(&conn, &other).unwrap().unwrap().txid,
            [2u8; 32]
        );
        // Replacing one account's row must not disturb the other's.
        record_immediate_run(&conn, &account, [3u8; 32], h(300)).unwrap();
        assert_eq!(
            immediate_run_row(&conn, &account).unwrap().unwrap().txid,
            [3u8; 32]
        );
        assert_eq!(
            immediate_run_row(&conn, &other).unwrap().unwrap().txid,
            [2u8; 32]
        );
    }

    #[test]
    fn resolve_immediate_run_reads_mined_and_expiry_from_transactions_table() {
        let conn = Connection::open_in_memory().unwrap();
        // A minimal stand-in for zcash_client_sqlite's `transactions` table: just the two columns
        // `resolve_immediate_run`'s query reads (see `zcash_client_sqlite::wallet::get_tx_height`
        // for the upstream query this mirrors and extends).
        conn.execute_batch(
            "CREATE TABLE transactions (txid BLOB PRIMARY KEY, mined_height INTEGER, expiry_height INTEGER)",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO transactions (txid, mined_height, expiry_height) VALUES (?1, ?2, ?3)",
            rusqlite::params![&[1u8; 32][..], 150u32, 200u32],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO transactions (txid, mined_height, expiry_height) VALUES (?1, NULL, ?2)",
            rusqlite::params![&[2u8; 32][..], 500u32],
        )
        .unwrap();

        let mined = resolve_immediate_run(
            &conn,
            ImmediateRunRow {
                txid: [1u8; 32],
                recorded_at_height: h(100),
            },
            h(300),
        )
        .unwrap();
        assert_eq!(mined.mined_height, Some(h(150)));
        assert_eq!(mined.expiry_height, Some(h(200)));

        let unmined = resolve_immediate_run(
            &conn,
            ImmediateRunRow {
                txid: [2u8; 32],
                recorded_at_height: h(100),
            },
            h(300),
        )
        .unwrap();
        assert_eq!(unmined.mined_height, None);
        assert_eq!(unmined.expiry_height, Some(h(500)));

        // A txid the wallet has never observed at all: both columns resolve to None.
        let unknown = resolve_immediate_run(
            &conn,
            ImmediateRunRow {
                txid: [9u8; 32],
                recorded_at_height: h(100),
            },
            h(300),
        )
        .unwrap();
        assert_eq!(unknown.mined_height, None);
        assert_eq!(unknown.expiry_height, None);
    }

    #[test]
    fn resolve_immediate_run_filters_future_mined_height_and_zero_expiry_sentinel() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE transactions (txid BLOB PRIMARY KEY, mined_height INTEGER, expiry_height INTEGER)",
        )
        .unwrap();
        // A mined_height beyond the current tip is a stale/optimistic row (mirrors
        // `zcash_client_sqlite::wallet::get_tx_height`'s own guard) and must not report Complete.
        conn.execute(
            "INSERT INTO transactions (txid, mined_height, expiry_height) VALUES (?1, ?2, ?3)",
            rusqlite::params![&[1u8; 32][..], 500u32, 600u32],
        )
        .unwrap();
        // expiry_height = 0 is the wire "no real expiry" sentinel; treated the same as missing so
        // it does not fool the expiry check into firing immediately.
        conn.execute(
            "INSERT INTO transactions (txid, mined_height, expiry_height) VALUES (?1, NULL, 0)",
            rusqlite::params![&[2u8; 32][..]],
        )
        .unwrap();

        let future_mined = resolve_immediate_run(
            &conn,
            ImmediateRunRow {
                txid: [1u8; 32],
                recorded_at_height: h(100),
            },
            h(300),
        )
        .unwrap();
        assert_eq!(
            future_mined.mined_height, None,
            "a mined height beyond tip must be filtered out"
        );

        let zero_expiry = resolve_immediate_run(
            &conn,
            ImmediateRunRow {
                txid: [2u8; 32],
                recorded_at_height: h(100),
            },
            h(300),
        )
        .unwrap();
        assert_eq!(
            zero_expiry.expiry_height, None,
            "expiry_height=0 must read as missing"
        );
    }

    // ----- read-only open helpers (Q2-1 enforcement) -----

    /// Q2-1 enforcement: the read-only store connection makes accidental writes on the pure
    /// read paths impossible — any INSERT/UPDATE/DDL errors with SQLITE_READONLY, forever,
    /// including after future pin moves change what the engine calls do internally.
    #[test]
    fn read_only_store_conn_rejects_writes() {
        let path = std::env::temp_dir().join(format!(
            "zcashlc_readonly_store_{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        {
            let rw = Connection::open(&path).unwrap();
            init_immediate_runs(&rw).unwrap();
        }
        let ro = open_store_conn_read_only(&path).unwrap();
        let err = ro
            .execute(
                "INSERT INTO sdk_immediate_runs (account_uuid, txid, recorded_at_height) VALUES (?1, ?2, ?3)",
                rusqlite::params![&[9u8; 16][..], &[1u8; 32][..], 100i64],
            )
            .unwrap_err();
        match err {
            rusqlite::Error::SqliteFailure(e, _) => {
                assert_eq!(
                    e.code,
                    rusqlite::ErrorCode::ReadOnly,
                    "write must fail READONLY, got {e:?}"
                )
            }
            other => panic!("expected SqliteFailure(ReadOnly), got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    /// A read-only open of a wallet-database FILE that does not exist must error — and must NOT
    /// create the file (the rw `open()` path's `Connection::open` would).
    #[test]
    fn read_only_store_conn_on_missing_file_errors_without_creating_it() {
        let path = std::env::temp_dir().join(format!(
            "zcashlc_readonly_missing_{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        assert!(open_store_conn_read_only(&path).is_err());
        assert!(
            !path.exists(),
            "a read-only open must not create the database file"
        );
    }

    /// The pure `zcashlc_migration_progress` path may run before any rw migration call ever
    /// created `sdk_immediate_runs` (the table is created lazily by the rw `open()`, not by the
    /// schema graph) — the tolerant reader answers None instead of erroring on the missing table.
    #[test]
    fn immediate_run_row_if_table_exists_tolerates_a_missing_table() {
        let conn = Connection::open_in_memory().unwrap();
        let account = [9u8; 16];
        assert!(
            immediate_run_row_if_table_exists(&conn, &account)
                .unwrap()
                .is_none()
        );
        init_immediate_runs(&conn).unwrap();
        record_immediate_run(&conn, &account, [1u8; 32], h(100)).unwrap();
        assert_eq!(
            immediate_run_row_if_table_exists(&conn, &account)
                .unwrap()
                .unwrap()
                .txid,
            [1u8; 32]
        );
    }

    /// The accepted semantic shift, pinned: a pure statuses read reports what is PERSISTED — a
    /// `Broadcast` row stays `Broadcast` in its answer until a write lane (`advance_step`'s
    /// engine sweep, the prove executor, the delivery executor) persists the Mined promotion. Display
    /// green is unaffected (the app derives it from the wallet's own mined-txid set).
    #[test]
    fn pure_statuses_report_broadcast_until_a_write_lane_promotes() {
        let tx = test_transaction_from_parts(
            MigrationTransferId::new(1),
            MigrationTxKind::Transfer { crossing: 0 },
            vec![0u8; 8],
            Vec::new(),
            h(1_000),
            h(1_040),
            None,
            MigrationTxState::Broadcast {
                txid: TxId::from_bytes([1u8; 32]),
            },
            None,
        );
        let state = test_state_from_parts(
            MigrationStatus::InProgress,
            DenominationPlan::from_stored_parts(
                vec![zat(100_000_000)],
                zat(10_000),
                None,
                zat(20_000),
                zat(1_000_000_000),
                zat(999_000_000),
            )
            .unwrap(),
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            vec![tx],
            AnchorBucketInterval::ZIP_318,
        );
        let statuses = state.transaction_statuses(DuenessTargets::at(h(1_050)));
        assert!(matches!(
            statuses[0].state(),
            MigrationTxState::Broadcast { .. }
        ));
    }

    /// A freshly initialized wallet database has no stored migration, so
    /// `zcashlc_migration_advance_step` returns NULL with NO error recorded — the documented
    /// "no stored run" answer, distinct from an error NULL. The store tables come from the wallet
    /// schema migrations (they are no longer created by `open`), so the fixture runs
    /// `zcashlc_init_data_database` first, exactly like a real caller — and creates the account
    /// it queries, since the account-keyed store resolves the account row up front. This
    /// exercises `open` (path decode, `parse_network`, store read) end to end over the FFI, and
    /// holds before any chain tip exists.
    #[test]
    fn migration_advance_step_on_fresh_db_is_null_with_no_error() {
        let path = std::env::temp_dir().join(format!(
            "zcashlc_migration_advance_step_{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let path_bytes = path.to_str().unwrap().as_bytes();
        let init = unsafe {
            crate::zcashlc_init_data_database(
                path_bytes.as_ptr(),
                path_bytes.len(),
                std::ptr::null(),
                0,
                NETWORK_ID_MAINNET,
            )
        };
        assert!(init >= 0, "wallet-db initialization must succeed");
        let account = create_fixture_account(&path);
        let ptr = unsafe {
            zcashlc_migration_advance_step(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
                -1,
            )
        };
        assert!(
            ptr.is_null(),
            "no stored run must answer NULL (the benign no-run sentinel)"
        );
        assert!(
            ffi_helpers::error_handling::take_last_error().is_none(),
            "the no-run NULL must record NO error"
        );
        let _ = std::fs::remove_file(&path);
    }

    // ----- refresh stale transfers (rebuild-on-expiry lanes over the FFI) -----

    use zcash_client_sqlite::pool_migration::orchard_ironwood::PoolMigrations;

    /// Initializes a wallet database at a unique temp path (removing any leftover), returning the
    /// path. The refresh fixtures all start here, mirroring a real caller's `init_data_db`.
    fn init_fixture_db(prefix: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("{prefix}_{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let path_bytes = path.to_str().unwrap().as_bytes();
        let init = unsafe {
            crate::zcashlc_init_data_database(
                path_bytes.as_ptr(),
                path_bytes.len(),
                std::ptr::null(),
                0,
                NETWORK_ID_MAINNET,
            )
        };
        assert!(init >= 0, "wallet-db initialization must succeed");
        path
    }

    /// Stores `state` for `account` through the same account-keyed store the FFI reads — the
    /// fixture-side counterpart of the entry points' `replace_migration` write path.
    fn store_fixture_state(path: &std::path::Path, account: &[u8; 16], state: &MigrationState) {
        let mut conn = Connection::open(path).expect("the fixture store connection opens");
        let account = account_uuid_from_bytes(account.as_ptr()).expect("16 uuid bytes");
        let mut store = PoolMigrations::for_account(
            NetworkParams::Standard(Network::TestNetwork),
            SystemClock,
            &mut conn,
            account,
        )
        .expect("the account-keyed store resolves the fixture account");
        store
            .replace_migration(state)
            .expect("the fixture state stores");
    }

    /// A REAL unsigned transfer PCZT (2 Orchard actions + 1 Ironwood action, anchors and
    /// witnesses deferred per ZIP 374) for the stored-state fixtures: the rebuild path parses the
    /// stored PCZT and recovers the funding note by the nullifier of its ONE unwitnessed spend,
    /// so neither the `vec![0u8]` placeholder nor the actionless [`minimal_pczt_bytes`] can reach
    /// the funding-note resolution under test. The key and note are throwaway (seeded rng): the
    /// wallet under test holds no notes at all, so only the SHAPE matters. Heights must be past
    /// the mainnet NU6.3 activation for the builder to emit the Ironwood crossing output.
    fn fixture_transfer_pczt_bytes(target_height: u32, expiry_height: u32) -> Vec<u8> {
        use orchard::keys::{FullViewingKey, Scope, SpendingKey};
        use orchard::note::{Note, NoteVersion, RandomSeed, Rho};
        use orchard::value::NoteValue;
        use rand::RngCore;
        use zcash_primitives::transaction::fees::zip317::MARGINAL_FEE;
        use zcash_protocol::consensus::MAIN_NETWORK;

        let mut rng = StdRng::seed_from_u64(1806);
        let mut draw = [0u8; 32];
        let sk: SpendingKey = loop {
            rng.fill_bytes(&mut draw);
            if let Some(sk) = SpendingKey::from_bytes(draw).into_option() {
                break sk;
            }
        };
        let fvk = FullViewingKey::from(&sk);
        let rho = loop {
            rng.fill_bytes(&mut draw);
            if let Some(rho) = Rho::from_bytes(&draw).into_option() {
                break rho;
            }
        };
        let rseed = loop {
            rng.fill_bytes(&mut draw);
            if let Some(rseed) = RandomSeed::from_bytes(draw, &rho).into_option() {
                break rseed;
            }
        };
        // The builder enforces exact balance: the spent note carries the crossing value plus the
        // canonical ZIP 317 fee of the 3-logical-action transfer shape.
        let crossing = 100_000_000u64;
        let fee = 3 * u64::from(MARGINAL_FEE);
        let note = Note::from_parts(
            fvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(crossing + fee),
            rho,
            rseed,
            NoteVersion::V2,
        )
        .into_option()
        .expect("valid fixture note parts");
        zcash_pool_migration::build::build_transfer_pczt(
            &MAIN_NETWORK,
            target_height,
            expiry_height,
            &fvk,
            note,
            zat(crossing),
            None,
            &mut rng,
        )
        .expect("the fixture transfer builds")
        .serialize()
        .expect("the fixture transfer serializes")
    }

    /// On a freshly initialized wallet database with a created account but NO stored migration,
    /// refreshing stale transfers returns the benign EMPTY schedule — nothing to refresh and
    /// nothing to re-display — not an error, on the NULL-usk (external-signer) lane pinned here
    /// (the usk lane rides the welding offline tests). The stored state is read before any tip
    /// lookup, so the answer holds even before the wallet ever saw a chain tip.
    #[test]
    fn migration_refresh_stale_transfers_on_fresh_db_returns_an_empty_schedule() {
        let path = init_fixture_db("zcashlc_migration_refresh_fresh");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        let schedule_ptr = unsafe {
            zcashlc_migration_refresh_stale_transfers(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
                std::ptr::null(),
                0,
            )
        };
        assert!(
            !schedule_ptr.is_null(),
            "no stored migration means nothing to refresh, not an error"
        );
        let schedule = unsafe { &*schedule_ptr };
        assert_eq!(
            schedule.transfers_len, 0,
            "no stored migration yields the empty schedule"
        );
        assert_eq!(schedule.estimated_duration_hours, 0);
        unsafe { zcashlc_free_migration_schedule(schedule_ptr) };
        let _ = std::fs::remove_file(&path);
    }

    /// A stored TERMINAL run (completed or cancelled) has nothing to refresh and nothing the
    /// consent-echo lane would ever compare against: the EMPTY schedule, again read before any
    /// tip lookup (no chain tip is set in this fixture).
    #[test]
    fn migration_refresh_stale_transfers_on_a_terminal_run_returns_an_empty_schedule() {
        let path = init_fixture_db("zcashlc_migration_refresh_terminal");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        let state = test_state(MigrationStatus::Complete, &[MINED], &[MINED], 50, 10_000);
        store_fixture_state(&path, &account, &state);
        let schedule_ptr = unsafe {
            zcashlc_migration_refresh_stale_transfers(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
                std::ptr::null(),
                0,
            )
        };
        assert!(!schedule_ptr.is_null(), "a terminal run is not an error");
        let schedule = unsafe { &*schedule_ptr };
        assert_eq!(
            schedule.transfers_len, 0,
            "a terminal run yields the empty schedule"
        );
        unsafe { zcashlc_free_migration_schedule(schedule_ptr) };
        let _ = std::fs::remove_file(&path);
    }

    /// A stored run whose transfer has NOT expired at the tip rebuilds nothing and returns the
    /// CURRENT stored schedule — the atomically-persisted truth the host re-displays and later
    /// echoes — with the stored state untouched. This lane decodes a REAL spending key (the
    /// in-process signing selector), pinning that the usk input form is accepted even when no
    /// rebuild runs.
    #[test]
    fn migration_refresh_stale_transfers_with_nothing_expired_returns_the_current_schedule() {
        let path = init_fixture_db("zcashlc_migration_refresh_unexpired");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let (account, usk) = create_fixture_account_with_usk(&path);
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_600_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );
        // Expiry 4_000_000 is above the 3_600_001 target: still valid, nothing to rebuild.
        let state = test_state(
            MigrationStatus::InProgress,
            &[],
            &[MigrationTxState::Signed],
            3_499_000,
            4_000_000,
        );
        store_fixture_state(&path, &account, &state);
        let schedule_ptr = unsafe {
            zcashlc_migration_refresh_stale_transfers(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
                usk.as_ptr(),
                usk.len(),
            )
        };
        assert!(
            !schedule_ptr.is_null(),
            "an unexpired schedule refreshes nothing, not an error"
        );
        let schedule = unsafe { &*schedule_ptr };
        assert_eq!(
            schedule.transfers_len, 1,
            "the current stored schedule has its one transfer row"
        );
        assert_eq!(schedule.estimated_duration_hours, 0);
        let row = unsafe { &*schedule.transfers };
        assert_eq!(row.id, 0, "the stored transfer's engine id");
        // The state-side amount is what the transfer CROSSES: the fixture's funding note is
        // 100_010_000 (crossing 100_000_000 plus the 10_000 fee buffer), and the row serves the
        // crossing. The consent echo compares the same value (`expected_rows_from_state` uses the
        // same `transfer_amount`), so platform and native still agree.
        assert_eq!(row.amount, 100_000_000);
        assert_eq!(
            row.next_executable_after_height, 3_499_000,
            "the stored scheduled height is served unchanged"
        );
        assert_eq!(
            row.expiry_height, 4_000_000,
            "the stored expiry is served unchanged"
        );
        assert_eq!(
            row.anchor_height, 3_600_000,
            "the display-only now reference is the tip at encode time"
        );
        unsafe { zcashlc_free_migration_schedule(schedule_ptr) };

        // Nothing was rebuilt: the stored transfer still holds its fixture bytes, still Signed.
        let stored = read_fixture_state(&path, &account);
        let tx = stored
            .transactions()
            .first()
            .expect("the transfer row remains");
        assert!(
            matches!(tx.state(), MigrationTxState::Signed),
            "an unexpired transfer must stay untouched"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// With a stored run holding an EXPIRED transfer (row expiry below the tip) whose PCZT is a
    /// real built transfer — one unwitnessed spend revealing the funding nullifier — the refresh
    /// path attempts the rebuild, and on this otherwise-empty wallet (the funding note is not
    /// among the spendable notes) surfaces the `FundingNoteUnavailable` HARD error naming the
    /// restart remedy: NULL with the last-error channel set, and NOTHING persisted (the expired
    /// artifact stays stored untouched). This pins expired-detection plus the error routing end
    /// to end over the FFI.
    #[test]
    fn migration_refresh_stale_transfers_surfaces_funding_note_unavailable() {
        let path = init_fixture_db("zcashlc_migration_refresh_expired");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_600_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );
        // The stored transfer: expired at the tip (3_500_040 < 3_600_001), holding real
        // transfer-PCZT bytes so the rebuild reaches the funding-note resolution.
        let pczt_bytes = fixture_transfer_pczt_bytes(3_500_000, 3_500_040);
        let base = test_state(
            MigrationStatus::InProgress,
            &[],
            &[MigrationTxState::Signed],
            3_499_000,
            3_500_040,
        );
        let transactions = base
            .transactions()
            .iter()
            .map(|t| {
                test_transaction_from_parts(
                    t.id(),
                    t.kind(),
                    pczt_bytes.clone(),
                    t.depends_on().clone(),
                    t.scheduled_height(),
                    t.expiry_height(),
                    t.anchor_boundary(),
                    t.state(),
                    t.lock_owner(),
                )
            })
            .collect();
        let state = test_state_from_parts(
            base.status(),
            base.denominations().clone(),
            base.preparation().clone(),
            transactions,
            base.anchor_bucket_interval(),
        );
        store_fixture_state(&path, &account, &state);

        let schedule_ptr = unsafe {
            zcashlc_migration_refresh_stale_transfers(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
                std::ptr::null(),
                0,
            )
        };
        assert!(
            schedule_ptr.is_null(),
            "a gone funding note must be a hard error"
        );
        let message = ffi_helpers::error_handling::error_message()
            .expect("the last-error channel must carry the failure");
        assert!(
            message.contains("funding note"),
            "the error must tell the caller the funding note is gone, got: {message}"
        );
        assert!(
            message.contains("restartCurrentMigrationStep"),
            "the error must name the restart remedy, got: {message}"
        );

        // Nothing was persisted: the expired transfer still holds the old bytes, still Signed.
        let mut conn = Connection::open(&path).expect("the verification connection opens");
        let account_id = account_uuid_from_bytes(account.as_ptr()).expect("16 uuid bytes");
        let store = PoolMigrations::for_account(
            NetworkParams::Standard(Network::TestNetwork),
            SystemClock,
            &mut conn,
            account_id,
        )
        .expect("the account-keyed store resolves the fixture account");
        let stored = store
            .latest_migration()
            .expect("the store reads")
            .expect("the fixture state is still stored");
        let tx = stored
            .transactions()
            .first()
            .expect("the transfer row remains");
        assert_eq!(
            tx.pczt(),
            &pczt_bytes,
            "the expired artifact must be untouched"
        );
        assert!(
            matches!(tx.state(), MigrationTxState::Signed),
            "the expired transfer must stay Signed"
        );
        let _ = std::fs::remove_file(&path);
    }

    // ----- prove dispatch (kind routing + transient/hard error mapping) -----

    use zcash_pool_migration::engine::MigrationProver;
    use zcash_pool_migration::wallet::WalletProveError;
    use zcash_protocol::consensus::BranchId;

    /// The prover error type the dispatch tests fail with: the REAL upstream
    /// [`WalletProveError`] (so the classification under test is the production one), with unit
    /// tree/note/chain-state error parameters.
    type TestProveError = WalletProveError<(), (), (), ()>;

    /// Which prover method the dispatch routed a transaction to, and with which anchor.
    #[derive(Debug, PartialEq, Eq)]
    enum ProveCall {
        Transfer(BlockHeight),
        Preparation(BlockHeight),
    }

    /// A recording test prover: captures every call and "proves" by returning the PCZT unchanged.
    struct RecordingProver {
        calls: Vec<ProveCall>,
    }

    impl MigrationProver for RecordingProver {
        type Error = TestProveError;

        fn prove_transfer(
            &mut self,
            pczt: pczt::Pczt,
            anchor_boundary: BlockHeight,
        ) -> Result<pczt::Pczt, engine::ProveFailure<Self::Error>> {
            self.calls.push(ProveCall::Transfer(anchor_boundary));
            Ok(pczt)
        }

        fn prove_preparation(
            &mut self,
            pczt: pczt::Pczt,
            anchor: BlockHeight,
        ) -> Result<pczt::Pczt, engine::ProveFailure<Self::Error>> {
            self.calls.push(ProveCall::Preparation(anchor));
            Ok(pczt)
        }

        /// Models no note-lock state: reserves nothing and reports no owner, deliberately (the
        /// trait has no default so that taking no locks is always an explicit choice). These
        /// provers exercise dispatch and error classification, not the reservation.
        fn lock_spent_notes(
            &mut self,
            _pczt: &pczt::Pczt,
            _lock_expiry_height: BlockHeight,
        ) -> Result<Option<MigrationLockOwner>, Self::Error> {
            Ok(None)
        }

        fn anchor_bucket_interval(&self) -> AnchorBucketInterval {
            AnchorBucketInterval::ZIP_318
        }
    }

    /// A test prover that fails its one expected call with the configured error.
    struct FailingProver {
        error: Option<TestProveError>,
    }

    impl MigrationProver for FailingProver {
        type Error = TestProveError;

        fn prove_transfer(
            &mut self,
            _pczt: pczt::Pczt,
            _anchor_boundary: BlockHeight,
        ) -> Result<pczt::Pczt, engine::ProveFailure<Self::Error>> {
            Err(engine::ProveFailure::Other(
                self.error.take().expect("the prover is consulted once"),
            ))
        }

        fn prove_preparation(
            &mut self,
            _pczt: pczt::Pczt,
            _anchor: BlockHeight,
        ) -> Result<pczt::Pczt, engine::ProveFailure<Self::Error>> {
            Err(engine::ProveFailure::Other(
                self.error.take().expect("the prover is consulted once"),
            ))
        }

        /// Models no note-lock state: reserves nothing and reports no owner, deliberately (the
        /// trait has no default so that taking no locks is always an explicit choice). These
        /// provers exercise dispatch and error classification, not the reservation.
        fn lock_spent_notes(
            &mut self,
            _pczt: &pczt::Pczt,
            _lock_expiry_height: BlockHeight,
        ) -> Result<Option<MigrationLockOwner>, Self::Error> {
            Ok(None)
        }

        fn anchor_bucket_interval(&self) -> AnchorBucketInterval {
            AnchorBucketInterval::ZIP_318
        }
    }

    /// [`migration_finalize::prove_due_transaction`] with the re-draw inputs every dispatch test
    /// shares: testnet parameters, a scanned tip far past every fixture height, and `OsRng`. No
    /// fixture here triggers the proving-time boundary re-draw (every mined dependency mines at
    /// height 100, below each drawn boundary), so these remain pure dispatch tests — the re-draw
    /// itself is covered by the engine's own suite.
    fn prove_due_for_test<P>(
        prover: &mut P,
        state: &mut MigrationState,
        id: MigrationTransferId,
        preparation_anchor: Option<BlockHeight>,
    ) -> anyhow::Result<Option<()>>
    where
        P: MigrationProver,
        P::Error: migration_finalize::ProveErrorClass + std::fmt::Display,
    {
        // The proof comes out as a value now (nothing says `Proved` until it is consumed); these
        // in-memory tests discharge it through `ProvedTransaction::apply` — the same call a
        // store's `store_proved_transaction` makes on the state it persists — so the observable
        // the assertions pin (`Signed -> Proved` on the state) is unchanged. Durable persistence
        // is the store-backed tests' concern, not this wrapper's.
        migration_finalize::prove_due_transaction(
            &NetworkParams::Standard(Network::TestNetwork),
            prover,
            state,
            id,
            preparation_anchor,
            h(5_000),
            &mut OsRng,
        )
        .map(|outcome| outcome.map(|proved| proved.apply(state)))
    }

    /// A test prover whose FIRST call fails with the configured error and whose later calls
    /// succeed: the shape a sweep meets when one row's anchor is not scanned yet but the rest are.
    struct FirstFailsProver {
        error: Option<TestProveError>,
        calls: Vec<ProveCall>,
    }

    impl FirstFailsProver {
        fn answer(
            &mut self,
            call: ProveCall,
            pczt: pczt::Pczt,
        ) -> Result<pczt::Pczt, engine::ProveFailure<TestProveError>> {
            self.calls.push(call);
            match self.error.take() {
                Some(error) => Err(engine::ProveFailure::Other(error)),
                None => Ok(pczt),
            }
        }
    }

    impl MigrationProver for FirstFailsProver {
        type Error = TestProveError;

        fn prove_transfer(
            &mut self,
            pczt: pczt::Pczt,
            anchor_boundary: BlockHeight,
        ) -> Result<pczt::Pczt, engine::ProveFailure<Self::Error>> {
            self.answer(ProveCall::Transfer(anchor_boundary), pczt)
        }

        fn prove_preparation(
            &mut self,
            pczt: pczt::Pczt,
            anchor: BlockHeight,
        ) -> Result<pczt::Pczt, engine::ProveFailure<Self::Error>> {
            self.answer(ProveCall::Preparation(anchor), pczt)
        }

        /// Models no note-lock state: reserves nothing and reports no owner, deliberately (the
        /// trait has no default so that taking no locks is always an explicit choice). These
        /// provers exercise dispatch and error classification, not the reservation.
        fn lock_spent_notes(
            &mut self,
            _pczt: &pczt::Pczt,
            _lock_expiry_height: BlockHeight,
        ) -> Result<Option<MigrationLockOwner>, Self::Error> {
            Ok(None)
        }

        fn anchor_bucket_interval(&self) -> AnchorBucketInterval {
            AnchorBucketInterval::ZIP_318
        }
    }

    /// Minimal valid PCZT bytes (an empty NU6.3 v6 PCZT). The engine's prove path parses the
    /// stored PCZT before consulting the prover, so prove fixtures need bytes that parse — unlike
    /// the state-derivation fixtures' `vec![0u8]` placeholder.
    fn minimal_pczt_bytes() -> Vec<u8> {
        pczt::roles::creator::Creator::new(u32::from(BranchId::Nu6_3), 10_000, 133, None, None)
            .expect("an NU6.3 PCZT creator")
            .build()
            .expect("an empty v6 PCZT builds")
            .serialize()
            .expect("an empty v6 PCZT serializes")
    }

    /// The [`test_state`] skeleton (`InProgress`, scheduled 50, expiry 10_000) with parseable
    /// PCZT bytes on every transaction and the given drawn boundary on every TRANSFER row
    /// (preparation rows keep `None` — they never carry one).
    fn provable_state(
        prep_states: &[MigrationTxState],
        transfer_states: &[MigrationTxState],
        transfer_boundary: Option<BlockHeight>,
    ) -> MigrationState {
        let base = test_state(
            MigrationStatus::InProgress,
            prep_states,
            transfer_states,
            50,
            10_000,
        );
        let bytes = minimal_pczt_bytes();
        let transactions = base
            .transactions()
            .iter()
            .map(|t| {
                test_transaction_from_parts(
                    t.id(),
                    t.kind(),
                    bytes.clone(),
                    t.depends_on().clone(),
                    t.scheduled_height(),
                    t.expiry_height(),
                    match t.kind() {
                        MigrationTxKind::Transfer { .. } => transfer_boundary,
                        MigrationTxKind::Preparation { .. } => None,
                    },
                    t.state(),
                    t.lock_owner(),
                )
            })
            .collect();
        test_state_from_parts(
            base.status(),
            base.denominations().clone(),
            base.preparation().clone(),
            transactions,
            base.anchor_bucket_interval(),
        )
    }

    /// A TRANSFER proves via `prove_transfer` with EXACTLY the boundary persisted on its row —
    /// the caller resolves NO preparation anchor for it (`None`, the lazy per-kind contract: a wallet
    /// whose preparation anchor is not resolvable yet must still prove transfers) — and the proven
    /// bytes persist through the engine's `Proved` state.
    #[test]
    fn prove_dispatch_routes_a_transfer_to_its_stored_boundary() {
        let mut state = provable_state(&[MINED], &[MigrationTxState::Signed], Some(h(1440)));
        let mut prover = RecordingProver { calls: Vec::new() };
        let res = prove_due_for_test(&mut prover, &mut state, MigrationTransferId::new(1), None)
            .expect("a boundary-carrying transfer proves");
        assert_eq!(res, Some(()), "the transfer must prove, not defer");
        assert_eq!(
            prover.calls,
            vec![ProveCall::Transfer(h(1440))],
            "the prover must receive the row's drawn boundary, never the preparation anchor"
        );
        let tx = state
            .transactions()
            .iter()
            .find(|t| t.id() == MigrationTransferId::new(1))
            .expect("the transfer row remains");
        assert!(
            matches!(tx.state(), MigrationTxState::Proved),
            "the engine must persist Signed -> Proved"
        );
        let expected = pczt::Pczt::parse(&minimal_pczt_bytes())
            .expect("fixture bytes parse")
            .serialize()
            .expect("fixture pczt re-serializes");
        assert_eq!(
            tx.pczt(),
            &expected,
            "the stored artifact must be the proven PCZT the prover returned"
        );
    }

    /// A PREPARATION proves via `prove_preparation` with the caller-supplied preparation anchor (a
    /// preparation carries no drawn boundary).
    #[test]
    fn prove_dispatch_routes_a_preparation_to_the_preparation_anchor() {
        let mut state = provable_state(
            &[MigrationTxState::Signed],
            &[MigrationTxState::Signed],
            Some(h(1440)),
        );
        let mut prover = RecordingProver { calls: Vec::new() };
        let res = prove_due_for_test(
            &mut prover,
            &mut state,
            MigrationTransferId::new(0),
            Some(h(777)),
        )
        .expect("a signed preparation proves");
        assert_eq!(res, Some(()), "the preparation must prove, not defer");
        assert_eq!(
            prover.calls,
            vec![ProveCall::Preparation(h(777))],
            "the prover must receive the preparation anchor"
        );
        let tx = state
            .transactions()
            .iter()
            .find(|t| t.id() == MigrationTransferId::new(0))
            .expect("the preparation row remains");
        assert!(
            matches!(tx.state(), MigrationTxState::Proved),
            "the engine must persist Signed -> Proved"
        );
    }

    /// A TRANSFER whose row carries NO drawn boundary is a corrupt store: a hard error on the
    /// proving-unavailable route — never a silent fallback to the preparation anchor (the prover is
    /// not consulted at all).
    #[test]
    fn prove_dispatch_transfer_without_boundary_is_a_hard_error() {
        let mut state = provable_state(&[MINED], &[MigrationTxState::Signed], None);
        let mut prover = RecordingProver { calls: Vec::new() };
        let err = prove_due_for_test(&mut prover, &mut state, MigrationTransferId::new(1), None)
            .expect_err("a boundary-less transfer must not prove");
        assert!(
            err.to_string().starts_with(PROVING_UNAVAILABLE_PREFIX),
            "the corrupt store must surface on the proving-unavailable route, got: {err}"
        );
        assert!(
            prover.calls.is_empty(),
            "the prover must never be consulted without a boundary"
        );
        let tx = state
            .transactions()
            .iter()
            .find(|t| t.id() == MigrationTransferId::new(1))
            .expect("the transfer row remains");
        assert!(
            matches!(tx.state(), MigrationTxState::Signed),
            "the transaction must stay Signed"
        );
    }

    /// Every prover failure meaning "not scanned/retained yet or transiently unqueryable"
    /// (a restored wallet mid-sync, a transfer due before the wallet scanned past its boundary, or
    /// a shard-tree query race) maps to the transient nothing-due `Ok(None)`, leaving the
    /// transaction `Signed` for a later retry.
    #[test]
    fn prove_dispatch_maps_every_transient_prover_error_to_nothing_due() {
        let nullifier = Option::from(orchard::note::Nullifier::from_bytes(&[0u8; 32]))
            .expect("zero is a valid nullifier encoding");
        let transients: Vec<TestProveError> = vec![
            WalletProveError::UnknownSpentNote(nullifier),
            WalletProveError::AnchorNotFound(h(1440)),
            WalletProveError::WitnessNotFound(h(1440)),
            WalletProveError::Tree(shardtree::error::ShardTreeError::Query(
                shardtree::error::QueryError::CheckpointPruned,
            )),
            WalletProveError::ChainTipUnknown,
        ];
        for error in transients {
            let label = format!("{error}");
            let mut state = provable_state(&[MINED], &[MigrationTxState::Signed], Some(h(1440)));
            let mut prover = FailingProver { error: Some(error) };
            let res =
                prove_due_for_test(&mut prover, &mut state, MigrationTransferId::new(1), None)
                    .unwrap_or_else(|e| panic!("{label} must be transient, got hard error: {e}"));
            assert_eq!(res, None, "{label} must map to the nothing-due lane");
            let tx = state
                .transactions()
                .iter()
                .find(|t| t.id() == MigrationTransferId::new(1))
                .expect("the transfer row remains");
            assert!(
                matches!(tx.state(), MigrationTxState::Signed),
                "{label} must leave the transaction Signed for a retry"
            );
        }
    }

    /// Every other prover failure is HARD and carries the stable proving-unavailable prefix the
    /// Swift layer maps to `migrationProvingUnavailable` — including `IronwoodTreeUnavailable`,
    /// which is hard (not transient): the backend tracks no Ironwood commitment tree at all, so no
    /// amount of syncing produces one — and the non-query `Tree` variants (A6): a storage or
    /// insertion failure is not something more scanning repairs.
    #[test]
    fn prove_dispatch_routes_hard_prover_errors_through_the_proving_unavailable_prefix() {
        let hards: Vec<TestProveError> = vec![
            WalletProveError::RealSpends(
                zcash_pool_migration::pczt_spends::RealSpendError::NoRealSpends,
            ),
            WalletProveError::RealSpends(
                zcash_pool_migration::pczt_spends::RealSpendError::MalformedNullifier {
                    action_index: 0,
                    bytes: [0u8; 32],
                },
            ),
            WalletProveError::Notes(()),
            WalletProveError::IronwoodTreeUnavailable,
            WalletProveError::Prove("proof backend failure".into()),
            WalletProveError::Tree(shardtree::error::ShardTreeError::Storage(())),
            WalletProveError::Tree(shardtree::error::ShardTreeError::Insert(
                shardtree::error::InsertionError::CheckpointOutOfOrder,
            )),
        ];
        for error in hards {
            let label = format!("{error}");
            let mut state = provable_state(&[MINED], &[MigrationTxState::Signed], Some(h(1440)));
            let mut prover = FailingProver { error: Some(error) };
            let err =
                prove_due_for_test(&mut prover, &mut state, MigrationTransferId::new(1), None)
                    .expect_err(&format!("{label} must be a hard error"));
            assert!(
                err.to_string().starts_with(PROVING_UNAVAILABLE_PREFIX),
                "{label} must carry the proving-unavailable prefix, got: {err}"
            );
        }
    }

    /// A direct table-style pin of [`ProveErrorClass::is_transient`] itself — the two dispatch
    /// tests above exercise the same classification through the full prove-dispatch machinery,
    /// this one asserts it variant-by-variant with no fixture/prover indirection, so a
    /// classification regression fails here first. The exact transient set: `UnknownSpentNote`,
    /// `AnchorNotFound`, `WitnessNotFound`, `Tree(ShardTreeError::Query(_))`, `ChainTipUnknown`.
    /// `IronwoodTreeUnavailable` is pinned hard here too — it moved out of the transient set
    /// (was transient before this classification was aligned to Android's unit-tested,
    /// incident-litigated one) — and so are the NON-query `Tree` variants (A6): a `Storage`
    /// failure is the persistence layer erroring and an `Insert` a corrupt tree write, neither
    /// of which syncing repairs, so deferring them would stall the sweep silently forever.
    #[test]
    fn prove_error_class_transient_vs_hard_table() {
        let nullifier = Option::from(orchard::note::Nullifier::from_bytes(&[0u8; 32]))
            .expect("zero is a valid nullifier encoding");
        let transient: Vec<TestProveError> = vec![
            WalletProveError::UnknownSpentNote(nullifier),
            WalletProveError::AnchorNotFound(h(1440)),
            WalletProveError::WitnessNotFound(h(1440)),
            WalletProveError::Tree(shardtree::error::ShardTreeError::Query(
                shardtree::error::QueryError::CheckpointPruned,
            )),
            WalletProveError::ChainTipUnknown,
        ];
        for error in transient {
            assert!(error.is_transient(), "{error} must be transient");
        }

        let hard: Vec<TestProveError> = vec![
            WalletProveError::IronwoodTreeUnavailable,
            WalletProveError::RealSpends(
                zcash_pool_migration::pczt_spends::RealSpendError::NoRealSpends,
            ),
            WalletProveError::RealSpends(
                zcash_pool_migration::pczt_spends::RealSpendError::MalformedNullifier {
                    action_index: 0,
                    bytes: [0u8; 32],
                },
            ),
            WalletProveError::Prove("proof backend failure".into()),
            WalletProveError::Tree(shardtree::error::ShardTreeError::Storage(())),
            WalletProveError::Tree(shardtree::error::ShardTreeError::Insert(
                shardtree::error::InsertionError::CheckpointOutOfOrder,
            )),
        ];
        for error in hard {
            assert!(!error.is_transient(), "{error} must be hard");
        }
    }

    /// A PREPARATION reaching the dispatch WITHOUT a resolved preparation anchor is a caller bug and
    /// a hard proving-unavailable error — never a silent prove against a wrong anchor (the prover
    /// is not consulted at all). This is the guard behind the lazy per-kind resolution: only the
    /// preparation arm may demand the preparation anchor.
    #[test]
    fn prove_dispatch_preparation_without_a_preparation_anchor_is_a_hard_error() {
        let mut state = provable_state(
            &[MigrationTxState::Signed],
            &[MigrationTxState::Signed],
            Some(h(1440)),
        );
        let mut prover = RecordingProver { calls: Vec::new() };
        let err = prove_due_for_test(&mut prover, &mut state, MigrationTransferId::new(0), None)
            .expect_err("a preparation without a preparation anchor must not prove");
        assert!(
            err.to_string().starts_with(PROVING_UNAVAILABLE_PREFIX),
            "the missing anchor must surface on the proving-unavailable route, got: {err}"
        );
        assert!(
            prover.calls.is_empty(),
            "the prover must never be consulted without an anchor"
        );
    }

    // ----- the delivery lane's Signed -> Proved drive (C1) -----

    use crate::migration_finalize::ProveErrorClass;

    /// A [`provable_state`]-style row set with EXPLICIT per-transfer scheduling: each transfer is
    /// `(state, scheduled, boundary)` with parseable PCZT bytes and expiry 10_000. Preparation
    /// rows keep [`provable_state`]'s shape (scheduled 50, no boundary).
    fn scheduled_state(
        prep_states: &[MigrationTxState],
        transfers: &[(MigrationTxState, u32, Option<BlockHeight>)],
    ) -> MigrationState {
        let transfer_states: Vec<MigrationTxState> =
            transfers.iter().map(|(s, _, _)| s.clone()).collect();
        let base = test_state(
            MigrationStatus::InProgress,
            prep_states,
            &transfer_states,
            50,
            10_000,
        );
        let bytes = minimal_pczt_bytes();
        let offset = prep_states.len();
        let transactions = base
            .transactions()
            .iter()
            .map(|t| {
                let (scheduled, boundary) = match t.kind() {
                    MigrationTxKind::Transfer { .. } => {
                        let (_, scheduled, boundary) =
                            &transfers[u32::from(t.id()) as usize - offset];
                        (h(*scheduled), *boundary)
                    }
                    MigrationTxKind::Preparation { .. } => (t.scheduled_height(), None),
                };
                test_transaction_from_parts(
                    t.id(),
                    t.kind(),
                    bytes.clone(),
                    t.depends_on().clone(),
                    scheduled,
                    t.expiry_height(),
                    boundary,
                    t.state(),
                    t.lock_owner(),
                )
            })
            .collect();
        test_state_from_parts(
            base.status(),
            base.denominations().clone(),
            base.preparation().clone(),
            transactions,
            base.anchor_bucket_interval(),
        )
    }

    /// The test-side counterpart of [`prove_one`] for [`prove_named_rows`]: proves through the
    /// same generic [`migration_finalize::prove_due_transaction`] seam with the given test prover
    /// instead of the production `WalletMigrationProver`, and persists through the same
    /// account-keyed store. The preparation anchor is never resolved (these fixtures sweep
    /// transfers only, which prove against their persisted boundary).
    fn prove_with_test_prover<P>(
        path: &std::path::Path,
        account: &[u8; 16],
        prover: &mut P,
        state: &mut MigrationState,
        id: MigrationTransferId,
    ) -> anyhow::Result<bool>
    where
        P: MigrationProver,
        P::Error: ProveErrorClass + std::fmt::Display,
    {
        let tx_state = state
            .transactions()
            .iter()
            .find(|t| t.id() == id)
            .map(|t| t.state())
            .expect("the swept id exists in the fixture state");
        match tx_state {
            MigrationTxState::Proved => Ok(true),
            MigrationTxState::Signed => {
                if prove_due_for_test(prover, state, id, None)?.is_none() {
                    return Ok(false);
                }
                store_fixture_state(path, account, state);
                Ok(true)
            }
            other => panic!("the sweep must not prove a row in state {}", other.as_ref()),
        }
    }

    /// Re-reads the stored migration for `account`, for asserting what the sweep persisted.
    fn read_fixture_state(path: &std::path::Path, account: &[u8; 16]) -> MigrationState {
        let mut conn = Connection::open(path).expect("the verification connection opens");
        let account_id = account_uuid_from_bytes(account.as_ptr()).expect("16 uuid bytes");
        let store = PoolMigrations::for_account(
            NetworkParams::Standard(Network::TestNetwork),
            SystemClock,
            &mut conn,
            account_id,
        )
        .expect("the account-keyed store resolves the fixture account");
        store
            .latest_migration()
            .expect("the store reads")
            .expect("a migration is stored")
    }

    /// The ids a `Prove` INSTRUCTION over `state` would name: every `Signed` row, in stored order.
    /// The sweep is an executor now — it is told what to prove rather than deriving it — so this
    /// stands in for the [`zcashlc_migration_advance_step`] call a platform makes first. (The real
    /// drive additionally verifies each candidate against the store's oracle and orders the batch
    /// oldest-anchor-first; neither bears on what [`prove_named_rows`] then does with the ids,
    /// which is what these tests are about. The drive's own batch is pinned by
    /// `advance_step_prove_carries_the_whole_batch`.)
    fn prove_instruction(state: &MigrationState) -> Vec<MigrationTransferId> {
        state
            .transactions()
            .iter()
            .filter(|t| matches!(t.state(), MigrationTxState::Signed))
            .map(|t| t.id())
            .collect()
    }

    /// The head of the engine's BROADCAST QUEUE as the public status view renders it: the
    /// `(scheduled_height, id)`-min among the rows reported `ready` with
    /// [`NextAction::Broadcast`]. Exactly the derivation [`due_assuming_proving`]'s broadcast arm
    /// contributes, so a test asserting "what is offered for broadcast" pins the same read the
    /// production queries make rather than a second one of its own.
    fn ready_broadcast_head(
        state: &MigrationState,
        targets: DuenessTargets,
    ) -> Option<MigrationTransferId> {
        state
            .transaction_statuses(targets)
            .iter()
            .filter(|s| s.ready() && s.action() == Some(NextAction::Broadcast))
            .min_by_key(|s| (s.scheduled_height(), s.id()))
            .map(|s| s.id())
    }

    /// Opens a fixture [`CallCtx`] with the chain tip set so `target_from_tip` yields `target`,
    /// plus the two prerequisites the sweep's now-verified drive needs that the pre-drive
    /// prove-queue selector never touched: the wallet scanned through `target`, and the
    /// placeholder spend nullifier every non-`Mined` fixture row carries
    /// ([`test_transaction_from_parts`]) seeded as a known, unspent note. Without both, the
    /// store's satisfiability oracle can vouch for nothing and every candidate degrades silently
    /// to `Waiting` — the safe answer, but not the one under test. `target` is the sweep tests'
    /// own convention (what the pre-drive sweep took as a raw `BlockHeight`), kept so their
    /// existing schedule/boundary/expiry fixture numbers stay valid under a real wallet tip.
    fn sweep_fixture_ctx(prefix: &str, target: u32) -> (PathBuf, [u8; 16], CallCtx) {
        let path = init_fixture_db(prefix);
        let account = create_fixture_account(&path);
        let path_bytes = path.to_str().unwrap().as_bytes();
        let tip = target - 1;
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    tip as i32,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );
        mark_fixture_scanned_through(&path, tip);
        seed_placeholder_received_note(&path, [0u8; 32]);
        let ctx = unsafe {
            open(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        }
        .expect("the fixture call context opens");
        (path, account, ctx)
    }

    /// `max_proofs` chunks a sweep: the first call proves exactly the cap and leaves the rest
    /// `Signed`; the next (uncapped) call finishes the remainder. This is the seam platforms use
    /// to interleave interactive DB reads between seconds-long proofs.
    ///
    /// The two transfers are scheduled ABOVE the target (unlike [`provable_state`]'s uniform
    /// default): schedule plays no part in prove-readiness (only the anchor boundary does), and
    /// keeping both comfortably undue sidesteps the drive's ZIP 318 overdue re-spread, which
    /// (unlike the pre-drive selector) a `Prove` batch can also trigger when two or more live
    /// candidates sit far enough behind the target — a concern this test has nothing to do with.
    #[test]
    fn sweep_cap_proves_at_most_max_and_the_next_call_finishes() {
        let (path, account, mut ctx) = sweep_fixture_ctx("zcashlc_sweep_cap_chunks", 5_000);
        let mut state = scheduled_state(
            &[MINED],
            &[
                (MigrationTxState::Signed, 6_000, Some(h(1440))),
                (MigrationTxState::Signed, 6_000, Some(h(1440))),
            ],
        );

        let mut prover = RecordingProver { calls: Vec::new() };
        let ids = prove_instruction(&state);
        let first = prove_named_rows(&mut ctx, &mut state, &ids, Some(1), |_ctx, state, id| {
            prove_with_test_prover(&path, &account, &mut prover, state, id)
        })
        .expect("a capped sweep must not fail");
        assert_eq!(
            first.total_proved, 1,
            "the cap must stop the sweep after one proof"
        );
        assert_eq!(
            prover.calls.len(),
            1,
            "the prover must run exactly once under a cap of 1"
        );
        assert_eq!(
            state
                .transactions()
                .iter()
                .filter(|t| matches!(t.state(), MigrationTxState::Signed))
                .count(),
            1,
            "one transfer must remain Signed for the next chunk"
        );

        let second = prove_named_rows(&mut ctx, &mut state, &ids, None, |_ctx, state, id| {
            prove_with_test_prover(&path, &account, &mut prover, state, id)
        })
        .expect("the follow-up sweep must not fail");
        assert_eq!(
            second.total_proved, 1,
            "the uncapped follow-up must prove the remainder"
        );
        assert_eq!(prover.calls.len(), 2, "two proofs total across the chunks");
        let _ = std::fs::remove_file(&path);
    }

    /// The sweep proves a provable `Signed` transfer — `Signed -> Proved`, PERSISTED — against the
    /// boundary drawn on its row, and the delivery lane then serves that stored artifact WITHOUT
    /// consulting a prover: proving and broadcasting are separate steps.
    #[test]
    fn sweep_proves_a_signed_transfer_that_delivery_then_serves_without_proving() {
        let (path, account, mut ctx) = sweep_fixture_ctx("zcashlc_sweep_then_serve", 5_000);
        let mut state = provable_state(&[MINED], &[MigrationTxState::Signed], Some(h(1440)));

        let mut prover = RecordingProver { calls: Vec::new() };
        let ids = prove_instruction(&state);
        let proved = prove_named_rows(&mut ctx, &mut state, &ids, None, |_ctx, state, id| {
            prove_with_test_prover(&path, &account, &mut prover, state, id)
        })
        .expect("sweeping a provable transfer must not fail");

        assert_eq!(
            proved.total_proved, 1,
            "the sweep must prove the one provable row"
        );
        assert_eq!(
            prover.calls,
            vec![ProveCall::Transfer(h(1440))],
            "the sweep must prove against the row's persisted boundary"
        );
        let stored = read_fixture_state(&path, &account);
        let tx = stored
            .transactions()
            .iter()
            .find(|t| t.id() == MigrationTransferId::new(1))
            .expect("the transfer row remains stored");
        assert!(
            matches!(tx.state(), MigrationTxState::Proved),
            "the sweep must persist Signed -> Proved"
        );

        // The swept row is now what the broadcast queue offers, with the prover untouched. The
        // delivery executor serves it once the drive instructs it to (see
        // `take_broadcast_transaction_serves_a_proved_row_through_the_broadcast_seam`); this
        // asserts the queue the drive's broadcast arm draws from, which is what the sweep was
        // for.
        let calls_before = prover.calls.len();
        assert_eq!(
            ready_broadcast_head(&stored, DuenessTargets::at(h(5_000))),
            Some(MigrationTransferId::new(1)),
            "the proved, due row must be the one offered for broadcast"
        );
        assert_eq!(
            prover.calls.len(),
            calls_before,
            "the delivery lane must never consult a prover"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A due row that has not been proved yet is delivery work no executor can serve — NOT
    /// "nothing due": the drive offers it for PROVING, and the platform must be told that a sweep
    /// is what unblocks the broadcast rather than left polling an indefinitely empty lane. (The
    /// flag that carries this over the FFI is pinned by
    /// `advance_step_estimated_tip_marks_a_prove_target_schedule_due`, and the executor's refusal
    /// to serve such a row by
    /// `take_broadcast_transaction_refuses_a_row_that_is_not_proved`.)
    #[test]
    fn a_due_unproven_row_is_delivery_work_no_executor_can_serve() {
        let state = provable_state(&[MINED], &[MigrationTxState::Signed], Some(h(1440)));

        assert_eq!(
            ready_broadcast_head(&state, DuenessTargets::at(h(5_000))),
            None,
            "an unproved row is not broadcastable, whatever its schedule says"
        );
        assert_eq!(
            due_assuming_proving(&state, DuenessTargets::at(h(5_000))),
            Some(MigrationTransferId::new(1)),
            "a due Signed row is due delivery work, naming the row that needs the proof"
        );
    }

    /// A transient prover outcome (the anchor not scanned/retained yet) leaves the row `Signed`
    /// for a later sweep and is not an error — and, crucially, does not stop the sweep: the rows
    /// BEHIND the transiently-unprovable one are still proved on the same pass.
    #[test]
    fn sweep_skips_a_transiently_unprovable_row_and_proves_the_rest() {
        let (path, account, mut ctx) = sweep_fixture_ctx("zcashlc_sweep_transient", 100);
        // Both transfers are provable and due; the prover fails the FIRST one transiently and
        // proves the second.
        let mut state = scheduled_state(
            &[MINED],
            &[
                (MigrationTxState::Signed, 90, Some(h(40))),
                (MigrationTxState::Signed, 90, Some(h(40))),
            ],
        );

        let mut prover = FirstFailsProver {
            error: Some(WalletProveError::AnchorNotFound(h(40))),
            calls: Vec::new(),
        };
        let ids = prove_instruction(&state);
        let proved = prove_named_rows(&mut ctx, &mut state, &ids, None, |_ctx, state, id| {
            prove_with_test_prover(&path, &account, &mut prover, state, id)
        })
        .expect("a transient prove outcome must not be an error");

        assert_eq!(
            proved.total_proved, 1,
            "the sweep must prove the row behind the skipped one"
        );
        assert!(
            prover.error.is_none(),
            "the sweep must have attempted the first row"
        );
        assert_eq!(
            prover.calls.len(),
            2,
            "the sweep must attempt both rows, not stop at the transient one"
        );
        let stored = read_fixture_state(&path, &account);
        let row_state = |id: u32| {
            stored
                .transactions()
                .iter()
                .find(|t| t.id() == MigrationTransferId::new(id))
                .expect("the transfer row remains stored")
                .state()
        };
        assert!(
            matches!(row_state(1), MigrationTxState::Signed),
            "a transient prove must leave its row Signed for a later sweep"
        );
        assert!(
            matches!(row_state(2), MigrationTxState::Proved),
            "the row behind the skipped one must be proved and persisted"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The sweep proves rows that are provable but NOT yet due: a transfer's boundary settles long
    /// before its scheduled height, and proving in that window is the whole point — by broadcast
    /// time the artifact already exists.
    #[test]
    fn sweep_proves_a_provable_but_undue_transfer_ahead_of_its_schedule() {
        let (path, account, mut ctx) = sweep_fixture_ctx("zcashlc_sweep_undue", 100);
        // Provable (boundary settled) but scheduled far ABOVE the tip.
        let mut state =
            scheduled_state(&[MINED], &[(MigrationTxState::Signed, 9_000, Some(h(40)))]);

        let mut prover = RecordingProver { calls: Vec::new() };
        let ids = prove_instruction(&state);
        let proved = prove_named_rows(&mut ctx, &mut state, &ids, None, |_ctx, state, id| {
            prove_with_test_prover(&path, &account, &mut prover, state, id)
        })
        .expect("the sweep must not fail");

        assert_eq!(
            proved.total_proved, 1,
            "the undue but provable row must be proved"
        );
        let stored = read_fixture_state(&path, &account);
        let tx = stored
            .transactions()
            .iter()
            .find(|t| t.id() == MigrationTransferId::new(1))
            .expect("the transfer row remains stored");
        assert!(
            matches!(tx.state(), MigrationTxState::Proved),
            "the sweep must persist the ahead-of-schedule proof"
        );
        // Still nothing to broadcast: proving does not make a row due. `due_assuming_proving`
        // subsumes the broadcast-queue read, so `None` here is the whole "nothing due" answer.
        assert_eq!(
            due_assuming_proving(&stored, DuenessTargets::at(h(100))),
            None,
            "a proved but unscheduled row must not be served"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// THE A1 BOUNDARY PIN: the drive's target is always `tip + 1` (never the raw tip —
    /// [`target_from_tip`], baked into [`dueness_targets`] and applied uniformly by
    /// [`drive_advance`]), so a PREPARATION scheduled EXACTLY at the target is OFFERED for proving
    /// now rather than one block late. A preparation is the kind whose prove-readiness IS schedule
    /// due-ness, which is why the raw-tip regression A1 fixed only ever bit preparations.
    ///
    /// The pin is read off the CONDUIT, because that is now the only thing that decides which rows
    /// a sweep is told to prove; the executor below then proves the row it was handed, against the
    /// caller-resolved preparation anchor. The raw-tip COUNTERFACTUAL the pre-drive version of
    /// this test also pinned (feeding the sweep the bare tip and asserting it wrongly swept
    /// nothing) is gone: no entry point accepts a raw height at all any more — the wallet's chain
    /// tip is the only knob a caller has, and `drive_advance` converts it to `tip + 1` the same
    /// uniform way every time — so the off-by-one class A1 fixed is structurally unrepresentable
    /// rather than merely untested.
    #[test]
    fn sweep_proves_a_preparation_scheduled_exactly_at_target() {
        let tip = h(100);
        let (path, account, mut ctx) = sweep_fixture_ctx("zcashlc_sweep_prep_at_target", 101);
        let path_bytes = path.to_str().unwrap().as_bytes();
        let mut state = custom_state(
            MigrationStatus::InProgress,
            vec![test_transaction_from_parts(
                MigrationTransferId::new(0),
                MigrationTxKind::Preparation { layer: 0, index: 0 },
                minimal_pczt_bytes(),
                Vec::new(),
                h(101), // scheduled exactly at target = tip + 1
                h(10_000),
                None,
                MigrationTxState::Signed,
                None,
            )],
        );
        store_fixture_state(&path, &account, &state);

        let (step, _id, batch, ..) = read_advance_step(path_bytes, &account);
        assert_eq!(
            step, ZCASHLC_ADVANCE_STEP_PROVE,
            "a preparation scheduled exactly at tip + 1 is due for proving NOW, not one block \
             later"
        );
        let instruction: Vec<MigrationTransferId> = batch
            .iter()
            .map(|t| MigrationTransferId::new(t.0))
            .collect();
        assert_eq!(
            instruction,
            vec![MigrationTransferId::new(0)],
            "the boundary row must be the one named, got {batch:?}"
        );

        let mut prover = RecordingProver { calls: Vec::new() };
        let proved = prove_named_rows(
            &mut ctx,
            &mut state,
            &instruction,
            None,
            |_ctx, state, id| Ok(prove_due_for_test(&mut prover, state, id, Some(tip))?.is_some()),
        )
        .expect("the boundary sweep must not fail");
        assert_eq!(proved.total_proved, 1, "the named preparation is proved");
        assert_eq!(
            prover.calls,
            vec![ProveCall::Preparation(tip)],
            "the preparation proves against the caller-resolved anchor"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A HARD prover failure aborts the sweep and propagates: an unprovable-for-real row is not
    /// something a later sweep fixes, and swallowing it would hide a corrupt store.
    #[test]
    fn sweep_propagates_a_hard_prover_failure() {
        let (path, account, mut ctx) = sweep_fixture_ctx("zcashlc_sweep_hard_failure", 5_000);
        let mut state = provable_state(&[MINED], &[MigrationTxState::Signed], Some(h(1440)));

        let mut prover = FailingProver {
            error: Some(WalletProveError::Prove("proof backend failure".into())),
        };
        let ids = prove_instruction(&state);
        let err = prove_named_rows(&mut ctx, &mut state, &ids, None, |_ctx, state, id| {
            prove_with_test_prover(&path, &account, &mut prover, state, id)
        })
        .expect_err("a hard prover failure must not be swallowed");

        assert!(
            err.to_string().starts_with(PROVING_UNAVAILABLE_PREFIX),
            "the hard failure must carry the proving-unavailable prefix, got: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// THE DUE-BROADCAST PRECEDENCE (RED against the pre-drive selector this arc replaced): a
    /// Proved, schedule-due, dependency-satisfied row is delivery work the drive names as
    /// `AdvanceStep::Broadcast`, which OUTRANKS proving in the engine's own precedence — a due
    /// broadcast is what lets a woken session submit and end without ever proving. The pre-drive
    /// prove-queue selector had no notion of that precedence and offered an
    /// independently-provable Signed row regardless of the due broadcast sitting right beside it.
    ///
    /// The pin now sits on the CONDUIT, which is where the precedence is decided: the sweep is an
    /// executor and proves whatever it is handed, so "prove nothing this session" can only be an
    /// instruction the advance declined to issue. What the executor does with an instruction that
    /// names a row it must not touch is
    /// [`prove_transactions_skips_a_row_that_is_no_longer_signed`].
    #[test]
    fn advance_defers_to_a_due_broadcast_and_offers_no_prove_batch() {
        let (path, account, _ctx) = sweep_fixture_ctx("zcashlc_sweep_due_broadcast", 100);
        let path_bytes = path.to_str().unwrap().as_bytes();
        let transactions = vec![
            // Proved, scheduled well under the target, no dependencies: ready to broadcast.
            test_transaction_from_parts(
                MigrationTransferId::new(1),
                MigrationTxKind::Transfer { crossing: 0 },
                minimal_pczt_bytes(),
                Vec::new(),
                h(50),
                h(10_000),
                Some(h(40)),
                MigrationTxState::Proved,
                None,
            ),
            // Signed, boundary settled: independently provable, but must not be offered while a
            // broadcast is due.
            test_transaction_from_parts(
                MigrationTransferId::new(2),
                MigrationTxKind::Transfer { crossing: 1 },
                minimal_pczt_bytes(),
                Vec::new(),
                h(9_000),
                h(10_000),
                Some(h(40)),
                MigrationTxState::Signed,
                None,
            ),
        ];
        let state = test_state_from_parts(
            MigrationStatus::InProgress,
            DenominationPlan::from_stored_parts(
                vec![zat(100_000_000), zat(100_000_000)],
                zat(10_000),
                None,
                zat(20_000),
                zat(1_000_000_000),
                zat(999_000_000),
            )
            .unwrap(),
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            transactions,
            AnchorBucketInterval::ZIP_318,
        );
        store_fixture_state(&path, &account, &state);

        let (step, id, targets, ..) = read_advance_step(path_bytes, &account);
        assert_eq!(
            step, ZCASHLC_ADVANCE_STEP_BROADCAST,
            "a due broadcast outranks proving: the drive must instruct a broadcast, not a sweep"
        );
        assert_eq!(id, 1, "the due, proved row is the one named");
        assert!(
            targets.is_empty(),
            "a Broadcast step carries no prove batch, so a sweeping platform is told to prove \
             nothing this session, got {targets:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// THE EXECUTOR'S STALENESS SKIP. `prove_named_rows` never re-asks the engine what to prove,
    /// so the one thing standing between a stale instruction and wasted (or wrong) work is the
    /// per-row check that the named transaction is still `Signed`. A row that has been proved
    /// since the instruction was issued is skipped — the prover is never consulted, the count is
    /// 0, and nothing is persisted — which is what makes acting on an out-of-date batch safe: the
    /// engine re-offers whatever it has not recorded on the next crank.
    #[test]
    fn prove_transactions_skips_a_row_that_is_no_longer_signed() {
        let (path, account, mut ctx) = sweep_fixture_ctx("zcashlc_sweep_stale_instruction", 5_000);
        let mut state = provable_state(&[MINED], &[MigrationTxState::Proved], Some(h(1440)));
        let stale = MigrationTransferId::new(1);

        let mut prover = RecordingProver { calls: Vec::new() };
        // The instruction names the row anyway — exactly the shape a batch that has gone stale
        // between the advance and this call arrives in.
        let proved = prove_named_rows(&mut ctx, &mut state, &[stale], None, |_ctx, state, id| {
            prove_with_test_prover(&path, &account, &mut prover, state, id)
        })
        .expect("a stale instruction must not be an error");

        assert_eq!(
            proved.total_proved, 0,
            "an already-proved row is a skip, not a re-prove"
        );
        assert!(
            prover.calls.is_empty(),
            "the prover must never be consulted for a row that is not Signed"
        );
        assert!(
            matches!(
                state
                    .transactions()
                    .iter()
                    .find(|t| t.id() == stale)
                    .expect("the row remains")
                    .state(),
                MigrationTxState::Proved
            ),
            "the skipped row must be left exactly as it was"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// [`due_assuming_proving`] mirrors the drive without a prover: a due `Signed` transfer
    /// behind an undue one IS reported, an undue-only schedule is NOT, and a row awaiting an
    /// external signature never is (the signing ceremony, not the delivery lane, advances it).
    #[test]
    fn due_assuming_proving_reports_due_signed_rows_and_only_those() {
        // A due Signed transfer behind an undue one: reported (the drive would serve it).
        let state = scheduled_state(
            &[MINED],
            &[
                (MigrationTxState::Signed, 9_000, Some(h(40))),
                (MigrationTxState::Signed, 90, Some(h(40))),
            ],
        );
        assert_eq!(
            due_assuming_proving(&state, DuenessTargets::at(h(100))),
            Some(MigrationTransferId::new(2)),
            "a due-but-unproved transfer is due delivery work"
        );
        assert!(
            state
                .transactions()
                .iter()
                .all(|t| !matches!(t.state(), MigrationTxState::Proved)),
            "the virtual drive must not mutate the caller's state"
        );

        // Provable but nothing schedule-due: not reported (proving alone is not overdue work).
        let undue = scheduled_state(&[MINED], &[(MigrationTxState::Signed, 9_000, Some(h(40)))]);
        assert_eq!(
            due_assuming_proving(&undue, DuenessTargets::at(h(100))),
            None
        );

        // Awaiting an external signature, schedule-due: not delivery work.
        let awaiting = scheduled_state(
            &[MINED],
            &[(MigrationTxState::AwaitingSignature, 90, Some(h(40)))],
        );
        assert_eq!(
            due_assuming_proving(&awaiting, DuenessTargets::at(h(100))),
            None
        );

        // Already Proved and due: reported exactly as before the drive existed.
        let proved = scheduled_state(&[MINED], &[(MigrationTxState::Proved, 90, Some(h(40)))]);
        assert_eq!(
            due_assuming_proving(&proved, DuenessTargets::at(h(100))),
            Some(MigrationTransferId::new(1))
        );
    }

    /// THE DUE-BROADCAST PRECEDENCE, as [`due_assuming_proving`] must mirror it. The engine's own
    /// `MigrationState::next_step` consults its broadcast queue UNCONDITIONALLY first and reaches
    /// its prove queue only when that queue is empty: a row that can be broadcast right now
    /// outranks all proving, whatever the two rows' relative schedules. So with a `Proved`, due
    /// transfer (id 1, scheduled 1000) beside a prove-ready `Signed` one scheduled EARLIER (id 2,
    /// scheduled 900), the answer is id 1 — the drive would broadcast it this crank and only reach
    /// id 2's proof on a later one.
    ///
    /// This is what makes the two-tier shape load-bearing rather than cosmetic: a FLAT
    /// `(scheduled_height, id)`-min over both actions answers id 2 and fails here.
    #[test]
    fn due_assuming_proving_serves_the_broadcastable_row_before_an_earlier_scheduled_unproved_one()
    {
        let state = scheduled_state(
            &[MINED],
            &[
                (MigrationTxState::Proved, 1_000, Some(h(40))),
                (MigrationTxState::Signed, 900, Some(h(40))),
            ],
        );
        assert_eq!(
            due_assuming_proving(&state, DuenessTargets::at(h(1_100))),
            Some(MigrationTransferId::new(1)),
            "a due broadcast outranks proving in the engine's own precedence: the schedule-earlier \
             row still awaiting its proof must not preempt it"
        );
    }

    /// THE NOTE-SPLIT CEREMONY'S RESUME ORDERING ([`ceremony_preparation_pick`]). A RESUMED
    /// ceremony walks into a run that already holds a `Proved`, due preparation, and must hand
    /// that artifact back rather than prove another row: re-proving what exists is seconds of
    /// wasted CPU, and the proved row is the one the engine's broadcast queue is offering right
    /// now. The fixture makes both wrong answers reachable — a still-`Signed` sibling scheduled
    /// EARLIER (which wins the fresh-commit fallback's `(scheduled_height, id)`-min), and a due
    /// `Proved` TRANSFER scheduled earlier still (which wins the broadcast queue outright, and
    /// which this lane must never hand back: the ceremony exists to serve a preparation).
    #[test]
    fn ceremony_pick_prefers_a_proved_due_preparation() {
        let prep = |id: u32, scheduled: u32, state: MigrationTxState| {
            tx_row(
                id,
                MigrationTxKind::Preparation {
                    layer: 0,
                    index: id as usize,
                },
                &[],
                scheduled,
                10_000,
                None,
                state,
            )
        };
        let transfer = |id: u32, deps: &[u32], scheduled: u32, state: MigrationTxState| {
            tx_row(
                id,
                MigrationTxKind::Transfer { crossing: 0 },
                deps,
                scheduled,
                10_000,
                None,
                state,
            )
        };

        let resumed = custom_state(
            MigrationStatus::InProgress,
            vec![
                prep(0, 100, MigrationTxState::Signed),
                prep(1, 110, MigrationTxState::Proved),
                transfer(2, &[], 90, MigrationTxState::Proved),
            ],
        );
        assert_eq!(
            ceremony_preparation_pick(&resumed, DuenessTargets::at(h(200))),
            Some(MigrationTransferId::new(1)),
            "a resume must re-serve the proved, due PREPARATION — not re-prove the \
             earlier-scheduled Signed sibling, and not hand back the transfer that outranks \
             both in the broadcast queue"
        );

        // A fresh commit holds no `Proved` row, so the fallback answers: the earliest-scheduled
        // preparation, and it answers even BEFORE the drawn window opens — the engine's queues
        // offer nothing there, and handing back that first preparation now is the whole reason
        // this lane does not simply defer to the delivery drive.
        let fresh = custom_state(
            MigrationStatus::InProgress,
            vec![
                prep(0, 100, MigrationTxState::Signed),
                prep(1, 110, MigrationTxState::Signed),
                transfer(2, &[0], 90, MigrationTxState::Signed),
            ],
        );
        for target in [h(50), h(200)] {
            assert_eq!(
                ceremony_preparation_pick(&fresh, DuenessTargets::at(target)),
                Some(MigrationTransferId::new(0)),
                "a fresh commit serves its earliest-scheduled preparation, due or not"
            );
        }

        // Every preparation is already out the door: nothing to serve, which the FFI reports as
        // an error rather than an empty answer.
        let spent = custom_state(
            MigrationStatus::InProgress,
            vec![
                prep(0, 100, MINED),
                transfer(1, &[0], 90, MigrationTxState::Signed),
            ],
        );
        assert_eq!(
            ceremony_preparation_pick(&spent, DuenessTargets::at(h(200))),
            None,
            "a run whose preparations have all been broadcast has no ceremony row left"
        );
    }

    // ----- selection order follows the engine's ordering keys, not commit order -----

    /// The broadcast queue every delivery decision rests on — the `(scheduled_height, id)`-min
    /// among ready-to-broadcast candidates, the drive's own order — never answers merely the
    /// first match in commit/dependency order. Id 3 is committed (appears in the transactions
    /// list) before id 4, but id 4 is scheduled EARLIER (3900 vs 4000): a first-match scan over
    /// commit order would answer id 3; the ordering key answers id 4, the earliest-scheduled row.
    /// Pinned through [`due_assuming_proving`], which composes that key over the public status
    /// view — the one place this module still re-derives the queue's order.
    #[test]
    fn next_due_prefers_the_schedule_earliest_row_like_the_drive() {
        let transactions = vec![
            // Committed FIRST (id 3), but scheduled LATER — must lose.
            test_transaction_from_parts(
                MigrationTransferId::new(3),
                MigrationTxKind::Transfer { crossing: 0 },
                vec![0u8],
                Vec::new(),
                h(4_000),
                h(10_000),
                None,
                MigrationTxState::Proved,
                None,
            ),
            // Committed SECOND (id 4), but scheduled EARLIER — the drive's actual pick.
            test_transaction_from_parts(
                MigrationTransferId::new(4),
                MigrationTxKind::Transfer { crossing: 1 },
                vec![0u8],
                Vec::new(),
                h(3_900),
                h(10_000),
                None,
                MigrationTxState::Proved,
                None,
            ),
        ];
        let state = test_state_from_parts(
            MigrationStatus::InProgress,
            DenominationPlan::from_stored_parts(
                vec![zat(100_000_000), zat(100_000_000)],
                zat(10_000),
                None,
                zat(20_000),
                zat(1_000_000_000),
                zat(999_000_000),
            )
            .unwrap(),
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            transactions,
            AnchorBucketInterval::ZIP_318,
        );

        assert_eq!(
            due_assuming_proving(&state, DuenessTargets::at(h(4_100))),
            Some(MigrationTransferId::new(4)),
            "the drive's (scheduled_height, id)-min must win: id 4 (scheduled 3900) over id 3 \
             (scheduled 4000), even though id 3 was committed first"
        );
    }

    /// OLDEST-ANCHOR-FIRST, pinned on both sides of the instruction. The DRIVE orders the batch
    /// by its own `(anchor_boundary, id)` key, never commit order: id 7 is committed before id 8,
    /// but id 8's boundary SETTLED EARLIER (3990 vs 4020), so the batch must name 8 first — a
    /// first-match scan over commit order would name id 7. The EXECUTOR then honours that order
    /// verbatim — with `max_proofs = 1` it proves the batch's head — because it has no ordering of
    /// its own to impose and must not reintroduce one.
    #[test]
    fn prove_sweep_serves_the_oldest_anchor_first() {
        let (path, account, mut ctx) =
            sweep_fixture_ctx("zcashlc_sweep_oldest_anchor_first", 4_100);
        let path_bytes = path.to_str().unwrap().as_bytes();
        let transactions = vec![
            // Committed FIRST (id 7), but its boundary settled LATER — must lose.
            test_transaction_from_parts(
                MigrationTransferId::new(7),
                MigrationTxKind::Transfer { crossing: 0 },
                vec![0u8],
                Vec::new(),
                h(9_000),
                h(20_000),
                Some(h(4_020)),
                MigrationTxState::Signed,
                None,
            ),
            // Committed SECOND (id 8), but its boundary settled EARLIER — the drive's actual pick.
            test_transaction_from_parts(
                MigrationTransferId::new(8),
                MigrationTxKind::Transfer { crossing: 1 },
                vec![0u8],
                Vec::new(),
                h(9_000),
                h(20_000),
                Some(h(3_990)),
                MigrationTxState::Signed,
                None,
            ),
        ];
        let mut state = test_state_from_parts(
            MigrationStatus::InProgress,
            DenominationPlan::from_stored_parts(
                vec![zat(100_000_000), zat(100_000_000)],
                zat(10_000),
                None,
                zat(20_000),
                zat(1_000_000_000),
                zat(999_000_000),
            )
            .unwrap(),
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            transactions,
            AnchorBucketInterval::ZIP_318,
        );
        store_fixture_state(&path, &account, &state);

        // The drive's own instruction, read over the conduit the platform actually calls.
        let (step, _id, batch, ..) = read_advance_step(path_bytes, &account);
        assert_eq!(step, ZCASHLC_ADVANCE_STEP_PROVE, "both rows are provable");
        let instruction: Vec<MigrationTransferId> = batch
            .iter()
            .map(|t| MigrationTransferId::new(t.0))
            .collect();
        assert_eq!(
            instruction,
            vec![MigrationTransferId::new(8), MigrationTransferId::new(7)],
            "the drive's (anchor_boundary, id)-min — oldest anchor first — must name id 8 \
             (boundary 3990) before id 7 (boundary 4020), even though id 7 was committed first"
        );

        // A recording prove closure: records which id it was asked to prove, flips that row
        // `Signed -> Proved` (as a real prove would, so `prove_named_rows`' own
        // still-Signed-after-a-successful-prove guard does not trip), and always succeeds.
        let mut proved_ids: Vec<MigrationTransferId> = Vec::new();
        let proved = prove_named_rows(
            &mut ctx,
            &mut state,
            &instruction,
            Some(1),
            |_ctx, state, id| {
                proved_ids.push(id);
                state.set_transaction_proved(id, Vec::new(), None);
                Ok(true)
            },
        )
        .expect("the recording prove closure must not fail");

        assert_eq!(
            proved.total_proved, 1,
            "max_proofs = Some(1) caps the sweep at one proof"
        );
        assert_eq!(
            proved_ids,
            vec![MigrationTransferId::new(8)],
            "the executor must take the instruction's head, imposing no order of its own"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A stored run whose next transaction is `Signed`, schedule-due, dependency-satisfied, and
    /// prove-ready is OVERDUE WORK over the real FFI: commit stores rows `Signed`, and proving is
    /// the delivery lane's own job, so answering only for already-`Proved` rows would report
    /// "nothing to do" forever on a run whose transfers were never proved.
    #[test]
    fn has_overdue_transfers_reports_a_due_signed_transfer() {
        let path = init_fixture_db("zcashlc_migration_overdue_signed");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_600_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );
        // Signed, scheduled below the tip (due), expiry above the target (valid), boundary
        // settled (`test_state` draws the boundary at the scheduled height, strictly below the
        // tip).
        let state = test_state(
            MigrationStatus::InProgress,
            &[],
            &[MigrationTxState::Signed],
            3_499_000,
            4_000_000,
        );
        store_fixture_state(&path, &account, &state);
        let overdue = unsafe {
            zcashlc_migration_has_overdue_transfers(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
                -1,
            )
        };
        assert!(
            overdue,
            "a due-but-unproved Signed transfer is overdue delivery work"
        );
        let _ = std::fs::remove_file(&path);
    }

    // ----- engine target-height boundary (F2): `transaction_statuses`, `expired_transactions`
    // and the drive are all defined over `target = tip + 1`, never the raw tip -----

    /// Engine semantics: the broadcast queue is defined over `target = tip + 1` (the height of
    /// the NEXT block), with schedule test `scheduled_height <= target` — so a `Proved` transfer
    /// scheduled at EXACTLY `tip + 1` is due for broadcast right now, one block earlier than a
    /// raw-tip check (`scheduled_height <= tip`) would have admitted it.
    #[test]
    fn has_overdue_transfers_reports_scheduled_at_target_as_due() {
        let path = init_fixture_db("zcashlc_migration_overdue_target_boundary");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_600_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );
        // Proved, scheduled at exactly tip + 1 (the target height), expiry comfortably above.
        let state = test_state(
            MigrationStatus::InProgress,
            &[],
            &[MigrationTxState::Proved],
            3_600_001, // scheduled_height == tip + 1
            4_000_000,
        );
        store_fixture_state(&path, &account, &state);
        let overdue = unsafe {
            zcashlc_migration_has_overdue_transfers(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
                -1,
            )
        };
        assert!(
            overdue,
            "a Proved transfer scheduled at tip + 1 must be due (engine: scheduled_height <= target)"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// An engine-expired `Proved` transfer (`expiry_height == tip`, so it can no longer be mined
    /// in the next block) must never be reported as due delivery work — a node would reject its
    /// broadcast outright. This already holds once the target fix lands (`next_broadcastable`
    /// already excludes expired rows when fed the right height); kept as an explicit regression
    /// pin on the exact boundary the old raw-tip call missed.
    #[test]
    fn has_overdue_transfers_does_not_report_an_expired_proved_transfer_at_the_tip() {
        let path = init_fixture_db("zcashlc_migration_overdue_expired_at_tip");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_600_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );
        // Proved, schedule-due, but expiry == tip: expired per the engine, and must not be
        // offered for broadcast even though it is otherwise ready.
        let state = test_state(
            MigrationStatus::InProgress,
            &[],
            &[MigrationTxState::Proved],
            3_499_000,
            3_600_000, // expiry_height == tip
        );
        store_fixture_state(&path, &account, &state);
        let overdue = unsafe {
            zcashlc_migration_has_overdue_transfers(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
                -1,
            )
        };
        assert!(
            !overdue,
            "an expired (expiry_height == tip) transfer must never be reported as due delivery work"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// ZIP 203 / engine semantics pin for the hand-rolled expiry check inside
    /// `zcashlc_migration_has_invalid_transfers`: `expiry_height == tip` can no longer be mined
    /// in the next block and must report as an invalid/attention-worthy transfer, one block
    /// earlier than the old `tip > expiry_height` check would catch it.
    #[test]
    fn has_invalid_transfers_reports_expiry_equal_to_tip_as_expired() {
        let path = init_fixture_db("zcashlc_migration_has_invalid_expiry_eq_tip");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_600_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );
        let state = test_state(
            MigrationStatus::InProgress,
            &[],
            &[MigrationTxState::Signed],
            3_499_000,
            3_600_000, // expiry_height == tip
        );
        store_fixture_state(&path, &account, &state);
        let invalid = unsafe {
            zcashlc_migration_has_invalid_transfers(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert!(
            invalid,
            "a transfer with expiry_height == tip can no longer be mined in the next block and \
             must report as an invalid transfer"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// `expiry_height == 0` is the engine's "never expires" sentinel; the hand-rolled check
    /// inside `zcashlc_migration_has_invalid_transfers` must not treat it as expired at any tip.
    #[test]
    fn has_invalid_transfers_ignores_expiry_zero_never_expires() {
        let path = init_fixture_db("zcashlc_migration_has_invalid_expiry_zero");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_600_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );
        let state = test_state(
            MigrationStatus::InProgress,
            &[],
            &[MigrationTxState::Signed],
            3_499_000,
            0, // expiry_height == 0: never expires
        );
        store_fixture_state(&path, &account, &state);
        let invalid = unsafe {
            zcashlc_migration_has_invalid_transfers(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert!(
            !invalid,
            "expiry_height == 0 must never expire, even at a huge tip"
        );
        let _ = std::fs::remove_file(&path);
    }

    // ----- per-transaction status view (`zcashlc_migration_transaction_statuses`) -----
    //
    // `zcashlc_migration_transaction_statuses` marshals `MigrationState::transaction_statuses`
    // verbatim, so these fixtures build heterogeneous rows directly (unlike `test_state`/
    // `scheduled_state`, which apply one uniform scheduled/expiry pair across the whole state),
    // at the file's usual 3,600,000-scale heights.

    /// A single migration-transaction row for [`custom_state`], with its own kind, dependencies,
    /// heights, and boundary — full control, unlike [`test_state`]/[`scheduled_state`].
    fn tx_row(
        id: u32,
        kind: MigrationTxKind,
        depends_on: &[u32],
        scheduled: u32,
        expiry: u32,
        anchor_boundary: Option<u32>,
        state: MigrationTxState,
    ) -> MigrationTransaction {
        test_transaction_from_parts(
            MigrationTransferId::new(id),
            kind,
            vec![0u8],
            depends_on
                .iter()
                .map(|&d| MigrationTransferId::new(d))
                .collect(),
            h(scheduled),
            h(expiry),
            anchor_boundary.map(h),
            state,
            None,
        )
    }

    /// A [`MigrationState`] built from explicit [`tx_row`]s. The note split's crossing values
    /// are throwaway placeholders (one per TRANSFER row, matching [`test_state`]'s own
    /// convention) — `transaction_statuses` never reads `note_split`.
    fn custom_state(status: MigrationStatus, rows: Vec<MigrationTransaction>) -> MigrationState {
        let funding: Vec<Zatoshis> = rows
            .iter()
            .filter(|t| matches!(t.kind(), MigrationTxKind::Transfer { .. }))
            .map(|_| zat(100_000_000))
            .collect();
        test_state_from_parts(
            status,
            DenominationPlan::from_stored_parts(
                funding,
                zat(10_000),
                None,
                zat(20_000),
                zat(1_000_000_000),
                zat(999_000_000),
            )
            .unwrap(),
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            rows,
            AnchorBucketInterval::ZIP_318,
        )
    }

    /// 1. No stored migration at all: an empty container, not an error — the same convention as
    /// [`encode_empty_schedule`], and (like
    /// [`migration_refresh_stale_transfers_on_fresh_db_returns_an_empty_schedule`]) answerable
    /// before any chain-tip lookup.
    #[test]
    fn migration_transaction_statuses_on_fresh_db_is_an_empty_container() {
        let path = init_fixture_db("zcashlc_migration_tx_statuses_fresh");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        let statuses_ptr = unsafe {
            zcashlc_migration_transaction_statuses(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert!(!statuses_ptr.is_null(), "no stored run is not an error");
        let statuses = unsafe { &*statuses_ptr };
        assert_eq!(statuses.len, 0, "no stored run yields an empty container");
        assert!(
            statuses.ptr.is_null(),
            "an empty container carries no heap array, mirroring encode_empty_schedule"
        );
        unsafe { zcashlc_free_migration_transaction_statuses(statuses_ptr) };
        let _ = std::fs::remove_file(&path);
    }

    /// 2. A mixed stored run — a MINED preparation, a BROADCAST transfer, a READY (prove) SIGNED
    /// transfer, and a SIGNED transfer blocked on its anchor boundary — marshaled verbatim from
    /// the engine. Every field is checked against `MigrationState::transaction_statuses` computed
    /// directly on the SAME state object, not a second hand-derivation.
    ///
    /// The task sketch that seeded this test named the fourth row "blocked on schedule"; the
    /// pinned engine (`zcash_pool_migration::state`) makes that unreachable for a
    /// TRANSFER — `anchor_boundary` is always `Some` for a transfer (only a preparation's is
    /// `None`), so a not-yet-prove-ready `Signed` transfer is always `Blocker::AnchorBoundary`,
    /// never `Blocker::Schedule` (`Schedule` is reported for a `Proved` row awaiting its
    /// broadcast height, or a `Signed` PREPARATION awaiting its own schedule). Row 3 below pins
    /// the real transfer-blocking case instead.

    /// 2b (item 10r). `depends_on` and `anchor_boundary` round-trip for REAL, non-empty
    /// dependency edges: a layer-0 preparation (no boundary, no deps), a layer-1 preparation (no
    /// boundary, depends on layer 0), and a transfer (a boundary, depends on the preparation that
    /// funds it).
    #[test]
    fn migration_transaction_statuses_marshals_depends_on_and_anchor_boundary() {
        let path = init_fixture_db("zcashlc_migration_tx_statuses_depends_on");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_600_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );

        let rows = vec![
            tx_row(
                0,
                MigrationTxKind::Preparation { layer: 0, index: 0 },
                &[],
                3_000_000,
                4_000_000,
                None,
                MigrationTxState::Mined {
                    txid: TxId::from_bytes([0u8; 32]),
                    height: h(3_000_000),
                },
            ),
            tx_row(
                1,
                MigrationTxKind::Preparation { layer: 1, index: 0 },
                &[0],
                3_100_000,
                4_000_000,
                None,
                MigrationTxState::Signed,
            ),
            tx_row(
                2,
                MigrationTxKind::Transfer { crossing: 0 },
                &[1],
                3_200_000,
                4_000_000,
                Some(3_000_000),
                MigrationTxState::Signed,
            ),
        ];
        let state = custom_state(MigrationStatus::InProgress, rows);
        store_fixture_state(&path, &account, &state);

        let statuses_ptr = unsafe {
            zcashlc_migration_transaction_statuses(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert!(!statuses_ptr.is_null());
        let statuses = unsafe { &*statuses_ptr };
        assert_eq!(statuses.len, 3);
        let ffi_rows = unsafe { std::slice::from_raw_parts(statuses.ptr, statuses.len) };

        let layer0_prep = ffi_rows.iter().find(|r| r.id == 0).unwrap();
        assert_eq!(layer0_prep.depends_on_len, 0, "layer 0 depends on nothing");
        assert_eq!(
            layer0_prep.anchor_boundary, -1,
            "a preparation carries no drawn boundary"
        );

        let layer1_prep = ffi_rows.iter().find(|r| r.id == 1).unwrap();
        let layer1_deps = unsafe {
            std::slice::from_raw_parts(layer1_prep.depends_on, layer1_prep.depends_on_len)
        };
        assert_eq!(layer1_deps, &[0u32], "layer 1 depends on layer 0's id");
        assert_eq!(
            layer1_prep.anchor_boundary, -1,
            "a preparation carries no drawn boundary"
        );

        let transfer = ffi_rows.iter().find(|r| r.id == 2).unwrap();
        let transfer_deps =
            unsafe { std::slice::from_raw_parts(transfer.depends_on, transfer.depends_on_len) };
        assert_eq!(
            transfer_deps,
            &[1u32],
            "the transfer depends on its funding preparation"
        );
        assert_eq!(
            transfer.anchor_boundary, 3_000_000,
            "the transfer's drawn boundary must round-trip"
        );

        unsafe { zcashlc_free_migration_transaction_statuses(statuses_ptr) };
        let _ = std::fs::remove_file(&path);
    }

    /// 3. RO-T2: `zcashlc_migration_transaction_statuses` is a PURE read of the persisted run — it
    /// no longer reconciles at the head of the read (unlike [`zcashlc_migration_advance_step`],
    /// which still sweeps as part of driving). A stored `Broadcast` transfer whose txid the
    /// WALLET's own `transactions` table already shows mined (and which the wallet has already
    /// scanned through) is still reported — and stays stored — as `Broadcast`: only a write lane
    /// (the advance-step sweep, the prove sweep, or a delivery serve) persists that promotion.
    /// Mirrors [`resolve_immediate_run_reads_mined_and_expiry_from_transactions_table`]'s
    /// technique of inserting directly into a `transactions` table, but against the REAL wallet
    /// schema (that test's table is a hand-rolled two-column stand-in;
    /// `ctx.wallet.get_tx_height` reads the real `zcash_client_sqlite` schema, so this fixture
    /// inserts the columns that schema requires: `txid`, `mined_height`, and the `NOT NULL`
    /// `min_observed_height`).
    #[test]
    fn migration_transaction_statuses_does_not_reconcile_a_mined_broadcast_transfer() {
        let path = init_fixture_db("zcashlc_migration_tx_statuses_reconcile");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_600_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );

        let txid = [3u8; 32];
        let mined_at = 3_500_000u32;
        // The wallet's own view: this txid mined at `mined_at`, independent of the migration
        // store (`reconcile_mined` cross-references the two). The wallet must also be SCANNED
        // through that height — promotion rests on evidence inside the scanned region, so a
        // hand-inserted row alone is not something the engine will act on.
        {
            let conn = Connection::open(&path).expect("the wallet connection opens");
            conn.execute(
                "INSERT INTO transactions (txid, mined_height, min_observed_height) \
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![&txid[..], mined_at, mined_at],
            )
            .expect("the fixture mined-transaction row inserts");
        }
        mark_fixture_scanned_through(&path, mined_at);

        let rows = vec![tx_row(
            0,
            MigrationTxKind::Transfer { crossing: 0 },
            &[],
            3_100_000,
            4_000_000,
            Some(3_000_000),
            MigrationTxState::Broadcast {
                txid: TxId::from_bytes(txid),
            },
        )];
        let state = custom_state(MigrationStatus::InProgress, rows);
        store_fixture_state(&path, &account, &state);

        let statuses_ptr = unsafe {
            zcashlc_migration_transaction_statuses(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert!(!statuses_ptr.is_null());
        let statuses = unsafe { &*statuses_ptr };
        assert_eq!(statuses.len, 1);
        let row = unsafe { &*statuses.ptr };
        assert_eq!(
            row.state, 3,
            "a pure read reports the PERSISTED state (Broadcast) even once the wallet's own scan \
             shows the txid mined"
        );
        assert_eq!(
            row.mined_height, -1,
            "unreconciled, the row carries no mined height"
        );
        assert!(
            row.has_txid,
            "the broadcast lifecycle state retains its txid"
        );
        assert_eq!(
            row.txid, txid,
            "the broadcast lifecycle state retains its txid"
        );
        unsafe { zcashlc_free_migration_transaction_statuses(statuses_ptr) };

        // No reconciliation happened, so nothing was persisted either — the read-only
        // connections this entry point opens through (`open_read`) could not write even if it
        // tried.
        let stored = read_fixture_state(&path, &account);
        let stored_tx = stored
            .transactions()
            .iter()
            .find(|t| t.id() == MigrationTransferId::new(0))
            .expect("the row remains stored");
        assert!(
            matches!(
                stored_tx.state(),
                MigrationTxState::Broadcast { txid: stored_txid } if stored_txid == TxId::from_bytes(txid)
            ),
            "a pure read must not mutate the stored run"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// 4. ZIP 203 / engine semantics: `expiry_height == tip` can no longer be mined in the next
    /// block (`target = tip + 1`), so the engine reports `Blocker::Expired` ahead of any other
    /// blocker. Ties the DTO to the same target-height semantics already pinned elsewhere in
    /// this file (F2: `has_overdue_transfers_does_not_report_an_expired_proved_transfer_at_the_tip`,
    /// `has_invalid_transfers_reports_expiry_equal_to_tip_as_expired`). A second row with
    /// `expiry_height == 0` (the engine's "never expires" sentinel) pins the contrast.
    #[test]
    fn migration_transaction_statuses_reports_expired_at_the_tip_boundary() {
        let path = init_fixture_db("zcashlc_migration_tx_statuses_expired");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_600_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );

        let rows = vec![
            tx_row(
                0,
                MigrationTxKind::Transfer { crossing: 0 },
                &[],
                3_000_000,
                3_600_000, // expiry_height == tip
                Some(3_000_000),
                MigrationTxState::Signed,
            ),
            tx_row(
                1,
                MigrationTxKind::Transfer { crossing: 1 },
                &[],
                3_000_000,
                0, // never expires
                Some(3_000_000),
                MigrationTxState::Signed,
            ),
        ];
        let state = custom_state(MigrationStatus::InProgress, rows);
        store_fixture_state(&path, &account, &state);

        let statuses_ptr = unsafe {
            zcashlc_migration_transaction_statuses(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert!(!statuses_ptr.is_null());
        let statuses = unsafe { &*statuses_ptr };
        assert_eq!(statuses.len, 2);
        let ffi_rows = unsafe { std::slice::from_raw_parts(statuses.ptr, statuses.len) };

        let expired = ffi_rows.iter().find(|r| r.id == 0).unwrap();
        assert!(!expired.ready, "an expired row is never ready");
        assert_eq!(expired.action, 0, "an expired row offers no action");
        assert_eq!(
            expired.blocked_on, 5,
            "expiry_height == tip must report Expired"
        );

        let never_expires = ffi_rows.iter().find(|r| r.id == 1).unwrap();
        assert!(
            never_expires.ready,
            "expiry_height == 0 must never expire, even at a huge tip"
        );
        assert_eq!(
            never_expires.action, 1,
            "the never-expiring row is prove-ready"
        );
        assert_eq!(never_expires.blocked_on, 0);

        unsafe { zcashlc_free_migration_transaction_statuses(statuses_ptr) };
        let _ = std::fs::remove_file(&path);
    }

    // ----- advance step (`zcashlc_migration_advance_step`, the verbatim next_step conduit) -----

    /// Sets the fixture chain tip to the file's usual 3,600,000.
    fn set_fixture_tip(path_bytes: &[u8]) {
        assert!(
            unsafe {
                crate::zcashlc_update_chain_tip(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    3_600_000,
                    NETWORK_ID_MAINNET,
                )
            },
            "chain-tip update must succeed"
        );
    }

    /// One copied-out `FfiProveTarget` row, as `(id, kind_is_preparation, kind_layer, kind_index,
    /// kind_crossing, schedule_due)` — the tuple shape [`read_advance_step`] collects
    /// `prove_targets` into.
    type ProveTargetTuple = (u32, bool, u32, u32, u32, bool);

    /// [`read_advance_step_at`] with no wall-clock estimate (`-1`), the ordinary reading.
    fn read_advance_step(
        path_bytes: &[u8],
        account: &[u8; 16],
    ) -> (u32, u32, Vec<ProveTargetTuple>, i64, u32) {
        read_advance_step_at(path_bytes, account, -1)
    }

    /// Reads one advance step over the FFI at `estimated_tip`, asserting success, and frees the
    /// DTO (and its `prove_targets` batch array, if any) after copying everything out. The
    /// trailing pair is the OUTLOOK (upstream #2936): `next_height` (`-1` = no outlook) and
    /// `next_kind`.
    fn read_advance_step_at(
        path_bytes: &[u8],
        account: &[u8; 16],
        estimated_tip: i64,
    ) -> (u32, u32, Vec<ProveTargetTuple>, i64, u32) {
        let ptr = unsafe {
            zcashlc_migration_advance_step(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
                estimated_tip,
            )
        };
        assert!(
            !ptr.is_null(),
            "a stored run must yield a step, not NULL: {:?}",
            ffi_helpers::error_handling::error_message()
        );
        let step = unsafe { &*ptr };
        let targets = unsafe { slice_or_empty(step.prove_targets, step.prove_targets_len) }
            .iter()
            .map(|t| {
                (
                    t.id,
                    t.kind_is_preparation,
                    t.kind_layer,
                    t.kind_index,
                    t.kind_crossing,
                    t.schedule_due,
                )
            })
            .collect();
        let out = (
            step.step,
            step.id,
            targets,
            step.next_height,
            step.next_kind,
        );
        unsafe { zcashlc_free_migration_advance_step(ptr) };
        out
    }

    /// A stored CANCELLED (`Failed`) run reports the `Complete` step VERBATIM — never remapped,
    /// and never driven: the fixture deliberately holds a `Proved`, schedule-due row that the
    /// broadcast arm would otherwise offer. The answer also precedes any chain-tip lookup (no
    /// tip is set here), pinning the conduit's hoisted terminal check (upstream `next_step`'s own
    /// first check, made answerable without a target).
    #[test]
    fn advance_step_cancelled_run_reports_complete_verbatim() {
        let path = init_fixture_db("zcashlc_advance_step_cancelled");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        // Proved and long since due — a driven run would broadcast it.
        let state = custom_state(
            MigrationStatus::Failed,
            vec![tx_row(
                0,
                MigrationTxKind::Transfer { crossing: 0 },
                &[],
                3_000_000,
                4_000_000,
                Some(3_000_000),
                MigrationTxState::Proved,
            )],
        );
        store_fixture_state(&path, &account, &state);

        let (step, id, ..) = read_advance_step(path_bytes, &account);
        assert_eq!(
            step, 4,
            "a cancelled (Failed) run must report Complete, exactly as upstream next_step does"
        );
        assert_eq!(id, 0, "the Complete step names no transaction");
        let _ = std::fs::remove_file(&path);
    }

    /// The broadcast-first ordering pin: with BOTH a proven, schedule-due row and another
    /// provable `Signed` row present, Broadcast wins. This is upstream `next_step`'s own native
    /// ordering since PR #2867 (a proven transaction's broadcast window is the scarcer resource;
    /// proving can happen on any later wake-up) — kept as a regression pin against the pinned
    /// upstream, no longer implemented by any local shim.

    /// The attend-precedence marshal pin: with an `Invalid` row present, `Attend` (naming that
    /// row) is surfaced ahead of a broadcast that is due right now — upstream's own ordering
    /// (only a terminal run outranks attention), marshaled verbatim onto the new step
    /// discriminant.

    /// Cancelling IS how attention clears: the same run as
    /// [`advance_step_attend_precedes_broadcast`] stops surfacing `Attend` (and
    /// `has_invalid_transfers`) once `zcashlc_migration_restart_step` cancels it — the cancelled
    /// run is terminal, so the conduit answers `Complete` and the attention queries answer
    /// `false`, with no separate clearing machinery involved.

    /// A provable PREPARATION reports `Prove` with a batch entry whose `kind_is_preparation` and
    /// layer/index are set — carried natively by upstream's `AdvanceStep::Prove { transactions }`,
    /// no stored-row lookup involved.

    /// A provable TRANSFER reports `Prove` with a batch entry whose crossing index is populated.

    /// Every transaction mined -> the `Complete` step (upstream's own all-mined arm).
    #[test]
    fn advance_step_all_mined_is_complete() {
        let path = init_fixture_db("zcashlc_advance_step_all_mined");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        set_fixture_tip(path_bytes);
        let state = custom_state(
            MigrationStatus::InProgress,
            vec![
                tx_row(
                    0,
                    MigrationTxKind::Preparation { layer: 0, index: 0 },
                    &[],
                    3_499_000,
                    4_000_000,
                    None,
                    MINED,
                ),
                tx_row(
                    1,
                    MigrationTxKind::Transfer { crossing: 0 },
                    &[],
                    3_499_000,
                    4_000_000,
                    Some(3_499_000),
                    MINED,
                ),
            ],
        );
        store_fixture_state(&path, &account, &state);

        let (step, id, ..) = read_advance_step(path_bytes, &account);
        assert_eq!(step, 4, "an all-mined run must report Complete");
        assert_eq!(id, 0);
        let _ = std::fs::remove_file(&path);
    }

    /// Nothing actionable (a signed transfer whose anchor boundary has not settled yet, schedule
    /// far in the future) -> `Waiting`.
    #[test]
    fn advance_step_nothing_actionable_is_waiting() {
        let path = init_fixture_db("zcashlc_advance_step_waiting");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        set_fixture_tip(path_bytes);
        let state = custom_state(
            MigrationStatus::InProgress,
            vec![tx_row(
                0,
                MigrationTxKind::Transfer { crossing: 0 },
                &[],
                3_800_000,
                4_000_000,
                Some(3_700_000), // boundary above the tip: not provable yet
                MigrationTxState::Signed,
            )],
        );
        store_fixture_state(&path, &account, &state);

        let (step, id, ..) = read_advance_step(path_bytes, &account);
        assert_eq!(step, 3, "nothing actionable must report Waiting");
        assert_eq!(id, 0, "the Waiting step names no transaction");
        let _ = std::fs::remove_file(&path);
    }

    /// The two-provable-transfers state both the batch pin and the outlook pin drive: two
    /// Signed transfers, both settled below the tip — row 0 is earliest-ready, its boundary
    /// settling before row 1's.
    fn store_two_provable_transfers(db_name: &str) -> (std::path::PathBuf, [u8; 16]) {
        let path = init_fixture_db(db_name);
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        set_fixture_tip(path_bytes);
        // The satisfiability oracle verifies a transfer's boundary checkpoint against SCANNED
        // data, not just the stored schedule — an unscanned wallet cannot vouch for either
        // boundary however far below the tip they sit.
        mark_fixture_scanned_through(&path, 3_600_000);
        // Both rows below share the fixture's placeholder spend nullifier; the oracle must find
        // it as a known, unspent input before either row is satisfiable.
        seed_placeholder_received_note(&path, [0u8; 32]);
        let state = custom_state(
            MigrationStatus::InProgress,
            vec![
                tx_row(
                    0,
                    MigrationTxKind::Transfer { crossing: 0 },
                    &[],
                    3_700_000,
                    4_000_000,
                    Some(3_500_000), // settled well below the tip: provable now
                    MigrationTxState::Signed,
                ),
                tx_row(
                    1,
                    MigrationTxKind::Transfer { crossing: 1 },
                    &[],
                    3_750_000,
                    4_000_000,
                    Some(3_550_000), // also settled, but later than row 0's boundary
                    MigrationTxState::Signed,
                ),
            ],
        );
        store_fixture_state(&path, &account, &state);
        (path, account)
    }

    /// The batch marshal pin (librustzcash #2939): with MULTIPLE provable rows outstanding, the
    /// Prove step carries the WHOLE provable set in one call rather than one candidate at a time
    /// — each entry keeping its own id and kind, ordered earliest-ready-first (a transfer by its
    /// settled anchor boundary) with distinct ids — and the step's own `id` is `0` (the batch
    /// entries carry their own).
    #[test]
    fn advance_step_prove_carries_the_whole_batch() {
        let (path, account) = store_two_provable_transfers("zcashlc_advance_step_prove_batch");
        let path_bytes = path.to_str().unwrap().as_bytes();

        let (step, id, targets, ..) = read_advance_step(path_bytes, &account);
        assert_eq!(step, 0, "multiple provable rows must report Prove");
        assert_eq!(id, 0, "the step itself names no single transaction");
        assert!(
            targets.len() >= 2,
            "the batch must carry every provable row, got {targets:?}"
        );
        let ids: Vec<u32> = targets.iter().map(|t| t.0).collect();
        assert_eq!(
            ids,
            vec![0, 1],
            "entries must be earliest-ready-first (row 0's boundary settled first) with distinct ids"
        );
        assert!(
            targets.iter().all(|t| !t.1),
            "both rows are transfers, so kind_is_preparation must be false throughout"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The preparation arm of the batch marshal: `kind_is_preparation`, `kind_layer`, and
    /// `kind_index` survive the crossing into the FFI row with layer and index NOT transposed
    /// (both cast to `u32`, so a swap would compile silently).
    #[test]
    fn advance_step_prove_marshals_a_preparation_target() {
        let path = init_fixture_db("zcashlc_advance_step_prove_preparation");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        set_fixture_tip(path_bytes);
        mark_fixture_scanned_through(&path, 3_600_000);
        seed_placeholder_received_note(&path, [0u8; 32]);
        let state = custom_state(
            MigrationStatus::InProgress,
            vec![tx_row(
                0,
                MigrationTxKind::Preparation { layer: 2, index: 5 },
                &[],
                3_500_000, // due: at or below the scanned target, so the schedule offers it
                4_000_000,
                None, // a preparation draws no anchor boundary
                MigrationTxState::Signed,
            )],
        );
        store_fixture_state(&path, &account, &state);

        let (step, id, targets, ..) = read_advance_step(path_bytes, &account);
        assert_eq!(
            step, ZCASHLC_ADVANCE_STEP_PROVE,
            "a due preparation is provable"
        );
        assert_eq!(id, 0, "the step itself names no single transaction");
        assert_eq!(
            targets.len(),
            1,
            "exactly the one preparation, got {targets:?}"
        );
        let (target_id, is_preparation, layer, index, crossing, schedule_due) = targets[0];
        assert_eq!(target_id, 0);
        assert!(is_preparation, "the kind must marshal as a preparation");
        assert_eq!(layer, 2, "layer must not be transposed with index");
        assert_eq!(index, 5, "index must not be transposed with layer");
        assert_eq!(crossing, 0, "a preparation carries no crossing");
        assert!(
            schedule_due,
            "the preparation is scheduled at or below the target, so its proof blocks delivery"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The OUTLOOK (upstream #2936, `Advance::next`): the earliest height at which the migration
    /// next has serviceable work, assuming the served step is executed — mirrors upstream's own
    /// `outlook_after_a_prove_is_the_broadcast_that_follows` (satisfiability.rs ~3089): a served
    /// Prove batch's own entries become `Proved` in the hypothetical, so their own (still-future)
    /// broadcast schedule is what the outlook reports next.
    #[test]
    fn advance_step_outlook_reports_next_work() {
        let (path, account) = store_two_provable_transfers("zcashlc_advance_step_outlook_prove");
        let path_bytes = path.to_str().unwrap().as_bytes();

        let (step, _id, targets, next_height, next_kind) = read_advance_step(path_bytes, &account);
        assert_eq!(
            step, ZCASHLC_ADVANCE_STEP_PROVE,
            "the whole provable batch is served now"
        );
        assert_eq!(targets.len(), 2, "both rows are provable now");
        assert!(
            next_height > 0,
            "once proved, row 0's own (still-future) broadcast schedule is a real height: {next_height}"
        );
        assert_eq!(
            next_height, 3_700_000,
            "the earliest of the two proved-and-scheduled followers wins"
        );
        assert_eq!(
            next_kind, ZCASHLC_STEP_KIND_BROADCAST,
            "once proved, a transfer's own later broadcast is the outlook"
        );
        let _ = std::fs::remove_file(&path);

        // Nothing height-schedulable: the sole transaction is already in flight (Broadcast,
        // unmined) -- mining is chain-derived, so upstream's `step_floor` reports no floor for
        // it, and the Waiting step's outlook is `None` (mirrors upstream's own
        // `outlook_is_none_when_nothing_is_height_schedulable`, satisfiability.rs, second case).
        // No anchor boundary: an in-flight row's boundary would otherwise route the drive's own
        // reorg-displacement check through the stored PCZT, which this fixture's placeholder
        // bytes cannot satisfy -- orthogonal to what this scenario exercises (`step_floor`
        // reports no floor for a `Broadcast`-state row regardless of its boundary).
        let path = init_fixture_db("zcashlc_advance_step_outlook_none");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        set_fixture_tip(path_bytes);
        mark_fixture_scanned_through(&path, 3_600_000);
        let state = custom_state(
            MigrationStatus::InProgress,
            vec![tx_row(
                0,
                MigrationTxKind::Transfer { crossing: 0 },
                &[],
                3_100_000,
                4_000_000,
                None,
                MigrationTxState::Broadcast {
                    txid: TxId::from_bytes([9u8; 32]),
                },
            )],
        );
        store_fixture_state(&path, &account, &state);

        let (step, _id, _targets, next_height, _next_kind) =
            read_advance_step(path_bytes, &account);
        assert_eq!(
            step, ZCASHLC_ADVANCE_STEP_WAITING,
            "an in-flight-only run must report Waiting"
        );
        assert_eq!(
            next_height, -1,
            "mining is chain-derived: nothing is height-schedulable"
        );
        let _ = std::fs::remove_file(&path);
    }

    // ----- progress (`zcashlc_migration_progress` — the standalone derivation) -----

    /// Reads the progress DTO over the FFI, asserting success, and frees it after copying it out.
    fn read_progress(path_bytes: &[u8], account: &[u8; 16]) -> (bool, u32, u32, i64, bool) {
        let ptr = unsafe {
            zcashlc_migration_progress(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert!(
            !ptr.is_null(),
            "progress must not error: {:?}",
            ffi_helpers::error_handling::error_message()
        );
        let progress = unsafe { &*ptr };
        let out = (
            progress.is_present,
            progress.completed_transfers,
            progress.total_transfers,
            progress.next_transfer_ready_at_height,
            progress.is_immediate,
        );
        unsafe { zcashlc_free_migration_progress(ptr) };
        out
    }

    /// An ACTIVE stored run reports its transfer counts (engine lane: `is_immediate == false`).
    #[test]
    fn progress_active_run_reports_counts() {
        let path = init_fixture_db("zcashlc_progress_active");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        set_fixture_tip(path_bytes);
        let state = test_state(
            MigrationStatus::InProgress,
            &[MINED],
            &[MINED, MigrationTxState::Signed],
            3_499_000,
            4_000_000,
        );
        store_fixture_state(&path, &account, &state);

        let (present, completed, total, next_ready, is_immediate) =
            read_progress(path_bytes, &account);
        assert!(present, "an active run must report progress");
        assert_eq!(completed, 1);
        assert_eq!(total, 2);
        assert_eq!(next_ready, 3_499_000);
        assert!(!is_immediate, "an engine-tracked run is not immediate");
        let _ = std::fs::remove_file(&path);
    }

    /// A terminal `Complete` run reports ABSENT (per-run completion is `advance_step`'s answer;
    /// progress has nothing live to show). No chain tip is set: the terminal answer precedes any
    /// tip lookup.
    #[test]
    fn progress_terminal_complete_run_is_absent() {
        let path = init_fixture_db("zcashlc_progress_complete");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        let state = test_state(
            MigrationStatus::Complete,
            &[MINED],
            &[MINED],
            3_499_000,
            4_000_000,
        );
        store_fixture_state(&path, &account, &state);

        let (present, ..) = read_progress(path_bytes, &account);
        assert!(!present, "a Complete run must report absent progress");
        let _ = std::fs::remove_file(&path);
    }

    /// A cancelled (`Failed`) run likewise reports ABSENT.
    #[test]
    fn progress_failed_run_is_absent() {
        let path = init_fixture_db("zcashlc_progress_failed");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        let state = test_state(
            MigrationStatus::Failed,
            &[MigrationTxState::Signed],
            &[MigrationTxState::Signed],
            3_499_000,
            4_000_000,
        );
        store_fixture_state(&path, &account, &state);

        let (present, ..) = read_progress(path_bytes, &account);
        assert!(!present, "a Failed run must report absent progress");
        let _ = std::fs::remove_file(&path);
    }

    /// A recorded, still-unmined immediate sweep reports the pending `0 of 1` snapshot flagged
    /// `is_immediate` (the immediate lane's ONLY surface).
    #[test]
    fn progress_immediate_unmined_is_present_zero_of_one() {
        let path = init_fixture_db("zcashlc_progress_immediate_pending");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        set_fixture_tip(path_bytes);
        let txid = [7u8; 32];
        assert!(
            unsafe {
                zcashlc_migration_record_immediate_run(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    account.as_ptr(),
                    NETWORK_ID_MAINNET,
                    txid.as_ptr(),
                )
            },
            "recording the immediate run must succeed"
        );

        let (present, completed, total, next_ready, is_immediate) =
            read_progress(path_bytes, &account);
        assert!(present, "a pending immediate run must report progress");
        assert_eq!((completed, total), (0, 1));
        assert_eq!(
            next_ready, -1,
            "the immediate lane has no next-ready height"
        );
        assert!(is_immediate, "the immediate lane must be flagged");
        let _ = std::fs::remove_file(&path);
    }

    /// Once the wallet observes the swept txid MINED, the immediate run is consumed and progress
    /// reports ABSENT.
    #[test]
    fn progress_immediate_mined_is_absent() {
        let path = init_fixture_db("zcashlc_progress_immediate_mined");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        set_fixture_tip(path_bytes);
        let txid = [8u8; 32];
        assert!(
            unsafe {
                zcashlc_migration_record_immediate_run(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    account.as_ptr(),
                    NETWORK_ID_MAINNET,
                    txid.as_ptr(),
                )
            },
            "recording the immediate run must succeed"
        );
        // The wallet's own transaction history now shows the sweep mined below the tip.
        let conn = Connection::open(&path).expect("the fixture connection opens");
        conn.execute(
            "INSERT INTO transactions (txid, mined_height, min_observed_height, expiry_height)
             VALUES (?1, ?2, ?2, ?3)",
            rusqlite::params![&txid[..], 3_599_000u32, 3_700_000u32],
        )
        .expect("the mined sweep row inserts");

        let (present, ..) = read_progress(path_bytes, &account);
        assert!(!present, "a mined immediate run is consumed: absent");
        let _ = std::fs::remove_file(&path);
    }

    // ----- sync wake-ups (`zcashlc_migration_sync_wakeups`) -----

    /// No stored run: the EMPTY schedule (valid pointer, `len == 0`), not an error — and no
    /// chain-tip lookup, so it holds on a never-synced wallet.
    #[test]
    fn sync_wakeups_no_run_is_empty() {
        let path = init_fixture_db("zcashlc_sync_wakeups_no_run");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        let ptr = unsafe {
            zcashlc_migration_sync_wakeups(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert!(!ptr.is_null(), "no stored run must answer EMPTY, not error");
        assert_eq!(unsafe { &*ptr }.len, 0);
        unsafe { zcashlc_free_migration_sync_wakeups(ptr) };
        let _ = std::fs::remove_file(&path);
    }

    /// A committed run with transfers still needing proofs yields a non-empty schedule whose
    /// `covers` ids all belong to the run's transfers (the mined preparation contributes
    /// nothing). Jitter is re-drawn per call, so a second call may differ in heights — the test
    /// deliberately asserts only jitter-independent facts (row structure, covers, window bounds)
    /// and NEVER equality across calls.
    #[test]
    fn sync_wakeups_committed_run_covers_its_transfers() {
        let path = init_fixture_db("zcashlc_sync_wakeups_covers");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        set_fixture_tip(path_bytes);
        // Two signed transfers in well-separated proving windows (boundary .. broadcast), plus a
        // mined preparation that must contribute no wake-up.
        let state = custom_state(
            MigrationStatus::InProgress,
            vec![
                tx_row(
                    0,
                    MigrationTxKind::Preparation { layer: 0, index: 0 },
                    &[],
                    3_499_000,
                    0,
                    None,
                    MINED,
                ),
                tx_row(
                    1,
                    MigrationTxKind::Transfer { crossing: 0 },
                    &[],
                    3_610_000,
                    0,
                    Some(3_601_440),
                    MigrationTxState::Signed,
                ),
                tx_row(
                    2,
                    MigrationTxKind::Transfer { crossing: 1 },
                    &[],
                    3_650_000,
                    0,
                    Some(3_641_440),
                    MigrationTxState::Signed,
                ),
            ],
        );
        store_fixture_state(&path, &account, &state);

        let read_covers = || {
            let ptr = unsafe {
                zcashlc_migration_sync_wakeups(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    account.as_ptr(),
                    NETWORK_ID_MAINNET,
                )
            };
            assert!(
                !ptr.is_null(),
                "a committed run must yield a schedule: {:?}",
                ffi_helpers::error_handling::error_message()
            );
            let wakeups = unsafe { &*ptr };
            let rows = unsafe { std::slice::from_raw_parts(wakeups.rows, wakeups.len) };
            let mut covered: Vec<u32> = Vec::new();
            for row in rows {
                let ids = unsafe { std::slice::from_raw_parts(row.covers, row.covers_len) };
                for id in ids {
                    assert!(
                        [1u32, 2u32].contains(id),
                        "every covered id must belong to the run's transfers, got {id}"
                    );
                    // Each wake-up must land strictly inside its transfers' proving windows:
                    // past the boundary, before the broadcast.
                    let (boundary, broadcast) = if *id == 1 {
                        (3_601_440i64, 3_610_000i64)
                    } else {
                        (3_641_440i64, 3_650_000i64)
                    };
                    assert!(
                        row.height > boundary && row.height < broadcast,
                        "wake-up {} must sit in ({boundary}, {broadcast})",
                        row.height
                    );
                }
                covered.extend_from_slice(ids);
            }
            covered.sort_unstable();
            unsafe { zcashlc_free_migration_sync_wakeups(ptr) };
            covered
        };

        // Two draws (fresh jitter each): both must cover exactly the run's pending transfers.
        // No cross-call height equality is asserted anywhere — that would pin the jitter.
        assert_eq!(read_covers(), vec![1, 2]);
        assert_eq!(read_covers(), vec![1, 2]);
        let _ = std::fs::remove_file(&path);
    }

    /// A transfer whose broadcast height is not at least two blocks above its anchor boundary
    /// admits no wake-up height: the stable `MIGRATION_WAKEUP_INFEASIBLE:<id>` error, carrying
    /// the offending id right after the colon.
    #[test]
    fn sync_wakeups_infeasible_transfer_errors_with_stable_prefix() {
        let path = init_fixture_db("zcashlc_sync_wakeups_infeasible");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        set_fixture_tip(path_bytes);
        let state = custom_state(
            MigrationStatus::InProgress,
            vec![tx_row(
                7,
                MigrationTxKind::Transfer { crossing: 0 },
                &[],
                3_601_441, // broadcast NOT >= boundary + 2: infeasible
                0,
                Some(3_601_440),
                MigrationTxState::Signed,
            )],
        );
        store_fixture_state(&path, &account, &state);

        let ptr = unsafe {
            zcashlc_migration_sync_wakeups(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert!(ptr.is_null(), "an infeasible transfer must be an error");
        let message = ffi_helpers::error_handling::error_message()
            .expect("the last-error channel must carry the failure");
        assert_eq!(
            message, "MIGRATION_WAKEUP_INFEASIBLE:7",
            "the stable prefix must carry the offending id directly after the colon"
        );
        let _ = std::fs::remove_file(&path);
    }

    // ----- block-rate samples (`zcashlc_migration_block_rate_samples`) -----

    /// A wallet that has scanned no blocks yet answers the EMPTY list, not an error.
    #[test]
    fn block_rate_samples_empty_wallet_is_empty() {
        let path = init_fixture_db("zcashlc_block_rate_empty");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let ptr = unsafe {
            zcashlc_migration_block_rate_samples(
                path_bytes.as_ptr(),
                path_bytes.len(),
                NETWORK_ID_MAINNET,
                10,
            )
        };
        assert!(
            !ptr.is_null(),
            "an empty wallet must answer EMPTY, not error"
        );
        assert_eq!(unsafe { &*ptr }.len, 0);
        unsafe { zcashlc_free_block_rate_samples(ptr) };
        let _ = std::fs::remove_file(&path);
    }

    /// A12: a wallet-database file that does not exist at all is the same benign "no scanned
    /// blocks yet" answer as a missing `blocks` table — EMPTY, with NO error recorded — because
    /// the read-only open cannot create the file (`SQLITE_CANTOPEN` is a state of the world, not
    /// a failure of this read).
    #[test]
    fn block_rate_samples_nonexistent_db_file_is_empty_not_an_error() {
        let path = std::env::temp_dir().join(format!(
            "zcashlc_block_rate_missing_{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let path_bytes = path.to_str().unwrap().as_bytes();
        let ptr = unsafe {
            zcashlc_migration_block_rate_samples(
                path_bytes.as_ptr(),
                path_bytes.len(),
                NETWORK_ID_MAINNET,
                10,
            )
        };
        assert!(
            !ptr.is_null(),
            "a missing wallet-database file must answer EMPTY, not error"
        );
        assert_eq!(unsafe { &*ptr }.len, 0);
        assert!(
            ffi_helpers::error_handling::take_last_error().is_none(),
            "the empty answer must record NO error"
        );
        unsafe { zcashlc_free_block_rate_samples(ptr) };
        assert!(
            !path.exists(),
            "the read-only probe must not have created the file"
        );
    }

    /// With scanned blocks present, the most recent `window` rows come back ASCENDING by height,
    /// carrying the stored header times.
    #[test]
    fn block_rate_samples_returns_window_ascending() {
        let path = init_fixture_db("zcashlc_block_rate_window");
        let path_bytes = path.to_str().unwrap().as_bytes();
        {
            let conn = Connection::open(&path).expect("the fixture connection opens");
            for (height, time) in [(100i64, 1_000i64), (101, 1_075), (102, 1_150), (103, 1_225)] {
                conn.execute(
                    "INSERT INTO blocks (height, hash, time, sapling_tree)
                     VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![height, &[0u8; 32][..], time, &[0u8; 0][..]],
                )
                .expect("the fixture block row inserts");
            }
        }
        let ptr = unsafe {
            zcashlc_migration_block_rate_samples(
                path_bytes.as_ptr(),
                path_bytes.len(),
                NETWORK_ID_MAINNET,
                3,
            )
        };
        assert!(!ptr.is_null());
        let samples = unsafe { &*ptr };
        assert_eq!(samples.len, 3, "the window caps the row count");
        let rows = unsafe { std::slice::from_raw_parts(samples.rows, samples.len) };
        let got: Vec<(i64, i64)> = rows.iter().map(|r| (r.height, r.unix_time)).collect();
        assert_eq!(
            got,
            vec![(101, 1_075), (102, 1_150), (103, 1_225)],
            "the MOST RECENT `window` rows must come back ASCENDING by height"
        );
        unsafe { zcashlc_free_block_rate_samples(ptr) };
        let _ = std::fs::remove_file(&path);
    }

    // ----- estimated-tip due-ness (M2: accelerate due-ness only, never expiry) -----

    fn has_overdue(path_bytes: &[u8], account: &[u8; 16], estimated_tip: i64) -> bool {
        unsafe {
            zcashlc_migration_has_overdue_transfers(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
                estimated_tip,
            )
        }
    }

    /// A transfer scheduled past the scanned target but at/below the estimated tip is overdue
    /// WITH the estimate and not without it (`-1` disables).
    #[test]
    fn has_overdue_estimated_tip_accelerates_due_ness() {
        let path = init_fixture_db("zcashlc_overdue_estimate_accelerates");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        set_fixture_tip(path_bytes);
        // Proved, scheduled at 3_600_010: above the scanned target (3_600_001), at the estimate.
        let state = test_state(
            MigrationStatus::InProgress,
            &[],
            &[MigrationTxState::Proved],
            3_600_010,
            4_000_000,
        );
        store_fixture_state(&path, &account, &state);

        assert!(
            !has_overdue(path_bytes, &account, -1),
            "without an estimate the row is not yet due"
        );
        assert!(
            has_overdue(path_bytes, &account, 3_600_010),
            "the estimate must accelerate scheduled-height due-ness"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// THE M2 HARD RULE, as upstream `DuenessTargets` encodes it: the estimate never DECIDES an
    /// expiry — but it does WITHHOLD a doomed broadcast (upstream's protective refusal, A4). A
    /// proved row due at the SCANNED tip whose expiry only the ESTIMATED target has passed:
    /// - is served without the estimate (the scanned view proves nothing wrong with it);
    /// - is NOT served with the estimate (if the estimate is right, a node would reject the
    ///   submission — withholding wastes nothing and is reversible);
    /// - is treated as EXPIRED nowhere (no attention verdict, nothing marked or persisted): the
    ///   expiry decision needs the scanned tip, and once withheld the row simply waits for the
    ///   scanned tip to prove the expiry either way.
    #[test]
    fn has_overdue_estimated_tip_withholds_a_doomed_broadcast_but_never_decides_expiry() {
        let path = init_fixture_db("zcashlc_overdue_estimate_expiry");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        set_fixture_tip(path_bytes);
        // Proved; due at the SCANNED target already; expiry ABOVE the scanned target but far
        // BELOW the estimated one.
        let state = test_state(
            MigrationStatus::InProgress,
            &[],
            &[MigrationTxState::Proved],
            3_499_000,
            3_600_020,
        );
        store_fixture_state(&path, &account, &state);

        assert!(
            has_overdue(path_bytes, &account, -1),
            "without the estimate the scanned view serves the due, unexpired row"
        );
        assert!(
            !has_overdue(path_bytes, &account, 3_700_000),
            "the doomed broadcast is withheld: under the estimate the node would reject it"
        );
        assert!(
            !unsafe {
                zcashlc_migration_has_invalid_transfers(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    account.as_ptr(),
                    NETWORK_ID_MAINNET,
                )
            },
            "the withhold is not an expiry verdict: nothing reports the row as expired/invalid"
        );
        assert!(
            has_overdue(path_bytes, &account, -1),
            "nothing was marked or persisted by the withheld query: the scanned view still serves"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The drive honours the doomed-broadcast withhold: a proved, scanned-due row whose expiry
    /// only the ESTIMATED target has passed is NOT offered by the broadcast queue the drive plans
    /// from, so over the FFI the advance step answers `Waiting` rather than a BROADCAST
    /// instruction an executor would then discharge — while without the estimate it is served.
    #[test]
    fn advance_step_withholds_a_doomed_broadcast() {
        let path = init_fixture_db("zcashlc_next_due_doomed");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        set_fixture_tip(path_bytes);
        mark_fixture_scanned_through(&path, 3_600_000);
        seed_placeholder_received_note(&path, [0u8; 32]);
        let scanned_tip = h(3_600_000);
        // Proved; due at the SCANNED target; expiry between the scanned and estimated targets.
        let state = test_state(
            MigrationStatus::InProgress,
            &[],
            &[MigrationTxState::Proved],
            3_499_000,
            3_600_020,
        );
        store_fixture_state(&path, &account, &state);

        // The pure queue read the drive plans from: offered on the scanned view, withheld under
        // the estimate.
        assert_eq!(
            ready_broadcast_head(&state, dueness_targets(scanned_tip, -1)),
            Some(MigrationTransferId::new(0)),
            "without the estimate the proved, due, unexpired row is offered"
        );
        assert_eq!(
            due_assuming_proving(&state, dueness_targets(scanned_tip, 3_700_000)),
            None,
            "under the estimate the doomed broadcast is withheld from the delivery lane"
        );

        // The same withhold over the FFI: the conduit issues no BROADCAST instruction, so the
        // executor is never reached.
        let (step, ..) = read_advance_step_at(path_bytes, &account, 3_700_000);
        assert_eq!(
            step, ZCASHLC_ADVANCE_STEP_WAITING,
            "the doomed row must yield no broadcast instruction under the estimate"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// An estimate BELOW the scanned tip is ignored (the max rule): it neither un-dues a due row
    /// nor dues an undue one.
    #[test]
    fn has_overdue_estimated_tip_below_scanned_is_ignored() {
        let path = init_fixture_db("zcashlc_overdue_estimate_below");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        set_fixture_tip(path_bytes);
        // Due at the scanned target already.
        let due = test_state(
            MigrationStatus::InProgress,
            &[],
            &[MigrationTxState::Proved],
            3_600_001,
            4_000_000,
        );
        store_fixture_state(&path, &account, &due);
        assert!(
            has_overdue(path_bytes, &account, 3_500_000),
            "a low estimate must not mask scanned due-ness (effective = max(scanned, estimated))"
        );

        // Not due at the scanned target: the low estimate must not make it due either.
        let undue = test_state(
            MigrationStatus::InProgress,
            &[],
            &[MigrationTxState::Proved],
            3_600_010,
            4_000_000,
        );
        store_fixture_state(&path, &account, &undue);
        assert!(
            !has_overdue(path_bytes, &account, 3_500_000),
            "an estimate below the scanned tip is ignored, not applied"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The PROVE step's `schedule_due` flag mirrors the same acceleration: a `Signed`, provable
    /// transfer scheduled past the scanned target is NOT schedule-due without the estimate and IS
    /// with it (the boundary-settle check stays scanned-side — the fixture's boundary IS settled).
    ///
    /// This is what lets a platform's delivery session distinguish "the batch is opportunistic
    /// proving work" from "the delivery lane is blocked on this proof" without asking the engine a
    /// second question of its own.
    ///
    /// The fixture owes the store's satisfiability oracle a scanned range and a known, unspent
    /// input, because the batch is drawn by the VERIFIED drive: an oracle with nothing to vouch
    /// with sets the candidate aside and the step degrades to `Waiting`, which is the safe answer
    /// but not the acceleration under test.
    #[test]
    fn advance_step_estimated_tip_marks_a_prove_target_schedule_due() {
        let path = init_fixture_db("zcashlc_next_due_estimate");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        set_fixture_tip(path_bytes);
        mark_fixture_scanned_through(&path, 3_600_000);
        seed_placeholder_received_note(&path, [0u8; 32]);
        let state = custom_state(
            MigrationStatus::InProgress,
            vec![tx_row(
                0,
                MigrationTxKind::Transfer { crossing: 0 },
                &[],
                3_600_010,
                4_000_000,
                Some(3_499_000), // settled boundary: provable at the SCANNED tip
                MigrationTxState::Signed,
            )],
        );
        store_fixture_state(&path, &account, &state);

        let read_due = |estimated_tip: i64| {
            let (step, _id, targets, ..) =
                read_advance_step_at(path_bytes, &account, estimated_tip);
            assert_eq!(
                step, ZCASHLC_ADVANCE_STEP_PROVE,
                "the provable row is offered for proving either way"
            );
            assert_eq!(targets.len(), 1, "exactly the one row, got {targets:?}");
            (targets[0].0, targets[0].5)
        };

        let (id, schedule_due) = read_due(-1);
        assert_eq!(id, 0, "the batch names the provable row");
        assert!(
            !schedule_due,
            "without an estimate the future-scheduled row's proof blocks no delivery"
        );
        let (id, schedule_due) = read_due(3_600_010);
        assert_eq!(id, 0, "the batch still names the same row");
        assert!(
            schedule_due,
            "under the estimate the row is due, so its missing proof IS what blocks delivery"
        );
        let _ = std::fs::remove_file(&path);
    }

    // ----- the delivery executor (`zcashlc_migration_take_broadcast_transaction`) -----
    //
    // The instruction the executor discharges comes from the engine's VERIFIED drive, so these
    // fixtures owe the store's satisfiability oracle what a real wallet would have: a scanned
    // range (`mark_fixture_scanned_through`) and a known, unspent input for the rows' placeholder
    // nullifier (`seed_placeholder_received_note`). Without both the oracle can vouch for nothing
    // and every step degrades to `Waiting` — the safe answer, but not the one under test. The
    // rows also carry PARSEABLE artifacts ([`provable_tx_row`]): the broadcast seam finalizes and
    // extracts the stored PCZT, which the `vec![0u8]` placeholder cannot survive.

    /// [`tx_row`] carrying parseable PCZT bytes ([`minimal_pczt_bytes`]) — what the delivery
    /// executor's broadcast seam needs, and what the heterogeneous-row fixtures otherwise lack.
    fn provable_tx_row(
        id: u32,
        kind: MigrationTxKind,
        scheduled: u32,
        expiry: u32,
        anchor_boundary: Option<u32>,
        state: MigrationTxState,
    ) -> MigrationTransaction {
        test_transaction_from_parts(
            MigrationTransferId::new(id),
            kind,
            minimal_pczt_bytes(),
            Vec::new(),
            h(scheduled),
            h(expiry),
            anchor_boundary.map(h),
            state,
            None,
        )
    }

    /// A fixture wallet whose oracle can vouch for [`provable_tx_row`] rows: tip and scanned
    /// range at the file's usual 3,600,000, with the placeholder spend nullifier seeded as a
    /// known, unspent note.
    fn init_delivery_fixture(prefix: &str) -> (PathBuf, [u8; 16]) {
        let path = init_fixture_db(prefix);
        let account = create_fixture_account(&path);
        set_fixture_tip(path.to_str().unwrap().as_bytes());
        mark_fixture_scanned_through(&path, 3_600_000);
        seed_placeholder_received_note(&path, [0u8; 32]);
        (path, account)
    }

    /// One run of the delivery executor over the FFI, with the DTO copied out and freed: the
    /// named id, the served txid, and the served (finalized transaction) bytes. Asserts success —
    /// the executor has no benign empty answer, so a NULL here is an error to be read with
    /// [`take_broadcast_error`] instead.
    fn take_broadcast_transaction(
        path_bytes: &[u8],
        account: &[u8; 16],
        id: u32,
    ) -> (u32, [u8; 32], Vec<u8>) {
        let ptr = unsafe {
            zcashlc_migration_take_broadcast_transaction(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
                id,
            )
        };
        assert!(
            !ptr.is_null(),
            "the delivery executor must not error: {:?}",
            ffi_helpers::error_handling::error_message()
        );
        let prepared = unsafe { &*ptr };
        let out = (
            prepared.id,
            prepared.txid,
            unsafe { slice_or_empty(prepared.pczt, prepared.pczt_len) }.to_vec(),
        );
        unsafe { zcashlc_free_migration_prepared_transfer(ptr) };
        out
    }

    /// The delivery executor's refusal message: asserts the NULL return and takes the last error.
    fn take_broadcast_error(path_bytes: &[u8], account: &[u8; 16], id: u32) -> String {
        let ptr = unsafe {
            zcashlc_migration_take_broadcast_transaction(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
                id,
            )
        };
        assert!(
            ptr.is_null(),
            "the executor was expected to refuse row {id}"
        );
        ffi_helpers::error_handling::take_last_error()
            .expect("the refusal must record a last-error")
            .to_string()
    }

    /// The number of rows the wallet's OWN `transactions` table holds with raw bytes recorded —
    /// the record the broadcast seam writes in the same database transaction as it hands the
    /// transaction out. (The fixtures' own hand-inserted rows carry no `raw`, so this counts
    /// exactly what the seam wrote.)
    fn wallet_transaction_records(path: &std::path::Path) -> i64 {
        let conn = Connection::open(path).expect("the verification connection opens");
        conn.query_row(
            "SELECT COUNT(*) FROM transactions WHERE raw IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .expect("the wallet transactions table is queryable")
    }

    /// The stored scheduled height of `id`, for asserting what a drive persisted.
    fn stored_scheduled_height(state: &MigrationState, id: u32) -> u32 {
        state
            .transactions()
            .iter()
            .find(|t| t.id() == MigrationTransferId::new(id))
            .map(|t| u32::from(t.scheduled_height()))
            .unwrap_or_else(|| panic!("row {id} remains stored"))
    }

    /// `PoolMigrations::take_transaction_for_broadcast` over the fixture wallet, surfacing the store's
    /// TYPED error — what the delivery lane's broadcast arm delegates to, and what
    /// [`broadcast_seam_error`] classifies. The store error type is `#[non_exhaustive]`, so a real
    /// call is the only way a test can hold one of its variants.
    fn take_for_broadcast(
        path: &std::path::Path,
        account: &[u8; 16],
        state: &MigrationState,
        id: u32,
    ) -> Result<(), PoolMigrationStoreError> {
        let path_bytes = path.to_str().unwrap().as_bytes();
        let mut ctx = unsafe {
            open(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        }
        .expect("the fixture call context opens");
        let mut store = account_store(&ctx.wallet, ctx.account, &mut ctx.store_conn)
            .expect("the fixture store opens");
        store
            .take_transaction_for_broadcast(state, MigrationTransferId::new(id))
            .map(|_| ())
    }

    /// THE DELIVERY LANE'S ERROR CLASSIFICATION. `MIGRATION_PROVING_UNAVAILABLE` is a STABLE FFI
    /// prefix — the Swift layer routes it to `ZcashError.migrationProvingUnavailable` and shows a
    /// different, actionable message for it — so which broadcast-seam failures carry it is part of
    /// the contract, not a detail of the message text.
    ///
    /// The pre-drive serve path prefixed exactly the two failures that meant "this stored artifact
    /// cannot be turned into servable bytes right now" (the PCZT would not re-parse; it would not
    /// extract) and left the "which row did you name" failures bare (unknown id, not `Proved`).
    /// Routing the lane through the store's seam must not silently reclassify either class: the
    /// same failures now arrive as `Error::Finalize` and `Error::NotProved` respectively, and must
    /// come out the same way. Both variants here are REAL ones from the store, since the error
    /// type is `#[non_exhaustive]` and cannot be constructed.
    #[test]
    fn broadcast_seam_error_keeps_the_proving_unavailable_prefix_contract() {
        let (path, account) = init_delivery_fixture("zcashlc_seam_error_class");
        let id = MigrationTransferId::new(0);
        let row = |state: MigrationTxState| {
            custom_state(
                MigrationStatus::InProgress,
                vec![provable_tx_row(
                    0,
                    MigrationTxKind::Transfer { crossing: 0 },
                    3_600_000,
                    4_000_000,
                    Some(3_500_000),
                    state,
                )],
            )
        };

        // A `Proved` row whose artifact will not finalize: the class the old path prefixed.
        let unfinalizable = take_for_broadcast(&path, &account, &row(MigrationTxState::Proved), 0)
            .expect_err("the fixture artifact carries no proofs, so it cannot be finalized");
        assert!(
            matches!(unfinalizable, PoolMigrationStoreError::Finalize(_)),
            "the fixture must produce the finalize class, got: {unfinalizable:?}"
        );
        let classified = broadcast_seam_error(id, unfinalizable).to_string();
        assert!(
            classified.starts_with(PROVING_UNAVAILABLE_PREFIX),
            "an unfinalizable artifact must stay on the proving-unavailable route, got: \
             {classified}"
        );

        // A row that is not `Proved`: the class the old path left bare.
        let not_proved = take_for_broadcast(&path, &account, &row(MigrationTxState::Signed), 0)
            .expect_err("an unproved row must not be finalizable");
        assert!(
            matches!(not_proved, PoolMigrationStoreError::NotProved(_)),
            "the fixture must produce the lifecycle class, got: {not_proved:?}"
        );
        let classified = broadcast_seam_error(id, not_proved).to_string();
        assert!(
            !classified.starts_with(PROVING_UNAVAILABLE_PREFIX),
            "a lifecycle refusal must NOT claim proving is unavailable, got: {classified}"
        );
        assert!(
            classified.contains("is not proved"),
            "the bare error must still carry the store's detail, got: {classified}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// THE ATOMIC BROADCAST SEAM. The delivery executor does not re-parse the stored PCZT and
    /// extract it just to recover a txid, throwing the transaction away: it calls the store's
    /// `PoolMigrations::take_transaction_for_broadcast`, which finalizes, extracts, and records the
    /// transaction in the WALLET's own tables in one database transaction with handing the bytes
    /// out — so the wallet's record binds at the broadcast ATTEMPT and a platform can never hold
    /// broadcastable bytes the wallet knows nothing about.
    ///
    /// What this fixture can pin is that the executor REACHES that seam and that the seam is
    /// all-or-nothing. Extraction re-verifies the proofs and signatures it assembles, so a
    /// SUCCESSFUL serve needs a genuinely proven artifact — real Orchard proving over a real
    /// commitment tree, which upstream covers in its `expensive-tests` chain simulation and no
    /// hand-built state here can stand in for. The refusal path is the same seam, and it must
    /// leave the wallet exactly as it found it.
    #[test]
    fn take_broadcast_transaction_serves_a_proved_row_through_the_broadcast_seam() {
        let (path, account) = init_delivery_fixture("zcashlc_next_due_seam");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let state = custom_state(
            MigrationStatus::InProgress,
            vec![provable_tx_row(
                0,
                MigrationTxKind::Transfer { crossing: 0 },
                3_600_000,
                4_000_000,
                Some(3_500_000),
                MigrationTxState::Proved,
            )],
        );
        store_fixture_state(&path, &account, &state);
        assert_eq!(
            wallet_transaction_records(&path),
            0,
            "no transaction is recorded before the executor runs"
        );

        // The executor delegates to the seam, whose verification refuses this fixture's unproven
        // artifact. The message is the STORE's, which is how this pins the delegation: a
        // hand-rolled extract failure could not name the store at all.
        let err = take_broadcast_error(path_bytes, &account, 0);
        assert!(
            err.contains("taking migration transaction 0 for broadcast failed")
                && err.contains("pool-migration store"),
            "the executor must fail THROUGH the store's seam, got: {err}"
        );
        // ...and over the FFI it keeps the stable prefix the pre-drive serve path put on exactly
        // this failure class, so the Swift layer still routes it to its own error rather than the
        // lane's generic one (the classification itself is pinned by
        // `broadcast_seam_error_keeps_the_proving_unavailable_prefix_contract`).
        assert!(
            err.starts_with(PROVING_UNAVAILABLE_PREFIX),
            "the executor must keep classifying an unfinalizable artifact as \
             proving-unavailable, got: {err}"
        );
        assert_eq!(
            wallet_transaction_records(&path),
            0,
            "a refused finalization must record nothing: the seam is all-or-nothing"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// THE STALENESS GUARD. The executor takes the id it was given and never re-asks the engine
    /// whether that id is still the right one — so what protects it from acting on an instruction
    /// that has gone stale is the seam's own refusal of a row that is not `Proved`. Serving an
    /// unproved row is refused, BARE (no proving-unavailable prefix: this is a question about
    /// WHICH row was named, not about the artifact), and leaves the wallet untouched.
    ///
    /// The same refusal is what makes a stale BROADCAST instruction safe: the engine re-offers
    /// un-discharged work on the next crank, so a caller that lost the race simply advances again.
    #[test]
    fn take_broadcast_transaction_refuses_a_row_that_is_not_proved() {
        let (path, account) = init_delivery_fixture("zcashlc_take_broadcast_stale");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let unproved = custom_state(
            MigrationStatus::InProgress,
            vec![provable_tx_row(
                0,
                MigrationTxKind::Transfer { crossing: 0 },
                3_600_000,
                4_000_000,
                Some(3_500_000),
                MigrationTxState::Signed,
            )],
        );
        store_fixture_state(&path, &account, &unproved);

        let err = take_broadcast_error(path_bytes, &account, 0);
        assert!(
            err.contains("is not proved"),
            "the seam must name the lifecycle problem, got: {err}"
        );
        assert!(
            !err.starts_with(PROVING_UNAVAILABLE_PREFIX),
            "a lifecycle refusal must not claim proving is unavailable, got: {err}"
        );
        assert_eq!(
            wallet_transaction_records(&path),
            0,
            "the refused row leaves no wallet record behind"
        );

        // An id the stored run does not contain at all is refused before the seam is even reached.
        let err = take_broadcast_error(path_bytes, &account, 99);
        assert!(
            err.contains("no migration transaction with id 99"),
            "an unknown id must be named, got: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// THE RE-SPREAD REGRESSION. A wallet that slept through several scheduled broadcasts and
    /// wakes to deliver must have its backlog RE-SPREAD before anything is served: ZIP 318
    /// releases at most one overdue transfer immediately and defers the rest by the lag, drawn
    /// inter-broadcast gaps intact. That re-spread fires ONLY inside `advance_migration` — which
    /// is exactly why the delivery session's FIRST call is the advance, and the executor that
    /// follows is told what to serve rather than choosing for itself.
    ///
    /// One advance over a three-transfer backlog: the released row lands at the SCANNED target
    /// (release means executable — a proof rests on scanned chain data), and it is the only row
    /// servable there afterwards; the other two moved later by the same lag, so the gap between
    /// them survives unchanged.
    ///
    /// The backlog is `Signed`, so the released row comes back as a schedule-due `Prove` target
    /// rather than a BROADCAST instruction. The trigger, the release and the deferral are the
    /// drive's and are identical for its `Prove` and `Broadcast` steps; what this pins is that the
    /// SESSION-OPENING ADVANCE is what fires them, and a `Proved` backlog would need a genuinely
    /// proven artifact to get past the broadcast seam's verification (see
    /// [`take_broadcast_transaction_serves_a_proved_row_through_the_broadcast_seam`]).
    #[test]
    fn advance_step_re_spreads_a_slept_through_backlog_before_serving() {
        let (path, account) = init_delivery_fixture("zcashlc_next_due_respread");
        let path_bytes = path.to_str().unwrap().as_bytes();
        // Three transfers, all scheduled far below the scanned target (3,600,001) — the wallet
        // slept through the whole window. Their drawn gaps are 100 and 200 blocks.
        let transfer = |id: u32, scheduled: u32| {
            provable_tx_row(
                id,
                MigrationTxKind::Transfer {
                    crossing: id as usize,
                },
                scheduled,
                4_000_000,
                Some(3_400_000),
                MigrationTxState::Signed,
            )
        };
        let state = custom_state(
            MigrationStatus::InProgress,
            vec![
                transfer(0, 3_500_000),
                transfer(1, 3_500_100),
                transfer(2, 3_500_300),
            ],
        );
        // The counterfactual the drive fixes: every row of the backlog starts due at the scanned
        // target, so a selector-served lane would hand them out back-to-back.
        assert_eq!(
            state
                .transactions()
                .iter()
                .filter(|t| u32::from(t.scheduled_height()) <= 3_600_001)
                .count(),
            3,
            "the fixture backlog must start fully due"
        );
        store_fixture_state(&path, &account, &state);

        let (step, _id, targets, ..) = read_advance_step(path_bytes, &account);
        assert_eq!(
            step, ZCASHLC_ADVANCE_STEP_PROVE,
            "the released row is offered for proving"
        );
        assert_eq!(
            targets
                .iter()
                .filter(|t| t.5)
                .map(|t| t.0)
                .collect::<Vec<_>>(),
            vec![0],
            "exactly the most overdue row is released as schedule-due, got {targets:?}"
        );

        let stored = read_fixture_state(&path, &account);
        assert_eq!(
            stored
                .transactions()
                .iter()
                .filter(|t| u32::from(t.scheduled_height()) <= 3_600_001)
                .count(),
            1,
            "exactly one row may be servable at the scanned target after the re-spread"
        );
        assert_eq!(
            stored_scheduled_height(&stored, 0),
            3_600_001,
            "the release lands at the scanned target, where the wallet can execute it"
        );
        // The lag is 3,600,001 - 3,500,000 = 100,001 blocks; every deferred row moves by it.
        assert_eq!(
            stored_scheduled_height(&stored, 1),
            3_600_101,
            "the first deferred row moves later by the full lag"
        );
        assert_eq!(
            stored_scheduled_height(&stored, 2),
            3_600_301,
            "the second deferred row moves later by the same lag"
        );
        assert_eq!(
            stored_scheduled_height(&stored, 2) - stored_scheduled_height(&stored, 1),
            200,
            "the drawn inter-broadcast gap survives the wallet's absence unchanged"
        );
        let _ = std::fs::remove_file(&path);
    }

    // ----- the txid seam (the prove return + `zcashlc_migration_take_preparation_by_txid`) -----
    //
    // A proved preparation is a complete PCZT whose submission is the platform's ORDINARY path
    // (preparations are ZIP 318-exempt, and the engine's contract is that a preparation is
    // broadcast as soon as it is proved), so the prove executor NAMES the preparations it proved
    // and the accessor hands each one back by txid. The accessor is the take seam itself — the
    // wallet's record binds at retrieval — so these fixtures inherit the delivery lane's limits
    // exactly: what is reachable here is that the seam is REACHED and that every refusal is
    // all-or-nothing.

    /// One retrieval over the FFI, with the DTO copied out and freed: the engine transfer id, the
    /// served txid, and the served (finalized transaction) bytes. Asserts success — a NULL is an
    /// error to be read with [`take_preparation_error`] instead.
    fn take_preparation_by_txid(
        path_bytes: &[u8],
        account: &[u8; 16],
        txid: [u8; 32],
    ) -> (u32, [u8; 32], Vec<u8>) {
        let ptr = unsafe {
            zcashlc_migration_take_preparation_by_txid(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
                txid.as_ptr(),
            )
        };
        assert!(
            !ptr.is_null(),
            "the preparation accessor must not error: {:?}",
            ffi_helpers::error_handling::error_message()
        );
        let prepared = unsafe { &*ptr };
        let out = (
            prepared.id,
            prepared.txid,
            unsafe { slice_or_empty(prepared.pczt, prepared.pczt_len) }.to_vec(),
        );
        unsafe { zcashlc_free_migration_prepared_transfer(ptr) };
        out
    }

    /// The preparation accessor's refusal message: asserts the NULL return and takes the last
    /// error.
    fn take_preparation_error(path_bytes: &[u8], account: &[u8; 16], txid: [u8; 32]) -> String {
        let ptr = unsafe {
            zcashlc_migration_take_preparation_by_txid(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
                txid.as_ptr(),
            )
        };
        assert!(
            ptr.is_null(),
            "the accessor was expected to refuse txid {}",
            TxId::from_bytes(txid)
        );
        ffi_helpers::error_handling::take_last_error()
            .expect("the refusal must record a last-error")
            .to_string()
    }

    /// The fixture txid [`test_transaction_from_parts`] stamps on row `id`.
    fn fixture_txid(id: u32) -> [u8; 32] {
        [id as u8; 32]
    }

    /// THE PROVE RETURN NAMES PREPARATIONS ONLY. A mixed batch proves both kinds and the total
    /// counts both, but only the preparations' txids come back: appearing in that list MEANS
    /// "retrievable through the accessor", and a transfer never is — it is delivered by the
    /// drive's broadcast instruction alone.
    #[test]
    fn prove_outcome_names_the_proved_preparations_and_no_transfer() {
        let (path, account, mut ctx) = sweep_fixture_ctx("zcashlc_prove_outcome_mixed", 5_000);
        let anchor = h(4_000);
        let mut state = custom_state(
            MigrationStatus::InProgress,
            vec![
                provable_tx_row(
                    0,
                    MigrationTxKind::Preparation { layer: 0, index: 0 },
                    4_000,
                    10_000,
                    None,
                    MigrationTxState::Signed,
                ),
                provable_tx_row(
                    1,
                    MigrationTxKind::Transfer { crossing: 0 },
                    4_000,
                    10_000,
                    Some(1_440),
                    MigrationTxState::Signed,
                ),
            ],
        );
        store_fixture_state(&path, &account, &state);

        let mut prover = RecordingProver { calls: Vec::new() };
        let ids = prove_instruction(&state);
        assert_eq!(ids.len(), 2, "both rows are named by the instruction");
        // The production dispatch ([`prove_one`]): a preparation proves against the resolved
        // anchor, a transfer against its persisted boundary.
        let outcome = prove_named_rows(&mut ctx, &mut state, &ids, None, |_ctx, state, id| {
            let is_preparation = state
                .transactions()
                .iter()
                .find(|t| t.id() == id)
                .is_some_and(|t| matches!(t.kind(), MigrationTxKind::Preparation { .. }));
            let preparation_anchor = is_preparation.then_some(anchor);
            Ok(prove_due_for_test(&mut prover, state, id, preparation_anchor)?.is_some())
        })
        .expect("the mixed sweep must not fail");

        assert_eq!(
            prover.calls,
            vec![
                ProveCall::Preparation(anchor),
                ProveCall::Transfer(h(1_440))
            ],
            "both kinds must actually have been proved"
        );
        assert_eq!(
            outcome,
            ProveOutcome {
                total_proved: 2,
                preparation_txids: vec![fixture_txid(0)],
            },
            "the total counts both kinds; the txids name the preparation alone"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The prove return's MARSHALING: the outcome crosses as a DTO whose txid array is a heap
    /// `[u8; 32]` buffer the caller frees, and the empty outcome is a valid (non-NULL) DTO rather
    /// than a sentinel — "nothing was provable right now" is an ordinary answer.
    #[test]
    fn prove_outcome_marshals_its_txid_buffer_and_frees() {
        let round_trip = |outcome: ProveOutcome| {
            let ptr = FfiMigrationProveOutcome::from_outcome(outcome);
            assert!(!ptr.is_null(), "the outcome DTO is always populated");
            let dto = unsafe { &*ptr };
            let read = (
                dto.total_proved,
                unsafe { slice_or_empty(dto.preparation_txids, dto.preparation_txids_len) }
                    .to_vec(),
            );
            unsafe { zcashlc_free_migration_prove_outcome(ptr) };
            read
        };

        assert_eq!(
            round_trip(ProveOutcome::default()),
            (0, Vec::new()),
            "the empty outcome marshals as a real DTO, not an error sentinel"
        );
        assert_eq!(
            round_trip(ProveOutcome {
                total_proved: 3,
                preparation_txids: vec![fixture_txid(1), fixture_txid(2)],
            }),
            (3, vec![fixture_txid(1), fixture_txid(2)]),
            "the total and every txid survive the crossing, in order"
        );
        // Freeing a null pointer is a no-op, as every free function in this module allows.
        unsafe { zcashlc_free_migration_prove_outcome(std::ptr::null_mut()) };
    }

    /// With no stored run there is nothing to prove, and the executor says so with an EMPTY
    /// outcome rather than an error: the benign answer is a DTO, and NULL now means only failure.
    #[test]
    fn prove_transactions_without_a_stored_run_returns_an_empty_outcome() {
        let path = init_fixture_db("zcashlc_prove_outcome_no_run");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        set_fixture_tip(path_bytes);

        let ids = [0u32];
        let ptr = unsafe {
            zcashlc_migration_prove_transactions(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
                ids.as_ptr(),
                ids.len(),
                1,
            )
        };
        assert!(
            !ptr.is_null(),
            "nothing to prove is not an error: {:?}",
            ffi_helpers::error_handling::error_message()
        );
        let dto = unsafe { &*ptr };
        assert_eq!(dto.total_proved, 0, "no run means nothing was proved");
        assert_eq!(
            dto.preparation_txids_len, 0,
            "and nothing is offered for retrieval"
        );
        unsafe { zcashlc_free_migration_prove_outcome(ptr) };
        let _ = std::fs::remove_file(&path);
    }

    /// THE ACCESSOR IS THE TAKE SEAM. Retrieving a preparation is not a byte read of the stored
    /// artifact: it resolves txid -> row and goes straight through
    /// `PoolMigrations::take_transaction_for_broadcast` ([`serve_for_broadcast`]), which finalizes,
    /// extracts and records the transaction in the WALLET's own tables in one database transaction
    /// with handing the bytes out — so the record binds at retrieval and a crashed consumer
    /// re-retrieves the same bytes over the same record.
    ///
    /// As with the delivery lane, a SUCCESSFUL serve needs a genuinely proven artifact (extraction
    /// re-verifies the proofs), which no hand-built fixture can stand in for; what is reachable
    /// here is that the accessor REACHES the seam — the message is the STORE's — and that the
    /// refusal leaves the wallet exactly as it found it.
    #[test]
    fn take_preparation_by_txid_serves_through_the_broadcast_seam() {
        let (path, account) = init_delivery_fixture("zcashlc_take_prep_seam");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let state = custom_state(
            MigrationStatus::InProgress,
            vec![provable_tx_row(
                0,
                MigrationTxKind::Preparation { layer: 0, index: 0 },
                3_600_000,
                4_000_000,
                None,
                MigrationTxState::Proved,
            )],
        );
        store_fixture_state(&path, &account, &state);
        assert_eq!(
            wallet_transaction_records(&path),
            0,
            "no transaction is recorded before the accessor runs"
        );

        let err = take_preparation_error(path_bytes, &account, fixture_txid(0));
        assert!(
            err.contains("taking migration transaction 0 for broadcast failed")
                && err.contains("pool-migration store"),
            "the accessor must fail THROUGH the store's seam, got: {err}"
        );
        assert!(
            err.starts_with(PROVING_UNAVAILABLE_PREFIX),
            "an unfinalizable artifact keeps the proving-unavailable route here too, got: {err}"
        );
        assert_eq!(
            wallet_transaction_records(&path),
            0,
            "a refused finalization must record nothing: the seam is all-or-nothing"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// THE PREPARATION GATE. A transfer's txid is refused even when the row is `Proved` and would
    /// serve perfectly well through the same seam: transfers are served by the drive's broadcast
    /// instruction alone, and this accessor exists only for the preparations the prove return
    /// names. The refusal is BARE — it is a question about WHICH row was named, not about whether
    /// an artifact can be made servable — and it is decided before the seam, so nothing is
    /// recorded.
    #[test]
    fn take_preparation_by_txid_refuses_a_transfer_txid() {
        let (path, account) = init_delivery_fixture("zcashlc_take_prep_gate");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let state = custom_state(
            MigrationStatus::InProgress,
            vec![provable_tx_row(
                0,
                MigrationTxKind::Transfer { crossing: 0 },
                3_600_000,
                4_000_000,
                Some(3_500_000),
                MigrationTxState::Proved,
            )],
        );
        store_fixture_state(&path, &account, &state);

        let err = take_preparation_error(path_bytes, &account, fixture_txid(0));
        assert!(
            err.contains("transfers are served by the drive's broadcast instruction alone"),
            "the gate must state the ruling, got: {err}"
        );
        assert!(
            !err.starts_with(PROVING_UNAVAILABLE_PREFIX),
            "the gate is not a claim about the artifact, got: {err}"
        );
        assert_eq!(
            wallet_transaction_records(&path),
            0,
            "the gated row must never reach the seam, so nothing is recorded"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// THE READINESS GATE, THE UNKNOWN TXID, AND THE NULL POINTER. A preparation that is not
    /// `Proved` is refused by the seam itself — the same staleness guard the delivery executor
    /// relies on, bare and recording nothing — a txid the stored run does not carry is refused,
    /// bare, before the seam is reached, and a null `txid_ptr` is refused before anything is read.
    #[test]
    fn take_preparation_by_txid_refuses_an_unproved_unknown_or_null_txid() {
        let (path, account) = init_delivery_fixture("zcashlc_take_prep_unready");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let state = custom_state(
            MigrationStatus::InProgress,
            vec![provable_tx_row(
                0,
                MigrationTxKind::Preparation { layer: 0, index: 0 },
                3_600_000,
                4_000_000,
                None,
                MigrationTxState::Signed,
            )],
        );
        store_fixture_state(&path, &account, &state);

        let err = take_preparation_error(path_bytes, &account, fixture_txid(0));
        assert!(
            err.contains("is not proved"),
            "the seam must name the lifecycle problem, got: {err}"
        );
        assert!(
            !err.starts_with(PROVING_UNAVAILABLE_PREFIX),
            "a lifecycle refusal must not claim proving is unavailable, got: {err}"
        );

        // A NULL txid pointer is refused, not read: `slice_or_empty` tolerates NULL only at
        // length 0, so reading 32 bytes from one would be undefined behaviour at a public C ABI
        // symbol.
        let ptr = unsafe {
            zcashlc_migration_take_preparation_by_txid(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
                std::ptr::null(),
            )
        };
        assert!(ptr.is_null(), "a null txid pointer must be refused");
        let err = ffi_helpers::error_handling::take_last_error()
            .expect("the refusal must record a last-error")
            .to_string();
        assert!(
            err.contains("txid_ptr is null"),
            "the null refusal must name the pointer, got: {err}"
        );

        let unknown = fixture_txid(99);
        let err = take_preparation_error(path_bytes, &account, unknown);
        assert!(
            err.contains(&format!(
                "no migration transaction with txid {}",
                TxId::from_bytes(unknown)
            )),
            "an unknown txid must be named, got: {err}"
        );
        assert!(
            !err.starts_with(PROVING_UNAVAILABLE_PREFIX),
            "an unknown txid says nothing about any artifact, got: {err}"
        );
        assert_eq!(
            wallet_transaction_records(&path),
            0,
            "neither refusal leaves a wallet record behind"
        );
        let _ = std::fs::remove_file(&path);
    }

    // ----- terminal broadcast rejections (`zcashlc_migration_record_transfer_result` tags 2/3) -----

    fn record_result(
        path_bytes: &[u8],
        account: &[u8; 16],
        transfer_id: u32,
        result_tag: i32,
    ) -> bool {
        unsafe {
            zcashlc_migration_record_transfer_result(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
                transfer_id,
                result_tag,
                std::ptr::null(),
            )
        }
    }

    /// A terminal rejection against a MINED row leaves it mined (chain inclusion outranks stale
    /// rejection evidence); an unknown id records nothing. Both outcomes are consumed.
    #[test]
    fn record_transfer_result_terminal_tag_is_a_no_op_on_mined_and_unknown_rows() {
        let path = init_fixture_db("zcashlc_record_result_noop");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        let state = test_state(
            MigrationStatus::InProgress,
            &[],
            &[MINED, MigrationTxState::Signed],
            3_499_000,
            4_000_000,
        );
        store_fixture_state(&path, &account, &state);

        assert!(
            record_result(path_bytes, &account, 0, 2),
            "a stale rejection against a mined row is consumed"
        );
        assert!(
            record_result(path_bytes, &account, 9, 3),
            "a rejection naming an unknown id is consumed"
        );
        let stored = read_fixture_state(&path, &account);
        assert!(
            matches!(
                stored.transactions()[0].state(),
                MigrationTxState::Mined { .. }
            ),
            "the mined row must stay mined"
        );
        assert!(
            matches!(stored.transactions()[1].state(), MigrationTxState::Signed),
            "the unrelated row must be untouched"
        );
        let _ = std::fs::remove_file(&path);
    }

    // ----- pure-read rewire parity (RO-T2) -----

    /// Parity harness for the pure-read rewire: on a freshly initialized wallet database (no
    /// accounts, chain tip set) the pure read wrappers answer exactly what they answer today.
    /// Written BEFORE the rewire (green against the reconcile-first bodies) and kept green after
    /// it.
    #[test]
    fn pure_read_wrappers_fresh_db_answers_are_stable() {
        let path = std::env::temp_dir().join(format!(
            "zcashlc_pure_read_parity_{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let path_bytes = path.to_str().unwrap().as_bytes();
        let init = unsafe {
            crate::zcashlc_init_data_database(
                path_bytes.as_ptr(),
                path_bytes.len(),
                std::ptr::null(),
                0,
                NETWORK_ID_MAINNET,
            )
        };
        assert!(init >= 0, "wallet-db initialization must succeed");
        assert!(unsafe {
            crate::zcashlc_update_chain_tip(
                path_bytes.as_ptr(),
                path_bytes.len(),
                3_000_000,
                NETWORK_ID_MAINNET,
            )
        });
        let account = [7u8; 16];
        // Unknown account: the store constructor reports AccountUnknown down every one of these
        // paths, and each wrapper coerces per ITS OWN error convention — pinned here verbatim.
        let overdue = unsafe {
            zcashlc_migration_has_overdue_transfers(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
                -1,
            )
        };
        assert!(!overdue, "error path coerces to false");
        let invalid = unsafe {
            zcashlc_migration_has_invalid_transfers(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert!(!invalid, "error path coerces to false");
        let statuses = unsafe {
            zcashlc_migration_transaction_statuses(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert!(statuses.is_null(), "error path reports null");
        let progress = unsafe {
            zcashlc_migration_progress(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert!(progress.is_null(), "error path reports null");
        let wakeups = unsafe {
            zcashlc_migration_sync_wakeups(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert!(wakeups.is_null(), "error path reports null");
        let _ = std::fs::remove_file(&path);
    }
}
