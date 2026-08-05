//! FFI over the final Orchard→Ironwood pool-migration engine
//! ([`zcash_pool_migration`] + the `zcash_client_sqlite::pool_migration` store).
//!
//! The engine is a set of free functions over traits — [`crate::migration_engine::Backend`] wires
//! this SDK's wallet database (and the account-keyed migration store living inside it) into them;
//! [`crate::migration_finalize`] proves transactions as soon as they become provable (ZIP 374
//! deferred anchors/witnesses, resolved through the upstream prover — transfers against their
//! drawn ZIP 318 boundary anchor, preparations against the wallet's scanned tip; see its module
//! doc), driven by [`zcashlc_migration_prove_pending`] rather than by the broadcast path;
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
//! Heap ownership: every function that returns a `*mut Ffi*` (or a [`ffi::BoxedSlice`]) transfers
//! ownership to the caller, who must free it with the matching `zcashlc_free_migration_*` (or
//! `zcashlc_free_boxed_slice`) function.

use std::collections::HashSet;
use std::ffi::{CStr, CString, OsStr};
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::slice;

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
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
    BLOCKS_PER_HOUR, BlockHeight, Network, NetworkConstants, NetworkUpgrade, Parameters,
};
use zcash_protocol::value::Zatoshis;
use zcash_protocol::{PoolType, ShieldedPool, TxId};

use zcash_pool_migration::engine::{
    self, MigrationBackend, MigrationPlan, MigrationState, MigrationStatus, MigrationTransaction,
    MigrationTransferId, MigrationTxKind, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
};
use zcash_pool_migration::satisfiability::{
    AdvanceConfig, DuenessTargets, ReorgSettleDepth, ReplanThreshold, UnsatisfiableKind,
    advance_migration,
};
use zcash_pool_migration::scheduling::{WakeupParams, WakeupScheduleError};
use zcash_pool_migration::signing_rounds::{
    NextFit, PREPARATION_ACTIONS, PlannedTx, SigningRoundBudget, SigningRoundStrategy,
    TRANSFER_ACTIONS, action_weight,
};
use zcash_pool_migration::state::{AdvanceStep, Blocker, NextAction, TransactionStatus};
use zcash_pool_migration::wallet::WalletMigrationProver;

use crate::migration_engine::{Backend, MigrationWallet};
use crate::migration_finalize;
use crate::migration_plan_cache;
use crate::{
    NETWORK_ID_MAINNET, NETWORK_ID_TESTNET, NetworkParams, account_uuid_from_bytes, ffi,
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
/// Every [`MigrationState`] query (`next_provable`, `next_broadcastable`, `expired_transactions`)
/// is defined over this height, never the raw tip — see [`CallCtx::target`], the primary way
/// callers reach this from a live wallet handle. Exposed as a pure function too for the callers
/// (like the estimated-tip due-ness split) that already hold a `tip` value rather than a
/// [`CallCtx`].
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
    /// [`MigrationState`] query (`next_provable`, `next_broadcastable`, `expired_transactions`,
    /// `commit_preparation`, `build_preparation_unsigned`) must use this, never `tip()` directly.
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

/// Loads the stored run with its `Broadcast` transactions promoted to `Mined` wherever the
/// wallet's scan has since seen them, persisting once if anything changed. `None` means the
/// account has never stored a migration at all.
///
/// The promotion itself is the ENGINE's — [`PoolMigrationRead::mined_height`], the same query
/// `advance_migration` sweeps with, bounded by the wallet's fully-scanned height rather than by
/// the chain tip `WalletRead::get_tx_height` uses. What remains SDK-side is only WHEN to ask: the
/// drive path gets the promotion inside `advance_migration` and does not call this, while the
/// read-only entry points (progress, statuses, the delivery queries) run it so a standalone read
/// is not answered from a state the wallet's own scan has already moved past.
///
/// The load is [`Backend::latest_migration`], NOT the pending-only `get_migration`: a finished or
/// cancelled run must stay READABLE — `zcashlc_migration_transaction_statuses` lists the
/// transactions it mined, and nothing else would ever surface them again — even though nothing
/// will drive it further. Every caller keeps its own `is_terminal()` branch for what a terminal
/// run means to its particular answer, and the reconciliation below never touches one: there is
/// nothing left to promote in a run the engine has already settled.
fn reconcile_mined(ctx: &mut CallCtx) -> anyhow::Result<Option<MigrationState>> {
    let mut backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?;
    let Some(mut state) = backend.latest_migration()? else {
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
        if let Some(height) = backend.mined_height(txid)? {
            state.mark_mined(id, height);
            changed = true;
        }
    }
    if changed {
        backend.replace_migration(&state)?;
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
    let backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?;
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
/// - Amounts are what each transfer CROSSES, straight from the engine's `crossing_values()`:
///   index-aligned with `funding_notes()` and with `schedule()`, and already net of the fee buffer
///   that pays each transfer's own fee. Serving the funding note instead would overstate every row
///   by one transfer fee and show a value that is not a round denomination the user approved.
/// - The engine numbers every preparation transaction first, then transfers in `schedule()`
///   order, so transfer `i`'s real committed id is `prep_tx_count + i`.
/// - The sort makes the platform's row order chronological: ZIP 318 SHUFFLE deliberately makes
///   funding-note order differ from broadcast order.
fn schedule_rows(
    crossing_values: &[Zatoshis],
    schedule: &[zcash_pool_migration::scheduling::Schedule],
    prep_tx_count: u32,
) -> anyhow::Result<Vec<(MigrationTransferId, Zatoshis, BlockHeight, BlockHeight)>> {
    if crossing_values.len() != schedule.len() {
        return Err(anyhow!(
            "migration plan invariant violated: {} crossing values but {} schedule entries",
            crossing_values.len(),
            schedule.len()
        ));
    }
    let mut rows: Vec<_> = crossing_values
        .iter()
        .zip(schedule.iter())
        .enumerate()
        .map(|(i, (crossing, entry))| {
            (
                MigrationTransferId::new(prep_tx_count + i as u32),
                *crossing,
                entry.broadcast_height(),
                entry.expiry_height(),
            )
        })
        .collect();
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

/// The number of preparation transactions a plan commits (across all layers) — the id offset of
/// the first transfer.
fn prep_tx_count(plan: &MigrationPlan) -> u32 {
    plan.preparation()
        .layers()
        .iter()
        .map(|layer| layer.len() as u32)
        .sum()
}

/// The plan's preparation transactions as schedule-preview rows — the PROPOSE-path derivation,
/// read-only over a not-yet-committed [`MigrationPlan`], mirroring EXACTLY how
/// `zcash_pool_migration::engine::commit_preparation`'s `Committer::build_preparation_layers`
/// will number and schedule these once committed: ids are assigned layer-major/index-minor over
/// `plan.preparation().layers()` (preparations before any transfer — the same traversal
/// [`prep_tx_count`] sums), `depends_on` is the WHOLE preceding layer's ids (layer 0 depends on
/// nothing — the commit path does not narrow this to the specific producer(s) a layer's inputs
/// spend), and `broadcast_height` is `plan.prep_schedule()[layer][index]`, index-aligned with
/// `layers()`. Do NOT invent a finer-grained dependency from `PrepInput`; the commit path itself
/// does not.
fn preparation_steps_from_plan(
    plan: &MigrationPlan,
) -> anyhow::Result<Vec<FfiMigrationPreparationStep>> {
    let layers = plan.preparation().layers();
    let schedule = plan.prep_schedule();
    if layers.len() != schedule.len() {
        return Err(anyhow!(
            "migration plan invariant violated: {} preparation layers but {} schedule layers",
            layers.len(),
            schedule.len()
        ));
    }
    let mut next_id: u32 = 0;
    let mut prev_layer_ids: Vec<u32> = Vec::new();
    let mut steps = Vec::new();
    for (layer_idx, (layer, heights)) in layers.iter().zip(schedule.iter()).enumerate() {
        if layer.len() != heights.len() {
            return Err(anyhow!(
                "migration plan invariant violated: preparation layer {layer_idx} has {} \
                 transactions but {} scheduled heights",
                layer.len(),
                heights.len()
            ));
        }
        let mut this_layer_ids = Vec::with_capacity(layer.len());
        for (index, height) in heights.iter().enumerate() {
            let id = next_id;
            next_id += 1;
            this_layer_ids.push(id);
            let depends_on = if layer_idx == 0 {
                Vec::new()
            } else {
                prev_layer_ids.clone()
            };
            let (depends_on, depends_on_len) = ptr_from_vec(depends_on);
            steps.push(FfiMigrationPreparationStep {
                id,
                layer: layer_idx as u32,
                index: index as u32,
                broadcast_height: i64::from(u32::from(*height)),
                depends_on,
                depends_on_len,
            });
        }
        prev_layer_ids = this_layer_ids;
    }
    Ok(steps)
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
    let rows = schedule_rows(plan.crossing_values(), plan.schedule(), prep_tx_count(plan))?;
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
/// and is durable, so there is nothing left the handle could protect. `sign` picks the
/// `commit_preparation` / `build_preparation_unsigned` variant. A terminal stored run (a
/// completed or cancelled previous migration) is REPLACED — that is the sequential-runs path.
/// When the cached preview came through the immediate lane, the committed transfers' scheduled
/// heights are rewritten to the commit tip (everything due at once; preparation mining order
/// still gates transfers via their dependencies).
fn commit_or_resume(
    ctx: &mut CallCtx,
    usk: Option<zcash_keys::keys::UnifiedSpendingKey>,
    unsigned_out: bool,
    plan_handle: migration_plan_cache::PlanHandle,
) -> anyhow::Result<(MigrationState, Vec<(MigrationTransferId, Vec<u8>, u32)>)> {
    {
        let backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?;
        if let Some(state) = backend.get_migration()? {
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
    let mut backend = Backend::new(&ctx.wallet, ctx.account, usk, &mut ctx.store_conn)?;
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
        let state = engine::commit_preparation(
            &ctx.network,
            target,
            &mut backend,
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
/// "re-propose" signal).
fn map_commit_err(e: engine::CommitError<anyhow::Error>) -> anyhow::Error {
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
/// the migration, so the remaining balance must be re-planned via the restart lane. Everything
/// else is a hard error carrying the engine's detail.
fn map_rebuild_err(e: engine::RebuildError<anyhow::Error>) -> anyhow::Error {
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

/// Serves an already-`Proved` row's stored artifact as `(proven pczt bytes, txid)`. A pure read:
/// the bytes were persisted when the row was proved, so a retry after a failed broadcast attempt
/// re-serves exactly the same transaction (same anchor, same txid) rather than re-proving.
fn serve_proved(
    state: &MigrationState,
    id: MigrationTransferId,
) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
    let tx = state
        .transactions()
        .iter()
        .find(|t| t.id() == id)
        .ok_or_else(|| anyhow!("no migration transaction with id {}", u32::from(id)))?;
    if !matches!(tx.state(), MigrationTxState::Proved) {
        return Err(anyhow!(
            "migration transaction {} is not broadcastable (state {})",
            u32::from(id),
            tx.state().as_ref()
        ));
    }
    let bytes = tx.pczt().clone();
    let pczt = pczt::Pczt::parse(&bytes)
        .map_err(|e| proving_unavailable(format!("re-parse proven pczt: {e:?}")))?;
    let (_, txid) = migration_finalize::extract_tx(pczt).map_err(proving_unavailable)?;
    Ok((bytes, txid))
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
            let fvk = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?
                .stored_orchard_fvk()?;
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
            let mut backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?;
            backend.store_proved_transaction(state, proved)?;
            Ok(true)
        }
        other => Err(anyhow!(
            "migration transaction {} cannot be proved (state {})",
            u32::from(id),
            other.as_ref()
        )),
    }
}

/// The next prove-ready row, skipping ids a sweep already found transiently unprovable.
///
/// Prove-readiness is upstream's rule, not this crate's, so the skip is expressed by asking a
/// SCRATCH clone: the skipped rows are flipped to `Proved` in the clone (with their own bytes —
/// `set_transaction_proved` then only advances the lifecycle state), which is exactly what makes
/// `next_provable` step past them. Nothing persists, and a skipped row cannot unblock a dependent
/// one, because dependency readiness is keyed on `Mined`, not `Proved`. The same trick backs
/// [`due_assuming_proving`].
fn next_provable_excluding(
    state: &MigrationState,
    target: BlockHeight,
    skip: &[MigrationTransferId],
) -> Option<MigrationTransferId> {
    state
        .transaction_statuses(DuenessTargets::at(target))
        .into_iter()
        .find(|status| {
            status.ready()
                && status.action() == Some(NextAction::Prove)
                && !skip.contains(&status.id())
        })
        .map(|status| status.id())
}

/// Proves every row that can be proved right now, persisting each, and returns how many were
/// proved.
///
/// This is the opportunistic seam: a transaction's anchor becomes witnessable long before its
/// broadcast schedule arrives, so proofs are produced as the wallet scans rather than on the
/// delivery path — by broadcast time there is nothing left to do but broadcast. A row the wallet
/// cannot prove yet (its anchor not scanned/retained) is SKIPPED, not fatal and not a reason to
/// stop: the rows behind it still prove, and the skipped row is retried by the next sweep.
///
/// `prove` is [`prove_one`] in production; tests substitute the generic
/// [`migration_finalize::prove_due_transaction`] seam with a recording/failing test prover plus a
/// fixture-store persist.
fn prove_pending_rows(
    state: &mut MigrationState,
    target: BlockHeight,
    max_proofs: Option<u32>,
    mut prove: impl FnMut(&mut MigrationState, MigrationTransferId) -> anyhow::Result<bool>,
) -> anyhow::Result<u32> {
    let mut deferred: Vec<MigrationTransferId> = Vec::new();
    let mut proved = 0;
    while let Some(id) = next_provable_excluding(state, target, &deferred) {
        // `max_proofs` caps SUCCESSFUL proofs per call so an FFI caller can chunk a sweep:
        // each proof is seconds of CPU, and a platform serializing DB access behind one
        // actor needs a seam between proofs for interactive reads to interleave. Deferred
        // (transient) rows don't count against the cap — they cost no proving time.
        if max_proofs.is_some_and(|max| proved >= max) {
            break;
        }
        if prove(state, id)? {
            // `next_provable` only offers `Signed` rows, so a successful prove must have advanced
            // this one; were that ever untrue the loop would re-select it forever, which as an FFI
            // call means a hung app. Fail loudly instead.
            let advanced = state
                .transactions()
                .iter()
                .find(|t| t.id() == id)
                .is_none_or(|t| !matches!(t.state(), MigrationTxState::Signed));
            if !advanced {
                return Err(anyhow!(
                    "migration transaction {} reported a successful prove but is still Signed",
                    u32::from(id)
                ));
            }
            proved += 1;
        } else {
            deferred.push(id);
        }
    }
    Ok(proved)
}

/// What the delivery lane has for the platform at the evaluated [`DuenessTargets`].
#[derive(Debug, PartialEq, Eq)]
enum DueOutcome {
    /// Nothing is due.
    Nothing,
    /// This row is proved and due: its stored artifact is what gets broadcast.
    Ready { id: MigrationTransferId },
    /// A transaction is due but still awaits its proof (see [`prove_pending_rows`]).
    AwaitingProof { id: MigrationTransferId },
}

// ----- estimated-tip due-ness (M2, upstream `DuenessTargets`) -----
//
// `zcashlc_migration_has_overdue_transfers` / `zcashlc_migration_next_due_transfer` /
// `zcashlc_migration_has_ready_broadcast` accept an OPTIONAL estimated chain tip (a wall-clock
// projection past the scanned tip, computed by the platform from
// `zcashlc_migration_block_rate_samples`). The estimate/scanned split is OWNED UPSTREAM now:
// `zcash_pool_migration::state::DuenessTargets` encodes the rule (the estimate may only
// ACCELERATE schedule due-ness; expiry, boundary settledness, and every destructive decision
// evaluate on the scanned target — plus the doomed-broadcast withhold, where an expiry the
// EFFECTIVE target has passed keeps a broadcast from being served without ever counting as
// expired), and the public transaction-status and advance APIs evaluate it. This module only
// converts the FFI's `estimated_tip: i64` into the estimated-target side of
// [`DuenessTargets::new`] — see [`dueness_targets`].

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

/// The delivery lane's decision, as a pure function of stored state: which row (if any) the
/// platform should broadcast now. NEVER proves.
///
/// Proving is decoupled from broadcasting (upstream's `next_provable` / `next_broadcastable`
/// split): by the time a row comes due its proof should already exist, produced by
/// [`prove_pending_rows`] as the wallet scanned. A due row that is still `Signed` is reported as
/// [`DueOutcome::AwaitingProof`] rather than proved here — the broadcast path stays free of
/// proving latency, and a platform that is not sweeping learns that it must, instead of seeing an
/// indefinite "nothing due". The chosen row's artifact is read by [`serve_proved`].
///
/// `targets` carries the scanned/estimated due-ness pair (coincident when no estimate is in
/// play) — see the section comment above [`estimated_target_from_tip`].
fn next_due(state: &MigrationState, targets: DuenessTargets) -> DueOutcome {
    if let Some(id) = next_ready_action(state, targets, NextAction::Broadcast) {
        return DueOutcome::Ready { id };
    }
    match due_assuming_proving(state, targets) {
        Some(id) => DueOutcome::AwaitingProof { id },
        None => DueOutcome::Nothing,
    }
}

/// The id [`zcashlc_migration_next_due_transfer`] WOULD serve once every outstanding
/// proof exists: the next broadcastable row after virtually proving every prove-ready `Signed` row
/// over a scratch copy — no prover runs and nothing persists (`set_transaction_proved` with the
/// row's own bytes only flips the lifecycle state). `None` when the delivery lane has nothing
/// actionable: nothing schedule-due yet, dependencies unmined, rows awaiting an external signature
/// (the signing ceremony, not the delivery lane, advances those), or everything already
/// broadcast/mined.
///
/// This is what separates "nothing is due" from "due, but its proof has not been produced yet"
/// ([`DueOutcome::AwaitingProof`]), and the queries built on it
/// ([`zcashlc_migration_has_overdue_transfers`], [`zcashlc_migration_pending_transfer_proposal`])
/// report due work whether or not its proof exists: the work exists either way, and proving is
/// [`prove_pending_rows`]' job, not the reporting path's.
///
/// `targets` carries the scanned/estimated due-ness pair (coincident when no estimate is in
/// play) — see the section comment above [`estimated_target_from_tip`].
fn due_assuming_proving(
    state: &MigrationState,
    targets: DuenessTargets,
) -> Option<MigrationTransferId> {
    if let Some(id) = next_ready_action(state, targets, NextAction::Broadcast) {
        return Some(id);
    }
    next_ready_action(state, targets, NextAction::Prove)?;
    let mut scratch = state.clone();
    while let Some(id) = next_ready_action(&scratch, targets, NextAction::Prove) {
        // The row's own bytes and its own lock owner, so this virtual proof is purely a lifecycle
        // flip: no prover runs, so no reservation is taken, and re-stating the stored token leaves
        // the scratch row's reservation exactly as the real one stands.
        let (bytes, lock_owner) = scratch
            .transactions()
            .iter()
            .find(|t| t.id() == id)
            .map(|t| (t.pczt().clone(), t.lock_owner()))
            .unwrap_or_default();
        scratch.set_transaction_proved(id, bytes, lock_owner);
    }
    next_ready_action(&scratch, targets, NextAction::Broadcast)
}

fn next_ready_action(
    state: &MigrationState,
    targets: DuenessTargets,
    action: NextAction,
) -> Option<MigrationTransferId> {
    state
        .transaction_statuses(targets)
        .into_iter()
        .find(|status| status.ready() && status.action() == Some(action))
        .map(|status| status.id())
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
pub const ZCASHLC_ADVANCE_STEP_ATTEND: u32 = 5;

/// The engine's next-step decision for the stored run (returned by
/// [`zcashlc_migration_advance_step`]) — a verbatim marshal of upstream
/// the public satisfiability advance API's [`AdvanceStep`].
#[repr(C)]
pub struct FfiMigrationAdvanceStep {
    /// The step discriminant (see the `ZCASHLC_ADVANCE_STEP_*` constants): `0` = Prove,
    /// `1` = Broadcast, `2` = Rebuild, `3` = Waiting, `4` = Complete, `5` = Attend (a
    /// transaction is marked invalid and no automatic step can advance the run — resolve
    /// out-of-band, typically by cancelling and re-planning).
    pub step: u32,
    /// The engine's raw transaction id for Prove/Broadcast/Rebuild/Attend; `0` for
    /// Waiting/Complete.
    pub id: u32,
    /// Whether the Prove step's transaction is a preparation (`true`) or a transfer (`false`).
    /// Meaningful only for `step == 0`; `false` otherwise.
    pub kind_is_preparation: bool,
    /// The preparation's layer, when `step == 0` and `kind_is_preparation`; `0` otherwise.
    pub kind_layer: u32,
    /// The preparation's index within its layer, when `step == 0` and `kind_is_preparation`; `0`
    /// otherwise.
    pub kind_index: u32,
    /// The transfer's crossing index, when `step == 0` and `!kind_is_preparation`; `0` otherwise.
    pub kind_crossing: u32,
}

impl FfiMigrationAdvanceStep {
    /// A step that names a transaction but carries no kind payload (Broadcast/Rebuild/Attend).
    fn with_id(step: u32, id: MigrationTransferId) -> *mut Self {
        Box::into_raw(Box::new(FfiMigrationAdvanceStep {
            step,
            id: u32::from(id),
            kind_is_preparation: false,
            kind_layer: 0,
            kind_index: 0,
            kind_crossing: 0,
        }))
    }

    /// A payload-free step (Waiting/Complete).
    fn bare(step: u32) -> *mut Self {
        Box::into_raw(Box::new(FfiMigrationAdvanceStep {
            step,
            id: 0,
            kind_is_preparation: false,
            kind_layer: 0,
            kind_index: 0,
            kind_crossing: 0,
        }))
    }

    /// The Prove step, carrying the transaction's kind so the platform can route it (preparations
    /// prove against the tip anchor, transfers against their drawn boundary).
    fn prove(id: MigrationTransferId, kind: MigrationTxKind) -> *mut Self {
        let (kind_is_preparation, kind_layer, kind_index, kind_crossing) = match kind {
            MigrationTxKind::Preparation { layer, index } => (true, layer as u32, index as u32, 0),
            MigrationTxKind::Transfer { crossing } => (false, 0, 0, crossing as u32),
        };
        Box::into_raw(Box::new(FfiMigrationAdvanceStep {
            step: ZCASHLC_ADVANCE_STEP_PROVE,
            id: u32::from(id),
            kind_is_preparation,
            kind_layer,
            kind_index,
            kind_crossing,
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

/// What a [`FfiPreparedTransfer`] carries, so the delivery lane's three outcomes stay distinct
/// instead of collapsing into one all-null sentinel.
///
/// The variants carry a `Migration` prefix of their own: cbindgen emits C enum variants
/// unqualified unless two enums collide, and these names land in the global namespace of a header
/// that ships to consuming apps.
#[repr(C)]
pub enum FfiPreparedTransferStatus {
    /// Nothing is due: nothing scheduled yet, dependencies unmined, rows awaiting an external
    /// signature, or everything already broadcast. `id` and `pczt` are null.
    MigrationNothingDue,
    /// A proven transaction is ready to broadcast: `id`, `txid` and `pczt` are all populated.
    MigrationReady,
    /// A transaction is DUE but not yet proved, so this call has nothing to broadcast: `id` names
    /// the row waiting on a proof, `pczt` is null and `txid` zeroed. The delivery lane never
    /// proves; the platform clears this by running `zcashlc_migration_prove_pending` (which it
    /// should be running as blocks are scanned anyway) and calling again.
    MigrationAwaitingProof,
}

/// A fully proven, signed transaction persisted as a PCZT, ready for the platform to broadcast.
/// When returned by `zcashlc_migration_next_due_transfer`, `status` distinguishes a broadcastable
/// transaction from the two empty outcomes (see [`FfiPreparedTransferStatus`]); a NULL return
/// signals an error.
#[repr(C)]
pub struct FfiPreparedTransfer {
    /// The transaction's id (the engine's raw id). Meaningful only when `pczt` is non-null; the
    /// "nothing due" sentinel leaves it `0`.
    pub id: u32,
    /// The finalized transaction's id, as raw (internal-order) 32-byte value (zeroed when the
    /// value is a storage receipt whose transaction has not been proven yet).
    pub txid: [u8; 32],
    /// Heap `pczt_len`-byte serialized PCZT (null unless `status` is
    /// [`FfiPreparedTransferStatus::MigrationReady`]).
    pub pczt: *mut u8,
    pub pczt_len: usize,
    /// Which of the three delivery outcomes this value is.
    pub status: FfiPreparedTransferStatus,
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
            status: FfiPreparedTransferStatus::MigrationReady,
        })))
    }

    /// The "due, but its proof has not been produced yet" outcome: the row's id with no artifact.
    fn awaiting_proof(id: MigrationTransferId) -> anyhow::Result<*mut Self> {
        Ok(Box::into_raw(Box::new(FfiPreparedTransfer {
            id: u32::from(id),
            txid: [0u8; 32],
            pczt: ptr::null_mut(),
            pczt_len: 0,
            status: FfiPreparedTransferStatus::MigrationAwaitingProof,
        })))
    }

    fn none() -> *mut Self {
        Box::into_raw(Box::new(FfiPreparedTransfer {
            id: 0,
            txid: [0u8; 32],
            pczt: ptr::null_mut(),
            pczt_len: 0,
            status: FfiPreparedTransferStatus::MigrationNothingDue,
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

impl FfiTransferProposal {
    fn boxed(
        id: MigrationTransferId,
        amount: Zatoshis,
        now_reference: BlockHeight,
        next_executable_after: BlockHeight,
        expiry: BlockHeight,
    ) -> anyhow::Result<*mut Self> {
        Ok(Box::into_raw(Box::new(FfiTransferProposal {
            id: u32::from(id),
            amount: zat_to_i64(amount),
            anchor_height: i64::from(u32::from(now_reference)),
            next_executable_after_height: i64::from(u32::from(next_executable_after)),
            expiry_height: i64::from(u32::from(expiry)),
        })))
    }
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
/// strings), rather than generalizing [`ffi::BoxedSlice`] (a single binary blob, not an array) or
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

/// Frees a [`FfiMigrationAdvanceStep`].
///
/// # Safety
/// `ptr` must be null or point to a [`FfiMigrationAdvanceStep`] handed out by this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_migration_advance_step(ptr: *mut FfiMigrationAdvanceStep) {
    if !ptr.is_null() {
        // Every field is plain data, so dropping the box is the whole of the cleanup.
        drop(unsafe { Box::from_raw(ptr) });
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

/// Frees a standalone [`FfiTransferProposal`] (as returned by
/// `zcashlc_migration_pending_transfer_proposal`).
///
/// # Safety
/// `ptr` must be null or point to a [`FfiTransferProposal`] handed out by this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_migration_transfer_proposal(ptr: *mut FfiTransferProposal) {
    if !ptr.is_null() {
        // The id is a plain `u32`; dropping the box is the whole of the cleanup.
        drop(unsafe { Box::from_raw(ptr) });
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
    let backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?;
    use zcash_pool_migration::engine::MigrationBackend;
    let values = backend.spendable_orchard_note_values()?;
    values
        .into_iter()
        .try_fold(Zatoshis::ZERO, |acc, v| acc + v)
        .ok_or_else(|| anyhow!("spendable Orchard balance overflows"))
}

/// Advances the stored run with upstream's public satisfiability API, using scanned and estimated
/// targets plus a ten-block reorg-settle depth. Reevaluate and Replan are projected onto the
/// existing Attend DTO case so the Swift public enum remains source-compatible.
///
/// Returns NULL **with no error recorded** when the account has never stored a migration — there
/// is nothing to advance and no step to report. Distinguish that benign NULL from an error NULL
/// via `zcashlc_last_error_length`. A stored TERMINAL run (Complete, or Failed/cancelled) reports
/// the `Complete` step VERBATIM, exactly as upstream's `next_step` does — a cancelled run is never
/// driven further, and is NEVER remapped to any other step. (The terminal check here is upstream's
/// own first check, hoisted only so the answer needs no chain-tip lookup — the same answer
/// `next_step` would give, available on a wallet that never saw a chain tip.)
///
/// Reporting that verbatim `Complete` is why the load is [`Backend::latest_migration`] rather than
/// the pending-only `get_migration`, which stops reporting a run at the exact moment it becomes
/// terminal: reading through the pending-only accessor would answer NULL — "no run was ever
/// stored" — for the one case this function exists to name.
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
        // would only ask the same question twice. History-inclusive, so the terminal check below
        // still has a run to check (see the function doc).
        let Some(mut state) = ({
            let backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?;
            backend.latest_migration()?
        }) else {
            // No stored run: NULL with NO error (see the function doc). Returned before any
            // chain-tip lookup, so it holds even before the wallet ever saw a chain tip.
            return Ok(ptr::null_mut());
        };
        // Upstream `next_step`'s own first check, hoisted ahead of the target lookup (not a
        // carve-out — identical answers): a cancelled (Failed) run reports Complete even on a
        // wallet with no chain tip, and is never driven further.
        if state.is_terminal() {
            return Ok(FfiMigrationAdvanceStep::bare(ZCASHLC_ADVANCE_STEP_COMPLETE));
        }
        let targets = dueness_targets(ctx.tip()?, estimated_tip);
        let mut backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?;
        // `OsRng`, the same source every other engine entry point here is given, because these
        // draws are PRIVACY-BEARING rather than incidental. The rng feeds upstream's re-spread of
        // a broadcast schedule the wallet slept through, and specifically the anchor-boundary
        // REDRAW that accompanies it: a still-unproved transfer whose schedule shifts forward but
        // whose boundary did not would broadcast an anchor older than any honest draw, by exactly
        // the shift — and every deferred transfer of this wallet older by the SAME amount, which
        // is a linkable fingerprint. A weak or reproducible source here is an on-chain disclosure,
        // not a test-determinism concern.
        let step = advance_migration(
            &mut backend,
            &mut state,
            targets,
            &AdvanceConfig::new(ReorgSettleDepth::new(10)),
            &mut OsRng,
        )?;
        Ok(match step {
            AdvanceStep::Reevaluate | AdvanceStep::Replan => {
                let id = state
                    .transaction_statuses(targets)
                    .into_iter()
                    .find(|status| {
                        matches!(
                            status.blocked_on(),
                            Some(
                                Blocker::AwaitingReevaluation
                                    | Blocker::Unsatisfiable
                                    | Blocker::Expired
                            )
                        )
                    })
                    .map(|status| status.id())
                    .unwrap_or_else(|| MigrationTransferId::new(0));
                FfiMigrationAdvanceStep::with_id(ZCASHLC_ADVANCE_STEP_ATTEND, id)
            }
            AdvanceStep::Prove { id, kind } => FfiMigrationAdvanceStep::prove(id, kind),
            AdvanceStep::Broadcast { id } => {
                FfiMigrationAdvanceStep::with_id(ZCASHLC_ADVANCE_STEP_BROADCAST, id)
            }
            AdvanceStep::Rebuild { id } => {
                FfiMigrationAdvanceStep::with_id(ZCASHLC_ADVANCE_STEP_REBUILD, id)
            }
            AdvanceStep::Waiting => FfiMigrationAdvanceStep::bare(ZCASHLC_ADVANCE_STEP_WAITING),
            AdvanceStep::Complete => FfiMigrationAdvanceStep::bare(ZCASHLC_ADVANCE_STEP_COMPLETE),
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
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let engine_state = reconcile_mined(&mut ctx)?;
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
        let immediate_row = immediate_run_row(&ctx.store_conn, &ctx.account_bytes)
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
/// than caching. Reconciles mined transactions first, like every other read.
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
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let Some(state) = reconcile_mined(&mut ctx)? else {
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
/// [`zcashlc_migration_has_overdue_transfers`] / [`zcashlc_migration_next_due_transfer`] as
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
/// decides what to sign/prove/broadcast next. Reconciles mined transactions first (the same
/// read-path convention as [`zcashlc_migration_advance_step`]), so a `Broadcast` row the wallet's
/// own scan has since observed mined is reported `Mined` here too. No stored run, or a stored run
/// with no transactions, returns an EMPTY container (`len == 0`) — not an error, the same
/// convention as [`encode_empty_schedule`].
///
/// This is a pure read: unlike [`zcashlc_migration_next_due_transfer`] it never drives a
/// prove-ready `Signed` row through proving — a `Signed` row ready to prove is reported via
/// `ready`/`action` (`action == 1`), not silently advanced to `Proved`.
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
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let Some(state) = reconcile_mined(&mut ctx)? else {
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
/// due, dependency-satisfied, prove-ready `Signed` one that
/// [`zcashlc_migration_next_due_transfer`] would drive through proving and serve (proofs are
/// assumed to succeed — a transiently unwitnessable anchor defers the delivery, not this
/// report; see [`due_assuming_proving`]). A row awaiting an EXTERNAL signature is not delivery
/// work (the signing ceremony advances it). Returns `false` on error (see
/// `zcashlc_last_error_message`).
///
/// NOT the sync-gate's work-pending predicate: a `Signed` row it counts (due, but its proof not
/// produced yet) must never hold sync hostage — that predicate is
/// [`zcashlc_migration_has_ready_broadcast`], which answers for PROVED, servable work only.
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
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let Some(state) = reconcile_mined(&mut ctx)? else {
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
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let Some(state) = reconcile_mined(&mut ctx)? else {
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

/// Whether the stored, NON-TERMINAL run has a broadcast the platform could serve RIGHT NOW: a
/// `Proved`, schedule-due, dependency-mined, unexpired transaction per upstream
/// the upstream transaction-status evaluation at the [`dueness_targets`] of the scanned tip and
/// `estimated_tip` (`-1` = disabled). Reconciles mined transactions first, like every other
/// read. Returns `1` for yes, `0` for no (including no stored run and a terminal run), `-1` on
/// error (see `zcashlc_last_error_message`).
///
/// This is the sync-gate's work-pending predicate: `1` means exactly "a PROVED, due, unexpired,
/// valid transfer is waiting", the one situation where the platform should broadcast instead of
/// starting a sync (ZIP 318's broadcast-or-sync session split). `Signed` rows — even due ones —
/// and rows awaiting a proof or an external signature must NEVER block sync (they need MORE
/// syncing/other work, not a broadcast session), which is why the gate cannot be derived from
/// [`zcashlc_migration_has_overdue_transfers`] (that query deliberately counts due-but-unproved
/// work). Rows marked `Invalid` are excluded upstream (a dead transfer gates nothing), and so is
/// a doomed broadcast whose expiry only the ESTIMATED target has passed (upstream's protective
/// withhold — served again once the scanned tip proves it either way).
///
/// # Safety
/// See [`open`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_has_ready_broadcast(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    estimated_tip: i64,
) -> i32 {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let Some(state) = reconcile_mined(&mut ctx)? else {
            return Ok(0);
        };
        if state.is_terminal() {
            return Ok(0);
        }
        let targets = dueness_targets(ctx.tip()?, estimated_tip);
        Ok(i32::from(
            next_ready_action(&state, targets, NextAction::Broadcast).is_some(),
        ))
    });
    unwrap_exc_or(res, -1)
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
        let usk = unsafe { crate::decode_usk(usk_ptr, usk_len)? };

        let (mut state, _) = commit_or_resume(&mut ctx, Some(usk), false, proposal_handle)?;

        // The first broadcastable preparation transaction (lowest scheduled height not yet
        // broadcast): proven now, against the wallet's scanned-tip anchor, and returned for the
        // platform's immediate broadcast — this lane exists to hand back something to broadcast,
        // so its proof cannot wait for a sweep. Remaining preparation transactions are proved by
        // `zcashlc_migration_prove_pending` and ride the normal delivery lane as they come due.
        let first_prep = state
            .transactions()
            .iter()
            .filter(|t| {
                matches!(t.kind(), MigrationTxKind::Preparation { .. })
                    && matches!(
                        t.state(),
                        MigrationTxState::Signed | MigrationTxState::Proved
                    )
            })
            .min_by_key(|t| t.scheduled_height())
            .map(|t| t.id())
            .ok_or_else(|| {
                anyhow!("the committed migration has no broadcastable preparation transaction")
            })?;
        if !prove_one(&mut ctx, &mut state, first_prep)? {
            return Err(anyhow!(
                "the note split is not yet finalizable — its funding note is not witnessable; sync first"
            ));
        }
        let (proven, txid) = serve_proved(&state, first_prep)?;
        FfiPreparedTransfer::from_parts(first_prep, txid, proven)
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
            let backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?;
            if let Some(state) = backend.get_migration()? {
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
        // Selection targets the next block, mirroring `Backend::selection_target`.
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
        let backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?;
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
        commit_or_resume(&mut ctx, Some(usk), false, proposal_handle)?;
        Ok(true)
    });
    unwrap_exc_or(res, false)
}

/// Proves every migration transaction of the stored run whose anchor the wallet can resolve right
/// now, persisting each proof, and returns HOW MANY were proved (`0` is the ordinary "nothing left
/// to prove" answer; `-1` signals an error — see `zcashlc_last_error_message`).
///
/// Call this opportunistically as the wallet scans (proofs are wanted long before their
/// transactions come due), not on the broadcast path: proving needs the wallet's commitment tree
/// and takes real time, while `zcashlc_migration_next_due_transfer` must only broadcast. A
/// transaction whose anchor is not scanned/retained yet is skipped and retried by a later call, so
/// this is safe to run on any schedule, including mid-sync.
///
/// # Safety
/// See [`open`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_prove_pending(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    max_proofs: i64,
) -> i64 {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let Some(mut state) = reconcile_mined(&mut ctx)? else {
            return Ok(0);
        };
        if state.is_terminal() {
            return Ok(0);
        }
        // `target = tip + 1`, the height every `MigrationState` query is defined over (see
        // `CallCtx::target`; A1 — this sweep briefly fed the raw tip, which left a preparation
        // scheduled exactly at the target un-proved for one extra block).
        let target = ctx.target()?;
        // `max_proofs <= 0` means unlimited. A platform whose DB access serializes behind one
        // actor should pass 1 and loop with a yield between calls, so interactive reads
        // interleave between proofs instead of waiting out the whole sweep.
        let cap = u32::try_from(max_proofs).ok().filter(|&n| n > 0);
        let proved = prove_pending_rows(&mut state, target, cap, |state, id| {
            prove_one(&mut ctx, state, id)
        })?;
        Ok(i64::from(proved))
    });
    unwrap_exc_or(res, -1)
}

/// The next due transaction of the stored run, already proven and ready to broadcast — or, per
/// `status`, "nothing is due" or "due, but its proof has not been produced yet" (see
/// [`FfiPreparedTransferStatus`]). Reconciles mined transactions first. Serves preparation
/// transactions and transfers alike, in scheduled order.
///
/// This call NEVER proves: proofs are produced by `zcashlc_migration_prove_pending` as the wallet
/// scans, so broadcasting stays a pure delivery step. A platform that has not swept sees
/// `AwaitingProof` and can sweep then retry, rather than paying proving latency here.
///
/// `estimated_tip` (`-1` = disabled) follows upstream's [`DuenessTargets`] rule: it may only
/// ACCELERATE scheduled-height due-ness; expiry is always evaluated against the SCANNED tip
/// (with the doomed-broadcast withhold when only the estimate has passed an expiry) — the same
/// rule as [`zcashlc_migration_has_overdue_transfers`].
///
/// # Safety
/// See [`open`]. Free the returned pointer with [`zcashlc_free_migration_prepared_transfer`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_next_due_transfer(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    estimated_tip: i64,
) -> *mut FfiPreparedTransfer {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let Some(state) = reconcile_mined(&mut ctx)? else {
            return Ok(FfiPreparedTransfer::none());
        };
        if state.is_terminal() {
            return Ok(FfiPreparedTransfer::none());
        }
        let targets = dueness_targets(ctx.tip()?, estimated_tip);
        match next_due(&state, targets) {
            DueOutcome::Ready { id } => {
                let (pczt, txid) = serve_proved(&state, id)?;
                FfiPreparedTransfer::from_parts(id, txid, pczt)
            }
            DueOutcome::AwaitingProof { id } => FfiPreparedTransfer::awaiting_proof(id),
            DueOutcome::Nothing => Ok(FfiPreparedTransfer::none()),
        }
    });
    unwrap_exc_or_null(res)
}

/// The next due-and-unbroadcast TRANSFER of the stored run as a proposal row (id, amount, its
/// scheduled and expiry heights), or NULL with no error when there is none. Distinguish the two
/// NULL meanings via `zcashlc_last_error_length`.
///
/// "Due-and-unbroadcast" matches what [`zcashlc_migration_next_due_transfer`] would serve: an
/// already-`Proved` due transfer, or a due, prove-ready `Signed` one the delivery call would
/// first drive through proving (see [`due_assuming_proving`] — this query itself never proves;
/// it reports the row the delivery lane is being driven toward, assuming its proof succeeds).
/// NULL when the would-be-served transaction is a preparation, when due rows still await an
/// external signature, or when nothing is due.
///
/// # Safety
/// See [`open`]. Free the returned pointer with [`zcashlc_free_migration_transfer_proposal`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_pending_transfer_proposal(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> *mut FfiTransferProposal {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let Some(state) = reconcile_mined(&mut ctx)? else {
            return Ok(ptr::null_mut());
        };
        if state.is_terminal() {
            return Ok(ptr::null_mut());
        }
        // `tip` is the display-only "now" reference the DTO carries (see
        // `FfiTransferProposal::anchor_height`'s doc); `target` (`tip + 1`) is what the engine
        // query below is actually defined over — see `CallCtx::target`. This query takes no
        // estimated tip, so both due-ness targets coincide (`DuenessTargets::at`).
        let tip = ctx.tip()?;
        let target = target_from_tip(tip);
        let next_transfer = due_assuming_proving(&state, DuenessTargets::at(target))
            .and_then(|id| state.transactions().iter().find(|t| t.id() == id))
            .filter(|t| matches!(t.kind(), MigrationTxKind::Transfer { .. }));
        match next_transfer {
            Some(tx) => {
                let amount = transfer_amount(&state, tx)
                    .ok_or_else(|| anyhow!("stored transfer has no valid net crossing amount"))?;
                FfiTransferProposal::boxed(
                    tx.id(),
                    amount,
                    tip,
                    tx.scheduled_height(),
                    tx.expiry_height(),
                )
            }
            None => Ok(ptr::null_mut()),
        }
    });
    unwrap_exc_or_null(res)
}

/// Extracts the consensus transaction bytes from a proven, finalized migration PCZT.
///
/// # Safety
/// See [`open`]; `pczt_ptr` must be valid for reads of `pczt_len` bytes. Free the returned
/// pointer with `zcashlc_free_boxed_slice`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_extract_broadcast_tx(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    pczt_ptr: *const u8,
    pczt_len: usize,
) -> *mut ffi::BoxedSlice {
    let res = catch_panic(|| {
        let _ = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let pczt_bytes = unsafe { slice_or_empty(pczt_ptr, pczt_len) };
        let pczt =
            pczt::Pczt::parse(pczt_bytes).map_err(|e| anyhow!("Error parsing PCZT: {e:?}"))?;
        let (raw, _) = migration_finalize::extract_tx(pczt)?;
        Ok(ffi::BoxedSlice::some(raw))
    });
    unwrap_exc_or_null(res)
}

/// Records a broadcast outcome for the identified transaction. `result_tag`: 0 = success (with
/// `txid_bytes`, 32 raw bytes) — the transaction is marked broadcast, to be reconciled to mined
/// as the wallet scans; 1 = network error (retryable — nothing is recorded, the transaction stays
/// offered); 2 = invalid note, 3 = expired — each rejection is reported to the engine at the
/// wallet's observed chain tip. The next advance reevaluates satisfiability and projects any
/// resulting Reevaluate/Replan step onto the existing Attend DTO case.
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
                let mut backend =
                    Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?;
                let mut state = backend
                    .get_migration()?
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
                backend.replace_migration(&state)?;
                Ok(true)
            }
            1 => Ok(true),
            2 | 3 => {
                let mut backend =
                    Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?;
                let mut state = backend
                    .get_migration()?
                    .ok_or_else(|| anyhow!("no migration is stored"))?;
                if state
                    .transactions()
                    .iter()
                    .any(|tx| tx.id() == id && matches!(tx.state(), MigrationTxState::Proved))
                {
                    let observed_tip = backend.chain_tip_height()?;
                    state.report_broadcast_failure(id, observed_tip);
                    backend.replace_migration(&state)?;
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

/// Cancels the stored run (persisting it as `Failed` — its pre-signed transactions are abandoned;
/// already-broadcast ones are unaffected on-chain) and previews a fresh plan against the live
/// balance for the platform's re-confirm lane.
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
            let mut backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?;
            if let Some(state) = backend.get_migration()? {
                if !state.is_terminal() {
                    let cancelled = MigrationState::from_parts(
                        MigrationStatus::Failed,
                        state.denominations().clone(),
                        state.preparation().clone(),
                        state.transactions().clone(),
                        state.anchor_bucket_interval(),
                        state.replan_threshold(),
                    );
                    backend.replace_migration(&cancelled)?;
                }
            }
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

        let sign_in_process = usk.is_some();
        let mut rng = OsRng;
        let mut backend = Backend::new(&ctx.wallet, ctx.account, usk, &mut ctx.store_conn)?;
        for id in &expired {
            if sign_in_process {
                engine::rebuild_expired_transfer(&ctx.network, &backend, &mut state, *id, &mut rng)
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
        backend.replace_migration(&state)?;
        encode_schedule_from_state(&state, tip)
    });
    unwrap_exc_or_null(res)
}

/// Fetches the account's ZIP 32 seed fingerprint and account index, required to annotate
/// external-signer (Keystone) migration PCZTs with `spend_zip32_derivation` — see
/// [`crate::migration_keystone::annotate_spend_zip32_derivation`]'s doc comment for why this is
/// needed.
///
/// Applied as a post-processing step on whatever unsigned PCZT bytes `commit_or_resume` returns
/// (freshly built, or resumed from an already-committed migration) rather than inside the engine
/// build call itself: `commit_or_resume` only calls the engine builder on first commit, so
/// annotating only there would silently skip already-committed migrations (e.g. ones committed
/// before this annotation existed) on every later re-entry into the Keystone sign screen.
fn account_zip32_derivation(
    wallet: &MigrationWallet,
    account: AccountUuid,
) -> anyhow::Result<([u8; 32], zip32::AccountId)> {
    use zcash_client_backend::data_api::Account;

    let account_info = wallet
        .get_account(account)
        .map_err(|e| anyhow!("account lookup failed: {}", e))?
        .ok_or_else(|| anyhow!("Account not found"))?;
    let derivation = account_info.source().key_derivation().ok_or_else(|| {
        anyhow!(
            "Account has no known ZIP 32 seed fingerprint/account index — cannot annotate \
             migration PCZTs for external-signer batch signing"
        )
    })?;
    Ok((
        derivation.seed_fingerprint().to_bytes(),
        derivation.account_index(),
    ))
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
/// Every returned PCZT is annotated with the account's ZIP 32 spend derivation (see
/// [`account_zip32_derivation`]) so an external signer (Keystone) can identify which of its
/// accounts each spend belongs to — annotation happens here, after `commit_or_resume`, so it
/// covers both a freshly built and a resumed (already-committed) run alike.
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
        let (seed_fingerprint, account_index) = account_zip32_derivation(&ctx.wallet, ctx.account)?;
        let preps = preps
            .into_iter()
            .map(|(id, pczt_bytes, actions)| {
                let pczt_bytes = crate::migration_keystone::annotate_spend_zip32_derivation(
                    &pczt_bytes,
                    seed_fingerprint,
                    ctx.network.coin_type(),
                    account_index,
                )
                .map_err(|e| anyhow!("Error annotating note-split PCZT derivation: {:?}", e))?;
                Ok::<_, anyhow::Error>((id, pczt_bytes, actions))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
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
        let mut backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?;
        let mut state = backend
            .get_migration()?
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
        backend.replace_migration(&state)?;
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
/// Every returned PCZT is annotated with the account's ZIP 32 spend derivation — see
/// [`account_zip32_derivation`] and `zcashlc_migration_create_unsigned_note_split_pczts`'s doc.
///
/// Every returned PCZT is annotated with the account's ZIP 32 spend derivation — see
/// [`account_zip32_derivation`] and `zcashlc_migration_create_unsigned_note_split_pczts`'s doc.
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
        let (seed_fingerprint, account_index) = account_zip32_derivation(&ctx.wallet, ctx.account)?;
        let transfers: Vec<_> = transfers
            .into_iter()
            .map(|(id, pczt_bytes, actions)| {
                let pczt_bytes = crate::migration_keystone::annotate_spend_zip32_derivation(
                    &pczt_bytes,
                    seed_fingerprint,
                    ctx.network.coin_type(),
                    account_index,
                )
                .map_err(|e| anyhow!("Error annotating transfer PCZT derivation: {:?}", e))?;
                Ok::<_, anyhow::Error>((id, pczt_bytes, actions))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
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
                // `layer`/`index`/`crossing` are dummies (see the doc above): the packer never
                // reads them, only each entry's action weight.
                Ok(PlannedTx::new(MigrationTransferId::new(i as u32), kind))
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
        let mut backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?;
        let mut state = backend
            .get_migration()?
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
        backend.replace_migration(&state)?;
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

/// DEBUG ONLY: overrides this account's persisted migration schedule so its transfers become due
/// in quick succession, for manually testing real broadcast execution without waiting out ZIP
/// 318's privacy-motivated delay (mean 66 blocks, about 82 minutes, between transfers — see
/// `zcash_pool_migration::scheduling`'s module doc: this is a deliberate anti-correlation choice,
/// not a technical requirement). Not exposed to production users. Mirrors the Android SDK's
/// `debugRescheduleTransfersNative` exactly (same table names, same query, same rewrite rule).
///
/// Both `scheduled_height` (which gates BROADCAST — see `next_broadcastable`) AND `anchor_boundary`
/// (which gates PROVING — see `is_prove_ready`) are rewritten; dependency-mining is not touched or
/// bypassed:
/// - A transfer's `anchor_boundary`, as originally drawn at commit time
///   (`scheduling::draw_anchor_boundary`), is a boundary in the past relative to the chain tip
///   *at commit time* — normally already passed by the time the transfer's (much later,
///   ZIP-318-delayed) `scheduled_height` arrives. This override exists precisely because this
///   function moves `scheduled_height` to now, while the original `anchor_boundary` stays
///   wherever it was drawn: the original boundary can still be far ahead of the current synced
///   tip, since it was never meant to be reached this soon. Left alone, `is_prove_ready`
///   (`boundary + 1 < target_height`) would keep failing regardless of how close
///   `scheduled_height` is. So every rescheduled transfer's `anchor_boundary` is also rewritten,
///   to `natural_anchor_height` — the SAME anchor ordinary non-migration sends use (guaranteed
///   checkpointed/witnessed). NOT a full `BOUNDARY_MODULUS` bucket back like `draw_anchor_boundary`
///   draws in production (that bucketing is a privacy measure, irrelevant here, and can land
///   outside the checkpoint retention window), and NOT a hand-picked "tip minus N" guess either
///   (also not guaranteed checkpointed — see `natural_anchor_height`'s own doc comment) — so
///   proving can proceed as soon as the delivery lane next drives it.
/// - Transfers do NOT depend on each other (`MigrationTransaction::depends_on` for a `Transfer`
///   never lists another transfer's id, only the single preparation transaction that minted its
///   own funding note, if any) — so every transfer can be staggered independently; there is no
///   need to wait for transfer N to broadcast before N+1 becomes due.
/// - A transfer whose funding note comes from an actual note-split (preparation) transaction still
///   genuinely cannot broadcast until that preparation transaction is MINED (`deps_mined`) — this
///   function does not and cannot bypass that; it only affects how soon a transfer becomes due and
///   provable once its real dependencies are satisfied.
///
/// Every not-yet-broadcast/mined TRANSFER (preparation transactions are left alone) is
/// rescheduled to `target + FIRST_DELAY_BLOCKS + i * STRIDE_BLOCKS`, in `i` = the transfers'
/// existing relative order (by their current `scheduled_height`, so the engine's own ZIP 318
/// shuffle order is preserved even though the absolute heights are now compressed) — the first
/// becomes due in about `FIRST_DELAY_BLOCKS * 75s`, each subsequent one `STRIDE_BLOCKS * 75s`
/// after that.
///
/// Returns the number of transfers rescheduled (`0` when the account has no stored migration),
/// or a negative value on error (see `zcashlc_last_error_message`).
///
/// # Safety
/// See [`open`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_debug_reschedule_transfers(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> i64 {
    // ~2.5 min to the first transfer, ~5 min between each subsequent one, at the ~75s/block
    // testnet/mainnet target spacing.
    const FIRST_DELAY_BLOCKS: u32 = 2;
    const STRIDE_BLOCKS: u32 = 4;

    let res = catch_panic(|| {
        let ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let target = ctx.target()?;
        // The wallet's real, currently-witnessable anchor — NOT a hand-picked "tip minus N"
        // guess (see `natural_anchor_height`'s own doc comment for why that would be wrong).
        let debug_anchor_boundary =
            u32::from(migration_finalize::preparation_anchor_height(&ctx.wallet)?);

        let migration_id: Option<i64> = ctx
            .store_conn
            .query_row(
                "SELECT m.id FROM orchard_ironwood_migrations m \
                 JOIN accounts a ON a.id = m.account_id \
                 WHERE a.uuid = ?1",
                rusqlite::params![&ctx.account_bytes[..]],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| anyhow!("Error reading migration row: {e}"))?;
        let Some(migration_id) = migration_id else {
            return Ok(0i64);
        };

        let tx_ids: Vec<i64> = {
            let mut stmt = ctx
                .store_conn
                .prepare(
                    "SELECT transfer_id FROM orchard_ironwood_migration_transactions \
                     WHERE migration_id = ?1 AND kind = 'transfer' \
                       AND state NOT IN ('broadcast', 'mined') \
                     ORDER BY scheduled_height ASC",
                )
                .map_err(|e| anyhow!("Error preparing transfer query: {e}"))?;
            stmt.query_map(rusqlite::params![migration_id], |row| row.get(0))
                .map_err(|e| anyhow!("Error reading pending transfers: {e}"))?
                .collect::<Result<_, _>>()
                .map_err(|e| anyhow!("Error reading pending transfers: {e}"))?
        };

        for (i, tx_id) in tx_ids.iter().enumerate() {
            let new_height = u32::from(target) + FIRST_DELAY_BLOCKS + (i as u32) * STRIDE_BLOCKS;
            // `is_prove_ready` gates purely on `anchor_boundary`, NOT on `scheduled_height` — so
            // rewriting every transfer's anchor here would make ALL of them prove-ready in the
            // same pass (an unrealistic proving batch this debug tool itself would have
            // created). Only the earliest-due transfer (i==0, this loop's existing
            // scheduled_height-ascending order) gets a valid anchor; the rest keep their
            // original, still-in-the-future one, matching production's natural
            // one-becomes-ready-at-a-time shape. Re-invoke this debug action once this transfer
            // broadcasts to unlock the next one.
            let anchor_boundary = if i == 0 {
                Some(debug_anchor_boundary)
            } else {
                None
            };
            ctx.store_conn
                .execute(
                    "UPDATE orchard_ironwood_migration_transactions \
                     SET scheduled_height = ?1, \
                         anchor_boundary = COALESCE(?2, anchor_boundary) \
                     WHERE migration_id = ?3 AND transfer_id = ?4",
                    rusqlite::params![new_height, anchor_boundary, migration_id, tx_id],
                )
                .map_err(|e| anyhow!("Error rescheduling transfer {tx_id}: {e}"))?;
        }
        Ok(tx_ids.len() as i64)
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
    use zcash_pool_migration::engine::MigrationLockOwner;
    use zcash_pool_migration::preparation::PreparationPlan;
    use zcash_pool_migration::scheduling::{self, AnchorBucketInterval, SchedulingParams};
    use zcash_pool_migration::signing_rounds::min_signing_rounds;

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
            .create_account("fixture", &seed, &birthday, None)
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

    /// A view-only account imported by UFVK (no seed) — the negative-path counterpart to
    /// [`create_fixture_account_with_usk`], which only ever produces seed-derived accounts.
    /// Returns the wallet handle itself (not just the uuid bytes), since the caller exercises
    /// [`account_zip32_derivation`] directly, off the FFI boundary.
    fn create_fixture_view_only_account(path: &std::path::Path) -> (MigrationWallet, AccountUuid) {
        use zcash_client_backend::data_api::{Account, AccountBirthday, AccountPurpose};
        use zcash_client_backend::proto::service::TreeState;
        use zcash_keys::keys::UnifiedSpendingKey;
        use zcash_protocol::consensus::MAIN_NETWORK;

        let path_bytes = path.to_str().unwrap().as_bytes();
        let mut wallet = unsafe {
            crate::wallet_db(
                path_bytes.as_ptr(),
                path_bytes.len(),
                parse_network(NETWORK_ID_MAINNET).expect("mainnet parses"),
            )
        }
        .expect("the wallet database must open");

        // A throwaway seed, only to derive SOME validly-shaped UFVK to import — the wallet is
        // never given this seed (that is the entire point of `import_account_ufvk`), so it has
        // no ZIP 32 path to recover from it later.
        let usk = UnifiedSpendingKey::from_seed(&MAIN_NETWORK, &[9u8; 32], zip32::AccountId::ZERO)
            .expect("valid ZIP 32 seed derivation");
        let ufvk = usk.to_unified_full_viewing_key();
        let treestate = TreeState {
            hash: "00".repeat(32),
            ..TreeState::default()
        };
        let birthday = match AccountBirthday::from_treestate(treestate, None) {
            Ok(birthday) => birthday,
            Err(_) => panic!("the fixture treestate must convert to a birthday"),
        };
        let account = wallet
            .import_account_ufvk(
                "fixture-view-only",
                &ufvk,
                &birthday,
                AccountPurpose::ViewOnly,
                None,
            )
            .expect("ufvk import must succeed");
        let account_id = account.id();
        (wallet, account_id)
    }

    /// `account_zip32_derivation` is this SDK's own addition (annotating Keystone migration
    /// PCZTs with the spend derivation path — see its doc comment), so it has no Android
    /// original to mirror. A UFVK-imported (view-only) account is exactly the case its error
    /// branch guards: the wallet was never given a seed for it, so there is no ZIP 32 path to
    /// annotate with, and Keystone has no way to recognize which of its accounts a spend belongs
    /// to.
    #[test]
    fn account_zip32_derivation_errors_for_a_view_only_account() {
        let path = init_fixture_db("zcashlc_migration_account_zip32_derivation_view_only");
        let (wallet, account) = create_fixture_view_only_account(&path);

        let result = account_zip32_derivation(&wallet, account);
        let err = match result {
            Ok(_) => panic!("a view-only account must have no known ZIP 32 derivation"),
            Err(e) => e,
        };
        assert!(
            err.to_string()
                .contains("Account has no known ZIP 32 seed fingerprint/account index"),
            "unexpected error message: {err}"
        );
        let _ = std::fs::remove_file(&path);
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

    #[test]
    fn schedule_rows_sort_chronologically_with_prep_offset() {
        let mut rng = StdRng::seed_from_u64(7);
        let schedule = scheduling::schedule(&SchedulingParams::ZIP_318, h(1_000), 5, &mut rng);
        // The engine hands the crossing values straight over; they are already net of the fee
        // buffer that pays each transfer's own fee.
        let crossing_values: Vec<Zatoshis> = (1..=5).map(|i| zat(i * 100_000_000)).collect();
        let rows = schedule_rows(&crossing_values, &schedule, 3).unwrap();
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
        let rows_a = schedule_rows(&crossing_values, &schedule_a, 0).unwrap();

        let mut rng_b = StdRng::seed_from_u64(99);
        let schedule_b = scheduling::schedule(&SchedulingParams::ZIP_318, h(1_000), 5, &mut rng_b);
        let rows_b = schedule_rows(&crossing_values, &schedule_b, 0).unwrap();

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
        assert!(schedule_rows(&crossing_values, &schedule, 0).is_err());
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
        let rows = schedule_rows(note_split.crossing_values(), &schedule, 0).unwrap();
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
    fn fixture_orchard_compact_action(
        usk: &zcash_keys::keys::UnifiedSpendingKey,
        value_zat: u64,
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

        let mut rng = StdRng::seed_from_u64(0x1806_0002);
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

    /// Funds the account whose spending key is `usk_bytes` ([`Era::Orchard`]-encoded exactly as
    /// [`create_fixture_account_with_usk`] returns it) with one real, spendable Orchard note of
    /// `value_zat`, by scanning ONE synthetic compact block at height 1 — right after the empty
    /// birthday frontier every [`create_fixture_account_with_usk`] fixture starts from — through
    /// the production [`scan_cached_blocks`] entry point: the same trial-decryption and
    /// commitment-tree insert the real sync pipeline runs, just fed an in-memory block instead of
    /// the filesystem cache `zcashlc_scan_blocks` reads from (so no FS block-metadata-db setup is
    /// needed for one block). `value_zat` should be an amount that is not itself a single
    /// canonical ZIP 318 denomination (e.g. not an exact `{1,2,5}·10^k` ZEC amount), so the note
    /// actually needs splitting — exercising preparation transactions, not just a transfer.
    fn fund_fixture_account_with_orchard_note(
        path: &std::path::Path,
        usk_bytes: &[u8],
        value_zat: u64,
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
        let action = fixture_orchard_compact_action(&usk, value_zat);

        let ctx = CompactTx {
            index: 1,
            txid: vec![0xABu8; 32],
            actions: vec![action],
            ..Default::default()
        };
        let block = CompactBlock {
            height: 1,
            hash: vec![0x11u8; 32],
            prev_hash: vec![0x00u8; 32],
            vtx: vec![ctx],
            chain_metadata: Some(ChainMetadata {
                sapling_commitment_tree_size: 0,
                orchard_commitment_tree_size: 1,
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
            1,
            "the fixture block's one action must be detected as belonging to this wallet"
        );
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
        let (state, unsigned) = commit_or_resume(&mut ctx, Some(usk), false, handle)
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
        let err = commit_or_resume(&mut ctx, Some(usk), false, handle1)
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

    // ----- debug fast-reschedule FFI (#1806 / MOB-1513): `zcashlc_migration_debug_reschedule_
    // transfers`, mirroring the Android SDK's `debugRescheduleTransfersNative` -----

    /// Scans one EMPTY synthetic compact block at height 1 (no transactions) into the fixture
    /// wallet — just enough to give it a real chain tip (height 1, so `CallCtx::target()` is a
    /// small, deterministic `2`) AND a real note-commitment-tree checkpoint at that height, which
    /// `WalletRead::get_target_and_anchor_heights` (via
    /// [`migration_finalize::natural_anchor_height`], what the debug-reschedule FFI resolves its
    /// override anchor from) needs to answer at all — confirmed empirically: on a freshly
    /// initialized wallet with no scanned blocks it errors ("no anchor height yet"). Lighter than
    /// [`fund_fixture_account_with_orchard_note`]: the debug-reschedule path never touches note
    /// selection, so the block need not carry a real decryptable action, only a checkpoint.
    fn scan_one_empty_fixture_block(path: &std::path::Path) {
        use zcash_client_backend::data_api::chain::scan_cached_blocks;
        use zcash_client_backend::proto::compact_formats::{ChainMetadata, CompactBlock};
        use zcash_client_backend::proto::service::TreeState;
        use zcash_client_sqlite::WalletDb;
        use zcash_client_sqlite::util::SystemClock;
        use zcash_protocol::consensus::MAIN_NETWORK;

        let block = CompactBlock {
            height: 1,
            hash: vec![0x22u8; 32],
            prev_hash: vec![0x00u8; 32],
            chain_metadata: Some(ChainMetadata {
                sapling_commitment_tree_size: 0,
                orchard_commitment_tree_size: 0,
                ironwood_commitment_tree_size: 0,
            }),
            ..Default::default()
        };
        let mut wallet = WalletDb::for_path(path, MAIN_NETWORK, SystemClock, OsRng)
            .expect("the fixture wallet database must reopen");
        let from_state = TreeState {
            hash: "00".repeat(32),
            ..TreeState::default()
        }
        .to_chain_state()
        .expect("the empty birthday treestate converts to a chain state");
        let block_source = FixtureBlockSource(vec![block]);
        scan_cached_blocks(
            &MAIN_NETWORK,
            &block_source,
            &mut wallet,
            h(1),
            &from_state,
            10,
        )
        .expect("scanning the one empty fixture block must succeed");
    }

    /// A stored migration with ONE preparation transaction and FIVE transfers spanning every
    /// pre-broadcast state plus `Broadcast` and `Mined`, at scrambled `scheduled_height`s (NOT in
    /// id or storage order) and distinct, individually identifiable `anchor_boundary`/
    /// `expiry_height` values — the fixture `zcashlc_migration_debug_reschedule_transfers`'s
    /// tests share, proving: only PENDING transfers (not broadcast/mined, not preparations) are
    /// touched; the NEW order follows the transfers' EXISTING `scheduled_height` order, not their
    /// id or storage order; only the earliest-due transfer's `anchor_boundary` is rewritten; and
    /// `expiry_height` is never touched.
    fn debug_reschedule_fixture_state() -> MigrationState {
        let transactions = vec![
            // A preparation: excluded by `kind = 'transfer'` alone, even though its state
            // (Signed) would otherwise qualify as "pending".
            test_transaction_from_parts(
                MigrationTransferId::new(0),
                MigrationTxKind::Preparation { layer: 0, index: 0 },
                vec![9u8],
                Vec::new(),
                h(500),
                h(999_990),
                None,
                MigrationTxState::Signed,
                None,
            ),
            // Pending transfers, stored latest-first (7000, 3000, 5000) -- the rescheduled order
            // must come out ascending by the OLD scheduled_height (3000 < 5000 < 7000, i.e. ids
            // 1, 2, 3 in that order), never storage order.
            test_transaction_from_parts(
                MigrationTransferId::new(3),
                MigrationTxKind::Transfer { crossing: 2 },
                vec![3u8],
                Vec::new(),
                h(7000),
                h(999_003),
                Some(h(333)),
                MigrationTxState::AwaitingSignature,
                None,
            ),
            test_transaction_from_parts(
                MigrationTransferId::new(1),
                MigrationTxKind::Transfer { crossing: 0 },
                vec![1u8],
                Vec::new(),
                h(3000),
                h(999_001),
                Some(h(222)),
                MigrationTxState::Signed,
                None,
            ),
            test_transaction_from_parts(
                MigrationTransferId::new(2),
                MigrationTxKind::Transfer { crossing: 1 },
                vec![2u8],
                Vec::new(),
                h(5000),
                h(999_002),
                Some(h(111)),
                MigrationTxState::Proved,
                None,
            ),
            // Already broadcast: excluded by `state NOT IN ('broadcast', 'mined')`.
            test_transaction_from_parts(
                MigrationTransferId::new(4),
                MigrationTxKind::Transfer { crossing: 3 },
                vec![4u8],
                Vec::new(),
                h(4000),
                h(999_004),
                Some(h(444)),
                MigrationTxState::Broadcast {
                    txid: TxId::from_bytes([4u8; 32]),
                },
                None,
            ),
            // Already mined: same exclusion.
            test_transaction_from_parts(
                MigrationTransferId::new(5),
                MigrationTxKind::Transfer { crossing: 4 },
                vec![5u8],
                Vec::new(),
                h(2000),
                h(999_005),
                Some(h(555)),
                MigrationTxState::Mined {
                    txid: TxId::from_bytes([0u8; 32]),
                    height: h(50),
                },
                None,
            ),
        ];
        let funding: Vec<Zatoshis> = (0..5).map(|_| zat(100_000_000)).collect();
        test_state_from_parts(
            MigrationStatus::InProgress,
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
            transactions,
            AnchorBucketInterval::ZIP_318,
        )
    }

    /// Items (a)-(f): pending transfers are rescheduled to `target + FIRST_DELAY_BLOCKS + i *
    /// STRIDE_BLOCKS` in their EXISTING `scheduled_height` order (a); a broadcast and a mined
    /// transfer are left completely untouched (b); the preparation row is left untouched (c);
    /// only the earliest-due (`i == 0`) transfer's `anchor_boundary` is rewritten to the wallet's
    /// natural anchor, the others keep their original, distinct values (d); `expiry_height` is
    /// never touched on any row (e); the function returns the count of transfers it rescheduled,
    /// 3 here (f).
    #[test]
    fn debug_reschedule_transfers_reschedules_pending_transfers_in_scheduled_height_order() {
        let path = init_fixture_db("zcashlc_migration_debug_reschedule_pending");
        let account = create_fixture_account(&path);
        scan_one_empty_fixture_block(&path);
        store_fixture_state(&path, &account, &debug_reschedule_fixture_state());

        let path_bytes = path.to_str().unwrap().as_bytes();
        // Tip = 1 (the one scanned block), so target = 2: new heights are 2+2=4, 2+6=8, 2+10=12.
        // The wallet's natural anchor at this same fixture state is BlockHeight(0) (see
        // `scan_one_empty_fixture_block`'s doc).
        let rescheduled = unsafe {
            zcashlc_migration_debug_reschedule_transfers(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert_eq!(
            rescheduled,
            3,
            "(f) exactly the 3 pending transfers count: {:?}",
            ffi_helpers::error_handling::error_message()
        );

        let mut ctx = unsafe {
            open(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        }
        .expect("the fixture context opens");
        let backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)
            .expect("the fixture backend opens");
        let state = backend
            .get_migration()
            .expect("reading the migration back must succeed")
            .expect("the stored migration is still present");
        let tx = |id: u32| {
            state
                .transactions()
                .iter()
                .find(|t| t.id() == MigrationTransferId::new(id))
                .unwrap_or_else(|| panic!("transaction {id} must still be present"))
        };

        // (a) + (d): earliest-due (id 1, was 3000) -> target+2, anchor rewritten to the natural
        // anchor.
        assert_eq!(tx(1).scheduled_height(), h(4));
        assert_eq!(tx(1).anchor_boundary(), Some(h(0)));
        // (a) + (d): middle (id 2, was 5000) -> target+6, anchor UNCHANGED.
        assert_eq!(tx(2).scheduled_height(), h(8));
        assert_eq!(tx(2).anchor_boundary(), Some(h(111)));
        // (a) + (d): latest (id 3, was 7000) -> target+10, anchor UNCHANGED.
        assert_eq!(tx(3).scheduled_height(), h(12));
        assert_eq!(tx(3).anchor_boundary(), Some(h(333)));
        // (e): expiry untouched on all three rescheduled rows.
        assert_eq!(tx(1).expiry_height(), h(999_001));
        assert_eq!(tx(2).expiry_height(), h(999_002));
        assert_eq!(tx(3).expiry_height(), h(999_003));

        // (b): broadcast and mined transfers are completely untouched.
        assert_eq!(tx(4).scheduled_height(), h(4000));
        assert_eq!(tx(4).anchor_boundary(), Some(h(444)));
        assert_eq!(tx(4).expiry_height(), h(999_004));
        assert!(matches!(tx(4).state(), MigrationTxState::Broadcast { .. }));
        assert_eq!(tx(5).scheduled_height(), h(2000));
        assert_eq!(tx(5).anchor_boundary(), Some(h(555)));
        assert_eq!(tx(5).expiry_height(), h(999_005));
        assert!(matches!(tx(5).state(), MigrationTxState::Mined { .. }));

        // (c): the preparation is completely untouched.
        assert_eq!(tx(0).scheduled_height(), h(500));
        assert_eq!(tx(0).anchor_boundary(), None);
        assert_eq!(tx(0).expiry_height(), h(999_990));

        let _ = std::fs::remove_file(&path);
    }

    /// Item (g): no stored migration row for the account -- returns `0`, not an error (the tip
    /// and natural-anchor lookups above the migration-row check must not themselves fail just
    /// because there is nothing to reschedule).
    #[test]
    fn debug_reschedule_transfers_with_no_stored_migration_returns_zero() {
        let path = init_fixture_db("zcashlc_migration_debug_reschedule_no_migration");
        let account = create_fixture_account(&path);
        scan_one_empty_fixture_block(&path);

        let path_bytes = path.to_str().unwrap().as_bytes();
        let rescheduled = unsafe {
            zcashlc_migration_debug_reschedule_transfers(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert_eq!(
            rescheduled, 0,
            "no migration row means nothing to reschedule"
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
            .get_migration()
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

    /// The test-side counterpart of [`prove_one`] for [`prove_pending_rows`]: proves through the
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
    ///
    /// History-inclusive (`latest_migration`, not the pending-only `get_migration`): a fixture
    /// whose last transaction the write under test promoted to `Mined` has by that act become
    /// terminal, and asserting on WHAT was written must not be defeated by the accessor that
    /// stops reporting a run once it is finished.
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

    /// `max_proofs` chunks a sweep: the first call proves exactly the cap and leaves the rest
    /// `Signed`; the next (uncapped) call finishes the remainder. This is the seam platforms use
    /// to interleave interactive DB reads between seconds-long proofs.
    #[test]
    fn sweep_cap_proves_at_most_max_and_the_next_call_finishes() {
        let path = init_fixture_db("zcashlc_sweep_cap_chunks");
        let account = create_fixture_account(&path);
        let mut state = provable_state(
            &[MINED],
            &[MigrationTxState::Signed, MigrationTxState::Signed],
            Some(h(1440)),
        );
        store_fixture_state(&path, &account, &state);

        let mut prover = RecordingProver { calls: Vec::new() };
        let first = prove_pending_rows(&mut state, h(5_000), Some(1), |state, id| {
            prove_with_test_prover(&path, &account, &mut prover, state, id)
        })
        .expect("a capped sweep must not fail");
        assert_eq!(first, 1, "the cap must stop the sweep after one proof");
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

        let second = prove_pending_rows(&mut state, h(5_000), None, |state, id| {
            prove_with_test_prover(&path, &account, &mut prover, state, id)
        })
        .expect("the follow-up sweep must not fail");
        assert_eq!(second, 1, "the uncapped follow-up must prove the remainder");
        assert_eq!(prover.calls.len(), 2, "two proofs total across the chunks");
    }

    /// The sweep proves a provable `Signed` transfer — `Signed -> Proved`, PERSISTED — against the
    /// boundary drawn on its row, and the delivery lane then serves that stored artifact WITHOUT
    /// consulting a prover: proving and broadcasting are separate steps.
    #[test]
    fn sweep_proves_a_signed_transfer_that_delivery_then_serves_without_proving() {
        let path = init_fixture_db("zcashlc_sweep_then_serve");
        let account = create_fixture_account(&path);
        let mut state = provable_state(&[MINED], &[MigrationTxState::Signed], Some(h(1440)));
        store_fixture_state(&path, &account, &state);

        let mut prover = RecordingProver { calls: Vec::new() };
        let proved = prove_pending_rows(&mut state, h(5_000), None, |state, id| {
            prove_with_test_prover(&path, &account, &mut prover, state, id)
        })
        .expect("sweeping a provable transfer must not fail");

        assert_eq!(proved, 1, "the sweep must prove the one provable row");
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

        // Delivery picks up the swept row, with the prover untouched.
        let calls_before = prover.calls.len();
        assert_eq!(
            next_due(&stored, DuenessTargets::at(h(5_000))),
            DueOutcome::Ready {
                id: MigrationTransferId::new(1)
            },
            "the proved, due row must be the one served"
        );
        assert_eq!(
            prover.calls.len(),
            calls_before,
            "the delivery lane must never consult a prover"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A due row that has not been proved yet is reported as `AwaitingProof` — NOT as "nothing
    /// due": the delivery lane refuses to prove, so the platform must be told that a sweep is what
    /// unblocks the broadcast, instead of polling an indefinitely empty lane.
    #[test]
    fn delivery_reports_a_due_unproven_row_as_awaiting_proof() {
        let state = provable_state(&[MINED], &[MigrationTxState::Signed], Some(h(1440)));

        assert_eq!(
            next_due(&state, DuenessTargets::at(h(5_000))),
            DueOutcome::AwaitingProof {
                id: MigrationTransferId::new(1)
            },
            "a due Signed row must report AwaitingProof, naming the row that needs the proof"
        );

        // And the artifact read refuses that row outright: an unproven row has nothing to serve.
        let err = serve_proved(&state, MigrationTransferId::new(1))
            .expect_err("an unproven row must not yield a broadcastable artifact");
        assert!(
            err.to_string().contains("not broadcastable"),
            "the refusal must name the lifecycle problem, got: {err}"
        );
    }

    /// A transient prover outcome (the anchor not scanned/retained yet) leaves the row `Signed`
    /// for a later sweep and is not an error — and, crucially, does not stop the sweep: the rows
    /// BEHIND the transiently-unprovable one are still proved on the same pass.
    #[test]
    fn sweep_skips_a_transiently_unprovable_row_and_proves_the_rest() {
        let path = init_fixture_db("zcashlc_sweep_transient");
        let account = create_fixture_account(&path);
        // Both transfers are provable and due; the prover fails the FIRST one transiently and
        // proves the second.
        let mut state = scheduled_state(
            &[MINED],
            &[
                (MigrationTxState::Signed, 90, Some(h(40))),
                (MigrationTxState::Signed, 90, Some(h(40))),
            ],
        );
        store_fixture_state(&path, &account, &state);

        let mut prover = FirstFailsProver {
            error: Some(WalletProveError::AnchorNotFound(h(40))),
            calls: Vec::new(),
        };
        let proved = prove_pending_rows(&mut state, h(100), None, |state, id| {
            prove_with_test_prover(&path, &account, &mut prover, state, id)
        })
        .expect("a transient prove outcome must not be an error");

        assert_eq!(
            proved, 1,
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
        let path = init_fixture_db("zcashlc_sweep_undue");
        let account = create_fixture_account(&path);
        // Provable (boundary settled) but scheduled far ABOVE the tip.
        let mut state =
            scheduled_state(&[MINED], &[(MigrationTxState::Signed, 9_000, Some(h(40)))]);
        store_fixture_state(&path, &account, &state);

        let mut prover = RecordingProver { calls: Vec::new() };
        let proved = prove_pending_rows(&mut state, h(100), None, |state, id| {
            prove_with_test_prover(&path, &account, &mut prover, state, id)
        })
        .expect("the sweep must not fail");

        assert_eq!(proved, 1, "the undue but provable row must be proved");
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
        // Still nothing to broadcast: proving does not make a row due.
        assert_eq!(
            next_due(&stored, DuenessTargets::at(h(100))),
            DueOutcome::Nothing,
            "a proved but unscheduled row must not be served"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// THE A1 BOUNDARY PIN: the sweep is driven at `target = tip + 1` (the height every
    /// `MigrationState` query is defined over — `zcashlc_migration_prove_pending` reads
    /// `ctx.target()`, not the raw tip), so a PREPARATION scheduled EXACTLY at the target is
    /// proved now rather than one block late. A preparation is the kind whose prove-readiness
    /// IS schedule due-ness, which is why the raw-tip regression only ever bit preparations; the
    /// raw-tip counterfactual is pinned alongside.
    #[test]
    fn sweep_proves_a_preparation_scheduled_exactly_at_target() {
        let tip = h(100);
        let build_state = || {
            custom_state(
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
            )
        };

        let mut prover = RecordingProver { calls: Vec::new() };
        let mut state = build_state();
        let proved = prove_pending_rows(&mut state, target_from_tip(tip), None, |state, id| {
            Ok(prove_due_for_test(&mut prover, state, id, Some(tip))?.is_some())
        })
        .expect("the boundary sweep must not fail");
        assert_eq!(
            proved, 1,
            "a preparation scheduled exactly at tip + 1 is due the sweep NOW"
        );
        assert_eq!(
            prover.calls,
            vec![ProveCall::Preparation(tip)],
            "the preparation proves against the caller-resolved anchor"
        );

        // The raw-tip counterfactual (the exact off-by-one A1 fixed): fed the tip instead of the
        // target, the same state sweeps nothing.
        let mut prover = RecordingProver { calls: Vec::new() };
        let mut state = build_state();
        let proved = prove_pending_rows(&mut state, tip, None, |state, id| {
            Ok(prove_due_for_test(&mut prover, state, id, Some(tip))?.is_some())
        })
        .expect("the counterfactual sweep must not fail");
        assert_eq!(
            proved, 0,
            "at the raw tip the target-scheduled preparation is (wrongly) not yet due — the \
             convention the FFI must therefore never feed the sweep"
        );
    }

    /// A HARD prover failure aborts the sweep and propagates: an unprovable-for-real row is not
    /// something a later sweep fixes, and swallowing it would hide a corrupt store.
    #[test]
    fn sweep_propagates_a_hard_prover_failure() {
        let path = init_fixture_db("zcashlc_sweep_hard_failure");
        let account = create_fixture_account(&path);
        let mut state = provable_state(&[MINED], &[MigrationTxState::Signed], Some(h(1440)));
        store_fixture_state(&path, &account, &state);

        let mut prover = FailingProver {
            error: Some(WalletProveError::Prove("proof backend failure".into())),
        };
        let err = prove_pending_rows(&mut state, h(5_000), None, |state, id| {
            prove_with_test_prover(&path, &account, &mut prover, state, id)
        })
        .expect_err("a hard prover failure must not be swallowed");

        assert!(
            err.to_string().starts_with(PROVING_UNAVAILABLE_PREFIX),
            "the hard failure must carry the proving-unavailable prefix, got: {err}"
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

    // ----- engine target-height boundary (F2): `next_broadcastable`/`next_provable`/
    // `expired_transactions` are all defined over `target = tip + 1`, never the raw tip -----

    /// Engine semantics: `next_broadcastable` is defined over `target = tip + 1` (the height of
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

    /// 3. Reconciliation runs at the head of this read too (the same convention as
    /// [`zcashlc_migration_advance_step`]): a stored `Broadcast` transfer whose txid the WALLET's own
    /// `transactions` table now shows mined is reported — and PERSISTED — as `Mined`, not
    /// `Broadcast`. Mirrors
    /// [`resolve_immediate_run_reads_mined_and_expiry_from_transactions_table`]'s technique of
    /// inserting directly into a `transactions` table, but against the REAL wallet schema (that
    /// test's table is a hand-rolled two-column stand-in; `ctx.wallet.get_tx_height` reads the
    /// real `zcash_client_sqlite` schema, so this fixture inserts the columns that schema
    /// requires: `txid`, `mined_height`, and the `NOT NULL` `min_observed_height`).
    #[test]
    fn migration_transaction_statuses_reconciles_a_mined_broadcast_transfer() {
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
            row.state, 4,
            "the row must report Mined once the wallet shows it mined"
        );
        assert_eq!(
            row.mined_height,
            i64::from(mined_at),
            "the reported mined height must be the wallet's"
        );
        assert!(row.has_txid, "the mined lifecycle state retains its txid");
        assert_eq!(row.txid, txid, "the mined lifecycle state retains its txid");
        unsafe { zcashlc_free_migration_transaction_statuses(statuses_ptr) };

        // The reconciliation must be PERSISTED, not just reported for this one read — the
        // read-path convention every sibling read follows.
        let stored = read_fixture_state(&path, &account);
        let stored_tx = stored
            .transactions()
            .iter()
            .find(|t| t.id() == MigrationTransferId::new(0))
            .expect("the row remains stored");
        assert!(
            matches!(
                stored_tx.state(),
                MigrationTxState::Mined { height, .. } if height == h(mined_at)
            ),
            "reconciliation must persist Broadcast -> Mined"
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

    /// Reads one advance step over the FFI, asserting success, and frees the DTO after copying it
    /// out (every field is plain data).
    fn read_advance_step(path_bytes: &[u8], account: &[u8; 16]) -> (u32, u32, bool, u32, u32, u32) {
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
            !ptr.is_null(),
            "a stored run must yield a step, not NULL: {:?}",
            ffi_helpers::error_handling::error_message()
        );
        let step = unsafe { &*ptr };
        let out = (
            step.step,
            step.id,
            step.kind_is_preparation,
            step.kind_layer,
            step.kind_index,
            step.kind_crossing,
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

    /// A provable PREPARATION reports `Prove` with `kind_is_preparation` and its layer/index —
    /// carried natively by upstream's `AdvanceStep::Prove { id, kind }`, no stored-row lookup
    /// involved.

    /// A provable TRANSFER reports `Prove` with its crossing index populated.

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

    fn has_ready_broadcast(path_bytes: &[u8], account: &[u8; 16], estimated_tip: i64) -> i32 {
        unsafe {
            zcashlc_migration_has_ready_broadcast(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
                estimated_tip,
            )
        }
    }

    // ----- the sync-gate predicate (`zcashlc_migration_has_ready_broadcast`) -----

    /// THE A2 WEDGE PIN: a `Signed`, schedule-due, prove-ready transfer is overdue DELIVERY work
    /// (`has_overdue_transfers` answers `true` — a sweep plus a broadcast will discharge it) but
    /// must NOT gate sync (`has_ready_broadcast` answers `0`): it needs MORE syncing/proving
    /// before a broadcast session can do anything with it, so a gate keyed on it would wedge —
    /// sync withheld for a broadcast that cannot be served until sync proceeds.
    #[test]
    fn has_ready_broadcast_signed_due_row_answers_no_while_overdue_answers_yes() {
        let path = init_fixture_db("zcashlc_ready_broadcast_signed");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        set_fixture_tip(path_bytes);
        // Signed, due, boundary settled — `has_overdue_transfers_reports_a_due_signed_transfer`'s
        // exact fixture.
        let state = test_state(
            MigrationStatus::InProgress,
            &[],
            &[MigrationTxState::Signed],
            3_499_000,
            4_000_000,
        );
        store_fixture_state(&path, &account, &state);

        assert!(
            has_overdue(path_bytes, &account, -1),
            "sanity: the due Signed row IS overdue delivery work"
        );
        assert_eq!(
            has_ready_broadcast(path_bytes, &account, -1),
            0,
            "a Signed row — even a due one — must never block sync (the A2 wedge)"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The gate's yes-case and its exclusions: a `Proved`, due row answers `1`; the same row
    /// marked `Invalid` answers `0` (a dead transfer gates nothing); no stored run answers `0`.

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

    /// The delivery lane and the sync-gate predicate honour the same doomed-broadcast withhold: a
    /// proved, scanned-due row whose expiry only the ESTIMATED target has passed is NOT served by
    /// the delivery decision ([`next_due`], and over the FFI
    /// [`zcashlc_migration_next_due_transfer`] answers `NothingDue`) and does NOT gate sync via
    /// [`zcashlc_migration_has_ready_broadcast`] — while without the estimate both serve it.
    #[test]
    fn next_due_transfer_and_ready_broadcast_withhold_a_doomed_broadcast() {
        let path = init_fixture_db("zcashlc_next_due_doomed");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        set_fixture_tip(path_bytes);
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

        // The pure delivery decision: served on the scanned view, withheld under the estimate.
        assert_eq!(
            next_due(&state, dueness_targets(scanned_tip, -1)),
            DueOutcome::Ready {
                id: MigrationTransferId::new(0)
            },
            "without the estimate the proved, due, unexpired row is served"
        );
        assert_eq!(
            next_due(&state, dueness_targets(scanned_tip, 3_700_000)),
            DueOutcome::Nothing,
            "under the estimate the doomed broadcast is withheld from the delivery lane"
        );

        // The same withhold over the FFI: the delivery call answers the benign NothingDue (it
        // never reaches the artifact read), and the sync gate stops gating.
        let ptr = unsafe {
            zcashlc_migration_next_due_transfer(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
                3_700_000,
            )
        };
        assert!(
            !ptr.is_null(),
            "the withheld delivery answer is not an error"
        );
        assert!(
            matches!(
                unsafe { &*ptr }.status,
                FfiPreparedTransferStatus::MigrationNothingDue
            ),
            "the doomed row must read as NothingDue under the estimate"
        );
        unsafe { zcashlc_free_migration_prepared_transfer(ptr) };
        assert_eq!(
            has_ready_broadcast(path_bytes, &account, -1),
            1,
            "without the estimate the row gates sync (a broadcast is servable right now)"
        );
        assert_eq!(
            has_ready_broadcast(path_bytes, &account, 3_700_000),
            0,
            "the doomed row must not gate sync: serving it would only earn a rejection"
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

    /// The delivery lane mirrors the same acceleration: a `Signed`, provable transfer scheduled
    /// past the scanned target is `NothingDue` without the estimate and `AwaitingProof` with it
    /// (the boundary-settle check stays scanned-side — the fixture's boundary IS settled).
    #[test]
    fn next_due_transfer_estimated_tip_reports_awaiting_proof() {
        let path = init_fixture_db("zcashlc_next_due_estimate");
        let path_bytes = path.to_str().unwrap().as_bytes();
        let account = create_fixture_account(&path);
        set_fixture_tip(path_bytes);
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

        let read_status = |estimated_tip: i64| {
            let ptr = unsafe {
                zcashlc_migration_next_due_transfer(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    account.as_ptr(),
                    NETWORK_ID_MAINNET,
                    estimated_tip,
                )
            };
            assert!(!ptr.is_null(), "next_due_transfer must not error");
            let transfer = unsafe { &*ptr };
            let out = (
                matches!(
                    transfer.status,
                    FfiPreparedTransferStatus::MigrationNothingDue
                ),
                matches!(
                    transfer.status,
                    FfiPreparedTransferStatus::MigrationAwaitingProof
                ),
                transfer.id,
            );
            unsafe { zcashlc_free_migration_prepared_transfer(ptr) };
            out
        };

        let (nothing, awaiting, _) = read_status(-1);
        assert!(
            nothing && !awaiting,
            "without an estimate the future-scheduled row is not due"
        );
        let (nothing, awaiting, id) = read_status(3_600_010);
        assert!(
            !nothing && awaiting,
            "under the estimate the due-but-unproved row must report AwaitingProof"
        );
        assert_eq!(id, 0, "the awaiting row must be named");
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
}
