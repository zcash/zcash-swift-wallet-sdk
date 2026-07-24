//! FFI over the final Orchard→Ironwood pool-migration engine
//! ([`zcash_pool_migration_backend`] + the `zcash_client_sqlite::pool_migration` store).
//!
//! The engine is a set of free functions over traits — [`crate::migration_engine::Backend`] wires
//! this SDK's wallet database (and the account-keyed migration store living inside it) into them;
//! [`crate::migration_finalize`] proves transactions at broadcast time (ZIP 374 deferred
//! anchors/witnesses, resolved through the upstream prover — transfers against their drawn
//! ZIP 318 boundary anchor, preparations against the natural anchor; see its module doc);
//! [`crate::migration_plan_cache`] carries the previewed plan from propose to commit.
//! This module keeps the platform-facing C ABI of the v1 integration: the same entry points, the
//! same `#[repr(C)]` DTOs, the same sentinels — the engine swap is absorbed here, with two
//! deliberate exceptions (the external-signer note-split pair went plural, because the engine
//! builds N preparation transactions rather than one split transaction).
//!
//! Semantics that moved into this layer (the v1 crate did them internally):
//! - The public 5-state machine is DERIVED (see [`derive_state`]): the v1 crate's `ReadyToPropose`
//!   state and `SyncRequiredBeforeNext` attention reason are gone entirely (the engine commits the
//!   split and the schedule atomically, so that intermediate moment cannot occur), and `Complete`
//!   is PER-RUN — "the stored run is fully mined", never "nothing left to migrate". After
//!   completion the platform asks `zcashlc_migration_propose_transfers` whether anything remains
//!   (an empty schedule means no).
//! - Mined-transaction reconciliation ([`reconcile_mined`]) runs at the head of every read.
//! - Rejection classification is recorded in the SDK-owned `sdk_invalid_marks` side table (the
//!   engine has no failure states).
//! - The immediate lane (an ordinary send-max sweep, entirely outside the engine) is tracked in
//!   its own SDK-owned `sdk_immediate_runs` side table and folded into [`derive_state`]: while
//!   unmined it derives `InProgress` (flagged `is_immediate`); once mined it is CONSUMED — it
//!   derives nothing and masks any stale engine `Complete`, so the aftermath stays quiet — and past
//!   its expiry it is ignored. See that function's precedence rule.
//!
//! Error channel: failures land in the thread-local last-error message. Two stable prefixes let
//! the Swift layer surface dedicated errors: `MIGRATION_PLAN_STALE:` (commit without a matching
//! cached proposal — re-propose) and `MIGRATION_PROVING_UNAVAILABLE:` (proving failed hard).
//! Pointer-returning functions yield NULL on error, `bool`-returning functions `false`, and the
//! `i64` sentinels are documented per function.
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
use zcash_client_backend::data_api::{InputSource, WalletRead, WalletWrite};
use zcash_client_backend::wallet::{LockOwner, OutputRef};
use zcash_client_sqlite::AccountUuid;
use zcash_protocol::consensus::{
    BLOCKS_PER_HOUR, BlockHeight, Network, NetworkConstants, NetworkUpgrade, Parameters,
};
use zcash_protocol::value::Zatoshis;
use zcash_protocol::{PoolType, ShieldedPool, TxId};

use zcash_pool_migration_backend::engine::{
    self, MigrationPlan, MigrationState, MigrationStatus, MigrationTransaction, MigrationTxId,
    MigrationTxKind, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
};
use zcash_pool_migration_backend::state::{Blocker, NextAction, TransactionStatus};
use zcash_pool_migration_backend::wallet::WalletMigrationProver;

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

/// Decode a decimal transaction-id string (`MigrationTxId` raw value) from a C string.
fn transfer_id_from_c(id: *const c_char) -> anyhow::Result<MigrationTxId> {
    if id.is_null() {
        return Err(anyhow!("transfer_id is null"));
    }
    let raw = unsafe { CStr::from_ptr(id) }
        .to_str()
        .map_err(|e| anyhow!("transfer id is not valid UTF-8: {e}"))?;
    let idx: u32 = raw
        .parse()
        .map_err(|e| anyhow!("invalid transfer id {raw}: {e}"))?;
    Ok(MigrationTxId::new(idx))
}

/// The engine's target height for a given chain tip: `tip + 1`, the height of the next block.
/// Every [`MigrationState`] query (`next_provable`, `next_broadcastable`, `expired_transactions`)
/// is defined over this height, never the raw tip — see [`CallCtx::target`], the primary way
/// callers reach this from a live wallet handle. Exposed as a pure function too for the rare
/// caller (like [`derive_state`]) that already holds a `tip` value rather than a [`CallCtx`].
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
/// drops it at the end (no persistent handle). The engine's store tables are created by the wallet
/// schema migrations during `init_data_db` (`zcash_client_sqlite::pool_migration` registers them);
/// only the SDK's own side tables are ensured idempotently here.
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
    let store_conn = open_store_conn(&db_path)?;
    init_invalid_marks(&store_conn)
        .map_err(|e| anyhow!("Error initializing migration marks table: {e}"))?;
    init_immediate_runs(&store_conn)
        .map_err(|e| anyhow!("Error initializing immediate-run table: {e}"))?;
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

// ----- SDK-owned invalid-transfer marks -----
//
// The engine has no failure states: a rejected broadcast leaves the transaction `Signed`/`Proved`
// and re-offered. The platform's rejection classifier distinguishes terminal rejections
// (invalid-note, expired) from retryable ones; the terminal ones are recorded here so
// `zcashlc_migration_has_invalid_transfers` / the `RequiresAttention` derivation can surface
// them. Cleared when the run is cancelled (`zcashlc_migration_restart_step`).

fn init_invalid_marks(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sdk_invalid_marks (
            account_uuid BLOB NOT NULL,
            tx_id INTEGER NOT NULL,
            reason TEXT NOT NULL,
            PRIMARY KEY (account_uuid, tx_id)
        )",
    )
}

fn insert_invalid_mark(
    conn: &Connection,
    account: &[u8; 16],
    id: MigrationTxId,
    reason: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO sdk_invalid_marks (account_uuid, tx_id, reason) VALUES (?1, ?2, ?3)
         ON CONFLICT(account_uuid, tx_id) DO UPDATE SET reason = excluded.reason",
        rusqlite::params![&account[..], u32::from(id), reason],
    )?;
    Ok(())
}

fn invalid_marks(conn: &Connection, account: &[u8; 16]) -> rusqlite::Result<Vec<u32>> {
    let mut stmt =
        conn.prepare("SELECT tx_id FROM sdk_invalid_marks WHERE account_uuid = ?1 ORDER BY tx_id")?;
    let rows = stmt.query_map(rusqlite::params![&account[..]], |row| row.get::<_, u32>(0))?;
    rows.collect()
}

fn clear_invalid_marks(conn: &Connection, account: &[u8; 16]) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM sdk_invalid_marks WHERE account_uuid = ?1",
        rusqlite::params![&account[..]],
    )?;
    Ok(())
}

// ----- SDK-owned immediate-migration-run record -----
//
// The immediate lane (an ordinary send-max sweep to the account's own unified address, built
// entirely outside the engine — see `zcashlc_propose_send_max_transfer`) has no engine-tracked
// plan, preparation, or schedule at all: from the engine's point of view nothing happened. This
// one-row-per-account table is the SDK's own record that a sweep was broadcast, so `derive_state`
// can still report its progress the way an engine-tracked transfer would: the stored txid is
// resolved against the wallet database's own transaction history by `resolve_immediate_run`
// (mined -> `Complete`, unmined -> `InProgress`) — the same kind of wallet-DB access
// `reconcile_mined` uses to advance an engine-tracked transaction from `Broadcast` to `Mined`, here
// extended to also read the expiry height that `WalletRead` does not expose on its own. See the
// precedence rule documented on `derive_state` for how this interacts with an engine-tracked run.

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
/// record time (the fallback expiry bound `derive_state` uses when the wallet database does not
/// know, or no longer knows, the transaction's real expiry height).
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
/// (which errors on a not-yet-synced wallet — see the callers in `zcashlc_migration_state` /
/// `zcashlc_migration_progress`).
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

/// Marks as mined every `Broadcast` transaction whose txid the wallet has since observed on-chain,
/// persisting once if anything changed, and returns the freshest state (or `None` when no
/// migration is stored). This is the v1 crate's internal reconciliation, now SDK-owned: it is the
/// only way transactions advance `Broadcast -> Mined` (and therefore the only way a run reaches
/// `Complete`).
fn reconcile_mined(ctx: &mut CallCtx) -> anyhow::Result<Option<MigrationState>> {
    let mut backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?;
    let Some(mut state) = backend.get_migration()? else {
        return Ok(None);
    };
    if state.is_terminal() {
        return Ok(Some(state));
    }
    let broadcast: Vec<(MigrationTxId, [u8; 32])> = state
        .transactions()
        .iter()
        .filter_map(|t| match t.state() {
            MigrationTxState::Broadcast { .. } => {
                t.state().broadcast_txid().map(|txid| (t.id(), txid))
            }
            _ => None,
        })
        .collect();
    let mut changed = false;
    for (id, txid) in broadcast {
        if let Some(height) = ctx
            .wallet
            .get_tx_height(TxId::from_bytes(txid))
            .map_err(|e| anyhow!("mined-height lookup failed: {e}"))?
        {
            state.mark_mined(id, height);
            changed = true;
        }
    }
    if changed {
        backend.replace_migration(&state)?;
    }
    Ok(Some(state))
}

/// Computes a fresh preview plan against the account's live balance and caches it (a later commit
/// signs exactly this plan, not an independently re-randomized one).
///
/// Returns the plan alongside the SAME reference height that got cached with it — every caller
/// that encodes a schedule from this plan must reuse THIS height rather than reading `ctx.tip()`
/// again: a block landing between an internal re-read and the cached value can flip an hour
/// bucket and make an honest pre-commit echo fail with `MIGRATION_PLAN_STALE`.
///
/// Returns `Ok(None)` when there is nothing to migrate (the balance is zero, or entirely below the
/// dust floor) — the "ask rust whether anything remains" answer after a completed run.
fn plan_and_cache(ctx: &mut CallCtx) -> anyhow::Result<Option<(MigrationPlan, BlockHeight)>> {
    let backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?;
    let mut rng = OsRng;
    match engine::plan_migration(&ctx.network, &backend, &mut rng) {
        Ok(plan) => {
            // `plan_migration` itself just resolved the tip internally (`chain_tip_height`) to
            // plan against, so this can't newly fail here; it just makes the same value available
            // to cache alongside the plan and to every caller that encodes from it.
            let reference_height = ctx.tip()?;
            migration_plan_cache::set(
                ctx.db_path.clone(),
                ctx.account_bytes,
                plan.clone(),
                reference_height,
            );
            Ok(Some((plan, reference_height)))
        }
        Err(engine::MigrationError::NothingToMigrate) => Ok(None),
        Err(e) => Err(anyhow!("Error planning migration: {e}")),
    }
}

/// The row set the platform sees for a plan's transfer schedule: `(engine tx id, amount, broadcast
/// height, expiry height)`, sorted chronologically by broadcast height.
///
/// - `amount` is the engine's authoritative crossing value — `NoteSplitPlan::crossing_values()[i]`
///   (F3) — the NET value that crosses the turnstile when the funding note at the same index is
///   spent (see `crossing_values`'s doc: "the denomination values ... that will cross the
///   turnstile ... when the note at the same index is spent"). It is index-aligned with
///   `funding_notes()`/`schedule()` by construction: `funding_notes()` (`migration_outputs()`) maps
///   `crossing_values()` 1:1 (each funding note is `crossing_values()[i] + note_fee_buffer`), so
///   reading `crossing_values()[i]` directly pairs correctly with schedule entry `i` — no
///   re-derivation (`funding_notes()[i] - note_fee_buffer`) needed.
/// - The engine numbers every preparation transaction first, then transfers in `schedule()`
///   order, so transfer `i`'s real committed id is `prep_tx_count + i`.
/// - The sort makes the platform's row order chronological: ZIP 318 SHUFFLE deliberately makes
///   funding-note order differ from broadcast order.
fn schedule_rows(
    crossing_values: &[Zatoshis],
    schedule: &[zcash_pool_migration_backend::scheduling::Schedule],
    prep_tx_count: u32,
) -> anyhow::Result<Vec<(MigrationTxId, Zatoshis, BlockHeight, BlockHeight)>> {
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
        .map(|(i, (crossing_value, entry))| {
            (
                MigrationTxId::new(prep_tx_count + i as u32),
                *crossing_value,
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

/// Marshal a plan into the platform's schedule DTO. `now_reference` (the tip at encode time) fills
/// the DTO's `anchor_height` field: with ZIP 374 the real anchor is drawn per transfer and
/// installed at proving time, so the field now carries the "now" height the platform's duration
/// math measures waits from — it is NOT a commitment-tree anchor.
fn encode_schedule_from_plan(
    plan: &MigrationPlan,
    now_reference: BlockHeight,
) -> anyhow::Result<*mut FfiMigrationSchedule> {
    let rows = schedule_rows(
        plan.note_split().crossing_values(),
        plan.schedule(),
        prep_tx_count(plan),
    )?;
    let transfers = rows
        .into_iter()
        .map(|(id, amount, broadcast, expiry)| {
            Ok(FfiTransferProposal {
                id: cstring_raw(&u32::from(id).to_string(), "transfer proposal id")?,
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
    let (transfers, transfers_len) = ptr_from_vec(transfers);
    Ok(Box::into_raw(Box::new(FfiMigrationSchedule {
        transfers,
        transfers_len,
        estimated_duration_hours: estimated,
    })))
}

/// An empty schedule: the "nothing to migrate" answer (also the post-completion "nothing remains"
/// answer the platform's sequential-run check consumes).
fn encode_empty_schedule() -> *mut FfiMigrationSchedule {
    Box::into_raw(Box::new(FfiMigrationSchedule {
        transfers: ptr::null_mut(),
        transfers_len: 0,
        estimated_duration_hours: 0,
    }))
}

// ----- verified consent echoes (F4) -----
//
// `zcashlc_migration_sign_and_store_schedule` and `zcashlc_migration_create_unsigned_transfer_pczts`
// take back the transfer schedule the platform displayed and got the user's consent for — the same
// shape `zcashlc_migration_propose_transfers`/`_immediate_transfers` returned. These are verified
// consent echoes: the values the user approved must match what is about to be signed, or the call
// fails with the `MIGRATION_PLAN_STALE:` prefix (the app's existing recovery — re-propose/re-read
// and re-display — reused rather than adding a new error route).

/// One transfer's consent-echo fields, checked against the CACHED preview plan (before commit —
/// see [`validate_schedule_echo_against_cache`]). `anchor_height` is deliberately excluded from
/// this comparison: it is a display-only "now" reference at encode time (see
/// `FfiTransferProposal::anchor_height`'s doc — "callers must not treat it as one"), not a value
/// any transaction commits to, and the stored (post-commit) state has no durable record of it to
/// compare against. For the POST-COMMIT comparison against stored state, see [`StoredEchoRow`],
/// which additionally excludes `next_executable_after_height`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EchoRow {
    id: u32,
    amount: i64,
    next_executable_after_height: i64,
    expiry_height: i64,
}

/// One transfer's consent-echo fields, checked against the STORED (post-commit) migration state
/// (see [`validate_schedule_echo_against_state`]). Unlike [`EchoRow`], `next_executable_after_height`
/// is absent here — not just unchecked, structurally not part of the comparison — because a
/// stored transfer's scheduled height can legitimately move after the platform captured its
/// display copy: `zcashlc_migration_refresh_stale_transfers` rebuilds an expired transfer with a
/// FRESH scheduled height drawn from the current tip (the whole point of the rebuild). An honest,
/// unmodified echo of what the platform last displayed would then mismatch the stored state on
/// this field alone — and unlike a genuinely stale plan, re-proposing can never converge here:
/// the STORED value is already fixed by the committed run, and re-proposing never re-touches it.
/// So comparing this field post-commit would surface `MIGRATION_PLAN_STALE` on a correct echo
/// with no recovery path, which is worse than not checking it (the refresh call returns the
/// fresh schedule precisely so the platform can re-display and re-echo it). `ids`/`amounts`/
/// `expiry_heights` are pinned at commit and never silently rewritten under an unchanged run.
///
/// `estimated_duration_hours` (returned alongside these rows, not a field of this struct — see
/// [`expected_rows_from_state`]) has the SAME problem since #1806 and is excluded from the
/// STATE-side comparison for the same reason: measured as `max(scheduled) - now` (see
/// [`stored_duration_hours`]), it is derived, serve-time-relative DISPLAY metadata, not a value an
/// honest echo can be expected to reproduce exactly — the `now` behind whatever value the platform
/// is echoing back can differ (in either direction) from `now` at validation time, and unlike
/// [`expected_rows_from_cached_plan`]'s PRE-commit path (where `cached.reference_height` survives
/// to reproduce the original value byte-for-byte, so duration is still checked there exactly — see
/// [`schedule_echo_matches`]'s `_detects_wrong_duration` test), there is no reference height
/// surviving a commit to reconstruct here. The consent-stable surface once a run is stored is
/// `ids`/`amounts`/`expiry_heights`; display-drift detection on duration stays at the pre-commit
/// consent moment, where a stable reference actually exists to detect it against.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StoredEchoRow {
    id: u32,
    amount: i64,
    expiry_height: i64,
}

/// The consent-echo rows and duration `zcashlc_migration_propose_transfers` returned for the
/// cached plan, reconstructed byte-for-byte from the cache: the plan is deterministic — ids,
/// net amounts, drawn broadcast heights, and expiries never move between propose and commit for
/// the scheduled lane, so no row-level tip re-read is involved. (The immediate lane is an
/// ordinary send-max sweep outside the engine and never touches the plan cache — see the module
/// doc.) The duration is, since #1806, measured from `cached.reference_height` (the ORIGINAL
/// propose-time `now`, see [`estimated_duration_hours`]) rather than a freshly re-read tip: it is
/// exactly what `encode_schedule_from_plan` used to compute the value this call reproduces, byte
/// for byte. This PRE-commit path is also, since #1806, the ONLY place
/// `estimated_duration_hours` is still checked as a verified consent echo — see
/// [`StoredEchoRow`]'s doc for why the POST-commit (STORED-state) path deliberately excludes it
/// instead of re-deriving a value that could disagree here.
fn expected_rows_from_cached_plan(
    cached: &migration_plan_cache::CachedPlan,
) -> anyhow::Result<(Vec<EchoRow>, u32)> {
    let rows = schedule_rows(
        cached.plan.note_split().crossing_values(),
        cached.plan.schedule(),
        prep_tx_count(&cached.plan),
    )?;
    let duration = estimated_duration_hours(
        cached.plan.schedule().iter().map(|e| e.broadcast_height()),
        cached.reference_height,
    );
    let rows = rows
        .into_iter()
        .map(|(id, amount, broadcast, expiry)| EchoRow {
            id: u32::from(id),
            amount: zat_to_i64(amount),
            next_executable_after_height: i64::from(u32::from(broadcast)),
            expiry_height: i64::from(u32::from(expiry)),
        })
        .collect();
    Ok((rows, duration))
}

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
/// ([`encode_schedule_from_state`]) to compute the value the platform displays. NOT used by the
/// consent-echo expectation ([`expected_rows_from_state`]) — see [`StoredEchoRow`]'s doc for why
/// duration is excluded from that comparison entirely, post-#1806. Empty, or every height
/// at/behind `now`, is `0` (saturating, never underflows).
fn stored_duration_hours(transfers: &[&MigrationTransaction], now: BlockHeight) -> u32 {
    let now = u32::from(now);
    transfers
        .iter()
        .map(|t| u32::from(t.scheduled_height()))
        .max()
        .map_or(0, |max| max.saturating_sub(now) / BLOCKS_PER_HOUR)
}

/// The consent-echo rows for the stored run's TRANSFER subset — the values a commit call
/// validates the platform's echo against once a run is committed (there is no cache to consult
/// post-commit; this is ALWAYS the ground truth of what is about to be signed, whether the run
/// was just now committed fresh or is being resumed). Returns [`StoredEchoRow`]s (no
/// `next_executable_after_height`, and no duration — see [`StoredEchoRow`]'s doc for why both are
/// excluded from this comparison entirely).
fn expected_rows_from_state(state: &MigrationState) -> Vec<StoredEchoRow> {
    let transfers = stored_transfers(state);
    transfers
        .iter()
        .filter_map(|t| {
            transfer_amount(state, t).map(|amount| StoredEchoRow {
                id: u32::from(t.id()),
                amount: zat_to_i64(amount),
                expiry_height: i64::from(u32::from(t.expiry_height())),
            })
        })
        .collect()
}

/// Marshal the STORED run's full transfer subset into the platform's schedule DTO — the
/// post-commit counterpart of [`encode_schedule_from_plan`], read from persisted state instead of
/// a previewed plan. Every transfer of the run is included (mined ones too: the state-side
/// consent echo, [`validate_schedule_echo_against_state`], compares the FULL subset, and this DTO
/// is what the host re-displays and later echoes), sorted chronologically by stored scheduled
/// height; `anchor_height` carries the same display-only "now" reference as the plan-side
/// encoding, and the duration is derived from `now_reference` and the stored scheduled heights via
/// [`stored_duration_hours`] — re-serving later naturally reports a smaller duration; that is
/// intended (see [`stored_duration_hours`]'s doc). `estimated_duration_hours` is display-only here:
/// the consent-echo validation this DTO is later checked against does NOT re-derive or compare it
/// (see [`StoredEchoRow`]'s doc for why).
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
                id: cstring_raw(&u32::from(t.id()).to_string(), "transfer proposal id")?,
                amount: zat_to_i64(amount),
                anchor_height: i64::from(u32::from(now_reference)),
                next_executable_after_height: i64::from(u32::from(t.scheduled_height())),
                expiry_height: i64::from(u32::from(t.expiry_height())),
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let (transfers, transfers_len) = ptr_from_vec(rows);
    Ok(Box::into_raw(Box::new(FfiMigrationSchedule {
        transfers,
        transfers_len,
        estimated_duration_hours: estimated,
    })))
}

/// Decode the platform's parallel echo arrays into [`EchoRow`]s (the CACHE-side shape, including
/// `next_executable_after_height`). A decode failure (e.g. a non-UTF8 or non-numeric id string)
/// propagates as a plain error — a malformed echo, not a semantic mismatch, so it is deliberately
/// NOT routed through the `MIGRATION_PLAN_STALE` prefix.
fn decode_echo_rows(
    ids: &[*const c_char],
    amounts: &[i64],
    next_executable_after_heights: &[i64],
    expiry_heights: &[i64],
) -> anyhow::Result<Vec<EchoRow>> {
    ids.iter()
        .enumerate()
        .map(|(i, &id_ptr)| {
            Ok(EchoRow {
                id: u32::from(transfer_id_from_c(id_ptr)?),
                amount: amounts[i],
                next_executable_after_height: next_executable_after_heights[i],
                expiry_height: expiry_heights[i],
            })
        })
        .collect()
}

/// Decode the platform's parallel echo arrays into [`StoredEchoRow`]s (the STORED-state shape —
/// no `next_executable_after_height`; see its doc). Same decode-failure handling as
/// [`decode_echo_rows`].
fn decode_stored_echo_rows(
    ids: &[*const c_char],
    amounts: &[i64],
    expiry_heights: &[i64],
) -> anyhow::Result<Vec<StoredEchoRow>> {
    ids.iter()
        .enumerate()
        .map(|(i, &id_ptr)| {
            Ok(StoredEchoRow {
                id: u32::from(transfer_id_from_c(id_ptr)?),
                amount: amounts[i],
                expiry_height: expiry_heights[i],
            })
        })
        .collect()
}

/// Whether the platform's echoed transfer-schedule consent values match `expected`,
/// order-independent (both sides are sorted by id — the platform's own display order never
/// matters here). CACHE-side (see [`EchoRow`]).
fn schedule_echo_matches(
    mut expected: Vec<EchoRow>,
    expected_duration_hours: u32,
    mut got: Vec<EchoRow>,
    estimated_duration_hours: u32,
) -> bool {
    expected.sort();
    got.sort();
    expected == got && expected_duration_hours == estimated_duration_hours
}

/// Whether the platform's echoed transfer-schedule consent values match `expected`,
/// order-independent. STORED-state side (see [`StoredEchoRow`] — neither
/// `next_executable_after_height` nor a duration is part of either side's row, by construction:
/// see [`StoredEchoRow`]'s doc for why both are excluded from the STATE-side comparison).
fn stored_schedule_echo_matches(
    mut expected: Vec<StoredEchoRow>,
    mut got: Vec<StoredEchoRow>,
) -> bool {
    expected.sort();
    got.sort();
    expected == got
}

/// Whether the platform's echoed note-split consent values (`zcashlc_migration_sign_note_split`'s
/// `output_values`/`fee`) match the previewed plan's note split: the output values
/// order-independent (the platform may display them in any order), the fee exactly.
fn note_split_echo_matches(
    expected_outputs: &[i64],
    expected_fee: i64,
    mut got_outputs: Vec<i64>,
    got_fee: i64,
) -> bool {
    let mut expected_outputs = expected_outputs.to_vec();
    expected_outputs.sort_unstable();
    got_outputs.sort_unstable();
    expected_outputs == got_outputs && expected_fee == got_fee
}

/// Validates the platform's echoed transfer-schedule values against the plan cached for this
/// account — the values `zcashlc_migration_propose_transfers`/`_immediate_transfers` returned.
/// `Ok(())` when nothing is cached: that is the resume case (a run is already stored, so there is
/// nothing "about to commit" to check the echo against here); `commit_or_resume`'s own cache
/// lookup handles the "neither a cache nor a stored run" case.
#[allow(clippy::too_many_arguments)]
fn validate_schedule_echo_against_cache(
    db_path: &PathBuf,
    account_bytes: [u8; 16],
    ids: &[*const c_char],
    amounts: &[i64],
    next_executable_after_heights: &[i64],
    expiry_heights: &[i64],
    estimated_duration_hours: u32,
) -> anyhow::Result<()> {
    let Some(cached) = migration_plan_cache::get(db_path, account_bytes) else {
        return Ok(());
    };
    let (expected, expected_duration) = expected_rows_from_cached_plan(&cached)?;
    if ids.len() != expected.len() {
        return Err(plan_stale(&format!(
            "the echoed schedule has {} transfer(s) but the previewed plan has {} — propose again",
            ids.len(),
            expected.len()
        )));
    }
    let got = decode_echo_rows(ids, amounts, next_executable_after_heights, expiry_heights)?;
    if !schedule_echo_matches(expected, expected_duration, got, estimated_duration_hours) {
        return Err(plan_stale(
            "the echoed schedule does not match the previewed plan — propose again",
        ));
    }
    Ok(())
}

/// Validates the platform's echoed transfer-schedule values against the run's STORED, already
/// committed transfer subset — the source of truth once a run exists (there is no cache to consult
/// post-commit). Two of the five echoed values are accepted but deliberately NOT compared here —
/// see [`StoredEchoRow`]'s doc for why both are structurally excluded, not just unchecked:
/// - `next_executable_after_heights`: the immediate lane's commit-time reschedule can legitimately
///   move this value away from what the platform honestly previewed and is echoing back, and
///   unlike an actually stale plan there is no way to converge on a match by re-proposing (the
///   stored value is already fixed by the completed commit).
/// - `estimated_duration_hours` (#1806): post-fix it is derived, serve-time-relative display
///   metadata (`max(scheduled) - now`), not a value with a stable pre-commit reference surviving
///   here to reproduce byte-for-byte the way [`expected_rows_from_cached_plan`]'s cached
///   `reference_height` still does PRE-commit.
///
/// `ids`/`amounts`/`expiry_heights` are still checked exactly — the consent-stable surface once a
/// run is stored.
fn validate_schedule_echo_against_state(
    state: &MigrationState,
    ids: &[*const c_char],
    amounts: &[i64],
    next_executable_after_heights: &[i64],
    expiry_heights: &[i64],
    estimated_duration_hours: u32,
) -> anyhow::Result<()> {
    let _ = next_executable_after_heights;
    let _ = estimated_duration_hours;
    let expected = expected_rows_from_state(state);
    if ids.len() != expected.len() {
        return Err(plan_stale(&format!(
            "the echoed schedule has {} transfer(s) but the committed migration has {} — \
             re-read the current state",
            ids.len(),
            expected.len()
        )));
    }
    let got = decode_stored_echo_rows(ids, amounts, expiry_heights)?;
    if !stored_schedule_echo_matches(expected, got) {
        return Err(plan_stale(
            "the echoed schedule does not match the committed migration — re-read the current state",
        ));
    }
    Ok(())
}

/// Returns the already-committed migration state if a non-terminal one exists (resume — never
/// rebuild over pre-signed, possibly broadcast transactions), otherwise commits the plan cached by
/// the most recent propose/prepare call: `sign` picks the `commit_preparation` /
/// `build_preparation_unsigned` variant. A terminal stored run (a completed or cancelled previous
/// migration) is REPLACED — that is the sequential-runs path.
///
/// `validate_amounts`: the platform-echoed transfer amounts to check against the cached plan
/// (`None` skips validation — the Keystone build path has no echo).
fn commit_or_resume(
    ctx: &mut CallCtx,
    usk: Option<zcash_keys::keys::UnifiedSpendingKey>,
    unsigned_out: bool,
) -> anyhow::Result<(MigrationState, Vec<(MigrationTxId, Vec<u8>)>)> {
    {
        let backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?;
        if let Some(state) = backend.get_migration()? {
            if !state.is_terminal() {
                let unsigned = state
                    .transactions()
                    .iter()
                    .filter(|t| matches!(t.state(), MigrationTxState::AwaitingSignature))
                    .map(|t| (t.id(), t.pczt().clone()))
                    .collect();
                return Ok((state, unsigned));
            }
        }
    }

    let cached = migration_plan_cache::get(&ctx.db_path, ctx.account_bytes)
        .ok_or_else(|| plan_stale("no previewed migration plan for this account"))?;

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
        )
        .map_err(map_commit_err)?;
        (
            state,
            unsigned.into_iter().map(|tx| tx.into_parts()).collect(),
        )
    } else {
        let state =
            engine::commit_preparation(&ctx.network, target, &mut backend, &cached.plan, &mut rng)
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

/// Proves a due transaction if it is still `Signed`, dispatching through the upstream engine
/// prover ([`migration_finalize::prove_due_transaction`] driving a `WalletMigrationProver`): a
/// transfer against the boundary anchor persisted on its row, a preparation against the wallet's
/// natural anchor. The engine persists the proven bytes through its own `Proved` state. Returns
/// the broadcastable `(proven pczt bytes, txid)` — or `None` when the wallet has not
/// scanned/retained the needed anchor yet (a restored wallet mid-sync, a boundary not yet
/// checkpointed), the ordinary transient state the caller maps to "nothing due".
fn prove_if_needed(
    ctx: &mut CallCtx,
    state: &mut MigrationState,
    id: MigrationTxId,
) -> anyhow::Result<Option<(Vec<u8>, [u8; 32])>> {
    let tx = state
        .transactions()
        .iter()
        .find(|t| t.id() == id)
        .ok_or_else(|| anyhow!("no migration transaction with id {}", u32::from(id)))?;

    match tx.state() {
        MigrationTxState::Proved => {
            // Re-serve the stored proven bytes (a retry after a failed broadcast attempt).
            let bytes = tx.pczt().clone();
            let pczt = pczt::Pczt::parse(&bytes)
                .map_err(|e| proving_unavailable(format!("re-parse proven pczt: {e:?}")))?;
            let (_, txid) = migration_finalize::extract_tx(pczt).map_err(proving_unavailable)?;
            Ok(Some((bytes, txid)))
        }
        MigrationTxState::Signed => {
            // The natural anchor is resolved LAZILY, only for the kind that proves against it: a
            // transfer proves against its persisted boundary and must not fail just because the
            // natural anchor is not resolvable yet (a wallet with a chain tip but no scanned
            // blocks — e.g. a restored wallet whose delivery lane wakes before its first scan —
            // has none, and `natural_anchor_height` hard-errors there, without the
            // proving-unavailable prefix).
            let natural_anchor = match tx.kind() {
                MigrationTxKind::Preparation { .. } => {
                    Some(migration_finalize::natural_anchor_height(&ctx.wallet)?)
                }
                MigrationTxKind::Transfer { .. } => None,
            };
            let fvk = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?
                .stored_orchard_fvk()?;
            let mut prover = WalletMigrationProver::new(&mut ctx.wallet, ctx.account, fvk);
            if migration_finalize::prove_due_transaction(&mut prover, state, id, natural_anchor)?
                .is_none()
            {
                // Not scanned/retained yet — transient, retry on a later call.
                return Ok(None);
            }
            let mut backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?;
            backend.replace_migration(state)?;
            // Re-read the engine-stored proven bytes and extract the txid to serve alongside.
            let tx = state
                .transactions()
                .iter()
                .find(|t| t.id() == id)
                .ok_or_else(|| anyhow!("no migration transaction with id {}", u32::from(id)))?;
            let bytes = tx.pczt().clone();
            let pczt = pczt::Pczt::parse(&bytes)
                .map_err(|e| proving_unavailable(format!("re-parse proven pczt: {e:?}")))?;
            let (_, txid) = migration_finalize::extract_tx(pczt).map_err(proving_unavailable)?;
            Ok(Some((bytes, txid)))
        }
        other => Err(anyhow!(
            "migration transaction {} is not broadcastable (state {})",
            u32::from(id),
            other.as_ref()
        )),
    }
}

/// The delivery lane's drive-and-serve: returns the next broadcastable transaction as
/// `(id, txid, proven pczt bytes)` due at `target` (the engine's `chain tip + 1` — see
/// [`CallCtx::target`]), or `None` when nothing is due.
///
/// Commit stores every in-process-signed transaction `Signed` (and the external-signer ceremony
/// lands its rows `Signed` too), while `next_broadcastable` serves only `Proved` rows — so before
/// answering "nothing due", this drives the prove-ready `Signed` rows through `prove`
/// (`Signed -> Proved`, persisted per prove by the caller's `prove`), looping until a row becomes
/// broadcastable or neither selector advances. Each iteration flips one `Signed` row to `Proved`,
/// so the loop terminates. Proving is decoupled from the broadcast schedule (upstream
/// `next_provable`'s contract), so the drive may prove a not-yet-due transfer on the way to
/// serving a due one behind it. Aside from `zcashlc_migration_sign_note_split`'s explicit
/// first-preparation prove, this drive is the only place proving is initiated.
///
/// A transient prove outcome (`prove` returning `Ok(None)`: the wallet has not scanned/retained
/// the needed anchor yet) means "nothing due yet", not an error — the row stays `Signed` and a
/// later call retries.
///
/// `prove` is [`prove_if_needed`] in production; tests substitute a closure driving
/// [`migration_finalize::prove_due_transaction`] with a recording/failing test prover (that seam
/// is generic over `impl MigrationProver`) plus a fixture-store persist.
fn drive_and_serve_next_due(
    state: &mut MigrationState,
    target: BlockHeight,
    mut prove: impl FnMut(
        &mut MigrationState,
        MigrationTxId,
    ) -> anyhow::Result<Option<(Vec<u8>, [u8; 32])>>,
) -> anyhow::Result<Option<(MigrationTxId, [u8; 32], Vec<u8>)>> {
    while state.next_broadcastable(target).is_none() {
        let Some(provable) = state.next_provable(target) else {
            return Ok(None);
        };
        if prove(state, provable)?.is_none() {
            return Ok(None);
        }
    }
    let id = state
        .next_broadcastable(target)
        .expect("the drive loop exits with a broadcastable row");
    Ok(prove(state, id)?.map(|(proven, txid)| (id, txid, proven)))
}

/// The id [`zcashlc_migration_next_due_transfer`] WOULD serve at `target` (the engine's `chain
/// tip + 1` — see [`CallCtx::target`]), assuming every due proof succeeds: the next broadcastable
/// row after virtually proving every prove-ready `Signed` row over a scratch copy — no prover
/// runs and nothing persists (`set_transaction_proved` with the row's own bytes only flips the
/// lifecycle state, mirroring [`drive_and_serve_next_due`]'s loop without its side effects).
/// `None` when the delivery lane has nothing actionable: nothing schedule-due yet, dependencies
/// unmined, rows awaiting an external signature (the signing ceremony, not the delivery lane,
/// advances those), or everything already broadcast/mined.
///
/// The queries built on this ([`zcashlc_migration_has_overdue_transfers`],
/// [`zcashlc_migration_pending_transfer_proposal`]) deliberately assume proofs succeed: a
/// transiently unwitnessable anchor (a restored wallet mid-sync) defers the actual delivery, not
/// the report — the due work exists either way, and the delivery call stays the one place that
/// consults the prover.
fn due_assuming_proving(state: &MigrationState, target: BlockHeight) -> Option<MigrationTxId> {
    if let Some(id) = state.next_broadcastable(target) {
        return Some(id);
    }
    if state.next_provable(target).is_none() {
        return None;
    }
    let mut scratch = state.clone();
    while let Some(id) = scratch.next_provable(target) {
        let bytes = scratch
            .transactions()
            .iter()
            .find(|t| t.id() == id)
            .map(|t| t.pczt().clone())
            .unwrap_or_default();
        scratch.set_transaction_proved(id, bytes);
    }
    scratch.next_broadcastable(target)
}

// ----- public-state derivation (pure; unit-tested) -----

/// What the platform's 5-state machine derives to, before marshaling.
enum DerivedState {
    NotStarted,
    SplitPendingConfirmation,
    InProgress {
        completed_transfers: u32,
        total_transfers: u32,
        next_transfer_ready_at_height: Option<BlockHeight>,
        /// Whether this run is the immediate (single-transaction) send-max sweep rather than an
        /// engine-tracked schedule. `true` only for the immediate lane; engine runs carry `false`.
        is_immediate: bool,
    },
    InvalidTransfer(u32),
    TransferExpired,
    Complete,
}

/// The fallback bound (blocks past `recorded_at_height`) an unmined immediate run is treated as
/// pending until, when the wallet database does not know (or no longer knows) the transaction's
/// real expiry height: the typical wallet transaction-expiry delta, so a run that the wallet's own
/// history never corroborates does not linger forever before the banner re-offers.
const IMMEDIATE_RUN_FALLBACK_EXPIRY_DELTA: u32 = 40;

/// An immediate-run row resolved against the wallet database (see [`resolve_immediate_run`]),
/// pre-computed by the caller so [`derive_state`] stays pure and unit-testable without a wallet
/// database.
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

/// The immediate-run row's derivation:
/// - mined -> `NotStarted`: the sweep is CONSUMED (its swept balance is zero, nothing to
///   acknowledge). Returning a state here — rather than `None` — masks any stale engine `Complete`
///   the caller would otherwise fall back to, keeping the aftermath quiet.
/// - unmined and not past its expiry bound -> `InProgress` of one, flagged `is_immediate`.
/// - `None` when the row should be ignored (expired unmined, or vanished) so the caller falls
///   through to the engine's own terminal/absent verdict.
fn derive_immediate_run(run: &ImmediateRunLookup, tip: BlockHeight) -> Option<DerivedState> {
    if run.mined_height.is_some() {
        // A mined immediate sweep is CONSUMED: it swept the whole spendable Orchard balance to
        // zero, so there is nothing for the app to acknowledge and no `Complete` screen to show.
        // It derives `NotStarted` — which, returned here (the caller only consults an immediate run
        // once no engine run is active), also MASKS any stale engine `Complete` left by an earlier
        // engine-tracked run, keeping the immediate aftermath fully quiet. If new Orchard funds
        // arrive later, the ordinary balance-gated re-offer path applies afresh.
        return Some(DerivedState::NotStarted);
    }
    if tip <= run.expiry_bound() {
        return Some(DerivedState::InProgress {
            completed_transfers: 0,
            total_transfers: 1,
            next_transfer_ready_at_height: None,
            is_immediate: true,
        });
    }
    None
}

/// Derive the platform's migration state from the persisted engine state and, when the engine has
/// nothing active to report, the account's immediate-run row.
///
/// - No stored migration -> `NotStarted`.
/// - A stored `Failed` run (our cancel) -> `NotStarted` (the platform re-plans).
/// - `Complete` is PER-RUN: the stored run is fully mined. Whether anything REMAINS to migrate is
///   answered by a fresh propose, never by this state.
/// - The v1 crate's "split confirmed, schedule pending" intermediate state and its matching
///   attention reason are gone: the engine commits the note split and the transfer schedule
///   atomically, so that moment cannot occur anymore.
///
/// Precedence: an engine run counts as ACTIVE — and wins outright, exactly as before the immediate
/// lane existed — whenever one is stored and has not reached a terminal status. A `Failed` or
/// `Complete` engine run, or no stored engine run at all, instead defers to `immediate_run` (mined
/// -> consumed: `NotStarted`, masking any stale engine `Complete`; unmined and not expired ->
/// `InProgress` of one, flagged `is_immediate`; expired or vanished -> ignored) before falling back
/// to the engine's own terminal/absent verdict.
///
/// `tip` carries two distinct meanings inside: it feeds `immediate_run`'s SDK-owned, tip-based
/// fallback-expiry policy unchanged (see [`ImmediateRunLookup::expiry_bound`]), while the
/// engine-mirroring expiry check on an ACTIVE run is computed from `target_from_tip(tip)` — the
/// engine's `chain tip + 1` contract (see [`CallCtx::target`]).
fn derive_state(
    persisted: Option<&MigrationState>,
    tip: BlockHeight,
    invalid_marks: &[u32],
    immediate_run: Option<&ImmediateRunLookup>,
) -> DerivedState {
    let active = persisted.filter(|state| {
        !matches!(
            state.status(),
            MigrationStatus::Complete | MigrationStatus::Failed
        )
    });
    let Some(state) = active else {
        if let Some(derived) = immediate_run.and_then(|run| derive_immediate_run(run, tip)) {
            return derived;
        }
        return match persisted.map(MigrationState::status) {
            Some(MigrationStatus::Complete) => DerivedState::Complete,
            _ => DerivedState::NotStarted,
        };
    };

    if let Some(&id) = invalid_marks.first() {
        return DerivedState::InvalidTransfer(id);
    }
    // The engine's expiry predicate is defined over `target = tip + 1` (see `target_from_tip`),
    // not the raw tip — membership in `expired_transactions` already excludes `Mined` rows and
    // treats `expiry_height == 0` as "never expires" (see `MigrationState::is_expired`'s doc).
    if !state.expired_transactions(target_from_tip(tip)).is_empty() {
        return DerivedState::TransferExpired;
    }

    let preps_all_mined = state
        .transactions()
        .iter()
        .filter(|t| matches!(t.kind(), MigrationTxKind::Preparation { .. }))
        .all(|t| matches!(t.state(), MigrationTxState::Mined { .. }));
    if !preps_all_mined {
        return DerivedState::SplitPendingConfirmation;
    }

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
    DerivedState::InProgress {
        completed_transfers: completed,
        total_transfers: transfers.len() as u32,
        next_transfer_ready_at_height: next_ready,
        is_immediate: false,
    }
}

/// The NET amount a stored transfer crosses the turnstile: the engine's authoritative crossing
/// value at `tx`'s crossing index (F3) — `note_split().crossing_values()[crossing]`, read directly
/// rather than re-derived as `funding_notes()[crossing] - note_fee_buffer` (the two are identical
/// by construction; see `schedule_rows`'s doc). `None` when `tx` is not a transfer, or its crossing
/// index is out of range.
fn transfer_amount(state: &MigrationState, tx: &MigrationTransaction) -> Option<Zatoshis> {
    match tx.kind() {
        MigrationTxKind::Transfer { crossing } => {
            state.note_split().crossing_values().get(crossing).copied()
        }
        _ => None,
    }
}

// ============================================================================================
// #[repr(C)] return DTOs
//
// These are named `Ffi*` in Rust because the base names would collide with the engine types this
// module marshals from; the prefix also lands the `Ffi*` C names the header convention wants
// without any `build.rs` `rename_item` entry.
// ============================================================================================

/// Live migration progress. When returned standalone (`zcashlc_migration_progress`), `is_present`
/// is `false` when no migration is in progress; as the payload of
/// [`FfiMigrationState::InProgress`] it is always `true`.
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

/// Why a migration requires user attention (payload of [`FfiMigrationState::RequiresAttention`]).
#[repr(C, u8)]
pub enum FfiAttentionReason {
    /// The transfer identified by `transfer_id` was terminally rejected at broadcast (its input
    /// note was spent externally, or the network refused it as invalid). `transfer_id` is an owned
    /// C string, freed by [`zcashlc_free_migration_state`].
    InvalidTransfer { transfer_id: *mut c_char },
    /// A transaction's expiry elapsed before it could be broadcast (or mined).
    TransferExpired,
}

/// The top-level migration state machine surfaced to the app.
///
/// `#[allow(dead_code)]`: the data-carrying variants' payloads are read by the C consumer across
/// the FFI (cbindgen emits them into the header), which rustc cannot observe.
#[allow(dead_code)]
#[repr(C, u8)]
pub enum FfiMigrationState {
    /// No migration run is stored (none started, or a previous run was cancelled).
    NotStarted,
    /// The run is committed and its preparation (note-split) transactions are not yet all mined.
    SplitPendingConfirmation,
    /// Preparation is mined and the run's transfers are executing.
    InProgress(FfiMigrationProgress),
    /// A transfer cannot proceed automatically; the app must act.
    RequiresAttention(FfiAttentionReason),
    /// Every transaction of the STORED RUN is mined. Per-run: whether anything remains to migrate
    /// is answered by a fresh `zcashlc_migration_propose_transfers` (empty schedule = nothing).
    Complete,
}

/// A planned note split: the per-note output values (zatoshi) and the preparation fees.
#[repr(C)]
pub struct FfiNoteSplitProposal {
    /// Heap array of `output_values_len` output-note values (zatoshi).
    pub output_values: *mut i64,
    pub output_values_len: usize,
    /// The total fees (zatoshi) paid by the preparation (note-split) transactions.
    pub fee: i64,
}

/// A fully proven, signed transaction persisted as a PCZT, ready for the platform to broadcast.
/// When returned by `zcashlc_migration_next_due_transfer`, an all-null/zeroed value (`id` and
/// `pczt` null) means "nothing is due" (as opposed to a NULL return, which signals an error).
#[repr(C)]
pub struct FfiPreparedTransfer {
    /// The transaction's id (the engine's decimal id), as an owned C string (null only in the
    /// "nothing due" sentinel).
    pub id: *mut c_char,
    /// The finalized transaction's id, as raw (internal-order) 32-byte value (zeroed when the
    /// value is a storage receipt whose transaction has not been proven yet).
    pub txid: [u8; 32],
    /// Heap `pczt_len`-byte serialized PCZT (null only in the "nothing due" sentinel).
    pub pczt: *mut u8,
    pub pczt_len: usize,
}

impl FfiPreparedTransfer {
    fn from_parts(
        id: MigrationTxId,
        txid: [u8; 32],
        pczt_bytes: Vec<u8>,
    ) -> anyhow::Result<*mut Self> {
        let id = cstring_raw(&u32::from(id).to_string(), "prepared transfer id")?;
        let (pczt, pczt_len) = ptr_from_vec(pczt_bytes);
        Ok(Box::into_raw(Box::new(FfiPreparedTransfer {
            id,
            txid,
            pczt,
            pczt_len,
        })))
    }

    fn none() -> *mut Self {
        Box::into_raw(Box::new(FfiPreparedTransfer {
            id: ptr::null_mut(),
            txid: [0u8; 32],
            pczt: ptr::null_mut(),
            pczt_len: 0,
        }))
    }
}

/// A single scheduled Orchard→Ironwood transfer (element of [`FfiMigrationSchedule`]).
#[repr(C)]
pub struct FfiTransferProposal {
    /// The transfer's id (the engine's decimal id), as an owned C string.
    pub id: *mut c_char,
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
        id: MigrationTxId,
        amount: Zatoshis,
        now_reference: BlockHeight,
        next_executable_after: BlockHeight,
        expiry: BlockHeight,
    ) -> anyhow::Result<*mut Self> {
        Ok(Box::into_raw(Box::new(FfiTransferProposal {
            id: cstring_raw(&u32::from(id).to_string(), "transfer proposal id")?,
            amount: zat_to_i64(amount),
            anchor_height: i64::from(u32::from(now_reference)),
            next_executable_after_height: i64::from(u32::from(next_executable_after)),
            expiry_height: i64::from(u32::from(expiry)),
        })))
    }
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
    /// The transaction's id (the engine's decimal id), as an owned C string.
    pub id: *mut c_char,
    /// Heap `pczt_len`-byte serialized unsigned PCZT.
    pub pczt: *mut u8,
    pub pczt_len: usize,
}

/// A set of unsigned PCZTs to route to an external signer. Despite the name, this is really a
/// generic `(id, PCZT bytes)` pair set: [`zcashlc_migration_keystone_apply_batch_signatures`]
/// also returns its batch-SIGNED PCZTs through this same type, positionally paired back up with
/// the ids the caller passed in.
#[repr(C)]
pub struct FfiUnsignedTransferPczts {
    pub ptr: *mut FfiUnsignedTransferPczt,
    pub len: usize,
}

impl FfiUnsignedTransferPczts {
    fn from_pairs(pairs: Vec<(MigrationTxId, Vec<u8>)>) -> anyhow::Result<*mut Self> {
        let items = pairs
            .into_iter()
            .map(|(id, bytes)| {
                let id = cstring_raw(&u32::from(id).to_string(), "unsigned transfer pczt id")?;
                let (pczt, pczt_len) = ptr_from_vec(bytes);
                Ok(FfiUnsignedTransferPczt { id, pczt, pczt_len })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let (ptr, len) = ptr_from_vec(items);
        Ok(Box::into_raw(Box::new(FfiUnsignedTransferPczts {
            ptr,
            len,
        })))
    }
}

/// One migration transaction's LIVE status, as the engine computes it — an element of
/// [`FfiMigrationTransactionStatuses`]. Mirrors
/// [`zcash_pool_migration_backend::state::TransactionStatus`] field-for-field — minus its
/// `depends_on` edge list, deliberately not marshaled so every row stays heap-pointer-free (a
/// `blocked_on = dependencies` row reports THAT it waits, not on which ids) — and nothing here
/// is derived independently of the engine's own view (see
/// [`zcashlc_migration_transaction_statuses`]).
#[repr(C)]
pub struct FfiMigrationTransactionStatus {
    /// This transaction's stable id (`MigrationTxId`'s raw ordinal). Stable across reads and
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
    /// `3` = Broadcast, `4` = Mined.
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
    /// `5` = expired.
    pub blocked_on: u8,
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

/// Frees a [`FfiMigrationState`], including the attention transfer id if present.
///
/// # Safety
/// `ptr` must be null or point to a [`FfiMigrationState`] handed out by this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_migration_state(ptr: *mut FfiMigrationState) {
    if !ptr.is_null() {
        let boxed = unsafe { Box::from_raw(ptr) };
        if let FfiMigrationState::RequiresAttention(FfiAttentionReason::InvalidTransfer {
            transfer_id,
        }) = &*boxed
            && !transfer_id.is_null()
        {
            unsafe { zcashlc_string_free(*transfer_id) }
        }
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
        if !boxed.id.is_null() {
            unsafe { zcashlc_string_free(boxed.id) }
        }
        free_ptr_from_vec(boxed.pczt, boxed.pczt_len);
        drop(boxed);
    }
}

/// Frees a [`FfiMigrationSchedule`], including every transfer's id string.
///
/// # Safety
/// `ptr` must be null or point to a [`FfiMigrationSchedule`] handed out by this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_migration_schedule(ptr: *mut FfiMigrationSchedule) {
    if !ptr.is_null() {
        let boxed = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec_with(boxed.transfers, boxed.transfers_len, |t| {
            if !t.id.is_null() {
                unsafe { zcashlc_string_free(t.id) }
            }
        });
        drop(boxed);
    }
}

/// Frees a standalone [`FfiTransferProposal`] (as returned by
/// `zcashlc_migration_pending_transfer_proposal`), including its id string.
///
/// # Safety
/// `ptr` must be null or point to a [`FfiTransferProposal`] handed out by this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_migration_transfer_proposal(ptr: *mut FfiTransferProposal) {
    if !ptr.is_null() {
        let boxed = unsafe { Box::from_raw(ptr) };
        if !boxed.id.is_null() {
            unsafe { zcashlc_string_free(boxed.id) }
        }
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
            if !u.id.is_null() {
                unsafe { zcashlc_string_free(u.id) }
            }
            free_ptr_from_vec(u.pczt, u.pczt_len);
        });
        drop(boxed);
    }
}

/// Frees a [`FfiMigrationTransactionStatuses`] container. Every row is a fixed-size value (the
/// `txid` is an inline `[u8; 32]`, not a heap pointer), so freeing the array itself is enough —
/// no per-row free callback, unlike [`zcashlc_free_migration_unsigned_transfer_pczts`].
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
        free_ptr_from_vec(boxed.ptr, boxed.len);
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
// State
// ============================================================================================

/// Marshal a derived state (plus its progress inputs) into the boxed C DTO.
fn marshal_state(
    derived: DerivedState,
    remaining_orchard: Zatoshis,
) -> anyhow::Result<*mut FfiMigrationState> {
    let value = match derived {
        DerivedState::NotStarted => FfiMigrationState::NotStarted,
        DerivedState::SplitPendingConfirmation => FfiMigrationState::SplitPendingConfirmation,
        DerivedState::InProgress {
            completed_transfers,
            total_transfers,
            next_transfer_ready_at_height,
            is_immediate,
        } => FfiMigrationState::InProgress(FfiMigrationProgress {
            is_present: true,
            completed_transfers,
            total_transfers,
            remaining_orchard_value: zat_to_i64(remaining_orchard),
            next_transfer_ready_at_height: height_opt_to_i64(next_transfer_ready_at_height),
            is_immediate,
        }),
        DerivedState::InvalidTransfer(id) => {
            FfiMigrationState::RequiresAttention(FfiAttentionReason::InvalidTransfer {
                transfer_id: cstring_raw(&id.to_string(), "attention transfer id")?,
            })
        }
        DerivedState::TransferExpired => {
            FfiMigrationState::RequiresAttention(FfiAttentionReason::TransferExpired)
        }
        DerivedState::Complete => FfiMigrationState::Complete,
    };
    Ok(Box::into_raw(Box::new(value)))
}

/// The account's live spendable Orchard balance (what is still in the old pool).
fn remaining_orchard(ctx: &mut CallCtx) -> anyhow::Result<Zatoshis> {
    let backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?;
    use zcash_pool_migration_backend::engine::MigrationBackend;
    let values = backend.spendable_orchard_note_values()?;
    values
        .into_iter()
        .try_fold(Zatoshis::ZERO, |acc, v| acc + v)
        .ok_or_else(|| anyhow!("spendable Orchard balance overflows"))
}

/// The current migration state. The app calls this on launch and after every operation; it is
/// also the reconciliation hub (advancing broadcast transactions to mined as the wallet scans).
/// `Complete` is PER-RUN (see the module doc).
///
/// # Safety
/// See [`open`]. Free the returned pointer with [`zcashlc_free_migration_state`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_state(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> *mut FfiMigrationState {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let engine_state = reconcile_mined(&mut ctx)?;
        let immediate_row = immediate_run_row(&ctx.store_conn, &ctx.account_bytes)
            .map_err(|e| anyhow!("immediate run read failed: {e}"))?;
        if engine_state.is_none() && immediate_row.is_none() {
            // Neither an engine-tracked run nor an immediate-run row: nothing to derive, and
            // (crucially) no need to touch the chain tip, which a not-yet-synced wallet lacks.
            return marshal_state(DerivedState::NotStarted, Zatoshis::ZERO);
        }
        let marks = invalid_marks(&ctx.store_conn, &ctx.account_bytes)
            .map_err(|e| anyhow!("marks read failed: {e}"))?;
        let tip = ctx.tip()?;
        let immediate = immediate_row
            .map(|row| resolve_immediate_run(&ctx.store_conn, row, tip))
            .transpose()
            .map_err(|e| anyhow!("wallet transaction lookup failed: {e}"))?;
        let derived = derive_state(engine_state.as_ref(), tip, &marks, immediate.as_ref());
        let remaining = match derived {
            DerivedState::InProgress { .. } => remaining_orchard(&mut ctx)?,
            _ => Zatoshis::ZERO,
        };
        marshal_state(derived, remaining)
    });
    unwrap_exc_or_null(res)
}

/// Migration progress, present only while a migration run is in progress. On success the returned
/// pointer is non-null; its `is_present` flag is `false` when there is no progress to report. A
/// NULL return signals an error.
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
        let immediate_row = immediate_run_row(&ctx.store_conn, &ctx.account_bytes)
            .map_err(|e| anyhow!("immediate run read failed: {e}"))?;
        if engine_state.is_none() && immediate_row.is_none() {
            // Neither an engine-tracked run nor an immediate-run row: nothing to derive, and
            // (crucially) no need to touch the chain tip, which a not-yet-synced wallet lacks.
            return Ok(Box::into_raw(Box::new(FfiMigrationProgress::absent())));
        }
        let marks = invalid_marks(&ctx.store_conn, &ctx.account_bytes)
            .map_err(|e| anyhow!("marks read failed: {e}"))?;
        let tip = ctx.tip()?;
        let immediate = immediate_row
            .map(|row| resolve_immediate_run(&ctx.store_conn, row, tip))
            .transpose()
            .map_err(|e| anyhow!("wallet transaction lookup failed: {e}"))?;
        let value = match derive_state(engine_state.as_ref(), tip, &marks, immediate.as_ref()) {
            DerivedState::InProgress {
                completed_transfers,
                total_transfers,
                next_transfer_ready_at_height,
                is_immediate,
            } => FfiMigrationProgress {
                is_present: true,
                completed_transfers,
                total_transfers,
                remaining_orchard_value: zat_to_i64(remaining_orchard(&mut ctx)?),
                next_transfer_ready_at_height: height_opt_to_i64(next_transfer_ready_at_height),
                is_immediate,
            },
            _ => FfiMigrationProgress::absent(),
        };
        Ok(Box::into_raw(Box::new(value)))
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

/// Marshal one engine [`TransactionStatus`] row verbatim into the FFI DTO — see
/// [`zcashlc_migration_transaction_statuses`] for the field-by-field contract.
fn encode_transaction_status(ts: &TransactionStatus) -> FfiMigrationTransactionStatus {
    let (is_transfer, prep_layer, prep_index, crossing) = match ts.kind() {
        MigrationTxKind::Preparation { layer, index } => (false, layer as i64, index as i64, -1i64),
        MigrationTxKind::Transfer { crossing } => (true, -1i64, -1i64, crossing as i64),
    };
    let state = match ts.state() {
        MigrationTxState::AwaitingSignature => 0,
        MigrationTxState::Signed => 1,
        MigrationTxState::Proved => 2,
        MigrationTxState::Broadcast { .. } => 3,
        MigrationTxState::Mined { .. } => 4,
    };
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
    };
    let (txid, has_txid) = match ts.txid() {
        Some(txid) => (<[u8; 32]>::from(txid), true),
        None => ([0u8; 32], false),
    };
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
    }
}

/// The LIVE status of every committed migration transaction, keyed by its stable id — a verbatim
/// marshal of `MigrationState::transaction_statuses(target)` at `target = tip + 1` (see
/// [`CallCtx::target`]), the engine's own per-transaction view a wallet renders progress from and
/// decides what to sign/prove/broadcast next. Reconciles mined transactions first (the same
/// read-path convention as [`zcashlc_migration_state`]), so a `Broadcast` row the wallet's own
/// scan has since observed mined is reported `Mined` here too. No stored run, or a stored run
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
        let target = ctx.target()?;
        let rows: Vec<FfiMigrationTransactionStatus> = state
            .transaction_statuses(target)
            .into_iter()
            .map(|ts| encode_transaction_status(&ts))
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
        Ok(match plan_and_cache(&mut ctx)? {
            Some((plan, _)) => plan.preparation().transaction_count() > 0,
            None => false,
        })
    });
    unwrap_exc_or(res, false)
}

/// Whether any transaction of the stored run is due-and-unbroadcast at the current tip — that
/// is, whether the delivery lane has actionable work: an already-`Proved` transaction due for
/// broadcast, or a due, dependency-satisfied, prove-ready `Signed` one that
/// [`zcashlc_migration_next_due_transfer`] would drive through proving and serve (proofs are
/// assumed to succeed — a transiently unwitnessable anchor defers the delivery, not this
/// report; see [`due_assuming_proving`]). A row awaiting an EXTERNAL signature is not delivery
/// work (the signing ceremony advances it). Returns `false` on error (see
/// `zcashlc_last_error_message`).
///
/// # Safety
/// See [`open`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_has_overdue_transfers(
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
        let target = ctx.target()?;
        Ok(due_assuming_proving(&state, target).is_some())
    });
    unwrap_exc_or(res, false)
}

/// Whether the stored run has a transfer that cannot proceed: a terminally-rejected transfer (per
/// the platform's recorded classification) or an expired, unmined transaction. Returns `false` on
/// error (see `zcashlc_last_error_message`).
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
        if matches!(state.status(), MigrationStatus::Complete) {
            return Ok(false);
        }
        let marks = invalid_marks(&ctx.store_conn, &ctx.account_bytes)
            .map_err(|e| anyhow!("marks read failed: {e}"))?;
        if !marks.is_empty() {
            return Ok(true);
        }
        // The engine's expiry predicate is defined over `target = tip + 1`, not the raw tip (see
        // `CallCtx::target`); membership in `expired_transactions` already excludes `Mined` rows
        // and treats `expiry_height == 0` as "never expires".
        let target = ctx.target()?;
        Ok(!state.expired_transactions(target).is_empty())
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
        let (values, fee) = match plan_and_cache(&mut ctx)? {
            Some((plan, _)) => {
                let split = plan.note_split();
                let values: Vec<i64> = split
                    .migration_outputs()
                    .iter()
                    .map(|v| zat_to_i64(*v))
                    .collect();
                (values, zat_to_i64(split.prep_fees()))
            }
            None => (Vec::new(), 0),
        };
        let (output_values, output_values_len) = ptr_from_vec(values);
        Ok(Box::into_raw(Box::new(FfiNoteSplitProposal {
            output_values,
            output_values_len,
            fee,
        })))
    });
    unwrap_exc_or_null(res)
}

/// Commits the previewed migration (signing EVERY transaction — preparation and transfers — in
/// one pass with the spending key), then proves and returns the first preparation transaction for
/// immediate broadcast. If a matching non-terminal run is already stored, resumes it instead of
/// recommitting (the retry path); a terminal stored run is replaced (the sequential-runs path).
///
/// `output_values`/`fee` are verified consent echoes — the values the user approved must match
/// what will be signed — checked against the previewed plan's note split when one is cached for
/// this account (`MIGRATION_PLAN_STALE` on mismatch; a missing cache falls through to
/// `commit_or_resume`, which either resumes a stored non-terminal run or reports the same error).
///
/// # Safety
/// See [`open`]; `output_values`/`usk_ptr` must be valid for reads of their lengths.
/// Free the returned pointer with [`zcashlc_free_migration_prepared_transfer`].
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_sign_note_split(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    output_values: *const i64,
    output_values_len: usize,
    fee: i64,
    usk_ptr: *const u8,
    usk_len: usize,
) -> *mut FfiPreparedTransfer {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let usk = unsafe { crate::decode_usk(usk_ptr, usk_len)? };
        let echoed: Vec<i64> = unsafe { slice_or_empty(output_values, output_values_len) }.to_vec();

        // The echoed values are the note-split outputs and fee; validation happens against the
        // funding notes inside `commit_or_resume` only for the schedule echo. For the split echo,
        // validate against the previewed split outputs/fee here.
        {
            let cached = migration_plan_cache::get(&ctx.db_path, ctx.account_bytes);
            if let Some(cached) = &cached {
                let expected: Vec<i64> = cached
                    .plan
                    .note_split()
                    .migration_outputs()
                    .iter()
                    .map(|z| zat_to_i64(*z))
                    .collect();
                let expected_fee = zat_to_i64(cached.plan.note_split().prep_fees());
                if !note_split_echo_matches(&expected, expected_fee, echoed.clone(), fee) {
                    return Err(plan_stale(
                        "the echoed note split does not match the previewed plan — propose again",
                    ));
                }
            }
            // A missing cache falls through to `commit_or_resume`, which either resumes a stored
            // non-terminal run (no cache needed) or reports MIGRATION_PLAN_STALE.
        }

        let (mut state, _) = commit_or_resume(&mut ctx, Some(usk), false)?;

        // The first broadcastable preparation transaction (lowest scheduled height not yet
        // broadcast): proven now, against the wallet's natural anchor, and returned for the
        // platform's immediate broadcast. Remaining preparation transactions ride the normal
        // delivery lane as they come due.
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
        let (proven, txid) = prove_if_needed(&mut ctx, &mut state, first_prep)?.ok_or_else(|| {
            anyhow!("the note split is not yet finalizable — its funding note is not witnessable; sync first")
        })?;
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
                    return Ok(state.note_split().change().map_or(-1, zat_to_i64));
                }
            }
        }
        Ok(match plan_and_cache(&mut ctx)? {
            Some((plan, _)) => plan.note_split().change().map_or(-1, zat_to_i64),
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
        match plan_and_cache(&mut ctx)? {
            Some((plan, reference_height)) => encode_schedule_from_plan(&plan, reference_height),
            None => Ok(encode_empty_schedule()),
        }
    });
    unwrap_exc_or_null(res)
}

/// Commits the previewed migration with the spending key if nothing is committed yet (covering
/// the no-split lane); when a matching non-terminal run is already stored (the normal case — the
/// note-split submission committed it), succeeds as a no-op.
///
/// `ids`/`amounts`/`next_executable_after_heights`/`expiry_heights`/`estimated_duration_hours` are
/// verified consent echoes — the values the user approved must match what will be signed. When
/// nothing is committed yet (a fresh commit is about to happen), all five are checked against the
/// previewed plan cached for this account. When a matching non-terminal run already exists (the
/// resume/no-op case — there is no cache to consult, and the stored state is the actual thing
/// about to be (re-)signed), only `ids`/`amounts`/`expiry_heights` are checked, against the
/// STORED state; `next_executable_after_heights` and `estimated_duration_hours` are NOT:
/// - `next_executable_after_heights`: the immediate lane's commit legitimately reschedules every
///   transfer to the commit-time tip, which can differ from the preview-time tip the platform is
///   honestly echoing back (e.g. a block landed during user review).
/// - `estimated_duration_hours` (#1806): once committed, duration is re-serve-time-relative
///   display metadata (see `stored_duration_hours`'s doc) with no stable pre-commit reference
///   surviving here to check an echo against byte-for-byte.
///
/// Both are cases where the platform cannot converge on a match by re-proposing (the stored value
/// is already fixed by the completed commit — see `StoredEchoRow`'s doc). Mismatch on a checked
/// field — including a length mismatch — errors with the `MIGRATION_PLAN_STALE:` prefix (the
/// app's existing recovery: re-propose/re-read and re-display). `anchor_heights` is never checked,
/// in either branch: it is a display-only "now" reference the schedule DTO carries for duration
/// math, not a value any transaction commits to.
///
/// # Safety
/// See [`open`]; array pointers must be valid for reads of `ids_len` elements; `usk_ptr` for
/// `usk_len` bytes.
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_sign_and_store_schedule(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    ids: *const *const c_char,
    ids_len: usize,
    amounts: *const i64,
    anchor_heights: *const i64,
    next_executable_after_heights: *const i64,
    expiry_heights: *const i64,
    estimated_duration_hours: u32,
    usk_ptr: *const u8,
    usk_len: usize,
) -> bool {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let usk = unsafe { crate::decode_usk(usk_ptr, usk_len)? };
        let _ = anchor_heights;
        let ids_slice = unsafe { slice_or_empty(ids, ids_len) };
        let amounts = unsafe { slice_or_empty(amounts, ids_len) };
        let next_executable_after_heights =
            unsafe { slice_or_empty(next_executable_after_heights, ids_len) };
        let expiry_heights = unsafe { slice_or_empty(expiry_heights, ids_len) };

        // A matching non-terminal stored run means this call resumes/no-ops (no fresh commit
        // happens): the echo is checked against the actual stored state. Otherwise it is checked
        // against the cached preview this call is about to commit.
        let stored = {
            let backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?;
            backend
                .get_migration()?
                .filter(|state| !state.is_terminal())
        };
        match &stored {
            Some(state) => validate_schedule_echo_against_state(
                state,
                ids_slice,
                amounts,
                next_executable_after_heights,
                expiry_heights,
                estimated_duration_hours,
            )?,
            None => validate_schedule_echo_against_cache(
                &ctx.db_path,
                ctx.account_bytes,
                ids_slice,
                amounts,
                next_executable_after_heights,
                expiry_heights,
                estimated_duration_hours,
            )?,
        }

        commit_or_resume(&mut ctx, Some(usk), false)?;
        Ok(true)
    });
    unwrap_exc_or(res, false)
}

/// The next due transaction of the stored run, proven and ready to broadcast — or the
/// "nothing due" sentinel (null id/pczt) when nothing qualifies yet (nothing scheduled, deps
/// unmined, or a due transaction's anchor is not yet witnessable). Reconciles mined
/// transactions first, then DRIVES the run's prove-ready `Signed` rows through proving
/// (`Signed -> Proved`, each persisted) before serving — commit stores every transaction
/// `Signed`, so without this drive nothing would ever become broadcastable (see
/// [`drive_and_serve_next_due`]). Serves preparation transactions and transfers alike, in
/// scheduled order.
///
/// # Safety
/// See [`open`]. Free the returned pointer with [`zcashlc_free_migration_prepared_transfer`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_next_due_transfer(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> *mut FfiPreparedTransfer {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let Some(mut state) = reconcile_mined(&mut ctx)? else {
            return Ok(FfiPreparedTransfer::none());
        };
        if state.is_terminal() {
            return Ok(FfiPreparedTransfer::none());
        }
        let target = ctx.target()?;
        let served = drive_and_serve_next_due(&mut state, target, |state, id| {
            prove_if_needed(&mut ctx, state, id)
        })?;
        match served {
            Some((id, txid, proven)) => FfiPreparedTransfer::from_parts(id, txid, proven),
            // Nothing due, or due but not yet finalizable (anchor not witnessable yet).
            None => Ok(FfiPreparedTransfer::none()),
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
        // query below is actually defined over — see `CallCtx::target`.
        let tip = ctx.tip()?;
        let target = target_from_tip(tip);
        let next_transfer = due_assuming_proving(&state, target)
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
/// offered); 2 = invalid note, 3 = expired — recorded in the SDK's invalid marks so the run
/// surfaces `RequiresAttention`.
///
/// # Safety
/// See [`open`]; `transfer_id` must be a valid C string; for tag 0, `txid_bytes` must be valid
/// for reads of 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_record_transfer_result(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    transfer_id: *const c_char,
    result_tag: i32,
    txid_bytes: *const u8,
) -> bool {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let id = transfer_id_from_c(transfer_id)?;
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
                state.mark_broadcast(id, TxId::from_bytes(txid));
                backend.replace_migration(&state)?;
                Ok(true)
            }
            1 => Ok(true),
            2 | 3 => {
                let reason = if result_tag == 2 {
                    "invalid_note"
                } else {
                    "expired"
                };
                insert_invalid_mark(&ctx.store_conn, &ctx.account_bytes, id, reason)
                    .map_err(|e| anyhow!("marks write failed: {e}"))?;
                Ok(true)
            }
            other => Err(anyhow!("unknown TransferResult tag: {other}")),
        }
    });
    unwrap_exc_or(res, false)
}

/// Records a broadcast immediate-migration sweep (an ordinary send-max transaction proposed via
/// `zcashlc_propose_send_max_transfer(orchard_only: true)`, built entirely outside the engine's
/// plan cache) so the platform's migration state machine reports it: `InProgress` (0 of 1) while
/// unmined, `Complete` once mined, or a re-offer (`NotStarted`) if it expires unmined — see the
/// precedence rule on [`derive_state`]. One row per account: a new record supersedes any previous
/// one (INSERT OR REPLACE).
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
/// already-broadcast ones are unaffected on-chain), clears the invalid marks, and previews a
/// fresh plan against the live balance for the platform's re-confirm lane.
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
                        state.note_split().clone(),
                        state.preparation().clone(),
                        state.transactions().clone(),
                    );
                    backend.replace_migration(&cancelled)?;
                }
            }
        }
        clear_invalid_marks(&ctx.store_conn, &ctx.account_bytes)
            .map_err(|e| anyhow!("marks clear failed: {e}"))?;
        match plan_and_cache(&mut ctx)? {
            Some((plan, reference_height)) => encode_schedule_from_plan(&plan, reference_height),
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
        let expired = state.expired_transactions(target);
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
) -> *mut FfiUnsignedTransferPczts {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let (state, unsigned) = commit_or_resume(&mut ctx, None, true)?;
        let prep_ids: HashSet<MigrationTxId> = state
            .transactions()
            .iter()
            .filter(|t| matches!(t.kind(), MigrationTxKind::Preparation { .. }))
            .map(|t| t.id())
            .collect();
        let preps: Vec<_> = unsigned
            .into_iter()
            .filter(|(id, _)| prep_ids.contains(id))
            .collect();
        let (seed_fingerprint, account_index) = account_zip32_derivation(&ctx.wallet, ctx.account)?;
        let preps = preps
            .into_iter()
            .map(|(id, pczt_bytes)| {
                let pczt_bytes = crate::migration_keystone::annotate_spend_zip32_derivation(
                    &pczt_bytes,
                    seed_fingerprint,
                    ctx.network.coin_type(),
                    account_index,
                )
                .map_err(|e| anyhow!("Error annotating note-split PCZT derivation: {:?}", e))?;
                Ok::<_, anyhow::Error>((id, pczt_bytes))
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
    ids: *const *const c_char,
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
        let mut first: Option<(MigrationTxId, Vec<u8>)> = None;
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
/// already exist).
///
/// `ids`/`amounts`/`expiry_heights` are verified consent echoes, checked against the STORED
/// committed state this call serves from (there is no cache to consult post-commit): mismatch —
/// including a length mismatch — errors with the `MIGRATION_PLAN_STALE:` prefix (the app re-reads
/// the current state). `next_executable_after_heights`/`anchor_heights`/`estimated_duration_hours`
/// are accepted but NOT checked — see `zcashlc_migration_sign_and_store_schedule`'s doc for why
/// (the first's immediate-lane commit-time reschedule can legitimately move it away from an
/// honest echo, with no way to converge by re-proposing; the second is never consent-critical;
/// the third (#1806) is re-serve-time-relative display metadata post-commit, with no stable
/// pre-commit reference surviving here to check it against).
///
/// Every returned PCZT is annotated with the account's ZIP 32 spend derivation — see
/// [`account_zip32_derivation`] and `zcashlc_migration_create_unsigned_note_split_pczts`'s doc.
///
/// # Safety
/// See [`open`]; array pointers must be valid for reads of `ids_len` elements. Free the returned
/// pointer with [`zcashlc_free_migration_unsigned_transfer_pczts`].
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_create_unsigned_transfer_pczts(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    ids: *const *const c_char,
    ids_len: usize,
    amounts: *const i64,
    anchor_heights: *const i64,
    next_executable_after_heights: *const i64,
    expiry_heights: *const i64,
    estimated_duration_hours: u32,
) -> *mut FfiUnsignedTransferPczts {
    let res = catch_panic(|| {
        let _ = anchor_heights;
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let (state, unsigned) = commit_or_resume(&mut ctx, None, true)?;
        let ids_slice = unsafe { slice_or_empty(ids, ids_len) };
        let amounts = unsafe { slice_or_empty(amounts, ids_len) };
        let next_executable_after_heights =
            unsafe { slice_or_empty(next_executable_after_heights, ids_len) };
        let expiry_heights = unsafe { slice_or_empty(expiry_heights, ids_len) };
        validate_schedule_echo_against_state(
            &state,
            ids_slice,
            amounts,
            next_executable_after_heights,
            expiry_heights,
            estimated_duration_hours,
        )?;
        let transfer_ids: HashSet<MigrationTxId> = state
            .transactions()
            .iter()
            .filter(|t| matches!(t.kind(), MigrationTxKind::Transfer { .. }))
            .map(|t| t.id())
            .collect();
        let transfers: Vec<_> = unsigned
            .into_iter()
            .filter(|(id, _)| transfer_ids.contains(id))
            .collect();
        let (seed_fingerprint, account_index) = account_zip32_derivation(&ctx.wallet, ctx.account)?;
        let transfers: Vec<_> = transfers
            .into_iter()
            .map(|(id, pczt_bytes)| {
                let pczt_bytes = crate::migration_keystone::annotate_spend_zip32_derivation(
                    &pczt_bytes,
                    seed_fingerprint,
                    ctx.network.coin_type(),
                    account_index,
                )
                .map_err(|e| anyhow!("Error annotating transfer PCZT derivation: {:?}", e))?;
                Ok::<_, anyhow::Error>((id, pczt_bytes))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        FfiUnsignedTransferPczts::from_pairs(transfers)
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
    ids: *const *const c_char,
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

/// Decode the platform's parallel `(id, pczt)` arrays into owned pairs.
///
/// # Safety
/// `ids`/`pczts`/`pczt_lens` must be valid for reads of `len` elements; every `ids[i]` must be a
/// valid C string and every `pczts[i]` valid for `pczt_lens[i]` bytes.
unsafe fn decode_signed_pairs(
    ids: *const *const c_char,
    len: usize,
    pczts: *const *const u8,
    pczt_lens: *const usize,
) -> anyhow::Result<Vec<(MigrationTxId, Vec<u8>)>> {
    let id_ptrs = unsafe { slice_or_empty(ids, len) };
    let pczt_ptrs = unsafe { slice_or_empty(pczts, len) };
    let lens = unsafe { slice_or_empty(pczt_lens, len) };
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        let id = transfer_id_from_c(id_ptrs[i])?;
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
/// [`zcashlc_migration_keystone_build_sign_batch_qr_parts`]. `ids` pass through positionally onto
/// the returned signed PCZTs, reusing [`FfiUnsignedTransferPczts`] as a generic `(id, PCZT
/// bytes)` pair set (see its doc) and [`decode_signed_pairs`] to decode the parallel input
/// arrays.
///
/// # Safety
/// See [`decode_signed_pairs`]. `response` must be valid for reads of `response_len` bytes. Free
/// the returned pointer with [`zcashlc_free_migration_unsigned_transfer_pczts`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_keystone_apply_batch_signatures(
    ids: *const *const c_char,
    ids_len: usize,
    pczts: *const *const u8,
    pczt_lens: *const usize,
    response: *const u8,
    response_len: usize,
) -> *mut FfiUnsignedTransferPczts {
    let res = catch_panic(|| {
        let unsigned = unsafe { decode_signed_pairs(ids, ids_len, pczts, pczt_lens)? };
        let (ids, pczts): (Vec<MigrationTxId>, Vec<Vec<u8>>) = unsigned.into_iter().unzip();
        let response = unsafe { slice_or_empty(response, response_len) };
        let signed = crate::migration_keystone::apply_batch_signatures(&pczts, response)
            .map_err(|e| anyhow!("Error applying Keystone batch signatures: {e}"))?;
        FfiUnsignedTransferPczts::from_pairs(ids.into_iter().zip(signed).collect())
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
    use zcash_pool_migration_backend::note_splitting::NoteSplitPlan;
    use zcash_pool_migration_backend::preparation::PreparationPlan;
    use zcash_pool_migration_backend::scheduling;

    fn zat(v: u64) -> Zatoshis {
        Zatoshis::from_u64(v).unwrap()
    }

    fn h(v: u32) -> BlockHeight {
        BlockHeight::from_u32(v)
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
            transactions.push(MigrationTransaction::from_parts(
                MigrationTxId::new(i as u32),
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
            transactions.push(MigrationTransaction::from_parts(
                MigrationTxId::new(offset + i as u32),
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
        MigrationState::from_parts(
            status,
            NoteSplitPlan::from_stored_parts(
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
        )
    }

    const MINED: MigrationTxState = MigrationTxState::Mined {
        height: BlockHeight::from_u32(100),
    };

    #[test]
    fn derive_no_migration_is_not_started() {
        assert!(matches!(
            derive_state(None, h(100), &[], None),
            DerivedState::NotStarted
        ));
    }

    #[test]
    fn derive_failed_run_is_not_started() {
        let state = test_state(
            MigrationStatus::Failed,
            &[MigrationTxState::Signed],
            &[MigrationTxState::Signed],
            50,
            10_000,
        );
        assert!(matches!(
            derive_state(Some(&state), h(100), &[], None),
            DerivedState::NotStarted
        ));
    }

    #[test]
    fn derive_complete_is_per_run_complete() {
        let state = test_state(MigrationStatus::Complete, &[MINED], &[MINED], 50, 10_000);
        assert!(matches!(
            derive_state(Some(&state), h(100), &[], None),
            DerivedState::Complete
        ));
    }

    #[test]
    fn derive_unmined_prep_is_split_pending() {
        let state = test_state(
            MigrationStatus::InProgress,
            &[MigrationTxState::Signed],
            &[MigrationTxState::Signed],
            50,
            10_000,
        );
        assert!(matches!(
            derive_state(Some(&state), h(100), &[], None),
            DerivedState::SplitPendingConfirmation
        ));
    }

    #[test]
    fn derive_mined_preps_is_in_progress_with_transfer_counts() {
        let state = test_state(
            MigrationStatus::InProgress,
            &[MINED, MINED],
            &[MINED, MigrationTxState::Signed, MigrationTxState::Signed],
            50,
            10_000,
        );
        match derive_state(Some(&state), h(100), &[], None) {
            DerivedState::InProgress {
                completed_transfers,
                total_transfers,
                next_transfer_ready_at_height,
                is_immediate,
            } => {
                assert_eq!(completed_transfers, 1);
                assert_eq!(total_transfers, 3);
                assert_eq!(next_transfer_ready_at_height, Some(h(50)));
                assert!(
                    !is_immediate,
                    "an engine-tracked run must carry is_immediate = false"
                );
            }
            _ => panic!("expected InProgress"),
        }
    }

    /// F6: `next_transfer_ready_at_height` must be the min `scheduled_height()` over transfers
    /// that are still awaiting broadcast (`AwaitingSignature`/`Signed`/`Proved`), not merely "not
    /// yet mined". A `Broadcast` transfer is already in the mempool — there is nothing left for
    /// the platform to prepare or broadcast for it — so its height must not win even when it is
    /// numerically the smallest. Two transfers at DIFFERENT scheduled heights (the low one
    /// `Broadcast`, the high one `Signed`) pin the exact bug: today's `!= Mined` filter still
    /// counts the `Broadcast` row, reporting its LOWER height instead of the `Signed` row's.
    #[test]
    fn derive_next_ready_height_excludes_already_broadcast_transfers() {
        let transactions = vec![
            // Broadcast (in-mempool) at the LOW height — must be excluded.
            MigrationTransaction::from_parts(
                MigrationTxId::new(0),
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
            MigrationTransaction::from_parts(
                MigrationTxId::new(1),
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
        let state = MigrationState::from_parts(
            MigrationStatus::InProgress,
            NoteSplitPlan::from_stored_parts(
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
        );
        match derive_state(Some(&state), h(200), &[], None) {
            DerivedState::InProgress {
                next_transfer_ready_at_height,
                ..
            } => {
                assert_eq!(
                    next_transfer_ready_at_height,
                    Some(h(150)),
                    "a Broadcast (in-mempool) transfer must not count as 'next ready' even when \
                     its scheduled height is numerically lower than a not-yet-broadcast \
                     transfer's"
                );
            }
            _ => panic!("expected InProgress"),
        }
    }

    /// F6: once every transfer is `Broadcast` or `Mined`, nothing remains awaiting broadcast, so
    /// there is no "next ready" height at all (the field's `-1`/`None` sentinel).
    #[test]
    fn derive_next_ready_height_is_none_when_all_transfers_are_broadcast_or_mined() {
        let transactions = vec![
            MigrationTransaction::from_parts(
                MigrationTxId::new(0),
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
            MigrationTransaction::from_parts(
                MigrationTxId::new(1),
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
        let state = MigrationState::from_parts(
            MigrationStatus::InProgress,
            NoteSplitPlan::from_stored_parts(
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
        );
        match derive_state(Some(&state), h(200), &[], None) {
            DerivedState::InProgress {
                next_transfer_ready_at_height,
                ..
            } => {
                assert_eq!(next_transfer_ready_at_height, None);
            }
            _ => panic!("expected InProgress"),
        }
    }

    #[test]
    fn derive_invalid_mark_wins() {
        let state = test_state(
            MigrationStatus::InProgress,
            &[MINED],
            &[MigrationTxState::Signed],
            50,
            10_000,
        );
        assert!(matches!(
            derive_state(Some(&state), h(100), &[1], None),
            DerivedState::InvalidTransfer(1)
        ));
    }

    #[test]
    fn derive_expired_unmined_requires_attention() {
        let state = test_state(
            MigrationStatus::InProgress,
            &[MINED],
            &[MigrationTxState::Signed],
            50,
            90,
        );
        assert!(matches!(
            derive_state(Some(&state), h(100), &[], None),
            DerivedState::TransferExpired
        ));
    }

    /// ZIP 203 / engine semantics (`zcash_pool_migration_backend::state::MigrationState::is_expired`):
    /// a transaction may be mined only in a block at or below its `expiry_height`, so it is
    /// expired as soon as the NEXT block (`target = tip + 1`) would exceed that height — i.e.
    /// exactly when `tip == expiry_height`, one block EARLIER than a naive `tip > expiry_height`
    /// check would catch it. Pins the exact boundary the old hand-rolled check in `derive_state`
    /// missed.
    #[test]
    fn derive_expired_at_exact_tip_boundary_requires_attention() {
        let state = test_state(
            MigrationStatus::InProgress,
            &[MINED],
            &[MigrationTxState::Signed],
            50,
            100, // expiry_height == tip
        );
        assert!(
            matches!(
                derive_state(Some(&state), h(100), &[], None),
                DerivedState::TransferExpired
            ),
            "expiry_height == tip can no longer be mined in the next block and must derive \
             TransferExpired, not InProgress"
        );
    }

    /// `expiry_height == 0` is the engine's "never expires" sentinel (see
    /// `MigrationState::is_expired`'s doc); it must not be caught by any expiry check, however
    /// large the tip grows.
    #[test]
    fn derive_never_expires_when_expiry_height_is_zero() {
        let state = test_state(
            MigrationStatus::InProgress,
            &[MINED],
            &[MigrationTxState::Signed],
            50,
            0, // expiry_height == 0: never expires
        );
        assert!(
            matches!(
                derive_state(Some(&state), h(1_000_000), &[], None),
                DerivedState::InProgress { .. }
            ),
            "expiry_height == 0 must never expire, even at a huge tip"
        );
    }

    /// Builds an [`ImmediateRunLookup`] directly (bypassing the wallet-DB lookup), for exercising
    /// `derive_state`'s immediate-run precedence rule in isolation.
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
    fn derive_immediate_run_pending_is_in_progress_of_one() {
        let run = immediate_lookup(100, None, Some(500));
        match derive_state(None, h(300), &[], Some(&run)) {
            DerivedState::InProgress {
                completed_transfers,
                total_transfers,
                next_transfer_ready_at_height,
                is_immediate,
            } => {
                assert_eq!(completed_transfers, 0);
                assert_eq!(total_transfers, 1);
                assert_eq!(next_transfer_ready_at_height, None);
                assert!(
                    is_immediate,
                    "an immediate-lane run must carry is_immediate = true"
                );
            }
            _ => panic!("expected InProgress"),
        }
    }

    #[test]
    fn derive_immediate_run_mined_is_consumed() {
        // R2: a mined immediate sweep is CONSUMED — the swept balance is zero and there is nothing
        // for the app to acknowledge, so it derives no migration UI (NotStarted), not a `Complete`
        // screen. If new Orchard funds arrive later, the ordinary balance-gated re-offer applies.
        let run = immediate_lookup(100, Some(250), Some(500));
        assert!(matches!(
            derive_state(None, h(300), &[], Some(&run)),
            DerivedState::NotStarted
        ));
    }

    #[test]
    fn derive_mined_immediate_run_masks_stale_complete_engine_state() {
        // R2 masking rule: a consumed (mined) immediate run must suppress a stale engine `Complete`
        // left by an earlier engine-tracked run, so the user sees NO migration UI at all — neither
        // the immediate run's own screen (a mined immediate run has none) nor the stale Complete.
        // Net: NotStarted.
        let state = test_state(MigrationStatus::Complete, &[MINED], &[MINED], 50, 10_000);
        let run = immediate_lookup(1_000, Some(1_050), Some(1_500));
        assert!(matches!(
            derive_state(Some(&state), h(1_100), &[], Some(&run)),
            DerivedState::NotStarted
        ));
    }

    #[test]
    fn derive_immediate_run_expired_unmined_falls_through_to_not_started() {
        let run = immediate_lookup(100, None, Some(200));
        assert!(matches!(
            derive_state(None, h(300), &[], Some(&run)),
            DerivedState::NotStarted
        ));
    }

    #[test]
    fn derive_immediate_run_unknown_expiry_uses_fallback_bound() {
        let run = immediate_lookup(100, None, None);
        // Still within the fallback bound (100 + 40 = 140).
        assert!(matches!(
            derive_state(None, h(140), &[], Some(&run)),
            DerivedState::InProgress { .. }
        ));
        // Past the fallback bound: expired, falls through.
        assert!(matches!(
            derive_state(None, h(141), &[], Some(&run)),
            DerivedState::NotStarted
        ));
    }

    #[test]
    fn derive_engine_active_run_wins_over_immediate_run() {
        // An active (unmined-prep) engine run derives to SplitPendingConfirmation on its own.
        let state = test_state(
            MigrationStatus::InProgress,
            &[MigrationTxState::Signed],
            &[MigrationTxState::Signed],
            50,
            10_000,
        );
        // This immediate run is mined, so on its own it would be consumed (NotStarted) — but the
        // active engine run wins regardless.
        let run = immediate_lookup(100, Some(250), Some(500));
        assert!(matches!(
            derive_state(Some(&state), h(300), &[], Some(&run)),
            DerivedState::SplitPendingConfirmation
        ));
    }

    #[test]
    fn derive_unmined_immediate_run_overrides_stale_complete_engine_state() {
        // A `Complete` engine run is terminal (not "active"), so a separate, later UNMINED (still
        // live) immediate run still gets a say instead of being masked by the stale Complete
        // verdict: it derives its own `InProgress`. (A MINED immediate run instead masks the stale
        // Complete to NotStarted — see `derive_mined_immediate_run_masks_stale_complete_engine_state`.)
        let state = test_state(MigrationStatus::Complete, &[MINED], &[MINED], 50, 10_000);
        let run = immediate_lookup(1_000, None, Some(1_500));
        match derive_state(Some(&state), h(1_100), &[], Some(&run)) {
            DerivedState::InProgress {
                completed_transfers,
                total_transfers,
                is_immediate,
                ..
            } => {
                assert_eq!(completed_transfers, 0);
                assert_eq!(total_transfers, 1);
                assert!(
                    is_immediate,
                    "the immediate run that wins is an immediate-lane run"
                );
            }
            _ => panic!(
                "expected the immediate run's InProgress to win over the stale Complete engine state"
            ),
        }
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
        let schedule = scheduling::schedule(h(1_000), 5, &mut rng);
        // `crossing_values` mirrors a real plan's `note_split().crossing_values()`: the NET
        // turnstile value at each index (F3 — `schedule_rows` reads this directly, it no longer
        // takes a gross funding note plus a fee buffer to subtract).
        let buffer = zat(10_000);
        let crossing_values: Vec<Zatoshis> = (1..=5)
            .map(|i| (zat(i * 100_000_000) - buffer).unwrap())
            .collect();
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
        let schedule_a = scheduling::schedule(h(1_000), 5, &mut rng_a);
        let rows_a = schedule_rows(&crossing_values, &schedule_a, 0).unwrap();

        let mut rng_b = StdRng::seed_from_u64(99);
        let schedule_b = scheduling::schedule(h(1_000), 5, &mut rng_b);
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
        let schedule = scheduling::schedule(h(1_000), 3, &mut rng);
        let crossing_values = vec![zat(100)];
        assert!(schedule_rows(&crossing_values, &schedule, 0).is_err());
    }

    /// F3 pin: `schedule_rows`' amount is BOTH the engine's authoritative
    /// `note_split().crossing_values()[crossing]` (trivially — that is now its input) AND the
    /// legacy `funding_notes()[crossing] - note_fee_buffer` computation it replaces, proven equal
    /// for a real `NoteSplitPlan`. Pure refactor: values are identical, so this is green
    /// immediately (no red phase — see F3's task doc).
    #[test]
    fn schedule_rows_amount_matches_engine_crossing_values_and_legacy_subtraction() {
        let mut rng = StdRng::seed_from_u64(11);
        let crossing_values = vec![zat(100_000_000), zat(250_000_000), zat(40_000_000)];
        let note_split = NoteSplitPlan::from_stored_parts(
            crossing_values.clone(),
            zat(10_000),
            None,
            zat(20_000),
            zat(1_000_000_000),
            zat(999_000_000),
        )
        .unwrap();
        let schedule = scheduling::schedule(h(1_000), crossing_values.len(), &mut rng);
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
        MigrationTransaction::from_parts(
            MigrationTxId::new(id),
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
            MigrationTransaction::from_parts(
                MigrationTxId::new(0),
                MigrationTxKind::Transfer { crossing: 0 },
                vec![0u8],
                Vec::new(),
                h(1_000_336),
                h(1_100_000),
                Some(h(1_000_336)),
                MigrationTxState::Signed,
                None,
            ),
            MigrationTransaction::from_parts(
                MigrationTxId::new(1),
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
        let state = MigrationState::from_parts(
            MigrationStatus::InProgress,
            NoteSplitPlan::from_stored_parts(
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
        );

        let schedule_ptr =
            encode_schedule_from_state(&state, h(1_000_000)).expect("encoding must succeed");
        let schedule = unsafe { &*schedule_ptr };
        assert_eq!(schedule.estimated_duration_hours, 9);
        unsafe { zcashlc_free_migration_schedule(schedule_ptr) };
    }

    // ----- verified consent echoes (F4) -----

    fn row(id: u32, amount: i64, next_executable_after_height: i64, expiry_height: i64) -> EchoRow {
        EchoRow {
            id,
            amount,
            next_executable_after_height,
            expiry_height,
        }
    }

    fn stored_row(id: u32, amount: i64, expiry_height: i64) -> StoredEchoRow {
        StoredEchoRow {
            id,
            amount,
            expiry_height,
        }
    }

    #[test]
    fn schedule_echo_matches_accepts_a_matching_echo_regardless_of_order() {
        let expected = vec![row(1, 100, 50, 5_000), row(2, 200, 60, 6_000)];
        // The platform's echo is in the OPPOSITE order — order must not matter.
        let got = vec![row(2, 200, 60, 6_000), row(1, 100, 50, 5_000)];
        assert!(schedule_echo_matches(expected, 10, got, 10));
    }

    #[test]
    fn schedule_echo_matches_detects_wrong_amount() {
        let expected = vec![row(1, 100, 50, 5_000), row(2, 200, 60, 6_000)];
        // Id 2's amount is echoed wrong (201 instead of 200).
        let got = vec![row(1, 100, 50, 5_000), row(2, 201, 60, 6_000)];
        assert!(!schedule_echo_matches(expected, 10, got, 10));
    }

    #[test]
    fn schedule_echo_matches_detects_a_length_mismatch() {
        let expected = vec![row(1, 100, 50, 5_000), row(2, 200, 60, 6_000)];
        // Only one of the two expected transfers is echoed back (a wrong id COUNT).
        let got = vec![row(1, 100, 50, 5_000)];
        assert!(!schedule_echo_matches(expected, 10, got, 10));
    }

    #[test]
    fn schedule_echo_matches_detects_wrong_duration() {
        let expected = vec![row(1, 100, 50, 5_000)];
        let got = vec![row(1, 100, 50, 5_000)];
        assert!(!schedule_echo_matches(expected, 10, got, 11));
    }

    #[test]
    fn note_split_echo_matches_accepts_a_matching_echo_regardless_of_order() {
        assert!(note_split_echo_matches(&[100, 200], 50, vec![200, 100], 50));
    }

    #[test]
    fn note_split_echo_matches_detects_wrong_fee() {
        assert!(!note_split_echo_matches(
            &[100, 200],
            50,
            vec![100, 200],
            51
        ));
    }

    #[test]
    fn note_split_echo_matches_detects_wrong_outputs() {
        assert!(!note_split_echo_matches(
            &[100, 200],
            50,
            vec![100, 201],
            50
        ));
    }

    /// [`expected_rows_from_state`] pins the state-derived echo used to validate
    /// `zcashlc_migration_create_unsigned_transfer_pczts`'s echo: only the TRANSFER subset
    /// appears (the preparation transaction is excluded), amounts pair via `funding_notes()`
    /// (crossing-indexed, not declaration order). No duration is returned at all (post-#1806 —
    /// see [`StoredEchoRow`]'s doc for why it is excluded from the STATE-side comparison
    /// entirely); [`validate_schedule_echo_against_state_ignores_estimated_duration_hours`] pins
    /// that exclusion end to end.
    #[test]
    fn expected_rows_from_state_pins_transfer_subset() {
        let transactions = vec![
            MigrationTransaction::from_parts(
                MigrationTxId::new(0),
                MigrationTxKind::Preparation { layer: 0, index: 0 },
                vec![0u8],
                Vec::new(),
                h(50),
                h(10_000),
                None,
                MigrationTxState::Mined { height: h(60) },
                None,
            ),
            MigrationTransaction::from_parts(
                MigrationTxId::new(1),
                MigrationTxKind::Transfer { crossing: 0 },
                vec![0u8],
                Vec::new(),
                h(100),
                h(5_000),
                Some(h(100)),
                MigrationTxState::Signed,
                None,
            ),
            MigrationTransaction::from_parts(
                MigrationTxId::new(2),
                MigrationTxKind::Transfer { crossing: 1 },
                vec![0u8],
                Vec::new(),
                h(220),
                h(6_000),
                Some(h(220)),
                MigrationTxState::Signed,
                None,
            ),
        ];
        // Crossing values, a zero fee buffer (so `funding_notes()` == these values exactly,
        // keeping the amounts under test free of extra fee-buffer arithmetic).
        let crossing_values = vec![zat(100_000_000), zat(250_000_000)];
        let state = MigrationState::from_parts(
            MigrationStatus::InProgress,
            NoteSplitPlan::from_stored_parts(
                crossing_values,
                zat(0),
                None,
                zat(20_000),
                zat(1_000_000_000),
                zat(999_000_000),
            )
            .unwrap(),
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            transactions,
        );

        let mut rows = expected_rows_from_state(&state);
        rows.sort();
        // No `next_executable_after_height` field: the state-side echo excludes it (see
        // `StoredEchoRow`'s doc) even though the two transfers here have DIFFERENT scheduled
        // heights (100, 220).
        assert_eq!(
            rows,
            vec![
                stored_row(1, zat_to_i64(zat(100_000_000)), 5_000),
                stored_row(2, zat_to_i64(zat(250_000_000)), 6_000),
            ]
        );
    }

    /// Builds real, null-terminated C strings for `ids` (matching what the FFI layer decodes) and
    /// hands back both the owning `CString`s (keep them alive for the duration of the call) and
    /// the `*const c_char` pointers to pass.
    fn c_ids(ids: &[u32]) -> (Vec<CString>, Vec<*const c_char>) {
        let owned: Vec<CString> = ids
            .iter()
            .map(|id| CString::new(id.to_string()).unwrap())
            .collect();
        let ptrs = owned.iter().map(|s| s.as_ptr()).collect();
        (owned, ptrs)
    }

    #[test]
    fn validate_schedule_echo_against_state_accepts_a_matching_echo() {
        let state = test_state(
            MigrationStatus::InProgress,
            &[],
            &[MigrationTxState::Signed, MigrationTxState::Signed],
            50,
            10_000,
        );
        // `test_state`'s two transfers (ids 0, 1) both cross 100_000_000 zatoshi NET (the stored
        // funding note is gross of the fixed 10_000-zatoshi fee buffer; `transfer_amount` nets it
        // back out), at height 50, expiring at 10_000; the echoed duration (`0` below) is
        // excluded from the state-side comparison entirely (see `StoredEchoRow`), so its value
        // is arbitrary here.
        let (_owned, ids) = c_ids(&[0, 1]);
        let amounts = [100_000_000i64, 100_000_000i64];
        let next_executable_after_heights = [50i64, 50i64];
        let expiry_heights = [10_000i64, 10_000i64];
        assert!(
            validate_schedule_echo_against_state(
                &state,
                &ids,
                &amounts,
                &next_executable_after_heights,
                &expiry_heights,
                0,
            )
            .is_ok()
        );
    }

    /// Pins Part B's "wrong id count" lane (`zcashlc_migration_create_unsigned_transfer_pczts`):
    /// the stored run has two transfers, but only one is echoed back — a real
    /// [`MigrationState`] (built the same way the real production code reads one, via
    /// `test_state`), driven through the exact function the FFI entry point calls.
    #[test]
    fn validate_schedule_echo_against_state_detects_wrong_id_count() {
        let state = test_state(
            MigrationStatus::InProgress,
            &[],
            &[MigrationTxState::Signed, MigrationTxState::Signed],
            50,
            10_000,
        );
        let (_owned, ids) = c_ids(&[0]);
        let amounts = [100_000_000i64];
        let next_executable_after_heights = [50i64];
        let expiry_heights = [10_000i64];
        let err = validate_schedule_echo_against_state(
            &state,
            &ids,
            &amounts,
            &next_executable_after_heights,
            &expiry_heights,
            0,
        )
        .unwrap_err();
        assert!(err.to_string().starts_with(PLAN_STALE_PREFIX));
    }

    #[test]
    fn validate_schedule_echo_against_state_detects_wrong_amount() {
        let state = test_state(
            MigrationStatus::InProgress,
            &[],
            &[MigrationTxState::Signed],
            50,
            10_000,
        );
        let (_owned, ids) = c_ids(&[0]);
        // The stored transfer crosses 100_000_000 zatoshi net; the echo claims one more.
        let amounts = [100_000_001i64];
        let next_executable_after_heights = [50i64];
        let expiry_heights = [10_000i64];
        let err = validate_schedule_echo_against_state(
            &state,
            &ids,
            &amounts,
            &next_executable_after_heights,
            &expiry_heights,
            0,
        )
        .unwrap_err();
        assert!(err.to_string().starts_with(PLAN_STALE_PREFIX));
    }

    #[test]
    fn validate_schedule_echo_against_state_detects_wrong_expiry() {
        let state = test_state(
            MigrationStatus::InProgress,
            &[],
            &[MigrationTxState::Signed],
            50,
            10_000,
        );
        let (_owned, ids) = c_ids(&[0]);
        let amounts = [100_000_000i64];
        let next_executable_after_heights = [50i64];
        // The stored transfer expires at 10_000; the echo claims 10_001.
        let expiry_heights = [10_001i64];
        let err = validate_schedule_echo_against_state(
            &state,
            &ids,
            &amounts,
            &next_executable_after_heights,
            &expiry_heights,
            0,
        )
        .unwrap_err();
        assert!(err.to_string().starts_with(PLAN_STALE_PREFIX));
    }

    /// Regression test for the false-fail the review caught: the platform's display copy carries
    /// the `next_executable_after_height` it last saw, but a stored transfer's `scheduled_height`
    /// legitimately moves (a refresh rebuild reschedules from the current tip) — these
    /// legitimately differ whenever a block lands during the user's review window (ordinary
    /// ~75s Zcash block times, not a rare race). An honest, unmodified echo of the displayed
    /// preview must still succeed against the stored state even though this one field "drifted";
    /// unlike a genuinely stale plan, re-proposing could never make it converge (the stored value
    /// is already fixed by the completed commit), so the only correct behavior is to not compare
    /// it at all here (`ids`/`amounts`/`expiry_heights` are unaffected and still pinned by the
    /// other tests in this group; `estimated_duration_hours` has its own dedicated exclusion test,
    /// [`validate_schedule_echo_against_state_ignores_estimated_duration_hours`], immediately
    /// below).
    #[test]
    fn validate_schedule_echo_against_state_ignores_drifted_next_executable_after_height() {
        let state = test_state(
            MigrationStatus::InProgress,
            &[],
            &[MigrationTxState::Signed],
            50,
            10_000,
        );
        let (_owned, ids) = c_ids(&[0]);
        let amounts = [100_000_000i64];
        // Drifted far from the stored transfer's actual scheduled height (50) — as if a block (or
        // several) landed between the immediate-lane preview and the commit that rescheduled it.
        let next_executable_after_heights = [999_999i64];
        let expiry_heights = [10_000i64];
        assert!(
            validate_schedule_echo_against_state(
                &state,
                &ids,
                &amounts,
                &next_executable_after_heights,
                &expiry_heights,
                0,
            )
            .is_ok()
        );
    }

    /// Fix-wave 1 (#1806 follow-up): the STATE-side echo accepts ANY `estimated_duration_hours`
    /// once `ids`/`amounts`/`expiry_heights` match — post-fix, duration is derived,
    /// serve-time-relative display metadata (see [`StoredEchoRow`]'s doc), not a value the
    /// STATE-side echo can hold the platform to. Two transfers at DIFFERENT scheduled heights
    /// (100, 220) so a naive re-derivation would depend on which tip you read at; the echoed
    /// duration here (`999_999`) is one no computation over this state could ever produce at any
    /// real tip — proving it genuinely is not compared, not just coincidentally matching.
    ///
    /// Contrast [`schedule_echo_matches_detects_wrong_duration`]: the PRE-commit CACHE-side echo
    /// still rejects a wrong duration exactly, because `cached.reference_height` makes it
    /// byte-for-byte reproducible with zero drift (see [`expected_rows_from_cached_plan`]'s doc).
    /// That asymmetry — checked before commit, not after — is deliberate.
    #[test]
    fn validate_schedule_echo_against_state_ignores_estimated_duration_hours() {
        let transactions = vec![
            MigrationTransaction::from_parts(
                MigrationTxId::new(0),
                MigrationTxKind::Transfer { crossing: 0 },
                vec![0u8],
                Vec::new(),
                h(100),
                h(5_000),
                Some(h(100)),
                MigrationTxState::Signed,
                None,
            ),
            MigrationTransaction::from_parts(
                MigrationTxId::new(1),
                MigrationTxKind::Transfer { crossing: 1 },
                vec![0u8],
                Vec::new(),
                h(220),
                h(6_000),
                Some(h(220)),
                MigrationTxState::Signed,
                None,
            ),
        ];
        // Zero fee buffer, as in `expected_rows_from_state_pins_transfer_subset`, so
        // `funding_notes()` equals the crossing values exactly.
        let state = MigrationState::from_parts(
            MigrationStatus::InProgress,
            NoteSplitPlan::from_stored_parts(
                vec![zat(100_000_000), zat(250_000_000)],
                zat(0),
                None,
                zat(20_000),
                zat(1_000_000_000),
                zat(999_000_000),
            )
            .unwrap(),
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            transactions,
        );
        let (_owned, ids) = c_ids(&[0, 1]);
        let amounts = [zat_to_i64(zat(100_000_000)), zat_to_i64(zat(250_000_000))];
        // Unchecked either way here, but filled in with the rows' real scheduled heights for
        // realism.
        let next_executable_after_heights = [100i64, 220i64];
        let expiry_heights = [5_000i64, 6_000i64];
        assert!(
            validate_schedule_echo_against_state(
                &state,
                &ids,
                &amounts,
                &next_executable_after_heights,
                &expiry_heights,
                999_999,
            )
            .is_ok(),
            "estimated_duration_hours must not be part of the STATE-side exact match"
        );
    }

    #[test]
    fn plan_cache_round_trip_and_clear() {
        let path = PathBuf::from("/tmp/zcashlc-plan-cache-test");
        let account = [3u8; 16];
        assert!(migration_plan_cache::get(&path, account).is_none());
        // A real plan is unconstructible here; the cache API is exercised end-to-end by the
        // welding offline tests. This pins the miss behavior only.
        migration_plan_cache::clear(&path, account);
        assert!(migration_plan_cache::get(&path, account).is_none());
    }

    #[test]
    fn invalid_marks_round_trip() {
        let conn = Connection::open_in_memory().unwrap();
        init_invalid_marks(&conn).unwrap();
        let account = [9u8; 16];
        let other = [8u8; 16];
        assert!(invalid_marks(&conn, &account).unwrap().is_empty());
        insert_invalid_mark(&conn, &account, MigrationTxId::new(4), "invalid_note").unwrap();
        insert_invalid_mark(&conn, &account, MigrationTxId::new(2), "expired").unwrap();
        insert_invalid_mark(&conn, &other, MigrationTxId::new(7), "invalid_note").unwrap();
        assert_eq!(invalid_marks(&conn, &account).unwrap(), vec![2, 4]);
        clear_invalid_marks(&conn, &account).unwrap();
        assert!(invalid_marks(&conn, &account).unwrap().is_empty());
        assert_eq!(invalid_marks(&conn, &other).unwrap(), vec![7]);
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

    /// A freshly initialized wallet database has no stored migration, so its state marshals as
    /// `NotStarted`. The store tables come from the wallet schema migrations (they are no longer
    /// created by `open`), so the fixture runs `zcashlc_init_data_database` first, exactly like a
    /// real caller — and creates the account it queries, since the account-keyed store resolves
    /// the account row up front. This exercises `open` (path decode, `parse_network`, store read)
    /// end to end over the FFI.
    #[test]
    fn migration_state_on_fresh_db_is_not_started() {
        let path = std::env::temp_dir().join(format!(
            "zcashlc_migration_state_{}.sqlite",
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
            zcashlc_migration_state(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert!(!ptr.is_null(), "state pointer must be non-null on success");
        assert!(
            matches!(unsafe { &*ptr }, FfiMigrationState::NotStarted),
            "a fresh database must report NotStarted"
        );
        unsafe { zcashlc_free_migration_state(ptr) };
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
        let mut store = PoolMigrations::for_account(&mut conn, account)
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
        zcash_pool_migration_backend::build::build_transfer_pczt(
            &MAIN_NETWORK,
            target_height,
            expiry_height,
            &fvk,
            note,
            zat(crossing),
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
        let row_id = unsafe { CStr::from_ptr(row.id) }
            .to_str()
            .expect("the row id is UTF-8");
        assert_eq!(row_id, "0", "the stored transfer's engine id");
        // The state-side amount is the NET crossing (funding note minus the fee buffer), exactly
        // what the consent echo compares (`expected_rows_from_state` uses the same
        // `transfer_amount`, which nets the buffer on this branch).
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
                MigrationTransaction::from_parts(
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
        let state = MigrationState::from_parts(
            base.status(),
            base.note_split().clone(),
            base.preparation().clone(),
            transactions,
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
        let store = PoolMigrations::for_account(&mut conn, account_id)
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

    use zcash_pool_migration_backend::engine::MigrationProver;
    use zcash_pool_migration_backend::wallet::WalletProveError;
    use zcash_protocol::consensus::BranchId;

    /// The prover error type the dispatch tests fail with: the REAL upstream
    /// [`WalletProveError`] (so the classification under test is the production one), with unit
    /// tree/note/chain-state error parameters.
    type TestProveError = WalletProveError<(), (), ()>;

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
        ) -> Result<pczt::Pczt, Self::Error> {
            self.calls.push(ProveCall::Transfer(anchor_boundary));
            Ok(pczt)
        }

        fn prove_preparation(
            &mut self,
            pczt: pczt::Pczt,
            anchor: BlockHeight,
        ) -> Result<pczt::Pczt, Self::Error> {
            self.calls.push(ProveCall::Preparation(anchor));
            Ok(pczt)
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
        ) -> Result<pczt::Pczt, Self::Error> {
            Err(self.error.take().expect("the prover is consulted once"))
        }

        fn prove_preparation(
            &mut self,
            _pczt: pczt::Pczt,
            _anchor: BlockHeight,
        ) -> Result<pczt::Pczt, Self::Error> {
            Err(self.error.take().expect("the prover is consulted once"))
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
                MigrationTransaction::from_parts(
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
        MigrationState::from_parts(
            base.status(),
            base.note_split().clone(),
            base.preparation().clone(),
            transactions,
        )
    }

    /// A TRANSFER proves via `prove_transfer` with EXACTLY the boundary persisted on its row —
    /// the caller resolves NO natural anchor for it (`None`, the lazy per-kind contract: a wallet
    /// whose natural anchor is not resolvable yet must still prove transfers) — and the proven
    /// bytes persist through the engine's `Proved` state.
    #[test]
    fn prove_dispatch_routes_a_transfer_to_its_stored_boundary() {
        let mut state = provable_state(&[MINED], &[MigrationTxState::Signed], Some(h(1440)));
        let mut prover = RecordingProver { calls: Vec::new() };
        let res = migration_finalize::prove_due_transaction(
            &mut prover,
            &mut state,
            MigrationTxId::new(1),
            None,
        )
        .expect("a boundary-carrying transfer proves");
        assert_eq!(res, Some(()), "the transfer must prove, not defer");
        assert_eq!(
            prover.calls,
            vec![ProveCall::Transfer(h(1440))],
            "the prover must receive the row's drawn boundary, never the natural anchor"
        );
        let tx = state
            .transactions()
            .iter()
            .find(|t| t.id() == MigrationTxId::new(1))
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

    /// A PREPARATION proves via `prove_preparation` with the caller-supplied natural anchor (a
    /// preparation carries no drawn boundary).
    #[test]
    fn prove_dispatch_routes_a_preparation_to_the_natural_anchor() {
        let mut state = provable_state(
            &[MigrationTxState::Signed],
            &[MigrationTxState::Signed],
            Some(h(1440)),
        );
        let mut prover = RecordingProver { calls: Vec::new() };
        let res = migration_finalize::prove_due_transaction(
            &mut prover,
            &mut state,
            MigrationTxId::new(0),
            Some(h(777)),
        )
        .expect("a signed preparation proves");
        assert_eq!(res, Some(()), "the preparation must prove, not defer");
        assert_eq!(
            prover.calls,
            vec![ProveCall::Preparation(h(777))],
            "the prover must receive the natural anchor"
        );
        let tx = state
            .transactions()
            .iter()
            .find(|t| t.id() == MigrationTxId::new(0))
            .expect("the preparation row remains");
        assert!(
            matches!(tx.state(), MigrationTxState::Proved),
            "the engine must persist Signed -> Proved"
        );
    }

    /// A TRANSFER whose row carries NO drawn boundary is a corrupt store: a hard error on the
    /// proving-unavailable route — never a silent fallback to the natural anchor (the prover is
    /// not consulted at all).
    #[test]
    fn prove_dispatch_transfer_without_boundary_is_a_hard_error() {
        let mut state = provable_state(&[MINED], &[MigrationTxState::Signed], None);
        let mut prover = RecordingProver { calls: Vec::new() };
        let err = migration_finalize::prove_due_transaction(
            &mut prover,
            &mut state,
            MigrationTxId::new(1),
            None,
        )
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
            .find(|t| t.id() == MigrationTxId::new(1))
            .expect("the transfer row remains");
        assert!(
            matches!(tx.state(), MigrationTxState::Signed),
            "the transaction must stay Signed"
        );
    }

    /// Every prover failure meaning "the wallet has not scanned or retained that boundary yet"
    /// (a restored wallet mid-sync, or a transfer due before the wallet scanned past its
    /// boundary) maps to the transient nothing-due `Ok(None)`, leaving the transaction `Signed`
    /// for a later retry.
    #[test]
    fn prove_dispatch_maps_every_transient_prover_error_to_nothing_due() {
        let transients: Vec<TestProveError> = vec![
            WalletProveError::AnchorNotFound(h(1440)),
            WalletProveError::WitnessNotFound(h(1440)),
            WalletProveError::ChainTipUnknown,
            WalletProveError::IronwoodTreeUnavailable,
        ];
        for error in transients {
            let label = format!("{error}");
            let mut state = provable_state(&[MINED], &[MigrationTxState::Signed], Some(h(1440)));
            let mut prover = FailingProver { error: Some(error) };
            let res = migration_finalize::prove_due_transaction(
                &mut prover,
                &mut state,
                MigrationTxId::new(1),
                None,
            )
            .unwrap_or_else(|e| panic!("{label} must be transient, got hard error: {e}"));
            assert_eq!(res, None, "{label} must map to the nothing-due lane");
            let tx = state
                .transactions()
                .iter()
                .find(|t| t.id() == MigrationTxId::new(1))
                .expect("the transfer row remains");
            assert!(
                matches!(tx.state(), MigrationTxState::Signed),
                "{label} must leave the transaction Signed for a retry"
            );
        }
    }

    /// Every other prover failure is HARD and carries the stable proving-unavailable prefix the
    /// Swift layer maps to `migrationProvingUnavailable`.
    #[test]
    fn prove_dispatch_routes_hard_prover_errors_through_the_proving_unavailable_prefix() {
        let nullifier = Option::from(orchard::note::Nullifier::from_bytes(&[0u8; 32]))
            .expect("zero is a valid nullifier encoding");
        let hards: Vec<TestProveError> = vec![
            WalletProveError::UnknownSpentNote(nullifier),
            WalletProveError::Notes(()),
            WalletProveError::Tree(shardtree::error::ShardTreeError::Query(
                shardtree::error::QueryError::CheckpointPruned,
            )),
            WalletProveError::Prove("proof backend failure".into()),
        ];
        for error in hards {
            let label = format!("{error}");
            let mut state = provable_state(&[MINED], &[MigrationTxState::Signed], Some(h(1440)));
            let mut prover = FailingProver { error: Some(error) };
            let err = migration_finalize::prove_due_transaction(
                &mut prover,
                &mut state,
                MigrationTxId::new(1),
                None,
            )
            .expect_err(&format!("{label} must be a hard error"));
            assert!(
                err.to_string().starts_with(PROVING_UNAVAILABLE_PREFIX),
                "{label} must carry the proving-unavailable prefix, got: {err}"
            );
        }
    }

    /// A PREPARATION reaching the dispatch WITHOUT a resolved natural anchor is a caller bug and
    /// a hard proving-unavailable error — never a silent prove against a wrong anchor (the prover
    /// is not consulted at all). This is the guard behind the lazy per-kind resolution: only the
    /// preparation arm may demand the natural anchor.
    #[test]
    fn prove_dispatch_preparation_without_a_natural_anchor_is_a_hard_error() {
        let mut state = provable_state(
            &[MigrationTxState::Signed],
            &[MigrationTxState::Signed],
            Some(h(1440)),
        );
        let mut prover = RecordingProver { calls: Vec::new() };
        let err = migration_finalize::prove_due_transaction(
            &mut prover,
            &mut state,
            MigrationTxId::new(0),
            None,
        )
        .expect_err("a preparation without a natural anchor must not prove");
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
                MigrationTransaction::from_parts(
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
        MigrationState::from_parts(
            base.status(),
            base.note_split().clone(),
            base.preparation().clone(),
            transactions,
        )
    }

    /// The test-side counterpart of [`prove_if_needed`] for [`drive_and_serve_next_due`]: proves
    /// through the same generic [`migration_finalize::prove_due_transaction`] seam with the given
    /// test prover instead of the production `WalletMigrationProver`, persists through the same
    /// account-keyed store, and serves the stored bytes. The txid is zeroed (these fixture PCZTs
    /// carry no extractable transaction) and the natural anchor is never resolved (these fixtures
    /// drive transfers only, which prove against their persisted boundary).
    fn prove_with_test_prover<P>(
        path: &std::path::Path,
        account: &[u8; 16],
        prover: &mut P,
        state: &mut MigrationState,
        id: MigrationTxId,
    ) -> anyhow::Result<Option<(Vec<u8>, [u8; 32])>>
    where
        P: MigrationProver,
        P::Error: ProveErrorClass + std::fmt::Display,
    {
        let tx_state = state
            .transactions()
            .iter()
            .find(|t| t.id() == id)
            .map(|t| t.state())
            .expect("the driven id exists in the fixture state");
        match tx_state {
            MigrationTxState::Proved => {
                let bytes = state
                    .transactions()
                    .iter()
                    .find(|t| t.id() == id)
                    .expect("the driven id exists in the fixture state")
                    .pczt()
                    .clone();
                Ok(Some((bytes, [0u8; 32])))
            }
            MigrationTxState::Signed => {
                if migration_finalize::prove_due_transaction(prover, state, id, None)?.is_none() {
                    return Ok(None);
                }
                store_fixture_state(path, account, state);
                let bytes = state
                    .transactions()
                    .iter()
                    .find(|t| t.id() == id)
                    .expect("the driven id exists in the fixture state")
                    .pczt()
                    .clone();
                Ok(Some((bytes, [0u8; 32])))
            }
            other => panic!("the drive must not prove a row in state {}", other.as_ref()),
        }
    }

    /// Re-reads the stored migration for `account`, for asserting what the drive persisted.
    fn read_fixture_state(path: &std::path::Path, account: &[u8; 16]) -> MigrationState {
        let mut conn = Connection::open(path).expect("the verification connection opens");
        let account_id = account_uuid_from_bytes(account.as_ptr()).expect("16 uuid bytes");
        let store = PoolMigrations::for_account(&mut conn, account_id)
            .expect("the account-keyed store resolves the fixture account");
        store
            .get_migration()
            .expect("the store reads")
            .expect("a migration is stored")
    }

    /// The delivery serving path drives a due `Signed` transfer through proving — `Signed ->
    /// Proved`, PERSISTED — and serves it, instead of answering "nothing due" forever: commit
    /// stores every transaction `Signed` (never `Proved`), and aside from the note-split
    /// submission's explicit first-preparation prove, this path is the only prover driver.
    #[test]
    fn delivery_serving_proves_a_due_signed_transfer_and_serves_it() {
        let path = init_fixture_db("zcashlc_delivery_serves_signed");
        let account = create_fixture_account(&path);
        let mut state = provable_state(&[MINED], &[MigrationTxState::Signed], Some(h(1440)));
        store_fixture_state(&path, &account, &state);

        let mut prover = RecordingProver { calls: Vec::new() };
        let served = drive_and_serve_next_due(&mut state, h(5_000), |state, id| {
            prove_with_test_prover(&path, &account, &mut prover, state, id)
        })
        .expect("driving a provable, due transfer must not fail");

        let (id, _txid, bytes) = served.expect("the due Signed transfer must be served");
        assert_eq!(id, MigrationTxId::new(1), "the transfer row must be served");
        assert_eq!(
            prover.calls,
            vec![ProveCall::Transfer(h(1440))],
            "the drive must prove exactly once, against the row's persisted boundary"
        );
        let stored = read_fixture_state(&path, &account);
        let tx = stored
            .transactions()
            .iter()
            .find(|t| t.id() == MigrationTxId::new(1))
            .expect("the transfer row remains stored");
        assert!(
            matches!(tx.state(), MigrationTxState::Proved),
            "the drive must persist Signed -> Proved"
        );
        assert_eq!(
            tx.pczt(),
            &bytes,
            "the served bytes must be the persisted proven artifact"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A transient prover outcome (the anchor not scanned/retained yet) on the due `Signed`
    /// transfer maps to "nothing due" — not an error — with the row left `Signed` for a later
    /// retry, and the prover consulted exactly once (the drive DID attempt the prove).
    #[test]
    fn delivery_serving_maps_a_transient_prove_to_nothing_due_leaving_the_row_signed() {
        let path = init_fixture_db("zcashlc_delivery_transient");
        let account = create_fixture_account(&path);
        let mut state = provable_state(&[MINED], &[MigrationTxState::Signed], Some(h(1440)));
        store_fixture_state(&path, &account, &state);

        let mut prover = FailingProver {
            error: Some(WalletProveError::AnchorNotFound(h(1440))),
        };
        let served = drive_and_serve_next_due(&mut state, h(5_000), |state, id| {
            prove_with_test_prover(&path, &account, &mut prover, state, id)
        })
        .expect("a transient prove outcome must not be an error");

        assert!(
            served.is_none(),
            "a transient prove means nothing is due yet"
        );
        assert!(
            prover.error.is_none(),
            "the drive must have consulted the prover for the due Signed row"
        );
        let stored = read_fixture_state(&path, &account);
        let tx = stored
            .transactions()
            .iter()
            .find(|t| t.id() == MigrationTxId::new(1))
            .expect("the transfer row remains stored");
        assert!(
            matches!(tx.state(), MigrationTxState::Signed),
            "a transient prove must leave the row Signed for a retry"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The drive proves PAST a provable-but-not-yet-due transfer to serve a later one that is
    /// due: each successful prove persists `Proved` and the loop re-consults both selectors, so
    /// one blocked-on-schedule row cannot hide due work behind it.
    #[test]
    fn delivery_serving_proves_past_an_undue_transfer_to_serve_a_due_one() {
        let path = init_fixture_db("zcashlc_delivery_past_undue");
        let account = create_fixture_account(&path);
        // Transfer 1: provable (boundary settled) but scheduled ABOVE the tip; transfer 2:
        // provable and due. Both Signed.
        let mut state = scheduled_state(
            &[MINED],
            &[
                (MigrationTxState::Signed, 9_000, Some(h(40))),
                (MigrationTxState::Signed, 90, Some(h(40))),
            ],
        );
        store_fixture_state(&path, &account, &state);

        let mut prover = RecordingProver { calls: Vec::new() };
        let served = drive_and_serve_next_due(&mut state, h(100), |state, id| {
            prove_with_test_prover(&path, &account, &mut prover, state, id)
        })
        .expect("the drive must not fail");

        let (id, _, _) = served.expect("the due transfer behind the undue one must be served");
        assert_eq!(
            id,
            MigrationTxId::new(2),
            "the schedule-due transfer must be the one served"
        );
        let stored = read_fixture_state(&path, &account);
        for expect_id in [1u32, 2u32] {
            let tx = stored
                .transactions()
                .iter()
                .find(|t| t.id() == MigrationTxId::new(expect_id))
                .expect("the transfer row remains stored");
            assert!(
                matches!(tx.state(), MigrationTxState::Proved),
                "the drive must persist every prove it performed (row {expect_id})"
            );
        }
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
            due_assuming_proving(&state, h(100)),
            Some(MigrationTxId::new(2)),
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
        assert_eq!(due_assuming_proving(&undue, h(100)), None);

        // Awaiting an external signature, schedule-due: not delivery work.
        let awaiting = scheduled_state(
            &[MINED],
            &[(MigrationTxState::AwaitingSignature, 90, Some(h(40)))],
        );
        assert_eq!(due_assuming_proving(&awaiting, h(100)), None);

        // Already Proved and due: reported exactly as before the drive existed.
        let proved = scheduled_state(&[MINED], &[(MigrationTxState::Proved, 90, Some(h(40)))]);
        assert_eq!(
            due_assuming_proving(&proved, h(100)),
            Some(MigrationTxId::new(1))
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
        MigrationTransaction::from_parts(
            MigrationTxId::new(id),
            kind,
            vec![0u8],
            depends_on.iter().map(|&d| MigrationTxId::new(d)).collect(),
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
        MigrationState::from_parts(
            status,
            NoteSplitPlan::from_stored_parts(
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
    /// pinned engine (`zcash_pool_migration_backend::state`) makes that unreachable for a
    /// TRANSFER — `anchor_boundary` is always `Some` for a transfer (only a preparation's is
    /// `None`), so a not-yet-prove-ready `Signed` transfer is always `Blocker::AnchorBoundary`,
    /// never `Blocker::Schedule` (`Schedule` is reported for a `Proved` row awaiting its
    /// broadcast height, or a `Signed` PREPARATION awaiting its own schedule). Row 3 below pins
    /// the real transfer-blocking case instead.
    #[test]
    fn migration_transaction_statuses_marshals_mixed_rows_verbatim_from_the_engine() {
        let path = init_fixture_db("zcashlc_migration_tx_statuses_mixed");
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

        let broadcast_txid = [7u8; 32];
        let rows = vec![
            tx_row(
                0,
                MigrationTxKind::Preparation { layer: 0, index: 0 },
                &[],
                3_000_000,
                4_000_000,
                None,
                MigrationTxState::Mined {
                    height: h(3_000_000),
                },
            ),
            tx_row(
                1,
                MigrationTxKind::Transfer { crossing: 0 },
                &[],
                3_100_000,
                4_000_000,
                Some(3_100_000),
                MigrationTxState::Broadcast {
                    txid: TxId::from_bytes(broadcast_txid),
                },
            ),
            tx_row(
                2,
                MigrationTxKind::Transfer { crossing: 1 },
                &[],
                3_200_000,
                4_000_000,
                Some(3_000_000), // settled: boundary + 1 < target (3_600_001)
                MigrationTxState::Signed,
            ),
            tx_row(
                3,
                MigrationTxKind::Transfer { crossing: 2 },
                &[],
                3_600_000,
                4_000_000,
                Some(3_600_000), // not settled: boundary + 1 == target
                MigrationTxState::Signed,
            ),
        ];
        let state = custom_state(MigrationStatus::InProgress, rows);
        store_fixture_state(&path, &account, &state);

        // The expectation: computed directly from the engine, on the very same state.
        let target = h(3_600_001);
        let expected = state.transaction_statuses(target);
        assert_eq!(expected.len(), 4, "sanity: every row got a status");

        let statuses_ptr = unsafe {
            zcashlc_migration_transaction_statuses(
                path_bytes.as_ptr(),
                path_bytes.len(),
                account.as_ptr(),
                NETWORK_ID_MAINNET,
            )
        };
        assert!(
            !statuses_ptr.is_null(),
            "a mixed stored run is not an error"
        );
        let statuses = unsafe { &*statuses_ptr };
        assert_eq!(statuses.len, 4, "every stored row must get a status");
        let ffi_rows = unsafe { std::slice::from_raw_parts(statuses.ptr, statuses.len) };

        for exp in &expected {
            let id = u32::from(exp.id());
            let actual = ffi_rows
                .iter()
                .find(|r| r.id == id)
                .unwrap_or_else(|| panic!("row {id} must be present in the FFI output"));

            let (exp_is_transfer, exp_prep_layer, exp_prep_index, exp_crossing) = match exp.kind() {
                MigrationTxKind::Preparation { layer, index } => {
                    (false, layer as i64, index as i64, -1i64)
                }
                MigrationTxKind::Transfer { crossing } => (true, -1i64, -1i64, crossing as i64),
            };
            assert_eq!(
                actual.is_transfer, exp_is_transfer,
                "row {id}: kind discriminant"
            );
            assert_eq!(actual.prep_layer, exp_prep_layer, "row {id}: prep_layer");
            assert_eq!(actual.prep_index, exp_prep_index, "row {id}: prep_index");
            assert_eq!(actual.crossing, exp_crossing, "row {id}: crossing");

            let exp_state = match exp.state() {
                MigrationTxState::AwaitingSignature => 0,
                MigrationTxState::Signed => 1,
                MigrationTxState::Proved => 2,
                MigrationTxState::Broadcast { .. } => 3,
                MigrationTxState::Mined { .. } => 4,
            };
            assert_eq!(actual.state, exp_state, "row {id}: state");
            assert_eq!(
                actual.scheduled_height,
                i64::from(u32::from(exp.scheduled_height())),
                "row {id}: scheduled_height"
            );
            assert_eq!(
                actual.expiry_height,
                i64::from(u32::from(exp.expiry_height())),
                "row {id}: expiry_height"
            );
            assert_eq!(
                actual.mined_height,
                height_opt_to_i64(exp.mined_height()),
                "row {id}: mined_height"
            );
            assert_eq!(actual.ready, exp.ready(), "row {id}: ready");
            let exp_action = match exp.action() {
                None => 0,
                Some(NextAction::Prove) => 1,
                Some(NextAction::Broadcast) => 2,
            };
            assert_eq!(actual.action, exp_action, "row {id}: action");
            let exp_blocked_on = match exp.blocked_on() {
                None => 0,
                Some(Blocker::Dependencies) => 1,
                Some(Blocker::Schedule) => 2,
                Some(Blocker::AnchorBoundary) => 3,
                Some(Blocker::Signature) => 4,
                Some(Blocker::Expired) => 5,
            };
            assert_eq!(actual.blocked_on, exp_blocked_on, "row {id}: blocked_on");

            match exp.txid() {
                Some(txid) => {
                    assert!(actual.has_txid, "row {id}: has_txid must be true");
                    assert_eq!(actual.txid, <[u8; 32]>::from(txid), "row {id}: txid bytes");
                }
                None => assert!(!actual.has_txid, "row {id}: has_txid must be false"),
            }
        }

        // Pin the specific scenarios the doc comment calls out by id, so a coincidental pass of
        // the loop above (matching on both sides in the same wrong way) cannot hide a
        // regression.
        let mined_prep = ffi_rows.iter().find(|r| r.id == 0).unwrap();
        assert_eq!(mined_prep.state, 4, "row 0 must be Mined");
        assert_eq!(
            mined_prep.mined_height, 3_000_000,
            "row 0 must carry its mined height"
        );
        assert!(
            !mined_prep.has_txid,
            "a Mined row carries no txid: the engine's own Mined state has none"
        );

        let broadcast_transfer = ffi_rows.iter().find(|r| r.id == 1).unwrap();
        assert_eq!(broadcast_transfer.state, 3, "row 1 must be Broadcast");
        assert!(
            broadcast_transfer.has_txid,
            "row 1 must carry its broadcast txid"
        );
        assert_eq!(broadcast_transfer.txid, broadcast_txid);
        assert_eq!(
            broadcast_transfer.mined_height, -1,
            "row 1 has no mined height yet"
        );

        let ready_transfer = ffi_rows.iter().find(|r| r.id == 2).unwrap();
        assert!(ready_transfer.ready, "row 2 must be ready");
        assert_eq!(ready_transfer.action, 1, "row 2's action must be Prove");
        assert_eq!(ready_transfer.blocked_on, 0, "row 2 must report no blocker");

        let blocked_transfer = ffi_rows.iter().find(|r| r.id == 3).unwrap();
        assert!(!blocked_transfer.ready, "row 3 must not be ready");
        assert_eq!(blocked_transfer.action, 0, "row 3 must report no action");
        assert_eq!(
            blocked_transfer.blocked_on, 3,
            "row 3 must be blocked on its anchor boundary"
        );

        unsafe { zcashlc_free_migration_transaction_statuses(statuses_ptr) };
        let _ = std::fs::remove_file(&path);
    }

    /// 3. Reconciliation runs at the head of this read too (the same convention as
    /// [`zcashlc_migration_state`]): a stored `Broadcast` transfer whose txid the WALLET's own
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
        // store (`reconcile_mined` cross-references the two).
        {
            let conn = Connection::open(&path).expect("the wallet connection opens");
            conn.execute(
                "INSERT INTO transactions (txid, mined_height, min_observed_height) \
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![&txid[..], mined_at, mined_at],
            )
            .expect("the fixture mined-transaction row inserts");
        }

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
        assert!(
            !row.has_txid,
            "reconciled to Mined, the engine's own state no longer carries a txid"
        );
        unsafe { zcashlc_free_migration_transaction_statuses(statuses_ptr) };

        // The reconciliation must be PERSISTED, not just reported for this one read — the
        // read-path convention every sibling read follows.
        let stored = read_fixture_state(&path, &account);
        let stored_tx = stored
            .transactions()
            .iter()
            .find(|t| t.id() == MigrationTxId::new(0))
            .expect("the row remains stored");
        assert!(
            matches!(
                stored_tx.state(),
                MigrationTxState::Mined { height } if height == h(mined_at)
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
}
