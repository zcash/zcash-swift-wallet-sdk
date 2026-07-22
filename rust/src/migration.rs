//! FFI over the final Orchard→Ironwood pool-migration engine
//! ([`zcash_pool_migration_backend`] + the `zcash_client_sqlite::pool_migration` store).
//!
//! The engine is a set of free functions over traits — [`crate::migration_engine::Backend`] wires
//! this SDK's wallet database (and the account-keyed migration store living inside it) into them;
//! [`crate::migration_finalize`] proves transactions at broadcast time (ZIP 374 deferred
//! anchors/witnesses; see its module doc for the anchor policy and its current, approved ZIP 318
//! deviation); [`crate::migration_plan_cache`] carries the previewed plan from propose to commit.
//! This module keeps the platform-facing C ABI of the v1 integration: the same entry points, the
//! same `#[repr(C)]` DTOs, the same sentinels — the engine swap is absorbed here, with two
//! deliberate exceptions (the external-signer note-split pair went plural, because the engine
//! builds N preparation transactions rather than one split transaction).
//!
//! Semantics that moved into this layer (the v1 crate did them internally):
//! - The public 6-state machine is DERIVED (see [`derive_state`]): `ReadyToPropose` and the
//!   `SyncRequiredBeforeNext` attention reason are permanently unemitted (the engine commits the
//!   split and the schedule atomically), and `Complete` is PER-RUN — "the stored run is fully
//!   mined", never "nothing left to migrate". After completion the platform asks
//!   `zcashlc_migration_propose_transfers` whether anything remains (an empty schedule means no).
//! - Mined-transaction reconciliation ([`reconcile_mined`]) runs at the head of every read.
//! - Rejection classification is recorded in the SDK-owned `sdk_invalid_marks` side table (the
//!   engine has no failure states).
//! - `include_residual` is accepted and ignored (documented-inert; the engine plans canonically
//!   and ZIP 318 expects the residual to remain in Orchard).
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
use std::path::PathBuf;
use std::ptr;
use std::slice;

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
use rand::rngs::OsRng;
use rusqlite::{Connection, OptionalExtension};
use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_client_backend::data_api::{InputSource, WalletRead, WalletWrite};
use zcash_client_backend::wallet::OutputRef;
use zcash_client_sqlite::AccountUuid;
use zcash_protocol::consensus::{
    BLOCKS_PER_HOUR, BlockHeight, Network, NetworkUpgrade, Parameters,
};
use zcash_protocol::value::Zatoshis;
use zcash_protocol::{PoolType, ShieldedPool, TxId};

use zcash_pool_migration_backend::engine::{
    self, MigrationPlan, MigrationState, MigrationStatus, MigrationTransaction, MigrationTxId,
    MigrationTxKind, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
};

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
/// state, which is reported as "nothing due").
fn proving_unavailable(detail: impl std::fmt::Display) -> anyhow::Error {
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
    let store_conn = Connection::open(&db_path)
        .map_err(|e| anyhow!("Error opening migration store connection: {e}"))?;
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
    let mut backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn);
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
/// Returns `Ok(None)` when there is nothing to migrate (the balance is zero, or entirely below the
/// dust floor) — the "ask rust whether anything remains" answer after a completed run.
fn plan_and_cache(ctx: &mut CallCtx) -> anyhow::Result<Option<MigrationPlan>> {
    let backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn);
    let mut rng = OsRng;
    match engine::plan_migration(&ctx.network, &backend, &mut rng) {
        Ok(plan) => {
            migration_plan_cache::set(ctx.db_path.clone(), ctx.account_bytes, plan.clone());
            Ok(Some(plan))
        }
        Err(engine::MigrationError::NothingToMigrate) => Ok(None),
        Err(e) => Err(anyhow!("Error planning migration: {e}")),
    }
}

/// The row set the platform sees for a plan's transfer schedule: `(engine tx id, amount, broadcast
/// height, expiry height)`, sorted chronologically by broadcast height.
///
/// - `amount` is the NET value that crosses the turnstile (`funding_notes()[i] - note_fee_buffer`),
///   not the gross funding-note value the note-split minted. The row is still KEYED off
///   `funding_notes()` (the post-reconciliation values), NOT the note split's raw
///   `crossing_values()` — the two differ whenever preparation fees drop the smallest
///   denominations, and indexing `crossing_values()` directly would silently mispair a
///   denomination with the wrong schedule height. Subtracting the (constant) fee buffer from the
///   already-correctly-paired funding note sidesteps that entirely.
/// - The engine numbers every preparation transaction first, then transfers in `schedule()`
///   order, so transfer `i`'s real committed id is `prep_tx_count + i`.
/// - The sort makes the platform's row order chronological: ZIP 318 SHUFFLE deliberately makes
///   funding-note order differ from broadcast order.
fn schedule_rows(
    funding_notes: &[Zatoshis],
    schedule: &[zcash_pool_migration_backend::scheduling::Schedule],
    prep_tx_count: u32,
    note_fee_buffer: Zatoshis,
) -> anyhow::Result<Vec<(MigrationTxId, Zatoshis, BlockHeight, BlockHeight)>> {
    if funding_notes.len() != schedule.len() {
        return Err(anyhow!(
            "migration plan invariant violated: {} funding notes but {} schedule entries",
            funding_notes.len(),
            schedule.len()
        ));
    }
    let mut rows: Vec<_> = funding_notes
        .iter()
        .zip(schedule.iter())
        .enumerate()
        .map(|(i, (funding_note, entry))| {
            let crossing = (*funding_note - note_fee_buffer).ok_or_else(|| {
                anyhow!(
                    "funding note {} zatoshi is smaller than the fee buffer {} zatoshi",
                    u64::from(*funding_note),
                    u64::from(note_fee_buffer)
                )
            })?;
            Ok((
                MigrationTxId::new(prep_tx_count + i as u32),
                crossing,
                entry.broadcast_height(),
                entry.expiry_height(),
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    rows.sort_by_key(|(_, _, broadcast, _)| *broadcast);
    Ok(rows)
}

/// The schedule's rough wall-clock span in hours: earliest to latest scheduled broadcast.
fn estimated_duration_hours(
    schedule: &[zcash_pool_migration_backend::scheduling::Schedule],
) -> u32 {
    let heights = schedule.iter().map(|e| u32::from(e.broadcast_height()));
    match (heights.clone().max(), heights.min()) {
        (Some(max), Some(min)) => max.saturating_sub(min) / BLOCKS_PER_HOUR,
        _ => 0,
    }
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
        &plan.funding_notes(),
        plan.schedule(),
        prep_tx_count(plan),
        plan.note_split().note_fee_buffer(),
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
    let estimated = estimated_duration_hours(plan.schedule());
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

/// Validate that the platform-echoed transfer amounts match the cached plan (the user consented to
/// exactly these values). Order-independent: the platform displays chronologically while
/// `funding_notes()` is in crossing order.
fn validate_amounts_against_plan(plan: &MigrationPlan, amounts: &[i64]) -> anyhow::Result<()> {
    let mut expected: Vec<i64> = plan
        .funding_notes()
        .iter()
        .map(|z| zat_to_i64(*z))
        .collect();
    let mut got: Vec<i64> = amounts.to_vec();
    expected.sort_unstable();
    got.sort_unstable();
    if expected != got {
        return Err(plan_stale(
            "the echoed schedule does not match the previewed plan — propose again",
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
    validate_amounts: Option<&[i64]>,
    unsigned_out: bool,
) -> anyhow::Result<(MigrationState, Vec<(MigrationTxId, Vec<u8>)>)> {
    {
        let backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn);
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
    if let Some(amounts) = validate_amounts {
        validate_amounts_against_plan(&cached.plan, amounts)?;
    }

    let target = BlockHeight::from(u32::from(ctx.tip()?) + 1);
    let mut rng = OsRng;
    let mut backend = Backend::new(&ctx.wallet, ctx.account, usk, &mut ctx.store_conn);
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

/// Proves a due transaction if it is still `Signed` (installing anchor + witnesses per the policy
/// in [`migration_finalize`]), persisting the proven bytes through the engine's own `Proved`
/// state. Returns the broadcastable `(proven pczt bytes, txid)` — or `None` when the transaction
/// is not finalizable yet (funding note not yet observed/witnessable), the ordinary transient
/// state the caller maps to "nothing due".
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
            let anchor = migration_finalize::resolve_proving_anchor(&ctx.wallet, tx)?;
            let (fvk, spendable) = {
                let backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn);
                (
                    backend.stored_orchard_fvk()?,
                    backend.spendable_orchard_notes()?,
                )
            };
            let pczt_bytes = tx.pczt().clone();
            match migration_finalize::finalize_transaction(
                &mut ctx.wallet,
                &fvk,
                &spendable,
                anchor,
                &pczt_bytes,
            )
            .map_err(proving_unavailable)?
            {
                Some((proven, txid)) => {
                    state.set_transaction_proved(id, proven.clone());
                    let mut backend =
                        Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn);
                    backend.replace_migration(state)?;
                    Ok(Some((proven, txid)))
                }
                None => Ok(None),
            }
        }
        other => Err(anyhow!(
            "migration transaction {} is not broadcastable (state {})",
            u32::from(id),
            other.as_ref()
        )),
    }
}

// ----- public-state derivation (pure; unit-tested) -----

/// What the platform's 6-state machine derives to, before marshaling.
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
/// - `ReadyToPropose` and `SyncRequiredBeforeNext` are never derived: the engine commits the note
///   split and the transfer schedule atomically, so the v1 "split confirmed, schedule pending"
///   moment no longer exists.
///
/// Precedence: an engine run counts as ACTIVE — and wins outright, exactly as before the immediate
/// lane existed — whenever one is stored and has not reached a terminal status. A `Failed` or
/// `Complete` engine run, or no stored engine run at all, instead defers to `immediate_run` (mined
/// -> consumed: `NotStarted`, masking any stale engine `Complete`; unmined and not expired ->
/// `InProgress` of one, flagged `is_immediate`; expired or vanished -> ignored) before falling back
/// to the engine's own terminal/absent verdict.
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
    let expired_unmined = state
        .transactions()
        .iter()
        .any(|t| !matches!(t.state(), MigrationTxState::Mined { .. }) && tip > t.expiry_height());
    if expired_unmined {
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
    let next_ready = transfers
        .iter()
        .filter(|t| !matches!(t.state(), MigrationTxState::Mined { .. }))
        .map(|t| t.scheduled_height())
        .min();
    DerivedState::InProgress {
        completed_transfers: completed,
        total_transfers: transfers.len() as u32,
        next_transfer_ready_at_height: next_ready,
        is_immediate: false,
    }
}

/// The NET amount a stored transfer crosses the turnstile: its funding note (`Transfer { crossing
/// }` indexes into `funding_notes()`) minus the plan's constant fee buffer. `None` when `tx` is not
/// a transfer, its crossing index is out of range, or (invariantly impossible) the funding note is
/// smaller than the buffer.
fn transfer_amount(state: &MigrationState, tx: &MigrationTransaction) -> Option<Zatoshis> {
    match tx.kind() {
        MigrationTxKind::Transfer { crossing } => {
            let funding_note = state.funding_notes().get(crossing).copied()?;
            funding_note - state.note_split().note_fee_buffer()
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
///
/// `#[allow(dead_code)]`: `SyncRequiredBeforeNext` is never constructed by this integration but
/// stays for ABI stability (the C header and the Swift decoder both know the tag).
#[allow(dead_code)]
#[repr(C, u8)]
pub enum FfiAttentionReason {
    /// The transfer identified by `transfer_id` was terminally rejected at broadcast (its input
    /// note was spent externally, or the network refused it as invalid). `transfer_id` is an owned
    /// C string, freed by [`zcashlc_free_migration_state`].
    InvalidTransfer { transfer_id: *mut c_char },
    /// A transaction's expiry elapsed before it could be broadcast (or mined).
    TransferExpired,
    /// Unused: never derived by this integration (kept for ABI stability).
    SyncRequiredBeforeNext,
}

/// The top-level migration state machine surfaced to the app.
///
/// `#[allow(dead_code)]`: the data-carrying variants' payloads are read by the C consumer across
/// the FFI (cbindgen emits them into the header), which rustc cannot observe; `ReadyToPropose` and
/// the `SyncRequiredBeforeNext` reason are additionally never constructed by this integration (the
/// engine commits the split and the schedule atomically) but stay for ABI stability.
#[allow(dead_code)]
#[repr(C, u8)]
pub enum FfiMigrationState {
    /// No migration run is stored (none started, or a previous run was cancelled).
    NotStarted,
    /// The run is committed and its preparation (note-split) transactions are not yet all mined.
    SplitPendingConfirmation,
    /// Unused: never emitted by this integration (kept for ABI stability).
    ReadyToPropose,
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
    /// A rough estimate of how long the schedule takes to fully execute, in hours.
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

/// A set of unsigned PCZTs to route to an external signer.
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
    let backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn);
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
            Some(plan) => plan.preparation().transaction_count() > 0,
            None => false,
        })
    });
    unwrap_exc_or(res, false)
}

/// Whether any transaction of the stored run is due-and-unbroadcast at the current tip. Returns
/// `false` on error (see `zcashlc_last_error_message`).
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
        let tip = ctx.tip()?;
        Ok(state.next_broadcastable(tip).is_some())
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
        let tip = ctx.tip()?;
        Ok(state.transactions().iter().any(|t| {
            !matches!(t.state(), MigrationTxState::Mined { .. }) && tip > t.expiry_height()
        }))
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
            Some(plan) => {
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
/// The `output_values`/`fee` echo is validated against the previewed plan
/// (`MIGRATION_PLAN_STALE` on mismatch or when no preview is cached).
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
        let _ = fee; // The fee is display-echo only; amounts are the consent-critical values.
        let echoed: Vec<i64> = unsafe { slice_or_empty(output_values, output_values_len) }.to_vec();

        // Note: the echoed values are the note-split outputs; validation happens against the
        // funding notes inside `commit_or_resume` only for the schedule echo. For the split echo,
        // validate against the previewed split outputs here.
        {
            let cached = migration_plan_cache::get(&ctx.db_path, ctx.account_bytes);
            if let Some(cached) = &cached {
                let mut expected: Vec<i64> = cached
                    .plan
                    .note_split()
                    .migration_outputs()
                    .iter()
                    .map(|z| zat_to_i64(*z))
                    .collect();
                let mut got = echoed.clone();
                expected.sort_unstable();
                got.sort_unstable();
                if expected != got {
                    return Err(plan_stale(
                        "the echoed note split does not match the previewed plan — propose again",
                    ));
                }
            }
            // A missing cache falls through to `commit_or_resume`, which either resumes a stored
            // non-terminal run (no cache needed) or reports MIGRATION_PLAN_STALE.
        }

        let (mut state, _) = commit_or_resume(&mut ctx, Some(usk), None, false)?;

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
            let backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn);
            if let Some(state) = backend.get_migration()? {
                if !state.is_terminal() {
                    return Ok(state.note_split().change().map_or(-1, zat_to_i64));
                }
            }
        }
        Ok(match plan_and_cache(&mut ctx)? {
            Some(plan) => plan.note_split().change().map_or(-1, zat_to_i64),
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
/// (and returns only their value). A concurrent-lock race (another caller locked one of the
/// selected notes between selection and locking) surfaces as an error
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
            .select_unspent_notes(ctx.account, &[ShieldedPool::Orchard], target, &[], false)
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
            .lock_outputs(refs.into_iter(), BlockHeight::from(u32::MAX))
            .map_err(|e| anyhow!("locking the migration residual failed: {e}"))?;
        Ok(zat_to_i64(total))
    });
    unwrap_exc_or(res, -1)
}

/// Unlocks the account's locked outputs — the release half of
/// `zcashlc_migration_lock_residual` — and returns the number of outputs unlocked (`0` when
/// nothing was locked; `-1` signals an error, see `zcashlc_last_error_message`).
///
/// Clears ALL locks held for the account, regardless of expiry. That blanket clear is safe here
/// because this SDK never creates proposal-scoped output locks: the only locks an account can
/// hold are the permanent residual locks placed by `zcashlc_migration_lock_residual`.
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
        let backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn);
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
/// `include_residual` is accepted and IGNORED (documented-inert): the engine plans canonically,
/// and ZIP 318 expects the residual to remain in Orchard.
///
/// # Safety
/// See [`open`]. Free the returned pointer with [`zcashlc_free_migration_schedule`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_propose_transfers(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    include_residual: bool,
) -> *mut FfiMigrationSchedule {
    let res = catch_panic(|| {
        let _ = include_residual;
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        match plan_and_cache(&mut ctx)? {
            Some(plan) => encode_schedule_from_plan(&plan, ctx.tip()?),
            None => Ok(encode_empty_schedule()),
        }
    });
    unwrap_exc_or_null(res)
}

/// Commits the previewed migration with the spending key if nothing is committed yet (covering
/// the no-split lane); when a matching non-terminal run is already stored (the normal case — the
/// note-split submission committed it), validates the echoed schedule shape and succeeds as a
/// no-op. The echoed amounts are validated against the previewed plan when a fresh commit
/// happens (`MIGRATION_PLAN_STALE` on mismatch or missing preview).
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
        let _ = (
            ids,
            anchor_heights,
            next_executable_after_heights,
            expiry_heights,
            estimated_duration_hours,
        );
        let amounts = unsafe { slice_or_empty(amounts, ids_len) }.to_vec();
        commit_or_resume(&mut ctx, Some(usk), Some(&amounts), false)?;
        Ok(true)
    });
    unwrap_exc_or(res, false)
}

/// The next due transaction of the stored run, proven and ready to broadcast — or the
/// "nothing due" sentinel (null id/pczt) when nothing qualifies yet (nothing scheduled, deps
/// unmined, or the due transaction's funding note is not yet witnessable). Reconciles mined
/// transactions first. Serves preparation transactions and transfers alike, in scheduled order.
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
        let tip = ctx.tip()?;
        let Some(id) = state.next_broadcastable(tip) else {
            return Ok(FfiPreparedTransfer::none());
        };
        match prove_if_needed(&mut ctx, &mut state, id)? {
            Some((proven, txid)) => FfiPreparedTransfer::from_parts(id, txid, proven),
            // Due but not yet finalizable (funding note not witnessable yet) — "nothing due".
            None => Ok(FfiPreparedTransfer::none()),
        }
    });
    unwrap_exc_or_null(res)
}

/// The next due-and-unbroadcast TRANSFER of the stored run as a proposal row (id, amount, its
/// scheduled and expiry heights), or NULL with no error when there is none. Distinguish the two
/// NULL meanings via `zcashlc_last_error_length`.
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
        let tip = ctx.tip()?;
        let next_transfer = state
            .next_broadcastable(tip)
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
    retryable: bool,
    txid_bytes: *const u8,
) -> bool {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let id = transfer_id_from_c(transfer_id)?;
        let _ = retryable;
        match result_tag {
            0 => {
                if txid_bytes.is_null() {
                    return Err(anyhow!("txid_bytes is null for a success result"));
                }
                let txid: [u8; 32] = unsafe { slice::from_raw_parts(txid_bytes, 32) }
                    .try_into()
                    .expect("length 32 by construction");
                let mut backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn);
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

/// Whether a wallet sync is required before the next transfer can broadcast. Always `false`: ZIP
/// 318's sync/broadcast decoupling MUST is enforced by the SDK's Swift privacy gate and the app's
/// background-session policy, not by the engine (the engine surfaces no such predicate). Returns
/// `false` on error too (see `zcashlc_last_error_message`).
///
/// # Safety
/// See [`open`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_is_sync_required(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let _ = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        Ok(false)
    });
    unwrap_exc_or(res, false)
}

/// Cancels the stored run (persisting it as `Failed` — its pre-signed transactions are abandoned;
/// already-broadcast ones are unaffected on-chain), clears the invalid marks, and previews a
/// fresh plan against the live balance for the platform's re-confirm lane. `include_residual` is
/// accepted and ignored (documented-inert).
///
/// # Safety
/// See [`open`]. Free the returned pointer with [`zcashlc_free_migration_schedule`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_restart_step(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    include_residual: bool,
) -> *mut FfiMigrationSchedule {
    let res = catch_panic(|| {
        let _ = include_residual;
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        {
            let mut backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn);
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
            Some(plan) => encode_schedule_from_plan(&plan, ctx.tip()?),
            None => Ok(encode_empty_schedule()),
        }
    });
    unwrap_exc_or_null(res)
}

/// Unsupported by the final engine: rebuild-on-expiry is an explicit upstream later-slice, and no
/// app call sites exist. Always errors (returns `-1` with the error message set).
///
/// # Safety
/// See [`open`]; `usk_ptr` must be valid for reads of `usk_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_refresh_stale_transfers(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
    usk_ptr: *const u8,
    usk_len: usize,
    include_residual: bool,
) -> i64 {
    let res = catch_panic(|| {
        let _ = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let _ = unsafe { crate::decode_usk(usk_ptr, usk_len)? };
        let _ = include_residual;
        Err::<i64, _>(anyhow!(
            "refreshing stale transfers is not supported by the final migration engine \
             (rebuild-on-expiry is tracked upstream); cancel and re-plan via \
             zcashlc_migration_restart_step instead"
        ))
    });
    unwrap_exc_or(res, -1)
}

/// Builds the whole migration UNSIGNED (external-signer lane): every transaction is persisted
/// `AwaitingSignature`, and the preparation (note-split) subset is returned for the signing
/// ceremony. The run is created HERE; the transfer subset of the same build is served by
/// `zcashlc_migration_create_unsigned_transfer_pczts`. Resumes a stored non-terminal run
/// (re-serving its still-unsigned preparation transactions); replaces a terminal one.
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
        let (state, unsigned) = commit_or_resume(&mut ctx, None, None, true)?;
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
        let mut backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn);
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
/// already exist; the echoed schedule arrays are accepted and ignored, since the engine signs the
/// stored build, not a caller echo).
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
        let _ = (
            ids,
            ids_len,
            amounts,
            anchor_heights,
            next_executable_after_heights,
            expiry_heights,
            estimated_duration_hours,
        );
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        let (state, unsigned) = commit_or_resume(&mut ctx, None, None, true)?;
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
        let mut backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn);
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
        let buffer = zat(10_000);
        let amounts: Vec<Zatoshis> = (1..=5).map(|i| zat(i * 100_000_000)).collect();
        let rows = schedule_rows(&amounts, &schedule, 3, buffer).unwrap();
        assert_eq!(rows.len(), 5);
        // Chronological by broadcast height.
        for pair in rows.windows(2) {
            assert!(pair[0].2 <= pair[1].2);
        }
        // Ids are offset by the preparation count and cover exactly the transfer range.
        let mut ids: Vec<u32> = rows.iter().map(|(id, _, _, _)| u32::from(*id)).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![3, 4, 5, 6, 7]);
        // Amount pairing survives the sort: each id maps back to its funding note's NET crossing
        // value (the gross funding note minus the constant fee buffer), not the gross value.
        for (id, amount, _, _) in &rows {
            let crossing = u32::from(*id) - 3;
            let gross = (u64::from(crossing) + 1) * 100_000_000;
            assert_eq!(*amount, zat(gross - 10_000));
        }
    }

    #[test]
    fn schedule_rows_net_amounts_are_stable_across_reshuffled_schedules() {
        // Two different draws (different rng seeds -> different shuffled broadcast order) of the
        // same funding notes must still report the same total (and the same multiset) of NET
        // amounts, even though the rows themselves may come back in a different order.
        let amounts: Vec<Zatoshis> = (1..=5).map(|i| zat(i * 100_000_000)).collect();
        let buffer = zat(10_000);
        let expected_total: u64 = amounts.iter().map(|z| u64::from(*z) - 10_000).sum();

        let mut rng_a = StdRng::seed_from_u64(1);
        let schedule_a = scheduling::schedule(h(1_000), 5, &mut rng_a);
        let rows_a = schedule_rows(&amounts, &schedule_a, 0, buffer).unwrap();

        let mut rng_b = StdRng::seed_from_u64(99);
        let schedule_b = scheduling::schedule(h(1_000), 5, &mut rng_b);
        let rows_b = schedule_rows(&amounts, &schedule_b, 0, buffer).unwrap();

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
        let amounts = vec![zat(100)];
        assert!(schedule_rows(&amounts, &schedule, 0, zat(0)).is_err());
    }

    #[test]
    fn schedule_rows_reject_funding_note_below_fee_buffer() {
        let mut rng = StdRng::seed_from_u64(7);
        let schedule = scheduling::schedule(h(1_000), 1, &mut rng);
        let amounts = vec![zat(100)];
        assert!(schedule_rows(&amounts, &schedule, 0, zat(10_000)).is_err());
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
        let account = [7u8; 16];
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
    /// real caller. This exercises `open` (path decode, `parse_network`, store read) end to end
    /// over the FFI.
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
        let account = [7u8; 16];
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
}
