//! FFI over the final Orchard→Ironwood pool-migration engine
//! ([`zcash_pool_migration`] + the `zcash_client_sqlite::pool_migration` store).
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
//! - Rejection classification is recorded in the SDK-owned
//!   `ext_zcashlc_orchard_ironwood_migration_invalid_marks` extension table (the engine has no
//!   failure states), created by the wallet schema migrations via [`crate::ext_schema`] and
//!   written through the wallet's extension-transaction API.
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
//! Error channel: failures land in the thread-local last-error message. Two stable prefixes let
//! the Swift layer surface dedicated errors: `MIGRATION_PLAN_STALE:` (commit whose handle does
//! not identify the currently cached proposal — re-propose) and `MIGRATION_PROVING_UNAVAILABLE:`
//! (proving failed hard). Pointer-returning functions yield NULL on error, `bool`-returning
//! functions `false`, and the `i64` sentinels are documented per function.
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
use rusqlite::Connection;
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

use zcash_pool_migration::engine::{
    self, MigrationPlan, MigrationState, MigrationStatus, MigrationTransaction,
    MigrationTransferId, MigrationTxKind, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
};
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
    let store_conn = Connection::open(&db_path)
        .map_err(|e| anyhow!("Error opening migration store connection: {e}"))?;
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
// (invalid-note, expired) from retryable ones; the terminal ones are recorded in the
// `ext_zcashlc_orchard_ironwood_migration_invalid_marks` extension table so
// `zcashlc_migration_has_invalid_transfers` / the `RequiresAttention` derivation can surface
// them. Cleared when the run is cancelled (`zcashlc_migration_restart_step`).
//
// The table is created by the wallet schema migrations (see [`crate::ext_schema`]); access goes
// through `WalletDb::transactionally_with_extension`, whose authorizer restricts writes to the
// `ext_` namespace.

fn insert_invalid_mark(
    wallet: &mut MigrationWallet,
    account: &[u8; 16],
    id: MigrationTransferId,
    reason: &str,
) -> anyhow::Result<()> {
    wallet.transactionally_with_extension(|_wdb, ext| {
        ext.execute(
            "INSERT INTO ext_zcashlc_orchard_ironwood_migration_invalid_marks
                (account_uuid, tx_id, reason)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(account_uuid, tx_id) DO UPDATE SET reason = excluded.reason",
            rusqlite::params![&account[..], u32::from(id), reason],
        )?;
        Ok(())
    })
}

/// The account's marked transaction ids, sorted ascending. The extension-transaction API exposes
/// single-row queries only, so the ids arrive as one aggregated row and are split here.
fn invalid_marks(wallet: &mut MigrationWallet, account: &[u8; 16]) -> anyhow::Result<Vec<u32>> {
    let joined: Option<String> = wallet.transactionally_with_extension(|_wdb, ext| {
        ext.query_row(
            "SELECT group_concat(tx_id)
             FROM ext_zcashlc_orchard_ironwood_migration_invalid_marks
             WHERE account_uuid = ?1",
            rusqlite::params![&account[..]],
            |row| row.get(0),
        )
        .map_err(anyhow::Error::from)
    })?;
    let mut ids = joined
        .as_deref()
        .unwrap_or("")
        .split_terminator(',')
        .map(|id| {
            id.parse::<u32>()
                .map_err(|e| anyhow!("invalid mark id {id}: {e}"))
        })
        .collect::<anyhow::Result<Vec<u32>>>()?;
    ids.sort_unstable();
    Ok(ids)
}

fn clear_invalid_marks(wallet: &mut MigrationWallet, account: &[u8; 16]) -> anyhow::Result<()> {
    wallet.transactionally_with_extension(|_wdb, ext| {
        ext.execute(
            "DELETE FROM ext_zcashlc_orchard_ironwood_migration_invalid_marks
             WHERE account_uuid = ?1",
            rusqlite::params![&account[..]],
        )?;
        Ok(())
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
    let broadcast: Vec<(MigrationTransferId, [u8; 32])> = state
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
    let (transfers, transfers_len) = ptr_from_vec(transfers);
    Ok(Box::into_raw(Box::new(FfiMigrationSchedule {
        transfers,
        transfers_len,
        estimated_duration_hours: estimated,
        proposal_handle: plan_handle,
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
    Ok(Box::into_raw(Box::new(FfiMigrationSchedule {
        transfers,
        transfers_len,
        estimated_duration_hours: estimated,
        proposal_handle: 0,
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
) -> anyhow::Result<(MigrationState, Vec<(MigrationTransferId, Vec<u8>)>)> {
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

    let cached = migration_plan_cache::get(&ctx.db_path, ctx.account_bytes, plan_handle)
        .map_err(|e| plan_stale(&e.to_string()))?;

    let target = BlockHeight::from(u32::from(ctx.tip()?) + 1);
    let mut rng = OsRng;
    let mut backend = Backend::new(&ctx.wallet, ctx.account, usk, &mut ctx.store_conn)?;
    let (mut state, unsigned) = if unsigned_out {
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

    if cached.immediate {
        // The immediate lane: every transfer becomes due at the commit tip. Preparation mining
        // order still gates each transfer through its dependency; expiry stays canonical.
        let tip = ctx.tip()?;
        let transactions = state
            .transactions()
            .iter()
            .map(|t| {
                let scheduled = match t.kind() {
                    MigrationTxKind::Transfer { .. } => tip,
                    _ => t.scheduled_height(),
                };
                MigrationTransaction::from_parts(
                    t.id(),
                    t.kind(),
                    t.pczt().clone(),
                    t.depends_on().clone(),
                    scheduled,
                    t.expiry_height(),
                    t.anchor_boundary(),
                    t.state(),
                    t.lock_owner(),
                )
            })
            .collect();
        state = MigrationState::from_parts(
            state.status(),
            state.denominations().clone(),
            state.preparation().clone(),
            transactions,
            // Rebuilding transfers does not re-plan the run, so it stays on the grid it was
            // committed under.
            state.anchor_bucket_interval(),
        );
        let mut backend = Backend::new(&ctx.wallet, ctx.account, None, &mut ctx.store_conn)?;
        backend.replace_migration(&state)?;
    }

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
    id: MigrationTransferId,
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
/// `(id, txid, proven pczt bytes)`, or `None` when nothing is due.
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
    tip: BlockHeight,
    mut prove: impl FnMut(
        &mut MigrationState,
        MigrationTransferId,
    ) -> anyhow::Result<Option<(Vec<u8>, [u8; 32])>>,
) -> anyhow::Result<Option<(MigrationTransferId, [u8; 32], Vec<u8>)>> {
    while state.next_broadcastable(tip).is_none() {
        let Some(provable) = state.next_provable(tip) else {
            return Ok(None);
        };
        if prove(state, provable)?.is_none() {
            return Ok(None);
        }
    }
    let id = state
        .next_broadcastable(tip)
        .expect("the drive loop exits with a broadcastable row");
    Ok(prove(state, id)?.map(|(proven, txid)| (id, txid, proven)))
}

/// The id [`zcashlc_migration_next_due_transfer`] WOULD serve at `tip`, assuming every due proof
/// succeeds: the next broadcastable row after virtually proving every prove-ready `Signed` row
/// over a scratch copy — no prover runs and nothing persists (`set_transaction_proved` with the
/// row's own bytes only flips the lifecycle state, mirroring [`drive_and_serve_next_due`]'s loop
/// without its side effects). `None` when the delivery lane has nothing actionable: nothing
/// schedule-due yet, dependencies unmined, rows awaiting an external signature (the signing
/// ceremony, not the delivery lane, advances those), or everything already broadcast/mined.
///
/// The queries built on this ([`zcashlc_migration_has_overdue_transfers`],
/// [`zcashlc_migration_pending_transfer_proposal`]) deliberately assume proofs succeed: a
/// transiently unwitnessable anchor (a restored wallet mid-sync) defers the actual delivery, not
/// the report — the due work exists either way, and the delivery call stays the one place that
/// consults the prover.
fn due_assuming_proving(state: &MigrationState, tip: BlockHeight) -> Option<MigrationTransferId> {
    if let Some(id) = state.next_broadcastable(tip) {
        return Some(id);
    }
    if state.next_provable(tip).is_none() {
        return None;
    }
    let mut scratch = state.clone();
    while let Some(id) = scratch.next_provable(tip) {
        let bytes = scratch
            .transactions()
            .iter()
            .find(|t| t.id() == id)
            .map(|t| t.pczt().clone())
            .unwrap_or_default();
        scratch.set_transaction_proved(id, bytes);
    }
    scratch.next_broadcastable(tip)
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
    },
    InvalidTransfer(u32),
    TransferExpired,
    Complete,
}

/// Derive the platform's migration state from the persisted engine state.
///
/// - No stored migration -> `NotStarted`.
/// - A stored `Failed` run (our cancel) -> `NotStarted` (the platform re-plans).
/// - `Complete` is PER-RUN: the stored run is fully mined. Whether anything REMAINS to migrate is
///   answered by a fresh propose, never by this state.
/// - The v1 crate's "split confirmed, schedule pending" intermediate state and its matching
///   attention reason are gone: the engine commits the note split and the transfer schedule
///   atomically, so that moment cannot occur anymore.
fn derive_state(
    persisted: Option<&MigrationState>,
    tip: BlockHeight,
    invalid_marks: &[u32],
) -> DerivedState {
    let Some(state) = persisted else {
        return DerivedState::NotStarted;
    };
    match state.status() {
        MigrationStatus::Complete => return DerivedState::Complete,
        MigrationStatus::Failed => return DerivedState::NotStarted,
        _ => {}
    }

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
    }
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
}

impl FfiMigrationProgress {
    fn absent() -> Self {
        FfiMigrationProgress {
            is_present: false,
            completed_transfers: 0,
            total_transfers: 0,
            remaining_orchard_value: 0,
            next_transfer_ready_at_height: -1,
        }
    }
}

/// Why a migration requires user attention (payload of [`FfiMigrationState::RequiresAttention`]).
#[repr(C, u8)]
pub enum FfiAttentionReason {
    /// The transfer identified by `transfer_id` (the engine's raw id) was terminally rejected at
    /// broadcast: its input note was spent externally, or the network refused it as invalid.
    InvalidTransfer { transfer_id: u32 },
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
    /// Opaque identifier of the cached plan this proposal was rendered from. Commit calls pass
    /// it back, and the rust side refuses to sign any plan other than the one it identifies
    /// (`MIGRATION_PLAN_STALE` when missing or superseded). `0` means no plan was cached (the
    /// empty nothing-to-migrate proposal).
    pub proposal_handle: u64,
}

/// A fully proven, signed transaction persisted as a PCZT, ready for the platform to broadcast.
/// When returned by `zcashlc_migration_next_due_transfer`, an all-null/zeroed value (`id` and
/// `pczt` null) means "nothing is due" (as opposed to a NULL return, which signals an error).
#[repr(C)]
pub struct FfiPreparedTransfer {
    /// The transaction's id (the engine's raw id). Meaningful only when `pczt` is non-null; the
    /// "nothing due" sentinel leaves it `0`.
    pub id: u32,
    /// The finalized transaction's id, as raw (internal-order) 32-byte value (zeroed when the
    /// value is a storage receipt whose transaction has not been proven yet).
    pub txid: [u8; 32],
    /// Heap `pczt_len`-byte serialized PCZT (null only in the "nothing due" sentinel).
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

    fn none() -> *mut Self {
        Box::into_raw(Box::new(FfiPreparedTransfer {
            id: 0,
            txid: [0u8; 32],
            pczt: ptr::null_mut(),
            pczt_len: 0,
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
    /// The transaction's id (the engine's raw id).
    pub id: u32,
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
    fn from_pairs(pairs: Vec<(MigrationTransferId, Vec<u8>)>) -> anyhow::Result<*mut Self> {
        let items = pairs
            .into_iter()
            .map(|(id, bytes)| {
                let id = u32::from(id);
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
        // Every payload is plain data (`InvalidTransfer` carries a `u32` id), so dropping the
        // box is the whole of the cleanup.
        drop(unsafe { Box::from_raw(ptr) });
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

/// Frees a [`FfiMigrationSchedule`] and its transfer rows.
///
/// # Safety
/// `ptr` must be null or point to a [`FfiMigrationSchedule`] handed out by this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_migration_schedule(ptr: *mut FfiMigrationSchedule) {
    if !ptr.is_null() {
        let boxed = unsafe { Box::from_raw(ptr) };
        // Every row is plain data (ids are `u32`), so freeing the row vector is enough.
        free_ptr_from_vec(boxed.transfers, boxed.transfers_len);
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
        } => FfiMigrationState::InProgress(FfiMigrationProgress {
            is_present: true,
            completed_transfers,
            total_transfers,
            remaining_orchard_value: zat_to_i64(remaining_orchard),
            next_transfer_ready_at_height: height_opt_to_i64(next_transfer_ready_at_height),
        }),
        DerivedState::InvalidTransfer(id) => {
            FfiMigrationState::RequiresAttention(FfiAttentionReason::InvalidTransfer {
                transfer_id: id,
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
    use zcash_pool_migration::engine::MigrationBackend;
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
        let Some(state) = reconcile_mined(&mut ctx)? else {
            return marshal_state(DerivedState::NotStarted, Zatoshis::ZERO);
        };
        let marks = invalid_marks(&mut ctx.wallet, &ctx.account_bytes)
            .map_err(|e| anyhow!("marks read failed: {e}"))?;
        let tip = ctx.tip()?;
        let derived = derive_state(Some(&state), tip, &marks);
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
        let Some(state) = reconcile_mined(&mut ctx)? else {
            return Ok(Box::into_raw(Box::new(FfiMigrationProgress::absent())));
        };
        let marks = invalid_marks(&mut ctx.wallet, &ctx.account_bytes)
            .map_err(|e| anyhow!("marks read failed: {e}"))?;
        let tip = ctx.tip()?;
        let value = match derive_state(Some(&state), tip, &marks) {
            DerivedState::InProgress {
                completed_transfers,
                total_transfers,
                next_transfer_ready_at_height,
            } => FfiMigrationProgress {
                is_present: true,
                completed_transfers,
                total_transfers,
                remaining_orchard_value: zat_to_i64(remaining_orchard(&mut ctx)?),
                next_transfer_ready_at_height: height_opt_to_i64(next_transfer_ready_at_height),
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
        // `compute_plan`, NOT `plan_and_cache`: this is a pure peek — caching its throwaway plan
        // would supersede the handle of a proposal the user is currently reviewing.
        Ok(match compute_plan(&mut ctx)? {
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
        let tip = ctx.tip()?;
        Ok(due_assuming_proving(&state, tip).is_some())
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
        let marks = invalid_marks(&mut ctx.wallet, &ctx.account_bytes)
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

/// Like `zcashlc_migration_propose_transfers`, but the previewed plan is marked IMMEDIATE: at
/// commit time every transfer's scheduled height is rewritten to the commit tip, so the whole
/// migration drains as fast as preparation mining allows instead of over the drawn ZIP 318
/// spread. The returned preview reflects that (every transfer executable now).
///
/// # Safety
/// See [`open`]. Free the returned pointer with [`zcashlc_free_migration_schedule`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_migration_propose_immediate_transfers(
    db_data: *const u8,
    db_data_len: usize,
    account_uuid_bytes: *const u8,
    network_id: u32,
) -> *mut FfiMigrationSchedule {
    let res = catch_panic(|| {
        let mut ctx = unsafe { open(db_data, db_data_len, account_uuid_bytes, network_id)? };
        match plan_and_cache(&mut ctx, true)? {
            Some((plan, reference_height, handle)) => {
                // Preview mirrors the commit-time rewrite: every transfer due at the tip.
                let rows = schedule_rows(
                    plan.crossing_values(),
                    plan.schedule(),
                    prep_tx_count(&plan),
                )?;
                let transfers = rows
                    .into_iter()
                    .map(|(id, amount, _, expiry)| {
                        Ok(FfiTransferProposal {
                            id: u32::from(id),
                            amount: zat_to_i64(amount),
                            anchor_height: i64::from(u32::from(reference_height)),
                            next_executable_after_height: i64::from(u32::from(reference_height)),
                            expiry_height: i64::from(u32::from(expiry)),
                        })
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                let (transfers, transfers_len) = ptr_from_vec(transfers);
                Ok(Box::into_raw(Box::new(FfiMigrationSchedule {
                    transfers,
                    transfers_len,
                    estimated_duration_hours: 0,
                    proposal_handle: handle,
                })))
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
        let tip = ctx.tip()?;
        let served = drive_and_serve_next_due(&mut state, tip, |state, id| {
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
        let tip = ctx.tip()?;
        let next_transfer = due_assuming_proving(&state, tip)
            .and_then(|id| state.transactions().iter().find(|t| t.id() == id))
            .filter(|t| matches!(t.kind(), MigrationTxKind::Transfer { .. }));
        match next_transfer {
            Some(tx) => {
                let amount = transfer_amount(&state, tx)
                    .ok_or_else(|| anyhow!("stored transfer has no funding-note amount"))?;
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
                insert_invalid_mark(&mut ctx.wallet, &ctx.account_bytes, id, reason)
                    .map_err(|e| anyhow!("marks write failed: {e}"))?;
                Ok(true)
            }
            other => Err(anyhow!("unknown TransferResult tag: {other}")),
        }
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
                        state.denominations().clone(),
                        state.preparation().clone(),
                        state.transactions().clone(),
                        state.anchor_bucket_interval(),
                    );
                    backend.replace_migration(&cancelled)?;
                }
            }
        }
        clear_invalid_marks(&mut ctx.wallet, &ctx.account_bytes)
            .map_err(|e| anyhow!("marks clear failed: {e}"))?;
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
        let target = BlockHeight::from(u32::from(tip) + 1);
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

/// Decode the platform's parallel `(id, pczt)` arrays into owned pairs.
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
    use zcash_pool_migration::denomination::DenominationPlan;
    use zcash_pool_migration::preparation::PreparationPlan;
    use zcash_pool_migration::scheduling::{self, AnchorBucketInterval, SchedulingParams};

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
            transactions.push(MigrationTransaction::from_parts(
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
            transactions.push(MigrationTransaction::from_parts(
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
        MigrationState::from_parts(
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
        height: BlockHeight::from_u32(100),
    };

    #[test]
    fn derive_no_migration_is_not_started() {
        assert!(matches!(
            derive_state(None, h(100), &[]),
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
            derive_state(Some(&state), h(100), &[]),
            DerivedState::NotStarted
        ));
    }

    #[test]
    fn derive_complete_is_per_run_complete() {
        let state = test_state(MigrationStatus::Complete, &[MINED], &[MINED], 50, 10_000);
        assert!(matches!(
            derive_state(Some(&state), h(100), &[]),
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
            derive_state(Some(&state), h(100), &[]),
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
        match derive_state(Some(&state), h(100), &[]) {
            DerivedState::InProgress {
                completed_transfers,
                total_transfers,
                next_transfer_ready_at_height,
            } => {
                assert_eq!(completed_transfers, 1);
                assert_eq!(total_transfers, 3);
                assert_eq!(next_transfer_ready_at_height, Some(h(50)));
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
            derive_state(Some(&state), h(100), &[1]),
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
            derive_state(Some(&state), h(100), &[]),
            DerivedState::TransferExpired
        ));
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
        // Amount pairing survives the sort, and each row carries the CROSSING value (the round
        // denomination the user consented to), not the funding note that funds its fee.
        for (id, amount, _, _) in &rows {
            let crossing = u32::from(*id) - 3;
            assert_eq!(*amount, zat((u64::from(crossing) + 1) * 100_000_000));
        }
    }

    /// A row reports what the transfer moves: the engine's crossing value, already net of the fee
    /// buffer, so the amount is the round denomination the user approved.
    #[test]
    fn schedule_rows_report_the_crossing_value_not_the_funding_note() {
        let mut rng = StdRng::seed_from_u64(11);
        let schedule = scheduling::schedule(&SchedulingParams::ZIP_318, h(1_000), 1, &mut rng);
        let crossing = 500_000_000;
        let rows = schedule_rows(&[zat(crossing)], &schedule, 0).unwrap();
        assert_eq!(
            rows[0].1,
            zat(crossing),
            "the row must carry the crossing value, not the funding note"
        );
    }

    #[test]
    fn schedule_rows_reject_length_mismatch() {
        let mut rng = StdRng::seed_from_u64(7);
        let schedule = scheduling::schedule(&SchedulingParams::ZIP_318, h(1_000), 3, &mut rng);
        let crossing_values = vec![zat(100)];
        assert!(schedule_rows(&crossing_values, &schedule, 0).is_err());
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
            MigrationTransaction::from_parts(
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
            MigrationTransaction::from_parts(
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
        let state = MigrationState::from_parts(
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
        unsafe { zcashlc_free_migration_schedule(schedule_ptr) };
    }

    /// The handle gate's miss behavior: an empty cache reports `Missing` for ANY handle,
    /// including the `0` "no plan" sentinel a state-encoded or empty schedule carries. A real
    /// plan is unconstructible here (no public constructor), so the `Superseded` arm — a cached
    /// plan under a DIFFERENT handle — is pinned structurally by `migration_plan_cache::get`'s
    /// three-arm match and exercised end-to-end by the welding offline tests.
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

    /// Round-trips the invalid-transfer marks through the extension table that
    /// `zcashlc_init_data_database`'s external migrations create (exercising the whole chain:
    /// the `ext_zcashlc_*` schema migration, then the mediated extension-transaction access).
    #[test]
    fn invalid_marks_round_trip() {
        use zcash_client_sqlite::WalletDb;
        use zcash_client_sqlite::util::SystemClock;

        let path = init_fixture_db("zcashlc_migration_invalid_marks_round_trip");
        let network = parse_network(NETWORK_ID_MAINNET).expect("mainnet parses");
        let mut wallet = WalletDb::for_path(&path, network, SystemClock, OsRng)
            .expect("the fixture wallet opens");
        let account = [9u8; 16];
        let other = [8u8; 16];
        assert!(invalid_marks(&mut wallet, &account).unwrap().is_empty());
        insert_invalid_mark(
            &mut wallet,
            &account,
            MigrationTransferId::new(4),
            "invalid_note",
        )
        .unwrap();
        insert_invalid_mark(
            &mut wallet,
            &account,
            MigrationTransferId::new(2),
            "expired",
        )
        .unwrap();
        insert_invalid_mark(
            &mut wallet,
            &other,
            MigrationTransferId::new(7),
            "invalid_note",
        )
        .unwrap();
        assert_eq!(invalid_marks(&mut wallet, &account).unwrap(), vec![2, 4]);
        clear_invalid_marks(&mut wallet, &account).unwrap();
        assert!(invalid_marks(&mut wallet, &account).unwrap().is_empty());
        assert_eq!(invalid_marks(&mut wallet, &other).unwrap(), vec![7]);
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
        zcash_pool_migration::build::build_transfer_pczt(
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

    use zcash_pool_migration::engine::MigrationProver;
    use zcash_pool_migration::wallet::WalletProveError;
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
            base.denominations().clone(),
            base.preparation().clone(),
            transactions,
            base.anchor_bucket_interval(),
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
            MigrationTransferId::new(1),
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
            MigrationTransferId::new(0),
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
            .find(|t| t.id() == MigrationTransferId::new(0))
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
            MigrationTransferId::new(1),
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
            .find(|t| t.id() == MigrationTransferId::new(1))
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
                MigrationTransferId::new(1),
                None,
            )
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
                MigrationTransferId::new(1),
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
            MigrationTransferId::new(0),
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
            base.denominations().clone(),
            base.preparation().clone(),
            transactions,
            base.anchor_bucket_interval(),
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
        id: MigrationTransferId,
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
        assert_eq!(
            id,
            MigrationTransferId::new(1),
            "the transfer row must be served"
        );
        assert_eq!(
            prover.calls,
            vec![ProveCall::Transfer(h(1440))],
            "the drive must prove exactly once, against the row's persisted boundary"
        );
        let stored = read_fixture_state(&path, &account);
        let tx = stored
            .transactions()
            .iter()
            .find(|t| t.id() == MigrationTransferId::new(1))
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
            .find(|t| t.id() == MigrationTransferId::new(1))
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
            MigrationTransferId::new(2),
            "the schedule-due transfer must be the one served"
        );
        let stored = read_fixture_state(&path, &account);
        for expect_id in [1u32, 2u32] {
            let tx = stored
                .transactions()
                .iter()
                .find(|t| t.id() == MigrationTransferId::new(expect_id))
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
            )
        };
        assert!(
            overdue,
            "a due-but-unproved Signed transfer is overdue delivery work"
        );
        let _ = std::fs::remove_file(&path);
    }
}
