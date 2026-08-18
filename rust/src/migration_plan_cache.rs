//! In-process cache of the most recent [`MigrationPlan`] per `(database, account)`, bridging the
//! gap between `plan_migration_sized_with()` (a pure, unpersisted preview) and the commit functions
//! (`commit_preparation`/`build_preparation_unsigned`) that must sign that exact plan value later.
//!
//! Every cached plan is identified by an opaque, randomly drawn [`PlanHandle`], returned to the
//! platform inside the proposal DTOs (`FfiNoteSplitProposal::proposal_handle` /
//! `FfiMigrationSchedule::proposal_handle`). A commit call passes the handle back, and [`get`]
//! refuses to release a plan under any other handle — so a commit can only ever sign the exact
//! plan the platform displayed, never one that a later propose/prepare call happened to cache in
//! the meantime (ZIP 318's scheduling draws fresh randomness on every `plan_migration_sized_with()`
//! call, so two plans essentially never agree even over unchanged wallet state). The handle gate
//! replaces the earlier field-by-field "verified consent echo" (F4) contract: instead of the
//! platform echoing schedule values back for comparison against a byte-for-byte reproduction of the
//! preview DTO, plan details now never cross the FFI boundary inward at all.
//!
//! This is deliberately NOT persisted: the engine's `MigrationPlan` (and its `DenominationPlan`/
//! `PreparationPlan` fields) has no `serde` support and no public constructor — the only way to
//! obtain one is calling `plan_migration_sized_with()` itself — so it cannot round-trip through our
//! own storage. It lives in a process-lifetime static instead, which matches the app's flow: the
//! whole "review a migration proposal, then confirm it" sequence happens in one app-process
//! lifetime. If the process is killed between propose and confirm, the commit path surfaces the
//! stable `MIGRATION_PLAN_STALE` error (mapped to `ZcashError.migrationPlanStale` in Swift) so the
//! app re-proposes, rather than silently recomputing a fresh, differently-randomized plan the user
//! never saw or approved.
//!
//! Each entry also records whether the plan was previewed through the IMMEDIATE lane, so the
//! commit path knows to rewrite the committed transfers' scheduled heights to the commit height
//! (everything due at once) instead of keeping the drawn ZIP 318 spread.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use rand::RngCore;
use rand::rngs::OsRng;
use zcash_pool_migration::engine::MigrationPlan;

/// Opaque identifier of one cached [`MigrationPlan`]. Drawn fresh (randomly, never zero) for
/// every plan, so a handle from an earlier proposal can never accidentally match a later one.
/// `0` is reserved as the platform-visible "no plan" sentinel (an empty nothing-to-migrate
/// schedule, or a schedule encoded from already-committed STORED state, which no cache entry
/// backs) and is never issued.
pub(crate) type PlanHandle = u64;

/// Why [`get`] could not release a plan for the requested handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlanLookupError {
    /// No plan is cached for the `(database, account)` at all — the process was likely restarted
    /// (the cache is in-memory only), or the plan was already committed and cleared.
    Missing,
    /// A plan is cached, but under a different handle: a later propose/prepare call replaced the
    /// plan the platform displayed (or the handle is the `0` "no plan" sentinel).
    Superseded,
}

impl std::fmt::Display for PlanLookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanLookupError::Missing => {
                f.write_str("no previewed migration plan for this account — propose again")
            }
            PlanLookupError::Superseded => f.write_str(
                "the migration proposal identified by this handle has been superseded by a newer \
                 proposal — re-propose and re-display the new schedule before signing",
            ),
        }
    }
}

impl std::error::Error for PlanLookupError {}

/// A cached preview: the plan, the handle identifying it, and whether it was previewed through
/// the immediate lane.
#[derive(Clone)]
pub(crate) struct CachedPlan {
    pub plan: MigrationPlan,
    pub immediate: bool,
    handle: PlanHandle,
}

type Key = (PathBuf, [u8; 16]);

fn store() -> &'static Mutex<HashMap<Key, CachedPlan>> {
    static STORE: OnceLock<Mutex<HashMap<Key, CachedPlan>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Records the most recently previewed plan for `(db_path, account)`, replacing any previous one
/// (each propose call replaces any prior unconsumed proposal), and returns the fresh handle that
/// now identifies it. Any handle previously issued for the key is thereby invalidated:
/// committing with it fails with [`PlanLookupError::Superseded`].
pub(crate) fn set(
    db_path: PathBuf,
    account: [u8; 16],
    plan: MigrationPlan,
    immediate: bool,
) -> PlanHandle {
    let handle = loop {
        let candidate = OsRng.next_u64();
        if candidate != 0 {
            break candidate;
        }
    };
    store().lock().unwrap_or_else(|e| e.into_inner()).insert(
        (db_path, account),
        CachedPlan {
            plan,
            immediate,
            handle,
        },
    );
    handle
}

/// Returns a clone of the cached plan for `(db_path, account)`, but only if `handle` identifies
/// it — i.e. only if no later propose/prepare call has replaced the plan the platform displayed.
pub(crate) fn get(
    db_path: &PathBuf,
    account: [u8; 16],
    handle: PlanHandle,
) -> Result<CachedPlan, PlanLookupError> {
    match store()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&(db_path.clone(), account))
    {
        None => Err(PlanLookupError::Missing),
        Some(cached) if cached.handle != handle => Err(PlanLookupError::Superseded),
        Some(cached) => Ok(cached.clone()),
    }
}

/// Drops the cached plan for `(db_path, account)` — called once it has been committed, since the
/// durable, authoritative copy from that point on is what the migration store persists.
pub(crate) fn clear(db_path: &PathBuf, account: [u8; 16]) {
    store()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&(db_path.clone(), account));
}
