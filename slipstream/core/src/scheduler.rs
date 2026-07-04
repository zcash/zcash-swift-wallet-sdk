//! Scheduler v0: drive the wallet's own scan-queue (decision D3 — the coverage
//! ledger IS data.db's suggested ranges). For each suggested range, run the
//! fetch∥scan pipeline; re-suggest after each range until the queue is empty.
//! Priority handling (Verify-first) comes for free: suggest_scan_ranges returns
//! Verify ranges first by upstream contract.

use std::{collections::HashSet, sync::Arc, time::Duration};

use tracing::{info, warn};
use zcash_client_backend::data_api::{WalletWrite, scanning::ScanPriority};
use zcash_protocol::consensus::BlockHeight;

use crate::{
    chunk::chunk_queue,
    config::EngineConfig,
    connector::{ConnPurpose, TorConn, connect_via},
    enhance::{EnhanceStats, run_enhancement},
    error::SlipstreamError,
    events::Progress,
    fetch::{FetchPlan, FetchStats, run_fetch},
    scan::{ScanStats, scan_chunks},
    wallet_session::WalletSession,
};

/// Maximum number of consecutive reorg recoveries before giving up.
/// After this many back-to-back ScanContinuity errors without a successful
/// range completion, run_to_completion returns the error to break ping-pong.
const MAX_CONSECUTIVE_REORGS: u64 = 5;

// Compile-time bounds: ≥1 (otherwise the first reorg is never recovered) and
// ≤10 (otherwise infinite ping-pong is possible). Fails the build if violated.
const _: () = {
    assert!(MAX_CONSECUTIVE_REORGS >= 1);
    assert!(MAX_CONSECUTIVE_REORGS <= 10);
};

/// B3 (#1755 failure-path hardening): backoff before re-suggesting after a reorg
/// truncate, growing with the consecutive-recovery count.
///
/// Rationale: a tip-desync across a load-balanced lightwalletd cluster (zec.rocks /
/// eu.zec.rocks terminate one hostname on several backends) heals within seconds —
/// but instant retries can burn the whole MAX_CONSECUTIVE_REORGS budget against the
/// same momentarily-stale view, failing a multi-minute restore for a transient
/// condition (field failure 1 candidate trigger, 2026-06-12). Deterministic growth:
/// 500 ms × consecutive, capped at 3 s — total worst-case added latency across the
/// 5-recovery budget is 500+1000+1500+2000+2500 = 7.5 s, negligible vs a restore.
pub(crate) fn reorg_backoff_ms(consecutive: u64) -> u64 {
    consecutive.saturating_mul(500).min(3_000)
}

/// [API v2 §4.4 / Phase E] The wallet's GLOBAL scan position in permille: how much of
/// `[birthday, tip]` is NOT in the remaining scan queue. Seeds the session-monotonic
/// permille floor so the blessed progress never reads pass-local on a fresh handle —
/// the raw pass ratio would flash a 99.9%-synced wallet's UI to ~0% on every cold-launch
/// catch-up (the SDK used to mask this with its own summary-derived floor; this is that
/// floor's engine-owned successor). `None` when the inputs cannot express a position
/// (no tip advertised yet, no accounts, or a tip below the birthday).
pub(crate) fn global_floor_permille(tip: u64, birthday: Option<u64>, remaining: u64) -> Option<u64> {
    let birthday = birthday?;
    if tip == 0 || tip < birthday {
        return None;
    }
    let span = tip - birthday + 1;
    let scanned = span.saturating_sub(remaining);
    Some(scanned.saturating_mul(1000) / span)
}

/// [API v2.1 E-3] Seed the snapshot atomics from PERSISTED wallet state, so the snapshot is
/// truthful from `open()` — before the first suggest round — and hosts never compensate for
/// a pre-pass snapshot that "lies" (the ENGINE_API_V2.md §0 known gap: `is_recovering` read
/// 0 mid-restore and `progress_permille` read 0 on a 99%-synced wallet until the scheduler's
/// first suggest round, which on a Tor cold start can be many seconds away).
///
/// Replicates the first suggest round's math against the DB alone (no network):
///   - `chain_tip`  — the wallet's persisted tip view (`WalletRead::chain_height`, the height
///     the last `update_chain_tip` recorded). The live pass overwrites it on its first fetch.
///   - `recovering` — any suggested range still starts below MAX(`accounts.recover_until_height`)
///     (identical to the per-round computation in [`run_to_completion`]).
///   - permille floor — [`global_floor_permille`] over (persisted tip, MIN(birthday),
///     Σ remaining queue), folded via `fetch_max` (a seed can only raise the floor).
///   - `spendable`  — latched when NO ChainTip/Verify-priority range remains pending: the
///     recent window is fully scanned, which is exactly what the in-pass latch records.
///
/// A wallet with no accounts seeds nothing — a fresh wallet's zero snapshot IS truthful.
/// Callers treat errors as "no seed" (presentation state, never correctness state).
pub fn seed_progress_from_wallet(
    progress: &Progress,
    session: &WalletSession,
) -> Result<(), SlipstreamError> {
    let Some(birthday) = session.min_birthday()? else {
        return Ok(()); // no accounts — the zero snapshot is the truth
    };
    let ranges = session.suggest_scan_ranges()?;
    let recover_until = session.max_recover_until()?;
    let recovering = recover_until.map_or(false, |ru| {
        ranges.iter().any(|r| u64::from(r.block_range().start) < ru)
    });
    progress.set_recovering(recovering);

    let recent_pending = ranges
        .iter()
        .any(|r| matches!(r.priority(), ScanPriority::ChainTip | ScanPriority::Verify));
    if !recent_pending {
        progress.set_spendable();
    }

    let tip = session.chain_height()?.unwrap_or(0);
    if tip != 0 {
        progress.set_chain_tip(tip);
    }
    let sum_remaining: u64 = ranges
        .iter()
        .map(|r| {
            let s = u64::from(r.block_range().start);
            let e = u64::from(r.block_range().end);
            e.saturating_sub(s)
        })
        .sum();
    if let Some(seed) = global_floor_permille(tip, Some(birthday), sum_remaining) {
        let _ = progress.permille_floor(seed);
    }
    tracing::info!(
        tip,
        birthday,
        sum_remaining,
        recovering,
        spendable = !recent_pending,
        "E-3 snapshot seeded from persisted wallet state (truthful from open)"
    );
    Ok(())
}

#[derive(Debug, Default, Clone)]
pub struct SyncReport {
    pub ranges_processed: u64,
    pub fetch: FetchStatsTotals,
    pub scan: ScanStatsTotals,
    /// Enhancement stats accumulated across ALL per-range enhancement runs.
    /// F3: each range's enhancement contributes to this sum; the engine's final
    /// post-loop enhancement also accumulates here via SyncOutcome merge in engine.rs.
    pub enhance: EnhanceStats,
    /// Number of reorg recoveries performed (truncate + re-suggest) during this sync.
    pub reorgs_recovered: u64,
    /// Total wall-clock time spent in the fetch pipeline (across all ranges).
    /// Accumulated from `FetchStats::elapsed` per range. Default: zero.
    pub fetch_elapsed: Duration,
    /// Total wall-clock time spent in scan_chunks (across all ranges).
    /// Measured around the scan call per range. Default: zero.
    pub scan_elapsed: Duration,
    /// Total wall-clock time spent in per-range run_enhancement calls (F3).
    /// The engine's final post-loop enhancement adds its own elapsed to SyncOutcome
    /// directly; this field covers the scheduler's interleaved runs only.
    pub enhance_elapsed: Duration,
    /// T6.9 write-behind: Σ time the scan loop was blocked awaiting deferred
    /// commits (0 ≈ perfect overlap; always 0 with the flag off).
    pub persist_wait_elapsed: Duration,
    /// T6.9 write-behind: Σ wall time of the deferred commits themselves.
    pub persist_busy_elapsed: Duration,
    /// v0.4 census (spec §3.2): per-pool shard census unioned across all ranges.
    pub census_sapling: crate::census::ShardCensus,
    pub census_orchard: crate::census::ShardCensus,
}

#[derive(Debug, Default, Clone)]
pub struct FetchStatsTotals {
    pub blocks: u64,
    pub bytes: u64,
}

#[derive(Debug, Default, Clone)]
pub struct ScanStatsTotals {
    pub blocks: u64,
    pub sapling_received: u64,
    pub orchard_received: u64,
}

/// Process every suggested range until none remain. The caller has already
/// run update_chain_tip + put_subtree_roots (engine.rs).
///
/// `progress` — if `Some`, bumps `fetched_blocks`, `scanned_blocks`, `reorgs_recovered`,
/// and `current_range_end` atomics so poll-based consumers (CLI ticker, iOS D8) get
/// live updates. Pass `None` to skip all atomic stores (the default for tests).
pub async fn run_to_completion(
    config: &EngineConfig,
    session: &mut WalletSession,
    progress: Option<Arc<Progress>>,
    skipped_keys: &mut HashSet<String>,
    tor: Option<&TorConn>,
) -> Result<SyncReport, SlipstreamError> {
    let mut report = SyncReport::default();
    // Counter for back-to-back ScanContinuity recoveries without a successful range.
    // Reset to 0 on any successful range completion. Capped at MAX_CONSECUTIVE_REORGS
    // to prevent infinite ping-pong (e.g. adversarial server or database corruption).
    let mut consecutive_reorgs: u64 = 0;
    // F1: track blocks scanned so far in this pass (local accumulator).
    // Used to compute the whole-pass denominator: scanned_so_far + sum(remaining ranges).
    let mut scanned_so_far_in_pass: u64 = 0;
    // [API v2 §4.4] The wallet's recovery ceiling, read once per pass: the snapshot's
    // `is_recovering` is true while any suggested range still starts below it (the restore
    // backfill window). A read failure degrades to "not recovering" rather than failing the
    // pass — the flag is presentation state, never correctness state.
    let recover_until: Option<u64> = session.max_recover_until().unwrap_or_default();
    // [API v2 §4.4 / Phase E] The wallet's oldest birthday, read once per pass alongside the
    // recovery ceiling: with the chain tip and the remaining queue it seeds the global permille
    // floor each suggest round (below). A read failure degrades to "no seed" — presentation
    // state, never correctness state.
    let wallet_birthday: Option<u64> = session.min_birthday().unwrap_or_default();
    // [API v2.1 E-4] Pass-start baseline for the boundary tx-set signature check (see the
    // range-boundary block at the bottom of the loop). `None` (read failure) = the first
    // successful boundary read becomes the baseline without bumping.
    let mut last_tx_sig: Option<(u64, u64)> = session.tx_set_signature().ok();
    loop {
        let ranges = session.suggest_scan_ranges()?;
        // [API v2 §4.4] Recompute the recovery flag on every suggest round: still recovering
        // iff work remains below the recovery ceiling. An empty queue (handled below) or a
        // queue entirely above the ceiling flips it false — recovery is over even though the
        // pass may keep scanning newer ranges.
        if let Some(ref p) = progress {
            let recovering = recover_until.map_or(false, |ru| {
                ranges.iter().any(|r| u64::from(r.block_range().start) < ru)
            });
            p.set_recovering(recovering);
        }
        let Some(range) = ranges.first() else {
            info!("scan queue empty — sync complete");
            return Ok(report);
        };

        // F1: Compute whole-pass denominator from ALL returned ranges (not just the first).
        // `suggest_scan_ranges` returns all pending ranges for this pass together
        // (both ChainTip and Historic are returned on the first call — confirmed by the
        // user's iPad log showing the 0→100→60% snap-back: the old code accumulated
        // per-range, so ChainTip alone filled 100% before Historic expanded the denominator).
        // By summing ALL returned ranges and STORING (not adding), the denominator is
        // complete from the very first suggestion. Re-suggest after each range recomputes
        // correctly: scanned_so_far + sum(remaining) stays constant unless new ranges appear.
        if let Some(ref p) = progress {
            let sum_remaining: u64 = ranges
                .iter()
                .map(|r| {
                    let s = u64::from(r.block_range().start);
                    let e = u64::from(r.block_range().end);
                    e.saturating_sub(s)
                })
                .sum();
            p.set_pass_total(scanned_so_far_in_pass + sum_remaining);
            // [API v2 §4.4 / Phase E] Seed the session-monotonic floor with the GLOBAL position.
            // fetch_max semantics: the seed can only RAISE the floor, and re-seeding every suggest
            // round tracks global progress as ranges complete. Two behaviours fall out for free:
            // a cold-launch catch-up starts at ~99.9% instead of flashing 0% (the old Swift
            // summary floor), and a relaunched restore RESUMES near its true position instead of
            // 0% (the old Swift monotonic floor could not survive a relaunch).
            if let Some(seed) = global_floor_permille(p.chain_tip(), wallet_birthday, sum_remaining) {
                // [API v2.1 E-5] Scope-expansion re-baseline: an imported account with an
                // older birthday (or a rewind) grows the span under the session floor —
                // without this, the ~1000 floor from the previous scope's Done would mask
                // the whole re-scan at ~100% (the host used to bypass every floor with
                // `forceCounterProgressUntilDone`; the blessed permille now reads the
                // genuine climb by itself).
                if p.rebaseline_floor_if_scope_expanded(seed) {
                    info!(
                        seed,
                        birthday = wallet_birthday,
                        "scan scope expanded — session progress floor re-baselined (re-scan reads as a genuine climb)"
                    );
                }
                let _ = p.permille_floor(seed);
            }
        }

        // block_range() returns a Range<BlockHeight> where .end is END-EXCLUSIVE
        // (standard Rust Range semantics, confirmed at zcash_client_backend-0.22.0/src/data_api/scanning.rs:62).
        // Both u32::from(BlockHeight) and u64::from(BlockHeight) exist; use u64 directly
        // to avoid a two-step cast and to match the rest of the scheduler's u64 arithmetic.
        let start: u64 = u64::from(range.block_range().start);
        let end_exclusive: u64 = u64::from(range.block_range().end);

        // Guard the degenerate empty range (should not happen per upstream contract, but if it
        // does, return a Wallet error rather than constructing an invalid FetchPlan).
        if end_exclusive <= start {
            return Err(SlipstreamError::Wallet(format!(
                "degenerate scan range: start={start} end_exclusive={end_exclusive}"
            )));
        }

        // FetchPlan takes inclusive [start, end]; subtract 1 from the exclusive end.
        let end = end_exclusive - 1;
        info!(start, end, priority = ?range.priority(), "processing suggested range");

        // Advertise the current range end to poll-based consumers.
        if let Some(ref p) = progress {
            p.set_range_end(end);
        }

        let (tx, rx) = chunk_queue(config.memory_budget_bytes);
        let mut plan = FetchPlan::new(start, end, config.chunk_blocks, config.fetch_streams);
        // T6.8-S: byte-budgeted sub-chunk splitting (sandblasting-era survival).
        plan.split_bytes = config.chunk_split_bytes;
        let endpoint = config.endpoint.clone();
        // Clone the progress Arc for the fetch task so it can bump fetched_blocks.
        let fetch_progress = progress.clone();

        // Spawn the fetch task so it runs concurrently with scan_chunks below.
        // The tx is moved into the task; when the task finishes, tx is dropped, which
        // closes the channel and causes scan_chunks's rx.recv() loop to terminate.
        let fetch_task = tokio::spawn(async move {
            run_fetch(&endpoint, plan, tx, fetch_progress).await
        });

        // scan_chunks runs in the current task using a SEPARATE grpc client so it
        // does not contend with the fetch workers' connections.
        let mut scan_client = connect_via(&config.endpoint, tor, ConnPurpose::MetadataUnique).await?;

        let scan_started = std::time::Instant::now();
        let scan_result: Result<ScanStats, SlipstreamError> =
            scan_chunks(
                session,
                &mut scan_client,
                start,
                rx,
                progress.clone(),
                config,
                skipped_keys,
                tor,
                // v0.4 Plan A: only Historic ranges buffer (accumulator rule 2).
                range.priority() == ScanPriority::Historic,
            )
            .await;
        let scan_wall = scan_started.elapsed();

        // Error-precedence rationale (deviation from plan's draft `??` which loses nuance):
        // If scan_chunks fails first, dropping rx causes the fetch task to see a
        // send-error and finish with Stopped or a transport error — both are secondary.
        // We ALWAYS await the JoinHandle so the task is not left running in the background,
        // but if scan already failed we prefer returning the scan error; the fetch's secondary
        // error is downgraded to a tracing::warn.
        //
        // ScanContinuity is the special case: the fetch task for the aborted range is
        // awaited (to avoid leaking the task), its secondary error is warned but NOT
        // propagated, then we truncate + re-suggest and continue the loop.
        let fetch_result: Result<FetchStats, SlipstreamError> = fetch_task
            .await
            .map_err(|e| SlipstreamError::Transport(format!("fetch task panicked: {e}")))?;

        // Reorg recovery arm — mirrors upstream sync.rs:404-418
        // (zcash_client_backend-0.22.0/src/sync.rs:404-418):
        //
        //   Err(ChainError::Scan(err)) if err.is_continuity_error() => {
        //       let rewind_height = err.at_height().saturating_sub(10);
        //       db_data.truncate_to_height(rewind_height)?;
        //       // re-suggest via Ok(true)
        //   }
        //
        // Rewind computation: subtract 10 blocks from the error height, matching upstream
        // exactly. `saturating_sub` prevents underflow at low heights.
        if let Err(SlipstreamError::ScanContinuity { at }) = scan_result {
            // Await the fetch task for the aborted range (must not leave it running).
            // Its secondary error (Stopped / send-error from dropped rx) is demoted to warn.
            if let Err(ref fetch_err) = fetch_result {
                warn!(%fetch_err, "fetch task also errored during reorg recovery (secondary, demoted)");
            }

            consecutive_reorgs += 1;
            if consecutive_reorgs > MAX_CONSECUTIVE_REORGS {
                warn!(
                    consecutive_reorgs,
                    at,
                    "too many consecutive reorg recoveries — giving up"
                );
                return Err(SlipstreamError::ScanContinuity { at });
            }

            // Mirror upstream rewind: err_height.saturating_sub(10)
            // (sync.rs:409: `let rewind_height = err.at_height().saturating_sub(10)`)
            let rewind_height = at.saturating_sub(10);
            warn!(
                at,
                rewind_height,
                consecutive = consecutive_reorgs,
                "continuity break detected — truncating wallet DB and re-suggesting"
            );

            // truncate_to_height returns Result<BlockHeight, WalletDb::Error>
            // (data_api.rs:3233: `fn truncate_to_height(&mut self, max_height: BlockHeight) -> Result<BlockHeight, Self::Error>`)
            session
                .db_mut()
                .truncate_to_height(BlockHeight::from(rewind_height))
                .map_err(|e| SlipstreamError::Wallet(format!("truncate_to_height: {e}")))?;

            report.reorgs_recovered += 1;
            if let Some(ref p) = progress {
                p.add_reorg();
            }

            // B3 (#1755): give a desynced load-balanced cluster a heal window before
            // retrying — see reorg_backoff_ms. Connection freshness on retry is
            // structural, not added here: the next loop iteration creates a NEW
            // scan-side client (grpc::connect per range, above) and run_fetch spawns
            // NEW per-worker connections (fetch.rs worker() connects per worker, per
            // range) — no gRPC channel survives into the retry, so the retry cannot
            // be pinned to the same stale backend.
            let backoff_ms = reorg_backoff_ms(consecutive_reorgs);
            warn!(
                backoff_ms,
                consecutive = consecutive_reorgs,
                "reorg backoff before re-suggest (cluster tip-desync heal window)"
            );
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;

            // `continue` causes the outer loop to call suggest_scan_ranges again;
            // the repair range (from rewind_height up to current tip) is now suggested.
            continue;
        }

        let (scan_stats, fetch_stats) = match (scan_result, fetch_result) {
            (Ok(s), Ok(f)) => (s, f),
            (Err(scan_err), fetch_outcome) => {
                // Scan failed — fetch's secondary error (Stopped, send-error) is demoted.
                if let Err(ref fetch_err) = fetch_outcome {
                    warn!(%fetch_err, "fetch task also errored (secondary, scan error takes precedence)");
                }
                return Err(scan_err);
            }
            (Ok(_), Err(fetch_err)) => {
                // Fetch failed but scan succeeded — this is unusual (scan consumed all chunks
                // before fetch detected the error, or fetch had a worker panic after sending
                // all chunks). Return the fetch error so the caller is informed.
                return Err(fetch_err);
            }
        };

        // Successful range completion: reset the consecutive-reorg counter.
        consecutive_reorgs = 0;
        report.ranges_processed += 1;
        report.fetch.blocks += fetch_stats.blocks;
        report.fetch.bytes += fetch_stats.bytes;
        report.fetch_elapsed += fetch_stats.elapsed;
        report.scan.blocks += scan_stats.blocks;
        report.scan.sapling_received += scan_stats.sapling_received;
        report.scan.orchard_received += scan_stats.orchard_received;
        // T6.1: interleaved-enhancement time is enhancement, not scan.
        report.scan_elapsed += scan_wall.saturating_sub(scan_stats.interleaved_enhance_elapsed);
        report.enhance_elapsed += scan_stats.interleaved_enhance_elapsed;
        // T6.9: persist overlap accounting (scan_elapsed deliberately KEEPS the
        // persist_wait portion — it is honest loop wall time; see engine.rs log).
        report.persist_wait_elapsed += scan_stats.persist_wait;
        report.persist_busy_elapsed += scan_stats.persist_busy;
        report.census_sapling.merge(&scan_stats.census_sapling);
        report.census_orchard.merge(&scan_stats.census_orchard);
        report.enhance.requests += scan_stats.interleaved_enhance.requests;
        report.enhance.txs_stored += scan_stats.interleaved_enhance.txs_stored;
        report.enhance.statuses_set += scan_stats.interleaved_enhance.statuses_set;
        report.enhance.skipped += scan_stats.interleaved_enhance.skipped;

        // F1: accumulate scanned blocks for next iteration's whole-pass denominator.
        scanned_so_far_in_pass += scan_stats.blocks;

        // Spendable latch: if this range was ChainTip priority, funds are now likely
        // spendable (SBS semantics — the tip-priority range covers the most-recent
        // blocks where the wallet's own notes appear as spendable).
        if range.priority() == ScanPriority::ChainTip
            && let Some(ref p) = progress
        {
            p.set_spendable();
        }

        // F3: Per-range interleaved enhancement.
        // Runs AFTER scan_chunks completes for this range (scanner paused, DB in a
        // consistent state, low contention vs. rayon trial-decryption).
        // Cost on iPad A10: ~0.69s/run at sync end → interleaving is ~free per range.
        // This makes transactions visible progressively during the sync, not just at
        // the very end. The engine's final post-loop run_enhancement still fires
        // (catches any leftovers) and its stats are accumulated into SyncOutcome
        // separately. We reuse a fresh gRPC client per call (same pattern as engine.rs).
        //
        // NON-FATAL: interleaved enhancement is an optimization (progressive tx
        // visibility), not a correctness guarantee — that is the final post-loop run's
        // job. A transient connect/fetch failure here must NOT abort a multi-minute
        // sync at a range boundary; we log and continue scanning.
        {
            let enhance_started = std::time::Instant::now();
            let enhance_result = async {
                let mut enhance_client = connect_via(&config.endpoint, tor, ConnPurpose::MetadataUnique).await?;
                run_enhancement(session, &mut enhance_client, config.network, progress.clone(), skipped_keys)
                    .await
            }
            .await;
            match enhance_result {
                Ok(enhance_stats) => {
                    // Accumulate into report so stage-split in engine.rs sums all runs.
                    report.enhance.requests += enhance_stats.requests;
                    report.enhance.txs_stored += enhance_stats.txs_stored;
                    report.enhance.statuses_set += enhance_stats.statuses_set;
                    report.enhance.skipped += enhance_stats.skipped;
                }
                Err(err) => {
                    warn!(
                        %err,
                        start,
                        end,
                        "per-range enhancement failed — continuing; final post-loop enhancement will retry"
                    );
                }
            }
            report.enhance_elapsed += enhance_started.elapsed();
        }

        // F2: Bump ranges_completed AFTER scan + per-range enhancement.
        // Swift observes this counter and triggers ONE balance-summary fetch per boundary.
        if let Some(ref p) = progress {
            p.add_ranges_completed();
            // [API v2.1 E-4] Boundary tx-set signature check: catches set changes that arrive
            // WITHOUT an enhancement write — e.g. scanning a historic block stores the received
            // note that LINKS an already-stored dangling spend (reconciled flips with no new
            // tx). Direct writes (enhance/mempool) bump the version at their own sites; this
            // closes the scan-driven linkage class. Read failure = skip (presentation state).
            if let Ok(sig) = session.tx_set_signature() {
                if last_tx_sig != Some(sig) {
                    if last_tx_sig.is_some() {
                        p.bump_tx_set_version();
                    }
                    last_tx_sig = Some(sig);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_report_default_is_zero() {
        let r = SyncReport::default();
        assert_eq!(r.ranges_processed, 0);
        assert_eq!(r.fetch.blocks, 0);
        assert_eq!(r.fetch.bytes, 0);
        assert_eq!(r.scan.blocks, 0);
        assert_eq!(r.scan.sapling_received, 0);
        assert_eq!(r.scan.orchard_received, 0);
        assert_eq!(r.reorgs_recovered, 0);
        assert_eq!(r.fetch_elapsed, Duration::ZERO);
        assert_eq!(r.scan_elapsed, Duration::ZERO);
        assert_eq!(r.enhance_elapsed, Duration::ZERO);
        // T6.9 write-behind totals default to zero (and stay zero with the flag off).
        assert_eq!(r.persist_wait_elapsed, Duration::ZERO);
        assert_eq!(r.persist_busy_elapsed, Duration::ZERO);
        // F3 EnhanceStats default
        assert_eq!(r.enhance.requests, 0);
        assert_eq!(r.enhance.txs_stored, 0);
        assert_eq!(r.enhance.statuses_set, 0);
        assert_eq!(r.enhance.skipped, 0);
    }

    /// [API v2 §4.4 / Phase E] Cold-launch catch-up: a 99.9%-synced wallet must seed a
    /// near-1000 floor, so the blessed permille can never flash ~0% while the small pass runs.
    #[test]
    fn global_floor_catch_up_seeds_near_complete() {
        // tip 2.0M, birthday 1.0M (span 1_000_001), 3_000 blocks left to scan.
        let seed = global_floor_permille(2_000_000, Some(1_000_000), 3_000).unwrap();
        assert!((990..=1000).contains(&seed), "catch-up must seed near 1000, got {seed}");
    }

    /// A fresh from-birthday restore has (almost) the whole span in the queue — the seed
    /// must stay ~0 so the restore bar still climbs 0→100% off the pass counters.
    #[test]
    fn global_floor_fresh_restore_seeds_zero() {
        let seed = global_floor_permille(2_000_000, Some(1_000_000), 1_000_001).unwrap();
        assert_eq!(seed, 0, "fresh restore must not pre-raise the floor");
    }

    /// A relaunched half-done restore resumes near its true global position (the property
    /// the old Swift monotonic floor could not deliver across a relaunch).
    #[test]
    fn global_floor_relaunched_restore_resumes_position() {
        let seed = global_floor_permille(2_000_000, Some(1_000_000), 500_000).unwrap();
        assert_eq!(seed, 500, "half the span remaining ⇒ ~500‰");
    }

    /// Degenerate inputs cannot express a position: no seed (floor untouched).
    #[test]
    fn global_floor_degenerate_inputs_yield_none() {
        assert_eq!(global_floor_permille(0, Some(1_000_000), 10), None, "no tip yet");
        assert_eq!(global_floor_permille(2_000_000, None, 10), None, "no accounts");
        assert_eq!(global_floor_permille(999, Some(1_000), 10), None, "tip below birthday");
        // Remaining exceeding the span clamps to 0 rather than underflowing.
        assert_eq!(global_floor_permille(1_100, Some(1_000), 5_000), Some(0));
    }

    // ── [API v2.1 E-3] truthful-from-open seed ─────────────────────────────────

    /// Open a wallet with one imported account (TEST_UFVK, birthday treestate at 663149)
    /// and the chain tip persisted at `tip`. Returns the session (birthday = 663150).
    fn wallet_with_account(dir: &tempfile::TempDir, tip: u64) -> WalletSession {
        let path = dir.path().join("data.db");
        let mut s = WalletSession::open(zcash_protocol::consensus::Network::MainNetwork, &path)
            .expect("open wallet");
        let ts = zcash_client_backend::proto::service::TreeState {
            network: "main".into(),
            height: 663_149,
            hash: "0".repeat(64),
            time: 1,
            ..Default::default()
        };
        s.ensure_account(crate::wallet_session::TEST_UFVK, ts).expect("import account");
        s.update_chain_tip(tip).expect("update tip");
        s
    }

    /// A wallet with NO accounts seeds nothing — the zero snapshot is already truthful.
    #[test]
    fn seed_is_noop_on_fresh_wallet() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("data.db");
        let s = WalletSession::open(zcash_protocol::consensus::Network::MainNetwork, &path)
            .expect("open wallet");
        let p = Progress::default();
        seed_progress_from_wallet(&p, &s).expect("seed");
        assert_eq!(p.chain_tip.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert!(!p.recovering());
        assert_eq!(p.spendable(), 0);
        assert_eq!(p.progress_permille_floor.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    /// Never-scanned restore-shaped wallet: the seed reports the persisted tip, a truthful
    /// ~0 floor (the whole span is still queued), NOT recovering (no recover_until), and
    /// spendability mirroring whether a ChainTip/Verify range is still pending.
    #[test]
    fn seed_reports_persisted_position() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tip = 700_000u64;
        let s = wallet_with_account(&dir, tip);
        let p = Progress::default();
        seed_progress_from_wallet(&p, &s).expect("seed");

        assert_eq!(
            p.chain_tip.load(std::sync::atomic::Ordering::Relaxed),
            tip,
            "seed must surface the persisted chain tip"
        );
        assert!(!p.recovering(), "no recover_until ⇒ not recovering");
        assert_eq!(
            p.progress_permille_floor.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "nothing scanned ⇒ truthful 0‰ floor (restore bar still climbs from 0)"
        );
        // Wiring proof: the spendable latch mirrors the actual queue contents.
        let ranges = s.suggest_scan_ranges().expect("ranges");
        let recent_pending = ranges
            .iter()
            .any(|r| matches!(r.priority(), ScanPriority::ChainTip | ScanPriority::Verify));
        assert_eq!(p.spendable() == 1, !recent_pending, "spendable ⇔ no recent range pending");
        // The seed must never bump the tip-REFRESH counter (persisted ≠ freshly proven).
        assert_eq!(p.tip_refreshes(), 0, "E-3 seed must not fake tip freshness");
    }

    /// With `recover_until_height` persisted (a restore in flight), queued ranges below it
    /// must seed `recovering = true` — the mid-restore relaunch case that used to lie 0.
    #[test]
    fn seed_detects_recovering_from_persisted_recover_until() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tip = 700_000u64;
        let s = wallet_with_account(&dir, tip);
        {
            let conn = rusqlite::Connection::open(dir.path().join("data.db")).expect("side conn");
            conn.execute("UPDATE accounts SET recover_until_height = ?1", [tip])
                .expect("set recover_until");
        }
        let p = Progress::default();
        seed_progress_from_wallet(&p, &s).expect("seed");
        assert!(
            p.recovering(),
            "queued ranges below recover_until must seed recovering=true from open"
        );
    }

    #[test]
    fn fetch_stats_totals_default_is_zero() {
        let t = FetchStatsTotals::default();
        assert_eq!(t.blocks, 0);
        assert_eq!(t.bytes, 0);
    }

    #[test]
    fn scan_stats_totals_default_is_zero() {
        let t = ScanStatsTotals::default();
        assert_eq!(t.blocks, 0);
        assert_eq!(t.sapling_received, 0);
        assert_eq!(t.orchard_received, 0);
    }

    #[test]
    fn reorgs_recovered_accumulates() {
        let mut report = SyncReport::default();
        assert_eq!(report.reorgs_recovered, 0);
        report.reorgs_recovered += 1;
        assert_eq!(report.reorgs_recovered, 1);
        report.reorgs_recovered += 1;
        assert_eq!(report.reorgs_recovered, 2);
    }

    // NOTE: MAX_CONSECUTIVE_REORGS bounds are enforced at compile time via the
    // `const _: () = { assert!(...) }` block next to the constant definition.

    /// B3 (#1755): backoff grows 500 ms per consecutive recovery and caps at 3 s.
    #[test]
    fn reorg_backoff_grows_and_caps() {
        assert_eq!(reorg_backoff_ms(0), 0, "no recoveries -> no wait (unreachable in the arm)");
        assert_eq!(reorg_backoff_ms(1), 500, "first recovery waits 500 ms");
        assert_eq!(reorg_backoff_ms(2), 1_000);
        assert_eq!(reorg_backoff_ms(5), 2_500, "the cap budget's last step");
        assert_eq!(reorg_backoff_ms(6), 3_000, "capped at 3 s");
        assert_eq!(reorg_backoff_ms(u64::MAX), 3_000, "saturating mul + cap, no overflow");
    }

    #[test]
    fn report_accumulates_correctly() {
        let mut report = SyncReport::default();
        report.ranges_processed += 1;
        report.fetch.blocks += 10_000;
        report.fetch.bytes += 1_024 * 1_024;
        report.scan.blocks += 9_500;
        report.scan.sapling_received += 3;
        report.scan.orchard_received += 7;

        assert_eq!(report.ranges_processed, 1);
        assert_eq!(report.fetch.blocks, 10_000);
        assert_eq!(report.fetch.bytes, 1_024 * 1_024);
        assert_eq!(report.scan.blocks, 9_500);
        assert_eq!(report.scan.sapling_received, 3);
        assert_eq!(report.scan.orchard_received, 7);

        // Second range accumulation.
        report.ranges_processed += 1;
        report.fetch.blocks += 5_000;
        report.scan.blocks += 5_000;
        assert_eq!(report.ranges_processed, 2);
        assert_eq!(report.fetch.blocks, 15_000);
        assert_eq!(report.scan.blocks, 14_500);
    }

    /// F3: EnhanceStats fields in SyncReport accumulate correctly across multiple ranges.
    #[test]
    fn enhance_stats_accumulate_across_ranges() {
        let mut report = SyncReport::default();

        // Simulate per-range enhancement for range 1.
        report.enhance.requests += 5;
        report.enhance.txs_stored += 2;
        report.enhance.statuses_set += 1;
        report.enhance.skipped += 0;

        assert_eq!(report.enhance.requests, 5);
        assert_eq!(report.enhance.txs_stored, 2);
        assert_eq!(report.enhance.statuses_set, 1);
        assert_eq!(report.enhance.skipped, 0);

        // Simulate per-range enhancement for range 2.
        report.enhance.requests += 3;
        report.enhance.txs_stored += 1;
        report.enhance.statuses_set += 2;
        report.enhance.skipped += 1;

        assert_eq!(report.enhance.requests, 8, "requests must sum across ranges");
        assert_eq!(report.enhance.txs_stored, 3, "txs_stored must sum across ranges");
        assert_eq!(report.enhance.statuses_set, 3, "statuses_set must sum across ranges");
        assert_eq!(report.enhance.skipped, 1, "skipped must sum across ranges");
    }
}
