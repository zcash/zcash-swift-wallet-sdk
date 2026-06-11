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
    enhance::{EnhanceStats, run_enhancement},
    error::SlipstreamError,
    events::Progress,
    fetch::{FetchPlan, FetchStats, run_fetch},
    grpc,
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
) -> Result<SyncReport, SlipstreamError> {
    let mut report = SyncReport::default();
    // Counter for back-to-back ScanContinuity recoveries without a successful range.
    // Reset to 0 on any successful range completion. Capped at MAX_CONSECUTIVE_REORGS
    // to prevent infinite ping-pong (e.g. adversarial server or database corruption).
    let mut consecutive_reorgs: u64 = 0;
    // F1: track blocks scanned so far in this pass (local accumulator).
    // Used to compute the whole-pass denominator: scanned_so_far + sum(remaining ranges).
    let mut scanned_so_far_in_pass: u64 = 0;
    loop {
        let ranges = session.suggest_scan_ranges()?;
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
        let plan = FetchPlan::new(start, end, config.chunk_blocks, config.fetch_streams);
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
        let mut scan_client = grpc::connect(&config.endpoint).await?;

        let scan_started = std::time::Instant::now();
        let scan_result: Result<ScanStats, SlipstreamError> =
            scan_chunks(session, &mut scan_client, start, rx, progress.clone(), config, skipped_keys).await;
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
                let mut enhance_client = grpc::connect(&config.endpoint).await?;
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
        // F3 EnhanceStats default
        assert_eq!(r.enhance.requests, 0);
        assert_eq!(r.enhance.txs_stored, 0);
        assert_eq!(r.enhance.statuses_set, 0);
        assert_eq!(r.enhance.skipped, 0);
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
