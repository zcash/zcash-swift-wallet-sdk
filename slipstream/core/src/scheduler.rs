//! Scheduler v0: drive the wallet's own scan-queue (decision D3 — the coverage
//! ledger IS data.db's suggested ranges). For each suggested range, run the
//! fetch∥scan pipeline; re-suggest after each range until the queue is empty.
//! Priority handling (Verify-first) comes for free: suggest_scan_ranges returns
//! Verify ranges first by upstream contract.

use tracing::{info, warn};

use crate::{
    chunk::chunk_queue,
    config::EngineConfig,
    error::SlipstreamError,
    fetch::{FetchPlan, FetchStats, run_fetch},
    grpc,
    scan::{ScanStats, scan_chunks},
    wallet_session::WalletSession,
};

#[derive(Debug, Default, Clone)]
pub struct SyncReport {
    pub ranges_processed: u64,
    pub fetch: FetchStatsTotals,
    pub scan: ScanStatsTotals,
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
pub async fn run_to_completion(
    config: &EngineConfig,
    session: &mut WalletSession,
) -> Result<SyncReport, SlipstreamError> {
    let mut report = SyncReport::default();
    loop {
        let ranges = session.suggest_scan_ranges()?;
        let Some(range) = ranges.first() else {
            info!("scan queue empty — sync complete");
            return Ok(report);
        };

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

        let (tx, rx) = chunk_queue(config.memory_budget_bytes);
        let plan = FetchPlan::new(start, end, config.chunk_blocks, config.fetch_streams);
        let endpoint = config.endpoint.clone();

        // Spawn the fetch task so it runs concurrently with scan_chunks below.
        // The tx is moved into the task; when the task finishes, tx is dropped, which
        // closes the channel and causes scan_chunks's rx.recv() loop to terminate.
        let fetch_task = tokio::spawn(async move { run_fetch(&endpoint, plan, tx).await });

        // scan_chunks runs in the current task using a SEPARATE grpc client so it
        // does not contend with the fetch workers' connections.
        let mut scan_client = grpc::connect(&config.endpoint).await?;

        // TODO: [#1755] reorg/continuity recovery — port upstream sync.rs scan_blocks error arm
        let scan_result: Result<ScanStats, SlipstreamError> =
            scan_chunks(session, &mut scan_client, start, rx).await;

        // Error-precedence rationale (deviation from plan's draft `??` which loses nuance):
        // If scan_chunks fails first, dropping rx causes the fetch task to see a
        // send-error and finish with Stopped or a transport error — both are secondary.
        // We ALWAYS await the JoinHandle so the task is not left running in the background,
        // but if scan already failed we prefer returning the scan error; the fetch's secondary
        // error is downgraded to a tracing::warn.
        let fetch_result: Result<FetchStats, SlipstreamError> = fetch_task
            .await
            .map_err(|e| SlipstreamError::Transport(format!("fetch task panicked: {e}")))?;

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

        report.ranges_processed += 1;
        report.fetch.blocks += fetch_stats.blocks;
        report.fetch.bytes += fetch_stats.bytes;
        report.scan.blocks += scan_stats.blocks;
        report.scan.sapling_received += scan_stats.sapling_received;
        report.scan.orchard_received += scan_stats.orchard_received;
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
}
