//! Scan driver: consumes ordered chunks, runs upstream scan_cached_blocks once
//! per chunk (bounded memory: one commit per chunk), and hides the per-chunk
//! treestate RPC by prefetching the NEXT boundary state while the current
//! chunk scans (spike T2.3 outcome: ChainState must come from the server;
//! prefetch makes its latency invisible).

use std::sync::Arc;

use tracing::{debug, info};
use zcash_client_backend::data_api::chain::{error::Error as ChainError, scan_cached_blocks};
use zcash_protocol::consensus::BlockHeight;

#[cfg(any(test, feature = "darkside"))]
use zcash_client_backend::proto::service::TreeState;

use crate::{
    block_source::MemBlockSource,
    chunk::ChunkQueueReceiver,
    error::SlipstreamError,
    events::Progress,
    grpc::{self, LwdClient},
    wallet_session::WalletSession,
};

/// Convert a `scan_cached_blocks` error into a [`SlipstreamError`].
///
/// If the error is a continuity break (reorg), returns the structured
/// [`SlipstreamError::ScanContinuity`] variant so the scheduler can
/// recover via truncate + re-suggest. All other errors are stringified
/// into [`SlipstreamError::Wallet`].
///
/// Mirrors the discriminant from upstream sync.rs:404:
///   `Err(ChainError::Scan(err)) if err.is_continuity_error()`
///   (zcash_client_backend-0.22.0/src/sync.rs:404-413)
fn map_scan_error<WE: std::fmt::Display, BE: std::fmt::Display>(
    e: ChainError<WE, BE>,
) -> SlipstreamError {
    if let ChainError::Scan(ref scan_err) = e
        && scan_err.is_continuity_error()
    {
        // at_height() returns BlockHeight; u32::from(BlockHeight) is From<BlockHeight> for u32
        // confirmed at zcash_protocol-0.9.0/src/consensus.rs.
        let at = u32::from(scan_err.at_height());
        return SlipstreamError::ScanContinuity { at };
    }
    SlipstreamError::Wallet(format!("scan_cached_blocks: {e}"))
}

#[derive(Debug, Default, Clone)]
pub struct ScanStats {
    pub blocks: u64,
    pub chunks: u64,
    pub sapling_received: u64,
    pub orchard_received: u64,
}

/// Scans every chunk arriving on `rx` (they are ordered and continuity-verified
/// by the fetcher). `range_start` is the first height; the caller provides a
/// client for treestate prefetches.
/// Preconditions: range_start >= 1 (treestate is fetched at range_start - 1) and range_start equals the first chunk's start height.
///
/// `progress` — if `Some`, bumps `scanned_blocks` per chunk after a successful scan.
pub async fn scan_chunks(
    session: &mut WalletSession,
    client: &mut LwdClient,
    range_start: u64,
    mut rx: ChunkQueueReceiver,
    progress: Option<Arc<Progress>>,
) -> Result<ScanStats, SlipstreamError> {
    if range_start == 0 {
        return Err(SlipstreamError::Wallet("range_start must be >= 1".into()));
    }
    let mut stats = ScanStats::default();
    // State for the FIRST chunk: boundary just below the range.
    let mut next_state = grpc::get_tree_state(client, range_start - 1).await?;

    while let Some((chunk, permit)) = rx.recv().await {
        // Binding note 1: no expect() in non-test code — use structured error extraction.
        let (chunk_start, chunk_end) = match (chunk.start_height(), chunk.end_height()) {
            (Some(s), Some(e)) => (s, e),
            _ => return Err(SlipstreamError::Wallet("empty chunk".into())),
        };

        // Binding note 4: spawn the prefetch so it runs concurrently while scan_cached_blocks
        // executes below. LwdClient (tonic client) is cheaply cloneable.
        // The final prefetch's task runs to completion detached (JoinHandle dropped) — one extra gRPC call, acceptable.
        let prefetch = tokio::spawn({
            let mut c = client.clone();
            async move { grpc::get_tree_state(&mut c, chunk_end).await }
        });

        let from_state = next_state
            .to_chain_state()
            .map_err(|e| SlipstreamError::Wallet(format!("chain state: {e}")))?;
        let network = session.network;
        let len = chunk.blocks.len();

        let from_height = u32::try_from(chunk_start)
            .map_err(|_| SlipstreamError::Wallet(format!("height {chunk_start} exceeds u32")))?;

        // Binding note 3: wrap the synchronous scan_cached_blocks call in block_in_place
        // so it does not starve the tokio multi-thread runtime (SQLite + rayon decryption
        // are synchronous/CPU-bound; block_in_place is correct here because spawn_blocking
        // would require 'static, which &mut session does not satisfy; multi-thread runtime
        // is guaranteed by the CLI's #[tokio::main] with default flavor = multi_thread).
        // NOTE: block_in_place panics on a current_thread runtime — engine requires the multi-thread runtime (the CLI's Runtime::new()).
        let scan_result = tokio::task::block_in_place(|| {
            let source = MemBlockSource::new(&chunk);
            scan_cached_blocks(
                &network,
                &source,
                session.db_mut(),
                BlockHeight::from(from_height),
                &from_state,
                len,
            )
        });

        let summary = match scan_result {
            Ok(s) => s,
            Err(e) => {
                // On scan error, explicitly abort the in-flight prefetch task.
                prefetch.abort();
                return Err(map_scan_error(e));
            }
        };

        let scanned = u64::from(u32::from(summary.scanned_range().end))
            - u64::from(u32::from(summary.scanned_range().start));
        stats.blocks += scanned;
        stats.chunks += 1;
        // Binding note 2: accessor names confirmed against registry
        // zcash_client_backend-0.22.0/src/data_api/chain.rs:481,499 —
        // received_sapling_note_count() and received_orchard_note_count() exist exactly as named.
        stats.sapling_received += summary.received_sapling_note_count() as u64;
        stats.orchard_received += summary.received_orchard_note_count() as u64;
        // Bump the shared progress counter (poll-based; Relaxed ordering).
        if let Some(ref p) = progress {
            p.add_scanned(scanned);
        }
        debug!(chunk_start, chunk_end, len, "chunk scanned");

        drop(permit); // release byte budget only after the scan committed

        // Await the prefetch result; it was running concurrently with scan_cached_blocks above.
        next_state = prefetch
            .await
            .map_err(|e| SlipstreamError::Transport(format!("prefetch task: {e}")))??;
    }
    info!(blocks = stats.blocks, chunks = stats.chunks, sapling = stats.sapling_received, orchard = stats.orchard_received, "scan done");
    Ok(stats)
}

/// Like [`scan_chunks`] but uses a provided initial `TreeState` instead of fetching
/// one from the server. For subsequent chunk boundaries (prefetches), an empty tree state
/// at the chunk-end height is synthesized — this is correct for fabricated/empty blocks
/// (no shielded outputs → tree doesn't change between chunks).
///
/// **USE ONLY IN TESTS** against darkside servers that do not support GetTreeState
/// (e.g. lightwalletd v0.4.9). Production code uses [`scan_chunks`].
///
/// The correctness assertion this enables:
///   `scan_cached_blocks` will still decrypt and record shielded notes for blocks that
///   contain them — the provided initial state is used as the frontier before the range;
///   the scanner updates the frontier as it processes each block.
#[cfg(any(test, feature = "darkside"))]
pub async fn scan_chunks_from_treestate(
    session: &mut WalletSession,
    range_start: u64,
    initial_state: TreeState,
    mut rx: ChunkQueueReceiver,
) -> Result<ScanStats, SlipstreamError> {
    if range_start == 0 {
        return Err(SlipstreamError::Wallet("range_start must be >= 1".into()));
    }
    let mut stats = ScanStats::default();
    let mut next_state = initial_state;

    while let Some((chunk, permit)) = rx.recv().await {
        let (chunk_start, chunk_end) = match (chunk.start_height(), chunk.end_height()) {
            (Some(s), Some(e)) => (s, e),
            _ => return Err(SlipstreamError::Wallet("empty chunk".into())),
        };

        // Synthesize a tree state at `chunk_end` for the next iteration.
        // For darkside fabricated blocks, the tree doesn't change (no real shielded outputs
        // in empty blocks). The scan updates the frontier in-DB; we just need a valid height
        // to satisfy the from_state assertion.
        let synthesized_next = TreeState {
            network: next_state.network.clone(),
            height: chunk_end,
            hash: "0".repeat(64), // darkside block hash is irrelevant for tree state
            time: 0,
            sapling_tree: next_state.sapling_tree.clone(),
            orchard_tree: next_state.orchard_tree.clone(),
        };

        let from_state = next_state
            .to_chain_state()
            .map_err(|e| SlipstreamError::Wallet(format!("chain state: {e}")))?;
        let network = session.network;
        let len = chunk.blocks.len();

        let summary = {
            let source = MemBlockSource::new(&chunk);
            let from_height = u32::try_from(chunk_start)
                .map_err(|_| SlipstreamError::Wallet(format!("height {chunk_start} exceeds u32")))?;
            tokio::task::block_in_place(|| {
                scan_cached_blocks(
                    &network,
                    &source,
                    session.db_mut(),
                    BlockHeight::from(from_height),
                    &from_state,
                    len,
                )
            })
            .map_err(map_scan_error)?
        };

        let scanned = u64::from(u32::from(summary.scanned_range().end))
            - u64::from(u32::from(summary.scanned_range().start));
        stats.blocks += scanned;
        stats.chunks += 1;
        stats.sapling_received += summary.received_sapling_note_count() as u64;
        stats.orchard_received += summary.received_orchard_note_count() as u64;
        debug!(chunk_start, chunk_end, len, "chunk scanned (from_treestate)");

        drop(permit);
        next_state = synthesized_next;
    }
    info!(blocks = stats.blocks, chunks = stats.chunks, sapling = stats.sapling_received, orchard = stats.orchard_received, "scan_from_treestate done");
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_stats_default_is_zero() {
        let s = ScanStats::default();
        assert_eq!(s.blocks, 0);
        assert_eq!(s.chunks, 0);
        assert_eq!(s.sapling_received, 0);
        assert_eq!(s.orchard_received, 0);
    }
}
