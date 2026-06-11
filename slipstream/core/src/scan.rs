//! Scan driver: consumes ordered chunks, runs upstream scan_cached_blocks once
//! per chunk (bounded memory: one commit per chunk), and hides the per-chunk
//! treestate RPC by prefetching the NEXT boundary state while the current
//! chunk scans (spike T2.3 outcome: ChainState must come from the server;
//! prefetch makes its latency invisible).
//!
//! T5.2 — Adaptive sub-batching: within each chunk, `scan_cached_blocks` may be
//! called multiple times with a controller-sized window.  The controller grows the
//! batch towards the full chunk size on fast hardware (fast-path: one call per
//! chunk, identical to pre-T5.2 behaviour) and shrinks it towards MIN_BATCH on
//! slow hardware so each commit surfaces progress every ~TARGET_BATCH_MS ms.

use std::sync::Arc;
use std::time::Instant;

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

// ── Adaptive controller constants ──────────────────────────────────────────────

/// Target wall-clock milliseconds per scan_cached_blocks call.  The controller
/// adjusts the batch length to keep actual scan time near this value.
const TARGET_BATCH_MS: u64 = 3_000;

/// Minimum number of blocks in a single scan_cached_blocks call.  Prevents the
/// controller from issuing tiny batches under extreme slowness.
const MIN_BATCH: u32 = 1_000;

// ── Adaptive controller ────────────────────────────────────────────────────────

/// Pure time-feedback controller: given the previous batch length and its
/// elapsed time, return the recommended length for the NEXT batch.
///
/// Proportional rule: `prev_len * target_ms / prev_elapsed_ms`, then clamped to
/// `[min, max]`.  The `max` parameter should be set to the remaining blocks in
/// the current chunk so the controller never exceeds one chunk.
///
/// Zero-elapsed guard: if `prev_elapsed_ms == 0` (sub-millisecond scan),
/// `max` is returned directly — we have no signal to shrink, so stay large.
pub fn next_batch_len(
    prev_len: u32,
    prev_elapsed_ms: u64,
    target_ms: u64,
    min: u32,
    max: u32,
) -> u32 {
    if prev_elapsed_ms == 0 {
        return max;
    }
    let raw = (prev_len as u64).saturating_mul(target_ms) / prev_elapsed_ms;
    raw.clamp(min as u64, max as u64) as u32
}

// ── Scan-error mapper ──────────────────────────────────────────────────────────

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

// ── Stats ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct ScanStats {
    pub blocks: u64,
    pub chunks: u64,
    pub sapling_received: u64,
    pub orchard_received: u64,
}

// ── Production scan driver ─────────────────────────────────────────────────────

/// Scans every chunk arriving on `rx` (they are ordered and continuity-verified
/// by the fetcher). `range_start` is the first height; the caller provides a
/// client for treestate prefetches.
/// Preconditions: range_start >= 1 (treestate is fetched at range_start - 1) and
/// range_start equals the first chunk's start height.
///
/// `progress` — if `Some`, bumps `scanned_blocks` per chunk after a successful scan.
///
/// ## Adaptive sub-batching (T5.2)
///
/// `batch_len` is maintained across the entire call and is initialized to the
/// first chunk's full length (fast-path: on fast hardware every batch finishes
/// under TARGET_BATCH_MS, so batch_len grows to / stays at the chunk size and the
/// loop executes exactly once per chunk — identical to pre-T5.2 behaviour).
///
/// On slow hardware the controller shrinks `batch_len`, splitting each chunk into
/// multiple scan_cached_blocks calls so the DB commits (and progress bumps) every
/// ~3 s regardless of chunk size.
///
/// ### Treestate threading at intra-chunk boundaries
///
/// scan_cached_blocks requires `from_state.height + 1 == from_height` (upstream
/// assertion).  For intra-chunk sub-batch N+1, `from_state` must be the *server*
/// treestate at the boundary height `H` (last block of sub-batch N).  We generalise
/// the existing chunk-boundary prefetch: for every sub-batch we spawn a prefetch
/// for its *end* height *before* running the blocking scan; we await the prefetch
/// result after the scan completes and use it as `from_state` for the next
/// sub-batch.  The chunk-boundary case is the degenerate case where one sub-batch
/// equals the whole chunk.
///
/// RPC cost: ~1 GetTreeState per ~TARGET_BATCH_MS on slow devices, fully hidden
/// behind the blocking scan; zero extra RPCs on fast devices (fast-path = 1 call
/// per chunk, same as before T5.2).
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

    // Adaptive controller state: batch_len is initialised lazily from the first
    // chunk's full length and carried across chunks.  Initialising to 0 here is a
    // sentinel; it is replaced before the first scan_cached_blocks call.
    let mut batch_len: u32 = 0;

    while let Some((chunk, permit)) = rx.recv().await {
        // Binding note 1: no expect() in non-test code — use structured error extraction.
        let (chunk_start, chunk_end) = match (chunk.start_height(), chunk.end_height()) {
            (Some(s), Some(e)) => (s, e),
            _ => return Err(SlipstreamError::Wallet("empty chunk".into())),
        };

        let chunk_len = chunk.blocks.len(); // total blocks in this chunk

        // Initialise batch_len from the first chunk's full length (or carry the
        // controller's last value from the previous chunk).  The "batch_len == 0"
        // sentinel is set above and only true for the very first chunk.
        if batch_len == 0 {
            batch_len = chunk_len.min(u32::MAX as usize) as u32;
        }

        let network = session.network;

        // ── Sub-batch loop ────────────────────────────────────────────────────
        // Iterate over the chunk's blocks in controller-sized windows.
        // `sub_start` advances by `current_batch_len` each iteration.
        let mut sub_start = chunk_start; // first height of current sub-batch
        let mut chunk_scanned_blocks: u64 = 0;
        let mut chunk_sapling: u64 = 0;
        let mut chunk_orchard: u64 = 0;

        loop {
            // How many blocks remain in this chunk from sub_start?
            let remaining = (chunk_end + 1).saturating_sub(sub_start) as usize;
            if remaining == 0 {
                break;
            }

            // Cap current_batch_len to remaining so we never overshoot the chunk.
            let current_batch_len = (batch_len as usize).min(remaining);
            let sub_end = sub_start + current_batch_len as u64 - 1; // inclusive

            // ── Prefetch treestate for sub_end ────────────────────────────────
            // Spawn concurrently so it races the blocking scan below.
            // This is the same client.clone() pattern as the pre-T5.2 chunk-boundary
            // prefetch; the chunk-boundary case (current_batch_len == remaining) is
            // the degenerate single-batch path.
            //
            // The final sub-batch's prefetch task runs to completion detached
            // (JoinHandle dropped) — one extra gRPC call per chunk boundary,
            // acceptable (same as before T5.2).
            let prefetch = tokio::spawn({
                let mut c = client.clone();
                async move { grpc::get_tree_state(&mut c, sub_end).await }
            });

            let from_state = next_state
                .to_chain_state()
                .map_err(|e| SlipstreamError::Wallet(format!("chain state: {e}")))?;

            let from_height = u32::try_from(sub_start)
                .map_err(|_| SlipstreamError::Wallet(format!("height {sub_start} exceeds u32")))?;

            // Binding note 3: block_in_place for the synchronous scan call.
            // NOTE: the `from_state` passed to scan_cached_blocks must satisfy
            //   from_state.height() + 1 == from_height
            // This holds because:
            //   - For the first sub-batch of the first chunk, next_state was fetched
            //     at (range_start - 1), and sub_start == chunk_start == range_start.
            //   - For every subsequent sub-batch, next_state was fetched at sub_end
            //     of the previous sub-batch, and the new sub_start == prev sub_end + 1.
            //   - For the first sub-batch of subsequent chunks (chunk-boundary case),
            //     next_state was fetched at the previous chunk's end height, and
            //     sub_start == chunk_start == prev_chunk_end + 1.
            let batch_start_time = Instant::now();
            let scan_result = tokio::task::block_in_place(|| {
                let source = MemBlockSource::new(&chunk);
                scan_cached_blocks(
                    &network,
                    &source,
                    session.db_mut(),
                    BlockHeight::from(from_height),
                    &from_state,
                    current_batch_len,
                )
            });
            let elapsed_ms = batch_start_time.elapsed().as_millis() as u64;

            let summary = match scan_result {
                Ok(s) => s,
                Err(e) => {
                    prefetch.abort();
                    return Err(map_scan_error(e));
                }
            };

            let scanned = u64::from(u32::from(summary.scanned_range().end))
                - u64::from(u32::from(summary.scanned_range().start));
            chunk_scanned_blocks += scanned;
            chunk_sapling += summary.received_sapling_note_count() as u64;
            chunk_orchard += summary.received_orchard_note_count() as u64;

            debug!(
                batch_start = sub_start,
                batch_end = sub_end,
                batch_len = current_batch_len,
                elapsed_ms,
                "sub-batch scanned"
            );

            // Await the prefetch; it ran concurrently with the blocking scan.
            let fetched = prefetch
                .await
                .map_err(|e| SlipstreamError::Transport(format!("prefetch task: {e}")))??;

            // Controller: compute next batch length from this batch's timing.
            // `max` is capped to chunk_len so batch_len never exceeds one chunk.
            batch_len = next_batch_len(
                current_batch_len as u32,
                elapsed_ms,
                TARGET_BATCH_MS,
                MIN_BATCH,
                chunk_len.min(u32::MAX as usize) as u32,
            );

            // Advance for the next sub-batch.
            next_state = fetched;
            sub_start = sub_end + 1;
        }
        // ── End sub-batch loop ────────────────────────────────────────────────

        // Accumulate chunk totals into global stats.
        stats.blocks += chunk_scanned_blocks;
        stats.chunks += 1;
        stats.sapling_received += chunk_sapling;
        stats.orchard_received += chunk_orchard;

        // Bump the shared progress counter (poll-based; Relaxed ordering).
        if let Some(ref p) = progress {
            p.add_scanned(chunk_scanned_blocks);
        }

        // T5.1 per-chunk info log (kept at chunk granularity — would spam on fast devices
        // if emitted per sub-batch at info level; sub-batch detail is at debug level above).
        let len = chunk.blocks.len();
        info!(chunk_start, chunk_end, len, outputs = chunk.outputs, "chunk scanned");

        drop(permit); // release byte budget only after the chunk's last sub-batch committed
    }
    info!(
        blocks = stats.blocks,
        chunks = stats.chunks,
        sapling = stats.sapling_received,
        orchard = stats.orchard_received,
        "scan done"
    );
    Ok(stats)
}

// ── Darkside / test scan driver ────────────────────────────────────────────────

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
///
/// ## No sub-batching here (T5.2)
///
/// Synthesized tree states cannot be split mid-chunk: the synthesized state at
/// chunk_end holds a frozen copy of the tree that was valid *before* this chunk was
/// scanned.  Splitting into sub-batches would require a real server treestate at
/// each intra-chunk boundary, which is unavailable in darkside/test contexts.
/// Sub-batching is therefore applied only in the production [`scan_chunks`] path.
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

        let scan_start = Instant::now();
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
        let elapsed_ms = scan_start.elapsed().as_millis() as u64;

        let scanned = u64::from(u32::from(summary.scanned_range().end))
            - u64::from(u32::from(summary.scanned_range().start));
        stats.blocks += scanned;
        stats.chunks += 1;
        stats.sapling_received += summary.received_sapling_note_count() as u64;
        stats.orchard_received += summary.received_orchard_note_count() as u64;
        info!(chunk_start, chunk_end, len, outputs = chunk.outputs, elapsed_ms, "chunk scanned");

        drop(permit);
        next_state = synthesized_next;
    }
    info!(blocks = stats.blocks, chunks = stats.chunks, sapling = stats.sapling_received, orchard = stats.orchard_received, "scan_from_treestate done");
    Ok(stats)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

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

    // ── Controller unit tests (T5.2) ──────────────────────────────────────────

    /// Fast device: 1000ms for 5000 blocks → wants 5000 * 3000/1000 = 15000; clamped to max=10000.
    #[test]
    fn controller_clamps_to_max() {
        let result = next_batch_len(5_000, 1_000, 3_000, 1_000, 10_000);
        assert_eq!(result, 10_000);
    }

    /// Fast device (growth within max): 1000ms for 2000 blocks → wants 2000*3000/1000 = 6000; max=10000, so 6000.
    #[test]
    fn controller_grows_on_fast_device() {
        let result = next_batch_len(2_000, 1_000, 3_000, 1_000, 10_000);
        assert_eq!(result, 6_000);
    }

    /// Slow device: 9000ms for 10000 blocks → wants 10000*3000/9000 = 3333; min=1000, max=10000 → 3333.
    #[test]
    fn controller_shrinks_on_slow_device() {
        let result = next_batch_len(10_000, 9_000, 3_000, 1_000, 10_000);
        assert_eq!(result, 3_333);
    }

    /// Very slow device: 60000ms for 1000 blocks → wants 1000*3000/60000 = 50; clamped to min=1000.
    #[test]
    fn controller_clamps_to_min() {
        let result = next_batch_len(1_000, 60_000, 3_000, 1_000, 10_000);
        assert_eq!(result, 1_000);
    }

    /// Zero-elapsed guard: elapsed == 0 → return max (no shrink signal).
    #[test]
    fn controller_zero_elapsed_returns_max() {
        let result = next_batch_len(5_000, 0, 3_000, 1_000, 8_000);
        assert_eq!(result, 8_000);
    }

    /// On-target: 3000ms for 5000 blocks → wants 5000 (unchanged).
    #[test]
    fn controller_stable_when_on_target() {
        let result = next_batch_len(5_000, 3_000, 3_000, 1_000, 10_000);
        assert_eq!(result, 5_000);
    }
}
