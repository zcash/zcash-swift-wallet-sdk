//! Scan driver: consumes ordered chunks, runs upstream scan_cached_blocks once
//! per chunk (bounded memory: one commit per chunk), and hides the per-chunk
//! treestate RPC by prefetching the NEXT boundary state while the current
//! chunk scans (spike T2.3 outcome: ChainState must come from the server;
//! prefetch makes its latency invisible).
//!
//! T5.2 — Adaptive sub-batching (opt-in as of T5.5): pass
//! `batch_target_ms = Some(ms)` to split each chunk into time-targeted
//! sub-batches (~ms each).  Default `None` = one scan call per chunk
//! (pre-T5.2 behaviour; fastest on all hardware).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use tracing::{debug, info, warn};
use zcash_client_backend::data_api::chain::{error::Error as ChainError, scan_cached_blocks};
use zcash_protocol::consensus::BlockHeight;

#[cfg(any(test, feature = "darkside"))]
use zcash_client_backend::proto::service::TreeState;

use crate::{
    block_source::MemBlockSource,
    chunk::ChunkQueueReceiver,
    config::{Endpoint, EngineConfig},
    enhance::run_enhancement,
    error::SlipstreamError,
    events::Progress,
    grpc::{self, LwdClient},
    wallet_session::WalletSession,
};

// ── Adaptive controller constants ──────────────────────────────────────────────


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

// ── Interleave cadence helper ──────────────────────────────────────────────────

/// True when an interleaved enhancement run should fire after `chunks_done`
/// completed chunks with cadence `every` (T6.1). Never fires before the first
/// chunk completes.
pub fn should_interleave_enhancement(chunks_done: u64, every: u32) -> bool {
    every > 0 && chunks_done > 0 && chunks_done.is_multiple_of(u64::from(every))
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
    /// Stats from interleaved (per-K-chunk) enhancement runs (T6.1).
    pub interleaved_enhance: crate::enhance::EnhanceStats,
    /// Wall-clock spent in interleaved enhancement (excluded from scan-stage time).
    pub interleaved_enhance_elapsed: std::time::Duration,
    /// T6.9 write-behind: total time the scan loop was BLOCKED awaiting a
    /// previous deferred commit (Σ persist_wait; 0 ≈ perfect overlap).
    pub persist_wait: std::time::Duration,
    /// T6.9 write-behind: total wall time of the deferred commits themselves
    /// (Σ persist_busy, measured inside the persist closures). The overlap won
    /// is `persist_busy - persist_wait` (clamped at 0).
    pub persist_busy: std::time::Duration,
}

// ── T6.9 write-behind loop state ───────────────────────────────────────────────

/// Scan-side write-behind state: the pending-aware facade (virtualized reads +
/// stash) and the persist lane (second Db connection + per-range tree state +
/// the single in-flight deferred commit). See persist.rs T6.9 section.
struct WriteBehind {
    facade: crate::persist::WriteBehindFacade,
    lane: crate::persist::PersistLane,
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
    rx: ChunkQueueReceiver,
    progress: Option<Arc<Progress>>,
    config: &EngineConfig,
    skipped_keys: &mut HashSet<String>,
) -> Result<ScanStats, SlipstreamError> {
    if range_start == 0 {
        return Err(SlipstreamError::Wallet("range_start must be >= 1".into()));
    }

    // ── T6.9 write-behind setup ───────────────────────────────────────────────
    // Seed the pending-aware facade from the committed DB (no-pending barrier:
    // nothing is stashed or in flight yet) and open the persist lane's own
    // connection to the wallet file. `None` = today's serialized path.
    let mut wb: Option<WriteBehind> = if config.write_behind {
        let facade = crate::persist::WriteBehindFacade::seed(&*session.db_mut(), range_start)
            .map_err(|e| SlipstreamError::Wallet(format!("write-behind seed: {e}")))?;
        let lane = crate::persist::PersistLane::open(&config.wallet_db_path, config.network)?;
        Some(WriteBehind { facade, lane })
    } else {
        None
    };

    let result =
        scan_chunks_inner(session, client, range_start, rx, progress, config, skipped_keys, &mut wb)
            .await;

    // ── T6.9 full barrier (range end AND every error exit) ───────────────────
    // Drain the in-flight deferred commit before anything else may touch the
    // DB (reorg truncate, per-range enhancement, suggest, summary). Dropping
    // the JoinHandle would NOT stop the blocking commit — it must be awaited.
    // Precedence on double failure: the persist error wins (a failed commit is
    // a DB-integrity signal; a ScanContinuity reorg is retried next pass).
    if let Some(mut wb) = wb {
        if wb.facade.take_stash().is_some() {
            // A stashed-but-never-submitted unit only exists on error exits
            // between scan and submit; dropping it is safe (its range is still
            // marked unscanned — re-suggested next pass).
            warn!("write-behind: dropping an unsubmitted pending unit on error exit");
        }
        let drain_result = wb.lane.drain().await;
        return match (result, drain_result) {
            (Ok(mut stats), Ok(())) => {
                stats.persist_wait = wb.lane.total_wait();
                stats.persist_busy = wb.lane.total_busy();
                info!(
                    blocks = stats.blocks,
                    chunks = stats.chunks,
                    sapling = stats.sapling_received,
                    orchard = stats.orchard_received,
                    persist_wait_ms = stats.persist_wait.as_millis() as u64,
                    persist_busy_ms = stats.persist_busy.as_millis() as u64,
                    "scan done (write-behind drained)"
                );
                Ok(stats)
            }
            (Err(scan_err), Ok(())) => Err(scan_err),
            (scan_outcome, Err(persist_err)) => {
                if let Err(scan_err) = scan_outcome {
                    warn!(%scan_err, "scan error superseded by persist failure (persist precedence)");
                }
                Err(persist_err)
            }
        };
    }
    result
}

/// The scan loop body. Extracted so `?`-style early returns land at the
/// write-behind barrier in [`scan_chunks`] instead of skipping it.
#[allow(clippy::too_many_arguments)] // internal seam of scan_chunks; bundling would obscure the borrow structure
async fn scan_chunks_inner(
    session: &mut WalletSession,
    client: &mut LwdClient,
    range_start: u64,
    mut rx: ChunkQueueReceiver,
    progress: Option<Arc<Progress>>,
    config: &EngineConfig,
    skipped_keys: &mut HashSet<String>,
    wb: &mut Option<WriteBehind>,
) -> Result<ScanStats, SlipstreamError> {
    let mut sparse_state = crate::persist::SparseTreeState::default();
    // Read config fields once.
    let batch_target_ms = config.scan_batch_target_ms;
    let network = config.network;
    // Clone endpoint once for use in retry-capable prefetch spawns (T6.8-H2).
    let endpoint: Endpoint = config.endpoint.clone();

    let mut stats = ScanStats::default();
    // State for the FIRST chunk: seed treestate at (range_start - 1).
    // T6.8-H2: uses retry_get_tree_state (up to 3 attempts, reconnect on retry)
    // instead of bare get_tree_state — a single 30s server stall was FATAL here.
    let mut next_state =
        grpc::retry_get_tree_state(&endpoint, range_start - 1, "initial seed").await?;

    // batch_len: for the adaptive path (batch_target_ms = Some), this is carried
    // across chunks and updated by the controller.  For the None path it is set to
    // chunk_len before every chunk and never updated — the loop executes exactly once
    // per chunk (degenerate single-iteration).
    let mut batch_len: u32 = 0;

    while let Some((chunk, permit)) = rx.recv().await {
        // Binding note 1: no expect() in non-test code — use structured error extraction.
        let (chunk_start, chunk_end) = match (chunk.start_height(), chunk.end_height()) {
            (Some(s), Some(e)) => (s, e),
            _ => return Err(SlipstreamError::Wallet("empty chunk".into())),
        };

        let chunk_len = chunk.blocks.len(); // total blocks in this chunk

        // Initialise or reset batch_len.
        // None path: always reset to chunk_len (ensures the loop executes exactly once
        // per chunk — after one iteration sub_start == chunk_end + 1, remaining == 0,
        // loop exits without the controller running).
        // Some path: sentinel (== 0) → init from first chunk's full length; thereafter
        // carry the controller's last value across chunks.
        if batch_target_ms.is_none() || batch_len == 0 {
            batch_len = chunk_len.min(u32::MAX as usize) as u32;
        }

        // ── Sub-batch loop ────────────────────────────────────────────────────
        // Iterate over the chunk's blocks in controller-sized windows.
        // `sub_start` advances by `current_batch_len` each iteration.
        let mut sub_start = chunk_start; // first height of current sub-batch
        let mut chunk_scanned_blocks: u64 = 0;
        let mut chunk_sapling: u64 = 0;
        let mut chunk_orchard: u64 = 0;
        let mut chunk_elapsed_ms: u64 = 0;
        // T6.9: time this chunk's submits spent blocked on previous commits.
        let mut chunk_persist_wait_ms: u64 = 0;

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
            // T6.8-H2: the prefetch now uses retry_get_tree_state INSIDE the spawned
            // task so the fetch/scan overlap is preserved. The retry reconnects on each
            // attempt — a wedged channel is abandoned rather than reused. Up to 3 total
            // attempts: backoff 1s then 3s between attempts.
            //
            // On scan failure, prefetch.abort() is called before returning. The to_chain_state() and height-overflow error paths return without aborting — the spawned task completes detached, which is harmless.
            let prefetch = tokio::spawn({
                let ep = endpoint.clone();
                async move { grpc::retry_get_tree_state(&ep, sub_end, "chunk-boundary prefetch").await }
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
                if let Some(wb) = wb.as_mut() {
                    // T6.9 write-behind: virtualized reads + stash (no DB work
                    // on this task; the commit is deferred to the persist lane).
                    scan_cached_blocks(
                        &network,
                        &source,
                        &mut wb.facade,
                        BlockHeight::from(from_height),
                        &from_state,
                        current_batch_len,
                    )
                } else if config.sparse_persistence {
                    let mut facade = crate::persist::SparseFacade {
                        inner: session.db_mut(),
                        sparse: &mut sparse_state,
                    };
                    scan_cached_blocks(
                        &network,
                        &source,
                        &mut facade,
                        BlockHeight::from(from_height),
                        &from_state,
                        current_batch_len,
                    )
                } else {
                    scan_cached_blocks(
                        &network,
                        &source,
                        session.db_mut(),
                        BlockHeight::from(from_height),
                        &from_state,
                        current_batch_len,
                    )
                }
            });
            let elapsed_ms = batch_start_time.elapsed().as_millis() as u64;

            let summary = match scan_result {
                Ok(s) => s,
                Err(e) => {
                    prefetch.abort();
                    return Err(map_scan_error(e));
                }
            };

            // ── T6.9 submit the deferred commit (depth-1) ─────────────────────
            // Awaits the PREVIOUS unit first (error propagates here — the range
            // aborts before another unit is ever submitted), then spawns this
            // unit's commit so it overlaps the prefetch await + next recv +
            // next decrypt. The wait delta is this chunk's overlap-quality cost.
            if let Some(wb) = wb.as_mut()
                && let Some(pending) = wb.facade.take_stash()
            {
                let wait_before = wb.lane.total_wait();
                if let Err(e) = wb.lane.submit(pending).await {
                    prefetch.abort();
                    return Err(e);
                }
                chunk_persist_wait_ms +=
                    (wb.lane.total_wait() - wait_before).as_millis() as u64;
            }

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

            chunk_elapsed_ms += elapsed_ms;

            // Await the prefetch; it ran concurrently with the blocking scan.
            let fetched = prefetch
                .await
                .map_err(|e| SlipstreamError::Transport(format!("prefetch task: {e}")))??;

            // Controller: only consulted when sub-batching is enabled (batch_target_ms = Some).
            // None path: batch_len stays at chunk_len; the loop exits after this iteration
            // (remaining will be 0 after sub_start advances to chunk_end + 1).
            if let Some(target_ms) = batch_target_ms {
                batch_len = next_batch_len(
                    current_batch_len as u32,
                    elapsed_ms,
                    target_ms,
                    MIN_BATCH,
                    chunk_len.min(u32::MAX as usize) as u32,
                );
            }

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
        // T6.9: persist_wait_ms = time this chunk's submits blocked on previous deferred
        // commits (write-behind only; 0 = perfect overlap, also 0 with the flag off).
        let len = chunk.blocks.len();
        info!(
            chunk_start,
            chunk_end,
            len,
            outputs = chunk.outputs,
            chunk_elapsed_ms,
            persist_wait_ms = chunk_persist_wait_ms,
            "chunk scanned"
        );

        // T6.9 note: with write-behind the last sub-batch is SUBMITTED (not yet
        // committed) here; the permit guards the raw chunk bytes, which are
        // dropped with this loop iteration either way — the pending unit holds
        // only the decrypted ScannedBlocks (commitments + wallet data), bounded
        // at depth 1.
        drop(permit); // release byte budget after the chunk's last sub-batch was handed off

        // T6.1 — interleaved enhancement every K chunks. Non-fatal by design:
        // it is an optimization (progressive tx visibility); the per-range and
        // final post-loop runs are the correctness backstops. from_state
        // threading is untouched (next_state is not read or written here).
        if should_interleave_enhancement(stats.chunks, config.enhance_every_chunks) {
            // T6.9 full barrier: enhancement reads AND writes the wallet DB —
            // it must never see a half-committed range tail, and it must not
            // run concurrently with a deferred commit (single-writer rule).
            if let Some(wb) = wb.as_mut() {
                wb.lane.drain().await?;
            }
            let started = Instant::now();
            let mut enhance_client = client.clone();
            match run_enhancement(session, &mut enhance_client, network, progress.clone(), skipped_keys).await {
                Ok(es) => {
                    stats.interleaved_enhance.requests += es.requests;
                    stats.interleaved_enhance.txs_stored += es.txs_stored;
                    stats.interleaved_enhance.statuses_set += es.statuses_set;
                    stats.interleaved_enhance.skipped += es.skipped;
                }
                Err(err) => {
                    warn!(%err, chunk_end, "interleaved enhancement failed — continuing scan");
                }
            }
            stats.interleaved_enhance_elapsed += started.elapsed();
            // T6.9: enhancement may have stored fully-decrypted transactions
            // (new received notes / spends outside put_blocks) — re-seed the
            // facade's running nullifier views from the now-complete DB.
            // Unconditional (the non-fatal error arm may have partially written).
            if let Some(wb) = wb.as_mut() {
                wb.facade
                    .reseed_nullifiers(&*session.db_mut())
                    .map_err(|e| SlipstreamError::Wallet(format!("write-behind reseed: {e}")))?;
            }
        }
    }
    if wb.is_none() {
        // Write-behind logs its "scan done" in scan_chunks AFTER the drain
        // barrier (so the line means "fully committed", not "fully decrypted").
        info!(
            blocks = stats.blocks,
            chunks = stats.chunks,
            sapling = stats.sapling_received,
            orchard = stats.orchard_received,
            "scan done"
        );
    }
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
///
/// `sparse` — when `true`, use the `SparseFacade` / in-memory shardtree path
/// (exactly as `scan_chunks` does); one `SparseTreeState` is created for the
/// whole call, matching the one-per-range contract. Added at T6.4 so the
/// darkside oracle test can exercise the same sparse code-path as production.
///
/// `write_behind` — when `true` (requires `sparse`), use the T6.9 depth-1
/// write-behind pipeline exactly as production `scan_chunks` does: pending-aware
/// `WriteBehindFacade` + `PersistLane` (second connection to the session's DB
/// file), submit-after-scan, full drain barrier at exit. Added at T6.9 so the
/// darkside variants can exercise the write-behind path against real fixtures.
#[cfg(any(test, feature = "darkside"))]
pub async fn scan_chunks_from_treestate(
    session: &mut WalletSession,
    range_start: u64,
    initial_state: TreeState,
    rx: ChunkQueueReceiver,
    sparse: bool,
    write_behind: bool,
) -> Result<ScanStats, SlipstreamError> {
    if range_start == 0 {
        return Err(SlipstreamError::Wallet("range_start must be >= 1".into()));
    }
    if write_behind && !sparse {
        return Err(SlipstreamError::Wallet(
            "write_behind requires sparse (mirrors EngineConfig::validate)".into(),
        ));
    }
    let mut wb: Option<WriteBehind> = if write_behind {
        let facade = crate::persist::WriteBehindFacade::seed(&*session.db_mut(), range_start)
            .map_err(|e| SlipstreamError::Wallet(format!("write-behind seed: {e}")))?;
        let lane = crate::persist::PersistLane::open(session.db_path(), session.network)?;
        Some(WriteBehind { facade, lane })
    } else {
        None
    };

    let result =
        scan_chunks_from_treestate_inner(session, initial_state, rx, sparse, &mut wb).await;

    // T6.9 full barrier — mirror of scan_chunks (persist error precedence).
    if let Some(mut wb) = wb {
        if wb.facade.take_stash().is_some() {
            warn!("write-behind (treestate driver): dropping an unsubmitted pending unit on error exit");
        }
        let drain_result = wb.lane.drain().await;
        return match (result, drain_result) {
            (Ok(mut stats), Ok(())) => {
                stats.persist_wait = wb.lane.total_wait();
                stats.persist_busy = wb.lane.total_busy();
                Ok(stats)
            }
            (Err(scan_err), Ok(())) => Err(scan_err),
            (scan_outcome, Err(persist_err)) => {
                if let Err(scan_err) = scan_outcome {
                    warn!(%scan_err, "scan error superseded by persist failure (persist precedence)");
                }
                Err(persist_err)
            }
        };
    }
    result
}

/// Loop body of [`scan_chunks_from_treestate`] — extracted so early returns
/// land at the write-behind barrier instead of skipping it.
#[cfg(any(test, feature = "darkside"))]
async fn scan_chunks_from_treestate_inner(
    session: &mut WalletSession,
    initial_state: TreeState,
    mut rx: ChunkQueueReceiver,
    sparse: bool,
    wb: &mut Option<WriteBehind>,
) -> Result<ScanStats, SlipstreamError> {
    let mut sparse_state = crate::persist::SparseTreeState::default();
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

        let scan_start_t = Instant::now();
        let summary = {
            let source = MemBlockSource::new(&chunk);
            let from_height = u32::try_from(chunk_start)
                .map_err(|_| SlipstreamError::Wallet(format!("height {chunk_start} exceeds u32")))?;
            tokio::task::block_in_place(|| {
                if let Some(wb) = wb.as_mut() {
                    // T6.9 write-behind: virtualized reads + stash.
                    scan_cached_blocks(
                        &network,
                        &source,
                        &mut wb.facade,
                        BlockHeight::from(from_height),
                        &from_state,
                        len,
                    )
                } else if sparse {
                    let mut facade = crate::persist::SparseFacade {
                        inner: session.db_mut(),
                        sparse: &mut sparse_state,
                    };
                    scan_cached_blocks(
                        &network,
                        &source,
                        &mut facade,
                        BlockHeight::from(from_height),
                        &from_state,
                        len,
                    )
                } else {
                    scan_cached_blocks(
                        &network,
                        &source,
                        session.db_mut(),
                        BlockHeight::from(from_height),
                        &from_state,
                        len,
                    )
                }
            })
            .map_err(map_scan_error)?
        };
        let elapsed_ms = scan_start_t.elapsed().as_millis() as u64;

        // T6.9 submit the deferred commit (depth-1; awaits the previous unit
        // first — mirror of the production scan_chunks pipeline).
        if let Some(wb) = wb.as_mut()
            && let Some(pending) = wb.facade.take_stash()
        {
            wb.lane.submit(pending).await?;
        }

        let scanned = u64::from(u32::from(summary.scanned_range().end))
            - u64::from(u32::from(summary.scanned_range().start));
        stats.blocks += scanned;
        stats.chunks += 1;
        stats.sapling_received += summary.received_sapling_note_count() as u64;
        stats.orchard_received += summary.received_orchard_note_count() as u64;
        info!(chunk_start, chunk_end, len, outputs = chunk.outputs, chunk_elapsed_ms = elapsed_ms, "chunk scanned");

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

    // T6.1 — interleave cadence helper.
    #[test]
    fn interleave_fires_every_k_chunks() {
        assert!(!should_interleave_enhancement(0, 3));
        assert!(!should_interleave_enhancement(1, 3));
        assert!(!should_interleave_enhancement(2, 3));
        assert!(should_interleave_enhancement(3, 3));
        assert!(!should_interleave_enhancement(4, 3));
        assert!(should_interleave_enhancement(6, 3));
        assert!(should_interleave_enhancement(1, 1));
        assert!(should_interleave_enhancement(2, 1));
    }

    // T5.5 — None-path decision logic: with batch_target_ms=None, batch_len is
    // always reset to chunk_len before each iteration, so the loop exits after
    // exactly one sub-batch (remaining == 0 after advancing sub_start by chunk_len).
    //
    // This test exercises the two-line decision in scan_chunks:
    //   if batch_target_ms.is_none() || batch_len == 0 { batch_len = chunk_len }
    // by checking its arithmetic directly — no network, no WalletSession needed.
    #[test]
    fn none_target_means_single_batch_per_chunk() {
        let chunk_len: u32 = 10_000;
        let batch_target_ms: Option<u64> = None;

        // Simulate the reset guard: with None, batch_len is always set to chunk_len.
        let mut batch_len: u32 = 0; // sentinel (as in scan_chunks before first chunk)
        if batch_target_ms.is_none() || batch_len == 0 {
            batch_len = chunk_len;
        }
        assert_eq!(batch_len, chunk_len, "None: batch_len must equal chunk_len");

        // Simulate loop advancement: sub_start advances by batch_len.
        // After one iteration, remaining must be 0 → loop exits.
        let chunk_start: u64 = 1_000_000;
        let chunk_end: u64 = chunk_start + chunk_len as u64 - 1;
        let sub_start = chunk_start;
        let current_batch_len = (batch_len as usize).min((chunk_end + 1).saturating_sub(sub_start) as usize);
        let sub_end = sub_start + current_batch_len as u64 - 1;
        let next_sub_start = sub_end + 1;
        let remaining_after = (chunk_end + 1).saturating_sub(next_sub_start) as usize;
        assert_eq!(remaining_after, 0, "None: loop must exit after one iteration");

        // Also verify: with Some target, batch_len is NOT reset to chunk_len on
        // subsequent chunks (carried value persists if > 0).
        let batch_target_ms_some: Option<u64> = Some(3_000);
        let mut batch_len_carried: u32 = 5_000; // controller left 5000 from previous chunk
        if batch_target_ms_some.is_none() || batch_len_carried == 0 {
            batch_len_carried = chunk_len;
        }
        assert_eq!(batch_len_carried, 5_000, "Some: carried batch_len must not be overwritten");
    }
}
