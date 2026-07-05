//! Scan driver: consumes ordered chunks, runs upstream scan_cached_blocks once
//! per chunk (bounded memory: one commit per chunk), and hides the per-chunk
//! treestate RPC by prefetching the NEXT boundary state while the current
//! chunk scans (spike T2.3 outcome: ChainState must come from the server;
//! prefetch makes its latency invisible).
//!
//! v0.5 REVISION of the T2.3 premise (2026-07-06 pacer plan): the P1 split
//! measured the prefetch overhang at 62 % of the Mac scan wall — the RTT was
//! NOT invisible, and the ChainState does NOT have to come from the server:
//! `local_treestate` seeds one ChainState per range and absorbs the scanned
//! blocks' own commitments into running frontiers (`treestate.rs`), serving
//! every later boundary locally; the sampled server fetch survives as an
//! OFF-path audit.
//!
//! T5.2 — Adaptive sub-batching (opt-in as of T5.5): pass
//! `batch_target_ms = Some(ms)` to split each chunk into time-targeted
//! sub-batches (~ms each).  Default `None` = one scan call per chunk
//! (pre-T5.2 behaviour; fastest on all hardware).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use tracing::{debug, info, warn};
use zcash_client_backend::data_api::chain::{ChainState, error::Error as ChainError, scan_cached_blocks};
use zcash_client_backend::proto::service::TreeState;
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;

use crate::{
    block_source::MemBlockSource,
    chunk::ChunkQueueReceiver,
    config::{Endpoint, EngineConfig},
    connector::TorConn,
    enhance::run_enhancement,
    error::SlipstreamError,
    events::Progress,
    grpc::{self, LwdClient},
    wallet_session::WalletSession,
};

// ── v0.5 local treestate audit ─────────────────────────────────────────────────

/// One in-flight boundary audit: the spawned server fetch plus the locally
/// derived state it must match.
struct AuditEntry {
    height: u64,
    fetch: tokio::task::JoinHandle<Result<TreeState, SlipstreamError>>,
    expected: ChainState,
}

/// Settle boundary audits. With `force_all` every outstanding fetch is
/// awaited (range end — the tail costs at most ~one RTT); otherwise only
/// already-finished handles are consumed, so the audit NEVER blocks the
/// lane. A content mismatch is fatal and trips the process fuse (the
/// revived pass runs the server path); audit-fetch transport failures only
/// warn — the audit is defense in depth, not a correctness dependency (see
/// treestate.rs for the other two nets).
async fn drain_audits(audits: &mut Vec<AuditEntry>, force_all: bool) -> Result<(), SlipstreamError> {
    let mut remaining = Vec::with_capacity(audits.len());
    for entry in audits.drain(..) {
        if !force_all && !entry.fetch.is_finished() {
            remaining.push(entry);
            continue;
        }
        let AuditEntry { height, fetch, expected } = entry;
        match fetch.await {
            Err(join_err) => warn!(height, %join_err, "treestate audit task failed — skipped"),
            Ok(Err(fetch_err)) => warn!(height, %fetch_err, "treestate audit fetch failed — skipped"),
            Ok(Ok(server)) => match server.to_chain_state() {
                Err(e) => warn!(height, %e, "treestate audit parse failed — skipped"),
                Ok(server_state) => {
                    if server_state != expected {
                        crate::treestate::trip_fuse();
                        return Err(SlipstreamError::Wallet(format!(
                            "local treestate MISMATCH vs server at height {height} — pass aborted, fuse tripped (server path on revival)"
                        )));
                    }
                }
            },
        }
    }
    *audits = remaining;
    Ok(())
}

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
    /// v0.5 pacer split (2026-07-06 plan §3): the scan lane's wall decomposed.
    /// `scan_wall ≈ recv_wait + scan_call + prefetch_wait + interleave_drain +
    /// final_drain + persist_wait + residue` — the residue (computed at read
    /// time) is bookkeeping between the timed spans.
    /// Σ awaiting rx.recv() — fetch/split starvation.
    pub recv_wait: std::time::Duration,
    /// Σ inside scan_cached_blocks (upstream scan; decrypt rides rayon within).
    pub scan_call: std::time::Duration,
    /// Σ awaiting the treestate prefetch BEYOND the scan it raced (RTT overhang).
    pub prefetch_wait: std::time::Duration,
    /// Σ full persist-lane drains before interleaved enhancement (counted as
    /// scan time by the stage split — the pre-registered suspect #1).
    pub interleave_drain: std::time::Duration,
    /// The end-of-range persist drain barrier (also inside the scan stage).
    pub final_drain: std::time::Duration,
    /// v0.5 local treestate: Σ absorbing scanned commitments into the running
    /// frontiers (the lever's own cost — replaces prefetch_wait when on).
    pub treestate_absorb: std::time::Duration,
    /// v0.4 census (spec §3.2): per-pool shard-touch vs owned-note-shard counts
    /// for this range (copied out of whichever SparseTreeState ran the builds —
    /// the persist lane's on the write-behind path, the scan task's inline).
    pub census_sapling: crate::census::ShardCensus,
    pub census_orchard: crate::census::ShardCensus,
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
#[allow(clippy::too_many_arguments)] // +tor (T-Tor.2); bundling would obscure the borrow structure
pub async fn scan_chunks(
    session: &mut WalletSession,
    client: &mut LwdClient,
    range_start: u64,
    rx: ChunkQueueReceiver,
    progress: Option<Arc<Progress>>,
    config: &EngineConfig,
    skipped_keys: &mut HashSet<String>,
    tor: Option<&TorConn>,
    historic_range: bool,
) -> Result<ScanStats, SlipstreamError> {
    if range_start == 0 {
        return Err(SlipstreamError::Wallet("range_start must be >= 1".into()));
    }
    // v0.4 Plan A: buffering only on Historic ranges (accumulator safety rule 2).
    let graft_buffering = config.graft_subtree && historic_range;

    // ── T6.9 write-behind setup ───────────────────────────────────────────────
    // Seed the pending-aware facade from the committed DB (no-pending barrier:
    // nothing is stashed or in flight yet) and open the persist lane's own
    // connection to the wallet file. `None` = today's serialized path.
    let mut wb: Option<WriteBehind> = if config.write_behind {
        let facade = crate::persist::WriteBehindFacade::seed(&*session.db_mut(), range_start)
            .map_err(|e| SlipstreamError::Wallet(format!("write-behind seed: {e}")))?;
        let mut lane = crate::persist::PersistLane::open(&config.wallet_db_path, config.network, config.persist_depth, graft_buffering, config.graft_verify_sample, config.batch_combine)?;
        // [B4-16 drain] Every deferred commit holds the writer gate so the FFI
        // stop()/start() drain can wait out an orphan commit abort() can't cancel.
        if let Some(p) = &progress {
            lane.attach_writer_gate(p.clone());
        }
        Some(WriteBehind { facade, lane })
    } else {
        None
    };

    let result =
        scan_chunks_inner(session, client, range_start, rx, progress, config, skipped_keys, &mut wb, tor, graft_buffering)
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
        // v0.5 pacer: the end-of-range barrier is inside the scan stage too.
        let final_drain_started = Instant::now();
        let drain_result = wb.lane.drain().await;
        let final_drain_elapsed = final_drain_started.elapsed();
        return match (result, drain_result) {
            (Ok(mut stats), Ok(())) => {
                // v0.4 Plan A: build the range-end/tip shard the accumulators still
                // hold (success path only — on errors the buffer resumes the shard).
                tokio::task::block_in_place(|| wb.lane.finish_graft_blocking())?;
                stats.final_drain = final_drain_elapsed;
                stats.persist_wait = wb.lane.total_wait();
                stats.persist_busy = wb.lane.total_busy();
                // v0.4 census: the lane's sparse state ran the builds on this path.
                (stats.census_sapling, stats.census_orchard) = wb.lane.census();
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
    tor: Option<&TorConn>,
    graft_buffering: bool,
) -> Result<ScanStats, SlipstreamError> {
    let mut sparse_state = crate::persist::SparseTreeState::default();
    sparse_state.gpu_subtree = config.gpu_subtree; // B0: route Orchard build to GPU when set
    sparse_state.graft_buffering = graft_buffering; // v0.4: only used on the inline path (wb's lane carries its own)
    sparse_state.batch_combine = config.batch_combine; // v0.4 Plan B (inline path)
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
        grpc::retry_get_tree_state(&endpoint, range_start - 1, "initial seed", tor).await?;

    // ── v0.5 local treestate (2026-07-06 pacer plan) ─────────────────────────
    // When enabled, every boundary AFTER the seeded first sub-batch is served
    // from running frontiers absorbed out of the scanned blocks themselves;
    // the sampled server fetch becomes an off-path audit (drain_audits).
    let local_mode = config.local_treestate && !crate::treestate::fuse_tripped();
    if config.local_treestate && !local_mode {
        warn!("local treestate requested but the process fuse is tripped — server path");
    }
    let mut local_ts: Option<crate::treestate::LocalTreestate> = None;
    // (height, hash) of the last absorbed block = the next boundary identity.
    let mut local_boundary: Option<(u64, BlockHash)> = None;
    let mut boundary_index: u64 = 0;
    let mut audits: Vec<AuditEntry> = Vec::new();
    let mut boundaries_local: u64 = 0;
    let mut boundaries_audited: u64 = 0;
    // v0.5 pacer: notes found since the last interleaved enhancement — the
    // interleave (and its full persist drain) only fires when > 0.
    let mut notes_since_enhance: u64 = 0;

    // batch_len: for the adaptive path (batch_target_ms = Some), this is carried
    // across chunks and updated by the controller.  For the None path it is set to
    // chunk_len before every chunk and never updated — the loop executes exactly once
    // per chunk (degenerate single-iteration).
    let mut batch_len: u32 = 0;

    loop {
        // v0.5 pacer: time the chunk wait — fetch/split starvation shows here.
        let recv_started = Instant::now();
        let Some((chunk, permit, mut chunk_boundary)) = rx.recv().await else { break };
        stats.recv_wait += recv_started.elapsed();
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
            // v0.5: in local mode the fetch is needed only on audited
            // boundaries (and consumed off the critical path); in server mode
            // it is the actual next state, exactly as before. The queue may
            // have carried a FETCH-SIDE pre-spawned handle for the chunk's end
            // boundary (started at emit — its RTT has been hiding under queue
            // wait + scan since); use it when this sub-batch IS that boundary,
            // spawn late otherwise (mid-chunk sub-batches, tests, darkside).
            let audit_this = local_mode
                && config.treestate_verify_sample > 0
                && boundary_index.is_multiple_of(u64::from(config.treestate_verify_sample));
            boundary_index += 1;
            let carried = if sub_end == chunk_end { chunk_boundary.take() } else { None };
            let prefetch = if !local_mode || audit_this {
                carried.or_else(|| {
                    Some(tokio::spawn({
                        let ep = endpoint.clone();
                        let tor_owned = tor.cloned();
                        async move {
                            grpc::retry_get_tree_state(&ep, sub_end, "chunk-boundary prefetch", tor_owned.as_ref()).await
                        }
                    }))
                })
            } else {
                if let Some(h) = carried {
                    // Local mode, unaudited boundary — the carried fetch is unneeded.
                    h.abort();
                }
                None
            };

            let from_state = match (&local_ts, &local_boundary) {
                // v0.5: boundary served locally — zero round-trips.
                (Some(ts), Some((bh, bhash))) => {
                    let h = u32::try_from(*bh)
                        .map_err(|_| SlipstreamError::Wallet(format!("height {bh} exceeds u32")))?;
                    ts.chain_state(BlockHeight::from(h), *bhash)
                }
                _ => next_state
                    .to_chain_state()
                    .map_err(|e| SlipstreamError::Wallet(format!("chain state: {e}")))?,
            };
            if local_mode && local_ts.is_none() {
                // Seed the running frontiers from the range's first (server)
                // state — the ONE fetch this range still needs.
                local_ts = Some(crate::treestate::LocalTreestate::seed(&from_state));
            }

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
                    if let Some(p) = &prefetch {
                        p.abort();
                    }
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
                    if let Some(p) = &prefetch {
                        p.abort();
                    }
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
            // (elapsed_ms was captured immediately after scan_cached_blocks —
            // BEFORE the submit above — so this is pure scan-call time.)
            stats.scan_call += std::time::Duration::from_millis(elapsed_ms);

            // ── v0.5 local treestate: absorb this sub-batch so the NEXT
            // boundary is served locally. Anomalies are HARD errors (a wrong
            // from_state would corrupt note positions — never scan past one).
            if let Some(ts) = local_ts.as_mut() {
                let absorb_started = Instant::now();
                for h in sub_start..=sub_end {
                    let idx = (h - chunk_start) as usize;
                    let block = chunk.blocks.get(idx).ok_or_else(|| {
                        SlipstreamError::Wallet(format!("local treestate: chunk missing block {h}"))
                    })?;
                    if block.height != h || block.hash.len() != 32 {
                        return Err(SlipstreamError::Wallet(format!(
                            "local treestate: block at index {idx} is malformed (height {} hash_len {})",
                            block.height,
                            block.hash.len()
                        )));
                    }
                    ts.absorb_block(block)
                        .map_err(|e| SlipstreamError::Wallet(format!("local treestate absorb: {e}")))?;
                }
                let last = &chunk.blocks[(sub_end - chunk_start) as usize];
                local_boundary = Some((sub_end, last.hash()));
                boundaries_local += 1;
                stats.treestate_absorb += absorb_started.elapsed();
            }

            // Consume the fetch: in server mode it IS the next state (awaited
            // on the lane, timed as prefetch overhang); in local mode it is an
            // audit — parked for off-path settlement, never blocking the lane.
            if let Some(handle) = prefetch {
                if local_mode {
                    if let (Some(ts), Some((bh, bhash))) = (&local_ts, &local_boundary) {
                        let h = u32::try_from(*bh)
                            .map_err(|_| SlipstreamError::Wallet(format!("height {bh} exceeds u32")))?;
                        audits.push(AuditEntry {
                            height: *bh,
                            fetch: handle,
                            expected: ts.chain_state(BlockHeight::from(h), *bhash),
                        });
                        boundaries_audited += 1;
                    } else {
                        handle.abort();
                    }
                } else {
                    let prefetch_started = Instant::now();
                    let fetched = handle
                        .await
                        .map_err(|e| SlipstreamError::Transport(format!("prefetch task: {e}")))??;
                    stats.prefetch_wait += prefetch_started.elapsed();
                    next_state = fetched;
                }
            }
            // Opportunistically settle audits that already finished (non-blocking).
            drain_audits(&mut audits, false).await?;

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

            // Advance for the next sub-batch. (next_state was already updated
            // inside the server-mode prefetch consumption above; local mode
            // serves the next boundary from the running frontiers instead.)
            sub_start = sub_end + 1;
        }
        // ── End sub-batch loop ────────────────────────────────────────────────

        // Accumulate chunk totals into global stats.
        stats.blocks += chunk_scanned_blocks;
        stats.chunks += 1;
        stats.sapling_received += chunk_sapling;
        stats.orchard_received += chunk_orchard;
        notes_since_enhance += chunk_sapling + chunk_orchard;

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
        // v0.5 pacer: ALSO gated on notes found since the last run — the P1
        // split showed the full persist drain below firing every K chunks
        // even when there was nothing to reveal (~4.5 s/pass on the Mac).
        // Statuses/address windows still ride the per-range + final backstops.
        if should_interleave_enhancement(stats.chunks, config.enhance_every_chunks)
            && notes_since_enhance > 0
        {
            notes_since_enhance = 0;
            // T6.9 full barrier: enhancement reads AND writes the wallet DB —
            // it must never see a half-committed range tail, and it must not
            // run concurrently with a deferred commit (single-writer rule).
            // v0.5 pacer: this drain is INSIDE the scan stage (suspect #1).
            if let Some(wb) = wb.as_mut() {
                let drain_started = Instant::now();
                wb.lane.drain().await?;
                stats.interleave_drain += drain_started.elapsed();
            }
            let started = Instant::now();
            let mut enhance_client = client.clone();
            match run_enhancement(session, &mut enhance_client, network, progress.clone(), skipped_keys).await {
                Ok(es) => {
                    stats.interleaved_enhance.requests += es.requests;
                    stats.interleaved_enhance.txs_stored += es.txs_stored;
                    stats.interleaved_enhance.statuses_set += es.statuses_set;
                    stats.interleaved_enhance.skipped += es.skipped;
                    stats.interleaved_enhance.fetch_wait += es.fetch_wait;
                    stats.interleaved_enhance.store += es.store;
                    stats.interleaved_enhance.address += es.address;
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
    // v0.5 local treestate: settle every outstanding boundary audit (the tail
    // costs at most ~one RTT — the fetches ran concurrently with scanning).
    drain_audits(&mut audits, true).await?;
    if local_mode {
        info!(
            boundaries_local,
            boundaries_audited,
            absorb_ms = stats.treestate_absorb.as_millis() as u64,
            "local treestate summary"
        );
    }

    // v0.4 census: inline-sparse path — the local state ran the builds. (On the
    // write-behind path this is zeros; scan_chunks overwrites from the lane.)
    stats.census_sapling = std::mem::take(&mut sparse_state.census_sapling);
    stats.census_orchard = std::mem::take(&mut sparse_state.census_orchard);
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
///
/// `gpu_subtree` — when `true` (requires `sparse`), route the Orchard subtree
/// build to the GPU (feature `gpu`) exactly as production does, mirroring
/// `EngineConfig::gpu_subtree`. Added at B0.4 so the darkside oracle can prove
/// the GPU subtree build yields a byte-identical data.db against real fixtures.
/// `graft` — v0.4 Plan A: run this range with the graft accumulator enabled
/// (the byte-equal and semantic oracles A/B this flag against real fixtures).
#[cfg(any(test, feature = "darkside"))]
#[allow(clippy::too_many_arguments)] // test driver mirrors production toggles 1:1
pub async fn scan_chunks_from_treestate(
    session: &mut WalletSession,
    range_start: u64,
    initial_state: TreeState,
    rx: ChunkQueueReceiver,
    sparse: bool,
    write_behind: bool,
    gpu_subtree: bool,
    graft: bool,
) -> Result<ScanStats, SlipstreamError> {
    if range_start == 0 {
        return Err(SlipstreamError::Wallet("range_start must be >= 1".into()));
    }
    if write_behind && !sparse {
        return Err(SlipstreamError::Wallet(
            "write_behind requires sparse (mirrors EngineConfig::validate)".into(),
        ));
    }
    if gpu_subtree && !sparse {
        return Err(SlipstreamError::Wallet(
            "gpu_subtree requires sparse (mirrors EngineConfig::validate)".into(),
        ));
    }
    if graft && !sparse {
        return Err(SlipstreamError::Wallet(
            "graft requires sparse (mirrors EngineConfig::validate)".into(),
        ));
    }
    let mut wb: Option<WriteBehind> = if write_behind {
        let facade = crate::persist::WriteBehindFacade::seed(&*session.db_mut(), range_start)
            .map_err(|e| SlipstreamError::Wallet(format!("write-behind seed: {e}")))?;
        let lane = crate::persist::PersistLane::open(session.db_path(), session.network, 1, graft, 1, false)?;
        Some(WriteBehind { facade, lane })
    } else {
        None
    };

    let result =
        scan_chunks_from_treestate_inner(session, initial_state, rx, sparse, gpu_subtree, graft, &mut wb).await;

    // T6.9 full barrier — mirror of scan_chunks (persist error precedence).
    if let Some(mut wb) = wb {
        if wb.facade.take_stash().is_some() {
            warn!("write-behind (treestate driver): dropping an unsubmitted pending unit on error exit");
        }
        let drain_result = wb.lane.drain().await;
        return match (result, drain_result) {
            (Ok(mut stats), Ok(())) => {
                // v0.4 Plan A: build the range-end/tip shard the accumulators still
                // hold (success path only — on errors the buffer resumes the shard).
                tokio::task::block_in_place(|| wb.lane.finish_graft_blocking())?;
                stats.persist_wait = wb.lane.total_wait();
                stats.persist_busy = wb.lane.total_busy();
                // v0.4 census: the lane's sparse state ran the builds on this path.
                (stats.census_sapling, stats.census_orchard) = wb.lane.census();
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
    gpu_subtree: bool,
    graft: bool,
    wb: &mut Option<WriteBehind>,
) -> Result<ScanStats, SlipstreamError> {
    let mut sparse_state = crate::persist::SparseTreeState::default();
    sparse_state.gpu_subtree = gpu_subtree;
    sparse_state.graft_buffering = graft; // v0.4: inline path (wb's lane carries its own)
    let mut stats = ScanStats::default();
    let mut next_state = initial_state;

    while let Some((chunk, permit, _boundary)) = rx.recv().await {
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
    // v0.4 census: mirror of scan_chunks_inner (zeros under write-behind; the
    // wrapper overwrites from the lane after its drain barrier).
    stats.census_sapling = std::mem::take(&mut sparse_state.census_sapling);
    stats.census_orchard = std::mem::take(&mut sparse_state.census_orchard);
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
