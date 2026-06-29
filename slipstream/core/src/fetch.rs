//! Parallel block fetch: K workers claim consecutive sub-ranges ("plan chunks")
//! of the requested range and stream them via GetBlockRange, splitting each
//! stream into byte-budgeted SUB-chunks (T6.8-S) so spam-era plan chunks
//! (mainnet "sandblasting" ~1.70M–2.00M: hundreds of MB per 10k blocks) stay
//! memory-bounded and timeout-immune. A reorder stage releases sub-chunks
//! strictly in (plan_index, sub_index) order — continuity-verified — into the
//! byte-budgeted ChunkQueue. Design: docs/SLIPSTREAM_DESIGN.md §1/§2.2 (T0);
//! splitting + resume-from-height retry: STATE.md session 2026-06-12 T6.8-S.

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use crate::events::Progress;

use prost::Message;
use tokio::sync::{Semaphore, OwnedSemaphorePermit, mpsc};
use tracing::{debug, info, warn};
use zcash_client_backend::proto::{
    compact_formats::CompactBlock,
    service::{BlockId, BlockRange},
};

use crate::{
    chunk::{Chunk, ChunkQueueSender},
    config::{EngineConfig, Endpoint},
    connector::connect_direct_with_retry,
    error::SlipstreamError,
    grpc::{self, LwdClient},
    verify::Continuity,
};

#[derive(Clone, Debug)]
pub struct FetchPlan {
    pub start: u64,
    /// Inclusive.
    pub end: u64,
    pub chunk_blocks: u32,
    pub streams: usize,
    /// Budget of consecutive ZERO-PROGRESS attempts per plan chunk. An attempt
    /// that emitted at least one sub-chunk resets the counter (T6.8-S: resume
    /// makes retries cheap — each re-downloads at most one partial sub-chunk).
    pub retries_per_chunk: u32,
    /// Per-SUB-chunk progress deadline (T6.8-S): the time budget to accumulate
    /// ONE sub-chunk (≤ `split_bytes`), reset on every emitted sub-chunk.
    /// Replaces the old whole-chunk timeout, which a healthy-but-huge
    /// sandblasting chunk could never meet (field failure 2026-06-12: 10k-block
    /// chunks of ~hundreds of MB looped `chunk fetch timed out` forever). A
    /// genuinely stalled stream dies faster via grpc::STREAM_IDLE_TIMEOUT.
    pub chunk_timeout: Duration,
    /// Byte budget per emitted sub-chunk (estimated wire bytes). Normal-era
    /// 10k-block chunks (~1–6 MB) stay single sub-chunks; sandblasting chunks
    /// split into many small sub-chunks automatically. Threaded from
    /// [`EngineConfig::chunk_split_bytes`] by the scheduler.
    pub split_bytes: usize,
}

impl FetchPlan {
    /// `start <= end` is required; violations are a caller bug.
    pub fn new(start: u64, end: u64, chunk_blocks: u32, streams: usize) -> Self {
        assert!(start <= end, "FetchPlan: start {start} > end {end}");
        assert!(chunk_blocks > 0, "FetchPlan: chunk_blocks must be > 0");
        Self {
            start,
            end,
            chunk_blocks,
            streams,
            retries_per_chunk: 3,
            chunk_timeout: Duration::from_secs(120),
            split_bytes: EngineConfig::DEFAULT_CHUNK_SPLIT_BYTES,
        }
    }

    fn chunk_count(&self) -> u64 {
        let span = self.end - self.start + 1;
        span.div_ceil(self.chunk_blocks as u64)
    }

    fn chunk_range(&self, index: u64) -> (u64, u64) {
        let s = self.start + index * self.chunk_blocks as u64;
        let e = (s + self.chunk_blocks as u64 - 1).min(self.end);
        (s, e)
    }
}

#[derive(Debug, Default, Clone)]
pub struct FetchStats {
    pub blocks: u64,
    /// Sum of estimated (wire-encoded) chunk bytes.
    pub bytes: u64,
    /// Wall time of the whole pipeline INCLUDING ChunkQueue backpressure —
    /// pipeline throughput, not pure network speed. With a fast-draining
    /// consumer (the benchmark drains immediately) it approximates download speed.
    pub elapsed: Duration,
}

impl FetchStats {
    pub fn blocks_per_sec(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs > 0.0 { self.blocks as f64 / secs } else { 0.0 }
    }
    pub fn megabytes_per_sec(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs > 0.0 { self.bytes as f64 / (1024.0 * 1024.0) / secs } else { 0.0 }
    }
}

// ── T6.8-S sub-chunk splitting ─────────────────────────────────────────────────

/// One worker's in-order slice of a plan chunk. `sub_index` starts at 0 per plan
/// chunk and SURVIVES retries (resume continues the sequence, never repeating an
/// index); `is_last` marks the plan chunk's final sub-chunk so the reorder stage
/// can advance to the next plan index.
struct SubChunk {
    plan_index: u64,
    sub_index: u64,
    is_last: bool,
    /// Estimated wire bytes (sum of prost encoded_len), as accumulated by the splitter.
    bytes: usize,
    blocks: Vec<CompactBlock>,
    /// Fetch-ahead budget permit (None when emitted by the floor plan chunk).
    /// Held while the sub-chunk waits in the reorder channel/buffer; released
    /// when the reorder stage hands the sub-chunk to the ChunkQueue (whose own
    /// byte budget takes over from there).
    permit: Option<OwnedSemaphorePermit>,
}

/// Byte-budgeted accumulator: collects streamed blocks and yields a completed
/// sub-chunk whenever adding the next block would exceed `split_bytes` (the
/// pushed block then opens the next sub-chunk). Invariants: yielded sub-chunks
/// are never empty and preserve stream order; a single block larger than the
/// budget forms its own sub-chunk (no infinite loop).
pub(crate) struct ChunkSplitter {
    split_bytes: usize,
    acc: Vec<CompactBlock>,
    acc_bytes: usize,
}

impl ChunkSplitter {
    pub(crate) fn new(split_bytes: usize) -> Self {
        Self { split_bytes, acc: Vec::new(), acc_bytes: 0 }
    }

    /// Push the next streamed block; returns `Some((blocks, bytes))` when the
    /// budget overflows and a sub-chunk completes.
    pub(crate) fn push(&mut self, block: CompactBlock) -> Option<(Vec<CompactBlock>, usize)> {
        let block_bytes = Message::encoded_len(&block);
        let completed = if !self.acc.is_empty() && self.acc_bytes + block_bytes > self.split_bytes
        {
            let blocks = std::mem::take(&mut self.acc);
            let bytes = std::mem::replace(&mut self.acc_bytes, 0);
            Some((blocks, bytes))
        } else {
            None
        };
        self.acc.push(block);
        self.acc_bytes += block_bytes;
        completed
    }

    /// Final flush at clean end of stream; `None` when nothing is buffered.
    pub(crate) fn finish(self) -> Option<(Vec<CompactBlock>, usize)> {
        if self.acc.is_empty() { None } else { Some((self.acc, self.acc_bytes)) }
    }
}

// ── T6.8-S fetch-ahead admission control ───────────────────────────────────────

/// How far (in bytes) NON-floor workers may run ahead of the reorder release
/// point. Bounds the reorder buffer in dense eras: without it, K−1 workers
/// each streaming a ~300–900 MB sandblasting plan chunk would park it all in
/// the reorder buffer (default 4 streams: ~1–3 GB → device jetsam). 8×
/// `split_bytes` admits ≥8 normal-era chunks in flight (zero throttling in the
/// normal era) while capping spam-era ahead-buffering at ~64 MiB (default split).
const AHEAD_BUDGET_FACTOR: usize = 8;

/// Poll cadence for floor re-checks while a worker waits on the ahead budget.
const AHEAD_POLL: Duration = Duration::from_millis(100);

/// Admission control for the reorder stage (T6.8-S): the plan chunk currently
/// being released (the "floor") streams unthrottled — its sub-chunks flow
/// straight through to the ChunkQueue — while every other plan chunk must
/// acquire ahead-budget permits, pausing its stream when the budget is spent.
/// Deadlock-free by construction: the floor never waits on the budget, a
/// blocked waiter re-checks the floor every [`AHEAD_POLL`] (so a worker that
/// BECOMES the floor mid-wait proceeds promptly), and held budget is freed
/// exactly when buffered sub-chunks become the floor and drain into the queue.
#[derive(Clone)]
struct AheadGate {
    budget: Arc<Semaphore>,
    cap: usize,
    /// Plan index currently being released by the reorder stage.
    floor: Arc<AtomicU64>,
}

impl AheadGate {
    fn new(cap: usize, floor: Arc<AtomicU64>) -> Self {
        let cap = cap.max(1);
        Self { budget: Arc::new(Semaphore::new(cap.min(Semaphore::MAX_PERMITS))), cap, floor }
    }

    /// Returns a budget permit for one sub-chunk, or `None` when `plan_index`
    /// is (or becomes) the release floor — the floor is exempt.
    async fn admit(&self, plan_index: u64, bytes: usize) -> Option<OwnedSemaphorePermit> {
        // u32 saturation mirrors ChunkQueueSender::send; oversized sub-chunks
        // clamp to the whole budget instead of deadlocking.
        let need = u32::try_from(bytes.min(self.cap).max(1)).unwrap_or(u32::MAX);
        loop {
            if self.floor.load(Ordering::Acquire) >= plan_index {
                return None;
            }
            match tokio::time::timeout(
                AHEAD_POLL,
                Arc::clone(&self.budget).acquire_many_owned(need),
            )
            .await
            {
                Ok(Ok(permit)) => return Some(permit),
                // Semaphore closed = shutdown; the subsequent send fails anyway.
                Ok(Err(_closed)) => return None,
                Err(_elapsed) => {} // re-check the floor (acquire_many is cancel-safe)
            }
        }
    }
}

// ── T6.8-S worker-side streaming ───────────────────────────────────────────────

/// Per-plan-chunk streaming state, surviving retries (resume-from-height).
struct PlanChunkCursor {
    plan_index: u64,
    /// Plan-chunk end bound (inclusive).
    end: u64,
    /// Next height to request: (last emitted sub-chunk's end) + 1. Retries
    /// re-open the stream HERE — already-emitted heights are never re-sent, so
    /// double-release (and therefore double-scan) is structurally impossible.
    resume_from: u64,
    /// Continues across retries so (plan_index, sub_index) stays unique and dense.
    next_sub_index: u64,
    /// Set by every emitted sub-chunk; cleared at attempt start (see worker's
    /// zero-progress retry accounting).
    emitted_this_attempt: bool,
}

#[derive(Debug)]
enum PumpOutcome {
    /// Stream delivered cleanly through `cursor.end`; `is_last` was emitted.
    Completed,
    /// The reorder stage hung up (abort path) — stop quietly.
    ConsumerGone,
}

/// Sends one sub-chunk through the ahead gate into the reorder channel.
/// Returns `false` when the reorder stage is gone. Updates the cursor ONLY on
/// successful handoff (a failed send must not advance the resume point).
async fn emit_sub_chunk(
    cursor: &mut PlanChunkCursor,
    blocks: Vec<CompactBlock>,
    bytes: usize,
    is_last: bool,
    gate: &AheadGate,
    out: &mpsc::Sender<SubChunk>,
) -> bool {
    debug_assert!(!blocks.is_empty(), "splitter never yields empty sub-chunks");
    let last_height = blocks.last().map(|b| b.height);
    let permit = gate.admit(cursor.plan_index, bytes).await;
    let sub = SubChunk {
        plan_index: cursor.plan_index,
        sub_index: cursor.next_sub_index,
        is_last,
        bytes,
        blocks,
        permit,
    };
    if out.send(sub).await.is_err() {
        return false;
    }
    debug!(
        plan_index = cursor.plan_index,
        sub_index = cursor.next_sub_index,
        kb = bytes / 1024,
        is_last,
        "sub-chunk emitted"
    );
    if let Some(h) = last_height {
        cursor.resume_from = h + 1;
    }
    cursor.next_sub_index += 1;
    cursor.emitted_this_attempt = true;
    true
}

/// Streams one (possibly resumed) plan-chunk request into byte-budgeted
/// sub-chunks. Generic over the message stream so hermetic tests can inject
/// synthetic/flaky streams (production passes tonic's `Streaming`).
///
/// Deadline semantics (T6.8-S): `progress_deadline` bounds the accumulation of
/// any ONE sub-chunk, measured between emissions — admission/backpressure time
/// is excluded because the timer resets when an emission completes. A
/// stalled-but-open stream dies earlier via the per-message
/// grpc::STREAM_IDLE_TIMEOUT inside `next_with_idle_timeout`.
///
/// A clean stream end BEFORE `cursor.end` (short/empty delivery) is a
/// retryable Transport error: emitting the partial tail would either lose the
/// missing blocks silently or feed scan an empty chunk; the worker retries
/// from `resume_from` instead (the un-emitted tail is discarded by design —
/// resume re-downloads at most one sub-chunk's worth).
async fn pump_block_stream<S>(
    stream: &mut S,
    cursor: &mut PlanChunkCursor,
    split_bytes: usize,
    progress_deadline: Duration,
    gate: &AheadGate,
    out: &mpsc::Sender<SubChunk>,
) -> Result<PumpOutcome, SlipstreamError>
where
    S: futures_util::Stream<Item = Result<CompactBlock, tonic::Status>> + Unpin,
{
    let ctx = format!(
        "block stream {}..{} (plan chunk {})",
        cursor.resume_from, cursor.end, cursor.plan_index
    );
    let mut splitter = ChunkSplitter::new(split_bytes);
    // tokio Instant (not std) so start_paused tests drive the deadline.
    let mut last_progress = tokio::time::Instant::now();
    loop {
        let Some(item) = grpc::next_with_idle_timeout(stream, &ctx).await? else {
            // Clean end of stream: flush the tail iff it completes the plan chunk.
            return match splitter.finish() {
                Some((blocks, bytes))
                    if blocks.last().map(|b| b.height) == Some(cursor.end) =>
                {
                    if emit_sub_chunk(cursor, blocks, bytes, true, gate, out).await {
                        Ok(PumpOutcome::Completed)
                    } else {
                        Ok(PumpOutcome::ConsumerGone)
                    }
                }
                tail => {
                    let got = tail
                        .and_then(|(blocks, _)| blocks.last().map(|b| b.height))
                        .unwrap_or_else(|| cursor.resume_from.saturating_sub(1));
                    Err(SlipstreamError::Transport(format!(
                        "{ctx}: stream ended short at {got}, expected {}",
                        cursor.end
                    )))
                }
            };
        };
        let block =
            item.map_err(|e| SlipstreamError::Transport(format!("{ctx}: {e}")))?;
        if last_progress.elapsed() > progress_deadline {
            return Err(SlipstreamError::Transport(format!(
                "{ctx}: no completed sub-chunk within {}s",
                progress_deadline.as_secs()
            )));
        }
        if let Some((blocks, bytes)) = splitter.push(block) {
            if !emit_sub_chunk(cursor, blocks, bytes, false, gate, out).await {
                return Ok(PumpOutcome::ConsumerGone);
            }
            last_progress = tokio::time::Instant::now();
        }
    }
}

/// Opens the (resume-aware) GetBlockRange stream and pumps it into sub-chunks.
async fn open_and_pump(
    client: &mut LwdClient,
    cursor: &mut PlanChunkCursor,
    plan: &FetchPlan,
    gate: &AheadGate,
    out: &mpsc::Sender<SubChunk>,
) -> Result<PumpOutcome, SlipstreamError> {
    let req = BlockRange {
        start: Some(BlockId { height: cursor.resume_from, hash: vec![] }),
        end: Some(BlockId { height: cursor.end, hash: vec![] }),
        ..Default::default()
    };
    // B2 (#1755): response-headers deadline. A server that accepts the request
    // but never answers must fail fast into the worker's retry+reconnect loop.
    let mut stream = tokio::time::timeout(grpc::UNARY_TIMEOUT, client.get_block_range(req))
        .await
        .map_err(|_| {
            SlipstreamError::Transport(format!(
                "get_block_range {}..{}: timed out after {}s",
                cursor.resume_from,
                cursor.end,
                grpc::UNARY_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| {
            SlipstreamError::Transport(format!(
                "get_block_range {}..{}: {e}",
                cursor.resume_from, cursor.end
            ))
        })?
        .into_inner();
    pump_block_stream(&mut stream, cursor, plan.split_bytes, plan.chunk_timeout, gate, out).await
}

async fn worker(
    worker_id: usize,
    endpoint: Endpoint,
    plan: FetchPlan,
    next: Arc<AtomicU64>,
    gate: AheadGate,
    out: mpsc::Sender<SubChunk>,
) -> Result<(), SlipstreamError> {
    let mut client = connect_direct_with_retry(&endpoint).await?;
    loop {
        let index = next.fetch_add(1, Ordering::Relaxed);
        if index >= plan.chunk_count() {
            debug!(worker_id, "no more chunks");
            return Ok(());
        }
        let (s, e) = plan.chunk_range(index);
        let mut cursor = PlanChunkCursor {
            plan_index: index,
            end: e,
            resume_from: s,
            next_sub_index: 0,
            emitted_this_attempt: false,
        };
        // Counts consecutive ZERO-PROGRESS attempts; an attempt that emitted a
        // sub-chunk resets the budget (resume makes such retries cheap and the
        // total attempt count stays bounded by sub-chunks × retries).
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            cursor.emitted_this_attempt = false;
            match open_and_pump(&mut client, &mut cursor, &plan, &gate, &out).await {
                Ok(PumpOutcome::Completed) => break,
                Ok(PumpOutcome::ConsumerGone) => return Ok(()), // reorder stage gone (abort)
                Err(err) => {
                    let failed_attempt = attempt;
                    if cursor.emitted_this_attempt {
                        attempt = 0; // progress was made — fresh retry budget
                    }
                    if attempt > plan.retries_per_chunk {
                        return Err(SlipstreamError::Transport(format!(
                            "plan chunk {index} ({s}..{e}) failed after {attempt} zero-progress attempts: {err}"
                        )));
                    }
                    warn!(
                        worker_id,
                        index,
                        attempt = failed_attempt,
                        made_progress = cursor.emitted_this_attempt,
                        resume_from = cursor.resume_from,
                        %err,
                        "chunk fetch failed; retrying from resume height"
                    );
                    // Exponent capped: retries_per_chunk is a pub tunable; uncapped 2^n overflows u64.
                    tokio::time::sleep(Duration::from_millis(
                        250u64.saturating_mul(1 << attempt.saturating_sub(1).min(10)),
                    ))
                    .await;
                    // Reconnect: the channel may be poisoned after a stream error. Resilient to a
                    // brief server outage (bounded retry-with-backoff) so a transient connect blip
                    // resumes this chunk in place instead of failing it → restarting the whole pass.
                    client = connect_direct_with_retry(&endpoint).await?;
                }
            }
        }
    }
}

// ── T6.8-S reorder/release stage ───────────────────────────────────────────────

#[derive(Debug, Default)]
struct ReleaseSummary {
    blocks: u64,
    bytes: u64,
    /// Plan chunks fully released (`is_last` seen) — completeness-check input.
    plans_released: u64,
}

/// Reorder stage: receives sub-chunks in any cross-worker order and releases
/// them strictly in (plan_index, sub_index) order into the ChunkQueue,
/// advancing to plan chunk N+1 only after N's `is_last`. Each release also
/// advances the AheadGate floor so the worker owning the floor plan chunk
/// streams unthrottled and budget held by newly-floored sub-chunks drains.
async fn release_ordered(
    rx: &mut mpsc::Receiver<SubChunk>,
    queue: &ChunkQueueSender,
    progress: Option<&Arc<Progress>>,
    floor: &AtomicU64,
) -> Result<ReleaseSummary, SlipstreamError> {
    let mut summary = ReleaseSummary::default();
    let mut continuity = Continuity::default();
    let mut pending: BTreeMap<(u64, u64), SubChunk> = BTreeMap::new();
    let mut next: (u64, u64) = (0, 0);
    // Dense queue-chunk counter (Chunk.index contract: consecutive from 0).
    let mut emitted_chunks: u64 = 0;
    // Per-plan-chunk split accounting for the info! summary line.
    let (mut plan_subs, mut plan_blocks, mut plan_bytes) = (0u64, 0u64, 0u64);

    while let Some(sub) = rx.recv().await {
        pending.insert((sub.plan_index, sub.sub_index), sub);
        while let Some(sub) = pending.remove(&next) {
            let SubChunk { plan_index, is_last, bytes, blocks, permit, .. } = sub;
            continuity.verify_blocks(&blocks)?;
            let chunk = Chunk::from_blocks(emitted_chunks, blocks);
            let chunk_block_count = chunk.blocks.len() as u64;
            summary.blocks += chunk_block_count;
            summary.bytes += chunk.estimated_bytes as u64;
            plan_subs += 1;
            plan_blocks += chunk_block_count;
            plan_bytes += bytes as u64;
            // Bump the shared progress counter (poll-based; Relaxed — no ordering guarantee).
            if let Some(p) = progress {
                p.add_fetched(chunk_block_count);
            }
            queue.send(chunk).await?;
            emitted_chunks += 1;
            // Ahead-budget permit held until the ChunkQueue takes over.
            drop(permit);
            if is_last {
                if plan_subs > 1 {
                    info!(
                        plan_index,
                        subs = plan_subs,
                        blocks = plan_blocks,
                        mb = plan_bytes / (1024 * 1024),
                        "plan chunk split into sub-chunks (dense era)"
                    );
                }
                summary.plans_released += 1;
                (plan_subs, plan_blocks, plan_bytes) = (0, 0, 0);
                next = (plan_index + 1, 0);
                floor.store(plan_index + 1, Ordering::Release);
            } else {
                next.1 += 1;
            }
        }
    }
    Ok(summary)
}

/// Fetch `plan.start..=plan.end` with `plan.streams` workers; emits ordered,
/// continuity-verified chunks into `queue`. Returns stats on success.
///
/// `progress` — if `Some`, bumps `fetched_blocks` by the block count of each
/// ordered sub-chunk as it is released (Relaxed atomic; no cross-counter guarantees).
pub async fn run_fetch(
    endpoint: &Endpoint,
    plan: FetchPlan,
    queue: ChunkQueueSender,
    progress: Option<Arc<Progress>>,
) -> Result<FetchStats, SlipstreamError> {
    let started = Instant::now();
    let chunk_count = plan.chunk_count();
    info!(
        start = plan.start,
        end = plan.end,
        chunk_count,
        streams = plan.streams,
        split_bytes = plan.split_bytes,
        "fetch begin"
    );

    let next = Arc::new(AtomicU64::new(0));
    let floor = Arc::new(AtomicU64::new(0));
    let gate =
        AheadGate::new(plan.split_bytes.saturating_mul(AHEAD_BUDGET_FACTOR), Arc::clone(&floor));
    // Small reorder margin: each message is one sub-chunk (≤ ~split_bytes).
    let (tx, mut rx) = mpsc::channel::<SubChunk>(plan.streams.max(1));

    let mut handles = Vec::with_capacity(plan.streams);
    for worker_id in 0..plan.streams.max(1) {
        handles.push(tokio::spawn(worker(
            worker_id,
            endpoint.clone(),
            plan.clone(),
            Arc::clone(&next),
            gate.clone(),
            tx.clone(),
        )));
    }
    drop(tx); // release loop ends when all workers finish

    // On early error, abort workers explicitly: a dropped JoinHandle only detaches
    // the task, which would otherwise hold its socket until the next send fails.
    let abort_all = |handles: &Vec<tokio::task::JoinHandle<Result<(), SlipstreamError>>>| {
        for h in handles {
            h.abort();
        }
    };

    let summary = match release_ordered(&mut rx, &queue, progress.as_ref(), &floor).await {
        Ok(s) => s,
        Err(e) => {
            abort_all(&handles);
            return Err(e);
        }
    };

    for h in handles {
        h.await
            .map_err(|e| SlipstreamError::Transport(format!("worker panicked: {e}")))??;
    }
    if summary.plans_released != chunk_count {
        return Err(SlipstreamError::Transport(format!(
            "fetch incomplete: released {}/{chunk_count} plan chunks",
            summary.plans_released
        )));
    }
    let stats =
        FetchStats { blocks: summary.blocks, bytes: summary.bytes, elapsed: started.elapsed() };
    info!(
        blocks = stats.blocks,
        mb = stats.bytes / (1024 * 1024),
        elapsed_s = stats.elapsed.as_secs(),
        "fetch done"
    );
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::chunk_queue;
    use futures_util::stream;

    #[test]
    fn plan_chunking_covers_range_exactly() {
        let p = FetchPlan::new(1000, 1999, 300, 4);
        assert_eq!(p.chunk_count(), 4);
        assert_eq!(p.chunk_range(0), (1000, 1299));
        assert_eq!(p.chunk_range(3), (1900, 1999));
    }

    #[test]
    fn plan_single_block_range() {
        let p = FetchPlan::new(5, 5, 100, 2);
        assert_eq!(p.chunk_count(), 1);
        assert_eq!(p.chunk_range(0), (5, 5));
    }

    #[test]
    #[should_panic(expected = "FetchPlan: start")]
    fn plan_rejects_inverted_range() {
        FetchPlan::new(1000, 999, 100, 1);
    }

    // ── T6.8-S helpers ─────────────────────────────────────────────────────────

    /// Block with a controllable wire size via the `header` field; prev_hash
    /// links to height-1 so released runs pass Continuity.
    fn block_sized(height: u64, payload: usize) -> CompactBlock {
        CompactBlock {
            height,
            hash: hash_of(height),
            prev_hash: hash_of(height - 1),
            header: vec![0xAB; payload],
            ..Default::default()
        }
    }

    fn hash_of(height: u64) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v[..8].copy_from_slice(&height.to_le_bytes());
        v
    }

    fn linked(from: u64, count: u64, payload: usize) -> Vec<CompactBlock> {
        (from..from + count).map(|h| block_sized(h, payload)).collect()
    }

    fn test_cursor(plan_index: u64, start: u64, end: u64) -> PlanChunkCursor {
        PlanChunkCursor {
            plan_index,
            end,
            resume_from: start,
            next_sub_index: 0,
            emitted_this_attempt: false,
        }
    }

    /// Wide-open gate (huge budget) for pump tests that aren't about admission.
    fn open_gate() -> AheadGate {
        AheadGate::new(1 << 30, Arc::new(AtomicU64::new(0)))
    }

    fn drain_subs(rx: &mut mpsc::Receiver<SubChunk>) -> Vec<SubChunk> {
        let mut subs = Vec::new();
        while let Ok(s) = rx.try_recv() {
            subs.push(s);
        }
        subs
    }

    fn assert_heights_consecutive(subs: &[SubChunk], from: u64, to: u64) {
        let heights: Vec<u64> =
            subs.iter().flat_map(|s| s.blocks.iter().map(|b| b.height)).collect();
        let expected: Vec<u64> = (from..=to).collect();
        assert_eq!(heights, expected, "released heights must be exactly {from}..={to}, no dups");
    }

    // ── ChunkSplitter ──────────────────────────────────────────────────────────

    #[test]
    fn splitter_small_blocks_single_subchunk_fast_path() {
        let mut s = ChunkSplitter::new(1024 * 1024);
        for b in linked(100, 10, 16) {
            assert!(s.push(b).is_none(), "small blocks must not split");
        }
        let (blocks, bytes) = s.finish().expect("tail");
        assert_eq!(blocks.len(), 10);
        assert_eq!(blocks.iter().map(|b| b.height).collect::<Vec<_>>(), (100..110).collect::<Vec<_>>());
        assert!(bytes > 0);
    }

    #[test]
    fn splitter_splits_at_threshold_preserving_order() {
        // ~1040-byte blocks against a 2500-byte budget → 2-block sub-chunks.
        let mut s = ChunkSplitter::new(2500);
        let mut emitted: Vec<Vec<CompactBlock>> = Vec::new();
        for b in linked(100, 7, 1000) {
            if let Some((blocks, bytes)) = s.push(b) {
                assert!(bytes <= 2500, "emitted sub-chunk must respect the budget");
                emitted.push(blocks);
            }
        }
        if let Some((blocks, _)) = s.finish() {
            emitted.push(blocks);
        }
        assert_eq!(emitted.len(), 4, "7 blocks at 2/sub-chunk = 3 full + 1 tail");
        assert_eq!(emitted.iter().map(Vec::len).collect::<Vec<_>>(), vec![2, 2, 2, 1]);
        let heights: Vec<u64> =
            emitted.iter().flatten().map(|b| b.height).collect();
        assert_eq!(heights, (100..107).collect::<Vec<_>>(), "order preserved, nothing lost");
    }

    #[test]
    fn splitter_oversized_block_forms_own_subchunk() {
        let mut s = ChunkSplitter::new(1000);
        assert!(s.push(block_sized(100, 5000)).is_none(), "first block always accumulates");
        let (blocks, _) = s.push(block_sized(101, 5000)).expect("oversized block flushes alone");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].height, 100);
        let (tail, _) = s.finish().expect("tail");
        assert_eq!(tail[0].height, 101);
    }

    #[test]
    fn splitter_empty_finish_is_none() {
        assert!(ChunkSplitter::new(1000).finish().is_none());
    }

    // ── pump_block_stream ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn pump_emits_ordered_subchunks_with_final_marker() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(0, 100, 119);
        let mut s = stream::iter(
            linked(100, 20, 1000).into_iter().map(Ok::<_, tonic::Status>).collect::<Vec<_>>(),
        );
        let out = pump_block_stream(&mut s, &mut cursor, 2500, Duration::from_secs(120), &gate, &tx)
            .await
            .expect("pump");
        assert!(matches!(out, PumpOutcome::Completed));
        drop(tx);
        let subs = drain_subs(&mut rx);
        assert!(subs.len() > 1, "split must produce multiple sub-chunks");
        assert_eq!(
            subs.iter().map(|s| s.sub_index).collect::<Vec<_>>(),
            (0..subs.len() as u64).collect::<Vec<_>>(),
            "sub_index dense from 0"
        );
        let lasts: Vec<bool> = subs.iter().map(|s| s.is_last).collect();
        assert!(lasts.iter().rev().skip(1).all(|l| !*l), "only the final sub-chunk is last");
        assert!(*lasts.last().expect("nonempty"), "final sub-chunk carries is_last");
        assert_heights_consecutive(&subs, 100, 119);
        assert_eq!(cursor.resume_from, 120, "cursor advanced past the plan chunk");
        assert_eq!(cursor.next_sub_index, subs.len() as u64);
    }

    #[tokio::test]
    async fn pump_small_chunk_single_subchunk_fast_path() {
        // Default-sized budget swallowing the whole plan chunk → exactly one
        // sub-chunk, is_last=true: today's behaviour, one queue chunk per plan chunk.
        let (tx, mut rx) = mpsc::channel::<SubChunk>(8);
        let gate = open_gate();
        let mut cursor = test_cursor(3, 100, 109);
        let mut s = stream::iter(
            linked(100, 10, 100).into_iter().map(Ok::<_, tonic::Status>).collect::<Vec<_>>(),
        );
        let out = pump_block_stream(
            &mut s,
            &mut cursor,
            EngineConfig::DEFAULT_CHUNK_SPLIT_BYTES,
            Duration::from_secs(120),
            &gate,
            &tx,
        )
        .await
        .expect("pump");
        assert!(matches!(out, PumpOutcome::Completed));
        drop(tx);
        let subs = drain_subs(&mut rx);
        assert_eq!(subs.len(), 1, "normal-era plan chunk = exactly one sub-chunk");
        assert!(subs[0].is_last);
        assert_eq!(subs[0].sub_index, 0);
        assert_eq!(subs[0].blocks.len(), 10);
    }

    #[tokio::test]
    async fn pump_short_stream_errors_without_emitting_tail() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(0, 100, 119);
        // Clean end at 111 — 8 blocks short.
        let mut s = stream::iter(
            linked(100, 12, 1000).into_iter().map(Ok::<_, tonic::Status>).collect::<Vec<_>>(),
        );
        let err = pump_block_stream(&mut s, &mut cursor, 2500, Duration::from_secs(120), &gate, &tx)
            .await
            .expect_err("short stream must error");
        assert!(err.to_string().contains("ended short"), "got: {err}");
        drop(tx);
        let subs = drain_subs(&mut rx);
        assert!(subs.iter().all(|s| !s.is_last), "no is_last on a short stream");
        // 12 blocks at 2/sub-chunk → 5 emitted (10 blocks), 2-block tail discarded.
        let emitted_through = subs.last().and_then(|s| s.blocks.last()).map(|b| b.height);
        assert_eq!(cursor.resume_from, emitted_through.expect("subs emitted") + 1);
    }

    /// THE retry-resume contract (T6.8-S): a mid-plan-chunk failure after
    /// sub-chunk emission resumes from the next un-emitted height; the consumer
    /// sees every height exactly once and the sub_index sequence stays dense.
    #[tokio::test]
    async fn pump_resume_after_midstream_error_no_duplicates() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(0, 100, 139);

        // Attempt 1: 18 blocks then a transport error.
        let mut items: Vec<Result<CompactBlock, tonic::Status>> =
            linked(100, 18, 1000).into_iter().map(Ok).collect();
        items.push(Err(tonic::Status::unavailable("backend dropped")));
        let mut s1 = stream::iter(items);
        let err =
            pump_block_stream(&mut s1, &mut cursor, 2500, Duration::from_secs(120), &gate, &tx)
                .await
                .expect_err("attempt 1 must surface the stream error");
        assert!(err.to_string().contains("backend dropped"), "got: {err}");
        assert!(cursor.emitted_this_attempt, "attempt 1 made progress");
        // 18 blocks at 2/sub-chunk → 8 sub-chunks (16 blocks) emitted; 2 discarded.
        assert_eq!(cursor.resume_from, 116, "resume = last emitted height + 1");
        let subs_before = cursor.next_sub_index;

        // Attempt 2 (the worker's retry): resume_from..=end, clean.
        let mut s2 = stream::iter(
            linked(cursor.resume_from, 140 - cursor.resume_from, 1000)
                .into_iter()
                .map(Ok::<_, tonic::Status>)
                .collect::<Vec<_>>(),
        );
        let out =
            pump_block_stream(&mut s2, &mut cursor, 2500, Duration::from_secs(120), &gate, &tx)
                .await
                .expect("attempt 2 completes");
        assert!(matches!(out, PumpOutcome::Completed));
        assert!(cursor.next_sub_index > subs_before, "sub_index continued, not reset");

        drop(tx);
        let subs = drain_subs(&mut rx);
        assert_eq!(
            subs.iter().map(|s| s.sub_index).collect::<Vec<_>>(),
            (0..subs.len() as u64).collect::<Vec<_>>(),
            "sub_index dense across the retry boundary"
        );
        assert_eq!(subs.iter().filter(|s| s.is_last).count(), 1, "exactly one is_last");
        assert!(subs.last().expect("nonempty").is_last);
        assert_heights_consecutive(&subs, 100, 139);
    }

    /// Healthy-but-slow giant chunk: per-sub-chunk deadline RESETS on every
    /// emission, so total stream time far beyond the deadline still completes.
    #[tokio::test(start_paused = true)]
    async fn pump_deadline_resets_on_each_emitted_subchunk() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(0, 100, 129);
        // One block per simulated second; 2-block sub-chunks → an emission every
        // ~2s against a 5s deadline; total 30s >> 5s.
        let mut s = Box::pin(stream::unfold(100u64, |h| async move {
            if h > 129 {
                return None;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            Some((Ok::<_, tonic::Status>(block_sized(h, 1000)), h + 1))
        }));
        let out = pump_block_stream(&mut s, &mut cursor, 2500, Duration::from_secs(5), &gate, &tx)
            .await
            .expect("slow-but-progressing stream must complete");
        assert!(matches!(out, PumpOutcome::Completed));
        drop(tx);
        assert_heights_consecutive(&drain_subs(&mut rx), 100, 129);
    }

    /// No emission within the deadline (budget never fills) → progress timeout.
    #[tokio::test(start_paused = true)]
    async fn pump_deadline_fires_without_subchunk_progress() {
        let (tx, _rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(0, 100, 129);
        let mut s = Box::pin(stream::unfold(100u64, |h| async move {
            if h > 129 {
                return None;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            Some((Ok::<_, tonic::Status>(block_sized(h, 1000)), h + 1))
        }));
        // Budget is huge → nothing ever emits → the 5s progress deadline fires.
        let err = pump_block_stream(
            &mut s,
            &mut cursor,
            usize::MAX >> 8,
            Duration::from_secs(5),
            &gate,
            &tx,
        )
        .await
        .expect_err("no progress must time out");
        assert!(err.to_string().contains("no completed sub-chunk"), "got: {err}");
        assert!(!cursor.emitted_this_attempt);
        assert_eq!(cursor.resume_from, 100, "no emission → resume from plan start");
    }

    // ── AheadGate ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn gate_floor_is_exempt_even_when_budget_exhausted() {
        let floor = Arc::new(AtomicU64::new(0));
        let gate = AheadGate::new(1000, Arc::clone(&floor));
        // Ahead worker (plan 1) takes the whole budget.
        let held = gate.admit(1, 1000).await.expect("ahead worker gets a permit");
        // Floor worker (plan 0) is exempt — returns None immediately.
        assert!(gate.admit(0, 999_999).await.is_none(), "floor must not consume budget");
        drop(held);
    }

    #[tokio::test]
    async fn gate_blocked_ahead_worker_unblocks_when_it_becomes_floor() {
        let floor = Arc::new(AtomicU64::new(0));
        let gate = AheadGate::new(1000, Arc::clone(&floor));
        let _held = gate.admit(1, 1000).await.expect("plan 1 drains the budget");
        // Plan 2 cannot acquire (budget empty) — parks in the poll loop.
        let gate2 = gate.clone();
        let waiter = tokio::spawn(async move { gate2.admit(2, 500).await });
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(!waiter.is_finished(), "ahead worker must wait while budget is held");
        // The release stage advances the floor to 2 → exemption kicks in.
        floor.store(2, Ordering::Release);
        let got = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("waiter must unblock after floor advance")
            .expect("join");
        assert!(got.is_none(), "now-floor worker proceeds without a permit");
    }

    // ── release_ordered ────────────────────────────────────────────────────────

    fn sub(plan_index: u64, sub_index: u64, is_last: bool, blocks: Vec<CompactBlock>) -> SubChunk {
        let bytes = blocks.iter().map(Message::encoded_len).sum();
        SubChunk { plan_index, sub_index, is_last, bytes, blocks, permit: None }
    }

    /// Multi-worker out-of-order completion: the consumer must receive strictly
    /// height-ordered chunks regardless of sub-chunk arrival order.
    #[tokio::test]
    async fn release_orders_scrambled_subchunks_strictly() {
        let all = linked(100, 60, 64);
        let subs = vec![
            // plan 2: [140-149](0), [150-159](1, last)
            sub(2, 1, true, all[50..60].to_vec()),
            // plan 1: [120-139](0, last)
            sub(1, 0, true, all[20..40].to_vec()),
            // plan 0: [100-109](0), [110-119](1, last)
            sub(0, 1, true, all[10..20].to_vec()),
            sub(2, 0, false, all[40..50].to_vec()),
            sub(0, 0, false, all[0..10].to_vec()),
        ];
        let (tx, mut rx) = mpsc::channel::<SubChunk>(16);
        for s in subs {
            tx.send(s).await.expect("send");
        }
        drop(tx);

        let (qtx, mut qrx) = chunk_queue(usize::MAX >> 8);
        let floor = AtomicU64::new(0);
        let summary = release_ordered(&mut rx, &qtx, None, &floor).await.expect("release");
        assert_eq!(summary.plans_released, 3);
        assert_eq!(summary.blocks, 60);
        drop(qtx);

        let mut released_heights = Vec::new();
        let mut indices = Vec::new();
        while let Some((chunk, permit)) = qrx.recv().await {
            indices.push(chunk.index);
            released_heights.extend(chunk.blocks.iter().map(|b| b.height));
            drop(permit);
        }
        assert_eq!(released_heights, (100..160).collect::<Vec<_>>(), "strict height order");
        assert_eq!(indices, (0..5).collect::<Vec<_>>(), "queue chunk index dense from 0");
        assert_eq!(floor.load(Ordering::Acquire), 3, "floor advanced past the last plan chunk");
    }

    /// Retry-continuation shape: plan 0's tail (emitted by a resumed attempt)
    /// arrives AFTER plan 1 completed — release order must still be plan 0
    /// fully, then plan 1.
    #[tokio::test]
    async fn release_waits_for_retry_continuation_before_advancing() {
        let all = linked(100, 30, 64);
        let (tx, mut rx) = mpsc::channel::<SubChunk>(16);
        tx.send(sub(0, 0, false, all[0..10].to_vec())).await.expect("send");
        tx.send(sub(1, 0, true, all[20..30].to_vec())).await.expect("send");
        // ...worker 0 reconnects and resumes...
        tx.send(sub(0, 1, true, all[10..20].to_vec())).await.expect("send");
        drop(tx);

        let (qtx, mut qrx) = chunk_queue(usize::MAX >> 8);
        let floor = AtomicU64::new(0);
        let summary = release_ordered(&mut rx, &qtx, None, &floor).await.expect("release");
        assert_eq!(summary.plans_released, 2);
        drop(qtx);
        let mut released_heights = Vec::new();
        while let Some((chunk, permit)) = qrx.recv().await {
            released_heights.extend(chunk.blocks.iter().map(|b| b.height));
            drop(permit);
        }
        assert_eq!(released_heights, (100..130).collect::<Vec<_>>());
    }

    /// Continuity is verified ACROSS sub-chunk seams: a gap between two
    /// sub-chunks of the same plan chunk must fail the fetch.
    #[tokio::test]
    async fn release_rejects_gap_between_subchunks() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(16);
        tx.send(sub(0, 0, false, linked(100, 5, 64))).await.expect("send");
        tx.send(sub(0, 1, true, linked(200, 5, 64))).await.expect("send");
        drop(tx);
        let (qtx, _qrx) = chunk_queue(usize::MAX >> 8);
        let floor = AtomicU64::new(0);
        let err = release_ordered(&mut rx, &qtx, None, &floor)
            .await
            .expect_err("gap must fail");
        assert!(matches!(err, SlipstreamError::Discontinuity { at: 200, .. }), "got: {err}");
    }
}
