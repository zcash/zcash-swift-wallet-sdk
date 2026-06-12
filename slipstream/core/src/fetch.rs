//! Parallel block fetch: K workers claim consecutive sub-ranges ("chunks")
//! of the requested range, stream them via GetBlockRange, and a reorder
//! stage emits chunks strictly in order — continuity-verified — into the
//! byte-budgeted ChunkQueue. Design: docs/SLIPSTREAM_DESIGN.md §1/§2.2 (T0).

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use crate::events::Progress;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use zcash_client_backend::proto::{
    compact_formats::CompactBlock,
    service::{BlockId, BlockRange},
};

use crate::{
    chunk::{Chunk, ChunkQueueSender},
    config::Endpoint,
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
    pub retries_per_chunk: u32,
    pub chunk_timeout: Duration,
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

async fn fetch_one_chunk(
    client: &mut LwdClient,
    start: u64,
    end: u64,
) -> Result<Vec<CompactBlock>, SlipstreamError> {
    let req = BlockRange {
        start: Some(BlockId { height: start, hash: vec![] }),
        end: Some(BlockId { height: end, hash: vec![] }),
        ..Default::default()
    };
    // B2 (#1755): response-headers deadline. A server that accepts the request but
    // never answers must fail fast into the worker's retry+reconnect loop instead of
    // riding out the whole 120 s chunk timeout.
    let mut stream = tokio::time::timeout(grpc::UNARY_TIMEOUT, client.get_block_range(req))
        .await
        .map_err(|_| {
            SlipstreamError::Transport(format!(
                "get_block_range {start}..{end}: timed out after {}s",
                grpc::UNARY_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| SlipstreamError::Transport(format!("get_block_range {start}..{end}: {e}")))?
        .into_inner();
    let mut blocks = Vec::with_capacity((end - start + 1) as usize);
    // B2 (#1755): per-message idle deadline. A stalled-but-open stream (silently
    // dropped flow) surfaces as a Transport error -> worker retry+reconnect, instead
    // of hanging until the 120 s whole-chunk backstop (which stays in place).
    while let Some(item) =
        grpc::next_with_idle_timeout(&mut stream, &format!("block stream {start}..{end}")).await?
    {
        blocks.push(item.map_err(|e| {
            SlipstreamError::Transport(format!("block stream {start}..{end}: {e}"))
        })?);
    }
    Ok(blocks)
}

async fn worker(
    worker_id: usize,
    endpoint: Endpoint,
    plan: FetchPlan,
    next: Arc<AtomicU64>,
    out: mpsc::Sender<(u64, Vec<CompactBlock>)>,
) -> Result<(), SlipstreamError> {
    let mut client = grpc::connect(&endpoint).await?;
    loop {
        let index = next.fetch_add(1, Ordering::Relaxed);
        if index >= plan.chunk_count() {
            debug!(worker_id, "no more chunks");
            return Ok(());
        }
        let (s, e) = plan.chunk_range(index);
        let mut attempt = 0;
        let blocks = loop {
            attempt += 1;
            let result = tokio::time::timeout(plan.chunk_timeout, fetch_one_chunk(&mut client, s, e)).await;
            match result {
                Ok(Ok(blocks)) => break blocks,
                Ok(Err(err)) if attempt <= plan.retries_per_chunk => {
                    warn!(worker_id, index, attempt, %err, "chunk fetch failed; retrying");
                    // Exponent capped: retries_per_chunk is a pub tunable; uncapped 2^n overflows u64.
                    tokio::time::sleep(Duration::from_millis(
                        250u64.saturating_mul(1 << (attempt - 1).min(10)),
                    ))
                    .await;
                    // Reconnect: the channel may be poisoned after a stream error.
                    client = grpc::connect(&endpoint).await?;
                }
                Ok(Err(err)) => return Err(err),
                Err(_elapsed) if attempt <= plan.retries_per_chunk => {
                    warn!(worker_id, index, attempt, "chunk fetch timed out; retrying");
                    client = grpc::connect(&endpoint).await?;
                }
                Err(_elapsed) => {
                    return Err(SlipstreamError::Transport(format!(
                        "chunk {index} ({s}..{e}) timed out after {} attempts",
                        attempt
                    )));
                }
            }
        };
        if out.send((index, blocks)).await.is_err() {
            return Ok(()); // reorder stage gone (abort) — stop quietly
        }
    }
}

/// Fetch `plan.start..=plan.end` with `plan.streams` workers; emits ordered,
/// continuity-verified chunks into `queue`. Returns stats on success.
///
/// `progress` — if `Some`, bumps `fetched_blocks` by the block count of each ordered
/// chunk as it is emitted (Relaxed atomic; no cross-counter guarantees).
pub async fn run_fetch(
    endpoint: &Endpoint,
    plan: FetchPlan,
    queue: ChunkQueueSender,
    progress: Option<Arc<Progress>>,
) -> Result<FetchStats, SlipstreamError> {
    let started = Instant::now();
    let chunk_count = plan.chunk_count();
    info!(start = plan.start, end = plan.end, chunk_count, streams = plan.streams, "fetch begin");

    let next = Arc::new(AtomicU64::new(0));
    // Small reorder margin: workers can run ahead by ~one chunk each.
    let (tx, mut rx) = mpsc::channel::<(u64, Vec<CompactBlock>)>(plan.streams.max(1));

    let mut handles = Vec::with_capacity(plan.streams);
    for worker_id in 0..plan.streams.max(1) {
        handles.push(tokio::spawn(worker(
            worker_id,
            endpoint.clone(),
            plan.clone(),
            Arc::clone(&next),
            tx.clone(),
        )));
    }
    drop(tx); // reorder loop ends when all workers finish

    let mut stats = FetchStats::default();
    let mut continuity = Continuity::default();
    let mut pending: BTreeMap<u64, Vec<CompactBlock>> = BTreeMap::new();
    let mut next_emit: u64 = 0;

    // On early error, abort workers explicitly: a dropped JoinHandle only detaches
    // the task, which would otherwise hold its socket until the next send fails.
    let abort_all = |handles: &Vec<tokio::task::JoinHandle<Result<(), SlipstreamError>>>| {
        for h in handles {
            h.abort();
        }
    };

    while let Some((index, blocks)) = rx.recv().await {
        pending.insert(index, blocks);
        while let Some(blocks) = pending.remove(&next_emit) {
            if let Err(e) = continuity.verify_blocks(&blocks) {
                abort_all(&handles);
                return Err(e);
            }
            let chunk = Chunk::from_blocks(next_emit, blocks);
            let chunk_block_count = chunk.blocks.len() as u64;
            stats.blocks += chunk_block_count;
            stats.bytes += chunk.estimated_bytes as u64;
            // Bump the shared progress counter (poll-based; Relaxed — no ordering guarantee).
            if let Some(ref p) = progress {
                p.add_fetched(chunk_block_count);
            }
            if let Err(e) = queue.send(chunk).await {
                abort_all(&handles);
                return Err(e);
            }
            next_emit += 1;
        }
    }

    for h in handles {
        h.await
            .map_err(|e| SlipstreamError::Transport(format!("worker panicked: {e}")))??;
    }
    if next_emit != chunk_count {
        return Err(SlipstreamError::Transport(format!(
            "fetch incomplete: emitted {next_emit}/{chunk_count} chunks"
        )));
    }
    stats.elapsed = started.elapsed();
    info!(blocks = stats.blocks, mb = stats.bytes / (1024 * 1024), elapsed_s = stats.elapsed.as_secs(), "fetch done");
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
