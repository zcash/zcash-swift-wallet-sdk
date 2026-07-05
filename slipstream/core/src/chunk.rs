//! In-memory unit of transport: a height-ordered run of CompactBlocks plus
//! a byte-budgeted queue connecting fetch (producer) to scan (consumer).
//! Backpressure: permits are held until the CONSUMER drops the chunk's
//! `ChunkPermit`, so the budget covers queued AND in-processing bytes.

use std::sync::Arc;

use prost::Message;
use tokio::sync::{Semaphore, mpsc};
use zcash_client_backend::proto::compact_formats::CompactBlock;

use crate::error::SlipstreamError;

#[derive(Clone, Debug)]
pub struct Chunk {
    /// Index in the fetch plan (0-based, consecutive).
    pub index: u64,
    pub blocks: Vec<CompactBlock>,
    /// Sum of protobuf wire sizes. The in-memory footprint of decoded blocks
    /// can be 2–3× larger (Vec capacity, per-field allocations) — the budget
    /// is a conservative bound, not a tight one.
    pub estimated_bytes: usize,
    /// Trial-decryption work denominator: sapling outputs + orchard actions
    /// across all transactions in this chunk.
    pub outputs: u64,
}

impl Chunk {
    pub fn from_blocks(index: u64, blocks: Vec<CompactBlock>) -> Self {
        let estimated_bytes = blocks.iter().map(Message::encoded_len).sum();
        // Count total sapling outputs and orchard actions across all transactions.
        let outputs: u64 = blocks
            .iter()
            .flat_map(|block| &block.vtx)
            .map(|tx| (tx.outputs.len() + tx.actions.len()) as u64)
            .sum();
        Self { index, blocks, estimated_bytes, outputs }
    }

    pub fn start_height(&self) -> Option<u64> {
        self.blocks.first().map(|b| b.height)
    }
    pub fn end_height(&self) -> Option<u64> {
        self.blocks.last().map(|b| b.height)
    }
}

/// Holds the byte-budget permits for one chunk; drop to release budget.
#[must_use = "dropping the permit releases the byte budget; hold it until the chunk is fully processed"]
pub struct ChunkPermit {
    _permits: tokio::sync::OwnedSemaphorePermit,
}

/// v0.5 pacer fix: the boundary-treestate fetch spawned WHEN THE CHUNK IS
/// EMITTED, so its RTT overlaps queue wait + scan + submit instead of racing
/// one scan call (the P1 split measured that overhang at 62 % of the Mac
/// scan wall on a slow-treestate day).
pub type BoundaryHandle =
    tokio::task::JoinHandle<Result<zcash_client_backend::proto::service::TreeState, SlipstreamError>>;

/// Injected at queue construction (scheduler): given a chunk's end height,
/// spawn its boundary treestate fetch. `None` (tests, darkside) keeps the
/// scan-side late-spawn fallback.
pub type BoundaryFetcher = Arc<dyn Fn(u64) -> BoundaryHandle + Send + Sync>;

pub struct ChunkQueueSender {
    tx: mpsc::UnboundedSender<(Chunk, ChunkPermit, Option<BoundaryHandle>)>,
    budget: Arc<Semaphore>,
    budget_bytes: usize,
    boundary_fetcher: Option<BoundaryFetcher>,
}

pub struct ChunkQueueReceiver {
    rx: mpsc::UnboundedReceiver<(Chunk, ChunkPermit, Option<BoundaryHandle>)>,
}

/// `budget_bytes` bounds the estimated bytes in flight (queued + being
/// consumed). A single chunk larger than the budget is clamped to the whole
/// budget rather than deadlocking.
pub fn chunk_queue(budget_bytes: usize) -> (ChunkQueueSender, ChunkQueueReceiver) {
    let (tx, rx) = mpsc::unbounded_channel();
    (
        // A zero budget degenerates to 1 byte (fully serial) instead of blocking forever.
        ChunkQueueSender {
            tx,
            budget: Arc::new(Semaphore::new(budget_bytes.max(1))),
            budget_bytes: budget_bytes.max(1),
            boundary_fetcher: None,
        },
        ChunkQueueReceiver { rx },
    )
}

impl ChunkQueueSender {
    /// Install the boundary-treestate fetcher (scheduler, production path).
    pub fn set_boundary_fetcher(&mut self, f: BoundaryFetcher) {
        self.boundary_fetcher = Some(f);
    }

    /// Waits until the byte budget admits the chunk, then enqueues it.
    pub async fn send(&self, chunk: Chunk) -> Result<(), SlipstreamError> {
        // v0.5: fire the boundary fetch BEFORE the budget wait — treestates
        // are immutable historical data, and the earlier the RTT starts the
        // more scan it hides under. At most (queued chunks + 1) fetches are
        // ever in flight, so a slow server sees a trickle, never a burst.
        let boundary = match (&self.boundary_fetcher, chunk.end_height()) {
            (Some(f), Some(end)) => Some(f(end)),
            _ => None,
        };
        // Saturate: budgets beyond u32::MAX simply cap the per-chunk acquisition;
        // the semaphore itself holds the full usize budget, so backpressure stays correct.
        let need = u32::try_from(chunk.estimated_bytes.min(self.budget_bytes).max(1))
            .unwrap_or(u32::MAX);
        let permits = self
            .budget
            .clone()
            .acquire_many_owned(need)
            .await
            .map_err(|_| SlipstreamError::Stopped)?;
        self.tx
            .send((chunk, ChunkPermit { _permits: permits }, boundary))
            .map_err(|_| SlipstreamError::Stopped)?;
        Ok(())
    }
}

impl ChunkQueueReceiver {
    /// `None` when all senders are dropped (fetch finished or aborted).
    pub async fn recv(&mut self) -> Option<(Chunk, ChunkPermit, Option<BoundaryHandle>)> {
        self.rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use zcash_client_backend::proto::compact_formats::{CompactSaplingOutput, CompactOrchardAction, CompactTx};

    fn block(height: u64) -> CompactBlock {
        CompactBlock { height, hash: vec![height as u8; 32], ..Default::default() }
    }

    fn chunk_of(index: u64, heights: std::ops::RangeInclusive<u64>) -> Chunk {
        Chunk::from_blocks(index, heights.map(block).collect())
    }

    /// Helper to construct a CompactTx with known outputs and actions.
    fn tx_with_outputs_and_actions(outputs: u32, actions: u32) -> CompactTx {
        CompactTx {
            outputs: (0..outputs).map(|_| CompactSaplingOutput::default()).collect(),
            actions: (0..actions).map(|_| CompactOrchardAction::default()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn estimated_bytes_counts_encoded_blocks() {
        let c = chunk_of(0, 1..=10);
        assert!(c.estimated_bytes > 10 * 32, "must at least cover the hashes");
        assert_eq!(c.start_height(), Some(1));
        assert_eq!(c.end_height(), Some(10));
    }

    #[tokio::test]
    async fn queue_blocks_producer_when_budget_exhausted() {
        let c1 = chunk_of(0, 1..=10);
        let budget = c1.estimated_bytes + 1; // fits exactly one chunk
        let (tx, mut rx) = chunk_queue(budget);

        tx.send(c1).await.expect("first send fits");

        let c2 = chunk_of(1, 11..=20);
        let second = tx.send(c2);
        // Budget exhausted -> second send must be pending until we consume.
        tokio::select! {
            _ = second => panic!("second send must block while budget is held"),
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }

        // Consume + drop the first chunk's permit -> budget freed.
        let (got, permit, _boundary) = rx.recv().await.expect("first chunk");
        assert_eq!(got.index, 0);
        drop(permit);

        let c2 = chunk_of(1, 11..=20);
        tokio::time::timeout(Duration::from_secs(1), tx.send(c2))
            .await
            .expect("send unblocks after consumer releases budget")
            .expect("send ok");
    }

    #[tokio::test]
    async fn oversized_chunk_clamps_instead_of_deadlocking() {
        let big = chunk_of(0, 1..=100);
        let (tx, mut rx) = chunk_queue(8); // budget far below one chunk
        tokio::time::timeout(Duration::from_secs(1), tx.send(big))
            .await
            .expect("clamped send completes")
            .expect("send ok");
        assert!(rx.recv().await.is_some());
    }

    #[tokio::test]
    async fn recv_returns_none_when_sender_dropped() {
        let (tx, mut rx) = chunk_queue(1024);
        drop(tx);
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn zero_budget_degenerates_to_serial_not_deadlock() {
        let (tx, mut rx) = chunk_queue(0);
        tokio::time::timeout(Duration::from_secs(1), tx.send(chunk_of(0, 1..=3)))
            .await
            .expect("send completes under zero budget")
            .expect("send ok");
        assert!(rx.recv().await.is_some());
    }

    #[test]
    fn chunk_outputs_counts_vtx_outputs_and_actions() {
        // Build two blocks with known vtx contents.
        let blocks = vec![
            CompactBlock {
                height: 1,
                hash: vec![1; 32],
                vtx: vec![
                    tx_with_outputs_and_actions(3, 2), // 3 outputs + 2 actions = 5
                    tx_with_outputs_and_actions(1, 0), // 1 output + 0 actions = 1
                ],
                ..Default::default()
            },
            CompactBlock {
                height: 2,
                hash: vec![2; 32],
                vtx: vec![
                    tx_with_outputs_and_actions(0, 4), // 0 outputs + 4 actions = 4
                ],
                ..Default::default()
            },
        ];
        // Expected: 5 + 1 + 4 = 10
        let chunk = Chunk::from_blocks(0, blocks);
        assert_eq!(chunk.outputs, 10, "outputs must sum sapling outputs + orchard actions");
    }
}
