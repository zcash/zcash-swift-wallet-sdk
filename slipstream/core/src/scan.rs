//! Scan driver: consumes ordered chunks, runs upstream scan_cached_blocks once
//! per chunk (bounded memory: one commit per chunk), and hides the per-chunk
//! treestate RPC by prefetching the NEXT boundary state while the current
//! chunk scans (spike T2.3 outcome: ChainState must come from the server;
//! prefetch makes its latency invisible).

use tracing::{debug, info};
use zcash_client_backend::data_api::chain::scan_cached_blocks;
use zcash_protocol::consensus::BlockHeight;

use crate::{
    block_source::MemBlockSource,
    chunk::ChunkQueueReceiver,
    error::SlipstreamError,
    grpc::{self, LwdClient},
    wallet_session::WalletSession,
};

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
pub async fn scan_chunks(
    session: &mut WalletSession,
    client: &mut LwdClient,
    range_start: u64,
    mut rx: ChunkQueueReceiver,
) -> Result<ScanStats, SlipstreamError> {
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
        // The final prefetch (after the last chunk) resolves a treestate nobody consumes — harmless.
        let prefetch = tokio::spawn({
            let mut c = client.clone();
            async move { grpc::get_tree_state(&mut c, chunk_end).await }
        });

        let from_state = next_state
            .to_chain_state()
            .map_err(|e| SlipstreamError::Wallet(format!("chain state: {e}")))?;
        let network = session.network;
        let len = chunk.blocks.len();

        let summary = {
            let source = MemBlockSource::new(&chunk);
            // Binding note 3: wrap the synchronous scan_cached_blocks call in block_in_place
            // so it does not starve the tokio multi-thread runtime (SQLite + rayon decryption
            // are synchronous/CPU-bound; block_in_place is correct here because spawn_blocking
            // would require 'static, which &mut session does not satisfy; multi-thread runtime
            // is guaranteed by the CLI's #[tokio::main] with default flavor = multi_thread).
            tokio::task::block_in_place(|| {
                scan_cached_blocks(
                    &network,
                    &source,
                    session.db_mut(),
                    BlockHeight::from(chunk_start as u32),
                    &from_state,
                    len,
                )
            })
            .map_err(|e| SlipstreamError::Wallet(format!("scan_cached_blocks: {e}")))?
        };

        stats.blocks += len as u64;
        stats.chunks += 1;
        // Binding note 2: accessor names confirmed against registry
        // zcash_client_backend-0.22.0/src/data_api/chain.rs:481,499 —
        // received_sapling_note_count() and received_orchard_note_count() exist exactly as named.
        stats.sapling_received += summary.received_sapling_note_count() as u64;
        stats.orchard_received += summary.received_orchard_note_count() as u64;
        debug!(chunk_start, chunk_end, len, "chunk scanned");

        drop(permit); // release byte budget only after the scan committed

        // Await the prefetch result; it was running concurrently with scan_cached_blocks above.
        next_state = prefetch
            .await
            .map_err(|e| SlipstreamError::Transport(format!("prefetch task: {e}")))??;
    }
    info!(blocks = stats.blocks, chunks = stats.chunks, "scan done");
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
