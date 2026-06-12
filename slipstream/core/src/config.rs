//! Engine configuration. Defaults are the Sprint-mode values from
//! docs/SLIPSTREAM_DESIGN.md §4; modes adjust them later (P8).

use std::path::PathBuf;

use zcash_protocol::consensus::Network;

use crate::error::SlipstreamError;

/// lightwalletd endpoint.
// Deliberately exhaustive: an endpoint is exactly (host, port, tls).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

impl Endpoint {
    /// `http(s)://host:port` — scheme chosen by the `tls` flag.
    pub fn uri(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        format!("{}://{}:{}", scheme, self.host, self.port)
    }
}

/// Engine configuration. Construct via [`EngineConfig::new`]; fields are public tunables.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct EngineConfig {
    pub network: Network,
    /// Path to the (existing, zcash_client_sqlite-managed) wallet database.
    pub wallet_db_path: PathBuf,
    pub endpoint: Endpoint,
    /// Concurrent GetBlockRange sub-streams (P1).
    pub fetch_streams: usize,
    /// Target blocks per in-memory chunk / per scan call (P1/P2).
    pub chunk_blocks: u32,
    /// Upper bound for in-flight downloaded block data.
    pub memory_budget_bytes: usize,
    /// Byte budget per emitted fetch sub-chunk (T6.8-S): each fetch worker splits
    /// its streamed plan chunk into sub-chunks of at most ~this many (estimated
    /// wire) bytes. Normal-era 10k-block chunks (~1–6 MB) stay single sub-chunks;
    /// spam-era ("sandblasting", mainnet ~1.70M–2.00M: 0.3–2.5M outputs per 10k
    /// blocks ≈ hundreds of MB) chunks split into ~250–500-block sub-chunks
    /// automatically — density-adaptive, no hardcoded heights. Smaller values
    /// bound memory and make fetch retry/resume granular at the cost of more
    /// scan commits. Must be >= 1 MiB.
    pub chunk_split_bytes: usize,
    /// When `Some(ms)`, the scan splits fetch-chunks into time-targeted sub-batches
    /// (~ms each) for finer commits and progress updates on slow devices — at the cost
    /// of one full `put_blocks` commit + shardtree checkpoint per sub-batch (measured
    /// ≈1.5–2s fixed on A10-class hardware).
    ///
    /// `None` = one `scan_cached_blocks` call per fetch chunk (default; fastest).
    pub scan_batch_target_ms: Option<u64>,
    /// Run an interleaved (non-fatal) enhancement pass every N completed chunks
    /// during a range scan, so found transactions surface continuously instead of
    /// only at range boundaries (T6.1). Must be >= 1; the per-range and final
    /// post-loop enhancement runs are unaffected backstops.
    pub enhance_every_chunks: u32,
    /// Persist scan results via the sparse in-memory commitment-tree path
    /// (P6): upstream scan kernel unchanged; put_blocks tree work runs against
    /// an in-memory ShardTree flushed once per chunk. Default **true** as of
    /// T6.6 — oracle-clean per T6.4/T6.5 (hermetic + darkside + mainnet
    /// oracles IDENTICAL; reorg + truncate compatibility verified). Kill switch
    /// retained: set `sparse_persistence = false` to revert to the upstream
    /// path if a regression is found.
    pub sparse_persistence: bool,
    /// T6.9 L4b: depth-1 write-behind persistence pipelining. When `true`,
    /// chunk N's database commit (rows + tree + flush, one atomic transaction —
    /// the exact `sparse_put_blocks` logic, strictly serial) runs on a persist
    /// lane OVERLAPPED with chunk N+1's decryption; the scan's DB reads are
    /// served from a pending-aware facade (see `persist::WriteBehindFacade`).
    /// Requires `sparse_persistence` (validated). Default **false** pending
    /// field validation; CLI `--write-behind`.
    pub write_behind: bool,
}

impl EngineConfig {
    pub const DEFAULT_FETCH_STREAMS: usize = 4;
    pub const DEFAULT_CHUNK_BLOCKS: u32 = 10_000;
    pub const DEFAULT_MEMORY_BUDGET: usize = 256 * 1024 * 1024;
    /// 8 MiB: comfortably above a normal-era 10k-block chunk (~1–6 MB wire), so
    /// the default path emits exactly one sub-chunk per plan chunk; a
    /// sandblasting-era chunk (~hundreds of MB) splits into many (T6.8-S).
    pub const DEFAULT_CHUNK_SPLIT_BYTES: usize = 8 * 1024 * 1024;
    /// Run an interleaved enhancement pass every 3 completed chunks by default (T6.1).
    pub const DEFAULT_ENHANCE_EVERY_CHUNKS: u32 = 3;

    pub fn new(network: Network, wallet_db_path: PathBuf, endpoint: Endpoint) -> Self {
        Self {
            network,
            wallet_db_path,
            endpoint,
            fetch_streams: Self::DEFAULT_FETCH_STREAMS,
            chunk_blocks: Self::DEFAULT_CHUNK_BLOCKS,
            memory_budget_bytes: Self::DEFAULT_MEMORY_BUDGET,
            chunk_split_bytes: Self::DEFAULT_CHUNK_SPLIT_BYTES,
            scan_batch_target_ms: None,
            enhance_every_chunks: Self::DEFAULT_ENHANCE_EVERY_CHUNKS,
            sparse_persistence: true,
            write_behind: false,
        }
    }

    pub fn validate(&self) -> Result<(), SlipstreamError> {
        if self.endpoint.host.is_empty() {
            return Err(SlipstreamError::Config("endpoint host is empty".into()));
        }
        if self.fetch_streams == 0 {
            return Err(SlipstreamError::Config("fetch_streams must be >= 1".into()));
        }
        if self.chunk_blocks < 100 {
            return Err(SlipstreamError::Config("chunk_blocks must be >= 100".into()));
        }
        if self.memory_budget_bytes < 16 * 1024 * 1024 {
            return Err(SlipstreamError::Config("memory_budget_bytes must be >= 16 MiB".into()));
        }
        if self.chunk_split_bytes < 1024 * 1024 {
            return Err(SlipstreamError::Config("chunk_split_bytes must be >= 1 MiB".into()));
        }
        if let Some(ms) = self.scan_batch_target_ms
            && ms < 500
        {
            return Err(SlipstreamError::Config(
                "scan_batch_target_ms must be >= 500 ms".into(),
            ));
        }
        if self.enhance_every_chunks == 0 {
            return Err(SlipstreamError::Config(
                "enhance_every_chunks must be >= 1".into(),
            ));
        }
        if self.write_behind && !self.sparse_persistence {
            return Err(SlipstreamError::Config(
                "write_behind requires sparse_persistence (the deferred commit runs the sparse put_blocks path)".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> Endpoint {
        Endpoint { host: "zec.rocks".into(), port: 443, tls: true }
    }

    fn config() -> EngineConfig {
        EngineConfig::new(Network::MainNetwork, PathBuf::from("/tmp/data.db"), endpoint())
    }

    #[test]
    fn defaults_are_valid() {
        let c = config();
        assert!(c.validate().is_ok());
        assert_eq!(c.enhance_every_chunks, 3);
        // T6.6: sparse persistence defaults ON (oracle-clean, kill switch retained).
        assert!(c.sparse_persistence);
        // T6.8-S: byte-budgeted sub-chunk splitting defaults to 8 MiB.
        assert_eq!(c.chunk_split_bytes, 8 * 1024 * 1024);
        // T6.9: write-behind pipelining defaults OFF pending field validation.
        assert!(!c.write_behind);
    }

    #[test]
    fn write_behind_without_sparse_rejected() {
        let mut c = config();
        c.write_behind = true;
        c.sparse_persistence = false;
        assert!(matches!(c.validate(), Err(SlipstreamError::Config(_))));
    }

    #[test]
    fn write_behind_with_sparse_accepted() {
        let mut c = config();
        c.write_behind = true;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn tiny_chunk_split_bytes_rejected() {
        let mut c = config();
        c.chunk_split_bytes = 1024 * 1024 - 1;
        assert!(matches!(c.validate(), Err(SlipstreamError::Config(_))));
    }

    #[test]
    fn chunk_split_bytes_one_mib_accepted() {
        let mut c = config();
        c.chunk_split_bytes = 1024 * 1024;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn zero_streams_rejected() {
        let mut c = config();
        c.fetch_streams = 0;
        assert!(matches!(c.validate(), Err(SlipstreamError::Config(_))));
    }

    #[test]
    fn tiny_chunks_rejected() {
        let mut c = config();
        c.chunk_blocks = 99;
        assert!(matches!(c.validate(), Err(SlipstreamError::Config(_))));
    }

    #[test]
    fn empty_host_rejected() {
        let mut c = config();
        c.endpoint.host = String::new();
        assert!(matches!(c.validate(), Err(SlipstreamError::Config(_))));
    }

    #[test]
    fn tiny_memory_budget_rejected() {
        let mut c = config();
        c.memory_budget_bytes = 1024;
        assert!(matches!(c.validate(), Err(SlipstreamError::Config(_))));
    }

    #[test]
    fn uri_scheme_follows_tls_flag() {
        let mut e = endpoint();
        assert_eq!(e.uri(), "https://zec.rocks:443");
        e.tls = false;
        assert_eq!(e.uri(), "http://zec.rocks:443");
    }

    #[test]
    fn scan_batch_target_ms_below_500_rejected() {
        let mut c = config();
        c.scan_batch_target_ms = Some(499);
        assert!(matches!(c.validate(), Err(SlipstreamError::Config(_))));
    }

    #[test]
    fn scan_batch_target_ms_at_500_accepted() {
        let mut c = config();
        c.scan_batch_target_ms = Some(500);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn scan_batch_target_ms_none_accepted() {
        let c = config();
        assert!(c.validate().is_ok()); // None is the default, already tested via defaults_are_valid
    }

    #[test]
    fn enhance_every_chunks_zero_rejected() {
        let mut c = config();
        c.enhance_every_chunks = 0;
        assert!(matches!(c.validate(), Err(SlipstreamError::Config(_))));
    }

    #[test]
    fn enhance_every_chunks_one_accepted() {
        let mut c = config();
        c.enhance_every_chunks = 1;
        assert!(c.validate().is_ok());
    }
}
