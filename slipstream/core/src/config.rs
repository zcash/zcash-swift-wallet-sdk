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
    /// When `Some(ms)`, the scan splits fetch-chunks into time-targeted sub-batches
    /// (~ms each) for finer commits and progress updates on slow devices — at the cost
    /// of one full `put_blocks` commit + shardtree checkpoint per sub-batch (measured
    /// ≈1.5–2s fixed on A10-class hardware).
    ///
    /// `None` = one `scan_cached_blocks` call per fetch chunk (default; fastest).
    pub scan_batch_target_ms: Option<u64>,
}

impl EngineConfig {
    pub const DEFAULT_FETCH_STREAMS: usize = 4;
    pub const DEFAULT_CHUNK_BLOCKS: u32 = 10_000;
    pub const DEFAULT_MEMORY_BUDGET: usize = 256 * 1024 * 1024;

    pub fn new(network: Network, wallet_db_path: PathBuf, endpoint: Endpoint) -> Self {
        Self {
            network,
            wallet_db_path,
            endpoint,
            fetch_streams: Self::DEFAULT_FETCH_STREAMS,
            chunk_blocks: Self::DEFAULT_CHUNK_BLOCKS,
            memory_budget_bytes: Self::DEFAULT_MEMORY_BUDGET,
            scan_batch_target_ms: None,
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
        if let Some(ms) = self.scan_batch_target_ms
            && ms < 500
        {
            return Err(SlipstreamError::Config(
                "scan_batch_target_ms must be >= 500 ms".into(),
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
        assert!(config().validate().is_ok());
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
}
