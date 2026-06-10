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
}
