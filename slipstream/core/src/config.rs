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
    /// Requires `sparse_persistence` (validated). Default **true** since
    /// 2026-06-12 (oracle-clean at all levels: hermetic + darkside real-notes +
    /// mainnet; darkside 14/14 incl. write-behind reorg/spendability variants;
    /// Mac A/B ~9% with flag-off path identical). CLI `--write-behind false`
    /// is the kill switch.
    pub write_behind: bool,

    /// B0 (Phase B): compute the Orchard subtree combines on the GPU. Requires
    /// `sparse_persistence` and the `gpu` cargo feature. Default off; the CPU path
    /// is byte-for-byte identical when off (kill switch: `--gpu-subtree false`).
    pub gpu_subtree: bool,

    /// v0.4 P0 bench (spec §3.1): when set, the engine writes a machine-readable
    /// end-of-pass `BenchSummary` JSON (stage split + shard census) to this path —
    /// consumed by `slipstream-cli bench` and bench-ios. `None` (default) = off.
    pub bench_json_path: Option<PathBuf>,

    /// v0.4 Plan A (spec §4): graft server-provided subtree roots for note-free
    /// shards instead of computing them locally. Requires `sparse_persistence`.
    /// Default off until the P3 device gates pass (spec §2 policy); kill switch
    /// semantics match gpu_subtree — off = byte-for-byte today's path.
    pub graft_subtree: bool,

    /// v0.4 sampling verify (spec §4 trust): every Nth graftable shard is BUILT
    /// anyway and its computed root compared to the server root — a mismatch is
    /// logged loudly and the BUILT shard wins (fallback beats trust). 0 = off,
    /// 1 = verify every graft (the full-audit mode used for validation runs).
    /// Deterministic by shard index (reproducible; no RNG in the hot path).
    pub graft_verify_sample: u32,

    /// v0.4 Plan B (spec §5): batch-affine Orchard combine — all of a fragment's
    /// combines computed level-synchronously with shared Montgomery inversions
    /// (~12× the scalar combine in the probe), byte-identical output (KAT +
    /// lookup_build gate). Applies to every Orchard build incl. the segments
    /// that survive grafting. Default off until the P3/P4 device A-B.
    pub batch_combine: bool,

    /// Persist-pipelining: max unpersisted units (in-flight + queued) before the scan
    /// side blocks. `1` = legacy strict depth-1 backpressure (byte-for-byte identical).
    /// Higher lets scan run further ahead so more persist hides behind scan (~22%
    /// headroom on modern devices); cost is up to `persist_depth` buffered units in RAM.
    /// Only affects the write-behind path; the committed `data.db` is identical at any
    /// depth (persist stays serial + in-order). Auto-scaled per device RAM in R4.
    pub persist_depth: usize,
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
            write_behind: true,
            gpu_subtree: false,
            bench_json_path: None,
            graft_subtree: false,
            graft_verify_sample: 16,
            batch_combine: false,
            persist_depth: 1,
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
        if self.graft_subtree && !self.sparse_persistence {
            return Err(SlipstreamError::Config(
                "graft_subtree requires sparse_persistence (the graft verdict lives in the sparse build path)".into(),
            ));
        }
        if self.graft_subtree && !self.write_behind {
            return Err(SlipstreamError::Config(
                "graft_subtree requires write_behind (the graft plan runs in the persist lane; the inline path never grafts — v0.4 plan Task 7b rev 2)".into(),
            ));
        }
        if self.gpu_subtree && !self.sparse_persistence {
            return Err(SlipstreamError::Config(
                "gpu_subtree requires sparse_persistence (the GPU build replaces the sparse subtree build)".into(),
            ));
        }
        if self.persist_depth == 0 || self.persist_depth > 64 {
            return Err(SlipstreamError::Config(
                "persist_depth must be in 1..=64".into(),
            ));
        }
        Ok(())
    }

    /// Derated budgets for <3 GiB devices (A10-class, 2 GiB shared with the GPU).
    /// Sizing from the T6.8-S field record (STATE Blockers): a 64 MiB wire budget
    /// ≈ 128–192 MiB decoded (2–3× amplification) + the per-range sparse tree +
    /// allocator HWM stays well under the ~1.4 GiB practical jetsam line on a 2 GiB
    /// device. The 4 MiB split keeps the AheadGate (8×split = 32 MiB) and the
    /// per-sub-chunk RAM proportionally small.
    pub const SMALL_DEVICE_MEMORY_BUDGET: usize = 64 * 1024 * 1024;
    pub const SMALL_DEVICE_CHUNK_SPLIT_BYTES: usize = 4 * 1024 * 1024;
    /// Devices reporting less physical memory than this are derated.
    pub const SMALL_DEVICE_THRESHOLD_BYTES: u64 = 3 << 30;

    /// Applies device-memory-aware budget scaling (T8.4). `total_memory_bytes` is the
    /// host's physical memory (Swift passes `ProcessInfo.physicalMemory` via the FFI
    /// open hint; the CLI uses an explicit `--memory-budget-bytes` flag instead); 0 =
    /// unknown → defaults unchanged. Only ever DERATES — explicit field overrides set
    /// after this call still win.
    #[must_use]
    pub fn scaled_for_device_memory(mut self, total_memory_bytes: u64) -> Self {
        if total_memory_bytes > 0 && total_memory_bytes < Self::SMALL_DEVICE_THRESHOLD_BYTES {
            self.memory_budget_bytes = Self::SMALL_DEVICE_MEMORY_BUDGET;
            self.chunk_split_bytes = Self::SMALL_DEVICE_CHUNK_SPLIT_BYTES;
        }
        self
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
        // T6.9 flip (2026-06-12): write-behind defaults ON (oracle-clean at all
        // levels; darkside 14/14 incl. WB variants; kill switch retained).
        assert!(c.write_behind);
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

    #[test]
    fn device_memory_scaling_derates_small_devices() {
        let c = config();
        // Unknown (0) and big devices keep defaults.
        assert_eq!(c.clone().scaled_for_device_memory(0).memory_budget_bytes, EngineConfig::DEFAULT_MEMORY_BUDGET);
        assert_eq!(c.clone().scaled_for_device_memory(8 << 30).chunk_split_bytes, EngineConfig::DEFAULT_CHUNK_SPLIT_BYTES);
        assert_eq!(c.clone().scaled_for_device_memory(3 << 30).memory_budget_bytes, EngineConfig::DEFAULT_MEMORY_BUDGET);
        // Sub-3 GiB devices (A10 iPad = 2 GiB) derate to the Blockers sizing.
        let small = c.clone().scaled_for_device_memory((3 << 30) - 1);
        assert_eq!(small.memory_budget_bytes, EngineConfig::SMALL_DEVICE_MEMORY_BUDGET);
        assert_eq!(small.chunk_split_bytes, EngineConfig::SMALL_DEVICE_CHUNK_SPLIT_BYTES);
        small.validate().expect("derated config must validate");
    }
}
