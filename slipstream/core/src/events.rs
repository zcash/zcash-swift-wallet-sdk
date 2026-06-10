//! Engine → shell surface: a polled `Snapshot` plus a drained `Event` ring
//! (decision D8 in docs/slipstream/ROADMAP.md). Fields grow in P3; keep
//! both types additive (`#[non_exhaustive]`).

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// Shared engine progress for poll-based consumers (decision D8).
///
/// All counters are monotonic during one sync pass; `Relaxed` ordering is
/// sufficient because no cross-counter invariants are promised to readers
/// (each field is independent; the consumer only needs an eventually-consistent
/// view for UI display, not a fully-consistent snapshot).
///
/// Wrap in `Arc<Progress>` and pass `Some(arc)` to `engine::sync_once` to
/// receive live updates. `None` disables all progress tracking with zero overhead.
#[derive(Debug, Default)]
pub struct Progress {
    /// Current chain tip height as reported by the server.
    pub chain_tip: AtomicU64,
    /// Number of compact blocks fetched so far.
    pub fetched_blocks: AtomicU64,
    /// Number of compact blocks scanned so far.
    pub scanned_blocks: AtomicU64,
    /// Number of transactions enhanced (decrypt_and_store) so far.
    pub enhanced_txs: AtomicU64,
    /// End height of the range currently being processed (inclusive).
    pub current_range_end: AtomicU64,
    /// Number of reorg recoveries (truncate + re-suggest) performed.
    pub reorgs_recovered: AtomicU64,
}

impl Progress {
    /// Bump `fetched_blocks` by `n` (Relaxed — poll-only, no ordering guarantee).
    #[inline]
    pub fn add_fetched(&self, n: u64) {
        self.fetched_blocks.fetch_add(n, Ordering::Relaxed);
    }

    /// Bump `scanned_blocks` by `n`.
    #[inline]
    pub fn add_scanned(&self, n: u64) {
        self.scanned_blocks.fetch_add(n, Ordering::Relaxed);
    }

    /// Bump `enhanced_txs` by `n`.
    #[inline]
    pub fn add_enhanced(&self, n: u64) {
        self.enhanced_txs.fetch_add(n, Ordering::Relaxed);
    }

    /// Set `chain_tip` (Relaxed store).
    #[inline]
    pub fn set_chain_tip(&self, tip: u64) {
        self.chain_tip.store(tip, Ordering::Relaxed);
    }

    /// Set `current_range_end` (Relaxed store).
    #[inline]
    pub fn set_range_end(&self, end: u64) {
        self.current_range_end.store(end, Ordering::Relaxed);
    }

    /// Bump `reorgs_recovered` by 1.
    #[inline]
    pub fn add_reorg(&self) {
        self.reorgs_recovered.fetch_add(1, Ordering::Relaxed);
    }

    /// Read `chain_tip` (Relaxed load).
    #[inline]
    pub fn chain_tip(&self) -> u64 {
        self.chain_tip.load(Ordering::Relaxed)
    }

    /// Read `fetched_blocks` (Relaxed load).
    #[inline]
    pub fn fetched(&self) -> u64 {
        self.fetched_blocks.load(Ordering::Relaxed)
    }

    /// Read `scanned_blocks` (Relaxed load).
    #[inline]
    pub fn scanned(&self) -> u64 {
        self.scanned_blocks.load(Ordering::Relaxed)
    }

    /// Read `enhanced_txs` (Relaxed load).
    #[inline]
    pub fn enhanced(&self) -> u64 {
        self.enhanced_txs.load(Ordering::Relaxed)
    }

    /// Read `current_range_end` (Relaxed load).
    #[inline]
    pub fn range_end(&self) -> u64 {
        self.current_range_end.load(Ordering::Relaxed)
    }

    /// Read `reorgs_recovered` (Relaxed load).
    #[inline]
    pub fn reorgs(&self) -> u64 {
        self.reorgs_recovered.load(Ordering::Relaxed)
    }
}

/// Convenience alias used throughout the engine.
pub type ProgressArc = Arc<Progress>;

/// Which resource currently bounds throughput (honest-ETA reporting).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bound {
    Download,
    Cpu,
    Commit,
    Idle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncMode {
    /// Foreground restore: all cores, large buffers.
    Sprint,
    /// Foreground catch-up.
    Cruise,
    /// Background slice: minimal footprint, checkpoint-eager.
    Drip,
}

/// Point-in-time engine state; cheap to clone out for UI polling.
#[derive(Clone, Debug, Default, PartialEq)]
#[non_exhaustive]
pub struct Snapshot {
    pub chain_tip: u32,
    pub fully_scanned_height: u32,
    /// 0.0..=1.0 across the whole wallet recovery window.
    pub coverage: f32,
    pub download_bytes_per_sec: u64,
    pub scan_outputs_per_sec: u64,
    pub bound: Option<Bound>,
}

/// Engine lifecycle/progress events, drained by the platform shell.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Event {
    Started { mode: SyncMode },
    Progress(Snapshot),
    Finished { fully_scanned_height: u32 },
    Failed { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_default_is_idle_zeroes() {
        let s = Snapshot::default();
        assert_eq!(s.coverage, 0.0);
        assert_eq!(s.bound, None);
    }

    #[test]
    fn progress_counters_bump_and_read() {
        let p = Progress::default();

        // Initial state: all zeros.
        assert_eq!(p.chain_tip(), 0);
        assert_eq!(p.fetched(), 0);
        assert_eq!(p.scanned(), 0);
        assert_eq!(p.enhanced(), 0);
        assert_eq!(p.range_end(), 0);
        assert_eq!(p.reorgs(), 0);

        // Set helpers.
        p.set_chain_tip(3_373_435);
        assert_eq!(p.chain_tip(), 3_373_435);

        p.set_range_end(3_323_500);
        assert_eq!(p.range_end(), 3_323_500);

        // Additive helpers.
        p.add_fetched(1_000);
        p.add_fetched(500);
        assert_eq!(p.fetched(), 1_500);

        p.add_scanned(800);
        assert_eq!(p.scanned(), 800);

        p.add_enhanced(3);
        assert_eq!(p.enhanced(), 3);

        p.add_reorg();
        p.add_reorg();
        assert_eq!(p.reorgs(), 2);
    }

    #[test]
    fn progress_arc_shared_across_threads() {
        use std::sync::Arc;
        use std::thread;

        let p = Arc::new(Progress::default());
        let p2 = Arc::clone(&p);

        let handle = thread::spawn(move || {
            p2.add_fetched(42);
        });
        handle.join().expect("thread panicked");

        // Our thread adds 10; the spawned thread adds 42: total = 52.
        p.add_fetched(10);
        assert_eq!(p.fetched_blocks.load(Ordering::Relaxed), 52);
    }
}
