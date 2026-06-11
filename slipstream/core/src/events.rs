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
    /// Total blocks in the current pass. Set (not accumulated) by the scheduler each
    /// time it calls `suggest_scan_ranges`: the new value is `scanned_so_far_in_pass +
    /// sum(block-lengths of ALL returned ranges)`. Because all ranges for a pass are
    /// returned together by `suggest_scan_ranges`, the denominator is complete from the
    /// very first suggestion — no snap-back when Historic ranges are revealed.
    /// Updated via `set_pass_total(n)`.
    pub pass_total_blocks: AtomicU64,
    /// Spendable hint latch: 0 = funds not yet spendable; 1 = a ChainTip-priority range
    /// completed scanning (≈ SBS "funds-spendable" semantics). Latches to 1 and never
    /// resets to 0 within a pass. Read with `spendable()`.
    pub spendable_hint: AtomicU64,
    /// Number of suggested ranges whose scan+enhancement has completed in the current
    /// pass. Monotonically incremented by the scheduler after each range finishes
    /// (scan + per-range enhancement). Used by Swift to trigger a balance-summary
    /// fetch at each range boundary while Syncing.
    pub ranges_completed: AtomicU64,
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

    /// Set `pass_total_blocks` to `n` (STORE, not add). Called by the scheduler each
    /// time `suggest_scan_ranges` returns: the new value is `scanned_so_far_in_pass +
    /// sum(block-lengths of all returned ranges)`. Because the scheduler computes the
    /// whole-pass denominator in one shot after every re-suggest, the denominator is
    /// complete from the first suggestion and never causes a % snap-back when Historic
    /// ranges appear. Supersedes the old `add_pass_total` (accumulated per-range),
    /// which caused the 0→100→60% oscillation observed on the user's iPad A10 run.
    #[inline]
    pub fn set_pass_total(&self, n: u64) {
        self.pass_total_blocks.store(n, Ordering::Relaxed);
    }

    /// Deprecated: use `set_pass_total` instead.  Retained for any call sites that
    /// have not yet been updated; calls store (not add) to avoid accumulated-per-range
    /// semantics that caused the % snap-back bug.
    #[inline]
    #[deprecated(note = "use set_pass_total (store semantics); add_pass_total (accumulate) caused % snap-back")]
    pub fn add_pass_total(&self, n: u64) {
        // Preserve behaviour for callers that haven't migrated: treat as set.
        self.pass_total_blocks.store(n, Ordering::Relaxed);
    }

    /// Latch `spendable_hint` to 1. Called by the scheduler after a `ChainTip`-priority
    /// range completes scanning (≈ SBS funds-spendable semantics). Never resets within a pass.
    #[inline]
    pub fn set_spendable(&self) {
        self.spendable_hint.store(1, Ordering::Relaxed);
    }

    /// Bump `ranges_completed` by 1. Called by the scheduler after each suggested range's
    /// scan + per-range enhancement completes. Swift observes this counter and triggers a
    /// single balance-summary fetch at each range boundary (F2 — boundary balance refresh).
    #[inline]
    pub fn add_ranges_completed(&self) {
        self.ranges_completed.fetch_add(1, Ordering::Relaxed);
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

    /// Read `pass_total_blocks` (Relaxed load).
    #[inline]
    pub fn pass_total(&self) -> u64 {
        self.pass_total_blocks.load(Ordering::Relaxed)
    }

    /// Read `spendable_hint` (Relaxed load). Returns 1 when spendable, 0 otherwise.
    #[inline]
    pub fn spendable(&self) -> u64 {
        self.spendable_hint.load(Ordering::Relaxed)
    }

    /// Read `ranges_completed` (Relaxed load).
    #[inline]
    pub fn ranges_completed(&self) -> u64 {
        self.ranges_completed.load(Ordering::Relaxed)
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
        assert_eq!(p.pass_total(), 0);
        assert_eq!(p.spendable(), 0);
        assert_eq!(p.ranges_completed(), 0);

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
    fn progress_pass_total_and_spendable_hint() {
        let p = Progress::default();

        // Initial state: both zero.
        assert_eq!(p.pass_total(), 0);
        assert_eq!(p.spendable(), 0);

        // set_pass_total stores (not accumulates) — F1 whole-pass denominator fix.
        // First suggest: scanned_so_far=0, sum_of_ranges=15_000 → store 15_000.
        p.set_pass_total(15_000);
        assert_eq!(p.pass_total(), 15_000);
        // Re-suggest after first range (scanned_so_far=10_000 + remaining 5_000) → still 15_000.
        p.set_pass_total(15_000);
        assert_eq!(p.pass_total(), 15_000, "re-suggest with same total stays stable");
        // Re-suggest exposes more ranges: new total = 20_000 → store overwrites.
        p.set_pass_total(20_000);
        assert_eq!(p.pass_total(), 20_000, "set_pass_total must overwrite, not add");

        // spendable latches to 1 and stays there.
        assert_eq!(p.spendable(), 0, "not yet spendable before set_spendable()");
        p.set_spendable();
        assert_eq!(p.spendable(), 1, "spendable must be 1 after set_spendable()");
        p.set_spendable(); // idempotent
        assert_eq!(p.spendable(), 1, "set_spendable is idempotent");
    }

    #[test]
    fn pass_total_is_whole_pass() {
        // Simulates the F1 scheduler logic:
        //   - suggest returns [ChainTip(100), Historic(200)] → total = 0+100+200 = 300
        //   - after scanning ChainTip (100 blocks), re-suggest returns [Historic(200)]
        //     → scanned_so_far = 100, remaining = 200 → total = 100+200 = 300 (unchanged)
        //   - after scanning Historic (200 blocks), queue empty → done.
        // The denominator must be 300 throughout — no snap-back.
        let p = Progress::default();

        // First suggest: 0 scanned + 100 (ChainTip) + 200 (Historic) = 300.
        p.set_pass_total(300);
        assert_eq!(p.pass_total(), 300, "whole-pass denominator set on first suggest");

        // Scan ChainTip range.
        p.add_scanned(100);

        // Re-suggest: 100 scanned + 200 remaining = 300 → same value; store is idempotent.
        p.set_pass_total(300);
        assert_eq!(p.pass_total(), 300, "denominator stays 300 after re-suggest");

        // At this point, progress = 100/300 ≈ 33.3% — no 100→60% snap-back.
        let ratio = p.scanned() as f64 / p.pass_total() as f64;
        assert!((ratio - 1.0 / 3.0).abs() < 1e-9, "progress must be ~33.3% mid-pass");

        // Scan Historic range.
        p.add_scanned(200);
        let final_ratio = p.scanned() as f64 / p.pass_total() as f64;
        assert!((final_ratio - 1.0).abs() < 1e-9, "progress must be 100% when all ranges done");
    }

    #[test]
    fn counter_progress_ratio() {
        // scanned / max(pass_total, 1) is used in Swift tickPoll.
        // Mirror the formula here to verify the Rust side provides the right inputs.
        let p = Progress::default();
        p.set_pass_total(10_000);
        p.add_scanned(5_000);

        let ratio = p.scanned() as f64 / p.pass_total().max(1) as f64;
        assert!((ratio - 0.5).abs() < 1e-9, "5000/10000 must be 0.5");

        // pass_total == 0 edge: denominator is max(0, 1) = 1 → ratio = 0.
        let p2 = Progress::default();
        let ratio2 = p2.scanned() as f64 / p2.pass_total().max(1) as f64;
        assert_eq!(ratio2, 0.0, "0 scanned / 1 (clamped) must be 0.0");
    }

    #[test]
    fn ranges_completed_increments() {
        let p = Progress::default();
        assert_eq!(p.ranges_completed(), 0, "initial value must be 0");

        p.add_ranges_completed();
        assert_eq!(p.ranges_completed(), 1, "must be 1 after first range");

        p.add_ranges_completed();
        assert_eq!(p.ranges_completed(), 2, "must be 2 after second range");

        // Monotonic: never resets to 0 within a pass.
        for _ in 0..10 {
            p.add_ranges_completed();
        }
        assert_eq!(p.ranges_completed(), 12, "must accumulate across all ranges");
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
