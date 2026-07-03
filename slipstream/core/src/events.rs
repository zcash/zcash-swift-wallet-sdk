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
    // ── API v2 fields (ENGINE_API_V2.md §4.4) ──
    /// 1 while the current pass still has suggested ranges below the wallet's
    /// recover-until height (the restore backfill window); 0 otherwise. Written by the
    /// scheduler on every suggest round. The SNAPSHOT mapping forces 0 on terminal
    /// states (Done / Error) — the fail-safe latch that previously lived in the Swift
    /// SDK ("a dead pass can never wedge Restoring") now holds for every host.
    pub recovering: AtomicU64,
    /// Unix seconds of the last forward progress (any counter bump / pass start).
    /// The snapshot derives `stalled_seconds = now − this` while Syncing.
    pub last_progress_unix: AtomicU64,
    /// Session-monotonic progress floor in permille (0..=1000). The snapshot fetch-maxes
    /// the raw `scanned / pass_total` ratio into this and reports the floor, so reported
    /// progress NEVER regresses while the handle lives (subsumes the SDK's
    /// monotonicRecoveryProgress floor and its warm-start seeding: a follow-up catch-up
    /// pass holds the prior high-water mark instead of flashing back to 0%).
    pub progress_permille_floor: AtomicU64,
    /// [API v2.1 E-2/E-3] Count of successful `update_chain_tip` persists across the handle's
    /// life. Bumped by the ENGINE only (never by the E-3 open-time seed, which stores a
    /// persisted tip VALUE without proving freshness) — the FFI's `tip_fresh` fact latches
    /// when this counter has advanced since `start()`, i.e. "THIS run refreshed the tip",
    /// independent of whether the fetched tip happens to equal the persisted one.
    /// Monotonic per handle; deliberately NOT reset by [`Self::begin_pass`].
    pub tip_refreshes: AtomicU64,
    /// [API v2.1 E-4] Monotonic version of the wallet's STORED transaction set. Bumped exactly
    /// when the set changes: a transaction stored/updated by enhancement or the mempool
    /// monitor, a reconcile-linkage transition detected at a range boundary (the scheduler's
    /// `(tx_count, unreconciled_count)` signature moved), or a host submit-poke
    /// (`zcashlc_slipstream_notify_tx_change`). The HOST rule is one line: version moved →
    /// re-fetch + publish `foundTransactions` (replaces the SDK's counter-watch + SyncDone
    /// fallback + count-dedup strategy). The host's own reconcile-FILTER edge (`is_recovering`
    /// flips — visibility policy per API v2 §0) is deliberately NOT folded in here: the filter
    /// is host policy, so its edge is host-observed from the same snapshot.
    /// Monotonic per handle; deliberately NOT reset by [`Self::begin_pass`].
    pub tx_set_version: AtomicU64,
}

/// [API v2.1 E-5] Scope-expansion detection margin for the session progress floor: a
/// suggest-round seed this many permille (or more) BELOW the current floor means the scan
/// scope grew (import/rewind), not that progress regressed. See
/// [`Progress::rebaseline_floor_if_scope_expanded`].
pub const FLOOR_REBASELINE_EPSILON_PERMILLE: u64 = 50;

impl Progress {
    /// Bump `fetched_blocks` by `n` (Relaxed — poll-only, no ordering guarantee).
    #[inline]
    pub fn add_fetched(&self, n: u64) {
        self.fetched_blocks.fetch_add(n, Ordering::Relaxed);
        self.touch();
    }

    /// Bump `scanned_blocks` by `n`.
    #[inline]
    pub fn add_scanned(&self, n: u64) {
        self.scanned_blocks.fetch_add(n, Ordering::Relaxed);
        self.touch();
    }

    /// Bump `enhanced_txs` by `n`.
    #[inline]
    pub fn add_enhanced(&self, n: u64) {
        self.enhanced_txs.fetch_add(n, Ordering::Relaxed);
        self.touch();
    }

    /// Set `chain_tip` (Relaxed store). Stores a VALUE only — callers that just persisted a
    /// freshly-fetched server tip must also call [`Self::note_tip_refreshed`]; the E-3
    /// open-time seed calls this alone (a persisted tip is not proof of freshness).
    #[inline]
    pub fn set_chain_tip(&self, tip: u64) {
        self.chain_tip.store(tip, Ordering::Relaxed);
    }

    /// [API v2.1 E-2] Record that a sync pass successfully persisted a freshly-fetched
    /// server tip (`session.update_chain_tip` returned Ok). Drives the FFI `tip_fresh` fact.
    #[inline]
    pub fn note_tip_refreshed(&self) {
        self.tip_refreshes.fetch_add(1, Ordering::Relaxed);
    }

    /// Read the tip-refresh counter (see [`Self::note_tip_refreshed`]).
    #[inline]
    pub fn tip_refreshes(&self) -> u64 {
        self.tip_refreshes.load(Ordering::Relaxed)
    }

    /// [API v2.1 E-4] Record that the wallet's stored transaction set changed (see the
    /// `tx_set_version` field doc for the exact bump sites).
    #[inline]
    pub fn bump_tx_set_version(&self) {
        self.tx_set_version.fetch_add(1, Ordering::Relaxed);
        self.touch();
    }

    /// Read the tx-set version (see [`Self::bump_tx_set_version`]).
    #[inline]
    pub fn tx_set_version(&self) -> u64 {
        self.tx_set_version.load(Ordering::Relaxed)
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
    ///
    /// Monotonic per HANDLE (deliberately NOT reset by [`Self::begin_pass`]): Swift
    /// detects boundaries via a strict-greater comparison against its last-seen value,
    /// which only works if the counter never moves backwards while the handle lives.
    #[inline]
    pub fn add_ranges_completed(&self) {
        self.ranges_completed.fetch_add(1, Ordering::Relaxed);
        self.touch();
    }

    // ── API v2 (ENGINE_API_V2.md §4.4) ──

    /// Stamp `last_progress_unix` with the current wall-clock second. Called by every
    /// counter bump and at pass start; the snapshot derives stalledness from it.
    #[inline]
    pub fn touch(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.last_progress_unix.store(now, Ordering::Relaxed);
    }

    /// Scheduler: set whether the pass is still inside the recovery (restore backfill)
    /// window — i.e. suggested ranges remain below the wallet's recover-until height.
    #[inline]
    pub fn set_recovering(&self, recovering: bool) {
        self.recovering.store(u64::from(recovering), Ordering::Relaxed);
    }

    /// Read the live recovering flag (terminal-state forcing happens in the snapshot).
    #[inline]
    pub fn recovering(&self) -> bool {
        self.recovering.load(Ordering::Relaxed) != 0
    }

    /// Read `last_progress_unix`.
    #[inline]
    pub fn last_progress_unix_secs(&self) -> u64 {
        self.last_progress_unix.load(Ordering::Relaxed)
    }

    /// Fold `raw` (0..=1000) into the session-monotonic floor and return the floor.
    /// fetch_max keeps reported progress from ever regressing while the handle lives.
    #[inline]
    pub fn permille_floor(&self, raw: u64) -> u64 {
        let clamped = raw.min(1000);
        self.progress_permille_floor.fetch_max(clamped, Ordering::Relaxed);
        self.progress_permille_floor.load(Ordering::Relaxed)
    }

    /// [API v2.1 E-5] When a suggest round's GLOBAL seed lands materially BELOW the current
    /// session floor, the scan SCOPE EXPANDED under the floor's feet — an imported account
    /// with an older birthday, or a rewind re-growing the queue — and the old floor (folded
    /// to ~1000 by the previous scope's Done) would MASK the whole re-scan at ~100%. Reset
    /// the floor to the new truthful seed so the blessed permille reads a genuine climb.
    /// Normal operation can never trigger it: within one scope the seed is monotone (the
    /// queue only shrinks between suggest rounds) and tip drift moves it by <1‰ — the
    /// epsilon is 50× above that noise and far below any real expansion (an import drops
    /// the seed by hundreds of permille). Returns whether a re-baseline happened.
    pub fn rebaseline_floor_if_scope_expanded(&self, seed: u64) -> bool {
        let current = self.progress_permille_floor.load(Ordering::Relaxed);
        if seed.saturating_add(FLOOR_REBASELINE_EPSILON_PERMILLE) < current {
            self.progress_permille_floor.store(seed.min(1000), Ordering::Relaxed);
            return true;
        }
        false
    }

    /// Reset the per-pass RATIO counters at the start of a sync pass.
    ///
    /// The FFI handle outlives individual sync passes (Swift `prepare()` opens it once;
    /// `stop()`/`start()` reuse it across app background/foreground cycles), so without
    /// this reset a resumed pass would compute `scanned / pass_total` with a stale
    /// numerator from the previous pass — e.g. 100k stale scanned / 169k remaining
    /// = 59% at pass start, climbing past 100% (clamped) long before the pass is done.
    ///
    /// Resets: `scanned_blocks`, `fetched_blocks`, `pass_total_blocks`,
    /// `current_range_end`, and the `spendable_hint` latch (the new pass's ChainTip
    /// range re-latches it within seconds, mirroring old-SDK per-sync semantics).
    ///
    /// Deliberately NOT reset (monotonic per handle — Swift consumes these as deltas
    /// via strict-greater/last-seen comparisons): `enhanced_txs`, `ranges_completed`,
    /// `reorgs_recovered`. `chain_tip` is overwritten early in every pass anyway.
    pub fn begin_pass(&self) {
        self.scanned_blocks.store(0, Ordering::Relaxed);
        self.fetched_blocks.store(0, Ordering::Relaxed);
        self.pass_total_blocks.store(0, Ordering::Relaxed);
        self.current_range_end.store(0, Ordering::Relaxed);
        self.spendable_hint.store(0, Ordering::Relaxed);
        // v2: a new pass starts the stall clock fresh. `recovering` and the permille
        // floor are deliberately NOT reset — recovering is recomputed on the first
        // suggest round, and the floor is session-monotonic by contract (§4.4).
        self.touch();
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

    /// begin_pass resets the per-pass RATIO counters but preserves the monotonic
    /// delta counters Swift consumes via last-seen comparisons. Simulates an
    /// interrupted pass followed by a resume on the SAME handle (Swift prepare()
    /// opens once; stop()/start() reuse the handle).
    #[test]
    fn begin_pass_resets_ratio_counters_only() {
        let p = Progress::default();

        // Pass 1: interrupted mid-restore.
        p.set_chain_tip(3_374_188);
        p.add_fetched(120_000);
        p.add_scanned(100_000);
        p.set_pass_total(269_188);
        p.set_range_end(3_321_165);
        p.set_spendable();
        p.add_enhanced(20);
        p.add_ranges_completed();
        p.add_reorg();
        p.note_tip_refreshed();
        p.bump_tx_set_version();
        p.bump_tx_set_version();

        // Pass 2 begins (app foregrounded, start() on the same handle).
        p.begin_pass();

        // Ratio counters reset: scanned/pass_total must start at 0/0, not 100k/0.
        assert_eq!(p.scanned(), 0, "scanned must reset per pass");
        assert_eq!(p.fetched(), 0, "fetched must reset per pass");
        assert_eq!(p.pass_total(), 0, "pass_total must reset per pass");
        assert_eq!(p.range_end(), 0, "range_end must reset per pass");
        assert_eq!(p.spendable(), 0, "spendable latch re-arms each pass");

        // Monotonic delta counters preserved (Swift compares strict-greater).
        assert_eq!(p.enhanced(), 20, "enhanced_txs is monotonic per handle");
        assert_eq!(p.ranges_completed(), 1, "ranges_completed is monotonic per handle");
        assert_eq!(p.reorgs(), 1, "reorgs_recovered is cumulative diagnostics");
        assert_eq!(p.chain_tip(), 3_374_188, "chain_tip is overwritten by the new pass anyway");
        // [E-2/E-4] The freshness and tx-set counters are per-handle facts, not pass ratios.
        assert_eq!(p.tip_refreshes(), 1, "tip_refreshes is monotonic per handle");
        assert_eq!(p.tx_set_version(), 2, "tx_set_version is monotonic per handle");
    }

    /// [API v2.1 E-5] The floor re-baselines when the scope EXPANDS (seed materially below
    /// the floor — import/rewind) and stays monotone against within-scope noise.
    #[test]
    fn floor_rebaseline_on_scope_expansion_only() {
        let p = Progress::default();
        assert_eq!(p.permille_floor(990), 990);
        // Within-scope drift up to the epsilon never re-baselines (tip drift is <1‰).
        assert!(!p.rebaseline_floor_if_scope_expanded(989), "1‰ dip is noise");
        assert!(
            !p.rebaseline_floor_if_scope_expanded(990 - FLOOR_REBASELINE_EPSILON_PERMILLE),
            "exactly-epsilon dip is still within scope"
        );
        assert_eq!(p.permille_floor(0), 990, "floor held through noise");
        // Import with an older birthday: the seed plummets → re-baseline to the truth.
        assert!(p.rebaseline_floor_if_scope_expanded(120), "material drop = scope expansion");
        assert_eq!(p.permille_floor(0), 120, "floor re-baselined to the expanded-scope seed");
        // …and climbs monotonically again within the new scope.
        assert_eq!(p.permille_floor(300), 300);
    }
}
