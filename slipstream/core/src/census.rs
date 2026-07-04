//! v0.4 P0 — shard census + bench summary (spec: plans/2026-07-04-v04-graft-dont-grind-design.md §3).
//! Counts, per pool, which 2^16-position shards a pass touched and which of them hold
//! owned notes. `graftable_fraction` predicts Plan A's ceiling for a wallet BEFORE the
//! graft exists; the same numbers ride the `sparse … tree split` log lines and the
//! optional bench JSON (`EngineConfig::bench_json_path`) consumed by `slipstream-cli
//! bench` and bench-ios. JSON is hand-rolled (numbers + a static tag only) so the
//! published crate takes no serde dependency for one bench artifact.

use std::collections::BTreeSet;
use std::path::Path;

/// Both pools use shard height 16: shard index = position >> 16.
const SHARD_BITS: u32 = 16;

/// Per-pool, per-pass census of shard touches vs owned-note shards.
#[derive(Default, Debug, Clone)]
pub struct ShardCensus {
    touched: BTreeSet<u64>,
    noted: BTreeSet<u64>,
    /// Total commitments fed (both pools count leaves, not blocks).
    pub commitments: u64,
}

impl ShardCensus {
    /// Record `count` sequential commitments starting at `start_position`, plus the
    /// owned-note positions discovered in the same put_blocks call.
    pub fn feed(
        &mut self,
        start_position: u64,
        count: u64,
        note_positions: impl Iterator<Item = u64>,
    ) {
        if count > 0 {
            let first = start_position >> SHARD_BITS;
            let last = (start_position + count - 1) >> SHARD_BITS;
            self.touched.extend(first..=last);
            self.commitments += count;
        }
        for p in note_positions {
            self.noted.insert(p >> SHARD_BITS);
        }
    }

    /// Union another census into this one (range → pass aggregation).
    pub fn merge(&mut self, other: &ShardCensus) {
        self.touched.extend(other.touched.iter().copied());
        self.noted.extend(other.noted.iter().copied());
        self.commitments += other.commitments;
    }

    pub fn shards(&self) -> u64 {
        self.touched.len() as u64
    }

    pub fn noted_shards(&self) -> u64 {
        self.noted.len() as u64
    }

    /// Fraction of touched shards Plan A could graft: everything except noted shards
    /// and one tip shard (conservatively counted even if the tip shard is also noted).
    pub fn graftable_fraction(&self) -> f64 {
        let touched = self.touched.len() as u64;
        if touched == 0 {
            return 0.0;
        }
        let non_graftable = (self.noted.len() as u64).saturating_add(1).min(touched);
        (touched - non_graftable) as f64 / touched as f64
    }
}

/// Flat per-pool census block for the bench JSON.
#[derive(Debug, Clone, Copy)]
pub struct PoolCensusOut {
    pub shards: u64,
    pub noted_shards: u64,
    pub commitments: u64,
    pub graftable_fraction: f64,
}

impl From<&ShardCensus> for PoolCensusOut {
    fn from(c: &ShardCensus) -> Self {
        Self {
            shards: c.shards(),
            noted_shards: c.noted_shards(),
            commitments: c.commitments,
            graftable_fraction: c.graftable_fraction(),
        }
    }
}

/// End-of-pass machine-readable summary — the bench artifact (spec §3.1).
/// Field names are the contract with `slipstream-cli bench` and bench-ios.
#[derive(Debug, Clone)]
pub struct BenchSummary {
    pub engine_build: &'static str,
    pub total_s: f64,
    pub fetch_s: f64,
    pub scan_s: f64,
    pub enhance_s: f64,
    pub persist_wait_s: f64,
    pub persist_overlap_s: f64,
    pub blocks: u64,
    pub sapling: PoolCensusOut,
    pub orchard: PoolCensusOut,
}

impl BenchSummary {
    pub fn to_json(&self) -> String {
        fn pool(p: &PoolCensusOut) -> String {
            format!(
                "{{\"shards\":{},\"noted_shards\":{},\"commitments\":{},\"graftable_fraction\":{}}}",
                p.shards, p.noted_shards, p.commitments, p.graftable_fraction
            )
        }
        format!(
            "{{\"engine_build\":\"{}\",\"total_s\":{},\"fetch_s\":{},\"scan_s\":{},\"enhance_s\":{},\"persist_wait_s\":{},\"persist_overlap_s\":{},\"blocks\":{},\"sapling\":{},\"orchard\":{}}}",
            self.engine_build,
            self.total_s,
            self.fetch_s,
            self.scan_s,
            self.enhance_s,
            self.persist_wait_s,
            self.persist_overlap_s,
            self.blocks,
            pool(&self.sapling),
            pool(&self.orchard),
        )
    }

    pub fn write_json(&self, path: &Path) -> std::io::Result<()> {
        std::fs::write(path, self.to_json())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn census_counts_shards_and_notes() {
        let mut c = ShardCensus::default();
        // 2 commitments at the end of shard 0, 3 into shard 1; one note in shard 1.
        c.feed(65534, 5, [65537u64].into_iter());
        assert_eq!(c.shards(), 2);
        assert_eq!(c.noted_shards(), 1);
        assert_eq!(c.commitments, 5);
        // shard 1 noted + tip discount → nothing graftable of the 2.
        assert!(c.graftable_fraction() <= 0.5);
    }

    #[test]
    fn census_graftable_fraction_typical() {
        let mut c = ShardCensus::default();
        // 10 full shards, single note in shard 0 → 10 touched, 1 noted, 1 tip → 8/10.
        c.feed(0, 65536 * 10, [5u64].into_iter());
        assert!((c.graftable_fraction() - 0.8).abs() < 1e-9);
    }

    #[test]
    fn census_merge_unions() {
        let mut a = ShardCensus::default();
        a.feed(0, 65536, std::iter::empty());
        let mut b = ShardCensus::default();
        b.feed(65536, 65536, [65540u64].into_iter());
        a.merge(&b);
        assert_eq!(a.shards(), 2);
        assert_eq!(a.noted_shards(), 1);
        assert_eq!(a.commitments, 131_072);
    }

    #[test]
    fn census_empty_is_zero() {
        let c = ShardCensus::default();
        assert_eq!(c.shards(), 0);
        assert_eq!(c.graftable_fraction(), 0.0);
    }

    #[test]
    fn bench_summary_json_shape() {
        let pool = PoolCensusOut { shards: 3, noted_shards: 1, commitments: 42, graftable_fraction: 0.5 };
        let s = BenchSummary {
            engine_build: "test-build",
            total_s: 1.5,
            fetch_s: 0.25,
            scan_s: 1.0,
            enhance_s: 0.125,
            persist_wait_s: 0.0,
            persist_overlap_s: 0.5,
            blocks: 100,
            sapling: pool,
            orchard: pool,
        };
        let j = s.to_json();
        // Hand-rolled writer: deterministic, parseable shape.
        assert!(j.starts_with('{') && j.ends_with('}'), "json shape: {j}");
        for key in [
            "\"engine_build\":\"test-build\"",
            "\"total_s\":1.5",
            "\"blocks\":100",
            "\"orchard\":{",
            "\"graftable_fraction\":0.5",
            "\"commitments\":42",
        ] {
            assert!(j.contains(key), "missing {key} in {j}");
        }
    }
}
