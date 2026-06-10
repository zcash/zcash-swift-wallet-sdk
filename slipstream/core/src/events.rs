//! Engine → shell surface: a polled `Snapshot` plus a drained `Event` ring
//! (decision D8 in docs/slipstream/ROADMAP.md). Fields grow in P3; keep
//! both types additive (`#[non_exhaustive]`).

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
}
