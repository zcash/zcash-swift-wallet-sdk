//! Opaque FFI handle for the Slipstream engine.
//!
//! Lifecycle:
//!   open  → allocates SlipstreamHandle (tokio runtime + snapshot atomics + event ring)
//!   start → spawns sync task on the runtime; previous task cancelled first
//!   stop  → cancels the sync task; handle stays live for snapshot/drain_events
//!   free  → drops the handle (drops runtime → all tasks cancel)
//!
//! All fields are Send + Sync; the handle is always behind a raw pointer (Box::into_raw),
//! accessed from Swift/Obj-C single-threaded callers serialised by the actor.
//!
//! BINDING: SlipstreamHandle is NOT exposed in the C header (opaque pointer). Its fields
//! are internal. The C header only sees `typedef struct SlipstreamHandle SlipstreamHandle;`.

use std::sync::{Arc, Mutex};
use tokio::{runtime::Runtime, task::JoinHandle};

use crate::{config::Endpoint, events::Progress};

/// C-compatible snapshot struct. All fields are C-safe integers.
/// Maps to `FfiSlipstreamSnapshot` in `zcashlc.h` (cbindgen generates this).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct FfiSlipstreamSnapshot {
    /// Current chain tip height (0 = not yet fetched).
    pub chain_tip: u64,
    /// Number of blocks fetched in the current/last sync pass.
    pub fetched_blocks: u64,
    /// Number of blocks scanned in the current/last sync pass.
    pub scanned_blocks: u64,
    /// Number of transactions enhanced in the current/last sync pass.
    pub enhanced_txs: u64,
    /// End height of the block range currently being processed.
    pub current_range_end: u64,
    /// Sync state: 0=idle, 1=syncing, 2=error, 3=done.
    pub state: u8,
    // ── T5.5 counter-based progress fields (appended at END for padding stability) ──
    /// Total blocks in the current pass (sum of all suggested-range block-lengths taken
    /// so far). Denominator for counter-based progress: scanned_blocks / pass_total_blocks.
    pub pass_total_blocks: u64,
    /// Spendable hint: 0 = not yet spendable; 1 = a ChainTip-priority range has completed
    /// scanning (≈ SBS funds-spendable semantics). Latches to 1; never resets within a pass.
    pub spendable_hint: u8,
}

/// C-compatible event record.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FfiSlipstreamEvent {
    /// Event tag: 1=SyncStarted, 2=SyncProgress, 3=SyncDone, 4=SyncError, 5=FoundTransactions.
    pub tag: u8,
    /// For SyncDone: count of transactions stored; for SyncError: error code; others: 0.
    pub value: u64,
}

/// State of the sync task.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SyncState {
    Idle,
    Syncing,
    Error(u8), // error code (u8 for C compat)
    Done,
}

/// Maximum events to keep in the ring before dropping oldest.
pub const EVENT_RING_CAP: usize = 64;

pub struct SlipstreamHandle {
    /// Single multi-thread tokio runtime owned by this handle (dropped with the handle).
    /// D7 deviation: runtime is created at `open` and dropped at `free` (not per-start/stop).
    pub runtime: Runtime,
    /// Shared progress atomics — read by snapshot; written by the sync task.
    pub progress: Arc<Progress>,
    /// Current sync state — written by sync task, read by snapshot.
    pub state: Arc<Mutex<SyncState>>,
    /// Event ring — sync task pushes; Swift drains.
    pub events: Arc<Mutex<Vec<FfiSlipstreamEvent>>>,
    /// Join handle for the currently-running sync task (None = not started or stopped).
    pub task: Option<JoinHandle<()>>,
    /// Server endpoint — set at open; used for start.
    pub endpoint: Endpoint,
    /// Wallet db path — set at open.
    pub wallet_db_path: std::path::PathBuf,
    /// Network (MainNetwork or TestNetwork).
    pub network: zcash_protocol::consensus::Network,
}

impl SlipstreamHandle {
    /// Push one event onto the ring; drops the oldest if the ring is full.
    pub fn push_event(&self, event: FfiSlipstreamEvent) {
        let mut ring = self.events.lock().unwrap_or_else(|p| p.into_inner());
        if ring.len() >= EVENT_RING_CAP {
            ring.remove(0); // drop oldest
        }
        ring.push(event);
    }

    /// Read a point-in-time snapshot of progress counters and sync state.
    pub fn snapshot(&self) -> FfiSlipstreamSnapshot {
        let p = &self.progress;
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let state_u8 = match *state {
            SyncState::Idle => 0,
            SyncState::Syncing => 1,
            SyncState::Error(_) => 2,
            SyncState::Done => 3,
        };
        FfiSlipstreamSnapshot {
            chain_tip: p.chain_tip(),
            fetched_blocks: p.fetched(),
            scanned_blocks: p.scanned(),
            enhanced_txs: p.enhanced(),
            current_range_end: p.range_end(),
            state: state_u8,
            pass_total_blocks: p.pass_total(),
            spendable_hint: p.spendable() as u8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_snapshot_default_is_zero() {
        let s = FfiSlipstreamSnapshot::default();
        assert_eq!(s.chain_tip, 0);
        assert_eq!(s.fetched_blocks, 0);
        assert_eq!(s.scanned_blocks, 0);
        assert_eq!(s.enhanced_txs, 0);
        assert_eq!(s.current_range_end, 0);
        assert_eq!(s.state, 0);
        assert_eq!(s.pass_total_blocks, 0, "pass_total_blocks default must be 0");
        assert_eq!(s.spendable_hint, 0, "spendable_hint default must be 0");
    }

    #[test]
    fn ffi_snapshot_counter_fields_roundtrip() {
        // Build a fake Progress, set the new counters, and verify they surface in snapshot().
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("tokio runtime");
        let progress = std::sync::Arc::new(crate::events::Progress::default());
        let handle = SlipstreamHandle {
            runtime,
            progress: progress.clone(),
            state: std::sync::Arc::new(Mutex::new(SyncState::Syncing)),
            events: std::sync::Arc::new(Mutex::new(Vec::new())),
            task: None,
            endpoint: Endpoint { host: "localhost".into(), port: 9067, tls: false },
            wallet_db_path: std::path::PathBuf::from("/tmp/test.db"),
            network: zcash_protocol::consensus::Network::TestNetwork,
        };

        // Simulate scheduler taking two ranges.
        progress.add_pass_total(10_000); // first range
        progress.add_pass_total(5_000);  // second range
        progress.add_scanned(7_500);
        progress.set_spendable();

        let snap = handle.snapshot();
        assert_eq!(snap.pass_total_blocks, 15_000,
                   "pass_total_blocks must equal sum of add_pass_total calls");
        assert_eq!(snap.spendable_hint, 1,
                   "spendable_hint must be 1 after set_spendable()");
        assert_eq!(snap.scanned_blocks, 7_500,
                   "scanned_blocks must equal add_scanned total");
        assert_eq!(snap.state, 1, "state must be 1 (Syncing)");
    }

    #[test]
    fn event_ring_cap_at_64() {
        // Build a handle with a real tokio runtime for the ring test.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("tokio runtime");
        let handle = SlipstreamHandle {
            runtime,
            progress: Arc::new(Progress::default()),
            state: Arc::new(Mutex::new(SyncState::Idle)),
            events: Arc::new(Mutex::new(Vec::new())),
            task: None,
            endpoint: Endpoint { host: "localhost".into(), port: 9067, tls: false },
            wallet_db_path: std::path::PathBuf::from("/tmp/test.db"),
            network: zcash_protocol::consensus::Network::TestNetwork,
        };

        // Push 70 events — only the last 64 should survive.
        for i in 0u64..70 {
            handle.push_event(FfiSlipstreamEvent { tag: 1, value: i });
        }
        let ring = handle.events.lock().unwrap();
        assert_eq!(ring.len(), EVENT_RING_CAP);
        // The oldest 6 (values 0..5) were dropped; first kept value is 6.
        assert_eq!(ring[0].value, 6);
        // Last kept value is 69.
        assert_eq!(ring[EVENT_RING_CAP - 1].value, 69);
    }

    #[test]
    fn event_ring_drain_is_atomic() {
        // Build a handle and verify drain removes exactly the pushed events.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("tokio runtime");
        let handle = SlipstreamHandle {
            runtime,
            progress: Arc::new(Progress::default()),
            state: Arc::new(Mutex::new(SyncState::Idle)),
            events: Arc::new(Mutex::new(Vec::new())),
            task: None,
            endpoint: Endpoint { host: "localhost".into(), port: 9067, tls: false },
            wallet_db_path: std::path::PathBuf::from("/tmp/test.db"),
            network: zcash_protocol::consensus::Network::TestNetwork,
        };

        handle.push_event(FfiSlipstreamEvent { tag: 1, value: 10 });
        handle.push_event(FfiSlipstreamEvent { tag: 3, value: 2 });

        // Simulate drain by locking and draining.
        let drained: Vec<FfiSlipstreamEvent> = {
            let mut ring = handle.events.lock().unwrap();
            ring.drain(..).collect()
        };
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].value, 10);
        assert_eq!(drained[1].value, 2);

        // Ring must be empty after drain.
        let ring = handle.events.lock().unwrap();
        assert!(ring.is_empty());
    }
}
