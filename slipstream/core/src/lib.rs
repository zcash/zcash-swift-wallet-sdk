//! Slipstream sync engine core (platform-neutral).
//! See docs/SLIPSTREAM_DESIGN.md for the architecture and
//! docs/slipstream/ROADMAP.md for the build plan.

pub mod anchor;
// v0.5 Plan C (C1 home; today only the C0 probe — test-gated, no prod code).
#[cfg(test)]
mod batch_ecdh;
pub(crate) mod batch_sinsemilla;
pub mod block_source;
pub mod census;
pub mod chunk;
pub mod config;
pub mod connector;
pub mod enhance;
pub mod engine;
pub mod error;
pub mod events;
pub mod ffi_handle;
pub mod fetch;
// dead_code: consumed by the sparse build path in v0.4 plan Task 7 — this allow
// is deleted in that diff (buffer CRUD lands first so Task 6/7 build on green).
#[allow(dead_code)]
pub(crate) mod graft;
#[allow(dead_code)]
pub(crate) mod graft_accumulator;
pub mod grpc;
pub mod mempool;
pub mod oracle;
pub mod persist;
pub mod reconcile;
#[cfg(feature = "gpu")]
mod gpu_subtree;
pub(crate) mod lookup_build;
pub mod scan;
pub mod scan_queue;
pub mod scheduler;
pub mod session;
pub mod transparent;
pub mod treestate;
pub mod verify;
pub mod wallet_session;

#[cfg(feature = "darkside")]
#[allow(clippy::all, missing_docs)]
#[path = "grpc_generated/darkside.rs"]
pub mod darkside_generated;
#[cfg(feature = "darkside")]
pub mod darkside;

pub use config::{EngineConfig, Endpoint};
pub use error::SlipstreamError;
pub use events::{Bound, Event, Progress, ProgressArc, Snapshot, SyncMode};
pub use session::{SessionConfig, SessionReporter, TorSessionConfig, run_session};
pub use zcash_protocol::consensus::Network;

/// Crate smoke marker used by the workspace smoke test.
pub const CRATE_NAME: &str = "slipstream-core";

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert_eq!(super::CRATE_NAME, "slipstream-core");
    }
}
