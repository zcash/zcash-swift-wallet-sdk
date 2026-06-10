//! Slipstream sync engine core (platform-neutral).
//! See docs/SLIPSTREAM_DESIGN.md for the architecture and
//! docs/slipstream/ROADMAP.md for the build plan.

pub mod block_source;
pub mod chunk;
pub mod config;
pub mod error;
pub mod events;
pub mod fetch;
pub mod grpc;
pub mod scan;
pub mod scheduler;
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
pub use events::{Bound, Event, Snapshot, SyncMode};

/// Crate smoke marker used by the workspace smoke test.
pub const CRATE_NAME: &str = "slipstream-core";

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert_eq!(super::CRATE_NAME, "slipstream-core");
    }
}
