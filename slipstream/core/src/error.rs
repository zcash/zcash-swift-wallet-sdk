//! Crate-wide error type. One variant per subsystem; transport/wallet details
//! become structured payloads as those subsystems land (P1/P2).

/// Crate-wide error returned by every Slipstream subsystem.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SlipstreamError {
    #[error("invalid configuration: {0}")]
    Config(String),

    #[error("transport: {0}")]
    Transport(String),

    #[error("chain discontinuity at height {at}: {detail}")]
    Discontinuity { at: u32, detail: String },

    #[error("wallet db: {0}")]
    Wallet(String),

    #[error("misbehaving server (invalid or out-of-range data in response)")]
    MisbehavingServer,

    #[error("engine is stopped")]
    Stopped,

    /// Scan detected a chain continuity break (reorg) at the given height.
    /// The scheduler's recovery arm truncates the wallet DB and re-suggests ranges.
    /// Mirrors upstream sync.rs:404 `Err(ChainError::Scan(err)) if err.is_continuity_error()`
    /// (zcash_client_backend-0.22.0/src/sync.rs:404).
    #[error("scan continuity break at height {at}")]
    ScanContinuity { at: u32 },
}

impl SlipstreamError {
    /// Returns `true` for errors that reflect a transient transport-layer failure
    /// (timeout, connect failure, stream stall) where retrying — ideally with a
    /// fresh connection — may succeed.
    ///
    /// Classification table (T6.8-H2):
    /// - `Transport`       → **true**  (timeout / connect / stream stall — retry after reconnect)
    /// - `Config`          → false     (bad config; no amount of retrying fixes this)
    /// - `Wallet`          → false     (DB / scan logic error; retry would hit the same error)
    /// - `ScanContinuity`  → false     (internally handled by the reorg recovery arm)
    /// - `Discontinuity`   → false     (fetch continuity bug; retry would loop)
    /// - `MisbehavingServer` → false   (bad proto / decode error; not a transport transient)
    /// - `Stopped`         → false     (engine lifecycle; not retryable)
    pub fn is_transient(&self) -> bool {
        matches!(self, SlipstreamError::Transport(_))
    }
}

#[cfg(test)]
mod tests {
    use super::SlipstreamError;

    #[test]
    fn discontinuity_displays_height_and_detail() {
        let e = SlipstreamError::Discontinuity { at: 1_650_000, detail: "prev-hash mismatch".into() };
        assert_eq!(e.to_string(), "chain discontinuity at height 1650000: prev-hash mismatch");
    }

    #[test]
    fn scan_continuity_displays_height() {
        let e = SlipstreamError::ScanContinuity { at: 663_195 };
        assert_eq!(e.to_string(), "scan continuity break at height 663195");
    }

    // ── T6.8-H2: is_transient exhaustive classification ──────────────────────────

    #[test]
    fn transport_is_transient() {
        assert!(SlipstreamError::Transport("timeout".into()).is_transient());
        assert!(SlipstreamError::Transport("connect refused".into()).is_transient());
        assert!(SlipstreamError::Transport("stream idle timeout (30s without a message)".into()).is_transient());
    }

    #[test]
    fn config_is_not_transient() {
        assert!(!SlipstreamError::Config("bad birthday".into()).is_transient());
    }

    #[test]
    fn wallet_is_not_transient() {
        assert!(!SlipstreamError::Wallet("scan_cached_blocks: ...".into()).is_transient());
    }

    #[test]
    fn scan_continuity_is_not_transient() {
        assert!(!SlipstreamError::ScanContinuity { at: 663_195 }.is_transient());
    }

    #[test]
    fn discontinuity_is_not_transient() {
        assert!(!SlipstreamError::Discontinuity { at: 1_000_000, detail: "prev-hash mismatch".into() }.is_transient());
    }

    #[test]
    fn misbehaving_server_is_not_transient() {
        assert!(!SlipstreamError::MisbehavingServer.is_transient());
    }

    #[test]
    fn stopped_is_not_transient() {
        assert!(!SlipstreamError::Stopped.is_transient());
    }
}
