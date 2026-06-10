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
}
