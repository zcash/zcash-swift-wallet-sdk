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

    #[error("engine is stopped")]
    Stopped,
}

#[cfg(test)]
mod tests {
    use super::SlipstreamError;

    #[test]
    fn discontinuity_displays_height_and_detail() {
        let e = SlipstreamError::Discontinuity { at: 1_650_000, detail: "prev-hash mismatch".into() };
        assert_eq!(e.to_string(), "chain discontinuity at height 1650000: prev-hash mismatch");
    }
}
