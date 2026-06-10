//! Slipstream sync engine core (platform-neutral).
//! See docs/SLIPSTREAM_DESIGN.md for the architecture and
//! docs/slipstream/ROADMAP.md for the build plan.

/// Crate smoke marker used by the workspace smoke test.
pub const CRATE_NAME: &str = "slipstream-core";

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert_eq!(super::CRATE_NAME, "slipstream-core");
    }
}
