//! Engine v0: one full sync pass (preflight → chain state → scheduler → enhancement).
//! P3 adds enhancement/transparent/events; P4 wraps this behind FFI.

use std::time::Instant;

use tracing::info;

use crate::{
    config::EngineConfig,
    enhance::{EnhanceStats, run_enhancement},
    error::SlipstreamError,
    grpc,
    scheduler::{SyncReport, run_to_completion},
    wallet_session::WalletSession,
};

#[derive(Debug)]
pub struct SyncOutcome {
    pub report: SyncReport,
    pub enhance: EnhanceStats,
    pub elapsed: std::time::Duration,
    pub chain_tip: u64,
}

/// One sync pass. If `ufvk` is Some and the wallet has no accounts, imports it
/// with a birthday at `birthday_height` (treestate fetched from the server at
/// `birthday_height - 1`).
///
/// # Deviation from plan draft
/// The plan does not guard against `birthday_height == 0`. Since `birthday_height`
/// is u64, `birthday_height - 1` would underflow for 0. We guard here and return
/// a Config error; a birthday of 0 is never valid for a mainnet/testnet wallet.
pub async fn sync_once(
    config: &EngineConfig,
    ufvk: Option<(&str, u64)>,
) -> Result<SyncOutcome, SlipstreamError> {
    config.validate()?;

    // Early guard: birthday_height == 0 would underflow (birthday_height - 1) below.
    // A birthday of 0 is never valid for mainnet/testnet. Check here, before any I/O,
    // so the error is a clean Config failure regardless of network availability.
    // (u64 subtraction wraps in release builds without overflow checks — guard is required.)
    if let Some((_, 0)) = ufvk {
        return Err(SlipstreamError::Config(
            "birthday_height must be >= 1 (height 0 is not a valid wallet birthday)".into(),
        ));
    }

    let started = Instant::now();

    let mut session = WalletSession::open(config.network, &config.wallet_db_path)?;
    let mut client = grpc::connect(&config.endpoint).await?;

    if let Some((ufvk_str, birthday_height)) = ufvk {
        let birthday_ts = grpc::get_tree_state(&mut client, birthday_height - 1).await?;
        session.ensure_account(ufvk_str, birthday_ts)?;
    }

    let roots = grpc::get_subtree_roots(&mut client).await?;
    session.put_subtree_roots(&roots)?;

    let tip = grpc::get_latest_block_height(&mut client).await?;
    session.update_chain_tip(tip)?;
    info!(tip, "chain tip updated");

    let report = run_to_completion(config, &mut session).await?;

    // Enhancement: fetch full tx data for all pending TransactionDataRequests.
    // Runs AFTER the scan loop so all detected transactions are in the DB before
    // we try to enhance them (scan enqueues Enhancement/GetStatus requests).
    let enhance = run_enhancement(&mut session, &mut client, config.network).await?;

    Ok(SyncOutcome { report, enhance, elapsed: started.elapsed(), chain_tip: tip })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn birthday_height_zero_is_rejected() {
        // This test is hermetic: we just call validate_ufvk_birthday_guard, which
        // does not require a real network or wallet. We test the guard's logic
        // directly by checking that birthday=0 with a ufvk is a Config error.
        // The guard is inline in sync_once; exercise it via the public function
        // signature in a tokio runtime.
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime for test");
        let cfg = EngineConfig::new(
            zcash_protocol::consensus::Network::MainNetwork,
            std::path::PathBuf::from("/tmp/slipstream-engine-test-nonexistent/data.db"),
            crate::config::Endpoint { host: "127.0.0.1".into(), port: 1, tls: false },
        );
        // birthday=0 must fail before any network call.
        let result = rt.block_on(async {
            sync_once(&cfg, Some(("dummy_ufvk", 0))).await
        });
        assert!(
            matches!(result, Err(SlipstreamError::Config(_))),
            "expected Config error for birthday=0, got: {result:?}"
        );
    }
}
