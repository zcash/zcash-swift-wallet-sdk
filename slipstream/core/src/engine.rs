//! Engine v0: one full sync pass (preflight → chain state → scheduler → enhancement).
//! P3 adds enhancement/transparent/events; P4 wraps this behind FFI.

use std::{sync::Arc, time::Instant};

use tracing::info;

use crate::{
    config::EngineConfig,
    enhance::{EnhanceStats, run_enhancement},
    error::SlipstreamError,
    events::Progress,
    grpc,
    scheduler::{SyncReport, run_to_completion},
    transparent::{TransparentStats, refresh_utxos},
    wallet_session::WalletSession,
};

/// Engine build tag, logged at every sync start and in the stage-split line.
/// BUMP THIS on every performance-relevant engine change (anything that warrants a
/// framework rebuild) — it is the definitive freshness check for device logs: if the
/// tag in the log doesn't match HEAD's value, the device is running a stale
/// XCFramework (the three-layer gotcha, consuming side). Probe a built slice with:
/// `strings <slice>/libzcashlc.framework/libzcashlc | grep <tag>`.
pub const ENGINE_BUILD: &str = "2026-06-13.sandblast-split";

#[derive(Debug)]
pub struct SyncOutcome {
    pub report: SyncReport,
    pub enhance: EnhanceStats,
    pub transparent: TransparentStats,
    /// Total wall-clock time for the `run_enhancement` call.
    pub enhance_elapsed: std::time::Duration,
    pub elapsed: std::time::Duration,
    pub chain_tip: u64,
}

impl SyncOutcome {
    /// Returns the name of the stage that consumed the most wall-clock time:
    /// `"fetch"`, `"scan"`, `"enhance"`, or `"idle"` if all stages are < 1 s.
    ///
    /// Used for honest G5 "bound" reporting (Decision-Log requirement, 2026-06-10).
    /// F3: `enhance_elapsed` is now the SUM of all per-range runs + the final post-loop run.
    pub fn bound(&self) -> &'static str {
        let fetch_s = self.report.fetch_elapsed.as_secs_f64();
        let scan_s = self.report.scan_elapsed.as_secs_f64();
        let enhance_s = self.enhance_elapsed.as_secs_f64();

        // Threshold: stages < 1 s on a real sync are noise.
        if fetch_s < 1.0 && scan_s < 1.0 && enhance_s < 1.0 {
            return "idle";
        }

        if fetch_s >= scan_s && fetch_s >= enhance_s {
            "fetch"
        } else if scan_s >= enhance_s {
            "scan"
        } else {
            "enhance"
        }
    }
}

/// One sync pass. If `ufvk` is Some and the wallet has no accounts, imports it
/// with a birthday at `birthday_height` (treestate fetched from the server at
/// `birthday_height - 1`).
///
/// `progress` — optional shared progress state for poll-based consumers (decision D8).
/// Pass `Some(Arc::new(Progress::default()))` to receive live counter updates;
/// `None` for no-op (default in all tests and the darkside suite).
/// The `chain_tip` and `current_range_end` fields are set by the engine;
/// `fetched_blocks` / `scanned_blocks` / `enhanced_txs` are bumped during the pipeline.
///
/// # Deviation from plan draft
/// The plan does not guard against `birthday_height == 0`. Since `birthday_height`
/// is u64, `birthday_height - 1` would underflow for 0. We guard here and return
/// a Config error; a birthday of 0 is never valid for a mainnet/testnet wallet.
pub async fn sync_once(
    config: &EngineConfig,
    ufvk: Option<(&str, u64)>,
    progress: Option<Arc<Progress>>,
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

    // Reset per-pass ratio counters (scanned/fetched/pass_total/range_end/spendable).
    // The FFI handle — and therefore this Progress — outlives individual passes
    // (Swift opens it once in prepare(); stop()/start() reuse it across app
    // background/foreground cycles), so stale pass-1 counters would corrupt pass-2's
    // scanned/pass_total ratio. Monotonic delta counters (enhanced_txs,
    // ranges_completed, reorgs_recovered) are deliberately left untouched.
    if let Some(ref p) = progress {
        p.begin_pass();
    }

    // Definitive device-log freshness marker (see ENGINE_BUILD doc).
    info!(engine_build = ENGINE_BUILD, sparse = config.sparse_persistence, "engine pass starting");

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

    // Advertise the chain tip to poll-based consumers.
    if let Some(ref p) = progress {
        p.set_chain_tip(tip);
    }

    // Transparent UTXO refresh — runs BEFORE the shielded scan loop, mirroring upstream
    // sync.rs:108-121 ("We do this before we perform any shielded scanning, to ensure
    // that we discover any UTXOs between the old fully-scanned height and the current
    // chain tip.").
    let transparent = refresh_utxos(&mut session, &mut client).await?;

    // T6.1: per-pass dedupe set for TransactionsInvolvingAddress skip keys.
    // Scope = one sync pass (all interleaved/per-range/final runs share it).
    let mut skipped_keys: std::collections::HashSet<String> = std::collections::HashSet::new();

    let report = run_to_completion(config, &mut session, progress.clone(), &mut skipped_keys).await?;

    // Final enhancement: fetch full tx data for any remaining TransactionDataRequests
    // that were not caught by the per-range enhancement (F3 cleanup run). This is cheap
    // on a wallet with few remaining requests (typically zero after per-range runs).
    // Stats are merged into the report's `enhance` field so the stage-split log
    // reports total enhancement time (per-range runs + this final run) correctly.
    let enhance_started = Instant::now();
    let final_enhance =
        run_enhancement(&mut session, &mut client, config.network, progress.clone(), &mut skipped_keys).await?;
    let final_enhance_elapsed = enhance_started.elapsed();

    // F3: merge final enhancement stats into report so the total is correct.
    let mut report = report;
    report.enhance.requests += final_enhance.requests;
    report.enhance.txs_stored += final_enhance.txs_stored;
    report.enhance.statuses_set += final_enhance.statuses_set;
    report.enhance.skipped += final_enhance.skipped;
    // Total enhance_elapsed = per-range elapsed (in report) + final run elapsed.
    let total_enhance_elapsed = report.enhance_elapsed + final_enhance_elapsed;

    // Expose the merged enhance stats and total elapsed via SyncOutcome.
    let enhance = report.enhance.clone();
    let enhance_elapsed = total_enhance_elapsed;

    let outcome = SyncOutcome {
        report,
        enhance,
        transparent,
        enhance_elapsed,
        elapsed: started.elapsed(),
        chain_tip: tip,
    };

    // Log the stage split: total time + per-stage breakdown + bound.
    // F3: enhance_s is now the SUM of all per-range runs + the final post-loop run.
    // T6.6: sparse field added so log clearly shows which persistence path ran.
    info!(
        total_s = outcome.elapsed.as_secs_f64(),
        fetch_s = outcome.report.fetch_elapsed.as_secs_f64(),
        scan_s = outcome.report.scan_elapsed.as_secs_f64(),
        enhance_s = outcome.enhance_elapsed.as_secs_f64(),
        blocks = outcome.report.scan.blocks,
        bound = outcome.bound(),
        engine_build = ENGINE_BUILD,
        sparse = config.sparse_persistence,
        "sync stage split"
    );

    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to construct a minimal SyncOutcome with specified stage durations.
    fn make_outcome(fetch_s: f64, scan_s: f64, enhance_s: f64) -> SyncOutcome {
        use std::time::Duration;
        let report = crate::scheduler::SyncReport {
            fetch_elapsed: Duration::from_secs_f64(fetch_s),
            scan_elapsed: Duration::from_secs_f64(scan_s),
            ..Default::default()
        };
        SyncOutcome {
            report,
            enhance: crate::enhance::EnhanceStats::default(),
            transparent: crate::transparent::TransparentStats::default(),
            enhance_elapsed: Duration::from_secs_f64(enhance_s),
            elapsed: Duration::from_secs_f64(fetch_s + scan_s + enhance_s),
            chain_tip: 0,
        }
    }

    #[test]
    fn bound_picks_max_stage() {
        assert_eq!(make_outcome(5.0, 2.0, 1.0).bound(), "fetch");
        assert_eq!(make_outcome(2.0, 5.0, 1.0).bound(), "scan");
        assert_eq!(make_outcome(2.0, 1.0, 5.0).bound(), "enhance");
    }

    #[test]
    fn bound_returns_idle_when_all_tiny() {
        // All < 1 s → idle.
        assert_eq!(make_outcome(0.5, 0.3, 0.1).bound(), "idle");
    }

    #[test]
    fn bound_ties_prefer_fetch_then_scan() {
        // Equal fetch=scan=5s, enhance=0 → fetch wins (fetch >= scan in the branch).
        assert_eq!(make_outcome(5.0, 5.0, 0.0).bound(), "fetch");
        // Equal scan=enhance=5s, fetch=0 → scan wins.
        assert_eq!(make_outcome(0.0, 5.0, 5.0).bound(), "scan");
    }

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
            sync_once(&cfg, Some(("dummy_ufvk", 0)), None).await
        });
        assert!(
            matches!(result, Err(SlipstreamError::Config(_))),
            "expected Config error for birthday=0, got: {result:?}"
        );
    }
}
