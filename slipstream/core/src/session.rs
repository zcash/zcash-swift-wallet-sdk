//! Engine-owned sync **session orchestration** — the full sync lifecycle around the
//! per-pass engine (`engine::sync_once`).
//!
//! This is the single entry point a host calls to run a complete, privacy-correct sync:
//! resilient Tor bootstrap → resilient initial pass (T8.7) → tip-following loop with mempool
//! monitoring. It encodes the privacy + resilience POLICY (jitter-vs-fingerprint, never fall
//! back to direct on Tor failure, isolated circuits for metadata, never surface a transient
//! error to a foreground wallet, mempool-non-fatal) so that EVERY host (iOS/Android FFI, CLI,
//! zingo, zallet) gets it right by calling one function instead of re-deriving the loop.
//!
//! Lifted verbatim from the FFI `sync_body` (rust/src/lib.rs) — behaviour is unchanged; only
//! the location moved (into the crate that already owns the state/event/handle types).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::EngineConfig;
use crate::connector::TorConn;
use crate::engine::{SyncOutcome, probe_tip, should_resync, sync_once, wall_clock_utc};
use crate::error::SlipstreamError;
use crate::events::Progress;
use crate::ffi_handle::{FfiSlipstreamEvent, SyncState};
#[cfg(test)]
use crate::ffi_handle::EVENT_RING_CAP;

/// Per-session configuration: the per-pass engine config + optional account import + optional Tor.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// Per-pass engine config (network, db, endpoint, budgets, sparse, write-behind, gpu).
    pub engine: EngineConfig,
    /// `Some((ufvk, birthday))` imports the account on the initial pass if the wallet has none;
    /// `None` = already imported. Follow passes are always keyless regardless.
    pub account: Option<(String, u64)>,
    /// `Some` routes metadata over isolated Tor circuits (bulk stays direct); `None` = all direct.
    pub tor: Option<TorSessionConfig>,
}

/// Tor session policy. The HOST decides `dangerously_trust_everyone` (true on sandboxed app dirs:
/// iOS, Android) — this keeps the engine host-agnostic (no `cfg!(target_os = ...)` in core).
#[derive(Clone, Debug)]
pub struct TorSessionConfig {
    pub dir: std::path::PathBuf,
    pub dangerously_trust_everyone: bool,
}

// ── T8.1 follow-mode cadence (jittered probe interval) ───────────────────────
//
// A FIXED poll cadence is a correlatable timing fingerprint across users/sessions — passive
// network observers can detect a wallet's sync rhythm. Jitter in [FOLLOW_POLL_MIN_SECS,
// FOLLOW_POLL_MAX_SECS] breaks this (uniform random per cycle, independent across handles),
// matching the old-SDK's `random(in: 10...30)` (CompactBlockProcessor.swift:74-76).

/// Minimum follow-probe sleep (inclusive). Matches the old-SDK jitter floor.
pub(crate) const FOLLOW_POLL_MIN_SECS: u64 = 10;

/// Maximum follow-probe sleep (inclusive). Matches the old-SDK jitter ceiling.
pub(crate) const FOLLOW_POLL_MAX_SECS: u64 = 30;

/// Consecutive follow-iteration failures after which the follow loop logs an ESCALATED warning
/// (likely a connectivity problem). T8.7: a follow-phase failure NEVER surfaces
/// `SyncState::Error` — the wallet stays synced to `last_tip` and keeps retrying; only the
/// INITIAL sync's non-transient errors (and panics, via the supervisor) surface Error.
pub(crate) const FOLLOW_FAILURE_CAP: u32 = 8;

/// Consecutive mempool-session failures tolerated before mempool monitoring is disabled for THIS
/// handle (T8.2). Mempool is a non-fatal convenience layer on top of following: a persistently
/// failing stream must NOT kill the follow loop — the handle drops back to plain tip-polling and
/// the user still syncs (Deviation D6). Lower than `FOLLOW_FAILURE_CAP` because, unlike tip
/// probes, losing mempool degrades nothing essential.
pub(crate) const MEMPOOL_FAILURE_CAP: u32 = 5;

/// Maximum number of ADDITIONAL `sync_once` calls after the first failure (T6.8-H2 Fix B).
/// Total attempts = `PASS_RETRY_MAX + 1` = 3.
pub(crate) const PASS_RETRY_MAX: u32 = 2;

/// Capped exponential backoff for the resilient initial-sync retry loop (T8.7). A foreground
/// wallet must NOT surface a hard sync error for a transient network blip — the runner retries
/// with this backoff (showing Disconnected) instead of Error-ing. attempt 1→3s, 2→6s, 3→12s,
/// 4→24s, ≥5→30s (capped). Pure + unit-tested.
pub(crate) fn sync_retry_backoff(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(4);
    Duration::from_secs((3u64 << shift).min(30))
}

/// Maps a uniform random sample in [0, 1) to a probe sleep duration in
/// [`FOLLOW_POLL_MIN_SECS`, `FOLLOW_POLL_MAX_SECS`] (inclusive on both ends).
///
/// Pure and unit-testable: callers supply the sample (drawn from `rand::random::<f64>()` in the
/// hot path) so tests can pin boundary values without real randomness.
pub(crate) fn follow_poll_jitter(rng_sample: f64) -> Duration {
    // span = MAX - MIN + 1 = 21 (number of distinct integer seconds available)
    let span = (FOLLOW_POLL_MAX_SECS - FOLLOW_POLL_MIN_SECS + 1) as f64;
    // Map [0,1) → [0, span) → floor → [0, span-1] as u64, then add MIN.
    let offset = (rng_sample * span) as u64;
    // Clamp defensively (rng_sample == 1.0 is theoretically impossible for a well-formed f64
    // uniform [0,1) generator but guard against edge cases).
    let secs = FOLLOW_POLL_MIN_SECS + offset.min(FOLLOW_POLL_MAX_SECS - FOLLOW_POLL_MIN_SECS);
    Duration::from_secs(secs)
}

/// Sleep durations between pass-level retries.
/// Attempt 1 (first retry): 5 s — short enough to recover quickly from a brief stall.
/// Attempt 2+ (second retry): 15 s — longer back-off for a genuinely wedged server.
pub(crate) fn pass_retry_sleep(attempt: u32) -> Duration {
    match attempt {
        1 => Duration::from_secs(5),
        _ => Duration::from_secs(15),
    }
}

/// Returns the sleep duration to wait before retry `attempt` (1-based), or `None` if the error is
/// non-transient or all retries are exhausted. Extracted as a pure function so unit tests can
/// exercise the decision logic without running a full sync (T6.8-H2 test requirement).
pub(crate) fn should_retry(err: &SlipstreamError, attempt: u32) -> Option<Duration> {
    if err.is_transient() && attempt <= PASS_RETRY_MAX {
        Some(pass_retry_sleep(attempt))
    } else {
        None
    }
}

/// Run `sync_once` with the T6.8-H2 bounded retry ladder and return the first successful
/// `SyncOutcome` or the last error.
///
/// `SyncState` is NOT modified by this function — the caller sets Syncing before calling and
/// transitions Done/Error based on the result. SyncStarted is NOT emitted here — it is the
/// caller's responsibility (emitted once per session).
pub(crate) async fn run_pass_with_retry(
    cfg: &EngineConfig,
    ufvk_ref: Option<(&str, u64)>,
    progress: &Arc<Progress>,
    tor: Option<&TorConn>,
) -> Result<SyncOutcome, SlipstreamError> {
    let mut attempt: u32 = 0;
    loop {
        let result = sync_once(cfg, ufvk_ref, Some(progress.clone()), tor).await;
        match result {
            Ok(outcome) => return Ok(outcome),
            Err(err) => {
                attempt += 1;
                match should_retry(&err, attempt) {
                    Some(sleep_dur) => {
                        tracing::warn!(
                            %err,
                            attempt,
                            sleep_secs = sleep_dur.as_secs(),
                            "slipstream sync failed (transient) — retrying pass"
                        );
                        tokio::time::sleep(sleep_dur).await;
                        // Continue with SyncState::Syncing (caller owns state transitions).
                    }
                    None => return Err(err),
                }
            }
        }
    }
}

/// The reporting sink: the host's shared progress/state/event handles — the EXACT types the FFI
/// handle (`ffi_handle::SlipstreamHandle`) already owns. Hosts read them via the existing
/// poll-based `snapshot()`/drain model, the easiest shape for both iOS and Android JNI (no FFI
/// callbacks across a language boundary). `run_session` writes through this.
#[derive(Clone)]
pub struct SessionReporter {
    pub progress: Arc<Progress>,
    pub state: Arc<Mutex<SyncState>>,
    pub events: Arc<Mutex<Vec<FfiSlipstreamEvent>>>,
}

impl SessionReporter {
    /// Write the sync state (poison-tolerant — a panicked holder must not wedge the session).
    pub fn set_state(&self, s: SyncState) {
        *self.state.lock().unwrap_or_else(|p| p.into_inner()) = s;
    }

    /// Push one event onto the bounded ring. v2 ([audit ENG-4]): overflow evicts the oldest
    /// DROPPABLE event (started/progress) first — done/error/found-transactions survive — and
    /// every eviction is logged. Policy lives in `ffi_handle::push_event_bounded` (shared with
    /// the panic supervisor's push).
    pub fn push_event(&self, e: FfiSlipstreamEvent) {
        let mut ring = self.events.lock().unwrap_or_else(|p| p.into_inner());
        crate::ffi_handle::push_event_bounded(&mut ring, e);
    }
}

/// Run a full sync session: resilient Tor bootstrap (never falls back to direct) → resilient
/// initial pass (T8.7) → tip-following loop with mempool monitoring, until the future is dropped
/// or aborted by the host (via the `AbortHandle` returned by `ffi_handle::spawn_supervised`).
///
/// Returns only if the initial pass hits a NON-transient error (after surfacing `Error` to the
/// reporter — exactly the pre-lift FFI behaviour). On success it never returns: it follows the
/// chain tip until the host aborts the task. Panics are converted to `Error` by the supervisor.
pub async fn run_session(
    config: SessionConfig,
    reporter: SessionReporter,
    pass_lock: Arc<tokio::sync::Mutex<()>>,
) {
    // ── Serialize overlapping passes on this handle (Keystone restore race, 2026-06-30) ───────
    // Hold the pass lock for the WHOLE session — this is the OUTERMOST local. On a
    // start()-while-running restart the host aborts the previous task (lib.rs
    // `zcashlc_slipstream_start`), but tokio's `abort()` is ASYNCHRONOUS: the old pass keeps
    // running until its next await. Acquiring here makes this new pass wait until the aborted old
    // pass has unwound and dropped its guard; because guards drop in reverse acquisition order, the
    // old pass's `WalletSession` (and its `data.db` connection) is already closed by then — so the
    // two passes never touch `data.db` concurrently. Without this, `importAccount`'s restart raced
    // two passes on one DB → panic → `SyncState::Error(2)` (the `rustSlipstreamSyncFailed` dialog a
    // Keystone restore hit). The host always abort()s the old task before spawning the new one, so
    // the old holder is guaranteed to release — no deadlock. A tokio `Mutex` is not poisoned by a
    // panic/cancel, so even a panicking old pass frees the lock cleanly.
    let _pass_guard = pass_lock.lock().await;

    // Notify SyncStarted (tag=1) — emitted exactly ONCE, before any retry or follow pass.
    reporter.push_event(FfiSlipstreamEvent { tag: 1, value: 0 });

    // ── Engine-owned Tor bootstrap ───────────────────────────────────────────
    // When Tor is enabled, bootstrap an arti client on THIS tokio runtime (Client::create binds
    // to PreferredRuntime::current(), so no block_on / no cross-runtime). Bootstrapping is
    // RESILIENT: a transient failure shows Disconnected and retries forever — we NEVER fall back
    // to direct, because Tor was explicitly requested and a direct fallback would silently
    // de-anonymise the sync. Once up, the client is held for the whole session (initial pass +
    // follow loop); metadata calls get isolated circuits, bulk fetch stays direct (per-call
    // policy in connector.rs).
    let tor_conn: Option<TorConn> = match config.tor {
        None => None,
        Some(ref t) => {
            let mut boot_failures: u32 = 0;
            loop {
                match TorConn::bootstrap(&t.dir, t.dangerously_trust_everyone).await {
                    Ok(tc) => {
                        tracing::info!(
                            "slipstream Tor bootstrapped (engine-owned isolated circuits)"
                        );
                        break Some(tc);
                    }
                    Err(err) => {
                        boot_failures += 1;
                        let backoff = sync_retry_backoff(boot_failures);
                        tracing::warn!(
                            %err,
                            boot_failures,
                            backoff_secs = backoff.as_secs(),
                            "Tor bootstrap failed (transient) — retrying; NOT falling back to direct"
                        );
                        reporter.set_state(SyncState::Idle);
                        tokio::time::sleep(backoff).await;
                    }
                }
            }
        }
    };

    // Initial-pass account import (if any). `Option<(&str, u64)>` is Copy, so it is reused per
    // retry iteration without re-borrowing.
    let account_ref = config.account.as_ref().map(|(s, h)| (s.as_str(), *h));

    // ── Initial pass: RESILIENT retry loop (T8.7) ────────────────────────────
    // A foreground wallet must NEVER surface a hard sync error for a recoverable
    // (transient/transport) failure. On a transient error we retry with a capped backoff,
    // surfacing Disconnected (Swift maps state 0 → .disconnected) between attempts; a
    // NON-transient error (config/logic) surfaces Error below. Panics → the supervisor → Error(2).
    let mut initial_failures: u32 = 0;
    let initial_result = loop {
        reporter.set_state(SyncState::Syncing);
        match run_pass_with_retry(
            &config.engine,
            account_ref,
            &reporter.progress,
            tor_conn.as_ref(),
        )
        .await
        {
            Ok(outcome) => break Ok(outcome),
            Err(err) if err.is_transient() => {
                initial_failures += 1;
                let backoff = sync_retry_backoff(initial_failures);
                tracing::warn!(
                    %err,
                    initial_failures,
                    backoff_secs = backoff.as_secs(),
                    "initial sync attempt failed (transient) — retrying, NOT surfacing Error"
                );
                reporter.set_state(SyncState::Idle);
                tokio::time::sleep(backoff).await;
            }
            Err(err) => break Err(err),
        }
    };

    match initial_result {
        Err(err) => {
            tracing::error!(
                %err,
                failed_at_utc = %wall_clock_utc(),
                "slipstream sync failed"
            );
            reporter.set_state(SyncState::Error(1));
            reporter.push_event(FfiSlipstreamEvent { tag: 4, value: 1 });
        }
        Ok(outcome) => {
            // Initial pass succeeded: Done + SyncDone event.
            reporter.set_state(SyncState::Done);
            reporter.push_event(FfiSlipstreamEvent {
                tag: 3,
                value: outcome.enhance.txs_stored,
            });

            // ── T8.1 follow loop: track the chain while the host keeps the task alive ─────
            // State contract (Deviation D3): Done between passes, Syncing during real catch-up
            // passes. Jitter (uniform [MIN, MAX] per cycle) defeats the timing fingerprint a
            // fixed cadence would leak. The host aborts this task on stop()/free()/restart
            // (tokio sleeps/awaits are abort-safe).
            let mut last_tip = outcome.chain_tip;
            let mut consecutive_failures: u32 = 0;
            // T8.2 mempool monitoring state (per-session). Non-fatal: a persistently failing
            // stream disables mempool for this session and the loop keeps tip-polling.
            // `seen_txids` persists across reconnects because lightwalletd replays the whole
            // mempool on every reconnect (Deviation D6).
            let mut mempool_enabled = true;
            let mut mempool_failures: u32 = 0;
            let mut seen_txids: std::collections::HashSet<[u8; 32]> =
                std::collections::HashSet::new();
            loop {
                // Between passes: hold a mempool session (surfaces 0-conf incoming) or jitter-sleep
                // if mempool is disabled. A live session blocks until the server closes the stream
                // on a new block (then we probe immediately) or MEMPOOL_SESSION_IDLE elapses;
                // either way it bounds the iteration cadence. Mempool failure is NON-FATAL (D6).
                if mempool_enabled {
                    match crate::mempool::run_session(
                        &config.engine,
                        Some(reporter.progress.clone()),
                        &mut seen_txids,
                        crate::mempool::MEMPOOL_SESSION_IDLE,
                        tor_conn.as_ref(),
                    )
                    .await
                    {
                        Ok((end, stats)) => {
                            mempool_failures = 0;
                            tracing::debug!(
                                ?end,
                                received = stats.received,
                                hits = stats.stored_hits,
                                last_tip,
                                "follow: mempool session ended"
                            );
                        }
                        Err(err) => {
                            mempool_failures += 1;
                            tracing::warn!(
                                %err,
                                mempool_failures,
                                "follow: mempool session failed (non-fatal)"
                            );
                            if mempool_failures >= MEMPOOL_FAILURE_CAP {
                                tracing::warn!(
                                    "follow: mempool monitoring disabled for this handle (cap reached) — tip polling continues"
                                );
                                mempool_enabled = false;
                            }
                            // Back off with the same jittered cadence as the plain poll so a
                            // flapping stream cannot hot-loop.
                            tokio::time::sleep(follow_poll_jitter(rand::random::<f64>())).await;
                        }
                    }
                } else {
                    let sleep_dur = follow_poll_jitter(rand::random::<f64>());
                    tracing::debug!(
                        sleep_secs = sleep_dur.as_secs(),
                        last_tip,
                        "follow: sleeping before tip probe"
                    );
                    tokio::time::sleep(sleep_dur).await;
                }

                // Fast-path probe: GetLatestBlock only (no subtree roots, no UTXO refresh).
                let observed = match probe_tip(&config.engine, tor_conn.as_ref()).await {
                    Ok(t) => {
                        consecutive_failures = 0;
                        t
                    }
                    Err(err) if err.is_transient() => {
                        consecutive_failures += 1;
                        // T8.7: a transient probe failure NEVER surfaces Error — the wallet is
                        // already synced; retry on the next tick.
                        if consecutive_failures > FOLLOW_FAILURE_CAP {
                            tracing::warn!(
                                %err,
                                consecutive_failures,
                                "follow tip probe failing repeatedly — wallet stays synced, still retrying (check connectivity)"
                            );
                        } else {
                            tracing::warn!(
                                %err,
                                consecutive_failures,
                                "follow tip probe failed (transient) — will retry"
                            );
                        }
                        continue;
                    }
                    Err(err) => {
                        consecutive_failures += 1;
                        // T8.7: even a non-transient probe error stays OUT of Error — the wallet is
                        // synced; surfacing a hard error for a follow-phase blip is exactly what
                        // internal testers must not see. Retry next tick.
                        tracing::warn!(
                            %err,
                            consecutive_failures,
                            "follow tip probe failed (non-transient) — staying synced, will retry"
                        );
                        continue;
                    }
                };

                if !should_resync(last_tip, observed) {
                    tracing::debug!(last_tip, observed, "follow: tip unchanged, no pass needed");
                    continue;
                }

                tracing::info!(last_tip, observed, "follow: tip advanced, running catch-up pass");

                // New block(s): Syncing for the pass duration, then Done. Follow passes are ALWAYS
                // keyless (ufvk=None) — the account is already imported; passing Some would waste a
                // GetTreeState RPC on every catch-up pass.
                reporter.set_state(SyncState::Syncing);
                match run_pass_with_retry(&config.engine, None, &reporter.progress, tor_conn.as_ref())
                    .await
                {
                    Ok(o) => {
                        last_tip = o.chain_tip;
                        consecutive_failures = 0;
                        reporter.set_state(SyncState::Done);
                        reporter.push_event(FfiSlipstreamEvent {
                            tag: 3,
                            value: o.enhance.txs_stored,
                        });
                    }
                    Err(err) => {
                        consecutive_failures += 1;
                        // T8.7: a failed catch-up pass is RECOVERABLE — the wallet is still synced
                        // to last_tip. Revert to Done (NOT Error) and retry on the next tick.
                        tracing::warn!(
                            %err,
                            consecutive_failures,
                            last_tip,
                            failed_at_utc = %wall_clock_utc(),
                            "follow catch-up pass failed — staying synced, will retry"
                        );
                        reporter.set_state(SyncState::Done);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SlipstreamError;

    // ── should_retry pure logic (T6.8-H2) ───────────────────────────────────

    #[test]
    fn should_retry_transient_attempt_1_returns_5s() {
        let err = SlipstreamError::Transport("timed out after 30s".into());
        assert_eq!(should_retry(&err, 1), Some(Duration::from_secs(5)));
    }

    #[test]
    fn should_retry_transient_attempt_2_returns_15s() {
        let err = SlipstreamError::Transport("stream idle timeout".into());
        assert_eq!(should_retry(&err, 2), Some(Duration::from_secs(15)));
    }

    #[test]
    fn should_retry_transient_exhausted_returns_none() {
        let err = SlipstreamError::Transport("connect refused".into());
        assert!(should_retry(&err, PASS_RETRY_MAX + 1).is_none());
    }

    #[test]
    fn should_retry_non_transient_returns_none_always() {
        let wallet = SlipstreamError::Wallet("scan_cached_blocks: continuity error".into());
        assert!(should_retry(&wallet, 1).is_none());
        let config = SlipstreamError::Config("bad birthday".into());
        assert!(should_retry(&config, 1).is_none());
        let cont = SlipstreamError::ScanContinuity { at: 663_195 };
        assert!(should_retry(&cont, 1).is_none());
        let misbehaving = SlipstreamError::MisbehavingServer;
        assert!(should_retry(&misbehaving, 1).is_none());
    }

    #[test]
    fn pass_retry_max_is_two() {
        assert_eq!(PASS_RETRY_MAX, 2, "PASS_RETRY_MAX must be 2 (3 total attempts)");
        assert_eq!(pass_retry_sleep(1), Duration::from_secs(5));
        assert_eq!(pass_retry_sleep(2), Duration::from_secs(15));
        assert_eq!(pass_retry_sleep(3), Duration::from_secs(15)); // default arm
    }

    // ── T8.1 follow-poll jitter ──────────────────────────────────────────────

    #[test]
    fn follow_poll_jitter_min_sample_yields_min_secs() {
        assert_eq!(follow_poll_jitter(0.0), Duration::from_secs(FOLLOW_POLL_MIN_SECS));
    }

    #[test]
    fn follow_poll_jitter_near_max_sample_yields_at_most_max_secs() {
        let d = follow_poll_jitter(f64::from(u32::MAX) / f64::from(u32::MAX) - f64::EPSILON * 64.0);
        assert!(d <= Duration::from_secs(FOLLOW_POLL_MAX_SECS));
        assert!(d >= Duration::from_secs(FOLLOW_POLL_MIN_SECS));
    }

    #[test]
    fn follow_poll_jitter_midpoint_is_between_bounds() {
        let d = follow_poll_jitter(0.5);
        assert!(d >= Duration::from_secs(FOLLOW_POLL_MIN_SECS));
        assert!(d <= Duration::from_secs(FOLLOW_POLL_MAX_SECS));
    }

    // ── T8.7 resilient backoff ───────────────────────────────────────────────

    #[test]
    fn sync_retry_backoff_grows_then_caps() {
        assert_eq!(sync_retry_backoff(1), Duration::from_secs(3));
        assert_eq!(sync_retry_backoff(2), Duration::from_secs(6));
        assert_eq!(sync_retry_backoff(3), Duration::from_secs(12));
        assert_eq!(sync_retry_backoff(4), Duration::from_secs(24));
        assert_eq!(sync_retry_backoff(5), Duration::from_secs(30));
        assert_eq!(sync_retry_backoff(100), Duration::from_secs(30));
    }

    // ── cap sanity ───────────────────────────────────────────────────────────

    #[test]
    fn follow_poll_is_in_old_sdk_band() {
        assert!(FOLLOW_POLL_MIN_SECS >= 10, "min must be >= 10 (old-SDK floor)");
        assert!(FOLLOW_POLL_MAX_SECS <= 30, "max must be <= 30 (old-SDK ceiling)");
        assert!(FOLLOW_POLL_MIN_SECS <= FOLLOW_POLL_MAX_SECS, "min must be <= max");
    }

    #[test]
    fn follow_failure_cap_is_sane() {
        assert!(FOLLOW_FAILURE_CAP >= 3, "must tolerate transient server weather");
    }

    #[test]
    fn mempool_failure_cap_is_sane() {
        assert!(MEMPOOL_FAILURE_CAP >= 1, "one failure must not disable mempool");
        assert!(
            MEMPOOL_FAILURE_CAP < FOLLOW_FAILURE_CAP,
            "mempool (non-essential) must give up before the essential tip poll"
        );
    }

    // ── SessionReporter ──────────────────────────────────────────────────────

    fn reporter() -> SessionReporter {
        SessionReporter {
            progress: Arc::new(Progress::default()),
            state: Arc::new(Mutex::new(SyncState::Idle)),
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    #[test]
    fn reporter_push_event_caps_at_ring_cap() {
        let r = reporter();
        // Push CAP + 6 events; only the last CAP survive, oldest 6 dropped.
        for i in 0u64..(EVENT_RING_CAP as u64 + 6) {
            r.push_event(FfiSlipstreamEvent { tag: 1, value: i });
        }
        let ring = r.events.lock().unwrap();
        assert_eq!(ring.len(), EVENT_RING_CAP);
        assert_eq!(ring[0].value, 6, "oldest 6 must be dropped");
        assert_eq!(ring[EVENT_RING_CAP - 1].value, EVENT_RING_CAP as u64 + 5);
    }

    #[test]
    fn reporter_set_state_writes() {
        let r = reporter();
        r.set_state(SyncState::Syncing);
        assert_eq!(*r.state.lock().unwrap(), SyncState::Syncing);
        r.set_state(SyncState::Error(2));
        assert_eq!(*r.state.lock().unwrap(), SyncState::Error(2));
    }

    /// The pass-lock contract `run_session` relies on (Keystone restore race fix, 2026-06-30):
    /// an ABORTED task that holds `pass_lock` MUST release it so the next pass can acquire —
    /// otherwise `importAccount`'s `start()`-while-running restart would deadlock instead of
    /// racing. Proves a cancelled holder drops its guard (a tokio `Mutex` is not poisoned by
    /// cancellation) and the next acquirer then proceeds promptly. This is the property that lets
    /// `run_session` hold `pass_lock` for the whole follow loop yet still be safely restarted.
    #[tokio::test]
    async fn pass_lock_released_when_holder_is_aborted() {
        let lock = Arc::new(tokio::sync::Mutex::new(()));

        // Task A acquires the lock and holds it until aborted (mirrors the OLD pass running the
        // follow loop forever). It signals once it actually holds the guard.
        let (tx, rx) = tokio::sync::oneshot::channel();
        let a_lock = Arc::clone(&lock);
        let a = tokio::spawn(async move {
            let _g = a_lock.lock().await;
            let _ = tx.send(());
            std::future::pending::<()>().await; // hold until aborted
        });
        rx.await.expect("task A signals it holds the pass lock");

        // The lock is genuinely held: a bounded acquire times out.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), lock.lock())
                .await
                .is_err(),
            "pass lock must be held by the in-flight pass"
        );

        // Abort A — exactly what `zcashlc_slipstream_start` does to the previous pass on restart.
        a.abort();

        // The aborted holder must release the lock so the NEW pass can acquire — no deadlock.
        let _reacquired = tokio::time::timeout(Duration::from_millis(500), lock.lock())
            .await
            .expect("an aborted pass must release pass_lock so the restart can proceed");
    }
}
