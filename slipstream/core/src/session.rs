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
use crate::engine::{SyncOutcome, sync_once};
use crate::error::SlipstreamError;
use crate::events::Progress;
use crate::ffi_handle::{EVENT_RING_CAP, FfiSlipstreamEvent, SyncState};

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
// Used by `run_session` (added in R2); allow the transient unused-warning until then.
#[allow(dead_code)]
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

    /// Push one event onto the ring, dropping the oldest when full (cap-then-push at
    /// `EVENT_RING_CAP` — the exact pre-lift `push_ring_event` semantics).
    pub fn push_event(&self, e: FfiSlipstreamEvent) {
        let mut ring = self.events.lock().unwrap_or_else(|p| p.into_inner());
        if ring.len() >= EVENT_RING_CAP {
            ring.remove(0);
        }
        ring.push(e);
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
}
