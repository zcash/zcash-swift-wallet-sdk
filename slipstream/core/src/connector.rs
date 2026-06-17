//! Lightwalletd connection factory honoring the old SDK's per-call Tor policy.
//!
//! Mirrors the old SDK's `ServiceMode`: the **bulk** block fetch is ALWAYS direct (the old
//! SDK's `blockStream` uses `.direct` — public range data, too high-volume for Tor; per-user
//! exposure (IP + birthday) is identical with or without Tor). Wallet-**identifying** metadata
//! (treestate, latest-block, lightd info) goes over **isolated Tor circuits** when Tor is on.
//!
//! Tor is transport-only — the bytes written to the wallet DB are identical either way, so the
//! golden + darkside oracles are unaffected.
//!
//! Runtime model (T-Tor.0, GO): the engine OWNS its arti [`TorConn`], bootstrapped on the
//! engine's own tokio runtime (`Client::create` binds to `PreferredRuntime::current()`), so no
//! `block_on` and no cross-runtime polling — see `tests/tor_runtime_spike.rs`.

use std::path::Path;

use tonic::transport::Uri;
use zcash_client_backend::tor::Client as TorClient;

use crate::{
    config::Endpoint,
    error::SlipstreamError,
    grpc::{self, LwdClient},
};

/// Why a lightwalletd connection is being opened — selects direct vs Tor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnPurpose {
    /// Bulk compact-block download. ALWAYS direct, even with Tor on (mirrors `blockStream(.direct)`).
    BulkFetch,
    /// Wallet-identifying metadata (treestate, latest-block, tip). Isolated Tor (`.uniqueTor`).
    MetadataUnique,
    /// Server validation / lightd info. Default Tor circuit (`.defaultTor`).
    MetadataDefault,
}

/// Which Tor circuit a purpose uses, or `None` for direct. This is the single source of the
/// per-call policy (mirrors the old SDK's `ServiceMode` mapping); [`Connector::connect`] uses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TorMode {
    Isolated,
    Default,
}

fn tor_mode(purpose: ConnPurpose) -> Option<TorMode> {
    match purpose {
        ConnPurpose::BulkFetch => None, // always direct
        ConnPurpose::MetadataUnique => Some(TorMode::Isolated),
        ConnPurpose::MetadataDefault => Some(TorMode::Default),
    }
}

/// Per-attempt timeout for building a Tor circuit + connecting to lightwalletd. A healthy circuit
/// builds in a few seconds; a STUCK one (dead relay / bad path) is cut here so we can retry on a
/// FRESH isolated circuit instead of blocking on arti's much longer internal circuit-build
/// timeout. Field evidence (2026-06-17, device, Tor ON): a single stuck circuit wedged a per-range
/// enhancement connect for ~58s, turning a ~90s restore into ~161s. 15s leaves a slow-but-healthy
/// circuit room while cutting a stuck one promptly.
const TOR_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Fresh-circuit attempts before giving up a single connect. With `Isolated` mode each attempt
/// draws a NEW isolated circuit, so a transient bad circuit recovers on the next try. The error
/// returned after all attempts is still `Transport` (transient) — every higher resilience layer
/// (scan treestate retry, the per-range enhancement's non-fatal defer, the initial-pass
/// never-Error retry loop) still stacks on top. 3 attempts ⇒ ≤45s worst case vs the old single
/// ~58s-then-fail, and ~0 overhead in the healthy case (attempt 1 connects fast).
const TOR_CONNECT_ATTEMPTS: u32 = 3;

/// A bootstrapped arti Tor client, owned by the engine and driven on its own runtime.
#[derive(Clone)]
pub struct TorConn {
    client: TorClient,
}

impl TorConn {
    /// Bootstrap a Tor client on the CURRENT (engine's) runtime, from `tor_dir`.
    /// Performs the one-time Tor bootstrap; call once at sync start when Tor is enabled.
    pub async fn bootstrap(
        tor_dir: &Path,
        dangerously_trust_everyone: bool,
    ) -> Result<Self, SlipstreamError> {
        let client = TorClient::create(tor_dir, |permissions| {
            if dangerously_trust_everyone {
                permissions.dangerously_trust_everyone();
            }
        })
        .await
        .map_err(|e| SlipstreamError::Transport(format!("tor bootstrap: {e}")))?;
        Ok(Self { client })
    }

    async fn connect(&self, mode: TorMode, endpoint: &Endpoint) -> Result<LwdClient, SlipstreamError> {
        let uri: Uri = endpoint
            .uri()
            .parse()
            .map_err(|e| SlipstreamError::Config(format!("bad endpoint uri for tor: {e}")))?;

        // Bounded circuit build + retry on a FRESH circuit (see TOR_CONNECT_* docs). A stuck
        // circuit is cut at TOR_CONNECT_TIMEOUT and the next attempt draws a new isolated circuit,
        // instead of blocking on arti's long internal timeout. The healthy case connects on
        // attempt 1 with no added latency.
        let mut last_err: Option<String> = None;
        for attempt in 1..=TOR_CONNECT_ATTEMPTS {
            // `.uniqueTor` = a fresh isolated circuit EACH attempt (so a retry escapes a stuck
            // circuit); `.defaultTor` = the default circuit.
            let client = match mode {
                TorMode::Isolated => self.client.isolated_client(),
                TorMode::Default => self.client.clone(),
            };
            match tokio::time::timeout(
                TOR_CONNECT_TIMEOUT,
                client.connect_to_lightwalletd(uri.clone()),
            )
            .await
            {
                Ok(Ok(c)) => return Ok(c),
                Ok(Err(e)) => {
                    tracing::warn!(attempt, err = %e, "tor connect failed — retrying on a fresh circuit");
                    last_err = Some(format!("tor connect: {e}"));
                }
                Err(_elapsed) => {
                    tracing::warn!(
                        attempt,
                        timeout_secs = TOR_CONNECT_TIMEOUT.as_secs(),
                        "tor circuit build timed out — retrying on a fresh circuit"
                    );
                    last_err = Some(format!(
                        "tor connect: circuit build exceeded {}s",
                        TOR_CONNECT_TIMEOUT.as_secs()
                    ));
                }
            }
        }
        // Still transient — callers retry/defer (the build never silently de-anonymises to direct).
        Err(SlipstreamError::Transport(last_err.unwrap_or_else(|| {
            "tor connect: failed to obtain a circuit".to_string()
        })))
    }
}

/// Builds lightwalletd clients honoring the per-call Tor policy.
#[derive(Clone)]
pub struct Connector {
    endpoint: Endpoint,
    tor: Option<TorConn>,
}

impl Connector {
    /// Tor-off: every purpose dials directly.
    pub fn direct(endpoint: Endpoint) -> Self {
        Self { endpoint, tor: None }
    }

    /// Tor-on: metadata over Tor, bulk still direct.
    pub fn with_tor(endpoint: Endpoint, tor: TorConn) -> Self {
        Self {
            endpoint,
            tor: Some(tor),
        }
    }

    /// Open a lightwalletd client for `purpose`.
    pub async fn connect(&self, purpose: ConnPurpose) -> Result<LwdClient, SlipstreamError> {
        connect_via(&self.endpoint, self.tor.as_ref(), purpose).await
    }
}

/// Free-function form of [`Connector::connect`] for call sites that already thread `endpoint`
/// (from `EngineConfig`) and an optional Tor handle separately — avoids restructuring the run
/// path around the bundled [`Connector`]. Same per-call policy: bulk → direct; metadata → Tor
/// when `tor` is `Some`. The bulk path (`tor_mode == None`) stays on the plain direct client even
/// with Tor on, mirroring the old SDK's `blockStream(.direct)`.
pub async fn connect_via(
    endpoint: &Endpoint,
    tor: Option<&TorConn>,
    purpose: ConnPurpose,
) -> Result<LwdClient, SlipstreamError> {
    match (tor, tor_mode(purpose)) {
        (Some(t), Some(mode)) => t.connect(mode, endpoint).await,
        _ => grpc::connect(endpoint).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulk_is_always_direct() {
        // Even when Tor is on, bulk fetch carries no Tor circuit (mirrors blockStream(.direct)).
        assert_eq!(tor_mode(ConnPurpose::BulkFetch), None);
    }

    #[test]
    fn metadata_maps_to_isolated_and_default_circuits() {
        assert_eq!(tor_mode(ConnPurpose::MetadataUnique), Some(TorMode::Isolated)); // .uniqueTor
        assert_eq!(tor_mode(ConnPurpose::MetadataDefault), Some(TorMode::Default)); // .defaultTor
    }

    /// Locks the bounded-retry design intent: at least one fresh-circuit retry, and a per-attempt
    /// timeout that gives a healthy circuit room (>=5s) while cutting a stuck one promptly (<=30s).
    #[test]
    fn tor_connect_retry_constants_are_sane() {
        assert!(
            TOR_CONNECT_ATTEMPTS >= 2,
            "need at least one retry on a fresh circuit"
        );
        let secs = TOR_CONNECT_TIMEOUT.as_secs();
        assert!(
            (5..=30).contains(&secs),
            "per-attempt timeout must be 5..=30s (room for a healthy circuit, cut a stuck one), got {secs}s"
        );
    }
}
