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
        // `.uniqueTor` = a fresh isolated circuit; `.defaultTor` = the default circuit.
        let client = match mode {
            TorMode::Isolated => self.client.isolated_client(),
            TorMode::Default => self.client.clone(),
        };
        let uri: Uri = endpoint
            .uri()
            .parse()
            .map_err(|e| SlipstreamError::Config(format!("bad endpoint uri for tor: {e}")))?;
        client
            .connect_to_lightwalletd(uri)
            .await
            .map_err(|e| SlipstreamError::Transport(format!("tor connect: {e}")))
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
        match (&self.tor, tor_mode(purpose)) {
            (Some(tor), Some(mode)) => tor.connect(mode, &self.endpoint).await,
            // Tor off (None), or BulkFetch (tor_mode == None → always direct, even with Tor on).
            _ => grpc::connect(&self.endpoint).await,
        }
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
}
