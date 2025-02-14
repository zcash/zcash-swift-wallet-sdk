//! Tor support

use std::path::Path;

use tor_rtcompat::{BlockOn, PreferredRuntime};
use zcash_client_backend::tor::Client;

pub struct TorRuntime {
    runtime: PreferredRuntime,
    client: Client,
}

impl TorRuntime {
    #[tracing::instrument]
    pub(crate) fn create(tor_dir: &Path, dangerously_trust_everyone: bool) -> anyhow::Result<Self> {
        let runtime = PreferredRuntime::create()?;
        let client = runtime.block_on(async {
            Client::create(tor_dir, |permissions: &mut fs_mistrust::MistrustBuilder| {
                if dangerously_trust_everyone {
                    permissions.dangerously_trust_everyone();
                }
            })
            .await
        })?;
        Ok(Self { runtime, client })
    }

    pub(crate) fn runtime(&self) -> &PreferredRuntime {
        &self.runtime
    }

    pub(crate) fn client(&self) -> &Client {
        &self.client
    }

    /// Returns a new isolated `TorRuntime ` handle.
    ///
    /// The two `TorRuntime `s will share internal state and configuration, but their
    /// streams will never share circuits with one another.
    ///
    /// Use this method when you want separate parts of your program to each have a
    /// `TorRuntime ` handle, but where you don't want their activities to be linkable to
    /// one another over the Tor network.
    ///
    /// Calling this method is usually preferable to creating a completely separate
    /// `TorRuntime ` instance, since it can share its internals with the existing
    /// `TorRuntime `.
    pub(crate) fn isolated_client(&self) -> Self {
        Self {
            runtime: self.runtime.clone(),
            client: self.client.isolated_client(),
        }
    }
}
