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
    pub(crate) fn create(tor_dir: &Path) -> anyhow::Result<Self> {
        let runtime = PreferredRuntime::create()?;
        let client = runtime.block_on(async { Client::create(tor_dir).await })?;
        Ok(Self { runtime, client })
    }

    pub(crate) fn runtime(&self) -> &PreferredRuntime {
        &self.runtime
    }

    pub(crate) fn client(&self) -> &Client {
        &self.client
    }
}
