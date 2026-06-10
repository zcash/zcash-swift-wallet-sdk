//! Control-plane client for darkside lightwalletd (hermetic integration tests).
//! Drives Reset / StageBlocksCreate / ApplyStaged so transport tests run
//! against the real lightwalletd implementation with fabricated blocks.

use tonic::transport::Channel;
use zcash_client_backend::proto::service::Empty;

use crate::{
    config::Endpoint,
    darkside_generated::{
        DarksideEmptyBlocks, DarksideHeight, DarksideMetaState,
        darkside_streamer_client::DarksideStreamerClient,
    },
    error::SlipstreamError,
};

/// Canonical darkside chain params (match the Swift DarksideTests).
pub const SAPLING_ACTIVATION: i32 = 663_150;
pub const BRANCH_ID: &str = "2bb40e60";
pub const CHAIN_NAME: &str = "main";

pub struct DarksideCtl {
    client: DarksideStreamerClient<Channel>,
}

fn err(context: &str, e: impl std::fmt::Display) -> SlipstreamError {
    SlipstreamError::Transport(format!("darkside {context}: {e}"))
}

impl DarksideCtl {
    pub async fn connect(endpoint: &Endpoint) -> Result<Self, SlipstreamError> {
        let channel = tonic::transport::Endpoint::from_shared(endpoint.uri())
            .map_err(|e| err("uri", e))?
            .connect()
            .await
            .map_err(|e| err("connect", e))?;
        Ok(Self { client: DarksideStreamerClient::new(channel) })
    }

    pub async fn reset(&mut self) -> Result<(), SlipstreamError> {
        self.client
            .reset(DarksideMetaState {
                sapling_activation: SAPLING_ACTIVATION,
                branch_id: BRANCH_ID.into(),
                chain_name: CHAIN_NAME.into(),
                start_sapling_commitment_tree_size: 0,
                start_orchard_commitment_tree_size: 0,
            })
            .await
            .map_err(|e| err("reset", e))?;
        Ok(())
    }

    /// Fabricate `count` empty blocks starting at `height` (staged, not yet live).
    pub async fn stage_blocks_create(
        &mut self,
        height: i32,
        count: i32,
    ) -> Result<(), SlipstreamError> {
        self.client
            .stage_blocks_create(DarksideEmptyBlocks { height, nonce: 0, count })
            .await
            .map_err(|e| err("stage_blocks_create", e))?;
        Ok(())
    }

    /// Make staged blocks up to `height` visible to GetBlockRange.
    pub async fn apply_staged(&mut self, height: i32) -> Result<(), SlipstreamError> {
        self.client
            .apply_staged(DarksideHeight { height })
            .await
            .map_err(|e| err("apply_staged", e))?;
        Ok(())
    }

    pub async fn ping(&mut self) -> Result<(), SlipstreamError> {
        // GetIncomingTransactions on a fresh darkside returns an (empty) stream —
        // cheap liveness probe.
        let _ = self
            .client
            .get_incoming_transactions(Empty {})
            .await
            .map_err(|e| err("ping", e))?;
        Ok(())
    }
}
