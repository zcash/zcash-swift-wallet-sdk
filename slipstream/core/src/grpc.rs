//! Direct (non-Tor) lightwalletd connectivity. Produces the same client type
//! `rust/src/tor.rs` uses (`CompactTxStreamerClient<Channel>`) so a Tor-backed
//! channel can be swapped in later (P8) without touching callers.

use futures_util::TryStreamExt;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint as TonicEndpoint};
use zcash_client_backend::{
    data_api::chain::CommitmentTreeRoot,
    proto::service::{
        BlockId, ChainSpec, Empty, GetSubtreeRootsArg, LightdInfo, ShieldedProtocol, TreeState,
        compact_tx_streamer_client::CompactTxStreamerClient,
    },
};
use zcash_primitives::merkle_tree::HashSer;

use crate::{config::Endpoint, error::SlipstreamError};

pub type LwdClient = CompactTxStreamerClient<Channel>;

fn transport_err(context: &str, e: impl std::fmt::Display) -> SlipstreamError {
    SlipstreamError::Transport(format!("{context}: {e}"))
}

/// Open a channel to lightwalletd. TLS uses webpki roots (same trust source
/// as the upstream tor module).
pub async fn connect(endpoint: &Endpoint) -> Result<LwdClient, SlipstreamError> {
    let mut ep = TonicEndpoint::from_shared(endpoint.uri())
        .map_err(|e| transport_err("endpoint uri", e))?
        .connect_timeout(std::time::Duration::from_secs(10));
    if endpoint.tls {
        ep = ep
            .tls_config(ClientTlsConfig::new().with_webpki_roots())
            .map_err(|e| transport_err("tls config", e))?;
    }
    let channel = ep
        .connect()
        .await
        .map_err(|e| transport_err(&format!("connect {}", endpoint.host), e))?;
    Ok(CompactTxStreamerClient::new(channel))
}

pub async fn get_lightd_info(client: &mut LwdClient) -> Result<LightdInfo, SlipstreamError> {
    Ok(client
        .get_lightd_info(Empty {})
        .await
        .map_err(|e| transport_err("get_lightd_info", e))?
        .into_inner())
}

pub async fn get_latest_block_height(client: &mut LwdClient) -> Result<u64, SlipstreamError> {
    Ok(client
        .get_latest_block(ChainSpec {})
        .await
        .map_err(|e| transport_err("get_latest_block", e))?
        .into_inner()
        .height)
}

pub async fn get_tree_state(client: &mut LwdClient, height: u64) -> Result<TreeState, SlipstreamError> {
    Ok(client
        .get_tree_state(BlockId { height, hash: vec![] })
        .await
        .map_err(|e| transport_err("get_tree_state", e))?
        .into_inner())
}

/// Collected subtree roots for both pools (Sapling first, Orchard second).
pub struct SubtreeRoots {
    pub sapling: Vec<CommitmentTreeRoot<sapling::Node>>,
    pub orchard: Vec<CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>>,
}

pub async fn get_subtree_roots(client: &mut LwdClient) -> Result<SubtreeRoots, SlipstreamError> {
    let mut req = GetSubtreeRootsArg::default();
    req.set_shielded_protocol(ShieldedProtocol::Sapling);
    let sapling_roots: Vec<CommitmentTreeRoot<sapling::Node>> = client
        .get_subtree_roots(req)
        .await
        .map_err(|e| transport_err("get_subtree_roots(sapling)", e))?
        .into_inner()
        .map_err(|e| SlipstreamError::Transport(format!("subtree root stream: {e}")))
        .and_then(|r| async move {
            let node = sapling::Node::read(&r.root_hash[..])
                .map_err(|e| SlipstreamError::Transport(format!("sapling root: {e}")))?;
            Ok(CommitmentTreeRoot::from_parts(
                zcash_protocol::consensus::BlockHeight::from_u32(r.completing_block_height as u32),
                node,
            ))
        })
        .try_collect()
        .await?;

    let mut req = GetSubtreeRootsArg::default();
    req.set_shielded_protocol(ShieldedProtocol::Orchard);
    let orchard_roots: Vec<CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>> = client
        .get_subtree_roots(req)
        .await
        .map_err(|e| transport_err("get_subtree_roots(orchard)", e))?
        .into_inner()
        .map_err(|e| SlipstreamError::Transport(format!("subtree root stream: {e}")))
        .and_then(|r| async move {
            let node = orchard::tree::MerkleHashOrchard::read(&r.root_hash[..])
                .map_err(|e| SlipstreamError::Transport(format!("orchard root: {e}")))?;
            Ok(CommitmentTreeRoot::from_parts(
                zcash_protocol::consensus::BlockHeight::from_u32(r.completing_block_height as u32),
                node,
            ))
        })
        .try_collect()
        .await?;

    Ok(SubtreeRoots { sapling: sapling_roots, orchard: orchard_roots })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Endpoint;

    #[tokio::test]
    async fn connect_to_unroutable_host_fails_with_transport_error() {
        let ep = Endpoint { host: "127.0.0.1".into(), port: 1, tls: false };
        match connect(&ep).await {
            Err(SlipstreamError::Transport(msg)) => assert!(msg.contains("connect")),
            other => panic!("expected Transport error, got {other:?}"),
        }
    }

    // Live-network smoke; run manually: cargo test -p slipstream-core -- --ignored
    #[tokio::test]
    #[ignore = "network"]
    async fn live_lightd_info_smoke() {
        let ep = Endpoint { host: "zec.rocks".into(), port: 443, tls: true };
        let mut c = connect(&ep).await.expect("connect");
        let info = get_lightd_info(&mut c).await.expect("info");
        assert_eq!(info.chain_name, "main");
        let h = get_latest_block_height(&mut c).await.expect("height");
        assert!(h > 2_000_000);
    }
}
