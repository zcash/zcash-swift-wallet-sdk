//! Direct (non-Tor) lightwalletd connectivity. Produces the same client type
//! `rust/src/tor.rs` uses (`CompactTxStreamerClient<Channel>`) so a Tor-backed
//! channel can be swapped in later (P8) without touching callers.

use std::time::Duration;

use futures_util::StreamExt;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint as TonicEndpoint};
use zcash_client_backend::{
    data_api::chain::CommitmentTreeRoot,
    proto::service::{
        BlockId, ChainSpec, Empty, GetAddressUtxosArg, GetAddressUtxosReply, GetSubtreeRootsArg,
        LightdInfo, RawTransaction, ShieldedProtocol, TransparentAddressBlockFilter, TreeState,
        TxFilter, compact_tx_streamer_client::CompactTxStreamerClient,
    },
};
use zcash_primitives::merkle_tree::HashSer;

use crate::{config::Endpoint, error::SlipstreamError};

pub type LwdClient = CompactTxStreamerClient<Channel>;

// ── B2 (#1755 failure-path hardening) transport deadlines ──────────────────────
//
// A stalled-but-open connection (NAT/LB silently dropping a flow, a wedged
// backend in a load-balanced cluster) previously hung the corresponding await
// FOREVER — the engine state stayed "Syncing" with frozen counters and zero
// logs (field failure 2, 2026-06-12). Every call below now carries a deadline;
// the resulting Transport error flows into the existing retry/recovery
// semantics (fetch chunks retry+reconnect; per-range/interleaved enhancement is
// non-fatal; preflight/treestate/final-enhancement errors fail the pass loudly).

/// Hard deadline for a single unary gRPC call (and for the response headers of
/// a server-streaming call).
pub(crate) const UNARY_TIMEOUT: Duration = Duration::from_secs(30);

/// Idle deadline between consecutive messages of a server-streaming response.
/// A healthy stream delivers messages continuously; 30 s of silence on an open
/// stream means the connection is dead.
pub(crate) const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

fn transport_err(context: &str, e: impl std::fmt::Display) -> SlipstreamError {
    SlipstreamError::Transport(format!("{context}: {e}"))
}

/// Awaits a unary gRPC call under [`UNARY_TIMEOUT`]; maps both the gRPC status
/// and a deadline expiry into [`SlipstreamError::Transport`].
async fn with_unary_timeout<T>(
    context: &str,
    fut: impl std::future::Future<Output = Result<tonic::Response<T>, tonic::Status>>,
) -> Result<T, SlipstreamError> {
    match tokio::time::timeout(UNARY_TIMEOUT, fut).await {
        Ok(Ok(resp)) => Ok(resp.into_inner()),
        Ok(Err(status)) => Err(transport_err(context, status)),
        Err(_) => Err(SlipstreamError::Transport(format!(
            "{context}: timed out after {}s",
            UNARY_TIMEOUT.as_secs()
        ))),
    }
}

/// `stream.next()` under [`STREAM_IDLE_TIMEOUT`]; `Ok(None)` = clean end of stream.
pub(crate) async fn next_with_idle_timeout<T, S>(
    stream: &mut S,
    context: &str,
) -> Result<Option<Result<T, tonic::Status>>, SlipstreamError>
where
    S: futures_util::Stream<Item = Result<T, tonic::Status>> + Unpin,
{
    tokio::time::timeout(STREAM_IDLE_TIMEOUT, stream.next()).await.map_err(|_| {
        SlipstreamError::Transport(format!(
            "{context}: stream idle timeout ({}s without a message)",
            STREAM_IDLE_TIMEOUT.as_secs()
        ))
    })
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
    with_unary_timeout("get_lightd_info", client.get_lightd_info(Empty {})).await
}

pub async fn get_latest_block_height(client: &mut LwdClient) -> Result<u64, SlipstreamError> {
    Ok(with_unary_timeout("get_latest_block", client.get_latest_block(ChainSpec {}))
        .await?
        .height)
}

pub async fn get_tree_state(client: &mut LwdClient, height: u64) -> Result<TreeState, SlipstreamError> {
    with_unary_timeout("get_tree_state", client.get_tree_state(BlockId { height, hash: vec![] }))
        .await
}

/// Collected subtree roots for both pools (Sapling first, Orchard second).
pub struct SubtreeRoots {
    pub sapling: Vec<CommitmentTreeRoot<sapling::Node>>,
    pub orchard: Vec<CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>>,
}

/// One pool's subtree-root stream, collected under per-message idle deadlines (B2).
async fn collect_subtree_roots<H: HashSer>(
    client: &mut LwdClient,
    protocol: ShieldedProtocol,
    label: &str,
) -> Result<Vec<CommitmentTreeRoot<H>>, SlipstreamError> {
    let mut req = GetSubtreeRootsArg::default();
    req.set_shielded_protocol(protocol);
    let context = format!("get_subtree_roots({label})");
    let mut stream = with_unary_timeout(&context, client.get_subtree_roots(req)).await?;
    let mut roots = Vec::new();
    while let Some(item) = next_with_idle_timeout(&mut stream, &context).await? {
        let r = item.map_err(|e| SlipstreamError::Transport(format!("subtree root stream: {e}")))?;
        let node = H::read(&r.root_hash[..])
            .map_err(|e| SlipstreamError::Transport(format!("{label} root: {e}")))?;
        roots.push(CommitmentTreeRoot::from_parts(
            zcash_protocol::consensus::BlockHeight::from_u32(r.completing_block_height as u32),
            node,
        ));
    }
    Ok(roots)
}

pub async fn get_subtree_roots(client: &mut LwdClient) -> Result<SubtreeRoots, SlipstreamError> {
    let sapling_roots =
        collect_subtree_roots::<sapling::Node>(client, ShieldedProtocol::Sapling, "sapling")
            .await?;
    let orchard_roots = collect_subtree_roots::<orchard::tree::MerkleHashOrchard>(
        client,
        ShieldedProtocol::Orchard,
        "orchard",
    )
    .await?;
    Ok(SubtreeRoots { sapling: sapling_roots, orchard: orchard_roots })
}

/// Fetch a full transaction by txid.
///
/// Returns `Ok(Some(raw))` on success, `Ok(None)` when the server reports the
/// transaction is not found (tonic `NotFound` status code, or `Unknown`/`Internal`
/// with a "not found" message — lightwalletd v0.4.9 uses `Unknown` for unknown txids),
/// and `Err` for all other transport-level failures (connection refused, timeout, etc.).
///
/// # Deviation from T3.1 plan
/// The original T3.1 wrapper returned `Result<RawTransaction, SlipstreamError>`.
/// Changed to `Result<Option<RawTransaction>, SlipstreamError>` per T3.2 Binding Note 4:
/// enhancement must tolerate per-txid "not found" from the server (→ `TxidNotRecognized`)
/// while propagating connection-class errors to the caller.
pub async fn get_transaction(
    client: &mut LwdClient,
    txid: [u8; 32],
) -> Result<Option<RawTransaction>, SlipstreamError> {
    // B2: unary deadline; the not-found mapping below needs the raw status, so this
    // call cannot reuse with_unary_timeout's uniform error mapping.
    let outcome = tokio::time::timeout(
        UNARY_TIMEOUT,
        client.get_transaction(TxFilter { hash: txid.to_vec(), ..Default::default() }),
    )
    .await
    .map_err(|_| {
        SlipstreamError::Transport(format!(
            "get_transaction: timed out after {}s",
            UNARY_TIMEOUT.as_secs()
        ))
    })?;
    match outcome {
        Ok(resp) => Ok(Some(resp.into_inner())),
        Err(status) => {
            // lightwalletd returns NotFound or Unknown/Internal with "not found" message
            // for unrecognized txids. Treat these as Ok(None) — caller maps to
            // TxidNotRecognized. All other status codes propagate as transport errors.
            let code = status.code();
            let msg_lower = status.message().to_lowercase();
            if code == tonic::Code::NotFound
                || ((code == tonic::Code::Unknown || code == tonic::Code::Internal)
                    && (msg_lower.contains("not found")
                        || msg_lower.contains("no such transaction")))
            {
                Ok(None)
            } else {
                Err(transport_err("get_transaction", status))
            }
        }
    }
}

/// Stream raw transactions involving a transparent address in a height range.
pub async fn get_taddress_txids(
    client: &mut LwdClient,
    filter: TransparentAddressBlockFilter,
) -> Result<Vec<RawTransaction>, SlipstreamError> {
    let mut stream =
        with_unary_timeout("get_taddress_txids", client.get_taddress_txids(filter)).await?;
    let mut txs = Vec::new();
    while let Some(item) = next_with_idle_timeout(&mut stream, "get_taddress_txids").await? {
        txs.push(
            item.map_err(|e| SlipstreamError::Transport(format!("taddress txid stream: {e}")))?,
        );
    }
    Ok(txs)
}

/// Collect UTXOs for the given transparent addresses from `start_height`.
pub async fn get_address_utxos(
    client: &mut LwdClient,
    addresses: Vec<String>,
    start_height: u64,
) -> Result<Vec<GetAddressUtxosReply>, SlipstreamError> {
    let mut stream = with_unary_timeout(
        "get_address_utxos",
        client.get_address_utxos_stream(GetAddressUtxosArg {
            addresses,
            start_height,
            max_entries: 0,
        }),
    )
    .await?;
    let mut utxos = Vec::new();
    while let Some(item) = next_with_idle_timeout(&mut stream, "get_address_utxos").await? {
        utxos.push(item.map_err(|e| SlipstreamError::Transport(format!("utxo stream: {e}")))?);
    }
    Ok(utxos)
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

    // ── B2 (#1755) deadline tests — `start_paused` auto-advances the mock clock
    // when the runtime is idle, so the 30 s deadlines fire instantly. ───────────

    /// A unary call that never resolves (stalled-but-open connection) must
    /// surface as a Transport timeout, never hang.
    #[tokio::test(start_paused = true)]
    async fn unary_timeout_fires_on_stalled_call() {
        let fut =
            futures_util::future::pending::<Result<tonic::Response<()>, tonic::Status>>();
        match with_unary_timeout("stalled_unary", fut).await {
            Err(SlipstreamError::Transport(msg)) => {
                assert!(msg.contains("stalled_unary"), "context missing: {msg}");
                assert!(msg.contains("timed out"), "timeout marker missing: {msg}");
            }
            other => panic!("expected Transport timeout, got {other:?}"),
        }
    }

    /// A stream that stops delivering messages while staying open must surface
    /// as a stream-idle Transport timeout, never hang.
    #[tokio::test(start_paused = true)]
    async fn stream_idle_timeout_fires_on_stalled_stream() {
        let mut stream = futures_util::stream::pending::<Result<u32, tonic::Status>>();
        match next_with_idle_timeout(&mut stream, "stalled_stream").await {
            Err(SlipstreamError::Transport(msg)) => {
                assert!(msg.contains("stalled_stream"), "context missing: {msg}");
                assert!(msg.contains("stream idle timeout"), "idle marker missing: {msg}");
            }
            other => panic!("expected Transport idle timeout, got {other:?}"),
        }
    }

    /// Healthy streams pass through unchanged: messages then a clean end.
    #[tokio::test]
    async fn stream_idle_timeout_passes_messages_and_end() {
        let mut stream =
            futures_util::stream::iter(vec![Ok::<u32, tonic::Status>(7), Ok(8)]);
        let first = next_with_idle_timeout(&mut stream, "healthy").await.expect("no timeout");
        assert_eq!(first.expect("a message").expect("ok item"), 7);
        let second = next_with_idle_timeout(&mut stream, "healthy").await.expect("no timeout");
        assert_eq!(second.expect("a message").expect("ok item"), 8);
        let end = next_with_idle_timeout(&mut stream, "healthy").await.expect("no timeout");
        assert!(end.is_none(), "clean end of stream must be Ok(None)");
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
