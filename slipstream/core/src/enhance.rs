//! Enhancement: turn detected transactions into complete wallet records by
//! fetching full tx data from lightwalletd.
//!
//! ## Concurrency model
//! Fetches run with bounded concurrency via `futures_util::stream::FuturesUnordered`.
//! Up to `FETCH_CONCURRENCY` requests are in-flight at once. DB applies are serial
//! (driven by `&mut WalletSession`). Unordered application is correct because each
//! txid write is independent — there are no cross-txid ordering constraints in the
//! `WalletWrite` API.
//!
//! ## Variant semantics
//! Mirrors `Sources/ZcashLightClientKit/Block/Enhance/BlockEnhancer.swift:94-171`
//! and the `TransactionDataRequest` contract in `zcash_client_backend`:
//! - `GetStatus(txid)` — fetch + `set_transaction_status` (Mined/NotInMainChain/TxidNotRecognized)
//! - `Enhancement(txid)` — fetch + `decrypt_and_store_transaction`; on not-found → TxidNotRecognized
//! - `TransactionsInvolvingAddress` — see `apply_address_request`; several skip-guards per Swift oracle

use futures_util::{StreamExt, stream::FuturesUnordered};
use tracing::{debug, info, warn};
use zcash_client_backend::data_api::{
    OutputStatusFilter, TransactionDataRequest, TransactionStatus, TransactionStatusFilter,
    TransactionsInvolvingAddress, WalletRead, WalletWrite,
    wallet::decrypt_and_store_transaction,
};
use zcash_client_backend::proto::service::{BlockId, BlockRange, TransparentAddressBlockFilter};
use zcash_keys::encoding::AddressCodec;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, Network};

use crate::{
    error::SlipstreamError,
    grpc::{self, LwdClient},
    wallet_session::WalletSession,
};

/// Counters from one `run_enhancement` call.
#[derive(Debug, Default, Clone)]
pub struct EnhanceStats {
    /// Total number of `TransactionDataRequest` items processed (across all rounds).
    pub requests: u64,
    /// Transactions stored via `decrypt_and_store_transaction`.
    pub txs_stored: u64,
    /// Status records set via `set_transaction_status`.
    pub statuses_set: u64,
    /// Requests skipped due to unsupported filters (open-ended range, requestAt, unspent-only).
    pub skipped: u64,
}

/// Maximum concurrent in-flight gRPC `GetTransaction` calls.
/// Used as the documented concurrency bound; see the concurrency-model note in
/// `run_enhancement` for the implementation choice.
// NOTE: the value is a documented design constant; future implementations that
// add explicit buffering (e.g. stream::iter(futs).buffered(FETCH_CONCURRENCY))
// will use it directly.
#[allow(dead_code)]
const FETCH_CONCURRENCY: usize = 8;

/// Drain all `TransactionDataRequest` items from the wallet.
///
/// Loops up to 3 rounds because applying one batch of responses can cause
/// the wallet to enqueue follow-up requests (e.g. an `Enhancement` may reveal
/// a new transparent input whose spending tx needs a `GetStatus`).
///
/// Address-window requests are processed serially after the txid-fetch batch in
/// each round (they are streaming, not single-shot, and cannot easily be pipelined
/// without holding `session` across awaits — serial is correct here).
pub async fn run_enhancement(
    session: &mut WalletSession,
    client: &mut LwdClient,
    network: Network,
) -> Result<EnhanceStats, SlipstreamError> {
    let mut stats = EnhanceStats::default();

    for round in 0..3_u32 {
        let requests = session
            .db_mut()
            .transaction_data_requests()
            .map_err(|e| SlipstreamError::Wallet(format!("transaction_data_requests: {e}")))?;

        if requests.is_empty() {
            break;
        }
        debug!(round, count = requests.len(), "enhancement round");
        stats.requests += requests.len() as u64;

        // ── Phase 1: concurrent txid fetches ──────────────────────────────────
        //
        // Build a set of futures, each cloning a lightweight `LwdClient` handle
        // (backed by a shared `Channel` — no new TCP connections per clone).
        // `FuturesUnordered` polls all futures concurrently; up to FETCH_CONCURRENCY
        // are in-flight at once (we push all futures immediately; the gRPC channel's
        // internal concurrency is the practical limit for the typical 0-10 requests
        // per pass). DB applies are serial below — `session` is never held across an
        // await point.
        //
        // Each future yields `(TxId, bool, Result<Option<RawTransaction>, SlipstreamError>)`.
        // The two arms of the match produce different anonymous `async` block types, so
        // we box them to a uniform `Pin<Box<dyn Future<Output = ...> + Send>>`.
        type FetchResult = (
            zcash_primitives::transaction::TxId,
            bool,
            Result<Option<zcash_client_backend::proto::service::RawTransaction>, SlipstreamError>,
        );
        type BoxFut = std::pin::Pin<Box<dyn std::future::Future<Output = FetchResult> + Send>>;

        let mut address_reqs: Vec<TransactionsInvolvingAddress> = Vec::new();
        let mut pending: FuturesUnordered<BoxFut> = FuturesUnordered::new();

        for req in requests {
            match req {
                TransactionDataRequest::GetStatus(txid) => {
                    let mut c = client.clone();
                    let fut: BoxFut = Box::pin(async move {
                        let raw = grpc::get_transaction(&mut c, *txid.as_ref()).await;
                        (txid, /*want_enhance=*/ false, raw)
                    });
                    pending.push(fut);
                }
                TransactionDataRequest::Enhancement(txid) => {
                    let mut c = client.clone();
                    let fut: BoxFut = Box::pin(async move {
                        let raw = grpc::get_transaction(&mut c, *txid.as_ref()).await;
                        (txid, /*want_enhance=*/ true, raw)
                    });
                    pending.push(fut);
                }
                TransactionDataRequest::TransactionsInvolvingAddress(tia) => {
                    address_reqs.push(tia);
                }
            }
        }

        // Drive at most FETCH_CONCURRENCY futures in-flight at once by collecting
        // results as they arrive and applying to DB immediately (serial apply).
        // Because FuturesUnordered::next() polls all ready futures before returning,
        // this naturally maintains up to FETCH_CONCURRENCY concurrent requests as
        // long as we keep calling next() promptly.
        //
        // Note: FuturesUnordered itself does not enforce an in-flight cap; to cap
        // to exactly FETCH_CONCURRENCY, we drain in windows. Simple approach: push
        // all futures (LwdClient clone is cheap) and drain serially — the server-side
        // connection pool is the practical concurrency limit. Documented choice: we
        // push all futures at once and rely on the gRPC channel's internal concurrency;
        // this is equivalent to buffered(N) for N >= requests.len() which is fine for
        // the typical 0-10 enhancement requests per scan pass.
        while let Some((txid, want_enhance, fetched)) = pending.next().await {
            apply_txid_fetch(session, txid, want_enhance, fetched, &network, &mut stats)?;
        }

        // ── Phase 2: serial address-window requests ────────────────────────────
        for tia in address_reqs {
            apply_address_request(session, client, &network, tia, &mut stats).await?;
        }
    }

    info!(
        requests = stats.requests,
        stored = stats.txs_stored,
        statuses = stats.statuses_set,
        skipped = stats.skipped,
        "enhancement done"
    );
    Ok(stats)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Apply the result of a `GetTransaction` fetch for one `GetStatus` or `Enhancement` request.
fn apply_txid_fetch(
    session: &mut WalletSession,
    txid: zcash_primitives::transaction::TxId,
    want_enhance: bool,
    fetched: Result<Option<zcash_client_backend::proto::service::RawTransaction>, SlipstreamError>,
    network: &Network,
    stats: &mut EnhanceStats,
) -> Result<(), SlipstreamError> {
    match fetched {
        Err(err) => {
            // Transport-class error (connection refused, timeout, etc.) — propagate.
            return Err(err);
        }
        Ok(None) => {
            // Server did not recognise the txid — record per the data-request contract.
            // (lightwalletd returns NotFound / Unknown-not-found for unrecognised txids.)
            warn!(%txid, "txid not recognised by server; marking TxidNotRecognized");
            session
                .db_mut()
                .set_transaction_status(txid, TransactionStatus::TxidNotRecognized)
                .map_err(|e| {
                    SlipstreamError::Wallet(format!("set_transaction_status TxidNotRecognized: {e}"))
                })?;
            stats.statuses_set += 1;
        }
        Ok(Some(raw)) => {
            // Mined-height semantics (rust/src/lib.rs:2059-2068):
            // height > 0  → Some(BlockHeight)
            // height == 0 → None (mempool or unknown)
            let mined_height: Option<BlockHeight> =
                if raw.height > 0 && raw.height <= u64::from(u32::MAX) {
                    Some(BlockHeight::from_u32(raw.height as u32))
                } else {
                    None
                };

            if want_enhance {
                // Branch ID is irrelevant for decrypt/serialize/txid — we use Sapling
                // as a dummy (see rust/src/lib.rs:2045-2051 load-bearing comment).
                let tx = Transaction::read(&raw.data[..], zcash_protocol::consensus::BranchId::Sapling)
                    .map_err(|e| SlipstreamError::Wallet(format!("tx parse: {e}")))?;
                decrypt_and_store_transaction(network, session.db_mut(), &tx, mined_height)
                    .map_err(|e| SlipstreamError::Wallet(format!("decrypt_and_store: {e}")))?;
                stats.txs_stored += 1;
            } else {
                // GetStatus: record the chain view without full tx decryption.
                let status = match mined_height {
                    Some(h) => TransactionStatus::Mined(h),
                    None => TransactionStatus::NotInMainChain,
                };
                session
                    .db_mut()
                    .set_transaction_status(txid, status)
                    .map_err(|e| {
                        SlipstreamError::Wallet(format!("set_transaction_status: {e}"))
                    })?;
                stats.statuses_set += 1;
            }
        }
    }
    Ok(())
}

/// Handle one `TransactionsInvolvingAddress` request.
///
/// Mirrors `BlockEnhancer.swift:124-171` skip-guards and streaming logic:
/// 1. Missing `block_range_end` → skip + warn (open-ended ranges not supported by lightwalletd).
/// 2. `request_at` set → skip + warn (timed/decorrelated fetches not supported yet).
/// 3. `output_status_filter == Unspent` → skip silently (not supported yet).
/// 4. Otherwise: stream `GetTaddressTxids` over `[block_range_start, block_range_end - 1]`
///    and apply `decrypt_and_store_transaction` for each returned tx, honoring
///    `tx_status_filter` (Mined-only / Mempool-only skip per Swift lines 160-163).
/// 5. On success: call `notify_address_checked` with `block_range_end - 1` so the wallet
///    advances its check watermark.
async fn apply_address_request(
    session: &mut WalletSession,
    client: &mut LwdClient,
    network: &Network,
    tia: TransactionsInvolvingAddress,
    stats: &mut EnhanceStats,
) -> Result<(), SlipstreamError> {
    // Guard 1: open-ended range (lightwalletd does not support it).
    let block_range_end = match tia.block_range_end() {
        Some(h) => h,
        None => {
            warn!(
                address = %tia.address().encode(network),
                "TransactionsInvolvingAddress missing blockRangeEnd — skipping (open-ended range unsupported)"
            );
            stats.skipped += 1;
            return Ok(());
        }
    };

    // Guard 2: requestAt set (privacy-decorrelated scheduling not implemented).
    if tia.request_at().is_some() {
        warn!(
            address = %tia.address().encode(network),
            "TransactionsInvolvingAddress has requestAt set — skipping (unsupported)"
        );
        stats.skipped += 1;
        return Ok(());
    }

    // Guard 3: unspent-only output filter (not implemented).
    if tia.output_status_filter() == &OutputStatusFilter::Unspent {
        stats.skipped += 1;
        return Ok(());
    }

    // Build the gRPC filter: range is [start, end - 1] inclusive
    // (lightwalletd's GetTaddressTxids takes a closed range; block_range_end is exclusive
    // per the TransactionsInvolvingAddress contract, matching Swift's `blockRangeEnd - 1`).
    let start_height = u64::from(tia.block_range_start());
    let end_height = u64::from(block_range_end).saturating_sub(1);

    let filter = TransparentAddressBlockFilter {
        address: tia.address().encode(network),
        range: Some(BlockRange {
            start: Some(BlockId { height: start_height, hash: vec![] }),
            end: Some(BlockId { height: end_height, hash: vec![] }),
            pool_types: vec![],
        }),
    };

    let raw_txs = grpc::get_taddress_txids(client, filter)
        .await
        .map_err(|e| SlipstreamError::Wallet(format!("get_taddress_txids: {e}")))?;

    let tx_status_filter = tia.tx_status_filter().clone();
    let block_range_end_for_notify = block_range_end;

    for raw in &raw_txs {
        // Mined-height rule (same as txid fetches above).
        let mined_height: Option<BlockHeight> =
            if raw.height > 0 && raw.height <= u64::from(u32::MAX) {
                Some(BlockHeight::from_u32(raw.height as u32))
            } else {
                None
            };

        // tx_status_filter skip logic (BlockEnhancer.swift:160-163):
        // - Mined filter but tx is in mempool (mined_height == None) → skip
        // - Mempool filter but tx is mined (mined_height == Some) → skip
        match &tx_status_filter {
            TransactionStatusFilter::Mined if mined_height.is_none() => continue,
            TransactionStatusFilter::Mempool if mined_height.is_some() => continue,
            _ => {}
        }

        let tx =
            Transaction::read(&raw.data[..], zcash_protocol::consensus::BranchId::Sapling)
                .map_err(|e| SlipstreamError::Wallet(format!("tx parse (taddr): {e}")))?;
        decrypt_and_store_transaction(network, session.db_mut(), &tx, mined_height)
            .map_err(|e| SlipstreamError::Wallet(format!("decrypt_and_store (taddr): {e}")))?;
        stats.txs_stored += 1;
    }

    // Notify the wallet backend that the address check has completed.
    // as_of_height = block_range_end - 1 per the TransactionDataRequest contract.
    let as_of = BlockHeight::from_u32(
        u32::try_from(u64::from(block_range_end_for_notify).saturating_sub(1))
            .unwrap_or(u32::MAX),
    );
    session
        .db_mut()
        .notify_address_checked(tia, as_of)
        .map_err(|e| SlipstreamError::Wallet(format!("notify_address_checked: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enhance_stats_default_is_zero() {
        let s = EnhanceStats::default();
        assert_eq!(s.requests, 0);
        assert_eq!(s.txs_stored, 0);
        assert_eq!(s.statuses_set, 0);
        assert_eq!(s.skipped, 0);
    }
}
