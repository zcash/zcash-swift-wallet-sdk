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

use std::collections::HashSet;
use std::sync::Arc;

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
    events::Progress,
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
    /// Count of **unique** `TransactionsInvolvingAddress` requests skipped due to unsupported
    /// filters (open-ended range, `requestAt`, unspent-only).  Within a single
    /// `run_enhancement` call, duplicate skip keys (address + range) are counted only once;
    /// subsequent rounds that re-issue the same already-skipped request are silently dropped
    /// and do not increment this counter.
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
///
/// `progress` — if `Some`, bumps `enhanced_txs` each time a transaction is stored
/// via `decrypt_and_store_transaction` (Relaxed; poll-based).
///
/// `skipped_keys` — caller-owned dedupe set for `TransactionsInvolvingAddress` skip
/// keys (T6.1). Dedupe scope is now **one sync pass**: each unique skip is `warn!`-logged
/// once per pass and counted once in `stats.skipped`; duplicates across all
/// interleaved/per-range/final runs are `debug!` only and do not increment the counter.
pub async fn run_enhancement(
    session: &mut WalletSession,
    client: &mut LwdClient,
    network: Network,
    progress: Option<Arc<Progress>>,
    skipped_keys: &mut HashSet<String>,
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
        // All fetch futures are pushed into FuturesUnordered at once; the gRPC
        // channel's HTTP/2 stream multiplexing provides the practical concurrency
        // bound. FETCH_CONCURRENCY = 8 is reserved for a future
        // stream::iter(futs).buffered(N) upgrade. DB applies are serial below —
        // `session` is never held across an await point.
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

        // Collect results as they arrive and apply to DB immediately (serial apply).
        // All futures are already pushed; we drain them in order. The gRPC channel's
        // HTTP/2 multiplexing handles the actual concurrency (not FuturesUnordered).
        // This design is correct for typical 0-10 enhancement requests per scan pass.
        while let Some((txid, want_enhance, fetched)) = pending.next().await {
            apply_txid_fetch(session, txid, want_enhance, fetched, &network, &mut stats, progress.as_deref())?;
        }

        // ── Phase 2: serial address-window requests ────────────────────────────
        for tia in address_reqs {
            apply_address_request(session, client, &network, tia, &mut stats, skipped_keys, progress.as_deref())
                .await?;
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
    progress: Option<&Progress>,
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
                if let Some(p) = progress {
                    p.add_enhanced(1);
                }
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

/// Effective end-EXCLUSIVE bound for a `TransactionsInvolvingAddress` range (T8.5).
/// `None` means "unbounded above" (data_api.rs:1131-1135); the completest answer a
/// lightwalletd can give RIGHT NOW is through the chain tip, so an open range clamps to
/// `chain_height + 1` (end-exclusive ⇒ includes the tip block). The post-success
/// `notify_address_checked(end - 1)` then records exactly the height we checked through,
/// and the wallet re-issues a fresh request covering later heights next pass — no gap.
fn effective_range_end(
    block_range_end: Option<BlockHeight>,
    chain_height: BlockHeight,
) -> BlockHeight {
    block_range_end.unwrap_or(chain_height + 1)
}

/// Handle one `TransactionsInvolvingAddress` request.
///
/// Mirrors `BlockEnhancer.swift:124-171` skip-guards and streaming logic:
/// 1. Open-ended `block_range_end` (None) → clamp to `chain_height + 1` (T8.5); only
///    skipped if there is no scanned chain tip yet (cannot happen after preflight).
/// 2. `request_at` set → skip + warn (timed/decorrelated fetches not supported yet).
/// 3. `output_status_filter == Unspent` → skip silently (not supported yet).
/// 4. Otherwise: stream `GetTaddressTxids` over `[block_range_start, block_range_end - 1]`
///    and apply `decrypt_and_store_transaction` for each returned tx, honoring
///    `tx_status_filter` (Mined-only / Mempool-only skip per Swift lines 160-163).
/// 5. On success: call `notify_address_checked` with `block_range_end - 1` so the wallet
///    advances its check watermark.
///
/// `skipped_keys` — the per-run dedupe set shared across all rounds.  When a skip guard
/// fires, the skip key (`address:range_start-range_end` or `address:open-no-tip`) is inserted.
/// If the key is already present (same request re-issued in a later round), the duplicate
/// is silently counted without re-emitting a `warn!` or incrementing `stats.skipped`.
async fn apply_address_request(
    session: &mut WalletSession,
    client: &mut LwdClient,
    network: &Network,
    tia: TransactionsInvolvingAddress,
    stats: &mut EnhanceStats,
    skipped_keys: &mut HashSet<String>,
    progress: Option<&Progress>,
) -> Result<(), SlipstreamError> {
    // Guard 1 (T8.5): clamp an open-ended range to the wallet's current chain tip instead
    // of skipping it. An open range (None) means "unbounded above" (data_api.rs:1131-1135);
    // the completest answer lightwalletd can give now is through the tip — so we clamp via
    // effective_range_end and service the request as a closed range. Only skip if there is
    // genuinely no scanned tip yet (cannot happen after preflight; handled defensively so
    // an unbounded request never reaches upstream). Privacy: the clamped request sends the
    // SAME address string to GetTaddressTxids as any closed-range request already does — no
    // new transparent-address leakage surface (book ch.15).
    let block_range_end = match tia.block_range_end() {
        Some(h) => h,
        None => match session
            .db_mut()
            .chain_height()
            .map_err(|e| SlipstreamError::Wallet(format!("chain_height for open-range clamp: {e}")))?
        {
            Some(tip) => effective_range_end(None, tip),
            None => {
                let key = format!("{}:open-no-tip", tia.address().encode(network));
                if skipped_keys.insert(key) {
                    warn!(
                        address = %tia.address().encode(network),
                        "TransactionsInvolvingAddress open range with no scanned chain tip — skipping"
                    );
                    stats.skipped += 1;
                } else {
                    debug!(
                        address = %tia.address().encode(network),
                        "TransactionsInvolvingAddress open-no-tip skip (duplicate, already counted)"
                    );
                }
                return Ok(());
            }
        },
    };

    // Guard 2: requestAt set (privacy-decorrelated scheduling not implemented).
    if tia.request_at().is_some() {
        let key = format!(
            "{}:{}-{}:request_at",
            tia.address().encode(network),
            u64::from(tia.block_range_start()),
            u64::from(block_range_end)
        );
        if skipped_keys.insert(key) {
            warn!(
                address = %tia.address().encode(network),
                "TransactionsInvolvingAddress has requestAt set — skipping (unsupported)"
            );
            stats.skipped += 1;
        } else {
            debug!(
                address = %tia.address().encode(network),
                "TransactionsInvolvingAddress requestAt skip (duplicate, already counted)"
            );
        }
        return Ok(());
    }

    // Guard 3: unspent-only output filter (not implemented).
    if tia.output_status_filter() == &OutputStatusFilter::Unspent {
        let key = format!(
            "{}:{}-{}:unspent",
            tia.address().encode(network),
            u64::from(tia.block_range_start()),
            u64::from(block_range_end)
        );
        if skipped_keys.insert(key) {
            stats.skipped += 1;
        } else {
            debug!(
                address = %tia.address().encode(network),
                "TransactionsInvolvingAddress unspent-filter skip (duplicate, already counted)"
            );
        }
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
        if let Some(p) = progress {
            p.add_enhanced(1);
        }
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

    /// The dedupe-key logic used inside `apply_address_request` must count the SAME
    /// (address, range) skip key only once across multiple rounds.  This test validates
    /// the `HashSet::insert` contract: the first insert returns `true` (new key →
    /// increment skipped), subsequent inserts return `false` (duplicate → silent).
    #[test]
    fn skip_dedupe_counts_unique_keys_only() {
        let mut skipped_keys: HashSet<String> = HashSet::new();
        let mut skipped_count: u64 = 0;

        // Simulate the same open-range address being re-skipped across 3 rounds.
        let addr = "t1abc123";
        let key = format!("{addr}:open");

        for _ in 0..3 {
            if skipped_keys.insert(key.clone()) {
                skipped_count += 1;
            }
        }
        // Must be counted exactly once regardless of how many rounds re-emit it.
        assert_eq!(skipped_count, 1, "duplicate open-range skip must count as 1 unique skip");
        assert_eq!(skipped_keys.len(), 1);

        // A different address produces a distinct key → additional unique skip.
        let key2 = "t1xyz456:open".to_string();
        if skipped_keys.insert(key2) {
            skipped_count += 1;
        }
        assert_eq!(skipped_count, 2, "distinct address must count as a separate skip");

        // Range-keyed skip (requestAt guard): same address+range across 2 rounds.
        let key3 = format!("{addr}:663150-663200:request_at");
        for _ in 0..2 {
            if skipped_keys.insert(key3.clone()) {
                skipped_count += 1;
            }
        }
        assert_eq!(skipped_count, 3, "requestAt skip must be counted once per unique address+range");
    }

    /// T8.5 — open-ended TransactionsInvolvingAddress ranges clamp to the wallet's current
    /// chain height (end-EXCLUSIVE per data_api.rs:1131-1135: "mined at heights LESS than
    /// this height"); closed ranges pass through untouched.
    #[test]
    fn effective_range_end_clamps_open_ranges_to_tip() {
        use zcash_protocol::consensus::BlockHeight;
        let tip = BlockHeight::from_u32(3_375_000);
        // Closed range passes through untouched.
        assert_eq!(
            effective_range_end(Some(BlockHeight::from_u32(100)), tip),
            BlockHeight::from_u32(100)
        );
        // Open range → tip + 1 (end-exclusive ⇒ includes the tip block).
        assert_eq!(effective_range_end(None, tip), BlockHeight::from_u32(3_375_001));
    }
}
