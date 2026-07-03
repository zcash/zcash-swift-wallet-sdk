//! At-tip mempool monitoring (T8.2). One session = one `GetMempoolStream` from
//! connect to server-close; the engine's follow loop runs sessions strictly
//! BETWEEN sync passes (never concurrent with a scan — single-writer by
//! construction, Deviation D2). Decryption + storage go through upstream's own
//! `decrypt_and_store_transaction` (the old SDK's exact write path,
//! `rust/src/lib.rs:2070`).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use tracing::{debug, info, warn};
use zcash_client_backend::data_api::{WalletRead, wallet::decrypt_and_store_transaction};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

use crate::{
    config::EngineConfig, error::SlipstreamError, events::Progress, grpc,
    wallet_session::WalletSession,
};

/// A mempool session ends for one of these benign reasons (errors are `Err`).
#[derive(Debug, PartialEq, Eq)]
pub enum SessionEnd {
    /// Server closed the stream — a new block was mined (probe + pass NOW).
    BlockBoundary,
    /// No message for [`MEMPOOL_SESSION_IDLE`] — reconnect after a tip probe
    /// (dead-connection vs quiet-mempool are indistinguishable; Deviation D6).
    IdleReconnect,
}

/// Idle bound per session. 60 s ≈ block cadence; deliberately NOT the
/// hardening1 [`grpc::STREAM_IDLE_TIMEOUT`] (30 s) — an empty mempool is
/// legitimate silence, not a stalled connection (Deviation D6).
pub const MEMPOOL_SESSION_IDLE: Duration = Duration::from_secs(60);

/// Dedupe-set cap: lightwalletd replays the whole mempool on reconnect
/// (`mempool.go` `g_txList`), so `seen` persists across sessions; clear it when
/// it exceeds this bound (mempool churn makes unbounded growth possible).
pub const SEEN_TXIDS_CAP: usize = 4096;

// Compile-time invariant: the dedupe set must comfortably exceed a realistic
// live mempool so reconnect-replays don't churn it (a runtime `assert!` on a
// constant folds to `assert!(true)` and is optimized out — clippy flags it).
const _: () = assert!(
    SEEN_TXIDS_CAP >= 1024,
    "SEEN_TXIDS_CAP must comfortably exceed a live mempool to avoid churn"
);

/// Outcome counters for one session (logged; the enhanced bump goes to
/// [`Progress`], not here).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SessionStats {
    pub received: u64,
    pub stored_hits: u64,
}

/// Runs one mempool session against `config.endpoint`.
///
/// For each streamed tx: dedupe by txid → parse (`Transaction::read`, branch id
/// irrelevant pre-consensus: `rust/src/lib.rs:2045-2050` rationale) →
/// `decrypt_and_store_transaction(…, mined_height=None)` (upstream's relevance
/// gate stores ONLY wallet-involving txs — `ll/wallet.rs:655-662`) → hit check
/// via `WalletRead::get_transaction(txid)` → `progress.add_enhanced(1)` per NEW
/// stored hit (Swift's `foundTransactions` path fires off this counter, fact C).
///
/// We pass `mined_height = None` even though `raw.height` carries the server tip
/// (Deviation D1): the row converges to its true mined height when the block is
/// scanned by the next follow pass.
///
/// Parse failures on a single tx are logged and SKIPPED (a malformed mempool
/// entry must not kill monitoring); transport errors return `Err` (the caller
/// applies the non-fatal policy).
///
/// `idle` bounds BOTH the stream open and each `next()`; production passes
/// [`MEMPOOL_SESSION_IDLE`] (tests use a short value). A timeout yields a benign
/// [`SessionEnd::IdleReconnect`], never an error.
pub async fn run_session(
    config: &EngineConfig,
    progress: Option<Arc<Progress>>,
    seen: &mut HashSet<[u8; 32]>,
    idle: Duration,
    tor: Option<&crate::connector::TorConn>,
) -> Result<(SessionEnd, SessionStats), SlipstreamError> {
    let mut stats = SessionStats::default();
    if seen.len() > SEEN_TXIDS_CAP {
        seen.clear(); // bounded memory; worst case = one re-emit per live tx
    }
    let mut session = WalletSession::open(config.network, &config.wallet_db_path)?;
    let mut client = crate::connector::connect_via(
        &config.endpoint,
        tor,
        crate::connector::ConnPurpose::MetadataUnique,
    )
    .await?;
    // Bound the OPEN by `idle`, NOT the gRPC unary timeout: lightwalletd sends
    // GetMempoolStream response headers lazily (see grpc::open_mempool_stream),
    // so a quiet mempool legitimately blocks the open past 30 s. An over-idle
    // open is a benign reconnect (Deviation D6), not a failure.
    let mut stream = match tokio::time::timeout(idle, grpc::open_mempool_stream(&mut client)).await {
        Err(_elapsed) => return Ok((SessionEnd::IdleReconnect, stats)),
        Ok(res) => res?,
    };
    loop {
        let next = tokio::time::timeout(idle, stream.next()).await;
        let raw = match next {
            Err(_elapsed) => return Ok((SessionEnd::IdleReconnect, stats)),
            Ok(None) => return Ok((SessionEnd::BlockBoundary, stats)),
            Ok(Some(Err(status))) => {
                return Err(SlipstreamError::Transport(format!("mempool stream: {status}")));
            }
            Ok(Some(Ok(raw))) => raw,
        };
        stats.received += 1;
        // NOTE: raw.height is the SERVER TIP, not 0 (lightwalletd mempool.go;
        // fact E). We deliberately pass mined_height=None — Deviation D1.
        let tx = match Transaction::read(&raw.data[..], BranchId::Sapling) {
            Ok(tx) => tx,
            Err(e) => {
                warn!(%e, "mempool tx parse failed — skipping entry");
                continue;
            }
        };
        // TxId: AsRef<[u8; 32]> (zcash_protocol txid.rs) — annotate so the deref
        // picks the array impl.
        let txid: [u8; 32] = *tx.txid().as_ref();
        if !seen.insert(txid) {
            continue; // replayed on reconnect — already processed
        }
        decrypt_and_store_transaction(&config.network, session.db_mut(), &tx, None)
            .map_err(|e| SlipstreamError::Wallet(format!("mempool decrypt_and_store: {e}")))?;
        let stored = session
            .db_mut()
            .get_transaction(tx.txid())
            .map_err(|e| SlipstreamError::Wallet(format!("mempool hit check: {e}")))?
            .is_some();
        if stored {
            stats.stored_hits += 1;
            info!(txid = %tx.txid(), "mempool transaction stored (0-conf wallet hit)");
            if let Some(ref p) = progress {
                p.add_enhanced(1);
                p.bump_tx_set_version(); // [E-4] a 0-conf wallet tx was stored
            }
        } else {
            debug!(txid = %tx.txid(), "mempool transaction not wallet-relevant");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Documents Deviation D6: an empty mempool is legitimate silence, so the
    /// session idle bound is INTENTIONALLY looser than the hardening1 stream
    /// idle timeout (which treats silence as a stall).
    #[test]
    fn session_idle_is_longer_than_hardening() {
        assert!(
            MEMPOOL_SESSION_IDLE > grpc::STREAM_IDLE_TIMEOUT,
            "an empty mempool is legitimately silent — must not reuse the 30 s stall timeout (D6)"
        );
    }

    /// The dedupe contract `run_session` relies on: `HashSet::insert` returns
    /// `true` only the first time a txid is seen, so a reconnect replay (same
    /// txid) is skipped via `if !seen.insert(txid) { continue; }`.
    #[test]
    fn dedupe_set_admits_each_txid_once() {
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert!(seen.insert(a), "first sighting of a is new");
        assert!(!seen.insert(a), "replayed a is a duplicate — skipped");
        assert!(seen.insert(b), "first sighting of b is new");
        assert_eq!(seen.len(), 2, "only distinct txids are retained");
    }
}
