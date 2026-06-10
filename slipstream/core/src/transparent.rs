//! Transparent UTXO refresh: port of `zcash_client_backend::sync::refresh_utxos`
//! (registry `zcash_client_backend-0.22.0/src/sync.rs` lines 475-534 for the
//! per-account function, lines 108-121 for the per-account driver loop).
//!
//! Adaptations vs upstream:
//! - Error type: upstream `Error::MisbehavingServer` → `SlipstreamError::MisbehavingServer`;
//!   upstream `Error::Wallet(...)` → `SlipstreamError::Wallet(format!(...))`.
//! - gRPC: upstream calls `client.get_address_utxos_stream(request)` directly; we call
//!   `grpc::get_address_utxos(client, addresses, start_height)` which wraps the same
//!   streaming call (T3.1 wrapper from grpc.rs).
//! - Network/params: upstream takes a generic `params: &P`; we use `session.network`
//!   (the same `Network` type from `zcash_protocol::consensus`).
//! - The driver loop (sync.rs:108-121) is inlined into `refresh_utxos` here because
//!   our function owns the entire per-account pass including get_account_ids.
//! - `put_received_transparent_utxo` returns a `UtxoRef` on success (not `()`); we
//!   map it to `()` via `.map(|_| ())` exactly as upstream sync.rs:534.

use tracing::info;
use zcash_client_backend::{
    data_api::{WalletRead, WalletWrite},
    wallet::WalletTransparentOutput,
};
use zcash_keys::encoding::AddressCodec as _;
use zcash_protocol::{
    consensus::BlockHeight,
    value::Zatoshis,
};
use transparent::{
    address::Script,
    bundle::{OutPoint, TxOut},
};
use zcash_script::script;

use crate::{
    error::SlipstreamError,
    grpc::{self, LwdClient},
    wallet_session::WalletSession,
};

/// Counters from one `refresh_utxos` call.
#[derive(Debug, Default, Clone)]
pub struct TransparentStats {
    /// Number of accounts queried for transparent UTXOs.
    pub accounts: u64,
    /// Number of UTXO records stored via `put_received_transparent_utxo`.
    pub utxos: u64,
}

/// Refresh transparent UTXOs for all accounts in the wallet.
///
/// Mirrors `zcash_client_backend::sync::refresh_utxos` (sync.rs:475-534) and the
/// per-account driver loop (sync.rs:108-121). Must run BEFORE the shielded scan loop
/// per upstream ordering (sync.rs comment at line 108-110: "We do this before we
/// perform any shielded scanning, to ensure that we discover any UTXOs between the
/// old fully-scanned height and the current chain tip.").
///
/// Per account:
/// 1. `db.utxo_query_height(account_id)` — start height (sync.rs:113-115).
/// 2. `db.get_transparent_receivers(account_id, true, true)` — address set (sync.rs:493).
/// 3. `grpc::get_address_utxos` — fetch UTXOs from lightwalletd.
/// 4. For each reply: `WalletTransparentOutput::from_parts(OutPoint::new(...), TxOut::new(...), Some(height))`
///    then `db.put_received_transparent_utxo(&output)` (sync.rs:511-535).
pub async fn refresh_utxos(
    session: &mut WalletSession,
    client: &mut LwdClient,
) -> Result<TransparentStats, SlipstreamError> {
    let mut stats = TransparentStats::default();

    // Collect account ids up front to avoid holding a borrow on `session.db_mut()`
    // while driving the async loop below.
    let account_ids = session
        .db_mut()
        .get_account_ids()
        .map_err(|e| SlipstreamError::Wallet(format!("get_account_ids: {e}")))?;

    // Per-account driver loop — mirrors sync.rs:112-121.
    for account_id in account_ids {
        // sync.rs:113-115: start height from utxo_query_height.
        let start_height = session
            .db_mut()
            .utxo_query_height(account_id)
            .map_err(|e| SlipstreamError::Wallet(format!("utxo_query_height: {e}")))?;

        info!(?account_id, %start_height, "refreshing UTXOs");

        // sync.rs:492-497: collect transparent receiver addresses.
        // get_transparent_receivers(account_id, include_change=true, include_standalone=true)
        // exactly as upstream.
        let addresses: Vec<String> = session
            .db_mut()
            .get_transparent_receivers(account_id, true, true)
            .map_err(|e| SlipstreamError::Wallet(format!("get_transparent_receivers: {e}")))?
            .into_keys()
            .map(|addr| addr.encode(&session.network))
            .collect();

        // sync.rs:502: skip if no transparent receivers.
        if addresses.is_empty() {
            info!(?account_id, "no transparent receivers — skipping UTXO refresh");
            stats.accounts += 1;
            continue;
        }

        // Fetch all UTXOs for these addresses from start_height.
        // sync.rs:498: start_height.into() converts BlockHeight → u64.
        let replies =
            grpc::get_address_utxos(client, addresses, start_height.into()).await?;

        // sync.rs:511-537: construct WalletTransparentOutput and store each reply.
        for reply in replies {
            // sync.rs:512-519: OutPoint::new(txid_bytes, index).
            let outpoint = OutPoint::new(
                reply
                    .txid
                    .as_slice()
                    .try_into()
                    .map_err(|_| SlipstreamError::MisbehavingServer)?,
                reply
                    .index
                    .try_into()
                    .map_err(|_| SlipstreamError::MisbehavingServer)?,
            );

            // sync.rs:521-525: TxOut::new(Zatoshis, Script).
            let txout = TxOut::new(
                Zatoshis::from_nonnegative_i64(reply.value_zat)
                    .map_err(|_| SlipstreamError::MisbehavingServer)?,
                Script(script::Code(reply.script)),
            );

            // sync.rs:526-529: mined_height from reply.height.
            let mined_height = Some(
                BlockHeight::try_from(reply.height)
                    .map_err(|_| SlipstreamError::MisbehavingServer)?,
            );

            // sync.rs:511-531: from_parts returns None if recipient address is unknown.
            let output = WalletTransparentOutput::from_parts(outpoint, txout, mined_height)
                .ok_or(SlipstreamError::MisbehavingServer)?;

            // sync.rs:534-535: put and map UtxoRef → ().
            session
                .db_mut()
                .put_received_transparent_utxo(&output)
                .map(|_| ())
                .map_err(|e| SlipstreamError::Wallet(format!("put_received_transparent_utxo: {e}")))?;

            stats.utxos += 1;
        }

        stats.accounts += 1;
    }

    info!(accounts = stats.accounts, utxos = stats.utxos, "transparent UTXO refresh done");
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transparent_stats_default_is_zero() {
        let s = TransparentStats::default();
        assert_eq!(s.accounts, 0);
        assert_eq!(s.utxos, 0);
    }
}
