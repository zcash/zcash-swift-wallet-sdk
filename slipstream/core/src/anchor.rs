//! [API v2.1 E-6] `restore_anchor` — engine-owned wallet-provisioning anchor.
//!
//! Hosts creating or restoring a wallet need two chain facts before the first sync pass:
//!   - RESTORE: the `recover_until` height (the current tip), so the [birthday..tip]
//!     backfill is tracked as recovery (`is_recovering`) — with the OFFLINE fallback
//!     policy inside: a NULL recover_until would make a restore look like a new wallet
//!     (no "Restoring" UI, no recovery gate — field failure syncLogsMac9), so an
//!     unreachable server falls back to `max(bundled-checkpoint height, birthday + 1)`.
//!   - NEW: a reorg-safe recent tree state (`tip − MAX_REORG` floored at Sapling
//!     activation), so funds sent to the brand-new wallet can't be missed if the tip
//!     reorganizes; offline ⇒ no anchor (the host keeps its bundled checkpoint).
//!
//! This POLICY used to live per host (the Swift SDK's `Initializer.initialize` +
//! `importAccount`); moving it here gives every host the same provisioning semantics
//! through one primitive. Keys never cross this boundary — the host keeps its
//! `createAccount`/`importAccount` calls and passes only heights.
//!
//! Privacy: the tree-state/height fetches are identifying (they reveal wallet-birthday
//! interest), so when the host runs Tor they ride an isolated circuit (`MetadataUnique`)
//! exactly like the sync pass's metadata calls. A requested-but-failed Tor bootstrap is
//! treated as OFFLINE (fallback policy) — never a silent de-anonymising direct retry.

use tracing::{info, warn};
use zcash_client_backend::proto::service::TreeState;
use zcash_protocol::consensus::{Network, NetworkUpgrade, Parameters};

use crate::{
    config::Endpoint,
    connector::{ConnPurpose, TorConn, connect_via},
    grpc,
};

/// Reorg-safety margin for a NEW wallet's anchor: the tree state is fetched this many
/// blocks below the advertised tip. Mirrors the Swift SDK's `ZcashSDK.maxReorgSize`.
pub const ANCHOR_MAX_REORG_BLOCKS: u64 = 100;

/// What the host is provisioning.
#[derive(Debug, Clone, Copy)]
pub enum AnchorIntent {
    /// Restoring from seed (or importing a UFVK) with `birthday`; `fallback_checkpoint`
    /// is the host's latest BUNDLED checkpoint height — the offline recover_until input.
    Restore { birthday: u64, fallback_checkpoint: u64 },
    /// Creating a brand-new wallet (no history).
    New,
}

/// The provisioning anchor. For `Restore`: `height` = recover_until (always present by
/// policy — online tip or the offline fallback), `treestate` = None (the host keeps its
/// birthday checkpoint). For `New`: `height`+`treestate` = the reorg-safe server tree
/// state, or `None`/0 when offline (the host keeps its bundled checkpoint defaults).
#[derive(Debug)]
pub struct Anchor {
    pub height: u64,
    pub treestate: Option<TreeState>,
}

/// Resolve the provisioning anchor for `intent`. NEVER errors — the offline policy is the
/// whole point: a restore always gets a valid recover_until, a new wallet degrades to the
/// host's bundled checkpoint. `tor`: `Some` ⇒ identifying calls ride an isolated circuit.
pub async fn restore_anchor(
    endpoint: &Endpoint,
    network: Network,
    intent: AnchorIntent,
    tor: Option<&TorConn>,
) -> Anchor {
    match intent {
        AnchorIntent::Restore { .. } => match tip_via(endpoint, tor).await {
            Some(tip) => {
                info!(tip, "restore anchor: recover_until = live tip");
                Anchor { height: tip, treestate: None }
            }
            None => offline_anchor(intent),
        },
        AnchorIntent::New => {
            let sapling_activation: u64 = network
                .activation_height(NetworkUpgrade::Sapling)
                .map(|h| u64::from(u32::from(h)))
                .unwrap_or(0);
            let fetched = async {
                let mut client = client_via(endpoint, tor).await?;
                let tip = grpc::get_latest_block_height(&mut client).await.ok()?;
                let anchor_height = tip.saturating_sub(ANCHOR_MAX_REORG_BLOCKS).max(sapling_activation);
                let ts = grpc::get_tree_state(&mut client, anchor_height).await.ok()?;
                // Trust the SERVER's height for consistency (it equals anchor_height in
                // practice; on any discrepancy the treestate's own height wins).
                Some(Anchor { height: ts.height, treestate: Some(ts) })
            }
            .await;
            match fetched {
                Some(anchor) => {
                    info!(height = anchor.height, "new-wallet anchor: reorg-safe server tree state");
                    anchor
                }
                None => offline_anchor(intent),
            }
        }
    }
}

/// The pure OFFLINE resolution — no network attempted. Also used directly when a
/// REQUESTED Tor bootstrap fails: the result must be identical to an unreachable server
/// (never a silent de-anonymising direct retry).
pub fn offline_anchor(intent: AnchorIntent) -> Anchor {
    match intent {
        AnchorIntent::Restore { birthday, fallback_checkpoint } => {
            // The syncLogsMac9 rule, verbatim: the best offline estimate of "now";
            // max(.., birthday+1) guarantees a non-empty recovery segment even when the
            // wallet's birthday is newer than the bundled checkpoints.
            let height = fallback_checkpoint.max(birthday.saturating_add(1));
            warn!(
                height,
                fallback_checkpoint,
                birthday,
                "restore anchor: server unreachable — offline recover_until fallback"
            );
            Anchor { height, treestate: None }
        }
        AnchorIntent::New => {
            warn!("new-wallet anchor: server unreachable — host keeps its bundled checkpoint");
            Anchor { height: 0, treestate: None }
        }
    }
}

/// Fetch the advertised tip over the given transport; `None` on any failure.
async fn tip_via(endpoint: &Endpoint, tor: Option<&TorConn>) -> Option<u64> {
    let mut client = client_via(endpoint, tor).await?;
    grpc::get_latest_block_height(&mut client).await.ok()
}

/// Anchor connect policy: Tor rides the connector's bounded fresh-circuit retries (never
/// falls back to direct); DIRECT is a SINGLE attempt — old-SDK parity (`try?` + offline
/// fallback IS the retry policy here, and a user is waiting on the restore spinner, so
/// the multi-attempt backoff window the sync pass uses would be pure added latency).
async fn client_via(endpoint: &Endpoint, tor: Option<&TorConn>) -> Option<crate::grpc::LwdClient> {
    match tor {
        Some(_) => connect_via(endpoint, tor, ConnPurpose::MetadataUnique).await.ok(),
        None => grpc::connect(endpoint).await.ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Offline restore: the recover_until fallback is max(checkpoint, birthday+1) — a
    /// restore NEVER provisions recover_until = NULL (the syncLogsMac9 class).
    #[tokio::test]
    async fn offline_restore_falls_back_to_checkpoint_floor() {
        // Unroutable endpoint (TEST-NET-1 address, port closed) — connect fails fast enough
        // for the direct retry budget only on refused connections; use an invalid host to
        // fail at URI/DNS level instead.
        let endpoint = Endpoint { host: "invalid.host.invalid".into(), port: 1, tls: false };
        let anchor = restore_anchor(
            &endpoint,
            Network::MainNetwork,
            AnchorIntent::Restore { birthday: 2_000_000, fallback_checkpoint: 1_500_000 },
            None,
        )
        .await;
        assert_eq!(
            anchor.height, 2_000_001,
            "birthday newer than the bundled checkpoints ⇒ birthday+1 floor"
        );
        assert!(anchor.treestate.is_none(), "restore intent never carries a treestate");

        let anchor = restore_anchor(
            &endpoint,
            Network::MainNetwork,
            AnchorIntent::Restore { birthday: 1_000_000, fallback_checkpoint: 1_500_000 },
            None,
        )
        .await;
        assert_eq!(anchor.height, 1_500_000, "old birthday ⇒ the checkpoint estimate of now");
    }

    /// Offline new-wallet: no anchor — the host keeps its bundled checkpoint (height 0
    /// + no treestate is the documented "keep your defaults" signal).
    #[tokio::test]
    async fn offline_new_wallet_yields_no_anchor() {
        let endpoint = Endpoint { host: "invalid.host.invalid".into(), port: 1, tls: false };
        let anchor = restore_anchor(&endpoint, Network::MainNetwork, AnchorIntent::New, None).await;
        assert_eq!(anchor.height, 0);
        assert!(anchor.treestate.is_none());
    }
}
