//! Prove-at-broadcast-time support for the migration engine (ZIP 374 deferred anchor/witness).
//!
//! The engine (`zcash_pool_migration`) commits every migration transaction fully built and
//! signed, with its Orchard spend witnesses and anchors left unset — the durable artifact in
//! `MigrationTransaction::pczt()` never changes after commit. At proving time this module routes
//! each due transaction through the UPSTREAM prover: [`prove_due_transaction`] dispatches on the
//! transaction's kind into `engine::prove_transfer` / `engine::prove_preparation`, which drive a
//! [`MigrationProver`] (in production the crate's own `wallet::WalletMigrationProver`, borrowing
//! this SDK's wallet mutably for commitment-tree access) to install the real anchors and
//! witnesses through the PCZT `Updater` role and prove both bundles. The proven bytes persist
//! through the engine's own `MigrationState::set_transaction_proved` (state `Signed -> Proved`),
//! so a retry re-serves the stored proven PCZT without re-proving.
//!
//! # Anchor policy (ZIP 318 conformant)
//!
//! - TRANSFERS prove against the boundary anchor their schedule DREW and persisted on the row
//!   (`MigrationTransaction::anchor_boundary()`): `engine::prove_transfer` reads the persisted
//!   boundary and hands it to the prover, so transfers cluster into ZIP 318 anchor cohorts
//!   instead of timestamping the wallet's recent activity with a fresh anchor. A transfer with no
//!   stored boundary is a corrupt store and a HARD error — never a fallback to the natural
//!   anchor. Boundary checkpoints stay durably witnessable because upstream anchor-checkpoint
//!   retention (active from NU6.3 activation) keeps every boundary of the wallet's anchor
//!   retention interval — necessarily the same grid the engine draws boundaries on, since the
//!   engine reads that interval back off the wallet. [`crate::anchor_retention_interval`] is where
//!   the SDK selects it per network.
//! - PREPARATIONS carry no drawn boundary (they anchor to their already-mined dependencies, not
//!   to a bucketed boundary) and prove against the wallet's current natural anchor
//!   ([`natural_anchor_height`]) via `engine::prove_preparation`.
//!
//! # Transient vs hard failures
//!
//! Prover failures that mean "the wallet has not scanned or retained that anchor yet" — a
//! restored wallet mid-sync, or a transfer due before the wallet scanned past its boundary —
//! surface as the transient nothing-due `Ok(None)`, leaving the transaction `Signed` for a later
//! retry (see [`ProveErrorClass`]). Every other failure is hard and carries the stable
//! `MIGRATION_PROVING_UNAVAILABLE:` prefix the Swift layer maps to `migrationProvingUnavailable`.

use anyhow::anyhow;
use zcash_client_backend::data_api::WalletRead;
use zcash_pool_migration::engine::{
    self, MigrationProver, MigrationState, MigrationTransferId, MigrationTxKind,
};
use zcash_pool_migration::wallet::WalletProveError;
use zcash_protocol::consensus::BlockHeight;

use crate::migration::proving_unavailable;
use crate::migration_engine::MigrationWallet;

/// The wallet's real, currently-witnessable anchor height (the same one ordinary, non-migration
/// sends use, via `get_target_and_anchor_heights`) — NOT "chain tip minus one", which is not
/// necessarily checkpointed. Preparation transactions prove against this height; transfers never
/// use it (they prove against their persisted boundary).
pub(crate) fn natural_anchor_height(wallet: &MigrationWallet) -> anyhow::Result<BlockHeight> {
    wallet
        .get_target_and_anchor_heights(std::num::NonZeroU32::MIN)
        .map_err(|e| anyhow!("anchor height lookup failed: {e}"))?
        .map(|(_, anchor)| anchor)
        .ok_or_else(|| anyhow!("the wallet has no anchor height yet; sync first"))
}

/// How a prover failure maps onto the FFI's two lanes: transient (the wallet has not scanned or
/// retained the needed anchor yet — surfaces as the nothing-due `Ok(None)`, retried on a later
/// call) or hard (flows into the `MIGRATION_PROVING_UNAVAILABLE:` error channel).
///
/// This is [`prove_due_transaction`]'s only requirement on a prover's error type, so a test
/// prover plugs in with the same classification the production `WalletMigrationProver` gets from
/// the blanket [`WalletProveError`] impl below.
pub(crate) trait ProveErrorClass {
    /// Whether this failure means "not scanned/retained yet — retry later" rather than a real
    /// error.
    fn is_transient(&self) -> bool;
}

impl<TE, NE, RE> ProveErrorClass for WalletProveError<TE, NE, RE> {
    /// The transient set, exactly: no root at the anchor checkpoint yet (`AnchorNotFound`), the
    /// spent note not witnessable there yet (`WitnessNotFound`), no chain data at all
    /// (`ChainTipUnknown`), or no Ironwood destination tree yet (`IronwoodTreeUnavailable`) — all
    /// resolve themselves as the wallet syncs past the boundary. Everything else (an unknown
    /// spent note, note-enumeration or tree-query failures, proof-creation failures, malformed
    /// PCZT data) is a hard error.
    fn is_transient(&self) -> bool {
        matches!(
            self,
            WalletProveError::AnchorNotFound(_)
                | WalletProveError::WitnessNotFound(_)
                | WalletProveError::ChainTipUnknown
                | WalletProveError::IronwoodTreeUnavailable
        )
    }
}

/// Proves ONE due, `Signed` migration transaction through the upstream engine, dispatching on its
/// kind: a TRANSFER via [`engine::prove_transfer`] (the anchor comes from the transfer's
/// persisted `anchor_boundary()`; a missing boundary is a corrupt store and a hard error), a
/// PREPARATION via [`engine::prove_preparation`] with the caller-resolved `natural_anchor`. On
/// success the engine has stored the proven bytes into `state` (`Signed -> Proved` via
/// `set_transaction_proved`); the caller persists `state` and re-reads the proven PCZT from it.
///
/// `natural_anchor` is `Option`al because only a PREPARATION uses it — the caller resolves it
/// lazily, per kind, so proving a transfer never depends on the natural anchor being resolvable
/// (a wallet with a chain tip but no scanned blocks yet has none, and must still prove transfers
/// against their persisted boundaries). A preparation reaching this function without one is a
/// caller bug, surfaced as a hard error rather than a silent wrong anchor.
///
/// Returns `Ok(None)` — not an error — when the prover reports a transient "the wallet has not
/// scanned/retained that anchor yet" condition (see [`ProveErrorClass`]): the ordinary
/// nothing-due state the caller maps to "retry on a later call", exactly like a transaction whose
/// schedule is not due. Every hard failure carries the stable `MIGRATION_PROVING_UNAVAILABLE:`
/// prefix.
///
/// Generic over the prover so tests substitute a recording/failing `impl MigrationProver` for the
/// production `wallet::WalletMigrationProver`.
pub(crate) fn prove_due_transaction<P>(
    prover: &mut P,
    state: &mut MigrationState,
    id: MigrationTransferId,
    natural_anchor: Option<BlockHeight>,
) -> anyhow::Result<Option<()>>
where
    P: MigrationProver,
    P::Error: ProveErrorClass + std::fmt::Display,
{
    let kind = state
        .transactions()
        .iter()
        .find(|t| t.id() == id)
        .map(|t| t.kind())
        .ok_or_else(|| {
            proving_unavailable(format!(
                "no migration transaction with id {}",
                u32::from(id)
            ))
        })?;
    let result = match kind {
        MigrationTxKind::Transfer { .. } => engine::prove_transfer(prover, state, id),
        MigrationTxKind::Preparation { .. } => {
            let anchor = natural_anchor.ok_or_else(|| {
                proving_unavailable(format!(
                    "internal error: no natural anchor was resolved for preparation transaction {}",
                    u32::from(id)
                ))
            })?;
            engine::prove_preparation(prover, state, id, anchor)
        }
    };
    match result {
        Ok(()) => Ok(Some(())),
        Err(engine::ProveError::Prover(e)) if e.is_transient() => Ok(None),
        Err(e) => Err(proving_unavailable(e)),
    }
}

/// Extracts the consensus transaction bytes and txid (raw internal order) from a fully proven and
/// finalized PCZT.
pub(crate) fn extract_tx(pczt: pczt::Pczt) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
    let tx = pczt::roles::tx_extractor::TransactionExtractor::new(pczt)
        .extract()
        .map_err(|e| anyhow!("finalize: extract tx: {e:?}"))?;
    let txid: [u8; 32] = *tx.txid().as_ref();
    let mut raw = Vec::new();
    tx.write(&mut raw)
        .map_err(|e| anyhow!("finalize: encode tx: {e}"))?;
    Ok((raw, txid))
}
