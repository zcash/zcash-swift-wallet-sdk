//! Prove-when-provable support for the migration engine (ZIP 374 deferred anchor/witness).
//!
//! The engine (`zcash_pool_migration`) commits every migration transaction fully built and
//! signed, with its Orchard spend witnesses and anchors left unset — the durable artifact in
//! `MigrationTransaction::pczt()` never changes after commit. A transaction's anchor becomes
//! resolvable long before its broadcast schedule arrives, and upstream separates the two selectors
//! (`next_provable` / `next_broadcastable`) precisely so proving can happen in that window:
//! `crate::migration`'s sweep proves opportunistically as the wallet scans, and the delivery lane
//! only ever broadcasts what is already proved. This module is the proving step itself, routing
//! each transaction through the UPSTREAM prover: [`prove_due_transaction`] dispatches on the
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
//!   instead of timestamping the wallet's recent activity with a fresh anchor. The persisted
//!   boundary is PROVISIONAL, though: it was drawn from an estimate of when the funding
//!   preparations would mine, and `engine::prove_transfer` re-validates it against their REAL
//!   mined heights at proving time, re-drawing (and re-persisting) it when the funding note
//!   postdates it — the note is absent from that tree state and could never be witnessed there.
//!   That re-draw is why this caller supplies the network parameters, the wallet's scanned tip,
//!   and an rng. A transfer with no stored boundary is a corrupt store and a HARD error — never a
//!   fallback to the preparation anchor. Boundary checkpoints stay durably witnessable because upstream anchor-checkpoint
//!   retention (active from NU6.3 activation) keeps every boundary of the wallet's anchor
//!   retention interval — necessarily the same grid the engine draws boundaries on, since the
//!   engine reads that interval back off the wallet. [`crate::anchor_retention_interval`] is where
//!   the SDK selects it per network.
//! - PREPARATIONS carry no drawn boundary and prove against the wallet's scanned tip
//!   ([`preparation_anchor_height`]) via `engine::prove_preparation`, which is why that anchor is
//!   supplied by this caller rather than read off the row. Anchoring at the tip is correct for
//!   them: a preparation is a shielded self-send within the source pool that reveals no balance
//!   and no pool crossing, so its anchor leaks nothing a migration participant needs hidden.
//!   Bucketing is what pool-CROSSING transfers need, and only they carry a drawn boundary;
//!   upstream deliberately keeps preparations off the bucket grid (they need only temporal
//!   serialization behind their mined dependencies) because waiting for a boundary would add a
//!   full bucket to every preparation layer.
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
use zcash_client_backend::data_api::locking::LockError;
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
pub(crate) fn preparation_anchor_height(wallet: &MigrationWallet) -> anyhow::Result<BlockHeight> {
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

impl<TE, NE, RE, LE> ProveErrorClass for WalletProveError<TE, NE, RE, LE> {
    /// Transient = "not scanned/retained yet or transiently unqueryable — resolves as the wallet
    /// syncs": no spendable note yet matches the spend's revealed nullifier (`UnknownSpentNote` —
    /// a late-mining dependency's note the wallet has not seen yet), no root at the anchor
    /// checkpoint yet (`AnchorNotFound`), the spent note not witnessable there yet
    /// (`WitnessNotFound`), a commitment-tree QUERY failure (`Tree(ShardTreeError::Query(_))` —
    /// shard-tree query races during sync; this exact case crash-looped a prove batch on Android
    /// on 2026-07-28), no chain data at all (`ChainTipUnknown`), or a lost race for a spent note's
    /// reservation (`Lock(LockError::LockFailure(_))`).
    ///
    /// The lock case is transient for the same reason upstream declines to call it fatal: another
    /// flow — typically a user payment proposed while this transaction was being proved — holds an
    /// ADVISORY reservation on a note this transaction spends, and that flow may release the lock
    /// or let it expire without ever broadcasting, in which case a later sweep proves the
    /// transaction unchanged. Deferring is also the only response available: the notes were fixed
    /// by the transaction's signature, so nothing here can re-select around the conflict. Once the
    /// rival transaction actually mines, the conflict stops presenting as a lock failure and
    /// arrives as `UnknownSpentNote` instead, which the satisfiability sweep — not this
    /// classification — adjudicates.
    ///
    /// Hard = genuinely unrecoverable, must not be swallowed: everything else, including
    /// `IronwoodTreeUnavailable` explicitly — the backend tracks no Ironwood commitment tree at
    /// all, which no amount of syncing produces — and the NON-query `Tree` variants (A6): a
    /// `Storage(_)` failure is the persistence layer erroring and an `Insert(_)` a corrupt tree
    /// write, neither of which more syncing repairs, so deferring them would stall the sweep
    /// silently forever. `Lock(LockError::Storage(_))` is hard on that same reading — it is the
    /// lock table failing, not a rival owner holding it.
    fn is_transient(&self) -> bool {
        matches!(
            self,
            WalletProveError::UnknownSpentNote(_)
                | WalletProveError::AnchorNotFound(_)
                | WalletProveError::WitnessNotFound(_)
                | WalletProveError::Tree(shardtree::error::ShardTreeError::Query(_))
                | WalletProveError::ChainTipUnknown
                | WalletProveError::Lock(LockError::LockFailure(_))
        )
    }
}

/// Proves ONE due, `Signed` migration transaction through the upstream engine, dispatching on its
/// kind: a TRANSFER via [`engine::prove_transfer`] (the anchor comes from the transfer's
/// persisted `anchor_boundary()`; a missing boundary is a corrupt store and a hard error), a
/// PREPARATION via [`engine::prove_preparation`] with the caller-resolved `preparation_anchor`. On
/// success the engine has stored the proven bytes into `state` (`Signed -> Proved` via
/// `set_transaction_proved`); the caller persists `state` and re-reads the proven PCZT from it.
///
/// `preparation_anchor` is `Option`al because only a PREPARATION uses it — the caller resolves it
/// lazily, per kind, so proving a transfer never depends on the preparation anchor being resolvable
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
pub(crate) fn prove_due_transaction<C, P, R>(
    params: &C,
    prover: &mut P,
    state: &mut MigrationState,
    id: MigrationTransferId,
    preparation_anchor: Option<BlockHeight>,
    scanned_tip: BlockHeight,
    rng: &mut R,
) -> anyhow::Result<Option<engine::ProvedTransaction>>
where
    C: zcash_protocol::consensus::Parameters,
    P: MigrationProver,
    P::Error: ProveErrorClass + std::fmt::Display,
    R: rand::RngCore + rand::CryptoRng,
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
        // `params`, `scanned_tip`, and `rng` feed the engine's proving-time boundary re-draw: a
        // transfer whose funding preparation mined PAST its commit-time boundary gets a fresh
        // boundary drawn from the note's real creation height (ZIP 318 anchor selection is a
        // proving-time rule; the pre-signed PCZT pins nothing — ZIP 374 defers its anchor to
        // proving), instead of deferring forever against a tree state its input is absent from.
        MigrationTxKind::Transfer { .. } => {
            engine::prove_transfer(params, prover, state, id, scanned_tip, rng)
        }
        MigrationTxKind::Preparation { .. } => {
            let anchor = preparation_anchor.ok_or_else(|| {
                proving_unavailable(format!(
                    "internal error: no preparation anchor was resolved for preparation transaction {}",
                    u32::from(id)
                ))
            })?;
            engine::prove_preparation(prover, state, id, anchor)
        }
    };
    match result {
        // The proof comes OUT as a `#[must_use]` value rather than being written into the state:
        // nothing says `Proved` — in memory or on disk — until the caller hands it to
        // `PoolMigrationWrite::store_proved_transaction`, which persists the state atomically
        // with the wallet's own record of the finalized transaction (marking its inputs spent,
        // so the wallet cannot double-spend them during the prove-to-broadcast window).
        Ok(engine::ProveOutcome::Proved(proved)) => Ok(Some(proved)),
        Ok(engine::ProveOutcome::NotYetProvable) => Ok(None),
        Ok(engine::ProveOutcome::MarkedUnsatisfiable { .. }) => Ok(None),
        Err(engine::ProveError::Prover(e)) if e.is_transient() => {
            // The deferral is ordinary (the sweep retries later), but never silent (A6): a row
            // that defers on every sweep would otherwise present as a wallet that simply never
            // proves, with nothing in the logs naming the stall.
            tracing::warn!(
                "proving migration transaction {} deferred (transient): {e}",
                u32::from(id)
            );
            Ok(None)
        }
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
