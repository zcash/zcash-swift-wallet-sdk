//! Prove-at-broadcast-time support for the migration engine (ZIP 374 deferred anchor/witness).
//!
//! The engine (`zcash_pool_migration_backend`) commits every migration transaction fully built and
//! signed, with its Orchard spend witnesses and anchors left unset — the durable artifact in
//! `MigrationTransaction::pczt()` never changes after commit. At broadcast time the consumer
//! installs the real anchor and witnesses through the PCZT `Updater` role, proves both bundles,
//! finalizes the spends, and extracts the consensus transaction. This module does exactly that,
//! persisting the proven bytes back through the engine's own
//! `MigrationState::set_transaction_proved` (state `Signed -> Proved`), so a retry re-serves the
//! stored proven PCZT without re-proving.
//!
//! # Anchor policy — the one seam, and its deliberate ZIP 318 deviation
//!
//! [`resolve_proving_anchor`] is the single place the proving anchor is chosen:
//!
//! - Preparation transactions carry no drawn boundary (`anchor_boundary() == None`) and correctly
//!   prove against the wallet's current natural anchor — permanent behavior.
//! - Transfers DO carry a drawn ZIP 318 boundary anchor (`anchor_boundary()`), and per ZIP 318
//!   MUST prove against that boundary's tree state so transfers cluster into anchor cohorts.
//!   **This module currently ignores the drawn boundary and proves transfers against the natural
//!   anchor too — a deliberate, explicitly approved stopgap**: the wallet's checkpoint retention
//!   (`PRUNING_DEPTH`) is shallower than the drawn boundaries (144–2304 blocks below tip), so a
//!   boundary witness is unobtainable until migration anchor-checkpoint retention lands upstream
//!   (librustzcash issue #2700; the `tree_retained_checkpoints` tables are the groundwork). The
//!   deviation weakens the anchor-cohort privacy property (the anchor timestamps the wallet's
//!   recent activity) and MUST be flipped to the boundary path once upstream retention lands —
//!   see the "Proving flip to boundary anchors" handoff document.
//!
//! Ported from the Android SDK's equivalent bridge (`migration_finalize.rs` @ `9d93b4de`), itself
//! ported from the historical v1 crate's `backend::finalize_self_funding_transfer`/`prove_pczt`;
//! adapted here to the engine-persisted `Proved` state (no side proven-pczt cache) and the
//! account-keyed store.

use anyhow::anyhow;
use orchard::keys::FullViewingKey;
use zcash_client_backend::data_api::{WalletCommitmentTrees, WalletRead};
use zcash_pool_migration_backend::engine::MigrationTransaction;
use zcash_protocol::consensus::BlockHeight;

use crate::migration_engine::{MigrationWallet, SpendableNote};

/// The wallet's real, currently-witnessable anchor height (the same one ordinary, non-migration
/// sends use, via `get_target_and_anchor_heights`) — NOT "chain tip minus one", which is not
/// necessarily checkpointed.
pub(crate) fn natural_anchor_height(wallet: &MigrationWallet) -> anyhow::Result<BlockHeight> {
    wallet
        .get_target_and_anchor_heights(std::num::NonZeroU32::MIN)
        .map_err(|e| anyhow!("anchor height lookup failed: {e}"))?
        .map(|(_, anchor)| anchor)
        .ok_or_else(|| anyhow!("the wallet has no anchor height yet; sync first"))
}

/// The anchor height a migration transaction proves against. THE seam for the migration's anchor
/// policy: preparation transactions correctly use the natural anchor; transfers currently use it
/// too as the approved stopgap (see the module doc — `tx.anchor_boundary()` is deliberately
/// unused pending upstream anchor-checkpoint retention, librustzcash #2700).
pub(crate) fn resolve_proving_anchor(
    wallet: &MigrationWallet,
    _tx: &MigrationTransaction,
) -> anyhow::Result<BlockHeight> {
    natural_anchor_height(wallet)
}

/// Attempts to complete one migration transaction's PCZT: matches every redacted (witness-less)
/// spend to a currently-spendable wallet note by nullifier, fetches each note's Merkle path at
/// `anchor_height`, installs the witnesses and the anchor via the PCZT `Updater` role, proves both
/// bundles, finalizes spends, and extracts the resulting txid.
///
/// Returns `Ok(None)` — not an error — when the transaction is not finalizable YET: a funding note
/// is not a currently-spendable wallet note (its producer has not mined/scanned), or no checkpoint
/// exists at `anchor_height`, or a note is not witnessable there. All are the ordinary transient
/// "not ready yet" state the caller maps to "nothing due".
pub(crate) fn finalize_transaction(
    wallet: &mut MigrationWallet,
    fvk: &FullViewingKey,
    spendable: &[SpendableNote],
    anchor_height: BlockHeight,
    pczt_bytes: &[u8],
) -> anyhow::Result<Option<(Vec<u8>, [u8; 32])>> {
    let pczt =
        pczt::Pczt::parse(pczt_bytes).map_err(|e| anyhow!("finalize: parse pczt: {e:?}"))?;

    // Every action whose spend has no witness yet needs one resolved — a transaction can spend
    // more than one wallet note at once (a preparation transaction gathering several inputs), and
    // resolving only the first leaves the `Prover` failing with `MissingWitness`.
    let actions = pczt.orchard().actions();
    let redacted_indices: Vec<usize> = actions
        .iter()
        .enumerate()
        .filter(|(_, action)| action.spend().witness().is_none())
        .map(|(i, _)| i)
        .collect();

    if redacted_indices.is_empty() {
        // No redacted spend awaiting a witness — already complete; extract as-is.
        let (_, txid) = extract_tx(pczt)?;
        return Ok(Some((pczt_bytes.to_vec(), txid)));
    }

    let anchor = wallet
        .with_orchard_tree_mut::<_, _, anyhow::Error>(|tree| {
            Ok(tree.root_at_checkpoint_id(&anchor_height)?.map(Into::into))
        })
        .map_err(|e| anyhow!("finalize: read anchor: {e}"))?;
    let Some(anchor): Option<orchard::Anchor> = anchor else {
        // No checkpoint at anchor_height (yet, or pruned) — transient, retry later.
        return Ok(None);
    };

    let mut witnesses = Vec::with_capacity(redacted_indices.len());
    for spend_index in redacted_indices {
        let nullifier_bytes = *actions[spend_index].spend().nullifier();
        let Some(&(_, position, _)) = spendable
            .iter()
            .find(|(note, _, _)| note.nullifier(fvk).to_bytes() == nullifier_bytes)
        else {
            // The funding note is not a currently-spendable wallet note yet — transient, retry.
            return Ok(None);
        };

        let witness = wallet
            .with_orchard_tree_mut::<_, _, anyhow::Error>(|tree| {
                match tree.witness_at_checkpoint_id_caching(position, &anchor_height) {
                    Ok(path) => Ok(path),
                    Err(shardtree::error::ShardTreeError::Query(
                        shardtree::error::QueryError::NotContained(_)
                        | shardtree::error::QueryError::CheckpointPruned,
                    )) => Ok(None),
                    Err(e) => Err(anyhow!("finalize: read witness: {e}")),
                }
            })
            .map_err(|e| anyhow!("finalize: {e}"))?;
        let Some(merkle_path) = witness else {
            // Not witnessable at anchor_height yet — transient, retry later.
            return Ok(None);
        };
        witnesses.push((spend_index, orchard::tree::MerklePath::from(merkle_path)));
    }

    let updated = pczt::roles::updater::Updater::new(pczt)
        .set_orchard_spend_witnesses(witnesses)
        .map_err(|e| anyhow!("finalize: set spend witnesses: {e:?}"))?
        .set_orchard_anchor(anchor)
        .map_err(|e| anyhow!("finalize: set anchor: {e:?}"))?
        .finish();

    let proven = prove_pczt(updated)?;
    let finalized = pczt::roles::spend_finalizer::SpendFinalizer::new(proven)
        .finalize_spends()
        .map_err(|e| anyhow!("finalize: finalize spends: {e:?}"))?;
    let proven_bytes = finalized
        .clone()
        .serialize()
        .map_err(|e| anyhow!("finalize: serialize pczt: {e:?}"))?;

    let (_, txid) = extract_tx(finalized)?;
    Ok(Some((proven_bytes, txid)))
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

/// The PostNu6_3 proving key both migration bundle proofs use (the migration exists only after
/// NU6.3 activation), built once per process.
fn shielded_proving_key() -> &'static orchard::circuit::ProvingKey {
    static PK: std::sync::OnceLock<orchard::circuit::ProvingKey> = std::sync::OnceLock::new();
    PK.get_or_init(|| {
        orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3)
    })
}

/// Proves whichever bundles the PCZT requires (Orchard source, Ironwood destination).
fn prove_pczt(pczt: pczt::Pczt) -> anyhow::Result<pczt::Pczt> {
    let mut prover = pczt::roles::prover::Prover::new(pczt);
    if prover.requires_orchard_proof() {
        prover = prover
            .create_orchard_proof(shielded_proving_key())
            .map_err(|e| anyhow!("finalize: orchard proof: {e:?}"))?;
    }
    if prover.requires_ironwood_proof() {
        prover = prover
            .create_ironwood_proof(shielded_proving_key())
            .map_err(|e| anyhow!("finalize: ironwood proof: {e:?}"))?;
    }
    Ok(prover.finish())
}
