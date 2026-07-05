//! v0.5 local treestate derivation (plan: 2026-07-06-v05-scan-pacer-plan.md).
//!
//! The P0/P1 pacer split proved the scan wall is dominated by per-chunk
//! `GetTreeState` round-trips (Mac reference: 71 boundaries × ~455 ms = 62 %
//! of the scan). Every boundary treestate is derivable LOCALLY: seed one
//! `ChainState` per range from the server, then absorb each scanned block's
//! note commitments into running sapling + orchard frontiers — the exact
//! hashing the tree build performs anyway (`Node::combine` = Pedersen,
//! `MerkleHashOrchard::combine` = Sinsemilla), ~1 internal hash per leaf.
//!
//! Correctness posture (triple net):
//! 1. upstream `scan_cached_blocks` validates the from_state frontier SIZE
//!    against every block's `ChainMetadata` — any missed/extra commitment
//!    fails the very next scan call;
//! 2. the v0.4 graft audit already cross-checks locally built shard roots
//!    against server subtree roots;
//! 3. this module's own boundary audit: sampled boundaries ALSO fetch the
//!    server treestate (spawned, OFF the critical path) and compare the full
//!    `ChainState` (hash + height + both frontiers, `PartialEq`); a mismatch
//!    hard-aborts the pass and trips a process-global fuse so the revived
//!    pass runs the server path.

use core::sync::atomic::{AtomicBool, Ordering};

use incrementalmerkletree::frontier::Frontier;
use orchard::tree::MerkleHashOrchard;
use zcash_client_backend::{data_api::chain::ChainState, proto::compact_formats::CompactBlock};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;

/// Process-global fuse: once a boundary audit mismatches, every later pass
/// (this process) uses the server path regardless of config. Checked at
/// pass start in engine.rs.
static FUSE: AtomicBool = AtomicBool::new(false);

pub fn trip_fuse() {
    FUSE.store(true, Ordering::Relaxed);
}

pub fn fuse_tripped() -> bool {
    FUSE.load(Ordering::Relaxed)
}

/// Running per-pool note-commitment frontiers for one scan range.
/// Seeded from the range's initial server `ChainState`; absorbs every
/// compact block IN ORDER (block → tx → outputs, then actions — the global
/// tree order); yields the boundary `ChainState` upstream requires, with
/// zero further round-trips.
pub struct LocalTreestate {
    sapling: Frontier<sapling::Node, { sapling::NOTE_COMMITMENT_TREE_DEPTH }>,
    orchard: Frontier<MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>,
}

impl LocalTreestate {
    pub fn seed(state: &ChainState) -> Self {
        Self {
            sapling: state.final_sapling_tree().clone(),
            orchard: state.final_orchard_tree().clone(),
        }
    }

    /// Absorb one compact block's commitments. Errors are FATAL to local
    /// mode (malformed cmu/cmx or a full tree) — the caller falls back to
    /// the server path; the scan itself would reject such a block anyway.
    pub fn absorb_block(&mut self, block: &CompactBlock) -> Result<(), String> {
        for tx in &block.vtx {
            for out in &tx.outputs {
                let cmu = out
                    .cmu()
                    .map_err(|e| format!("cmu parse at height {}: {e:?}", block.height))?;
                if !self.sapling.append(sapling::Node::from_cmu(&cmu)) {
                    return Err("sapling frontier full".into());
                }
            }
            for act in &tx.actions {
                let cmx = act
                    .cmx()
                    .map_err(|e| format!("cmx parse at height {}: {e:?}", block.height))?;
                if !self.orchard.append(MerkleHashOrchard::from_cmx(&cmx)) {
                    return Err("orchard frontier full".into());
                }
            }
        }
        Ok(())
    }

    /// The boundary state after everything absorbed so far. `height`/`hash`
    /// identify the last absorbed block.
    pub fn chain_state(&self, height: BlockHeight, hash: BlockHash) -> ChainState {
        ChainState::new(height, hash, self.sapling.clone(), self.orchard.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_client_backend::proto::compact_formats::{
        CompactBlock, CompactOrchardAction, CompactSaplingOutput, CompactTx,
    };

    /// A valid Pallas/Jubjub base-field element from a small integer (LE) —
    /// same trick as the oracle testkit's fabricated commitments.
    fn le32(v: u64) -> Vec<u8> {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&v.to_le_bytes());
        b.to_vec()
    }

    fn block_with(height: u64, sapling: &[u64], orchard: &[u64]) -> CompactBlock {
        let mut tx = CompactTx::default();
        for &v in sapling {
            tx.outputs.push(CompactSaplingOutput { cmu: le32(v), ..Default::default() });
        }
        for &v in orchard {
            tx.actions.push(CompactOrchardAction { cmx: le32(v), ..Default::default() });
        }
        CompactBlock { height, vtx: vec![tx], ..Default::default() }
    }

    /// The absorbed frontier must equal a frontier built by direct appends
    /// in the same order — pins the block → tx → outputs/actions ordering.
    #[test]
    fn absorb_matches_direct_appends() {
        let seed = ChainState::empty(BlockHeight::from_u32(9), BlockHash([0u8; 32]));
        let mut local = LocalTreestate::seed(&seed);
        local.absorb_block(&block_with(10, &[1, 2], &[3])).expect("b10");
        local.absorb_block(&block_with(11, &[], &[4, 5])).expect("b11");

        let mut sap = Frontier::empty();
        for v in [1u64, 2] {
            let cmu = sapling::note::ExtractedNoteCommitment::from_bytes(
                le32(v).as_slice().try_into().expect("32 bytes"),
            )
            .expect("valid cmu");
            assert!(sap.append(sapling::Node::from_cmu(&cmu)));
        }
        let mut orch = Frontier::empty();
        for v in [3u64, 4, 5] {
            let cmx = orchard::note::ExtractedNoteCommitment::from_bytes(
                le32(v).as_slice().try_into().expect("32 bytes"),
            )
            .expect("valid cmx");
            assert!(orch.append(MerkleHashOrchard::from_cmx(&cmx)));
        }

        let got = local.chain_state(BlockHeight::from_u32(11), BlockHash([7u8; 32]));
        let want = ChainState::new(BlockHeight::from_u32(11), BlockHash([7u8; 32]), sap, orch);
        assert_eq!(got, want, "absorb order must match direct append order");
    }

    /// Seeding from a non-empty state and absorbing nothing reproduces it.
    #[test]
    fn seed_round_trips() {
        let mut sap = Frontier::empty();
        let cmu = sapling::note::ExtractedNoteCommitment::from_bytes(
            le32(42).as_slice().try_into().expect("32 bytes"),
        )
        .expect("valid cmu");
        assert!(sap.append(sapling::Node::from_cmu(&cmu)));
        let seed = ChainState::new(
            BlockHeight::from_u32(100),
            BlockHash([1u8; 32]),
            sap,
            Frontier::empty(),
        );
        let local = LocalTreestate::seed(&seed);
        assert_eq!(local.chain_state(BlockHeight::from_u32(100), BlockHash([1u8; 32])), seed);
    }

    /// A malformed commitment is a hard error, not a skip — local mode must
    /// never silently drift from the true tree.
    #[test]
    fn malformed_cmx_is_fatal() {
        let seed = ChainState::empty(BlockHeight::from_u32(0), BlockHash([0u8; 32]));
        let mut local = LocalTreestate::seed(&seed);
        let mut bad = block_with(1, &[], &[]);
        bad.vtx[0].actions.push(CompactOrchardAction { cmx: vec![0xFF; 32], ..Default::default() });
        assert!(local.absorb_block(&bad).is_err(), "non-canonical cmx must error");
    }
}
