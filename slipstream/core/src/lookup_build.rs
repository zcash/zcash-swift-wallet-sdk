//! Lookup-map subtree build (v0.4 Plan B / Phase B0 shared machinery): batch-compute
//! every combine a fragment needs, then run shardtree's `LocatedTree::from_iter`
//! VERBATIM through a `Hashable` wrapper whose `combine` consults the precomputed
//! map — retention/pruning/checkpoint semantics untouched, byte-identical output.
//! Correct-by-construction: any combine the precompute misses (true Nil-padding
//! boundaries, odd tails) falls back to the scalar `MerkleHashOrchard::combine`,
//! so the map is an OPTIMIZATION SET, never a correctness surface.
//!
//! Consumers: the v0.4 `batch_combine` path (CPU batch-affine kernel,
//! batch_sinsemilla.rs — always compiled) and the banked B0 GPU offload
//! (gpu_subtree.rs, feature `gpu`). Extracted from gpu_subtree.rs in Task 13.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use incrementalmerkletree::{Hashable, Level, Position, Retention};
use orchard::tree::MerkleHashOrchard;
use rayon::iter::{IndexedParallelIterator as _, ParallelIterator as _};
use rayon::slice::ParallelSliceMut as _;
use shardtree::{LocatedPrunableTree, LocatedTree, Node, PrunableTree, Tree};
use zcash_protocol::consensus::BlockHeight;

use crate::persist::BUILD_CHUNK_SIZE;

/// The batched-combine contract shared by the CPU batch-affine kernel and the
/// GPU offload: `output[i]` byte-identical to
/// `MerkleHashOrchard::combine(Level::from(layers[i]), &lefts[i], &rights[i])`.
pub(crate) type BatchCombineFn = fn(&[u8], &[[u8; 32]], &[[u8; 32]]) -> Vec<[u8; 32]>;

thread_local! {
    /// Precomputed combines for the fragment `from_iter` is currently building on THIS thread.
    static PRECOMP: RefCell<Option<HashMap<[u8; 65], [u8; 32]>>> = const { RefCell::new(None) };
}

/// Map key: level byte ‖ left (32 LE) ‖ right (32 LE). Keying on the level too avoids any
/// (astronomically unlikely) cross-level hash-pair aliasing.
fn combine_key(level: Level, a: &MerkleHashOrchard, b: &MerkleHashOrchard) -> [u8; 65] {
    let mut k = [0u8; 65];
    k[0] = u8::from(level);
    k[1..33].copy_from_slice(&a.to_bytes());
    k[33..65].copy_from_slice(&b.to_bytes());
    k
}

/// `MerkleHashOrchard` whose `combine` consults the thread-local precomputed map.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct LookupHashOrchard(pub MerkleHashOrchard);

impl Hashable for LookupHashOrchard {
    fn empty_leaf() -> Self {
        Self(MerkleHashOrchard::empty_leaf())
    }
    fn empty_root(level: Level) -> Self {
        Self(MerkleHashOrchard::empty_root(level))
    }
    fn combine(level: Level, a: &Self, b: &Self) -> Self {
        let hit = PRECOMP.with(|p| {
            p.borrow()
                .as_ref()
                .and_then(|m| m.get(&combine_key(level, &a.0, &b.0)).copied())
        });
        match hit.and_then(|bytes| Option::from(MerkleHashOrchard::from_bytes(&bytes))) {
            Some(node) => Self(node),
            None => Self(MerkleHashOrchard::combine(level, &a.0, &b.0)), // scalar fallback
        }
    }
}

/// Build the complete binary tree over `leaves` bottom-up (each level one call to
/// `batch`), recording every `(level, left, right) → parent`. Odd levels pad with
/// `empty_root(level)`; combines the map does not cover fall back to the scalar path.
fn precompute_shard_map(
    batch: BatchCombineFn,
    leaves: &[MerkleHashOrchard],
) -> HashMap<[u8; 65], [u8; 32]> {
    let mut map = HashMap::new();
    if leaves.len() <= 1 {
        return map;
    }
    let mut level: Vec<MerkleHashOrchard> = leaves.to_vec();
    let mut lvl: u8 = 0;
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(MerkleHashOrchard::empty_root(Level::from(lvl)));
        }
        let pairs = level.len() / 2;
        let layers = vec![lvl; pairs];
        let lefts: Vec<[u8; 32]> = (0..pairs).map(|i| level[2 * i].to_bytes()).collect();
        let rights: Vec<[u8; 32]> = (0..pairs).map(|i| level[2 * i + 1].to_bytes()).collect();
        let parents = batch(&layers, &lefts, &rights);
        let mut next = Vec::with_capacity(pairs);
        for i in 0..pairs {
            map.insert(combine_key(Level::from(lvl), &level[2 * i], &level[2 * i + 1]), parents[i]);
            let p = Option::from(MerkleHashOrchard::from_bytes(&parents[i])).unwrap_or_else(|| {
                MerkleHashOrchard::combine(Level::from(lvl), &level[2 * i], &level[2 * i + 1])
            });
            next.push(p);
        }
        level = next;
        lvl += 1;
    }
    map
}

/// Recursively rebuild a `PrunableTree<LookupHashOrchard>` as `PrunableTree<MerkleHashOrchard>`
/// (converts both the annotation `A` and the leaf value `V`).
fn convert_tree(t: &PrunableTree<LookupHashOrchard>) -> PrunableTree<MerkleHashOrchard> {
    match &**t {
        Node::Parent { ann, left, right } => Tree::parent(
            ann.as_ref().map(|h| Arc::new(h.0)),
            convert_tree(left),
            convert_tree(right),
        ),
        Node::Leaf { value } => Tree::leaf((value.0.0, value.1)),
        Node::Nil => Tree::empty(),
    }
}

/// Batched equivalent of `persist::build_subtrees` for Orchard. Same chunking and
/// structure; the only difference is batch-computed combines + the H-type convert.
/// Output is identical to the scalar path (gated by `lookup_build_matches_scalar`).
pub(crate) fn build_subtrees_lookup<const SHARD_HEIGHT: u8>(
    batch: BatchCombineFn,
    start_position: Position,
    commitments: &mut [Option<(MerkleHashOrchard, Retention<BlockHeight>)>],
) -> Vec<(LocatedPrunableTree<MerkleHashOrchard>, BTreeMap<BlockHeight, Position>)> {
    commitments
        .par_chunks_mut(BUILD_CHUNK_SIZE)
        .enumerate()
        .filter_map(|(i, chunk)| {
            let start = start_position + (i * BUILD_CHUNK_SIZE) as u64;
            let end = start + chunk.len() as u64;
            let leaves: Vec<MerkleHashOrchard> =
                chunk.iter().map(|n| n.as_ref().expect("always Some").0).collect();
            let map = precompute_shard_map(batch, &leaves);

            PRECOMP.with(|p| *p.borrow_mut() = Some(map));
            let res = LocatedTree::from_iter(
                start..end,
                Level::from(SHARD_HEIGHT),
                chunk.iter_mut().map(|n| {
                    let (h, r) = n.take().expect("always Some");
                    (LookupHashOrchard(h), r)
                }),
            );
            PRECOMP.with(|p| *p.borrow_mut() = None);

            res.map(|res| {
                let converted = LocatedTree::from_parts(
                    res.subtree.root_addr(),
                    convert_tree(res.subtree.root()),
                )
                .expect("converted tree is structure-preserving, so it matches its root address");
                (converted, res.checkpoints)
            })
        })
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use incrementalmerkletree::Marking;
    use zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT;

    /// Deterministic valid Orchard nodes; the last leaf carries a `Checkpoint` retention.
    pub(crate) fn synth(n: usize) -> Vec<Option<(MerkleHashOrchard, Retention<BlockHeight>)>> {
        let mut out = Vec::with_capacity(n);
        let mut a = MerkleHashOrchard::empty_leaf();
        let mut b = MerkleHashOrchard::empty_root(Level::from(0));
        for i in 0..n {
            let c = MerkleHashOrchard::combine(Level::from(0), &a, &b);
            a = b;
            b = c;
            let r = if i + 1 == n {
                Retention::Checkpoint {
                    id: BlockHeight::from(100u32 + i as u32),
                    marking: Marking::Reference,
                }
            } else {
                Retention::Ephemeral
            };
            out.push(Some((c, r)));
        }
        out
    }

    /// THE byte-equal gate for the v0.4 batch-affine path (always compiled).
    #[test]
    fn lookup_build_matches_scalar() {
        for n in [1usize, 7, 1000, 1024, 2000, 5000] {
            let start = Position::from(0);
            let mut a = synth(n);
            let mut b = synth(n);
            let scalar = crate::persist::build_subtrees::<MerkleHashOrchard, ORCHARD_SHARD_HEIGHT>(
                start, &mut a,
            );
            let batched = build_subtrees_lookup::<ORCHARD_SHARD_HEIGHT>(
                crate::batch_sinsemilla::orchard_combine_batch_cpu,
                start,
                &mut b,
            );
            assert_eq!(scalar, batched, "batch-affine build diverged from scalar at n={n}");
        }
    }
}
