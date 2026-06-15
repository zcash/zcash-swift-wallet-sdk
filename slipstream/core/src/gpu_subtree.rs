//! GPU-OFFLOAD Orchard subtree build (feature `gpu`, Phase B0). NOTE: this is offload — the
//! GPU computes ~all the combines and the CPU is freed (it does NOT cooperatively split the
//! combine work CPU+GPU; that "cooperative" model was designed in B1 but never built). v0.3
//! device matrix (2026-06-15) showed offload is a narrow ~1.1× win (A14/iPhone) that regresses
//! both extremes (A10 weak-GPU, M4 fast-CPU −25%); the path is PARKED, default-off. See STATE.md.
//!
//! Strategy (lowest byte-identical risk): GPU-precompute every Sinsemilla combine the shard
//! needs, then reuse `shardtree::LocatedTree::from_iter` VERBATIM — its retention/pruning logic
//! is untouched — via a `GpuHashOrchard` newtype whose `combine` reads a thread-local
//! precomputed `(level‖left‖right) → parent` map (CPU fallback on miss). The result tree is a
//! `LocatedPrunableTree<GpuHashOrchard>`; we rebuild it as `<MerkleHashOrchard>` with a small
//! recursive convert over shardtree's public `Node`/`Tree` API.
//!
//! B0.2 Decision Log: `LocatedTree::map` maps only the leaf value `V`, not the annotation `A`
//! (and `Tree`'s inner `Node` field is `pub(crate)`), so the `H`→`H` conversion cannot be a
//! one-line `map`; it is a recursive rebuild via the public `Tree::{parent,leaf,empty}` +
//! `Deref<Node>`. Correctness rests on the CPU fallback: any combine not in the precomputed
//! map is computed by `MerkleHashOrchard::combine`, so the result is byte-identical regardless
//! of how `from_iter` pads partial shards.

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

thread_local! {
    /// Precomputed combines for the shard `from_iter` is currently building on THIS thread.
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
pub(crate) struct GpuHashOrchard(pub MerkleHashOrchard);

impl Hashable for GpuHashOrchard {
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
            None => Self(MerkleHashOrchard::combine(level, &a.0, &b.0)), // CPU fallback
        }
    }
}

/// Build the complete binary tree over `leaves` bottom-up on the GPU (each level one batched
/// `orchard_combine_batch`), recording every `(level, left, right) → parent`. Odd levels pad
/// with `empty_root(level)`; the `from_iter` combines that `precompute` does not cover (true
/// `Nil`-padding boundaries) fall back to the CPU.
fn precompute_shard_map(leaves: &[MerkleHashOrchard]) -> HashMap<[u8; 65], [u8; 32]> {
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
        let parents = slipstream_gpuhash::orchard_combine_batch(&layers, &lefts, &rights);
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

/// Recursively rebuild a `PrunableTree<GpuHashOrchard>` as `PrunableTree<MerkleHashOrchard>`
/// (converts both the annotation `A` and the leaf value `V`).
fn convert_tree(t: &PrunableTree<GpuHashOrchard>) -> PrunableTree<MerkleHashOrchard> {
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

/// GPU equivalent of `persist::build_subtrees` for Orchard. Same chunking/structure; the only
/// difference is GPU-computed combines + the H-type convert. Output is identical to the CPU
/// path (gated by the `gpu_subtree_build_matches_cpu` test and the engine oracle).
pub(crate) fn build_subtrees_gpu<const SHARD_HEIGHT: u8>(
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
            let map = precompute_shard_map(&leaves);

            PRECOMP.with(|p| *p.borrow_mut() = Some(map));
            let res = LocatedTree::from_iter(
                start..end,
                Level::from(SHARD_HEIGHT),
                chunk.iter_mut().map(|n| {
                    let (h, r) = n.take().expect("always Some");
                    (GpuHashOrchard(h), r)
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
mod tests {
    use super::*;
    use incrementalmerkletree::Marking;
    use zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT;

    /// Deterministic valid Orchard nodes; the last leaf carries a `Checkpoint` retention.
    fn synth(n: usize) -> Vec<Option<(MerkleHashOrchard, Retention<BlockHeight>)>> {
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

    #[test]
    fn gpu_subtree_build_matches_cpu() {
        for n in [1usize, 7, 1000, 1024, 2000, 5000] {
            let start = Position::from(0);
            let mut a = synth(n);
            let mut b = synth(n);
            let cpu = crate::persist::build_subtrees::<MerkleHashOrchard, ORCHARD_SHARD_HEIGHT>(start, &mut a);
            let gpu = build_subtrees_gpu::<ORCHARD_SHARD_HEIGHT>(start, &mut b);
            assert_eq!(cpu, gpu, "GPU subtree build diverged from CPU at n={n}");
        }
    }
}
