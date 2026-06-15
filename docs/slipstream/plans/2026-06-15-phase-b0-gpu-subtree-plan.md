# Phase B0 — GPU subtree-build integration spike — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax. Follow `docs/slipstream/CONVENTIONS.md` (LOCAL-ONLY, branch
> `slipstream`, commit `[#1755] slipstream: <imperative>`, every commit = work + tests green +
> STATE.md update).

**Goal:** Prove that GPU-computing the Orchard Sinsemilla combines inside Slipstream's
`build_subtrees` yields a byte-identical `data.db`, behind `--gpu-subtree`, CPU path untouched.

**Architecture:** Graduate Phase A's proven GPU Orchard `combine` into a feature-gated
`slipstream-gpuhash` crate. In `persist.rs`, when `gpu_subtree` is on, the Orchard
`build_subtrees` GPU-precomputes the shard's combines (Phase A kernel, batched per level) and
feeds the **unmodified** `shardtree::LocatedTree::from_iter` via a `GpuHashOrchard` newtype
whose `combine` reads a thread-local precomputed map — reusing `from_iter`'s retention logic
verbatim. Gated by the existing golden oracle (byte-identical `data.db`).

**Tech Stack:** Rust (edition 2024, rust 1.90), `wgpu` 29 (new, feature `gpu`), `shardtree`,
`incrementalmerkletree`, `orchard`, `rayon`. Source of the GPU kernel: the proven spike at
`~/Dev/Xcode/GitHub/LukasKorba/zcash-gpu-spike`.

**Spec:** `2026-06-15-phase-b0-gpu-subtree-design.md` (this plan implements it).

---

## File structure

| File | Responsibility |
|---|---|
| `slipstream/gpuhash/Cargo.toml`, `slipstream/gpuhash/src/lib.rs`, `.../shaders/{field,pallas,sinsemilla}.wgsl` (new) | `slipstream-gpuhash`: the wgpu `Gpu` harness + `orchard_combine_batch` + a process-global `Gpu`. Ported verbatim from the spike. |
| `Cargo.toml` (root, modify) | workspace `members += "slipstream/gpuhash"`; `[workspace.dependencies]` += `wgpu`/`pollster`/`bytemuck`. |
| `slipstream/core/Cargo.toml` (modify) | `[features] gpu = ["dep:slipstream-gpuhash"]`; optional dep `slipstream-gpuhash`. |
| `slipstream/core/src/gpu_subtree.rs` (new, `#[cfg(feature="gpu")]`) | `gpu_precompute_shard`, `GpuHashOrchard` newtype + `Hashable`, the thread-local, `build_subtrees_gpu`. The novel core. |
| `slipstream/core/src/config.rs` (modify) | `EngineConfig.gpu_subtree: bool` + validation (mirror `write_behind`). |
| `slipstream/core/src/persist.rs` (modify, ~line 860) | branch the **orchard** `build_subtrees` call to `build_subtrees_gpu` when `gpu_subtree`. Sapling + CPU path untouched. |
| `slipstream/cli/src/main.rs` (modify) | `--gpu-subtree` (sync) + `--gpu-subtree-b` (oracle), mirroring `--write-behind`/`--write-behind-b`. |
| `docs/slipstream/STATE.md` (modify) | the pivot (B0.0) + per-task status. |

Crate-name convention: dir `slipstream/gpuhash`, package `slipstream-gpuhash` (matches
`slipstream-core`/`slipstream-cli`).

---

## Task B0.0: Record the pivot in STATE.md (docs-only)

**Files:** Modify `docs/slipstream/STATE.md`.

- [ ] **Step 1: Set NEXT ACTION + Decision Log.** Replace the `## NEXT ACTION` body with:
  `➡️ B0.1 — graduate the GPU Orchard hash into slipstream-gpuhash (plan: plans/2026-06-15-phase-b0-gpu-subtree-plan.md).` Move the current T8.2 line under "Previous:". Append a Decision Log entry: *"2026-06-15: user repriorized — GPU-driven cooperative speedup (Phase B) is now PRE-P8 priority; P8 hardening (T8.2+) deferred to follow Phase B. Phase A complete (bit-exact GPU Orchard combine, oracle 0/10M, in the local spike). B0 = byte-identical integration spike."* Add a `## Phase B — GPU cooperative speedup` section with a task table (B0.0–B0.4 + B1/Phase A′/B2 as future rows).
- [ ] **Step 2: Always-green (no code touched).** Run: `cargo test -p slipstream-core -p slipstream-cli` → expect the current baseline green (core 140+1ign / cli 24, per T8.1).
- [ ] **Step 3: Commit.** `git add docs/slipstream/STATE.md && git -c commit.gpgsign=false commit -m "[#1755] slipstream: B0.0 — pivot to Phase B (GPU speedup) pre-P8; STATE.md + Decision Log"`

---

## Task B0.1: Graduate the GPU hash into `slipstream-gpuhash`

**Files:** Create `slipstream/gpuhash/Cargo.toml`, `slipstream/gpuhash/src/lib.rs`,
`slipstream/gpuhash/shaders/{field,pallas,sinsemilla}.wgsl`. Modify root `Cargo.toml`,
`slipstream/core/Cargo.toml`.

- [ ] **Step 1: Port the shaders verbatim.** Copy from the spike unchanged:
  `cp ~/Dev/Xcode/GitHub/LukasKorba/zcash-gpu-spike/crates/gpu-wgpu/shaders/{field,pallas,sinsemilla}.wgsl slipstream/gpuhash/shaders/`. These are the bit-exact (oracle 0/10M) kernels — do not edit.

- [ ] **Step 2: Create `slipstream/gpuhash/Cargo.toml`.**
```toml
[package]
name = "slipstream-gpuhash"
version = "0.0.1"
edition = "2024"
rust-version = "1.90"
license = "MIT"
publish = false

[dependencies]
wgpu = { workspace = true }
pollster = { workspace = true }
bytemuck = { workspace = true }

[dev-dependencies]
orchard = { workspace = true }
incrementalmerkletree = { workspace = true }
rand = { workspace = true }
```

- [ ] **Step 3: Root `Cargo.toml` — workspace member + deps + Decision Log.**
  `members = ["slipstream/core", "slipstream/cli", "slipstream/protogen", "slipstream/gpuhash"]`.
  In `[workspace.dependencies]` add `wgpu = "29"`, `pollster = "0.4"`, `bytemuck = { version = "1", features = ["derive"] }`.
  Append to `docs/slipstream/CONVENTIONS.md` Decision Log (or STATE.md Decision Log if that's
  where it lives): *"2026-06-15 (B0.1): new deps wgpu 29 / pollster 0.4 / bytemuck 1 — GPU
  Sinsemilla offload. Confined to slipstream-gpuhash + the `gpu` feature; never in the default
  libzcashlc build. Justification: Phase A + device probe."*

- [ ] **Step 4: Port `src/lib.rs`** from the spike (`crates/gpu-wgpu/src/lib.rs`): the `Gpu`
  struct (`new`/`new_async` with `adapter.limits()`, the chunked `fp_mul_chain_timed`, the
  `dispatch_*` helpers, the `merkle_combine` host method) — verbatim. Then ADD the public API
  and a process-global device:
```rust
use std::sync::OnceLock;
static GPU: OnceLock<Gpu> = OnceLock::new();
/// Shared device (wgpu Device/Queue are Send+Sync). Created once on first use.
pub fn shared() -> &'static Gpu { GPU.get_or_init(Gpu::new) }

/// Batched Orchard MerkleCRH combine. `layers[i]`/`lefts[i]`/`rights[i]` → output[i].
/// Each input element packs to 17 u32 (layer ‖ left8 ‖ right8); output is 32 canonical bytes.
pub fn orchard_combine_batch(
    layers: &[u8], lefts: &[[u8; 32]], rights: &[[u8; 32]],
) -> Vec<[u8; 32]> {
    assert_eq!(layers.len(), lefts.len());
    assert_eq!(layers.len(), rights.len());
    let n = layers.len();
    let mut input = Vec::with_capacity(n * 17);
    for i in 0..n {
        input.push(layers[i] as u32);
        for w in 0..8 { input.push(u32::from_le_bytes(lefts[i][w*4..w*4+4].try_into().unwrap())); }
        for w in 0..8 { input.push(u32::from_le_bytes(rights[i][w*4..w*4+4].try_into().unwrap())); }
    }
    let out = shared().merkle_combine(&input, /* gens */ &generators_u32(), n); // n*8 u32
    (0..n).map(|i| {
        let mut b = [0u8; 32];
        for w in 0..8 { b[w*4..w*4+4].copy_from_slice(&out[i*8+w].to_le_bytes()); }
        b
    }).collect()
}
```
  Port `generators_u32()` by inlining the spike's `sinsemilla-consts::all_generators()` logic
  (derive Q via `pallas::Point::hash_to_curve`, read `sinsemilla::SINSEMILLA_S`) — add
  `sinsemilla`, `pasta_curves`, `group`, `ff` as deps. (The `.try_into().unwrap()` on a fixed
  4-byte slice is infallible; allowed only because it's a const-size slice — or use
  `u32::from_le_bytes([b[0],b[1],b[2],b[3]])` to satisfy the no-unwrap rule. Prefer the latter.)

- [ ] **Step 5: Add `slipstream-gpuhash` as an optional dep + `gpu` feature in `slipstream/core/Cargo.toml`.**
```toml
[features]
darkside = []
gpu = ["dep:slipstream-gpuhash"]

[dependencies]
slipstream-gpuhash = { path = "../gpuhash", optional = true }
# (sinsemilla/pasta_curves/group/ff added to workspace.dependencies if not present)
```

- [ ] **Step 6: Write the KAT (in `slipstream/gpuhash/src/lib.rs` `#[cfg(test)]`).**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use incrementalmerkletree::{Hashable, Level};
    use orchard::tree::MerkleHashOrchard;
    use rand::{rngs::StdRng, SeedableRng, RngCore};

    #[test]
    fn orchard_combine_batch_matches_orchard() {
        let mut rng = StdRng::seed_from_u64(0xB0_1);
        let n = 10_000;
        // deterministic valid nodes: fold combine from empties
        let mut pool = Vec::with_capacity(2 * n);
        let mut a = MerkleHashOrchard::empty_leaf();
        let mut b = MerkleHashOrchard::empty_root(Level::from(0));
        for _ in 0..2 * n { let c = MerkleHashOrchard::combine(Level::from(0), &a, &b); pool.push(c); a = b; b = c; }
        let layers: Vec<u8> = (0..n).map(|_| (rng.next_u32() % 32) as u8).collect();
        let lefts:  Vec<[u8;32]> = (0..n).map(|i| pool[i].to_bytes()).collect();
        let rights: Vec<[u8;32]> = (0..n).map(|i| pool[n + i].to_bytes()).collect();
        let got = orchard_combine_batch(&layers, &lefts, &rights);
        for i in 0..n {
            let exp = MerkleHashOrchard::combine(
                Level::from(layers[i]),
                &MerkleHashOrchard::from_bytes(&lefts[i]).unwrap(),
                &MerkleHashOrchard::from_bytes(&rights[i]).unwrap(),
            ).to_bytes();
            assert_eq!(got[i], exp, "mismatch at {i}");
        }
    }
}
```

- [ ] **Step 7: Build + test.**
  Run: `cargo test -p slipstream-gpuhash` → expect `orchard_combine_batch_matches_orchard ... ok`.
  Run: `cargo build -p slipstream-core --features gpu` → expect clean.
  Run: `cargo test -p slipstream-core -p slipstream-cli` (default, no gpu) → baseline green.

- [ ] **Step 8: `init-local-ffi.sh --macos-only` + `swift test --filter OfflineTests`** (root
  Cargo.toml touched). Expect OfflineTests green.

- [ ] **Step 9: Commit + STATE.md.**
  `[#1755] slipstream: B0.1 — slipstream-gpuhash crate (GPU Orchard combine, feature gpu), KAT vs orchard`

---

## Task B0.2: The precompute + lookup mechanism (`gpu_subtree.rs`)

**Files:** Create `slipstream/core/src/gpu_subtree.rs` (`#[cfg(feature="gpu")]`, declared in
`lib.rs` as `#[cfg(feature="gpu")] mod gpu_subtree;`). Test in the same file.

- [ ] **Step 1: Confirm the shardtree tree-map API.** In `slipstream/core` run
  `cargo doc -p shardtree --no-deps` or grep the cached source
  (`~/.cargo/registry/src/*/shardtree-0.6*/src/`) for `fn map` / `fn try_map` on
  `LocatedTree`/`Tree`. Record the exact signature used to convert
  `LocatedPrunableTree<GpuHashOrchard>` → `LocatedPrunableTree<MerkleHashOrchard>` (expected:
  `LocatedTree::map(|v| ...)` mapping node values). This is the one external-API unknown.

- [ ] **Step 2: Write the failing test** (synthetic shard, GPU path == CPU path):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use incrementalmerkletree::{Position, Retention};
    use orchard::tree::MerkleHashOrchard;
    use crate::persist::{build_subtrees, ORCHARD_SHARD_HEIGHT}; // make these pub(crate)

    fn synth(n: usize) -> Vec<Option<(MerkleHashOrchard, Retention<zcash_protocol::consensus::BlockHeight>)>> {
        // n real leaves (folded from empties), last one a Checkpoint retention
        let mut out = Vec::with_capacity(n);
        let mut a = MerkleHashOrchard::empty_leaf();
        let mut b = MerkleHashOrchard::empty_root(0u8.into());
        for i in 0..n {
            let c = MerkleHashOrchard::combine(0u8.into(), &a, &b); a = b; b = c;
            let r = if i + 1 == n { Retention::Checkpoint { id: 100u32.into(), marking: incrementalmerkletree::Marking::Reference } } else { Retention::Ephemeral };
            out.push(Some((c, r)));
        }
        out
    }

    #[test]
    fn gpu_subtree_build_matches_cpu() {
        for n in [1usize, 1000, 2000, 65535] { // incl. partial / padded shards
            let start = Position::from(0);
            let mut a = synth(n); let mut b = synth(n);
            let cpu = build_subtrees::<MerkleHashOrchard, ORCHARD_SHARD_HEIGHT>(start, &mut a);
            let gpu = build_subtrees_gpu::<ORCHARD_SHARD_HEIGHT>(start, &mut b);
            assert_eq!(cpu, gpu, "GPU subtree build diverged at n={n}");
        }
    }
}
```
  (`LocatedPrunableTree` + `BTreeMap` derive `PartialEq`, so `assert_eq!` on the
  `Vec<(LocatedPrunableTree<MerkleHashOrchard>, BTreeMap<..>)>` is a structural byte-compare.)

- [ ] **Step 3: Run it — expect FAIL** (`build_subtrees_gpu` undefined).
  Run: `cargo test -p slipstream-core --features gpu gpu_subtree_build_matches_cpu`

- [ ] **Step 4: Implement `gpu_subtree.rs`.**
```rust
//! GPU-cooperative Orchard subtree build (feature `gpu`). Precomputes the shard's Sinsemilla
//! combines on the GPU, then reuses shardtree's `from_iter` verbatim via a lookup-Hashable.
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use incrementalmerkletree::{Hashable, Level, Position, Retention};
use orchard::tree::MerkleHashOrchard;
use shardtree::LocatedPrunableTree;
use zcash_protocol::consensus::BlockHeight;
use crate::persist::BUILD_CHUNK_SIZE; // make pub(crate)

thread_local! {
    static PRECOMP: RefCell<Option<HashMap<[u8; 64], [u8; 32]>>> = const { RefCell::new(None) };
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GpuHashOrchard(pub MerkleHashOrchard);

fn key(a: &MerkleHashOrchard, b: &MerkleHashOrchard) -> [u8; 64] {
    let mut k = [0u8; 64];
    k[..32].copy_from_slice(&a.to_bytes());
    k[32..].copy_from_slice(&b.to_bytes());
    k
}

impl Hashable for GpuHashOrchard {
    fn empty_leaf() -> Self { Self(MerkleHashOrchard::empty_leaf()) }
    fn empty_root(level: Level) -> Self { Self(MerkleHashOrchard::empty_root(level)) }
    fn combine(level: Level, a: &Self, b: &Self) -> Self {
        let hit = PRECOMP.with(|p| p.borrow().as_ref().and_then(|m| m.get(&key(&a.0, &b.0)).copied()));
        match hit.and_then(|bytes| Option::from(MerkleHashOrchard::from_bytes(&bytes))) {
            Some(node) => Self(node),
            None => Self(MerkleHashOrchard::combine(level, &a.0, &b.0)), // CPU fallback (empties etc.)
        }
    }
}

/// Build the complete shard bottom-up on the GPU and record (left‖right)→parent for every
/// internal combine. `leaves[i]` is the node at position start+i; positions past `end` are
/// empty_root(0). Returns the lookup map for `from_iter`.
fn precompute_shard_map(
    start: Position, end: Position,
    leaves: &[(MerkleHashOrchard, Retention<BlockHeight>)],
) -> HashMap<[u8; 64], [u8; 32]> {
    // shard width is 2^SHARD_HEIGHT, but from_iter only combines within [start,end) rounded up
    // the binary tree over the chunk. Build levels until one node remains.
    let mut level: Vec<MerkleHashOrchard> = leaves.iter().map(|(h, _)| *h).collect();
    let mut map = HashMap::new();
    let mut lvl = 0u8;
    while level.len() > 1 {
        // pad to even with empty_root(lvl)
        if level.len() % 2 == 1 { level.push(MerkleHashOrchard::empty_root(Level::from(lvl))); }
        let pairs = level.len() / 2;
        let layers = vec![lvl; pairs];
        let lefts:  Vec<[u8;32]> = (0..pairs).map(|i| level[2*i].to_bytes()).collect();
        let rights: Vec<[u8;32]> = (0..pairs).map(|i| level[2*i+1].to_bytes()).collect();
        let parents = slipstream_gpuhash::orchard_combine_batch(&layers, &lefts, &rights);
        let mut next = Vec::with_capacity(pairs);
        for i in 0..pairs {
            map.insert(key(&level[2*i], &level[2*i+1]),
                       MerkleHashOrchard::from_bytes(&parents[i]).into_option().expect("gpu node canonical").to_bytes());
            next.push(MerkleHashOrchard::from_bytes(&parents[i]).into_option().expect("gpu node canonical"));
        }
        level = next;
        lvl += 1;
    }
    let _ = (start, end);
    map
}
```
  Then `build_subtrees_gpu`, mirroring `persist::build_subtrees` but per-chunk: for each
  `BUILD_CHUNK_SIZE` chunk, `precompute_shard_map`, set the thread-local, map the chunk's
  `(MerkleHashOrchard, Retention)` → `(GpuHashOrchard, Retention)`, call
  `shardtree::LocatedTree::from_iter::<GpuHashOrchard>(start..end, SHARD_HEIGHT, ...)`, convert
  the resulting `LocatedPrunableTree<GpuHashOrchard>` back to `<MerkleHashOrchard>` via the
  Step-1 map API (`.map(|g| g.0)`), clear the thread-local, return `(subtree, checkpoints)`.
  Keep the `par_chunks_mut` shape (the lane pool already scopes rayon). NOTE: replace the
  `.expect(...)` above with a CPU-combine fallback to honour no-expect-outside-tests, OR keep
  them only if you add a `// gpu node is always canonical` safety note — prefer the fallback.

- [ ] **Step 5: Run the test — expect PASS** (iterate on the tree-map conversion until the
  `Vec<(LocatedPrunableTree, _)>` compares equal for all n incl. 1 and 65535).
  Run: `cargo test -p slipstream-core --features gpu gpu_subtree_build_matches_cpu`

- [ ] **Step 6: Commit + STATE.md.**
  `[#1755] slipstream: B0.2 — GPU precompute + GpuHashOrchard lookup; subtree build == CPU`

---

## Task B0.3: Wire into `persist.rs` behind `EngineConfig.gpu_subtree`

**Files:** Modify `slipstream/core/src/config.rs`, `slipstream/core/src/persist.rs`,
`slipstream/cli/src/main.rs`.

- [ ] **Step 1: `EngineConfig` field + validation (mirror `write_behind`).** In `config.rs`
  add `pub gpu_subtree: bool` (doc: "Compute Orchard subtree combines on the GPU (B0). Requires
  `sparse_persistence` and the `gpu` cargo feature."); default `false`; in `validate()` add:
  `if self.gpu_subtree && !self.sparse_persistence { return Err(... "gpu_subtree requires sparse_persistence".into()) }`.

- [ ] **Step 2: CLI flags (mirror `--write-behind` / `--write-behind-b`).** In `cli/src/main.rs`
  add `--gpu-subtree` (bool, default false) to the `Sync` subcommand and `--gpu-subtree-b`
  (bool, default false) to the `Oracle` subcommand; thread `gpu_subtree` into the `EngineConfig`
  built for `sync`, and into the B-side config for `oracle` (exactly as `write_behind` /
  `write_behind_b` are threaded — same call sites).

- [ ] **Step 3: The persist hook.** In `persist.rs` at the Orchard build call (~line 860),
  branch:
```rust
let orchard_subtrees = {
    #[cfg(feature = "gpu")]
    if cfg.gpu_subtree {
        crate::gpu_subtree::build_subtrees_gpu::<ORCHARD_SHARD_HEIGHT>(orch_start, &mut orchard_commitments)
    } else {
        build_subtrees::<_, ORCHARD_SHARD_HEIGHT>(orch_start, &mut orchard_commitments)
    }
    #[cfg(not(feature = "gpu"))]
    build_subtrees::<_, ORCHARD_SHARD_HEIGHT>(orch_start, &mut orchard_commitments)
};
```
  (`cfg` = the `EngineConfig` already in scope in `sparse_put_blocks`; confirm the binding name
  and thread it in if needed. The **sapling** call at ~line 804 is NOT touched.)

- [ ] **Step 4: Hermetic no-regression + on-path test.** Add a hermetic test that runs the
  sparse commit on a synthetic block batch with `gpu_subtree=false` and `=true` (feature `gpu`)
  and asserts the resulting orchard tree root + serialized shards are identical. (Reuse the
  existing hermetic persist-test harness; if none isolates the tree, assert via
  `orch_tree.root()` equality across the two configs.)
  Run: `cargo test -p slipstream-core --features gpu` and `cargo test -p slipstream-core` → both green.

- [ ] **Step 5: clippy both feature sets.**
  `cargo clippy -p slipstream-core -p slipstream-cli -- -D warnings` and
  `cargo clippy -p slipstream-core --features gpu -- -D warnings` → zero warnings.

- [ ] **Step 6: Commit + STATE.md.**
  `[#1755] slipstream: B0.3 — --gpu-subtree flag + persist.rs orchard hook (CPU path untouched)`

---

## Task B0.4: Acceptance gate — oracle VERDICT IDENTICAL

**Files:** none new (uses the existing oracle harness); modify `STATE.md`, bump `ENGINE_BUILD`.

- [ ] **Step 1: Bump `ENGINE_BUILD`** to `"2026-06-15.b0-gpu-subtree"` (wherever the tag string
  lives, e.g. `rust/src/lib.rs` or `engine.rs` — grep `ENGINE_BUILD`).

- [ ] **Step 2: Hermetic darkside oracles with GPU on.** Start the darkside lightwalletd (see
  CONVENTIONS), then:
  `cargo test -p slipstream-core --features "darkside gpu" -- --ignored --test-threads=1`
  Expect: all darkside oracle/sync/reorg tests green (run the `--gpu-subtree-b` variants if the
  darkside oracle harness takes the flag; otherwise add one `*_gpu_subtree` darkside oracle test
  mirroring the `*_write_behind` one).

- [ ] **Step 3: Mainnet tip−N golden oracle — THE GATE.**
  `cargo run -p slipstream-cli --release --features gpu -- oracle --ufvk <TEST_UFVK> --birthday <tip-2000> --sparse-b --gpu-subtree-b`
  Expected: `VERDICT IDENTICAL` (A = CPU/upstream persistence, B = sparse + GPU Orchard subtree;
  all tables OK, incl. the orchard tree shards/cap/checkpoints byte-identical).

- [ ] **Step 4: Full gate sweep.**
  `cargo test -p slipstream-core -p slipstream-cli` (no gpu) +
  `cargo test -p slipstream-core --features gpu` + clippy both sets +
  `./Scripts/init-local-ffi.sh --macos-only` + `swift test --filter OfflineTests`.

- [ ] **Step 5: Record + commit.** Update STATE.md: B0 DONE — GPU Orchard subtree build is
  byte-identical (oracle VERDICT IDENTICAL tip−2000 + darkside CLEAN); set NEXT ACTION to B1
  (cooperative proportional CPU+GPU split + device sync-time measurement). Commit:
  `[#1755] slipstream: B0.4 — GPU Orchard subtree byte-identical (oracle VERDICT IDENTICAL); B0 done`

---

## Self-Review notes (author)

- **Spec coverage:** goal (byte-identical GPU Orchard subtree) → B0.2+B0.3+B0.4; mechanism
  (precompute + thread-local lookup + reuse from_iter) → B0.2; crate graduation + feature `gpu`
  → B0.1; flag + CPU-untouched → B0.3; oracle gate → B0.4; pivot → B0.0; Orchard-only / Sapling
  deferred → respected (sapling call untouched, noted in B0.3). ✓
- **Known soft spot (honest):** the shardtree tree-map API (`LocatedTree<GpuHashOrchard>` →
  `<MerkleHashOrchard>`) is the one external unknown — B0.2 Step 1 confirms it before
  implementing; the B0.2 `assert_eq!` is the safety net. If the map API is absent/awkward, that
  is a B0 finding that informs whether B1 reimplements the build instead of reusing `from_iter`.
- **No-unwrap rule:** the `.expect("gpu node canonical")` in the B0.2 sketch must become a
  CPU-combine fallback (or be test-only); flagged inline. `try_into().unwrap()` on fixed slices
  replaced with `from_le_bytes([..])`.
- **`pub(crate)` exposures:** `build_subtrees`, `ORCHARD_SHARD_HEIGHT`, `BUILD_CHUNK_SIZE` in
  `persist.rs` become `pub(crate)` for B0.2's test + code (additive, no behaviour change).
- **Feature hygiene:** every `gpu`-only item is `#[cfg(feature="gpu")]`; default build (and CI
  OfflineTests) never compiles wgpu. Verified by the "both feature sets" gate in B0.3/B0.4.
