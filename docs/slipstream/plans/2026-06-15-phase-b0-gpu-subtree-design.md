# Phase B0 — GPU subtree-build integration spike (design spec)

**Status:** approved 2026-06-15 (brainstorm). Feeds the B0 implementation plan.
**Scope:** prove that GPU-computing the **Orchard** subtree combines inside Slipstream's
`build_subtrees` yields a **byte-identical `data.db`**, behind a feature flag, with the CPU
path untouched when off. A de-risking spike — NOT the cooperative scheduler, NOT Sapling,
NOT device shipping (those are B1 / Phase A′ / B2).

## Why this exists

Phase A (in the local-only spike `~/Dev/Xcode/GitHub/LukasKorba/zcash-gpu-spike`) proved a
bit-exact GPU Orchard Sinsemilla `combine` (oracle 0/10M vs `orchard`). The device probe
proved the cooperative CPU+GPU economics (iPhone 16 Pro ~1.66×, iPad A10 ~1.47×). B0 is the
bridge: prove the GPU hash can be wired into the *real* Slipstream tree-build and still
produce a byte-identical wallet database — the integration risk, isolated and oracle-gated,
before B1 commits to the cooperative scheduler.

## Goal & success criterion

A feature-flagged path where Slipstream's **Orchard** `build_subtrees` computes its Sinsemilla
combines on the GPU.

**Done =** with `--gpu-subtree` on, the **existing Slipstream oracle reports VERDICT
IDENTICAL** `data.db` (vs CPU / upstream) on a mainnet tip−N range, AND the hermetic darkside
oracles are CLEAN — the same gate already used for `--sparse-b` / `--write-behind`. With the
flag off, the CPU path is byte-for-byte unchanged (zero behavioural diff).

## Scope: Orchard only — Sapling deferred, not dropped

- Orchard uses Sinsemilla (Pallas) = Phase A's kernel. Sapling uses **Pedersen hash on
  Jubjub** — a different hash on a different curve that Phase A did **not** build.
- B0's job is the **integration**, which is hash-agnostic: `build_subtrees<H>` and `from_iter`
  are generic over `H: Hashable`; the hook, the precompute mechanism, the feature flag, and
  the oracle gate are identical for Sapling (`H = sapling::Node`). Proving Orchard byte-
  identical **validates the integration pattern for both pools**, and the oracle already
  checks the *whole* `data.db` (Orchard via the new GPU path, Sapling via the untouched CPU
  path).
- The only Sapling-specific work is the **kernel** (Pedersen/Jubjub) — a separate Phase-A-
  sized cryptographic build. Roadmap: **Phase A′** builds the GPU Pedersen/Jubjub kernel
  (oracle vs the `sapling` crate); **B2** wires it into B0's already-proven integration.

## Integration point (grounded in source)

`slipstream/core/src/persist.rs:959` — Slipstream's own forked
`build_subtrees<H, const SHARD_HEIGHT>(start_position, commitments)`:
- `commitments.par_chunks_mut(BUILD_CHUNK_SIZE)` → for each chunk,
  `shardtree::LocatedTree::from_iter(start..end, SHARD_HEIGHT, leaves)` builds the shard.
- The Sinsemilla combines fire **inside `from_iter`**, one per internal node (~65k for a full
  Orchard shard, `H = orchard::tree::MerkleHashOrchard`).
- Called for both pools: sapling (persist.rs:804), orchard (persist.rs:862). B0 hooks the
  **orchard** call only.
- Already isolated in the dedicated lane `rayon::ThreadPool` (T6.9b), so GPU work here does
  not contend with the decrypt pool.

## Mechanism (the primary approach B0 validates)

`Hashable::combine(level, &a, &b)` is a **static** trait method (no `self`), so we cannot
thread a GPU context through it directly. Primary approach — **precompute + lookup, reusing
`from_iter` unchanged** (lowest byte-identical risk):

1. **GPU-precompute the shard's combines.** Given the chunk's leaves at `start..end`, build
   the *complete* shard bottom-up: level 0 = leaves (real) + `empty_root(0)` padding; each
   higher level = a single batched `orchard_combine_batch(...)` call (Phase A's kernel). This
   yields every internal node hash the shard needs. Record each `(left_bytes, right_bytes) →
   parent_bytes` in a map.
2. **Feed it to the unmodified `from_iter`** via a `GpuHashOrchard(MerkleHashOrchard)` newtype
   whose `combine` reads the precomputed map (set on a **thread-local** before the
   `from_iter` call — one per rayon chunk-worker; cleared after). Cache miss (e.g. an
   all-empty padding combine) falls back to the CPU `combine`. `empty_leaf`/`empty_root`
   delegate to the inner type.
3. Because `from_iter`'s structure/retention/pruning logic is **reused verbatim**, byte-
   identicalness reduces to "the map returns exactly what `combine` would" — which Phase A's
   oracle already proved to 0/10M.

B0 also **records the per-shard overhead** of this mechanism (map build + thread-local +
lookups). If that overhead is too high to leave room for B1's win, B1 may switch to
reimplementing the subtree build with per-level batches (carries retention-replication risk;
deferred precisely because B0 can measure whether it's needed).

## Components & containment

- **New crate `slipstream/gpuhash` (`slipstream-gpuhash`)** — graduated from the spike:
  `field.wgsl` + `pallas.wgsl` + `sinsemilla.wgsl` + the `wgpu` `Gpu` harness +
  `orchard_combine_batch(layers: &[u8], lefts: &[[u8;32]], rights: &[[u8;32]]) -> Vec<[u8;32]>`.
  Edition 2024; `no unwrap/expect` outside tests; `tracing` not `println`.
- **`persist.rs` hook** — behind `EngineConfig.gpu_subtree` (default off), the Orchard
  `build_subtrees` uses the precompute + `GpuHashOrchard`. Sapling + the inline/CPU path
  untouched. CLI flag `--gpu-subtree` (Mac/CLI validation).
- **Cargo feature `gpu`** on `slipstream-core` gating the `slipstream-gpuhash` dep + the hook,
  so the default `libzcashlc` XCFramework and CI `swift test --filter OfflineTests` are
  unaffected unless built with `--features gpu`.
- **Containment:** all under `slipstream/` + `docs/slipstream/`, plus the root `Cargo.toml`
  workspace member line (permitted exception). `wgpu` is a **new dep → Decision Log entry**
  (CONVENTIONS) in the plan.

## Out of scope (later phases)

- **B1**: the cooperative *proportional* CPU+GPU split (the probe's `thread::scope` pattern,
  productized), on-device build, sync-time measurement, perf tuning.
- **Phase A′**: the GPU Sapling Pedersen/Jubjub kernel.
- **B2**: wiring Sapling into B0's integration + B1's scheduler.

## Gates (B0 acceptance)

- **Oracle VERDICT IDENTICAL** — mainnet tip−N, `--gpu-subtree` vs CPU (the existing
  `--sparse-b`/`--write-behind` oracle harness) + hermetic darkside oracles CLEAN.
- `cargo test -p slipstream-core -p slipstream-cli` green **both with and without
  `--features gpu`**; clippy zero both feature sets.
- `swift test --filter OfflineTests` green (root `Cargo.toml`/workspace touched →
  `init-local-ffi.sh --macos-only` first).
- STATE.md updated in the same commit; ENGINE_BUILD tag bump.

## Risks & mitigations

- **Thread-local mechanism viability** — the crux; B0's explicit job to confirm (and to
  measure its overhead). Fallback (reimplement build) is deferred, not needed unless B0 says so.
- **`wgpu` in the Rust core** — feature-gated (`gpu`) so it never enters the default build;
  Decision Log entry; B0 validates it builds + links for the macOS slice (device is B1).
- **Byte-identicalness** — the entire point; oracle-gated, and the mechanism minimizes risk by
  reusing `from_iter` verbatim.

## Definition of done

`cargo run -p slipstream-cli --features gpu -- <oracle args> --gpu-subtree` on a mainnet
tip−N range reports **VERDICT IDENTICAL**, darkside oracles CLEAN, both cargo feature sets +
clippy + OfflineTests green. The GPU Orchard subtree build is then a proven, flag-gated path
— ready for B1 to make it *cooperative* and ship the device win.
