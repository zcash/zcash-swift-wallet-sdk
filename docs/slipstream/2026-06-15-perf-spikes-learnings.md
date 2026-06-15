# Slipstream performance spikes — learnings (GPU + persist-pipelining)

Date: 2026-06-15. Status: both spikes PARKED (kept, not removed). This doc captures what was
tried, measured, and concluded, so the next attempt starts from knowledge, not from scratch.

## TL;DR

- The **magnitude speedup is the engine rewrite** (v0.1+v0.2), already shipped: A14 iPad
  **25:11 (old SDK) → 2:05 (slipstream) ≈ 12×**.
- Two subsequent "+20%" theses — **GPU combine offload** (Phase B) and **deeper write-behind
  pipelining** — were each built, measured, and **FALSIFIED on modern devices.**
- **Root cause of both failures:** modern devices are **compute-bound** (`wall ≈ total_cpu_work
  / cores`). Concurrency levers conserve total work and **add core contention** → they don't
  help, and regress high-core devices.
- **The only remaining lever is WORK REDUCTION** (algorithmic): fewer combines / faster decrypt.

## Method (reusable)

- **Stage-split decomposition** from device/CLI logs: `total_s`, `scan_s`, `persist_wait_s`,
  `persist_overlap_s`; per-chunk `orch build_ms` (the `sparse orchard tree split` line). Sum
  `build_ms` and compare to `persist_wait` to find the combine's critical-path share.
- **Measurement-first.** Every thesis measured before believing. The `engine pass starting`
  log carries the config (`sparse`/`write_behind`/`gpu_subtree`). Controller-run CLI A/B on the
  Mac via `zec.rocks` + the repo `TEST_UFVK` (`wallet_session.rs`); device A/B via Zodl.
- **Golden oracle** (`semantic_diff`, byte-identical) + **darkside oracle** (hermetic) = the
  correctness gates.

## GPU (Phase B) — arc + verdict

- **B0 DONE, proven, parked.** Bit-exact GPU Orchard Sinsemilla combine: KAT 0/10k, mainnet
  oracle **VERDICT IDENTICAL** (765 shards byte-identical), darkside oracle CLEAN. The crypto +
  integration is real and reusable. `gpu` cargo feature **default-off** (zero wgpu shipped).
- It is **OFFLOAD, not cooperative** (the GPU does ~all combines, CPU freed — NOT a CPU+GPU
  split). For a *scan-bound* sync, offload is the right model (cooperative would steal CPU from
  the scan bottleneck). The spike's "cooperative 1.47–1.66×" measured hashing *in isolation*,
  which doesn't transfer to sync.
- **Device matrix (v0.2 CPU → v0.3 GPU, 273k restore):**
  | Device | v0.2 | v0.3 | result |
  |---|---|---|---|
  | iPad A10 (2-core, weak GPU) | 8:31 | pathological | gate OFF (poisons the device) |
  | iPhone 16 Pro (A18) | 89.7s | 79.8s | **1.12×** (below the 1.2–1.4× call) |
  | iPad A14 | 2:05 | (moot) | not run after park |
  | **Mac M4** | 32.3s | 40.5s | **0.80× (−25% REGRESSION)** |
- **M4 detail:** Σ orchard combine **identical 6.2s** CPU vs GPU (the M4 CPU is as fast as its
  GPU); GPU-on added **+8.2s to scan** = Metal driver/readback contention for zero combine gain.
- **Gating bombshell:** the M4 shows combine *parity* yet *regresses* → an "enable if GPU-rate ≥
  CPU-rate" probe MISCLASSIFIES it; a correct gate must measure NET sync benefit, not throughput.
- **Verdict:** GPU-combine is a narrow ~1.1× win (mid-range only), regresses both extremes
  (too-slow-GPU A10, too-fast-CPU M4). PARKED.

## Persist-pipelining (deeper write-behind) — arc + verdict

- **Thesis:** `persist_busy > scan-compute` on every device → persist (≈60% combine) is the
  bottleneck, only partially hidden by the **depth-1** write-behind. Computed ~22% headroom as
  `total − max(scan, persist)` (iPhone 89.7→70, A14 125.5→98, M4 32.3→25).
- **Design (sound, low-risk):** bounded pending-queue + serial persist worker. Persist stays
  serial + in-order → **byte-identical by construction**; the facade advances the unspent
  nullifier view **per chunk** → spend-detection is **depth-independent**. `EngineConfig.persist_depth`
  (default 1). R1 (queue refactor, depth-1 no-op) + R2 (config + `--persist-depth[-b]`): verified
  byte-identical (5 lane contracts + darkside oracle CLEAN).
- **R3 (M4 A/B) FALSIFIED IT:** depth-1 **33.4s** vs depth-4 **42.2s = 1.26× SLOWER**.
  `persist_wait` dropped (22.0→19.1 — scan *did* run ahead) but **scan-active DOUBLED
  (10.8→22.6s)** = core contention.
- **THE FLOOR WAS AN ARTIFACT.** `max(scan, persist)` assumed scan and persist run on *separate*
  resources. They don't: on ≥6-core devices the persist commit uses the **global rayon pool (all
  cores)** (`lane_pool_policy()` returns no dedicated pool there), and scan also uses all cores.
  Deeper buffering runs them concurrently → they fight for the same cores. depth-1's backpressure
  was beneficially *serializing* them. The real floor is `total_cpu_work / cores`, which
  pipelining **cannot reduce** (only reshuffles + adds contention).
- **Verdict:** deeper write-behind REGRESSES high-core devices. PARKED (default depth-1 =
  byte-identical, verified). depth>1 might help *only* the isolated-lane-pool low-core A10 (which
  is memory-constrained + gate-off) — i.e. nowhere useful.

## The unifying insight

**Modern devices are compute-bound: `wall ≈ total_cpu_work / cores`.** Both concurrency levers
(GPU offload, deeper pipeline):
1. **Conserve** total work (don't reduce it), and
2. **Add contention** (persist's rayon + scan's rayon both want all cores via the global pool).

→ Neither helps; both regress high-core devices. The existing depth-1 backpressure and the
CPU-combine were already near-optimal. The sync is sitting on the modern-device compute floor —
which is a *good* place to be (it's the 12× the engine already delivered).

## What WOULD work: WORK REDUCTION (the remaining lever)

Unlike concurrency, **reducing `total_cpu_work` lowers the floor.** Two candidates (both real
algorithmic spikes — harder, riskier, correctness-critical):

- **Fewer combines** — build/retain less of the commitment tree (only the paths to wallet notes
  + the frontier, not full ~65k-combine shards). Combine ≈ 60% of persist. Touches shardtree's
  retention/pruning + byte-identicalness — the golden oracle gates it.
- **Faster decrypt** — SIMD/batch the trial-decryption (scan ≈ the other half of the work). The
  parked "L4a decrypt kernel" idea.

## Parked artifacts (kept, not removed)

- **GPU:** `slipstream/gpuhash` + `slipstream/core/src/gpu_subtree.rs` + the v0.3 FFI toggle.
  `gpu` cargo feature DEFAULT-OFF → zero wgpu in released `libzcashlc`. `ZCASH_GPU_SUBTREE` /
  `--gpu-subtree[-b]` default-false. Local-only spike: `~/Dev/Xcode/.../zcash-gpu-spike`.
- **Pipelining:** `PersistLane` bounded-queue refactor + `EngineConfig.persist_depth` (default 1
  = byte-identical). depth>1 dormant. NOTE: this is a *live refactor*, not feature-gated — to
  reach GPU-level isolation, either feature-gate it or revert the lane (git: the R1/R2 commits).
- **Specs/plans:** `plans/2026-06-15-phase-b0-gpu-subtree-*.md`, `…-phase-b1-cooperative-gpu-design.md`,
  `…-phase-b1.1-measurement-plan.md`, `persist-pipelining-design.md`.

## If resuming

Don't re-test concurrency on modern devices (settled: regresses). Start from **work reduction**,
and measure on the M4 first (controller-run CLI A/B) before any device — the M4 is the strictest
compute-bound case and kills wrong ideas fastest.
