# Phase B1 — Cooperative CPU+GPU subtree hashing, on-device (design spec)

**Status:** approved 2026-06-15 (brainstorm). Feeds the B1 implementation plan.
**Scope:** ship the measured cooperative CPU+GPU Orchard subtree-hashing win to a **real
device**, gated on a critical-path measurement that decides whether the win exists at all.
Builds directly on B0 (byte-identical GPU `build_subtrees`, oracle-gated, default off).
Orchard only — Sapling stays deferred to Phase A′ + B2.

## Why this exists

B0 proved the GPU can compute Slipstream's Orchard `build_subtrees` combines and produce a
**byte-identical `data.db`** (B0.1 KAT 0/10k, B0.2 synthetic shard n≤5000, B0.4 gate(2)
darkside oracle PASSED on-Mac; gate(1) mainnet oracle pending user `TEST_UFVK`). The spike
proved the **cooperative throughput economics** (iPhone 16 Pro ~1.66×, iPad A10 ~1.47× over
CPU-alone) — but only as a *microbenchmark of pure combine work*. B1 is the bridge from
"the kernel is fast and correct" to "a real Zodl sync on real hardware finishes measurably
sooner, byte-for-byte identically."

## The crux (why this is measurement-first, not build-first)

**The cooperative throughput number is necessary but not sufficient.** Two unknowns sit
between it and a wall-clock win, and we are currently *guessing* both:

1. **Amdahl fraction.** What share of a real sync is Orchard-Sinsemilla-combine work that
   B0's GPU path can touch? Persist (where `build_subtrees` runs) was ~258 s of the iPad's
   ~9-min T6.9 sync — but persist is combines **plus** SQL writes **plus** tree bookkeeping.

2. **Critical-path occupancy (the dominant risk).** T6.9 write-behind **already overlaps
   persist behind scan**. The engine measures this directly: `scan_chunks_from_treestate`
   emits `persist_wait` (time scan stalls waiting on persist) and `persist_busy`. If
   `persist_wait ≈ 0`, the persist stage — and therefore the combines — is **already hidden
   off the critical path**, and a GPU combine speedup, however large, moves the wall clock by
   ≈0. If `persist_wait` is large and combine-dominated, that wait is our headroom ceiling.

We do not know which world we are in. **B1.1 produces that number before we build the
scheduler or touch the FFI.** B1.1 may legitimately conclude "stop" — and that is a
successful rung (knowledge banked, phantom win avoided).

## Decisions locked in this brainstorm

- **Scope = full on-device ship.** Destination is a device A/B showing real wall-time, not a
  bench. (User choice.)
- **Distribution = local-FFI build for now.** B1 validates via `init-local-ffi.sh --gpu`
  running in Zodl on the user's iPhone/iPad. The **public released `libzcashlc` XCFramework
  stays lean** (gpu OFF, zero wgpu — verified in B0.1 via `cargo tree`). How to eventually
  ship GPU to all SDK clients is **deferred** to a later phase. (User choice.)
- **Success bar = measurement-defined.** No fixed target now; B1.1's critical-path number
  sets the realistic ceiling and the ship is held to *that*. (User choice.)
- **Inherited, non-negotiable:** byte-identical `data.db` (golden oracle), runtime kill
  switch (default off), Slipstream branch, additive-only, old SDK path frozen, LOCAL-ONLY
  (never push).

## Approach (A — measurement-gated, persist-first)

Chosen over B (scan-stage hook up front — needs librustzcash-internals interception + likely
a scan/shardtree fork, out-of-scope tier) and C (full adaptive scheduler infra first — heavier,
builds infra before the Amdahl fraction justifies it). A reuses all of B0's proven byte-identical
machinery and defers every hard/expensive step behind the B1.1 data gate.

### B1.1 — Measure (ships NO GPU into sync)

Instruments the **CPU** `build_subtrees` path, so it runs on a normal gpu-off build — no
wgpu, no device-GPU risk. Answers the crux.

- **Metrics** → a `SyncProfile` (extends `ScanStats`): `combine_count`, `combine_wall`
  (time in the Orchard `build_orchard_subtrees` call), plus the **existing** `persist_busy` /
  `persist_wait`, scan-stage wall, total wall. Combine count = internal nodes built per shard
  (one combine each).
- **Critical-path signal** is derived from data the engine already produces: the ratio of
  `persist_wait` (critical-path stall on persist) to `persist_busy`, and of `combine_wall`
  to `persist_busy` (is persist combine-dominated or SQL-dominated?). Headroom ≈
  `min(persist_wait, combine_wall)` — combine work that is *both* on the critical path *and*
  GPU-addressable.
- **CPU occupancy during persist** (cooperative vs offload signal): inferred from whether
  scan and persist run concurrently (scan threads busy while persist runs ⇒ contended ⇒
  offload model; idle ⇒ spare ⇒ cooperative model). Reported per device.
- **Surfaces:** CLI `sync --profile` dumps `SyncProfile` as JSON at sync end (Mac, fast
  iteration); device emits the same structured line via the existing tracing/ring-event path
  (Zodl), so an unattended device run is profile-able from the log alone.
- **Deliverable:** for each device — "Orchard combine work is X % of persist, contributes
  Y ms to the critical path out of a Z s sync; CPU is {spare|contended} during persist." →
  the go/stop decision, the cooperative-vs-offload pick, and the measurement-defined bar.

### B1.2 — Cooperative / offload scheduler on `build_subtrees`

Extends B0's `build_subtrees_gpu`. **Cooperative and offload are one mechanism, different
ratios** — `AllGpu` (offload) frees contended cores; a fractional split (cooperative) uses
spare cores too.

- **Config (kill switch):** `EngineConfig.gpu_cooperative: bool` (requires `gpu_subtree`) +
  `gpu_split: GpuSplit { Auto | Fixed(f32) | AllGpu }`. Default off → zero behavioural diff,
  identical to today.
- **Calibration probe** at engine open: run a fixed synthetic batch (~4096 combines)
  CPU-alone vs GPU-alone, measure, compute `gpu_frac`; cache once (~tens of ms, amortized
  over the whole sync). `Auto` uses the probe; `Fixed` overrides; `AllGpu` forces offload.
- **Split** inside `build_subtrees_gpu`: per shard level, route `round(N · gpu_frac)`
  combines to the GPU and the remaining `N − that` to CPU-rayon via `thread::scope` (the
  spike's proven concurrent pattern); reassemble by index.
- **Byte-identicalness:** the partition is purely *who computes which combine* — results
  merge in index order, identical to all-CPU or all-GPU. The CPU fallback from B0 (any GPU
  miss → CPU) still backstops. Guaranteed by the golden oracle, not by inspection.

### B1.3 — On-device ship + A/B

- **Local-FFI feature passthrough:** `init-local-ffi.sh --gpu` enables a `rust/` passthrough
  feature (`slipstream-gpu = ["slipstream-core/gpu"]`) so the local XCFramework links wgpu;
  the release build path is untouched.
- **Config across the FFI:** `gpu_cooperative` + `gpu_split` cross at the EngineConfig build
  site in `rust/src/lib.rs`; Swift `SlipstreamSynchronizer` passes them (debug/dev surface
  only — not public API).
- **Device gotchas:** port the spike's A10 fixes verbatim — `required_limits:
  adapter.limits()` (stage-variable cap) and chunked dispatch (16384-elem command buffers,
  watchdog avoidance).
- **A/B:** standard 269k recent-wallet Zodl restore on iPhone 16 Pro + iPad A10, gpu-on vs
  gpu-off: **byte-identical `data.db`** (required) + wall-time delta **held to the B1.1 bar**.

### B1.4 — (conditional) scan-stage hook

Only if B1.1 shows the subtree build is too small or already-hidden **and** the scan-stage
per-block Orchard commitment appends are the real critical-path combine source. Higher risk
(librustzcash `scan_block` internals; possible scan/shardtree fork). **Data-gated, not
pre-committed** — its own spec if reached.

## Golden oracle & testing (inherited gate, extended)

- **Byte-identical golden oracle** is the safety net for every scheduler change: reuse the
  B0.4 mainnet oracle + the darkside `gpu_subtree` oracle, adding a **cooperative variant**
  (`--gpu-cooperative-b` on the CLI oracle; a darkside `gpu_cooperative_pipeline_matches_*`
  test mirroring the B0.4-prep `gpu_subtree` one) → VERDICT IDENTICAL with the split on.
- **Per-rung green gates** (CONVENTIONS): `cargo test -p slipstream-core -p slipstream-cli` +
  clippy **both** feature sets, every rung; darkside serial when touched; **swift
  `OfflineTests` (after `init-local-ffi.sh --macos-only`) only when `rust/` or root
  `Cargo.toml` is touched** (B1.3). Every rung = work + tests green + STATE.md, committed
  `[#1755] slipstream: B1.x — <imperative>`.
- **Device A/B** (B1.3) is user-run; a CLI sync-time A/B on Mac (controller-run) is the
  fast proxy gate before each device round.

## Acceptance (per rung)

| Rung | Done = |
|---|---|
| B1.1 | `SyncProfile` lands the critical-path number on CLI + device; go/stop + bar recorded in STATE.md. (A "stop" verdict is success.) |
| B1.2 | Cooperative/offload split byte-identical: CLI cooperative oracle + darkside `gpu_cooperative` test VERDICT IDENTICAL; clippy/test gates green; kill switch off ⇒ zero diff. |
| B1.3 | Local-FFI gpu build runs in Zodl; device A/B on iPhone+iPad meets the B1.1 bar with byte-identical `data.db`; OfflineTests green. |
| B1.4 | (only if reached) own spec. |

## Out of scope (recorded, not dropped)

- Shipping GPU in the **public** released XCFramework (distribution decision deferred).
- **Sapling** GPU (Pedersen/Jubjub) — Phase A′ kernel + B2 wiring.
- The general **adaptive scheduler infra** (Approach C) — revisit if multiple hooks justify it.
- **Scan-stage hook** (B1.4) unless B1.1 data demands it.
- Tor / decrypt-kernel / any non-combine GPU offload.

## Risks

- **R1 (dominant): combines already hidden by write-behind** ⇒ no wall-time headroom. Mitigation:
  B1.1 measures exactly this *before* any build; stop-gate is explicit and counted as success.
- **R2: device-GPU instability** (A10 watchdog, Metal init). Mitigation: spike already solved
  these; B1.3 ports the fixes; kill switch defaults off.
- **R3: calibration overhead/instability.** Mitigation: one-time probe, cached; `Fixed`
  escape hatch; `AllGpu`/off fallbacks.
- **R4: byte-divergence from the split.** Mitigation: golden oracle gate (mainnet + darkside
  cooperative variant) + B0's CPU fallback; rung does not land until VERDICT IDENTICAL.

## References

- B0 design/plan: `plans/2026-06-15-phase-b0-gpu-subtree-design.md` + `…-plan.md`.
- Spike (LOCAL-ONLY): `~/Dev/Xcode/GitHub/LukasKorba/zcash-gpu-spike` (Phase A kernel, device
  probe, A10 fixes).
- Integration point: `slipstream/core/src/persist.rs` `build_subtrees` / `build_orchard_subtrees`
  (B0.3); GPU crate `slipstream/gpuhash`; write-behind stats `persist_wait`/`persist_busy` in
  `scan.rs`.
- Conventions: `docs/slipstream/CONVENTIONS.md`. Living state: `docs/slipstream/STATE.md`.
