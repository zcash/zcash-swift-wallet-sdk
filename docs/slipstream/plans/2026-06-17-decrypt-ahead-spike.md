# Decrypt-ahead spike — does a persistent cross-chunk decryptor beat the per-call BatchRunner, and does it compose with write-behind?

> **Status:** SCOPED (not started).
> **Source:** the 2026-06-17 zallet↔slipstream comparison (`docs/slipstream/2026-06-17-zallet-vs-slipstream.md`), merge item ①.
> **Conventions:** `docs/slipstream/CONVENTIONS.md` — LOCAL-ONLY, branch `slipstream`, additive (flag default-OFF), byte-identical oracle-gated, **measure M4 first**.
> **Prior (load-bearing):** `2026-06-15-perf-spikes-learnings.md` — modern devices are **compute-bound** (`wall ≈ total_cpu_work/cores`); **concurrency levers were falsified twice** (GPU offload, deeper write-behind). "Don't re-test concurrency on modern devices … start from work reduction." This spike must respect that.

## The idea (from zallet)

zallet runs a persistent, decoupled batch-decryptor (`zcash_client_backend::sync::decryptor`): one long-lived runner fed by a `queue_block` API that trial-decrypts **ahead** across range boundaries. slipstream instead **builds and drops a fresh `BatchRunner` on every `scan_cached_blocks` call** — discarding the warm crossbeam channel + partial batch each chunk. The comparison flagged this as slipstream's #1 thing-to-steal — *but* also noted the decrypt **kernel** is the identical upstream code on the same rayon pool as zallet, so any win here is **orchestration, not a faster inner loop**.

## Two distinct hypotheses — DO NOT conflate them

| | Mechanism | Odds under the compute-bound prior |
|---|---|---|
| **H-work** | Per-call `BatchRunner` construct/teardown (rayon batch spin-up, channel alloc, partial-batch discard) is **fixed wasted WORK** a persistent runner removes. | **Promising.** This is *work reduction* — the one lever the perf-learnings says still works. Helps **regardless of core count** if the per-call cost is non-trivial. |
| **H-cores** | Decrypt-ahead overlaps chunk N+1's decrypt with chunk N's scan/commit, filling **idle cores**. | **Likely fails on ≥6-core.** Only helps if cores sit idle during scan. On a saturated pool this is the *exact* shape that falsified depth>1 write-behind (M4 **1.26× slower**, scan-active doubled from rayon contention). Burden of proof HIGH. |

The spike's job is to measure these **separately** — H-work could be a real win even if H-cores is dead.

## THE kill question (run first, cheapest)

**Does decrypt-ahead compose with the write-behind lane without re-triggering the rayon contention that already falsified depth>1?** Both the decrypt-ahead runner *and* the write-behind persist commit use the **global rayon pool** on ≥6-core devices (`lane_pool_policy()` returns no dedicated pool there). Co-scheduling decrypt(N+1) with persist(N) → both fight for all cores → the depth>1 failure mode. If so, the concurrency half is dead on ≥6-core for the same reason, and slipstream's per-call runner is already near-optimal there.

## Method (measurement-first; the M4 kills wrong ideas fastest)

### Phase 0 — disconfirm cheaply (instrumentation only, NO new engine)
Decide if *either* hypothesis is alive before building anything.
- **Per-call rebuild cost (H-work):** instrument the existing `scan_cached_blocks` path — time spent constructing/dropping the runner + channel per chunk, as a fraction of decrypt time. M4 + a 6-core iPhone, ~50k restore, default config (sparse + write-behind ON).
- **Scan-phase core occupancy (H-cores):** are cores idle during scan, or saturated? Reuse the stage-split + per-pool instrumentation already in `persist.rs`/`engine.rs`; add a scan-phase core-occupancy probe.
- **KILL gate:** per-call overhead ≈ 0 (H-work dead) **AND** scan already saturates cores (H-cores dead) → **NO-GO, stop here.** Record it like the pipelining park so nobody retries.

### Phase 1 — prototype (only if Phase 0 leaves a hypothesis alive)
- `EngineConfig.decrypt_ahead` (default **OFF**) + `--decrypt-ahead[-b]`.
- One long-lived runner (zallet's `decryptor::Engine` shape: bounded queue ~1000, batch threshold tuned toward the design-doc ~2–4k L2 target rather than upstream's hard-coded 100) feeding `ScannedBlock`s into the **existing** `sparse_put_blocks` → `PersistLane`.
- **Same upstream BatchRunner inside** — orchestration only, no kernel change.
- Byte-identity unchanged: decrypt-ahead changes *when* decryption happens, not *what*.

### Phase 2 — the composition A/B (the real test)
- M4 + 6-core iPhone + A10, `decrypt_ahead` ON vs OFF, **with `write_behind` ON** (the shipped config).
- Watch **scan-active time** (the depth>1 failure signature) + total `scan_s` + the stage-split.
- Gate to ≥6-core via the existing `lane_pool_policy` core detection (A10 decrypt already saturates → expect no win → keep off).

## GO / NO-GO criteria

- **GO:** ≥**1.3×** scan improvement on a ≥6-core device, **byte-identical golden oracle + darkside CLEAN**, **no A10 regression** (gated off there). ≥1.5× = unambiguous; a result in the [1.3, 1.7] ambiguity band → re-measure per the engine's usual rule.
- **NO-GO:** Phase 0 shows neither hypothesis alive; OR Phase 2 regresses scan-active on ≥6-core (rayon contention, like depth>1); OR the oracle diverges.
- **Either way:** record the verdict + numbers in `STATE.md` + `perf-spikes-learnings.md`. A NO-GO is a *kept* result (the pipelining/GPU parks are the model), not a deletion.

## What this spike is NOT
- NOT the decrypt **kernel** (SIMD/NEON/column-ECDH — the parked L4a). That is a separate, harder *work-reduction* spike on the inner loop. This is decryptor **orchestration** only.
- NOT a change to correctness/ordering — byte-identical is non-negotiable.

## Effort / risk
- **Phase 0:** small (instrumentation + 2 measurements). Good chance it kills H-cores cheaply.
- **Phase 1:** medium (persistent-runner refactor + flag + the queue/ownership handoff into `PersistLane` is the fiddly part).
- **Phase 2:** small (A/B once built).
- **Risk:** the prior is *against* the concurrency half (H-cores); **H-work (per-call overhead removal) is the realistic win** and the reason to run Phase 0 at all.

## Provenance
From the 2026-06-17 zallet comparison. The honest framing it surfaced: slipstream's decrypt kernel == zallet's (same upstream code, same rayon pool), so any decrypt-phase win here is overhead-removal + maybe overlap, **not** a faster inner loop. The kernel remains the bigger, separate lever — and per the perf-learnings, *work reduction* (kernel or overhead) is the only direction left that can lower the compute-bound floor.
