# Persist-pipelining (deeper write-behind) — design + plan

**Status:** approved 2026-06-15 (autonomous; user granted full autonomy, goal fixed = chase
the ~20%). Brainstorm + spec + plan in this doc; implementation follows TDD rungs below.
**Goal:** deepen the scan→persist write-behind from **depth-1 to depth-N** so scan stops
stalling on combine-heavy chunks → walk the total toward the `max(scan, persist)` perfect-overlap
floor (~22% measured headroom on iPhone/A14/M4). **Byte-identical `data.db`** (non-negotiable).

## Why (data)

Stage-split decomposition, all 3 modern devices: `persist_busy` > `scan-compute`, so persist
(≈60% the Orchard combine the GPU couldn't speed) is the true bottleneck — and it's only
partially hidden because the write-behind is **depth-1**. Current totals sit ~22% above the
floor: iPhone 89.7→70s, A14 125.5→98s, M4 32.3→25s. (This is the payoff of the parked GPU
detour: the measurement pinpointed persist as the under-hidden bottleneck. The win is to *hide*
it, not speed it.)

## Mechanism (grounded in persist.rs / scan.rs)

- **Depth-1 enforcement:** `PersistLane` owns `db: Option<Db>` + `sparse: Option<SparseTreeState>`
  (persist.rs:1618-1619). The single `in_flight: Option<JoinHandle>` runs one `spawn_blocking`
  persist that *moves db+sparse in and returns them* (the ownership ping-pong, await_in_flight
  1692-1706). Only one persist can run (one tree state). `submit_job` (1732) calls
  `await_in_flight()` **before** spawning the next — that await **is** `persist_wait`.
- **Why correctness is depth-independent:** `WriteBehindFacade::put_blocks` (1443) advances the
  running unspent nullifier views (`apply_nullifier_delta`, per block, 1466-1490) + `prior_meta`
  **every chunk**, regardless of how many persists are pending. So chunk N+k's spend detection
  already sees N..N+k-1's found/spent notes. The `stash` is just the pending *persist* unit; the
  facade keeps the depth-1 stash invariant because the scan loop `take_stash()`es each chunk
  before the next `put_blocks`.
- **Why byte-identical:** persist stays **serial and in-order** — the worker runs the exact same
  `sparse_put_blocks` calls in the exact same order. Only scan's run-ahead depth changes. The
  resulting `data.db` is identical bit-for-bit; the golden oracle confirms it.

## Design

Replace the lane's "block-at-every-submit" with a **bounded pending queue (depth N) + a serial
persist worker**:
- Scan loop: scan chunk → `take_stash()` → **enqueue** the `PendingPersist` (blocks only when N
  are already pending). Keeps scanning.
- Persist worker: owns `db`+`sparse`, drains the queue **one unit at a time, in order**
  (continuously — never idles while units are queued, which the current submit-driven design
  would). Same `sparse_put_blocks`, same order.
- `persist_wait` = scan-side time blocked on a full queue (still measured).
- **Depth budget (per device, memory):** `N=1` = today's behavior (kill switch); `N=3–4` for
  ≥4GB devices (iPhone/M4/A14); `N=1` for the constrained A10 (each queued unit buffers a chunk's
  scanned blocks + commitments). Plumbed from `EngineConfig` (and the FFI's
  `total_memory_bytes`, like the existing `scaled_for_device_memory`).

## Acceptance

1. **Byte-identical:** depth-N `data.db` == depth-1 `data.db` — CLI A/B (`semantic_diff`/byte
   compare) **and** the darkside oracle CLEAN at depth>1.
2. **Speedup:** M4 CLI A/B depth-1 vs depth-4 → `total_s` drops toward the floor (~10–22%).
3. **No deadlock / no lost unit:** the `sparse_join_stress_no_deadlock_under_constrained_pools`
   stress test green at depth-N; drain barrier still flushes all pending.
4. Gates: `cargo test -p slipstream-core -p slipstream-cli` + clippy both sets; darkside serial.

## Plan (TDD rungs — each green + committed + STATE.md)

- **R1 — refactor to bounded-queue + serial worker, DEFAULT depth-1 (no behavior change).**
  Restructure `PersistLane` (worker draining a bounded queue) keeping `N=1` semantics identical
  to today. Verify byte-identical (darkside oracle) + no-deadlock (stress test) + core/cli green.
  This isolates the structural change from the behavior change.
- **R2 — `EngineConfig.persist_depth` (default 1) + per-device budget + CLI `--persist-depth`.**
  Allow `N>1`. Validate (`persist_depth>=1`; requires write_behind). Plumb through scan.rs.
- **R3 — MEASURE + verify.** M4 CLI A/B depth-1 vs depth-4: assert byte-identical `data.db`,
  record `total_s` delta. Darkside oracle at depth-3 CLEAN. STATE.md with the measured %.
- **R4 (if R3 green) — FFI + device:** thread `persist_depth` (auto from `total_memory_bytes`)
  through `zcashlc_slipstream`; user runs the device A/B (iPhone/A14) for the real number.

## Conventions

Branch `slipstream`, LOCAL-ONLY, commits `[#1755] slipstream: persist-pipelining — <imperative>`,
every commit = work + tests green + STATE.md. No `unwrap`/`expect` outside tests; `tracing` not
`println`; edition 2024. R1-R3 are slipstream-internal (no swift gate); R4 touches `rust/`.
