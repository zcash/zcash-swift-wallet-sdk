# v0.5 scan-pacer hunt — find what actually paces the scan wall

> **Status: P0 in flight (2026-07-06, autonomous — Lukas: "go, fully autonomously,
> make a plan… keep going until we find a real tangible material to build on").**
> Successor to Plan C (CLOSED — see the mini-spec's ❌❌ block): the pass is
> `bound="scan"` on every device (A18 60 s / M4 29 s), yet the scan wall is
> INSENSITIVE to ±140 core-s of decrypt compute on both tiers. Decrypt — the
> biggest compute block (~150+ core-s) — runs in slack. Something else paces the
> lane. This plan names it, instrument-first (the census / firestats pattern,
> third outing), then builds the lever the data points at.

## 1 · What the scan lane actually does (code map, verified 2026-07-06)

`scan_chunks_inner` (scan.rs) is ONE sequential task per range:

```
loop per chunk (fetch-split sub-chunks, ≤8 MB / ≤10k blocks):
  A. rx.recv().await                      ← chunk wait (fetch/split starvation)   [UNMEASURED]
  B. spawn treestate prefetch (races C)
  C. scan_cached_blocks (block_in_place)  ← upstream; decrypt on rayon inside     [chunk_elapsed_ms, log-only]
  D. lane.submit(pending).await           ← write-behind handoff                  [persist_wait ✓ measured]
  E. prefetch.await                       ← treestate RTT overhang beyond C       [UNMEASURED]
  every 3 chunks (DEFAULT_ENHANCE_EVERY_CHUNKS):
  F. lane.drain().await                   ← FULL persist barrier                  [UNMEASURED, counts as SCAN]
  G. run_enhancement(...)                 ← measured, excluded from scan_s ✓
end: final lane.drain() barrier           ← end-of-range barrier                  [UNMEASURED, counts as SCAN]
```

Accounting facts: `scan_elapsed = scan_wall − interleaved_enhance_elapsed`
(scheduler.rs:442) — G is excluded but **F is not** (the drain runs before G's
timestamp); `enhance_s` in the stage split = final + interleaved enhancement
together. `scan_batch_target_ms` defaults to None → exactly one treestate
prefetch per chunk.

## 2 · Pre-registered suspects (ranked)

1. **F + end barrier — persist drains inside scan_s.** Device `persist_overlap_s`
   ≈ 29 s of commit work; the lane fully drains every 3 chunks. If commits trail
   the scan, the scan lane repeatedly eats the tail. Predicts: drains dominate on
   iPhone (slow I/O), modest on M4.
2. **C residue — upstream `scan_cached_blocks` bookkeeping** (per-action
   conversions, nullifier maps, batch orchestration on the scan thread; decrypt
   itself is rayon-side and proven slack). Predicts: scan_call_s ≈ scan_s and
   neither drains nor waits explain it.
3. **E — treestate RTT overhang** (one gRPC round-trip per chunk, hidden only if
   C is longer). Predicts: visible on fast-scan devices / slow networks.
4. **A — fetch/split starvation** beyond the fetch task's own active time
   (fetch_s 7 s vs scan_s 60 s says the pipe is fast, but split/permit
   backpressure could still stall recv).

The `enhance_s` device swing (1.1 → 11.0 → 20.8 s across three same-wallet runs)
is a second unexplained; instrument in the same wave (fetch vs store split).

## 3 · P0 — the instrument (this commit)

Engine-only, zero upstream/fork surface, always-on (nanosecond-cheap):

- `ScanStats` (scan.rs): `recv_wait`, `prefetch_wait`, `scan_call` (promote the
  existing per-chunk elapsed), `interleave_drain`, `final_drain` — Durations,
  summed per range.
- `SyncReport` (scheduler.rs): mirror + accumulate across ranges.
- `EnhanceStats` (enhance.rs): `fetch_elapsed` (gRPC get_transaction) vs
  `store_elapsed` (decrypt_and_store + DB) split.
- engine.rs: new `scan lane split` info line at pass end + BenchSummary/JSON
  fields (bench-ios renders them automatically): `scan_recv_wait_s`,
  `scan_prefetch_wait_s`, `scan_call_s`, `scan_interleave_drain_s`,
  `scan_final_drain_s`, `enhance_fetch_s`, `enhance_store_s`,
  `enhance_interleaved_s` (surfacing the already-measured value).
- Identity: `scan_s ≈ recv_wait + scan_call + prefetch_wait + interleave_drain +
  final_drain + residue` — residue computed at read time; a large residue is
  itself a finding (bookkeeping between the timed spans).
- Decrypt core-seconds already measured (`batch_dh_s`; full decrypt ≈ dh/0.924
  per C0) — no new fork surface for P0.
- `ENGINE_BUILD = 2026-07-06.v05-pacer-p0`.

## 4 · P1 — Mac reading (same session)

One clean interleaved pair on the reference wallet (quiet machine, prebuilt
binary — the measurement-hygiene rules from the Plan C postmortem). Read the
split → the pacer gets a name. Decision table:

| dominant term | named pacer | candidate lever (P2 shapes) |
|---|---|---|
| interleave/final drains | persist tail blocks the lane | decouple: enhance off the scan lane / drain-less reseed (nullifier views don't need a FULL drain) / deeper lane depth |
| scan_call_s ≈ scan_s | upstream per-action bookkeeping on the scan thread | 0-key probe to size it; then fork-or-upstream batch bookkeeping, or parallel ranges |
| recv_wait | fetch/split starvation | split-ahead decode workers, larger permits |
| prefetch_wait | treestate RTT per chunk | derive interior treestates locally (we already hold the frontier) — kills a round-trip per chunk |
| nothing dominates (flat residue) | orchestration overhead | parallel independent ranges (scan K ranges concurrently, own facades; persist lane already serializes) |

## 5 · P2+ — build the lever the data names (gated on P1)

Not pre-committed; the table above is the menu. Each lever ships behind its own
switch with an A/B gate on the Mac first, then the device protocol below.

## 6 · Device protocol (Lukas, after P1/P2 stabilize)

1. Rebuild probe: `./slipstream/bench-ios/app/build-xcframework.sh` runs on this
   side; Lukas rebuilds the app in Xcode (engine_build must read `v05-pacer-p0`
   or later).
2. COOL PHONE + healthy network, decrypt toggle irrelevant (leave OFF).
3. One run; send the new `scan_*` / `enhance_*` rows (screenshot or bench.json).
4. That single run names the pacer ON DEVICE (may differ from the Mac — the
   drains hypothesis predicts exactly that divergence).

## 7 · Session log

- **P0 (instrument)**: lane split (recv/scan_call/prefetch/drains/absorb) +
  enhance split (fetch/store/address) → log + bench JSON, always-on.
- **P1 (verdict — the pacer is named): `prefetch_wait_s = 32.3 s of a 52.2 s
  scan (62 %)` on the reference wallet — 71 chunk boundaries × ~455 ms
  `GetTreeState` round-trips.** `scan_call` (ALL upstream scan work incl.
  decrypt orchestration) = just 12.2 s; drains 4.7 s; recv 0.7 s. Bonus
  finds: (a) treestate RTT varies wildly server-side (~40 ms to ~455 ms
  across hours — the invisible "network weather" that swung day-to-day
  totals; `fetch_s` never showed it because it only times the block
  streamer); (b) `dh_s` sums wall-spans of oversubscribed rayon tasks and
  can exceed cores × wall — an upper bound, fine for A/Bs.
- **P2a (local treestate — built, audited, then measured OUT for speed):**
  `treestate.rs` running frontiers + per-boundary off-path server audit +
  process fuse, KAT'd, wired behind `local_treestate` (default OFF). The
  audit passed (byte-identical ChainStates) but the absorb cost
  **99.7 s/pass — plain per-leaf Pedersen/Sinsemilla hashing is the exact
  work the v0.4 graft skips and batch-affine 12×'s**; a naive frontier walks
  right back into it. PARKED (flag off, machinery + audit stay in-tree): the
  revival path is a batch-affine BULK absorb (orchard kernel exists; sapling
  Pedersen has none) and its real value is Tor/offline/server-load, not Mac
  speed. Also fixed en route: frontier CONTENT is load-bearing per chunk
  (persist.rs:1033 inserts it into the lane's trees) — size-only boundaries
  are impossible.
- **P2b (the shipped fix — fetch-side boundary prefetch):** the treestate
  fetch now spawns WHEN THE CHUNK IS EMITTED (`ChunkQueueSender` boundary
  fetcher, injected by the scheduler), so the RTT hides under queue wait +
  scan + submit instead of racing one scan call. Same fetches, same data,
  same sequencing; at most (queued+1) in flight. Tests/darkside fall back to
  the late spawn.
- **P2c (gated interleave):** interleaved enhancement (and its FULL persist
  drain — 4.5 s/pass, firing every 3 chunks) now runs only when notes were
  found since the last run; statuses/address windows keep the per-range +
  final backstops.
- **P2 A/B (Mac reference wallet, same-hour interleave): baseline 23.0 /
  23.5 s → fixed build 18.7 / 19.0 / 18.6 / 22.0 (median 18.8 s = +22 %
  same-weather; run 4's 22.0 was a fetch bump, not scan).** Split confirms
  both mechanisms: prefetch_wait 2.6–3.1 → 0.6 s, interleave_drain
  4.3–4.5 → 0.0 s, persist_wait 5.9–6.4 → 3.2–3.6 s (fewer barriers =
  smoother lane). Against the morning's slow-treestate baseline (52.6 s,
  455 ms/RPC) this build holds ~19 s ⇒ **the real headline is
  weather-immunity: every day is now a good-server day.** Remaining split
  at 18.8 s: scan_call 12.5 s (upstream scan) + submit 3.5 s + recv 0.7 s —
  the next targets if v0.5 pushes further. `ENGINE_BUILD =
  2026-07-06.v05-pacer-p2`.
- **DEVICE CONFIRMATION (Lukas's A18, 2026-07-06 07:04, cool phone, healthy
  net, C1 off): total 49.3 s vs the 62.2 s same-conditions baseline =
  +26 % — first sub-50 s iPhone restore.** `prefetch_wait = 77 µs` (the
  fetch-side spawn fully hides RTT on device), enhance mystery CLOSED
  (`enhance_s 0.82` — fetch 0.42 / store 0.15; the old 1.1→11→20.8 s swings
  were the no-op interleave rounds), drains 2.3 s, recv 1.2 s. New device
  split: **scan_call 36.6 s (76 % of scan) + submit ≈ 8 s (persist_wait
  9.35)** — the named A18 targets. STRATEGIC REOPENING: `dh_s 170.7` core-s
  over `scan_call 36.6` wall = average DH concurrency ≈ 4.7 on 6 cores —
  with the RTT slack gone the A18 scan is now genuinely compute-saturated,
  which re-arms **C2-endo-on-the-per-item-path for the PHONE specifically**
  (the mini-spec's own transfer condition now holds there; the Mac at
  scan_call 12.5 s keeps its slack). Order-of-operations lesson: C1's
  device A/B was run inside network slack — remove the slack first, then
  compute levers become measurable. Fleet on p2: **M4 18.8 s · A18 49.3 s**,
  both weather-immune.
- **C2-ENDO SHIPPED behind `endo_mul` (default OFF) + Mac production gate
  PASSED (2026-07-06, "go on all"):** GLV endomorphism on the PER-ITEM path
  (`vendor/orchard/src/endo.rs`) — constants derived + 300k-verified offline,
  φ↔λ pairing settled ON-CURVE (`(ζ_p·x, y) = Fq::ZETA·P`), re-proven
  in-crate (`decompose_reconstructs`, `endo_map_is_lambda`,
  `mul_endo_matches_group_mul`), wired at `ka_agree_dec` (both the batched
  seam's fallback and direct calls inherit), full-pipeline byte-equal
  (`wired_endo_mul_matches_per_item` via the shared harness). Honest
  per-item bench THROUGH THE REAL SEAM: 46.1 → 34.4 µs/mult = **1.34×**
  (theory 1.6–1.7×; gap = per-call table build + normalization —
  allocation-free recode tried, point ops dominate). **Production-shape
  gate (the C1 lesson): `dh_s 152.4 → 114.0 core-s = −25 % at
  `endo_calls = 2,411,814` (100 % coverage) — the ratio matches the
  microbench exactly, i.e. ZERO concurrency penalty** (C1's killer). Mac
  wall weather-bound as expected (slack); the wall verdict = the A18 run.
  Plumbing: config/env `ZCASH_ENDO_MUL`/CLI `--endo-mul`/probe ABI +
  bench-app "Endomorphism DH (C2)" toggle/JSON `endo_calls`.
  `ENGINE_BUILD = 2026-07-06.v05-c2-endo`.
- **persist-depth A/B (Mac): NO ship** — depth 3 left persist_wait unchanged
  (4.1 vs 4.0 s); the Mac lane outruns the scan. The A18's ~8 s submit tail
  needs the LANE cheaper, not deeper: named targets stand (checkpoint
  machinery ≈ 16 s/pass on device, row inserts ≈ 15.8 s). `--persist-depth`
  stays a bench flag for experiments.
- **Zodl victory-lap slices READY:** `--arm-all` FFI built from the
  committed p2 tree (iOS device + sim + versioned macOS in LocalPackages);
  macOS slice since refreshed with C2 (default-off — behaviorally identical
  until enabled).
- **C2 A18 DEVICE GATE PASSED (2026-07-06 08:18, Lukas's iPhone, cool +
  charging, healthy net): OFF 48.8 s → ON 42.29 s = +15.4 %** — formally
  clearing the mini-spec's ≥+15 % iOS-class gate that C1 failed. The rows
  prove the chain end-to-end: `endo_calls = 1,708,408` (100 % coverage),
  `batch_dh_s 170.7 → 130.6` (−23 %, matching the Mac's −25 %
  production-shape drop), and the ENTIRE wall win landed in
  `scan_call 36.6 → 30.1 s` — exactly where DH lives. Remaining A18 split:
  scan_call 30.1 (dh_s/scan_call ≈ 4.3 avg concurrency — still
  DH-saturated; further DH cuts keep paying) + persist_wait 9.0 (the lane
  targets) + drains 2.2 + recv 1.0. **iPhone arc: 78 → 55.4 (v0.4) → 49.3
  (pacer) → 42.3 s (C2).** Defaults decision pending: A18 +15.4 % ✓, Mac
  wall-neutral/dh −25 % ✓ (no harm); fleet rule wants an A14/A10 spot
  check before the flip.
- **PRODUCTION ZODL VICTORY LAP (2026-07-06 08:43, Lukas's iPhone, his
  real wallet, defaults only): total 50.04 s** — first sub-51 production
  restore, 0.7 s off the 49.3 s bench floor (Zodl overhead ≈ nil).
  297,570 blocks, bound="scan"; fetch 9.8 / scan 49.0 / **enhance 0.80**
  (the old 1.1→20.8 s swing is gone in production too) / persist_wait 8.6.
  Lane split: scan_call 38.0 / **prefetch_wait 99 µs** (the treestate RTT
  fully hidden on device) / drains 2.3 / recv 1.4 / residue 7.4;
  dh_s 177.3, endo_calls 0 (default-off). Zero errors; recovery→catch-up
  handoff clean. Production arc: **78 → 55.4 (v0.4) → 50.0 s (v0.5
  pacer, endo off)** = −36 % all-time; endo ON would project ~43–45 s
  (A18 gate +15.4 %). Morning detour recorded: the xcframework was
  macOS-only when Lukas first built (rebuild-local-ffi single-slice trap,
  third bite) → restored via `--arm-all`; the script now PRESERVES other
  slices + regenerates the plist from slices-present (`055e40d2` +
  `8bb2272e`, pushed).
- **ENDO IN PRODUCTION (2026-07-06 08:47, same wallet, minutes later,
  `ZCASH_ENDO_MUL=1` via scheme env): 43.14 s** — scan_call 38.0 → 30.8,
  dh_s 177.3 → 134.5 (−24 %), endo_calls 1,661,848 (100 %), zero errors.
  Raw wall +16.0 % / block-normalized +12 % / A18 bench pair +15.4 % —
  one band. Zodl switched endpoints 2 s in (eu.zec.rocks → zec.rocks);
  engine drained + restarted cleanly, first mini-pass banked one 10 k
  chunk (hence 287,574 vs 297,570 blocks); end-to-end incl. restart 45 s.
  **PRODUCTION ARC: 78 → 55.4 (v0.4) → 50.0 (pacer) → 43.1 s (endo) =
  −44.7 % all-time.** Defaults flip still gated on the A14/A10 spot pair.
