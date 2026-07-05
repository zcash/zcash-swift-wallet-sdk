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
