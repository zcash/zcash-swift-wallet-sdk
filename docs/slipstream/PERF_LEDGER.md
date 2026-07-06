# Slipstream Performance Ledger — findings, open candidates, revival paths

> **The living continuation document for perf work.** Parked 2026-07-06 after v0.5 shipped.
> Resume protocol: read STATE.md first (as always), then THIS file end-to-end — it holds
> every measured finding and every open candidate with its evidence and entry point.
> Update it whenever a candidate is measured, shipped, or killed. Never delete a row —
> move it to the graveyard with its verdict (dead ideas get re-proposed otherwise).

## Where v0.5 ended (the baseline any new work measures against)

Production Zodl, Lukas's real wallet, defaults only, 2026-07-06 (`ENGINE_BUILD=2026-07-06.v05-endo-on`):

| Device | v0.4 | v0.5 | All-time arc |
|---|---|---|---|
| M4 Mac | 18.7 s (best-day median) | **~19–20 s ANY day** (weather-immune) | 28.9 → 20 |
| iPhone A18 | 55.4 s | **43.1 s** | 78 → 43.1 (−45%) |
| iPad Air A14 | 117 s | **67.6 s** | ~134 → 67.6 (−50%) |
| iPad 2018 A10 (2 GB) | 354 s | **283 s** | 525 → 283 (−46%) |

v0.5 levers (all default-on): boundary treestate **prefetch** (unflagged), **gated
interleaved enhancement** (unflagged), **GLV endo DH** (`endo_mul`, kill `ZCASH_ENDO_MUL=0`).

The instrument suite that makes all numbers below cheap to re-measure: pass-end logs
`sync stage split` / `scan lane split` / `enhance split` / `batch_dh fire stats`; bench JSON
(`census.rs::BenchSummary`); CLI `slipstream bench`; SlipstreamBench iOS app (all lever
toggles); measurement hygiene rules in `plans/2026-07-05-plan-c-batched-decrypt-minispec.md` §measurement.

## OPEN CANDIDATES (ranked by expected wall win)

### 1. Persist lane cheapening — THE biggest named target (device tier)
- **Evidence (A18, 297k-block restore):** `persist_wait 7.6–9.4 s` of wall; inside the lane
  per pass: **checkpoint-window machinery ≈ 16 s** (59,206 downgraded retentions logged —
  the `downgraded=` counter in `sparse put_blocks`) + **row inserts ≈ 15.8 s** (`rows_ms`
  sums). Mac lane outruns scan (persist_wait 5.3 s, not binding).
- **What was already refuted:** `persist_depth > 1` (deeper write-behind) — Mac A/B depth-3
  = no change (4.1 vs 4.0 s persist_wait); the A18 submit tail needs the LANE CHEAPER, not
  deeper. Do not re-try depth. (Also the entire concurrency class — see graveyard.)
- **Attack shapes (unexplored):** (a) checkpoint-retention policy — why 59k downgrades per
  restore? Can retention be computed lazily / batched / skipped during recovery and rebuilt
  once at the end? (b) row-insert batching — multi-row INSERT statements / prepared-statement
  reuse / transaction shape in `persist.rs` `put_blocks` path; (c) profile `sparse tree split`
  sub-timers (`downgrade_ms/build_ms/frontier_ms/insert_ms/ensure_ms` — already logged
  per-chunk) on device to split the 16 s precisely.
- **Entry point:** `slipstream/core/src/persist.rs` (the put_blocks + checkpoint path);
  instruments already in the logs.

### 2. Scan-lane serial residue — never instrumented at stage level
- **Evidence:** post-pacer lane splits show a large *unattributed* residue: Mac
  `residue 4.0 s` (vs scan_call 10.8!), A18 `7.4 s`, A14 `11.9 s`, A10 `20.6 s`. This is the
  per-chunk serial path around the upstream scan call: decode → tree feed → stash → state
  chaining. On the Mac it is now ~40% the size of scan_call itself.
- **Next instrument (designed, never built — superseded by the pacer discovery):** per-chunk
  stage timers `decode_ms / tree_ms / stash_ms / chain_ms` in the scan lane (the
  census/firestats pattern, 4th outing) + bench JSON aggregate. ONE device run then names
  the target.
- **Entry point:** `slipstream/core/src/scan.rs` chunk loop; pattern reference:
  `AuditEntry`/lane-split wiring from the pacer work.

### 3. DH is still the A-series pacer — shared endo tables next (~6%/call)
- **Evidence:** A18 post-endo `scan_call 30.8 s`, `dh_s 134.5` core-s ⇒ ~4.4 avg DH
  concurrency — the A-series scan remains DH-saturated; further DH cuts transfer to wall
  there (and ONLY there — Mac has slack, see graveyard rule).
- **Next cut:** the wNAF+φ table is built per `mul_endo` call (per epk×ivk). Both scope ivks
  (external+internal) agree against the SAME epk back-to-back ⇒ build the table once per epk,
  use twice. Measured table-build share ≈ 6% of call cost. Shape: cache keyed on epk bytes at
  the `batch_ka_agree_dec` level (the fork already sees all ivks per batch call).
- **Beyond that:** window-5 halves (table 8→16 entries — build cost vs walk savings needs the
  shared-table win first); NOT lockstep batching (see graveyard).
- **Entry point:** `slipstream/vendor/orchard/src/endo.rs` (`mul_endo` table build) +
  `note_encryption.rs` batch override.

### 4. Fetch wall on old hardware (the A10's next ceiling)
- **Evidence:** A10 `fetch_s 164.9` vs scan 272.9 (was 216/354 in v0.4) — one more scan-side
  win and the NETWORK binds on old devices. Mac fetch 9.6 s of 20.2 total is also creeping
  toward relevance.
- **Unexplored:** stream-count tuning per device/bandwidth (fixed 4 today), gRPC compression
  (does lightwalletd support it?), CompactBlock wire-size reduction (server-side ask),
  overlap-fetch-across-ranges (fetch range N+1 while scanning N — the scheduler currently
  serializes ranges).
- **Entry point:** `slipstream/core/src/fetch.rs`, `scheduler.rs` range loop;
  `fetch begin/done` logs already carry streams/bytes/elapsed.

### 5. Interleave/drain cost on slow devices
- **Evidence:** A10 `interleave_drain 15.5 s` + final_drain 1.6 s even WITH the notes-found
  gate (his wallet has notes, so gated drains legitimately fire — but each drain is a FULL
  persist-queue flush). A18: 1.9 s (fine). Mac: 1.3 s (fine).
- **Idea:** device-scaled `enhance_every_chunks` (3 today, could be 6–8 on slow devices), or
  decouple: interleaved enhancement without the full drain (enhance what's already committed;
  don't flush the queue for it).
- **Entry point:** `slipstream/core/src/scan.rs` `notes_since_enhance` gate +
  `config.rs::DEFAULT_ENHANCE_EVERY_CHUNKS`.

### 6. Zodl-side: endpoint race costs every fresh restore a pass restart
- **Evidence:** BOTH A18 and A10 fresh restores 2026-07-06: `switchTo during active sync`
  (eu.zec.rocks → zec.rocks) at ~2 s in; engine drains + restarts cleanly (≈1–2 s + restart
  overhead of free wall each time).
- **Status: IN FLIGHT in its own session** (task_a94a9c58, spawned 2026-07-06): settle server
  selection before first sync start. Zodl repo, not engine.

## HORIZON (not perf, but shapes v0.6 planning)

- **Ironwood pool (~mid-July 2026 — i.e. NOW):** new Orchard-shaped pool. Touches scanning,
  census/graft (pool-specific machinery), trial decrypt (a third ivk scope?). Analysis:
  `docs/slipstream/2026-06-19-upstream-dedup-and-ironwood.md`. Any v0.6 that ignores this
  may be rebased by it.
- **Upstream seam PRs** (endo.rs → zcash/orchard; `batch_ka_agree_dec` seam →
  librustzcash) — part of the SDK-PR track but also perf-relevant: once upstream, every
  wallet gets the −24% DH and the vendor forks die. See
  `2026-07-03-upstreaming-analysis.md` + its v0.5 addendum.
- **shardtree PR #181** (SparseCachingShardStore, with Danny) — independent; slipstream does
  not depend on it.

## GRAVEYARD (measured dead — do not re-propose without NEW evidence)

| Idea | Verdict | Evidence |
|---|---|---|
| **Lockstep batched-DH kernel (Plan C / C1)** | DEAD in production | 1.4× (M4) – ~2× (A18) SLOWER per lane under real concurrency despite 1.56× microbench; allocation-heavy + serial inversion chains lose to the allocation-free wNAF walk on shared threads. Kernel + fire-stats stay in-tree as instrument (`batch_decrypt` OFF permanently). Mini-spec §6 ❌❌. |
| **Any per-mult speedup transferring to Mac wall** | ZERO transfer where slack exists | The decisive same-state A18 pair: +140 core-s of DH moved the wall 0.0 s. DH runs in scan-lane slack on M4 (and pre-pacer A18). **Rule: remove slack first (pacer), then compute levers measure.** Endo passed ONLY because post-pacer A-series is compute-saturated. |
| **Local treestate derivation (naive absorb)** | Costs more than it saves | 99.7 s/pass of per-leaf Pedersen/Sinsemilla — exactly the work the graft skips. Fully built + KAT'd + server-audited, parked behind `local_treestate` OFF. **Revival path: batch-affine BULK absorb** (the batch_combine trick applied to frontier absorption) — worth it only for Tor/offline value (kills the per-boundary RPC entirely), not for speed. `core/src/treestate.rs`. |
| **persist_depth > 1 (deeper write-behind)** | No change | Mac depth-3 A/B: persist_wait 4.1 vs 4.0 s. The lane must get CHEAPER not deeper. `--persist-depth` stays a bench flag. |
| **GPU subtree offload** | Regresses modern devices | M4 −25%, A10 pathological, iPhone ~1.1× narrow. `gpu_subtree` OFF; the runtime-calibration-probe gating idea was never built and only matters if this revives. |
| **Concurrency levers in general (GPU, pipelining)** | Wrong class | Modern devices are compute-bound (`wall ≈ total_cpu_work / cores`); concurrency conserves work + adds contention. **Only WORK REDUCTION (or hiding non-CPU waits) lowers the floor.** `2026-06-15-perf-spikes-learnings.md`. |
| **Prefetch self-DDoS worry (65 concurrent GetTreeState)** | Non-issue | Audits are off-path; ≤ queued+1 boundary fetches in flight by design. |

## Measurement rules (hard-won, follow every time)

1. `ENGINE_BUILD` tag in the boot log = the ONLY per-slice freshness truth (preserved slices
   are stale by design — the rebuild script warns).
2. No cargo builds during benches; prebuilt absolute-path binary (`target/release/slipstream`
   — the `[[bin]]` name is `slipstream`, not slipstream-cli); interleave A/B runs; never
   `2>/dev/null` a bench (it ate a UFVK-extraction failure once).
3. "Network weather" is real and now visible: watch `prefetch_wait` + treestate-audit
   timings; fetch_s alone never showed it.
4. Device runs: cool + charging phone; same-day pairs; the UD flag cache can beat compiled
   defaults in Zodl (boot log `[#1755] ENGINE=` disambiguates).
5. Wallet keys: Lukas's UFVK never appears in chat/scripts; the in-repo `TEST_UFVK` constant
   is the bench identity (extract with the awk/concat-aware snippet in the pacer plan).

## The beer ledger (v0.5 leg)

Same-conditions shares: pacer +26% (A18 62.2→49.3) vs endo +15.4% (48.8→42.3). Flavor call
(skip-the-work vs compute-trick) is genuinely arguable — prefetch is latency-hiding, the
interleave gate IS work-skipping, endo IS a compute trick. Adjudicate over the physical beer.
Optional A14/A10 OFF pairs would decompose their shares (decision-irrelevant since defaults
flipped). Full history: memory `v04-beer-bet.md`.
