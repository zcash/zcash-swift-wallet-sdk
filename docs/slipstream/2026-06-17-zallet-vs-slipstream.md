# Zallet vs Slipstream — Sync Engine Comparison

> **Date:** 2026-06-17
> **Method:** 8 sync phases compared head-to-head; each phase read against *both* codebases, every per-phase verdict adversarially re-checked by an independent skeptic, then synthesized. 17 agents, ~1.5M tokens.
> **Scope caveat (load-bearing):** This comparison is **architectural** — it reasons from data model, parallelism, topology, and slipstream's own internal A/B logs. **Neither engine was benchmarked head-to-head on one device.** Treat magnitudes as directional, not measured.
> **Sources:** zallet = `github.com/zcash/wallet` (shallow clone 2026-06-17; pins librustzcash via git-rev `32fa8e25`, versions zcash_client_backend 0.23.0 / zcash_client_sqlite 0.21.0 / shardtree 0.6.2). slipstream = this repo (`slipstream/` + `rust/src/lib.rs`).
> **Verdict in one line:** Conclusion #3 — keep slipstream (correct engine for mobile), merge in zallet's persistent decrypt-ahead engine (≥6-core, gated on one experiment) + inline reorg pattern.

---

> ## ⚠️ Editor's verification (added 2026-06-17, post-synthesis)
> Two claims in the synthesis below were checked against the actual code/docs after the run and **corrected** — neither flips a verdict:
> 1. **"Fix the internal docs that mis-credit the persistence win to shard I/O" (§3 KEEP, §5) — WITHDRAWN.** The slipstream *conclusion* docs already attribute it correctly: STATE.md T6.3 says the bottleneck is *"the CPU cost of insert_tree/prune_excess_checkpoints … **not the SQLite I/O**,"* T6.3b credits the 5.05×/5.27× to checkpoint-churn (CPU), and book ch.7 says *"the bottleneck was not I/O — it was CPU."* The only I/O framing survives in the *pre-measurement Phase-6 plan* (a hypothesis T6.3 then falsified — correct as history). The mis-attribution was in the workflow's own first-pass reasoning; **no slipstream doc needs editing.**
> 2. **The persistence win is the T6.3b *checkpoint-downgrade* (CPU), not the in-memory store itself.** T6.3 measured the sparse *storage* change alone at **0.96× (4% slower)**; the 5.27× comes entirely from the checkpoint-downgrade, which merely *rides on* the `sparse_persistence` path. Read "in-memory sparse shard store" below as "the vehicle that carries the checkpoint-downgrade," not "the storage is the win."
>
> **Confirmed shipped (default-on):** `config.rs:118-119` → `sparse_persistence: true`, `write_behind: true` (depth-1). So the persistence/tree credits *are* accurate for the shipped engine. `gpu_subtree` + `persist_depth>1` remain parked/off.

# Verdict: Two Sync Engines for a Memory-Constrained Mobile Wallet — zallet vs slipstream

## 1. VERDICT

**Keep slipstream, but MERGE in two low-risk wins from zallet. Confidence: HIGH (architectural, not benchmarked head-to-head on-device).**

slipstream is the correct engine for this target and zallet is a non-starter as a drop-in replacement — not because zallet's code is worse, but because zallet is a **full-node desktop daemon** that is structurally disqualified on mobile:

- **It does not talk to lightwalletd at all.** Its data source is a Zcash *validator* (Zebra/zcashd) at `127.0.0.1:8232` fronted by an **in-process Zaino indexer** (chain.rs:104, 160-164). A phone has neither a local full node nor the indexer DB, and pointing it at a *remote* full node is a privacy/availability regression. This alone makes "use zallet instead" impossible.
- **It streams FULL blocks and trial-decrypts the full ~580 B ciphertext per output** (Block::read, chain.rs:470; FullDecryptor), vs slipstream's ~52 B compact path. On a bandwidth- and memory-constrained phone this is the dominant penalty: ~10× more bytes downloaded and fed through memory per output, on the very dimension (download) that the design doc's own floor numbers show dominates mobile wall-clock.
- **It has no wallet-level memory backpressure** (unbounded Zaino block stream, chain.rs:455-478) and embeds rocksdb + lmdb + zebra-state in-process — a desktop footprint that risks jetsam on a 2 GiB phone.
- **Any error in its tip loop tears down the whole process** (start.rs:131-132), delegating recovery to an external supervisor (systemd) that does not exist on iOS.

But the verdict is **MERGE, not "slipstream wins, ignore zallet"**, because zallet holds two genuinely better pieces that are *storage-model-independent* and portable: (a) a **persistent, decoupled batch-decryptor** that decrypts *ahead* across range boundaries (which slipstream lacks — it builds and drops a fresh BatchRunner per `scan_cached_blocks` call), and (b) **inline, proactive reorg/fork-point handling**. The decrypt phase is one of the two wall-clock-dominating phases, so even a modest decryptor-orchestration improvement is worth more than most other changes.

**Why not "slipstream wins outright":** be honest — slipstream's actual trial-decryption *kernel* is the **identical upstream `BatchRunner` on the same global rayon pool** as zallet. slipstream's design-doc NEON/GPU/column-oriented decrypt kernel is **aspirational and parked** ("the scan kernel is untouched", persist.rs:3). So on a ≥6-core phone, where decrypt does *not* saturate all cores, zallet's persistent cross-task decryptor could use idle cores that slipstream's per-call runner leaves on the floor. That is the one real weakness, and it is exactly what the merge plan targets.

---

## 2. Per-phase scorecard (adversarially-corrected verdicts)

| Phase | Winner | Why (one line) | Confidence |
|---|---|---|---|
| **Data source & block fetch** | **slipstream** | Compact blocks + 4-worker parallel gRPC + two-stage byte-budget that derates to 64 MiB on <3 GiB devices; zallet needs a co-located full node + indexer (disqualifying on mobile). | High |
| **Trial-decryption** | **tie / complementary** (payload edge: slipstream) | Identical upstream `BatchRunner` on the same rayon pool; slipstream wins on 52 B vs 580 B payload (download+RAM), zallet wins on persistent decrypt-*ahead* orchestration (esp. ≥6-core). | Medium |
| **Commitment-tree build (in put_blocks)** | **slipstream** | Same combine count, but T6.3b checkpoint-downgrade eliminates ~99% of create/destroy checkpoint churn (the real CPU lever) + parallel sapling∥orchard; zallet runs vanilla upstream. | Medium |
| **Persistence / DB commit** | **slipstream** | Two wins: durable in-memory sparse shard store (avoids per-shard SQLite I/O) + write-behind lane overlapping commit with next chunk's decrypt; zallet commits inline, serially. | High (win B); bounded (win A) |
| **Concurrency / pipeline topology** | **slipstream** | Stage-pipelined (fetch∥scan∥persist) with a memory-bounded fetch; zallet's region-task parallelism converges on one rayon pool (work-conserving but contention-adding — a lever slipstream measured and *falsified* at depth>1). | High |
| **Scan ordering & reorg handling** | **tie / complementary** | Byte-identical spend-before-sync ordering + same checkpoint-snap rewind floor. zallet rewinds to the exact fork point (needs Zaino); slipstream is reactive + adds ping-pong cap & backoff. | High |
| **Tip-following & mempool (0-conf)** | **slipstream** | Same stream-close detection edge + identical write path, but slipstream adds txid dedupe, bounded seen-set, and T8.7 resilience (never hard-errors on a blip); zallet's blip kills the daemon. | High |
| **Enhancement / transparent history** | **tie / complementary** (per-phase edge: slipstream) | slipstream fetches txids concurrently (FuturesUnordered/HTTP-2) vs zallet's serial loop, but they solve different problems — zallet folds transparent detection into full-block scan (a luxury compact-block mobile can't have). | High |

**Net:** slipstream wins or ties every phase *for the mobile target*. It does not lose a single phase outright. The two "complementary" decrypt/reorg cells are where zallet has portable ideas worth stealing.

---

## 3. MERGE plan — what to adopt, keep, ignore (ranked by speed-payoff-per-effort)

### ADOPT from zallet

**① Persistent, decoupled decrypt-ahead engine — HIGHEST payoff-per-effort on ≥6-core phones.**
- *What:* Replace the per-`scan_cached_blocks` construct-and-drop `BatchRunners` with one long-lived runner fed by a `queue_block`-style API (zallet's `decryptor::Engine`, threshold ~100-200, bounded queue ~1000), so trial-decryption of chunk N+1 runs *ahead* of chunk N's linear scan/commit across chunk boundaries — instead of restarting the runner (and discarding the warm crossbeam channel + partial batch) every call.
- *Payoff:* On 6-core iPhones (slipstream's own policy doc says these are "healthy shared," NOT decrypt-saturated), this fills the idle cores slipstream currently leaves between calls. Decrypt is one of the two wall-clock-dominating phases, so this is the single change most likely to move the needle. Also decouples the batch threshold from upstream's hard-coded 100 toward the design doc's ~2-4k L2-tuned target.
- *Risk/effort:* **Medium-high.** It must compose with the write-behind lane and the sparse tree — i.e. the decrypt-ahead engine produces `ScannedBlock`s that feed `sparse_put_blocks` → `PersistLane`. The hard question (see §5) is whether decrypt-ahead + write-behind together over-subscribe the same rayon pool and regress like depth>1 did. On ≤4-core (A10) devices decrypt already saturates cores, so gate this to ≥6 cores via the existing `lane_pool_policy` core-count detection. **Validate before shipping.**

**② Inline, proactive reorg handling in the follow loop — medium payoff, low-medium effort.**
- *What:* In the T8.1 follow loop, when the tip changes, handle a reorg *surgically* (truncate to the fork + re-scan just the tip region) instead of deferring it to the next full pass's upstream scan. zallet's `find_fork_point → truncate_to_height(fork) → re-scan` (sync.rs:277-328) is the clean reference shape.
- *Payoff:* Saves a redundant fetch+scan pass per tip-region reorg on cellular (bandwidth + battery). Small in absolute terms (reorgs are a few blocks) but a clean correctness/efficiency win for the steady-state phase.
- *Risk/effort:* **Low-medium.** Caveat: the *exact* fork point requires a fork-point RPC that **stock lightwalletd does not expose** — so the precise version is gated on a richer indexer. The portable version is the reactive `scan_cached_blocks` continuity-error path slipstream already has; the adoptable piece is doing it *inline in the follow loop* rather than via a full pass.

**③ Tip-change `Notify` to promptly wake enhancement — low payoff, low effort.**
- *What:* Borrow zallet's `tip_change` `Notify` pattern to wake the enhancement/data-requests work reactively on tip advance, rather than folding it into a fixed 3-round drain each pass.
- *Payoff:* Marginally fresher 0-conf / first-paint latency in steady state. Cosmetic for wall-clock.
- *Risk/effort:* **Low.**

### ADOPT *into zallet / upstream* (reverse direction — slipstream's pure wins worth upstreaming)

These are flagged because the core team owns both contexts: slipstream's **T6.3b checkpoint-downgrade** and **in-memory sparse shard store + once-per-chunk dirty flush** are byte-identical, golden-oracle-gated, storage-model-independent CPU/I-O wins that upstream librustzcash (and therefore zallet) should take. Pure win, no concurrency added. Not work *for* slipstream, but the highest-leverage thing to contribute back.

### KEEP in slipstream (do not regress)

- **Compact-block fetch + 4-worker fan-out + two-stage byte budget with <3 GiB derate.** This is the mobile-defining advantage. Non-negotiable.
- **In-memory sparse shard store + T6.3b checkpoint-downgrade + sapling∥orchard `rayon::join`.** The *durable* (CPU + I/O) persistence win, independent of write-behind. Verified ~7.49 s vs 39.47 s scan on the internal sparse-ON/OFF A/B (the dominant lever is the checkpoint-downgrade CPU reduction, *not* shard-serialization I/O — fix the internal docs that mis-credit this).
- **Write-behind lane at depth-1.** Keep depth-1 as default — deeper pipelining was *measured to regress* the M4 1.26× (rayon-vs-rayon contention). The win is overlapping the *non-rayon* parts (SQLite I/O + await/recv gaps). Do not "improve" it by deepening.
- **T8.7 resilience contract.** Never surface a hard error on a transient follow-phase blip. This is the single most important mobile-correctness property and zallet has the *opposite* behavior.
- **Bounded enhancement: concurrent txid fetch + serial DB apply + txid dedupe + bounded seen-set + GetTaddressTxids transparent recovery.** Required because compact blocks strip transparent data.

### IGNORE from zallet (do not port)

- **Zaino + Zebra-RPC in-process indexer.** Disqualifying on a phone (rocksdb/lmdb/zebra-state footprint, requires a co-located validator). This is the #1 thing *not* to bring over.
- **Full-block fetch / FullDecryptor.** ~10× the bytes and AEAD work per output for the same detection result on a bandwidth-constrained link. Compact-first + enhance-only-the-hits is strictly better on mobile.
- **"Any error → exit the process" failure model.** Assumes a process supervisor that iOS does not provide.
- **Transparent-via-full-block-scan (ignoring `TransactionsInvolvingAddress`).** Elegant *only* with a colocated full-block source; impossible against stock lightwalletd.

---

## 4. The core team's question: "Why build slipstream instead of using zallet?"

**Honestly: because zallet is a desktop full-node wallet and we are shipping a memory-constrained mobile SDK over remote lightwalletd. They are different products, not two implementations of the same product.** Three technical reasons make zallet unusable as-is on a phone, none of which are about code quality:

1. **Data source.** zallet does not use lightwalletd — it fronts a Zcash *validator* over loopback with an embedded Zaino indexer (chain.rs:104, 160-164). A phone can't run a full node, and trusting a *remote* one breaks privacy/availability. slipstream talks directly to the public lightwalletd servers (zec.rocks) a phone already uses, zero server-side infra.
2. **Wire & memory model.** zallet streams full blocks and decrypts full ciphertext+memo for every output; it has no wallet-level memory budget and embeds rocksdb+lmdb. slipstream streams compact blocks (~10× less data/output) with hard, device-RAM-scaled byte budgets (64 MiB floor on <3 GiB devices). On mobile, download bytes dominate wall-clock — this is the decisive difference.
3. **Lifecycle & resilience.** zallet's tip loop crashes the whole process on any error and relies on systemd to restart it. slipstream stays `.synced` through transient blips and freezes cleanly on iOS suspend (T8.7) — mandatory for a foregrounded wallet.

On top of the *fit* argument, slipstream also has **two genuine engineering innovations zallet lacks**, both targeting the persistence/tree phase that co-dominates wall-clock: the **in-memory sparse shard store with the T6.3b checkpoint-downgrade** (eliminates ~99% of checkpoint create/destroy churn — a CPU win, oracle-proven byte-identical), and the **write-behind persist lane** (overlaps the DB commit with the next chunk's decrypt). zallet runs the vanilla upstream `put_blocks`/`SqliteShardStore` path and pays both costs on its critical path. These innovations, plus the engine/scan-shape rewrite, are what delivered the measured ~12× over the old SDK on an A14 (25:11 → 2:05).

**Where the core team is RIGHT — what zallet does better and slipstream should steal:**
- **zallet's decryptor is architecturally cleaner.** A persistent, decoupled batch-decryptor that decrypts *ahead* across range boundaries. slipstream builds and *drops* a fresh BatchRunner every `scan_cached_blocks` call, discarding the warm channel and partial batch — leaving idle cores on ≥6-core phones. This is a real latent advantage for zallet and slipstream's #1 thing to adopt (§3①).
- **zallet's reorg handling is more surgical** — exact fork point, inline truncate+re-scan, an explicit finalized/non-finalized boundary — vs slipstream's coarser "rewind 10 below the error height + defer to next pass."
- **Be candid about the kernel:** slipstream's decrypt *kernel* is the **same upstream code on the same rayon pool** as zallet. The advertised NEON/GPU/column-oriented kernel is aspirational and parked. slipstream's decrypt-phase advantage today is *payload* (compact vs full) and *surrounding overlap*, not a faster inner loop.

---

## 5. Biggest unknowns & cheapest next experiments

**This entire comparison is ARCHITECTURAL. Neither engine was benchmarked head-to-head on-device in this pass — read-only, no wall-clock numbers were produced.** The verdict rests on data-model + parallelism + topology reasoning plus slipstream's own internal logs. Validate in this order (cheapest, highest-leverage first):

1. **Does decrypt-ahead compose with write-behind without regressing? (gates merge item ①)** — On a 6-core iPhone and a 4-core A10, prototype the persistent decrypt-ahead engine feeding the existing write-behind lane and measure scan-active vs persist-wait. The depth>1 falsification (M4 1.26× slower from rayon-vs-rayon contention) is the explicit risk: decrypt-ahead may over-subscribe the same pool. **If this regresses on ≥6-core devices, merge item ① is dead and slipstream's per-call runner is already near-optimal.** Cheapest possible disconfirming test — run it first.
2. **Benchmark zallet's decryptor throughput vs slipstream's scan on identical hardware/wallet.** Even desktop-side: feed the same block range through zallet's persistent decryptor and slipstream's per-call BatchRunner, count outputs/sec. Confirms whether the persistent-queue orchestration actually buys throughput once payload is held constant (same compact vs full caveat must be controlled).
3. **Measure Zaino's real in-process memory footprint.** Zaino internals were *not* in the clone (git rev at zingolabs/zaino) — the "non-mobile" claim is inferred from the dependency graph (zebra-state/rocksdb/lmdb/dashmap), not measured. A single RSS measurement of zallet at sync confirms (or refutes) the jetsam-risk disqualifier. Likely confirms, but it's the one unmeasured load-bearing claim in the "disqualifying" argument.
4. **Confirm the compact-vs-full byte ratio empirically.** The ~10× download/RAM advantage is asserted qualitatively (compact omits full tx data, 52 B vs 580 B per output). Measure actual bytes/block for a spam-era range to put a real number on the dominant mobile wall-clock lever.
5. **Validate the WriteBehindFacade read-surface against drift.** slipstream's second-connection safety depends on virtualizing *exactly* the 4 reads `scan_cached_blocks` makes; a future zcash_client_backend bump could add a 5th read → silent stale read (guarded by `unvirtualized` loud-fail + golden/darkside oracles, but worth a dedicated drift test pinned to the 0.23.0 read surface).

Minor evidence-hygiene notes for the record (none flip any verdict): zallet pins librustzcash via a **git rev** (32fa8e25), not crates.io, so "identical Cargo.lock" claims are wrong on *source* though the version numbers (zcash_client_backend 0.23.0 / zcash_client_sqlite 0.21.0 / shardtree 0.6.2) match; several zallet-side line citations are a few lines off and omit the `zallet/` prefix; and the persistence win is checkpoint-downgrade **CPU** reduction, not shard-serialization **I/O** (the internal docs mis-credit this — fix them).

---

## 6. Bottom line (paste to the core team)

> We built slipstream instead of using zallet because they're different products: zallet is a desktop full-node wallet that runs an in-process Zaino indexer against a co-located Zebra/zcashd validator, streams full blocks, has no memory budget, and kills its own process on any network blip — none of which works on a memory-constrained phone talking to remote lightwalletd. slipstream is purpose-built for that target: compact blocks (~10× less data/output), 4-worker parallel fetch with hard device-RAM-scaled byte budgets, an in-memory sparse commitment tree with a checkpoint-downgrade that eliminates ~99% of checkpoint churn, a write-behind persist lane, and a resilience model that never hard-errors on a transient blip — and it's already shipped ~12× over the old SDK on an A14. slipstream wins or ties every phase *for mobile* and loses none outright. But zallet is genuinely better in two portable ways we should steal: (1) a persistent decrypt-*ahead* engine — slipstream rebuilds its decryptor every chunk and leaves idle cores on 6-core phones, whereas zallet decrypts ahead across boundaries — and (2) more surgical inline reorg handling. The honest caveat is that slipstream's decrypt *kernel* is the same upstream code on the same rayon pool as zallet (the NEON/GPU kernel is still aspirational), so our decrypt edge today is payload + overlap, not a faster inner loop. Recommendation: keep slipstream, and merge in zallet's decrypt-ahead engine (gated to ≥6-core devices) and inline-reorg pattern — after first running the one cheap experiment that could kill it: does decrypt-ahead compose with the write-behind lane without re-triggering the rayon contention that already falsified deeper pipelining? Everything here is architectural; we have not yet benchmarked the two engines head-to-head on one device.

---

## Appendix: Adversarial verification record (per phase)

Each per-phase verdict below was produced by one agent reading both engines, then re-checked by an independent adversarial reviewer instructed to *refute* it. `survives=true` means the verdict held; `corrected` records what the skeptic changed (none flipped a winner).

### Data source & block fetch (indexer/zaino vs direct lightwalletd gRPC): data model, fetch parallelism, memory footprint, random-access vs streaming, mobile viability
- **overall:** slipstream_better  |  **speed:** unclear  |  **survives scrutiny:** True
- **adversarial note:** unchanged — slipstream_better holds for the mobile/remote-lightwalletd scope of this review; speed_verdict=unclear is correctly hedged (zallet's loopback-to-full-node serial fetch is not directly comparable and may be faster on its own desktop topology). Recommend the parent record the explicit caveat that zallet is a full-node desktop wallet, so the comparison is scope-bound, not universal.

### Trial-decryption
- **overall:** complementary  |  **speed:** slipstream_faster  |  **survives scrutiny:** True
- **adversarial note:** unchanged — overall stays 'complementary' and speed stays 'slipstream_faster'. Two refinements to the REASONING (not the verdict): (1) 'decrypts memos for every output' should read 'runs the full-ciphertext AEAD for every output; materializes memos only for matches'; (2) the 'no spare cores on a phone' premise holds only for the 4-core A10 — slipstream's own code says 6-core iPhones are not decrypt-saturated, so zallet's persistent cross-task decryptor could exploit spare cores there, making orchestration a mild edge to zallet rather than a pure wash. The slipstream_faster lean correctly rests on compact-vs-full payload (download+memory), which the design doc's floor numbers show dominates mobile wall-clock.

### Commitment-tree build (inside put_blocks): zallet FULL shardtree-through-SQLite vs slipstream SPARSE in-memory shardtree
- **overall:** slipstream_better  |  **speed:** slipstream_faster  |  **survives scrutiny:** True
- **adversarial note:** Direction UNCHANGED (slipstream_better / slipstream_faster for the commitment-tree-build phase) — the mechanism is real and verified in zallet's actual compiled source. But two corrections: (1) confidence should be MEDIUM, not high — there is no zallet-vs-slipstream A/B; the claim rests on a mechanism argument plus slipstream-internal numbers, and the magnitude vs zallet's 1000-block batching is much smaller than the 5.27x slipstream-vs-slipstream figure (zallet's small batches already avoid the worst O(checkpoint_count) prune blowup). (2) The speed REASONING is partly mis-attributed: per slipstream's own T6.3 result (sparse storage alone = 0.96x, 4% SLOWER), the win is NOT from the in-memory tree avoiding SQLite shard (de)serialization (rows/shard I/O was only ~300ms/chunk and the seed preload cancels it) — it is entirely the T6.3b checkpoint downgrade, which is CPU work reduction inside prune_excess_checkpoints. Also note the prior agent cited the crates.io copy of zcash_client_backend/zcash_client_sqlite for zallet, but zallet compiles a git-rev whose wallet.rs is reorganized, so the zallet-side line numbers are inaccurate (algorithm identical, substance unaffected).

### Persistence / DB commit — synchronous put_blocks (zallet) vs write-behind deferred-commit lane (slipstream)
- **overall:** slipstream_better  |  **speed:** slipstream_faster  |  **survives scrutiny:** True
- **adversarial note:** unchanged — slipstream_better / slipstream_faster. Caveat: the evidence's "identical deps, no version caveat" claim is wrong (zallet=git-rev backend incl. a newer async decryptor module; slipstream=crates.io release). This is an evidence-quality defect, not a verdict flip: the persistence-phase wins (structural SqliteShardStore-avoidance via in-memory sparse tree + sap∥orch rayon join = durable; write-behind overlap = real but bounded, near-falsified beyond depth-1 by the repo's own data) hold regardless. Confidence stays high on win B and the bounded framing; slightly tempered only because zallet's exact put_blocks rev isn't auditable on disk.

### Concurrency / pipeline topology (zallet's 4 parallel region-tasks vs slipstream's pipelined single pass + follow loop)
- **overall:** slipstream_better  |  **speed:** slipstream_faster  |  **survives scrutiny:** True
- **adversarial note:** unchanged — but with one detail correction: zallet's enhancement/mempool path (decrypt_and_store_transaction) runs INLINE single-threaded, not on the global rayon pool as the evidence implied. The bulk-restore compute (the wall-clock driver) does go through the shared rayon pool for both region tasks, so the conclusion is unaffected; the correction makes zallet look marginally worse on mobile throughput, not better.

### Scan ordering and reorg handling
- **overall:** complementary  |  **speed:** similar  |  **survives scrutiny:** True
- **adversarial note:** unchanged

### Tip-following & mempool (0-conf): tip-change signalling, 0-conf incoming visibility, and transient-blip resilience
- **overall:** slipstream_better  |  **speed:** similar  |  **survives scrutiny:** True
- **adversarial note:** unchanged

### Enhancement / transparent history (data_requests servicing: GetStatus/Enhancement/TransactionsInvolvingAddress, decrypt_and_store_transaction, transparent-address completeness)
- **overall:** complementary  |  **speed:** slipstream_faster  |  **survives scrutiny:** True
- **adversarial note:** unchanged

