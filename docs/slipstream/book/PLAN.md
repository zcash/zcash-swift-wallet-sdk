# Slipstream Book — Documentation Plan

> Audit-grade HTML documentation for the Slipstream sync engine. Tracking #1755. LOCAL-ONLY until the user lifts it.

## Purpose & audiences

1. **Reviewers / auditors** — people deciding whether Slipstream is safe to ship: correctness evidence, security/privacy analysis, exploitability review, honest gap list.
2. **Integrators** — wallet teams (Android SDK team, third parties) wanting to know how it works, what is generic vs. Zodl/iOS-specific, and what integration requires.
3. **Future maintainers** — the deep "why" behind each design decision, with pointers into code and the STATE.md decision log.

## Form

- Self-contained static HTML under `docs/slipstream/book/` — one chapter per file, shared `style.css`, no JavaScript, no build toolchain (nothing installed on this machine; zero-dep renders everywhere and prints cleanly for review).
- Every technical claim must be **grounded**: cite code (`module.rs:line` as of the stated commit) or STATE.md records. Performance numbers come from the truth table only.
- **Honesty register**: gaps are documented as gaps, NO-GOs as NO-GOs. Every chapter that makes guarantees ends with a "Known limitations" section. No marketing language.
- Baseline commit for citations: noted in each chapter footer.

## Table of contents

### Part I — Overview (wave 1)
1. **Introduction & Motivation** — the 10× problem; what Slipstream is and is not; headline results (64min → 8:30 on iPad A10, Zingo beaten on both devices, Zkool beaten on iPad); project history in brief; relationship to the old SDK (additive, behind a flag, same public interface).
2. **Architecture Overview** — "upstream brain, Slipstream body" (D2); module map (grpc/chunk/fetch/verify/block_source/wallet_session/scan/scheduler/enhance/transparent/events/persist/oracle/engine/ffi_handle); end-to-end data flow (fetch∥scan pipeline, byte-budgeted queue); concurrency model (tokio + rayon, actor-free atomics for progress); the FFI boundary and poll-based design (D8).
3. **The Data-Model Contract** — D3: byte-identical `zcash_client_sqlite` data.db; why (wallet remains openable by the old SDK; upstream brain keeps reading/writing it; spend path untouched); what enforces it (the golden oracle, chapter 13); migration story = none needed.
4. **Integration Guide** — the `Synchronizer` seam and `SlipstreamSynchronizer`; the C FFI surface (`zcashlc_slipstream_*`: open/start/stop/snapshot/drain_events/free) and its poll contract; what is engine-generic vs. iOS-specific vs. Zodl-specific; what an Android (or other) integration needs; configuration surface (EngineConfig fields incl. `sparse_persistence`, `chunk_split_bytes`, `enhance_every_chunks`); ENGINE_BUILD freshness tag discipline.

### Part II — Engine internals (wave 2)
5. **Fetch Pipeline** — claim-based parallel workers (K=4), ordered reorder buffer, byte-budgeted chunk queue + backpressure, AheadGate memory bounding, per-message idle deadlines, whole-sub-chunk deadline-reset, resume-from-height retries.
6. **Scan Pipeline** — one-chunk-per-`scan_cached_blocks` (memory rule), treestate prefetch overlap (+retry), sub-batching (opt-in), per-K-chunk enhancement interleave, continuity error mapping.
7. **Sparse Persistence** — the WalletWrite facade; in-memory ShardTree over SparseShardStore; checkpoint-downgrade (T6.3b) and why final state matches upstream's post-prune state; per-pool parallel tree work and its measured limits (90/10 Sinsemilla/Pedersen lopsidedness); flush atomicity.
8. **Scheduler & Spend-before-Sync** — `suggest_scan_ranges` as the single source of truth; ChainTip-first semantics; progress counters (ratio vs. monotonic-delta split, `begin_pass`); spendable latch; per-range enhancement; pass-level structure.
9. **Enhancement & Transparent** — TransactionDataRequests loop, dedupe, non-fatal interleaves, final backstop run; UTXO refresh ordering; the open-ended `TransactionsInvolvingAddress` skip (documented gap).

### Part III — Hard problems (wave 1)
10. **Reorg Handling** — three detection layers (transport continuity, wallet-level prev-hash/tree-size continuity, tip-priority verify ranges); structured `ScanContinuity{at}`; truncate-to-height semantics and why checkpoints make rewind a rollback, not a recalculation; jittered backoff for load-balanced-cluster tip desync; MAX_CONSECUTIVE_REORGS cap; darkside evidence (incl. sparse-mode variant + truncate-rescan oracle).
11. **The Sandblasting Era** — what the 2022 spam attack did to chain density (measured: 2.5M outputs per 10k blocks); why fixed block-count chunking fails (timeout loops, memory); byte-budgeted splitting design (density-adaptive, no hardcoded heights); deadline-reset; resume-from-height (double-scan impossibility argument); acceptance evidence (84,964 blocks / 43.2M outputs / 8.9k blk/min through the failure region); device memory caveat (A10).
12. **Failure Model & Resilience** — error taxonomy + `is_transient`; the three retry layers (stream message → treestate unary → whole pass); panic containment (supervisor + hook; why silent task death is impossible); deadlines everywhere; stall watchdog (Swift); the single-shot runner and its consequences; field validation stories (the 3.7% freeze → diagnosed → hardened → survived 3 simultaneous stalls).

### Part IV — Trust (wave 1)
13. **Correctness & the Golden Oracle** — the differ (canonical row multisets, schema union, views excluded); mutation tests (the oracle cannot lie); determinism baseline and the single-column allowlist (+ its protocol); the three oracle levels (hermetic synthetic / darkside real-notes / mainnet 50k); spendability gate; reorg gates; what "VERDICT IDENTICAL" does and does not prove.
14. **Security Analysis** — threat model (malicious/compromised lightwalletd, network attacker, malicious chain data); what the engine validates vs. trusts (server treestates are trusted-then-verified-by-scan; continuity checks; MisbehavingServer class); memory safety posture (Rust; `unsafe` confined to the FFI boundary); panic policy; dependency surface (upstream zcash crates, pinned versions); what an auditor should look at first.
15. **Privacy Analysis** — exactly what the server learns (connection IP; birthday/scan ranges via GetBlockRange; GetTreeState heights; transparent addresses via enhancement queries; txids via GetTransaction; timing/footprint of 4 streams) and what it never learns (keys — UFVK is imported locally and never transmitted; balances; which outputs decrypted); comparison to the old SDK (same lightwalletd protocol surface = same inherent leakage class); **Tor status: NOT wired into Slipstream paths (honest gap — old SDK has Tor for some flows; Slipstream fetch/scan/enhance is direct TLS)**; data at rest (data.db protection is app-level); no telemetry of any kind.
16. **Exploitability Review** — attack surfaces walked: oversized/malformed blocks (byte budgets, split caps, upstream parser); spam floods (sandblasting handling = DoS resistance); reorg ping-pong (cap + backoff); stalled-stream resource exhaustion (deadlines + AheadGate); DB corruption via crash (single-transaction-per-chunk atomicity; crash-consistency argument); retry amplification (bounded everywhere); what we explicitly do NOT defend against.

### Part V — Evidence & process (wave 2)
17. **Performance Evidence** — the truth table, methodology (measurement discipline: machine/server/range/wall/bound), device matrix history, stage-split instrumentation, per-chunk/per-pool attribution; how to reproduce (CLI subcommands).
18. **Test & Verification Matrix** — every suite (core unit, CLI, stress, hermetic oracles, darkside serial ×10, OfflineTests ×475), what each gates, exact commands, the always-green discipline.
19. **Known Gaps & Roadmap** — the complete honest list: mempool detection missing; no in-foreground tip-following (single-shot runner); A10 spam-era memory tuning; Tor not wired; open-ended transparent enhancement skip; L2 row batching seam-blocked; L4a decrypt kernel parked; L4b write-behind pipelining queued; shardtree `merge_checked` waste (fork-tier); darkside ≥v0.5 retirement items; flag/productization decisions.
20. **Glossary & Decision Digest** — terms (chunk/sub-chunk/plan index, range, pass, treestate, frontier, checkpoint, SbS…); D1–D9 locked decisions + the major in-flight ones, each with a one-paragraph rationale and STATE.md pointer.

## Visual & readability standard (user requirement: "enjoyable to read = learn", not 50 A4 plain-text pages)

**Diagrams: inline SVG, shared visual language.** No toolchain exists on this machine (no mdbook/pandoc/mermaid), and audit docs should be self-contained — so diagrams are hand-authored inline `<svg>` using the shared conventions below. They render from `file://`, print cleanly, and diff as text. (Fallback option recorded: vendor a pinned `mermaid.min.js` into the book if SVG authoring ever becomes the bottleneck — supply-chain note + hash required.)

Diagram language (defined in `style.css` + reference example in `index.html`):
- Palette: ink `#1a2333`, paper `#ffffff`, accent `#1f6feb` (flow/data), warm `#b54708` (warnings/failure paths), green `#1a7f37` (verified/evidence), muted `#6e7781` (annotations). Rounded boxes (`rx=8`), 1.5px strokes, `marker-end` arrowheads from the shared `<defs>` snippet.
- Kinds: pipeline/block diagrams (architecture, fetch∥scan), swimlane sequences (reorg recovery, retry ladders), state walks (sync pass lifecycle), annotated bar/timeline figures (sandblasting density, performance history).
- Every figure: `<figure class="diagram">` + `<figcaption>` with a number ("Figure 11.2 — …") so chapters can cross-reference.

Readability rules (every chapter):
- Opens with a `1-minute summary` callout box (what you'll learn, why it matters) + estimated reading time.
- A figure or table at least every ~2 screens of text; prefer showing over telling.
- Callout boxes: `.note` (context), `.warning` (gaps/limits), `.evidence` (measured numbers with truth-table provenance) — visually distinct.
- Narrative openings where the history is the best teacher (e.g., ch. 11 opens with the actual 2,536,689-outputs log line from the field failure; ch. 12 with the 3.7% freeze).
- Short sections, descriptive headings, code excerpts only where they earn their place (≤15 lines, cited).
- Chapter footer: baseline commit for citations + prev/next navigation.

## Maintenance rules (user-mandated, 2026-06-12)

1. **Doc-sync rule**: every engine change that alters documented behavior (a fix, a removal, a new gap, a closed gap) updates the affected chapter(s) in the same working session — the book must never describe a previous version of the engine. Chapter footers carry the citation baseline commit; bump it when a chapter is touched.
2. **Failure-first house style**: chapters teach through the real failure → diagnosis → fix arc (the sandblasting chapter is the reference: not "do we support it" but "we failed and rose"). Keep this direction for all future chapters and revisions.
3. **Honest-gaps completeness**: ch.19 is canonical; before any external sharing, sweep Blockers/STATE for unlisted gaps (user expects more to surface — add them as hit).

## Waves

- **Wave 1 (now, parallel)**: chapters 1–4 (Agent A), 10–12 (Agent B), 13–16 (Agent C) + index + style — the audit/review core the user named.
- **Wave 2 (next)**: chapters 5–9, 17–20.

## Status

- [x] Plan written
- [x] Scaffold (style.css, index.html)
- [x] Wave 1: ch 1–4 (2026-06-12; 5 figures, citations verified at ad755e08)
- [x] Wave 1: ch 10–12 (2026-06-12; 5 figures)
- [x] Wave 1: ch 13–16 (2026-06-12; 5 figures + 15 tables; declined-claims lists kept in session records)
- [x] Wave 2: ch 5–9 (2026-06-12; 7 figures; citations at 7eff661e)
- [x] Wave 2: ch 17–20 (2026-06-12; gate pyramid + stage-split anatomy figures; 15-item gap status table; 26-term glossary + D1–D9 digest)
- [x] Final cross-read pass 1 (nav chain complete 01→20→index, seam links fixed, TOC fully lit; deeper terminology/consistency read remains a standing item before any external review)
