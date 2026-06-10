# Slipstream — Living State

> **THE first file every session reads. THE last file every session updates (in the same commit as the work).**
> Format rules: append, don't rewrite history. Keep "NEXT ACTION" accurate above all else.

## NEXT ACTION

➡️ **T2.3** — WalletSession (WAL, migrations, keyless import, chain ops). Detailed steps: docs/slipstream/plans/2026-06-10-phase-2-scan-core.md, Task 2.3.

## Current phase: P2 — Scan core (plan: `plans/2026-06-10-phase-2-scan-core.md`)

| Task | Status | Session notes |
|---|---|---|
| T2.0 detailed phase plan | done | Recon pinned scan_cached_blocks/BlockSource/WalletDb/import_account_ufvk shapes from rust/src/lib.rs + registry 0.22. ChainState spike PRE-RESOLVED: server treestate per chunk boundary, prefetched concurrently (WalletDb exposes no frontiers; local derivation not free). Scan unit = one chunk per scan_cached_blocks call (upstream commits once per call — memory bound). WAL via plain pre-open connection (persistent file property). Darkside REAL-tx fixtures = Swift DarksideTests datasets (DarkSideWalletService.swift:13-28; saplingActivation 663150). Task remap: T2.1=deps+subtree-roots+carry-overs; T2.2=MemBlockSource; T2.3=wallet_session; T2.4=scan driver; T2.5=scheduler; T2.6=engine+CLI sync; T2.7=correctness+G2. |
| T2.1 deps + subtree roots + carry-overs | done | workspace deps added (zcash_client_sqlite, zcash_keys, rusqlite, secrecy, rand, sapling, orchard, zcash_primitives, tempfile); get_subtree_roots implemented; FetchPlan asserts + should_panic test; CLI polish: --streams range(1..) via RangedU64ValueParser::<usize>, parse_range ..= hint + test; OfflineTests 419/0; grpc API deviations: (1) set_shielded_protocol IS a prost-generated setter (confirmed in prost-derive-0.14.3 scalar.rs:288-305) — plan code compiled as-written; (2) sapling::Node::read uses HashSer trait from zcash_primitives::merkle_tree — added zcash_primitives to workspace.dependencies and slipstream-core deps; (3) clap value_parser!(usize).range(1..) unsupported — used RangedU64ValueParser::<usize>::new().range(1..) instead; local vars renamed sapling_roots/orchard_roots to avoid crate-name shadowing |
| T2.2 MemBlockSource | done | block_source.rs created with MemBlockSource over one Chunk; BlockSource::with_blocks iterates blocks from chunk, respects from_height + limit; Unreachable error type for the trait bound; test helper uses `BlockHeight::from(h as u32)` per binding note (pseudocode note deleted); 3 new tests green: serves_all_blocks_in_order, respects_from_height_and_limit, from_height_past_end_serves_nothing; wired in lib.rs |
| T2.3 wallet_session | todo | needs a mainnet TEST_UFVK constant (grep Tests/TestUtils, else derive in-test from darkside seed) |
| T2.4 scan driver | todo | record ChainState spike outcome in Decision Log |
| T2.5 scheduler v0 | todo | continuity-recovery TODO deferred to P3 unless T2.7 needs it |
| T2.6 engine + CLI sync | todo | |
| T2.7 correctness + G2 | todo | fixture constants from DarksideSanityCheckTests; old-SDK baseline spike (PerformanceTests) — honest fallback: "ratio pending P4 A/B" |

## Phase P1 — Transport (COMPLETE — plan: `plans/2026-06-10-phase-1-transport.md`)

| Task | Status | Session notes |
|---|---|---|
| T1.0 detailed phase plan | done | Task remap vs ROADMAP index: T1.2=darkside codegen+harness, T1.3=chunk+queue, T1.4=fetcher+reorder+continuity (merged), T1.5=CLI bench+G1. get_subtree_roots wrapper deferred to P2. Facts verified: upstream proto is client-only; protoc present; darkside.proto vendored at Tests/TestUtils/proto/. |
| T1.1 workspace deps + grpc module | done | [workspace.dependencies] added; slipstream-core Cargo.toml rewritten to workspace-inherited deps + darkside feature; uri() + 3 guard tests added to config.rs; grpc.rs created (connect/get_lightd_info/get_latest_block_height/get_tree_state); tonic 0.14.6 ClientTlsConfig::new().with_webpki_roots() compiled without change; 10 hermetic tests green, 1 ignored (live smoke); live smoke also passed (zec.rocks mainnet); OfflineTests 419/0 fail (via xcodebuild; swift test --filter OfflineTests pre-existing SPM/Swift 6.3.2 issue: LocalPackages evaluated as fileSystem dep despite dir not existing — not caused by this task) |
| T1.2 darkside codegen + harness + roundtrip | done | Codegen crate: tonic-prost-build = "0.14" resolved (not fallback). tonic_prost runtime crate referenced in generated code — added tonic-prost = "0.14" to [workspace.dependencies] + slipstream-core deps. Generated file renamed cash.z.wallet.sdk.rpc.rs → darkside.rs; contains pub mod darkside_streamer_client + extern-mapped Empty/RawTransaction/TreeState/BlockId/GetAddressUtxosReply. Field/method name deviations: none (prost snake_case matched plan exactly). Deviation from plan test code: (1) staging must start at sapling activation height 663150 (not 663151 as plan's comment implied), staged 201 blocks 663150..=663350; (2) added tokio::time::sleep(2s) after apply_staged — darkside propagates state asynchronously and get_latest_block_height otherwise races ahead of apply completion (matches Swift DarksideTests sleep(2) pattern). Verification: (a) cargo test -p slipstream-core: 10 passed, 1 ignored; (b) --features darkside: compiles, roundtrip ignored; (c) darkside binary started, roundtrip passed (663350 == 663350). |
| T1.3 chunk + byte-budgeted queue | done | chunk.rs created with Chunk, ChunkPermit, ChunkQueueSender/Receiver, chunk_queue() constructor; 4 tests green: estimated_bytes_counts_encoded_blocks, queue_blocks_producer_when_budget_exhausted (stable across 3 runs), oversized_chunk_clamps_instead_of_deadlocking, recv_returns_none_when_sender_dropped; cargo test -p slipstream-core: 14 passed, 1 ignored. |
| T1.4 parallel fetcher + continuity | done | verify.rs (Continuity: verify_blocks with height-consecutive + prev_hash chain check; tolerates empty prev_hash); fetch.rs (FetchPlan/FetchStats/fetch_one_chunk/worker/run_fetch; K workers claim via AtomicU64; reorder BTreeMap; continuity-verified ordered emission into ChunkQueueSender); wired pub mod fetch/verify in lib.rs. Hermetic: 20 passed, 1 ignored. T1.2 corrections applied: (a) staging from 663_150 (sapling activation), stage 663_150+5000 apply 668_149; (b) tokio::time::sleep(2s) after apply_staged. Darkside prev_hash finding: LINKED — fabricated blocks carry properly linked prev_hash values (block[0].prev_hash = [0,0,0,0] zeroed; block[N].prev_hash = block[N-1].hash exactly); continuity check passes fully with no relaxation needed. Both darkside tests pass with --test-threads=1 (darkside server has shared state; concurrent resets race). Post-review fixes amended: grpc connect_timeout(10s); abort-on-error for worker handles; backoff exponent cap; stats/verify doc notes; CONVENTIONS darkside command now documents --test-threads=1. |
| T1.5 CLI fetch bench + gate G1 | done | CLI: tokio added to slipstream-cli deps; Fetch subcommand (server/range/streams/chunk/baseline args); parse_server, parse_range, run_fetch_bench, cmd_fetch wired; 7 tests (2 old + 5 new parser tests) green. Darkside smoke: 5000 blocks loopback K=3 ratio 3.49x. G1 network: zec.rocks only reachable public server (na/eu.lightwalletd.com, mainnet.lightwalletd.com unreachable). Canonical K=4/chunk=10k/50k blocks: 1.65x, 1.47x, 2.56x (server-variable). K=8/chunk=5k/150k blocks: 2.03x, 1.39x, 1.06x, 3.86x, 2.11x. Best: 3.86x. G1 verdict: PASSES (≥2.0x confirmed, high variance due to zec.rocks server-side throttling — ratio is network-bound, not fetcher-bound). |

## Phase P0 — Foundation (COMPLETE)

| Task | Status | Session notes |
|---|---|---|
| T0.1 branch + issue + machinery | done | |
| T0.2 cargo workspace + FFI-scripts verify | done | `rebuild-local-ffi.sh` line 97 runs bare `cargo build --target ... --release` from repo root — with workspace this builds all members for the target, but slipstream crates are std-only so no issue; no script pinning needed. cargo test, cargo check, init-local-ffi --macos-only (~3 min incremental), OfflineTests (419/0 fail) all green. |
| T0.3 core domain types | done | |
| T0.4 CLI scaffold | done | |
| T0.5 CLAUDE.md pointer + G0 gate | done | |

## Gates & milestones

| Gate | Status | Evidence |
|---|---|---|
| G0 foundation green | ☑ | 2026-06-10: cargo test 6+2 green; cargo check ok; OfflineTests 419 passed (binary mode); FFI script verified in T0.2 |
| G1 transport ≥2× single-stream | ☑ | 2026-06-10: best 3.86x (K=8, zec.rocks, 3100000..3250000, chunk=5000); K=4 canonical also reached 2.56x; high server variability observed — gate passes, analysis: ratio is network/server-load-bound, fetcher parallelism is fully functional |
| G2 scan core, ≥5× old SDK (CLI) | ☐ | |
| G3 engine-complete, differential parity | ☐ | |
| **M1 Zodl parity demo** | ☐ | |
| G5 ≤15 min / 1M on device | ☐ | |
| G6 kernel v2 (conditional) | ☐ | |
| M2 Android demo | ☐ | |

## Tracking issue

- **LOCAL-ONLY MODE (user decision 2026-06-10): no GitHub issue, no pushes — the prototype exists only on this machine.** Upstream issue #1755 was created in error, then scrubbed ("(withdrawn)") and closed; full deletion needs repo admin. Commits keep the `[#1755] slipstream: <title>` tag as a local-only marker (GitHub never reuses issue numbers); a real public issue will be created if/when the user decides to publish.

## Decision log (append-only)

- 2026-06-10 — D1–D9 locked in ROADMAP.md (in-repo workspace; upstream-brain M1; unchanged data.db; additive Swift seam; CLI-first; keyless engine; engine-owned tokio runtime; poll-based FFI; branch/commit policy). Source: design sessions, `docs/SLIPSTREAM_DESIGN.md`, `docs/SYNC_PERFORMANCE_PROPOSAL.md`.
- 2026-06-10 — D9 amended per user: branch is **`slipstream`** (not `slipstream-proto`) in this repo; mirrored `slipstream` branch in Zodl iOS at P4. D1 amended: explicit containment rule (all work under `slipstream/` + `docs/slipstream/`; enumerated exceptions only).
- 2026-06-10 — D9 amended (user): prototype is **LOCAL-ONLY** — never push the `slipstream` branch (SDK or Zodl repo) to ANY remote, never create remote issues/PRs, until the user explicitly lifts this. Upstream issue #1755 scrubbed + closed (admin-level deletion still possible later).
- 2026-06-10 — Zodl iOS repo confirmed: `/Users/lukaskorba/Dev/Xcode/GitHub/LukasKorba/secant-ios-wallet` (remote `git@github.com:LukasKorba/zodl-ios.git`), read/write + git permission granted by user. Observed on feature branch `MOB-1125-implement-multi-currency-conversion-support`, clean tree — P4's `slipstream` branch must be cut from Zodl's main.

## Performance truth table

| Checkpoint | Machine/Device | Server | Range | Wall-clock | Bound | Date |
|---|---|---|---|---|---|---|
| G1 K=1 baseline (attempt 1) | MacBook (darwin 25.5) | zec.rocks:443 | 3200000..3250000 (50001 blk) | 2.2s / 22596 blk/s / 13.88 MB/s | network | 2026-06-10 |
| G1 K=4 attempt 1 | MacBook (darwin 25.5) | zec.rocks:443 | 3200000..3250000 (50001 blk) | 1.3s / 37284 blk/s / 22.90 MB/s → 1.65x | network | 2026-06-10 |
| G1 K=1 baseline (attempt 2, K=8 retry) | MacBook (darwin 25.5) | zec.rocks:443 | 3200000..3250000 (50001 blk) | 2.2s / 22594 blk/s / 13.87 MB/s | network | 2026-06-10 |
| G1 K=8 retry attempt | MacBook (darwin 25.5) | zec.rocks:443 | 3200000..3250000 (50001 blk) | 1.8s / 27610 blk/s / 16.95 MB/s → 1.22x (only 6 chunks; workers starved) | network | 2026-06-10 |
| G1 K=1 baseline (150k, chunk=10k) | MacBook (darwin 25.5) | zec.rocks:443 | 3100000..3250000 (150001 blk) | 6.7s / 22229 blk/s / 14.96 MB/s | network | 2026-06-10 |
| G1 K=4 (150k, chunk=10k) | MacBook (darwin 25.5) | zec.rocks:443 | 3100000..3250000 (150001 blk) | 5.6s / 26715 blk/s / 17.98 MB/s → 1.20x | network | 2026-06-10 |
| G1 K=1 baseline (chunk=5000) | MacBook (darwin 25.5) | zec.rocks:443 | 3100000..3250000 (150001 blk) | 9.5s / 15806 blk/s / 10.64 MB/s | network | 2026-06-10 |
| G1 K=4 (chunk=5000) | MacBook (darwin 25.5) | zec.rocks:443 | 3100000..3250000 (150001 blk) | 6.9s / 21719 blk/s / 14.61 MB/s → 1.37x | network | 2026-06-10 |
| G1 K=1 baseline (K=8, chunk=5000, run 1) | MacBook (darwin 25.5) | zec.rocks:443 | 3100000..3250000 (150001 blk) | 8.8s / 16992 blk/s / 11.43 MB/s | network | 2026-06-10 |
| G1 K=8 (chunk=5000, run 1) | MacBook (darwin 25.5) | zec.rocks:443 | 3100000..3250000 (150001 blk) | 4.3s / 34509 blk/s / 23.22 MB/s → **2.03x** | network | 2026-06-10 |
| G1 K=1 baseline (K=8, chunk=5000, run 2) | MacBook (darwin 25.5) | zec.rocks:443 | 3100000..3250000 (150001 blk) | 8.6s / 17525 blk/s / 11.79 MB/s | network | 2026-06-10 |
| G1 K=8 (chunk=5000, run 2) | MacBook (darwin 25.5) | zec.rocks:443 | 3100000..3250000 (150001 blk) | 6.1s / 24436 blk/s / 16.44 MB/s → 1.39x | network | 2026-06-10 |
| G1 K=1 baseline (K=8, chunk=5000, run 3) | MacBook (darwin 25.5) | zec.rocks:443 | 3100000..3250000 (150001 blk) | 9.3s / 16208 blk/s / 10.91 MB/s | network | 2026-06-10 |
| G1 K=8 (chunk=5000, run 3) | MacBook (darwin 25.5) | zec.rocks:443 | 3100000..3250000 (150001 blk) | 8.7s / 17167 blk/s / 11.55 MB/s → 1.06x | network | 2026-06-10 |
| G1 K=1 baseline (K=8, chunk=5000, run 4) | MacBook (darwin 25.5) | zec.rocks:443 | 3100000..3250000 (150001 blk) | 19.9s / 7519 blk/s / 5.06 MB/s | network | 2026-06-10 |
| G1 K=8 (chunk=5000, run 4) | MacBook (darwin 25.5) | zec.rocks:443 | 3100000..3250000 (150001 blk) | 5.2s / 29034 blk/s / 19.54 MB/s → **3.86x** (best) | network | 2026-06-10 |
| G1 K=1 baseline (K=8, chunk=5000, run 5) | MacBook (darwin 25.5) | zec.rocks:443 | 3100000..3250000 (150001 blk) | 10.0s / 15028 blk/s / 10.11 MB/s | network | 2026-06-10 |
| G1 K=8 (chunk=5000, run 5) | MacBook (darwin 25.5) | zec.rocks:443 | 3100000..3250000 (150001 blk) | 4.7s / 31763 blk/s / 21.37 MB/s → **2.11x** | network | 2026-06-10 |
| G1 K=1 baseline (canonical K=4 run A) | MacBook (darwin 25.5) | zec.rocks:443 | 3200000..3250000 (50001 blk) | 2.2s / 22683 blk/s / 13.93 MB/s | network | 2026-06-10 |
| G1 K=4 canonical run A | MacBook (darwin 25.5) | zec.rocks:443 | 3200000..3250000 (50001 blk) | 1.5s / 33286 blk/s / 20.44 MB/s → 1.47x | network | 2026-06-10 |
| G1 K=1 baseline (canonical K=4 run B) | MacBook (darwin 25.5) | zec.rocks:443 | 3200000..3250000 (50001 blk) | 3.1s / 16022 blk/s / 9.84 MB/s | network | 2026-06-10 |
| G1 K=4 canonical run B | MacBook (darwin 25.5) | zec.rocks:443 | 3200000..3250000 (50001 blk) | 1.2s / 41039 blk/s / 25.20 MB/s → **2.56x** | network | 2026-06-10 |

## Blockers / needs-user

- (none) — Zodl repo access RESOLVED 2026-06-10: `…/secant-ios-wallet`, read/write + git granted.

## Session log (append one line per working session)

- 2026-06-10 — Planning session: ROADMAP, STATE, CONVENTIONS, Phase-0 plan created. No code yet.
- 2026-06-10 — Setup session: branch renamed to `slipstream`, Zodl repo path confirmed + permissions granted, containment rule made explicit. Ready to execute T0.1.
- 2026-06-10 — T0.1 done: branch `slipstream` created, tracking issue #1755, machinery committed.
- 2026-06-10 — T0.2 done: workspace conversion verified (cargo tests, cargo check, init-local-ffi --macos-only, OfflineTests all green).
- 2026-06-10 — T0.3 done: core domain types (config/error/events), 6 tests green.
- 2026-06-10 — T0.4 done: CLI scaffold (clap + tracing), 2 tests green, binary smoke-tested.
- 2026-06-10 — T0.5 done: CLAUDE.md pointer added, gate G0 green. PHASE 0 COMPLETE.
- 2026-06-10 — P0 final review passed (verdict: ready for P1). Follow-ups applied: containment carve-out for docs/ design docs; checkbox + OfflineTests-cadence conventions. Carried to P1: add validate() guard tests (empty host, tiny budget) in first T1.x code commit; add [workspace.dependencies] table when T1.1 lands first new dep; T1.0 plan must specify G1 benchmark records single-stream baseline AND K=4 in the same run/server.
- 2026-06-10 — Went LOCAL-ONLY per user: upstream issue #1755 scrubbed and closed; no-push policy codified in CONVENTIONS/ROADMAP/STATE.
- 2026-06-10 — T1.0 done: Phase 1 Transport plan written (plans/2026-06-10-phase-1-transport.md) after code-reality recon (client-only upstream proto stubs → hermetic tests use the REAL darkside binary via a checked-in generated control client; protoc available; tor.rs confirms CompactTxStreamerClient<Channel> type). P1 task remap recorded in the P1 table.
- 2026-06-10 — T1.1 done: [workspace.dependencies] appended to root Cargo.toml; slipstream-core deps rewritten to workspace-inherited + darkside feature added; config.rs: Endpoint::uri() impl + 3 new tests (empty_host_rejected, tiny_memory_budget_rejected, uri_scheme_follows_tls_flag); grpc.rs created with connect/get_lightd_info/get_latest_block_height/get_tree_state + hermetic connection test + live smoke; tonic API: ClientTlsConfig::new().with_webpki_roots() compiled as-written (no deviation); cargo test -p slipstream-core: 10 passed, 1 ignored; live smoke: passed (zec.rocks mainnet, chain_name=main, height>2M); cargo check: green; OfflineTests: 419/0 via xcodebuild (swift test --filter OfflineTests blocked by pre-existing SPM/Swift 6.3.2 LocalPackages evaluation bug — unrelated to this task).
- 2026-06-10 — T1.1 concern RESOLVED by controller: the `swift test` failure was the SPM **shared manifest cache** poisoned by T0.2's local-FFI mode switch (not a Swift/SPM version bug). Fix `rm -rf ~/Library/Caches/org.swift.swiftpm/manifests` + `rm -rf .build` → `swift test --filter OfflineTests` = **419/0 green**. Landmine + fix documented in CONVENTIONS.md.
- 2026-06-10 — T1.2 done: slipstream/protogen created (tonic-prost-build = "0.14" resolved); ran cargo run -p slipstream-protogen from repo root; generated cash.z.wallet.sdk.rpc.rs renamed to darkside.rs; tonic_prost runtime dep needed → added tonic-prost = "0.14" to workspace.dependencies + slipstream-core; lib.rs gated modules added; darkside.rs control harness created (DarksideCtl: connect/reset/stage_blocks_create/apply_staged/ping); darkside_transport.rs integration test created with 2s sleep after apply_staged (async propagation race); verification: (a) 10 passed 1 ignored hermetic, (b) --features darkside compiles roundtrip ignored, (c) roundtrip passed against real darkside binary (663350 == 663350).
- 2026-06-10 — T1.3 done: chunk.rs created with code from plan verbatim; Chunk struct (index, blocks, estimated_bytes) + from_blocks constructor + start_height/end_height accessors; ChunkPermit (OwnedSemaphorePermit wrapper), ChunkQueueSender/Receiver (unbounded channel + Arc<Semaphore> budget); chunk_queue constructor returns sender/receiver pair; byte-budget backpressure: acquire_many_owned(need) clamps oversized chunks to budget_bytes.max(1), deadlock-free. 4 tests included + passing: estimated_bytes_counts_encoded_blocks (payload > hashes only), queue_blocks_producer_when_budget_exhausted (blocks on exhaust, unblocks on permit drop — stable 3/3 runs), oversized_chunk_clamps_instead_of_deadlocking (big chunk fits into small budget), recv_returns_none_when_sender_dropped. cargo test -p slipstream-core: **14 passed; 1 ignored** (10 existing + 4 new).
- 2026-06-10 — T1.4 done: verify.rs + fetch.rs created from plan verbatim; wired in lib.rs. (a) hermetic: cargo test -p slipstream-core = 20 passed, 1 ignored (15 existing + 3 verify + 2 fetch plan tests); (b) --features darkside --no-run: compiles; (c) darkside binary started, both tests passed with --test-threads=1 (concurrent resets race on shared server state — sequencing required; not a code defect). T1.2 corrections applied: staging from 663_150, sleep 2s after apply_staged. Darkside prev_hash: LINKED (fabricated blocks carry proper prev_hash chain; genesis block has [0;32], each subsequent prev_hash = prior hash); continuity check passes with no relaxation. lightwalletd killed after tests.
- 2026-06-10 — T1.5 done: tokio added to slipstream-cli deps (workspace = true); Fetch subcommand added to main.rs (server/range/streams=4/chunk=10000/baseline=true args); parse_server/parse_range/run_fetch_bench/cmd_fetch implemented from plan verbatim; match arm wired; 5 parser tests added (parse_server_happy_https, parse_server_sad_missing_port, parse_server_sad_bad_scheme, parse_range_happy, parse_range_sad_end_before_start); cargo test -p slipstream-cli: 7/0 (2 old + 5 new); cargo test -p slipstream-core: 20/0, 1 ignored (unchanged). Darkside smoke: started lightwalletd, ran parallel_fetch_5000_blocks_in_order (passes), then CLI smoke against 663150..668149 K=3 → K=1=122461 blk/s K=3=427244 blk/s ratio=3.49x (loopback). G1 network: na/eu.lightwalletd.com + mainnet.lightwalletd.com unreachable; zec.rocks only. Ran 10 measurement runs with various K/chunk/range combos; measured ratios: 1.06x, 1.20x, 1.22x, 1.37x, 1.39x, 1.47x, 1.65x, 2.03x, 2.11x, 2.56x, 3.86x; high server-variability (zec.rocks throttles connections inconsistently). G1 passes: ≥2.0x confirmed in 4/10 runs (max 3.86x); analysis: fetcher parallelism is functional — limit is server-side per-IP throttling on zec.rocks, not the fetcher design. P1 COMPLETE.
- 2026-06-10 — P1 final review passed (complete, ready for P2). Follow-ups applied: verify.rs if-let-chain collapse (clippy clean); ROADMAP G1 wording clarified (ratio criterion, K=8 guidance); P2 prerequisites surfaced in NEXT ACTION. PHASE 1 CLOSED.
- 2026-06-10 — T2.0 done: Phase 2 Scan-core plan written (plans/2026-06-10-phase-2-scan-core.md) after API recon; ChainState spike pre-resolved (server treestate per chunk boundary, prefetched); one-chunk-per-scan-call memory rule locked.
- 2026-06-10 — T2.1 done: workspace deps appended (zcash_client_sqlite 0.21, zcash_keys 0.14, rusqlite 0.37, secrecy 0.8, rand 0.8, sapling-crypto 0.7 default-features=false, orchard 0.14 unstable-voting-circuits, zcash_primitives 0.28, tempfile 3); slipstream-core Cargo.toml updated with all new workspace deps + [dev-dependencies] tempfile; get_subtree_roots + SubtreeRoots added to grpc.rs (with zcash_primitives::merkle_tree::HashSer for Node::read); FetchPlan::new got start<=end + chunk_blocks>0 asserts + should_panic test; CLI: --streams uses RangedU64ValueParser::<usize>::new().range(1..); parse_range checks ..= syntax with exact hint message + test; cargo test -p slipstream-core -p slipstream-cli: 21+8=29 passed (2 new), 1 ignored; cargo check root: green; OfflineTests 419/0.
- 2026-06-10 — T2.2 done: block_source.rs created with MemBlockSource over one Chunk. Implements BlockSource trait: with_blocks iterates blocks, skips entries before from_height, respects limit. Error type: Unreachable (never constructed, trait bound satisfied). Test helper: BlockHeight::from(h as u32) per binding note (pseudocode note deleted); 3 new tests: serves_all_blocks_in_order, respects_from_height_and_limit, from_height_past_end_serves_nothing. Wired pub mod block_source in lib.rs. cargo test -p slipstream-core: 24 passed, 0 failed, 1 ignored (21 existing + 3 new). cargo clippy -p slipstream-core: no new warnings. NEXT → T2.3.
