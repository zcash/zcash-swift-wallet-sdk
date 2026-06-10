# Slipstream Prototype — Master Roadmap

> **For any session picking this up:** Read `docs/slipstream/STATE.md` FIRST (current status + next task), then `CONVENTIONS.md`, then the current phase's plan in `docs/slipstream/plans/`. This roadmap is the map, not the territory — detailed, executable plans are written per-phase, just-in-time.

**Goal:** The fastest mobile Zcash sync engine in the industry (iOS + Android), prototyped against the Zodl wallet.
**Milestone M1:** Zodl running on the Slipstream engine shows the correct, expected balance and complete transaction history for a known seed — measurably faster than the old SDK.

**Background (read once):**
- `docs/SLIPSTREAM_DESIGN.md` — the target architecture (pipeline, warp packets, kernel, scheduler).
- `docs/SYNC_PERFORMANCE_PROPOSAL.md` — why the old SDK is slow (evidence, file:line).

---

## Strategic decisions (LOCKED — do not re-litigate in future sessions; changes require a Decision Log entry in STATE.md)

| # | Decision | Rationale |
|---|---|---|
| D1 | Engine lives in **this repo** as new cargo workspace members: `slipstream/core` (engine, platform-neutral), `slipstream/cli` (dev harness). **Containment rule:** ALL new work lives under `slipstream/` (code) and `docs/slipstream/` (plans). The only permitted touches outside those folders (plus read-once background design docs at `docs/` top level): root `Cargo.toml` `[workspace]` lines, the `CLAUDE.md` pointer, P4 FFI exports in `rust/src/lib.rs`, and P4 Swift files under `Sources/ZcashLightClientKit/Slipstream/` (must live in the SPM target). | Shares the exact `zcash_client_sqlite`/`zcash_client_backend` versions with `libzcashlc` (one copy of statics in one binary — two static libs would collide), reuses the XCFramework pipeline, darkside test infra, checkpoints. We are NOT refactoring the old sync path — it stays untouched and selectable. Containment keeps old-SDK and Slipstream work unmixable. |
| D2 | **M1 engine = "upstream brain, Slipstream body."** Parallel tonic fetchers → bounded in-memory chunk queue → upstream `scan_cached_blocks` over a custom in-memory `BlockSource` → unchanged `data.db` schema. The custom detect kernel / sparse tree are Phase 6+, behind a golden-oracle harness. | De-risks correctness completely for M1 (upstream's audited scanner), while still removing every architectural bottleneck (disk cache, per-batch RPCs, tiny chunks, no overlap, connection churn). |
| D3 | **The wallet data model does not change.** Engine writes through `zcash_client_sqlite` into the same `data.db`; coverage ledger v0 IS the existing scan-queue in `data.db`. | User constraint; keeps the entire old-SDK query/spend/PCZT surface working unchanged; witnesses live where the spend path looks. |
| D4 | Swift seam = new **`SlipstreamSynchronizer: Synchronizer`** (additive file), implementing the ~10 sync members on the engine and delegating the ~40 data-model members to existing SDK components via the existing DIContainer. | Zodl swaps implementations behind its dependency client; zero app-surface change. |
| D5 | **CLI-first development.** Every engine capability lands and is verified in `slipstream-cli` on macOS (cargo test + darkside lightwalletd) before any Xcode involvement. Phases 1–3 require no Xcode at all. | Fast iteration, cheap verification for fresh sessions, deterministic CI. |
| D6 | Engine is **keyless**: accepts UFVKs only; spend authority never enters it. | Security posture from the design doc. |
| D7 | Engine owns a multi-thread tokio runtime per instance (one instance per wallet/alias), created at `start()`, dropped at `stop()`. | Matches existing TorRuntime precedent in libzcashlc. |
| D8 | iOS FFI is **poll-based**: Swift drains an event ring + reads an atomic snapshot on its own cadence. No cross-FFI progress callbacks. | Simplest, restart-safe, matches zcashlc patterns. |
| D9 | Branch: **`slipstream`** off `main` in this repo; mirrored **`slipstream`** branch in the Zodl iOS repo at P4 (`/Users/lukaskorba/Dev/Xcode/GitHub/LukasKorba/secant-ios-wallet`, remote `zodl-ios`, read/write + git granted — cut from Zodl's main, not from in-flight feature branches). All commits `[#1755] slipstream: <title>` (local-only marker — see STATE.md Tracking issue). `main` is never broken; `swift test --filter OfflineTests` and `cargo test -p slipstream-core` stay green at every commit. **LOCAL-ONLY amendment (2026-06-10): no pushes/issues/PRs to any remote until the user lifts it.** | User decision 2026-06-10 + repo policy + always-green rule. |

---

## Phase overview

| Phase | Name | Deliverable | Gate (objective, executable) |
|---|---|---|---|
| P0 | Foundation & session machinery | Workspace, crates skeleton, plan/state files, CI-green baseline | **G0:** `cargo test` green; `./Scripts/init-local-ffi.sh --macos-only` + `swift test --filter OfflineTests` green on branch |
| P1 | Transport | Parallel `GetBlockRange` fetchers → ordered in-memory chunks; continuity verify; fetch benchmark CLI | **G1:** hermetic darkside fetch test green; on public lwd, K=4 streams ≥2× single-stream MB/s (recorded in STATE.md) |
| P2 | Scan core | `MemBlockSource`; persistent WalletDb session (open once, WAL); chunked `scan_cached_blocks` (≈10k); scheduler v0 (verify→tip-window→linear backfill via existing scan-queue); fetch∥scan pipeline | **G2:** darkside wallet syncs, found-tx matches fixture; 1M-block mainnet range completes via CLI; ≥5× old-SDK wall-clock on same machine/server (recorded) |
| P3 | Completeness | Rust enhancer (concurrent GetTransaction → decrypt_and_store), transparent/UTXO refresh, event+snapshot surface | **G3 (engine-complete):** differential parity script passes — balances + tx history in `data.db` identical to an old-SDK-synced db for darkside fixtures and ≥1 real mainnet test seed |
| P4 | iOS docking | `zcashlc_slipstream_*` FFI; XCFramework all-arch build; `SlipstreamSynchronizer`; darkside subset on it; Zodl behind a debug flag | **M1 (THE milestone):** Zodl-on-Slipstream restores a known seed → correct balance + full tx history (vs Zodl-on-old-SDK control); wall-clock recorded |
| P5 | Performance pass (T0) | Per-stage instrumentation; commit/write tuning; fetcher adaptivity + server selection; device A/B methodology vs YWallet/Zingo | **G5:** 1M recent blocks ≤15 min on device, good Wi-Fi; published comparison table |
| P6 | Kernel v2 + sparse tree (conditional) | Golden-oracle harness; column-oriented batch ECDH kernel; `put_blocks`-compatible output; tree fast-path eval | **G6:** ≥2× scan throughput vs upstream scanner with ZERO diffs vs oracle on recorded fixtures. *Enter only if G5 shows CPU-bound or spam-era targets unmet.* |
| P7 | Android | uniffi (or JNI) bindings, cargo-ndk pipeline, Kotlin shell, docking analysis vs zcash-android-sdk seam | **M2:** Android wallet parity demo (same criteria as M1) |
| P8 | Hardening | Tor transport, Drip/background modes, reorg fuzz suite, memory budgets, T1 warp-packet exporter + format spec | rolling gates per feature |

Dependency chain: P0→P1→P2→P3→P4(M1). P5 after M1. P6 conditional on P5 data. P7 after G3 (can parallel P5/P6). P8 rolling.

---

## Task index

Tasks are one-session-sized. `T{phase}.0` is always "write the detailed phase plan" (full TDD format, complete code, into `docs/slipstream/plans/YYYY-MM-DD-phase-N-<name>.md`) — that session reads current code reality first, so detailed plans are never stale.

### P0 — Foundation (detailed plan EXISTS: `plans/2026-06-10-phase-0-foundation.md`)
- T0.1 Create branch `slipstream` and tracking issue; commit the `docs/slipstream/` machinery (STATE/CONVENTIONS/ROADMAP/phase plans).
- T0.2 Convert root `Cargo.toml` to workspace; empty `slipstream/core` crate + smoke test; **verify FFI scripts still build** (`--macos-only`) and OfflineTests green.
- T0.3 `slipstream-core` domain types: `EngineConfig`, `SlipstreamError`, `Event`, `Snapshot`, `SyncMode` + unit tests.
- T0.4 `slipstream/cli` scaffold (clap, tracing, `version` cmd) + smoke test.
- T0.5 CLAUDE.md pointer section; STATE.md updated; G0 checklist run + recorded.

### P1 — Transport
- T1.0 Detailed phase plan.
- T1.1 `grpc` module: connect (TLS + plaintext-for-darkside), `get_lightd_info`, `get_latest_block`, `get_tree_state`, `get_subtree_roots`; integration test against darkside.
- T1.2 `chunk` module: `Chunk` (blocks + bounds + prev-hash + tree sizes from ChainMetadata), `ChunkQueue` (bounded by estimated bytes, async).
- T1.3 Parallel fetcher: K disjoint `GetBlockRange` sub-streams → reorder buffer → ordered queue; retry/timeout; K configurable.
- T1.4 Continuity verifier (prev-hash across chunk seams; structured `Discontinuity` error).
- T1.5 `slipstream-cli fetch --range A..B --streams K` benchmark (blocks/s, MB/s); record G1 numbers in STATE.md.

### P2 — Scan core
- T2.1 `MemBlockSource`: `zcash_client_backend` `BlockSource` impl over in-memory chunks + unit tests (incl. `with_blocks` ordering/limit semantics).
- T2.2 `wallet_session`: open WalletDb ONCE; `PRAGMA journal_mode=WAL`, `synchronous=NORMAL`; init/migrations; `update_subtree_roots` + `update_chain_tip` steps.
- T2.3 **SPIKE (timeboxed):** ChainState for chunk N+1 without an RPC — (a) baseline: one `get_tree_state` per ~10k chunk start (correct, acceptable: ~100 RPCs/1M blocks); (b) derive from WalletDb block metadata after scanning chunk N. Implement (a), pursue (b) only if free. Record outcome in Decision Log.
- T2.4 Scan driver: height-ordered chunk consumption → `scan_cached_blocks(limit=chunk_len)`; continuity-error → truncate + invalidate + refetch (upstream semantics).
- T2.5 Scheduler v0 over existing scan-queue (`suggest_scan_ranges`): Verify range first, then ranges as suggested; bounded out-of-order (tip window only).
- T2.6 Pipeline integration: fetch ∥ scan with backpressure; memory-cap test (queue refuses past budget).
- T2.7 `slipstream-cli sync` end-to-end: darkside deterministic test (known seed → expected found-tx set); mainnet 1M-range smoke + wall-clock; record G2 numbers.

### P3 — Completeness
- T3.1 Enhancer task: `transaction_data_requests` → bounded-concurrency `get_transaction` → `decrypt_and_store_transaction` → status updates; tests against darkside.
- T3.2 Transparent task: per-account UTXO refresh + `transactionsInvolvingAddress` handling (mirror upstream `sync.rs` semantics).
- T3.3 Event/snapshot surface: `Event` ring + `Snapshot` (coverage %, stage rates, bound: download|cpu, ETA); CLI renders live.
- T3.4 **Differential parity harness (G3):** script syncing same seed via old SDK (darkside + mainnet test seed) and via CLI; SQL diff of balances/tx views; zero-diff required. This harness is the permanent regression rail for everything after.

### P4 — iOS docking → M1
- T4.1 FFI: `zcashlc_slipstream_open/start/stop/snapshot/drain_events/free` (handle pattern; poll-based per D8); cbindgen header; Rust-side tests.
- T4.2 Full-arch XCFramework build (`init-local-ffi.sh` all slices) + workspace script fixes if needed.
- T4.3 `SlipstreamSynchronizer.swift`: sync members on engine; data members delegated (reuse DIContainer components); state/event mapping incl. progress→`SynchronizerState`.
- T4.4 SDK tests: mapping unit tests (Offline); darkside scenario subset (sync, foundTransactions, reorg) running on `SlipstreamSynchronizer`.
- T4.5 Zodl integration (repo: `/Users/lukaskorba/Dev/Xcode/GitHub/LukasKorba/secant-ios-wallet`, create `slipstream` branch off Zodl main): synchronizer swap behind debug toggle; A/B same seed; **M1 demo checklist** (balance match, tx-history match, wall-clock both engines, screenshots) recorded in STATE.md.

### P5 — Performance pass
- T5.1 Stage instrumentation (per-stage throughput, queue depths, bound detection) surfaced in snapshot + CLI `--report`.
- T5.2 Write-path tuning within `zcash_client_sqlite` constraints (commit sizing, WAL checkpointing cadence, prepared-statement reuse via session).
- T5.3 Fetcher adaptivity (stream count by measured RTT/bandwidth; server scorecard ≈ `evaluateBestOf`).
- T5.4 Device benchmark protocol: same seed/birthday across Zodl-Slipstream / YWallet / Zingo; methodology + results table; G5 verdict → decides P6 entry.

### P6 — Kernel v2 (conditional)
- T6.1 Golden-oracle harness: recorded chunk fixtures; differential detect (v2 vs upstream `scan_block`) — REQUIRED before any kernel code.
- T6.2 **SPIKE:** construct `put_blocks`-compatible inputs (`ScannedBlock`) from custom kernel output with public APIs; if blocked → upstream issue/PR path; fallback = stay on upstream scanner, contribute parallelism upstream.
- T6.3 Column-oriented batched ECDH kernel (Sapling first, Orchard second) + rayon sharding; swap behind engine flag; G6 measurement.

### P7 — Android
- T7.1 Docking analysis: zcash-android-sdk seam (their `Synchronizer`/`Backend` equivalents) — written report into `docs/slipstream/`.
- T7.2 Bindings crate (uniffi preferred; fall back JNI) + cargo-ndk `.so` pipeline + CI.
- T7.3 Kotlin shell mirroring T4.3 mapping; demo app or SDK-fork integration → M2 checklist.

### P8 — Hardening (rolling)
- T8.x Tor transport (arti channel for tonic), Drip/background modes + checkpoint-resume tests, reorg fuzzer (darkside scripts), memory budget enforcement, T1 packet exporter + format spec doc, upstreaming conversations (ECC/zaino).

---

## Risk register (each has an owning task)

| Risk | Owning task | Fallback |
|---|---|---|
| Workspace conversion breaks XCFramework scripts | T0.2 (do this FIRST, verify immediately) | scripts pin `-p libzcashlc` |
| ChainState-per-chunk needs an RPC | T2.3 spike | baseline (a) is already acceptable (~100 RPCs/1M blocks) |
| `scan_cached_blocks` perf ceiling (serial tree/commit) | T5.x measures | P6 kernel; upstream PRs |
| `ScannedBlock` construction not public for kernel v2 | T6.2 spike | stay on upstream scanner (still fast); upstream PR |
| tokio runtime lifecycle in iOS app (suspend/resume) | T4.1 + T4.4 | follow TorRuntime precedent; stop()=drop runtime |
| ~~Zodl repo/branch access~~ RESOLVED 2026-06-10 | T4.5 | path: `…/secant-ios-wallet` (remote `zodl-ios`), read/write + git granted |
| Public lwd servers throttle parallel streams | T1.5 / T5.3 | per-server stream cap; server scorecard; (later) T1 packets |

## Performance truth table (update at every gate)

| Checkpoint | Machine/Device | Server | Range | Wall-clock | Bound | Recorded in |
|---|---|---|---|---|---|---|
| Old SDK baseline | (T2.7) | | 1M | | | STATE.md |
| G2 CLI | | | 1M | | | STATE.md |
| M1 on-device | | | restore | | | STATE.md |
| G5 device | | | 1M | | | STATE.md |
