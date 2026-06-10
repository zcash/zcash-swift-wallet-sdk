# Slipstream — Living State

> **THE first file every session reads. THE last file every session updates (in the same commit as the work).**
> Format rules: append, don't rewrite history. Keep "NEXT ACTION" accurate above all else.

## NEXT ACTION

➡️ **T1.3** — chunk + byte-budgeted queue. Detailed steps: docs/slipstream/plans/2026-06-10-phase-1-transport.md, Task 1.3.

## Current phase: P1 — Transport (plan: `plans/2026-06-10-phase-1-transport.md`)

| Task | Status | Session notes |
|---|---|---|
| T1.0 detailed phase plan | done | Task remap vs ROADMAP index: T1.2=darkside codegen+harness, T1.3=chunk+queue, T1.4=fetcher+reorder+continuity (merged), T1.5=CLI bench+G1. get_subtree_roots wrapper deferred to P2. Facts verified: upstream proto is client-only; protoc present; darkside.proto vendored at Tests/TestUtils/proto/. |
| T1.1 workspace deps + grpc module | done | [workspace.dependencies] added; slipstream-core Cargo.toml rewritten to workspace-inherited deps + darkside feature; uri() + 3 guard tests added to config.rs; grpc.rs created (connect/get_lightd_info/get_latest_block_height/get_tree_state); tonic 0.14.6 ClientTlsConfig::new().with_webpki_roots() compiled without change; 10 hermetic tests green, 1 ignored (live smoke); live smoke also passed (zec.rocks mainnet); OfflineTests 419/0 fail (via xcodebuild; swift test --filter OfflineTests pre-existing SPM/Swift 6.3.2 issue: LocalPackages evaluated as fileSystem dep despite dir not existing — not caused by this task) |
| T1.2 darkside codegen + harness + roundtrip | done | Codegen crate: tonic-prost-build = "0.14" resolved (not fallback). tonic_prost runtime crate referenced in generated code — added tonic-prost = "0.14" to [workspace.dependencies] + slipstream-core deps. Generated file renamed cash.z.wallet.sdk.rpc.rs → darkside.rs; contains pub mod darkside_streamer_client + extern-mapped Empty/RawTransaction/TreeState/BlockId/GetAddressUtxosReply. Field/method name deviations: none (prost snake_case matched plan exactly). Deviation from plan test code: (1) staging must start at sapling activation height 663150 (not 663151 as plan's comment implied), staged 201 blocks 663150..=663350; (2) added tokio::time::sleep(2s) after apply_staged — darkside propagates state asynchronously and get_latest_block_height otherwise races ahead of apply completion (matches Swift DarksideTests sleep(2) pattern). Verification: (a) cargo test -p slipstream-core: 10 passed, 1 ignored; (b) --features darkside: compiles, roundtrip ignored; (c) darkside binary started, roundtrip passed (663350 == 663350). |
| T1.3 chunk + byte-budgeted queue | todo | |
| T1.4 parallel fetcher + continuity | todo | hermetic darkside 5000-block test |
| T1.5 CLI fetch bench + gate G1 | todo | K=1 baseline AND K=N same run/server (carry-over) |

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
| G1 transport ≥2× single-stream | ☐ | |
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
| (empty — first entry lands at T2.7 old-SDK baseline) | | | | | | |

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
