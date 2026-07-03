# Full Audit — slipstream engine · SDK · Zodl macOS

**Commissioned 2026-07-01 by Lukas. Executor: Claude (Fable 5), fully autonomous.**
Goal: restore full confidence across all three layers. Find gaps, issues, discrepancies —
correctness, security, privacy — with evidence. The engine must provably do its job; the macOS
app must be secure, private, and correct in the areas that matter: **sending, restoring,
syncing, rewind, seed handling**.

## Ground rules
- **Read-only.** The audit changes no code. Output = findings docs in `docs/slipstream/audit/`.
  Fixes happen after, as a prioritized wave Lukas triggers (P0s flagged loudly and immediately).
- Working tree has live uncommitted work (5 Keystone-sign fixes in Zodl mid device-test; Lukas's
  own WIP in both repos). The audit must not disturb it and must audit what's ON DISK (= what ships).
- Repos: SDK `~/Dev/Xcode/GitHub/LukasKorba/ZcashLightClientKit` @ `slipstream` (engine vendored
  at `slipstream/`, FFI at `rust/` + repo-root Cargo.toml, Swift at `Sources/ZcashLightClientKit/`);
  Zodl `~/Dev/Xcode/GitHub/LukasKorba/secant-ios-wallet` @ `slipstream-macos`.
  Published engine mirror: github.com/LukasKorba/slipstream (divergence check = hygiene item).

## Severity scale
- **P0** — funds loss, seed/key compromise, crash on a mainline path.
- **P1** — correctness (wrong balance/tx state shown, sync wedges), privacy leak (seed/keys/addresses/amounts in logs, network metadata).
- **P2** — robustness (unhandled edge, race, missing retry/timeout, error swallowed).
- **P3** — hygiene (version drift, dead code, stale docs, release-process gaps).

Every finding: `severity | repo | file:line | claim | evidence | suggested fix | confidence`.
Every area also reports **verified-OK coverage** — what was checked and found sound. An audit
that only lists bugs gives no confidence about the rest.

## Phases (each ends with findings on disk + AUDIT_STATE.md updated — interruption-safe)

### Phase 0 — Charter + ground truth ✅ (this doc)
Dep graph: Swift SDK → `libzcashlc` FFI (`rust/src/lib.rs`, `zcashlc_slipstream_*` ~L4230+)
→ `slipstream_core::ffi_handle`. Engine = 4 crates (core 24 modules, gpuhash, cli, protogen), ~16.9k LOC.

### Phase 1 — Engine (Rust) audit — 6 parallel lenses
- **1A pipeline**: engine.rs, scheduler.rs, session.rs, wallet_session.rs, chunk.rs, scan.rs, verify.rs —
  pass lifecycle, restart/resume, recent-first ordering, cancellation, wedge-states.
- **1B persistence**: persist.rs, oracle.rs, gpu_subtree.rs — schema/migrations, WAL, crash-safety,
  shardtree overlay (SparseCachingShardStore), Swift-reader concurrency (SQLITE_BUSY hazard).
- **1C wallet semantics**: reconcile.rs, enhance.rs, mempool.rs, transparent.rs — reconcile view
  correctness incl. OPEN Q (why reconciled=0 on a fully-synced wallet / Keystone txs), balance deltas, TIA.
- **1D network**: connector.rs, grpc.rs, fetch.rs, block_source.rs, darkside.rs — retry/backoff
  (connect_direct_with_retry), Tor parity, TLS, server-trust boundaries, metadata privacy.
- **1E failure modes**: whole-crate sweep — panic!/unwrap/expect/assert in reachable paths
  (known: QA "state2 = panic"), error taxonomy, what leaks into logs (privacy).
- **1F FFI boundary**: ffi_handle.rs, events.rs, config.rs + rust/src/lib.rs slipstream section —
  memory safety, panic hook coverage, event drain, thread-safety of C surface, handle lifecycle.
- **1G hygiene** (inline): crate version 0.0.1 vs shipped "v0.2.5"; local-vs-published divergence;
  test coverage map.

### Phase 2 — SDK (Swift) audit
- **2A lifecycle**: SlipstreamSynchronizer prepare/start/stop/wipe; init-mode derivation
  (WalletInitMode removed — prepare(seed?, birthday?)); importAccount restart serialization; pass gating.
- **2B isRecovering**: recover_until_height persistence, fail-safe gate, monotonic progress floor,
  derived restoring signal end-to-end.
- **2C balances**: getAccountsBalances during recovery, recoveryAccountBalances() Σ-delta path
  (STATE.md says a 06-30 field fix exists — VERIFY it's actually committed; STATE.md-vs-git drift),
  spendable-early-hold gate.
- **2D transactions**: foundTransactions emission, reconcile filter gate (c6bc6b9d), allTransactions
  paths, pending/mined transitions (open Zodl bugs P0-2a/2d live here too).
- **2E restore/rewind**: KNOWN GAP — restore writes seed but never wipes data.db (seed↔account desync,
  ZRUST0002) — confirm current state + spec the guard; rewind semantics + wipe correctness.
- **2F DB concurrency**: SimpleConnectionProvider (uncommitted busyTimeout=5s WIP validates a real
  uncatchable-crash hazard) — full Swift-reads-vs-Rust-writes story.
- **2G hygiene**: [send-debug] TEMP logs (SDKSynchronizerLive — privacy), error-code surface,
  CHANGELOG/MIGRATING drift, OfflineTests coverage of slipstream paths.

### Phase 3 — Zodl macOS audit
- **3A seed & keychain**: SE wrap (userPresence), migration crash-safety, MISSING step-3b
  seed-fingerprint guard, PrimedSeedBox, keychain mutationQuery fix, seed-input hardening S4–S7 status,
  clipboard/screen-capture posture, RecoveryPhrase resign-active.
- **3B send paths**: software + Keystone (PCZT/QR incl. the 5 uncommitted fixes), Touch ID contexts,
  [send-debug] logs in SendConfirmationStore, broadcast lock, wipe-on-restore desync surface.
- **3C restore/sync UX correctness**: isRecovering label, SmartBanner priority machine, walletStatus,
  progress display truthfulness.
- **3D macOS platform-gap SWEEP** (the popover class): every iOS-only presenter/API —
  .popover/.sheet/.fullScreenCover/UIKit-isms inside `#else`/os(iOS) with no macOS equivalent;
  onAppear/scenePhase lifecycle differences (the pcztForUI wipe class); every binding-driven flow
  checked for a macOS presenter.
- **3E privacy & logging**: LoggerProxy in release builds, what ships in os_log, hardcoded strings,
  network toggles (Tor), no-analytics confirmation.
- **3F release hygiene**: Beta3 built from unpushed commit + uncommitted deltas; versioned-framework
  script; entitlements/sandbox review (macOS target).

### Phase 4 — Adversarial verification + final report
Re-verify every P0/P1 against source (kill plausible-but-wrong findings), rank survivors,
write `ZODL_AUDIT_REPORT.md`: executive summary, per-repo confidence statement, prioritized fix
plan (P0s first), verified-OK coverage map. This is the "eyes" deliverable.

## Limits & resume strategy (the one thing Lukas asked me to manage)
- I cannot see the usage meter, so the design assumes ANY turn can be the last before a cutoff:
  **write early, write often** — findings append to disk per-area, AUDIT_STATE.md updated at every
  checkpoint, agents return structured summaries (their transcripts also persist under the session).
- **Resume protocol** (works for any model — Fable, Opus, Sonnet): new session → memory index points
  here → read `AUDIT_STATE.md` → continue the first unchecked item. Zero re-derivation.
- Phase sizing: each subsystem completable in one modest turn; Phase 1/3 fan out via parallel
  read-only agents (breadth without loading my context).
- Model economics: Fable is included until July 7 (per Lukas's UI) — deep phases (1, 2, 4 synthesis)
  run best on Fable now. If limits pinch: 5-hour reset windows — pause and resume; mechanical sweeps
  (3D, hygiene) run fine on Opus/Sonnet if needed. If Lukas upgrades to Max 20, nothing changes
  except fewer pauses.

## Seed findings (known going in — audit must confirm/refute/track)
1. [P0?] Restore never wipes data.db → seed↔account desync (ZRUST0002 on send). Fix designed, NOT implemented. → 2E
2. [P1] Reconcile view flags fully-scanned (Keystone) txs unreconciled on synced wallet — root cause unknown. → 1C
3. [P1] SQLITE_BUSY uncatchable `try!` crash — Swift reader vs Rust writer; busyTimeout WIP uncommitted. → 2F/1B
4. [P1] rustSlipstreamSyncFailed state2 = engine panic path. → 1E/1F
5. [P1-privacy] [send-debug] TEMP logs in SDKSynchronizerLive + SendConfirmationStore. → 2G/3B
6. [P1] SE hardening step 3b (seed-fingerprint guard) unimplemented. → 3A
7. [P2] Seed-input hardening S4–S7 not done. → 3A
8. [P3] Engine crate version 0.0.1 vs shipped v0.2.5; local vs published repo divergence. → 1G
9. [P3] Beta3 released from unpushed commit + uncommitted deltas. → 3F
10. [P3] STATE.md "NEXT ACTION" says 06-30 balance fix UNCOMMITTED; git shows file clean — doc/commit drift. → 2C
11. [P1-class] iOS-only presenters with no macOS equivalent (popover bug just found = instance; sweep the class). → 3D
