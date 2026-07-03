# AUDIT_STATE — resume here

> **Resume protocol:** read `AUDIT_PLAN.md` (charter), then this file top-to-bottom, then continue
> the first ⏳ item. Findings live in `findings/`. Update this file at EVERY checkpoint.
> Works on any model. Commissioned 2026-07-01; fully autonomous (no approvals needed, read-only audit).

## Status
- [x] Phase 0 — charter + ground truth (2026-07-01)
- [x] Phase 1 — engine audit COMPLETE (2026-07-01) → `findings/phase1-engine.md`
  - Verdict: NO confirmed P0. 2 surviving P1s (ENG-1 no busy_timeout anywhere in engine;
    ENG-2 reconcile nf-population/scoping = prime root-cause candidate for vanished-Keystone-tx),
    8 P2s, 8 P3s, 12 verified-OK invariants. 6 agent claims refuted/reclassified (documented in file —
    incl. both agent "P0"s: flush-atomicity refuted by direct read; Tor-CA was fs-mistrust).
- [x] Phase 2 — SDK audit COMPLETE (2026-07-01) → `findings/phase2-sdk.md`
  - Verdict: 1 confirmed P0 (SDK-P0-1 restore seed↔account desync no-op at Initializer.swift:461-462,
    funds-loss adjacent, matches 06-27 field report). 3 P1 (stop/start inversion; rewind misses cache
    reset; Keystone recovery-balance frozen — contingent on ENG-2). 6 P2, 7 P3. 12 verified-OK.
    [send-debug] logs already gone. App-bug leads: $0-send = app-side filter (not SDK); live-pending =
    SDK-8 (no pending emission path). Several claims refuted (documented).
- [x] Phase 3 — Zodl macOS audit COMPLETE (2026-07-01) → `findings/phase3-zodl.md`
  - Verdict: security & privacy HIGH (seed SE-wrap crash-safe, no iCloud sync, S1-S3 hardening, spend
    SE-gated no-bypass, Keystone PCZT can't submit partial sigs, ZERO analytics, no log leaks, Tor
    opt-in). Platform sweep found NO new gaps (only the 2 already-fixed). App-side: no $0 value filter
    (P0-2a = pending-window gap); live-pending = missing optimistic insert (+SDK-8). Restore guard
    exists app-side but asymmetric vs SDK (SDK-P0-1 is the systemic fix). CMC-key-in-repo REFUTED
    (gitignored). Sandbox/hardened-runtime in build settings (6 pbxproj matches). iCloud CloudDocuments
    entitlement inherited from Zashi — verify nothing sensitive uses it (P3).
- [x] Phase 4 — COMPLETE (2026-07-01) → `ZODL_AUDIT_REPORT.md` (the deliverable)
  - Ran INLINE (no fan-out, per cost constraint). Reconcile account-scoping REFUTED (nf globally
    unique + tx-anchored view); nf-NULL is the sole surviving trigger; reseed_nullifiers (scan.rs:524)
    is where to look. Device nf-query is the #1 open item.

## FINAL TALLY (see ZODL_AUDIT_REPORT.md)
- Confirmed P0: 1 systemic (SDK-P0-1 restore desync) + 1 contingent (P0-B Keystone nf, device-gated)
  + P0-C (commit the 2 uncommitted Keystone macOS fixes = ship-blockers).
- P1: busy_timeout both halves · live-pending emission · rewind cache reset · stop/start inversion.
- 9 agent "P0"s proposed → 7 refuted against source, 2 survive.
- Confidence: engine HIGH, SDK HIGH-on-recovery/MEDIUM-overall, Zodl macOS HIGH security+privacy.
- AUDIT IS READ-ONLY & DONE. Fix wave = separate, Lukas-triggered.

## FIX WAVE (2026-07-01, triggered by Lukas) — IMPLEMENTED, VERIFIED, UNCOMMITTED
- **P0-B CLOSED via live device DB** (read-only query on the Mac's ZcashSdk_mainnet_data.db):
  nf-NULL REFUTED (0/159 notes incl. all 116 Keystone); real cause = permanent-dangle classes
  (external senders' spends in txs that pay us + pre-birthday spends). Display gate is the CORRECT
  fix; invariant documented in reconcile.rs. No view change.
- **P0-A implemented**: `initializerSeedMismatch` (ZINIT0006, Sourcery-regenerated) thrown by
  Initializer.initialize when seed≠stored derived account (imported-only wallets exempt via
  seedFingerprint/hdAccountIndex check — SeedRelevance::NoDerivedAccounts reads false!).
- **P1 batch implemented**: SDK-1 stop→start ordering (pendingStopTask awaited in start()); SDK-5
  rewind() cache resets (counters intentionally NOT reset — handle survives rewind); SDK-8
  emitPostSubmitTransactions() on successful broadcast (fixes app bug P0-2d root, likely P0-2a's
  pending window too); ENG-1 busy_timeout(5s) on both engine side connections (WalletDb conn is
  upstream-internal; single-writer makes it non-contending); ENG-3 height u32::try_from →
  MisbehavingServer + warn.
- **Docs**: CHANGELOG (Added+Fixed), MIGRATING (WalletInitMode removal + seed-mismatch = SDK-11 done).
- **VERIFIED**: cargo test slipstream-core 170/0 · swift build green · OfflineTests 555/0 · lint clean
  on changed files · macOS FFI slice rebuild kicked (engine changed → app needs fresh slice).
- **NOT committed** (standing rule). Zodl-side items pending Lukas: device-test + commit the 5
  Keystone fixes (P0-C); optional app optimistic insert (may be unnecessary now — SDK-8 emission
  likely suffices); trace Update→Reset→Restore ordering (P0-1) — the SDK guard now catches the
  desync outcome regardless.
- macOS FFI slice rebuilt green post-fix-wave (engine busy_timeout + height guard live for app builds).

## FOLLOW-ON WORKSTREAMS (planned 2026-07-01, NOT started — Lukas's deep-confidence ask)
1. **Engine↔SDK boundary review** ("slipstream for everybody"; SDK = thin interface; CLI as the
   second-host proof) → `docs/slipstream/plans/2026-07-01-engine-sdk-boundary-review.md`.
   Phases A-F; one approval gate (Lukas reviews the Phase-A ENGINE_API_V2.md design doc).
2. **macOS foundations review** (MacCard verdict, FixedSidebarWidth fragility, blank-frame nav,
   platform-gap class → presentation registry, a11y pass) →
   `secant-ios-wallet/docs/macos/FOUNDATIONS_REVIEW_PLAN.md`. Phases F-1..F-5; sandbox adjudications.
   Precondition: land the uncommitted baseline first.

## Context anchors (avoid re-derivation)
- Engine: vendored in SDK repo `slipstream/` (core/gpuhash/cli/protogen, ~16.9k LOC Rust, core has 24 modules).
- FFI: repo-root Cargo.toml = `libzcashlc` 2.6.0-alpha.4; `rust/src/lib.rs` `zcashlc_slipstream_*` from ~L4230; panic hook `install_slipstream_panic_hook` L4302.
- SDK HEAD at audit start: `c6bc6b9d` (slipstream). Zodl HEAD: `29f83201` (slipstream-macos).
- Uncommitted (DO NOT DISTURB): Zodl 5 Keystone-sign fixes (mine, mid device-test; SmartBannerStore is MIXED — Lukas hunk @~542) + Lukas WIP (pbxproj, eye PNGs, WalletAccountsSheet, SwapForm, WalletBalancesView, WalletConfig); SDK SimpleConnectionProvider busyTimeout (Lukas) + docs.
- Zodl task list P0s still open (app bugs, separate from audit): P0-1 restore silent no-op, P0-2a $0 send missing, P0-2d live pending state.

## Checkpoint log
- 2026-07-01: Phase 0 done. Phase 1 agents launched (A–F). Seed findings 1–11 logged in plan.
