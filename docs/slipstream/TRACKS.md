# TRACKS — the one-page "where are we" (both repos)
**Updated 2026-07-02. This file is the anti-lost map: 4 tracks, their state, who's blocked on what.
Detail lives in the linked docs; this page only ever says what's ACTIVE, DONE, or PARKED.**

## 1 · SHIP (Zodl app bugs) — **Beta4 punch list: ALL 11 IMPLEMENTED `518c57f5`** (2026-07-02,
autonomous hour; both schemes green on fresh all-slice FFI; VISUAL PASS = Lukas next)
→ **`secant-ios-wallet/docs/macos/BETA4_PUNCHLIST.md`** (per-item status at top; tasks B4-1..11).
Highlights: B4-3 account-switch → reset-to-root (DECIDED, new macOS nav class); B4-4
import-during-restore dead OK (SDK/engine contract question); B4-5 spendable spinner must go
offline-first (Harry's 14–30s = suspected gRPC timeout); B4-10 = split-view stale-gate class
sweep; B4-11 = the parked MacCard-browser trap (Beta4 fix: external browser).
Prior wave: Keystone shield + banner-dismiss root fix committed `632e84ef`; Harry QA outstanding.
Live-pending (P0-2d) + $0-send (P0-2a) root fixes are in SDK Phase D (poke path) — device re-test.

## 2 · CORRECTNESS (engine + SDK) — ✅ audited · fix wave · boundary phases A–E ALL DONE
- Full 3-repo audit → `docs/slipstream/audit/ZODL_AUDIT_REPORT.md` (engine: no P0; SDK P0 fixed).
- Fix wave **committed `ab6c905c`** (slipstream): seed↔account guard ZINIT0006, post-submit
  foundTransactions, rewind/stop hardening, engine busy_timeout + height guard, docs.
- **Boundary review (engine API v2 per `plans/ENGINE_API_V2.md` §0) — COMPLETE 2026-07-02.
  Lukas: this work = milestone v0.3** (GPU/SIMD renumbered → v0.4); crates bumped 0.3.0
  (`17e7a63e`), published-repo README versioning map updated (`29194509` local):
  ✅ B-1 never-drop event ring (push_event_bounded, 3 push sites unified, overflow warn, 2 tests)
  ✅ B-2 snapshot v2 fields end-to-end — `is_recovering` (scheduler computes from suggested ranges
     vs accounts.recover_until via new WalletSession::max_recover_until; Done/Error force 0 in the
     snapshot = fail-safe latch engine-side), `progress_permille` (session-monotonic fetch_max
     floor; Done folds 1000), `stalled_seconds` (touch-stamped counters) — core struct + lib.rs
     C mirror both extended, 2 more tests.
  ✅ B-3 `slipstream_v_recovery_balance` view (reconcile.rs, installed at WalletSession.open) +
     postmortem replay test (dangling excluded → linked included) + per-account isolation test
  ✅ B-4 `zcashlc_slipstream_notify_tx_change` FFI (emits tag-5 through the normal channel;
     retires the SDK's post-submit emission in Phase D)
  ✅ B-5 unified `zcashlc_slipstream_wallet_summary(handle, confirmations_policy)` — returns the
     SAME `ffi::WalletSummary` type hosts already parse (freed by the existing free fn). Not
     recovering → upstream summary unchanged; recovering → per-account balances REPLACED from
     `slipstream_v_recovery_balance` via the SDK's exact Direction-B mapping (clamped net as
     orchard spendable, breakdown collapsed, unshielded zeroed; missing accounts read 0).
     Marshal-then-override design (helpers in ffi.rs: Balance::zero/from_spendable,
     AccountBalance::override_with_recovery_net/uuid_bytes, WalletSummary::account_balances_mut).
  **PHASE B ENGINE SURFACE COMPLETE** (uncommitted): cargo slipstream-core 176/0, libzcashlc
  check clean, macOS FFI slice rebuild kicked (header gains the 3 snapshot fields + 2 fns).
  KNOWN SMALL GAP (record for C/D): `is_recovering` is scheduler-set on the FIRST suggest round —
  for the few seconds between open() and the first round it reads 0, so the unified summary
  passes through upstream there; decide in Phase D whether to seed it at open (recover_until
  presence + incomplete recovery_progress) or let the SDK's existing prepare warm path cover it.
  ✅ **Phase C — `slipstream-cli watch` DONE + LIVE-SMOKED (2026-07-02)**: new subcommand renders
  state/permille/recovering/stalled + events + balances + visible-tx count with ZERO wallet math —
  only `derive_snapshot` (extracted in ffi_handle.rs so FFI + Rust hosts share ONE derivation) and
  the two documented host rules over the engine views/upstream summary. Live run against a COPY of
  the real wallet on zec.rocks: SyncStarted→Done, permille 0→1000 latch, stall clock ticking, both
  accounts' correct balances (4.00370732 / 0.39151296 ZEC), 170 visible txs. BONUS FIX: the CLI had
  not compiled since the pass-lock refactor (run_session 3rd arg) — repaired. Recovering-path
  rendering is unit-proven (B-3 replay); a live RESTORE demo (fresh --ufvk import) is an optional
  Lukas/darkside run: `slipstream watch --server https://zec.rocks:443 --wallet-dir <fresh> --ufvk
  <ufvk> --birthday <h>`.
  ✅ **Phases B+C COMMITTED `76eaa422`** (2026-07-02, Lukas-approved, not pushed).
  ✅ **Phase D COMMITTED `aeab259b`** (2026-07-02, Lukas: "commit D") — the SDK consumes v2
  behind the same public API: D-1 bridge +3 fields + notifyTxChange(); D-2 recovery gate ←
  snap.isRecovering (+first-suggest guard); D-3 % ← progressPermille; D-4 recoveryBalances ←
  engine view; D-5 emitPostSubmitTransactions → notifyTxChange poke + tag-5 triggers;
  D-6 watchdog ← stalledSeconds.
  ✅ **Phase E COMPLETE (2026-07-02, 4 commits, each gated build+OfflineTests+lint-diff):**
  E-1 `8f3682e7` recovery-gate machinery deleted (resolveRecoveryGate + releasedByError latch +
      setRecoveryGate funnel + summary→gate writes + 5 tests; gate writes: prepare/start seeds +
      tickPoll adoption ONLY — summary fetches refresh balances only). Tests 555→550.
  E-2 `6e70b608` progress floors: engine now SEEDS the permille floor each suggest round from
      global position (global_floor_permille(tip, min_birthday, remaining); wallet_session
      min_birthday()) — cold-launch catch-up reads ~99.9% not 0%, and a relaunched restore
      RESUMES its position (old Swift floor couldn't). Swift monotonicRecoveryProgress +
      syncingProgress + maxSurfacedSyncProgress deleted; tickPoll pre-first-suggest hold
      (Tor cold start) mirrors the D-2 guard. cargo 180/0 (+4); tests 550→544. macOS slice
      rebuilt with the seed.
  E-3 `72f9c72f` watchdog signature machinery deleted (ProgressSignature + watchdogSignature +
      2 vars + 1 test; isSyncStalled predicate + tests kept). Tests 544→543.
  E-4 `55e88f15` **SlipstreamSynchronizer is an ACTOR** (audit SDK-2): all mutable state
      isolated; sync protocol members nonisolated over immutable lets; stop() registers its
      teardown in a lock-guarded PendingStopSlot chain that start() awaits (SDK-1 ordering
      preserved without nonisolated writes); summary fetches hop results via
      applySummaryFetchResult; poll loop self-terminates on dealloc. NOTE: stop()'s .stopped
      emission now lands ms-async (one test adapted). 543/0; lint −2 warnings.
  NEXT: full init-local-ffi.sh (ALL slices) before any PR (FFI behavior changed in B+E-2).
  Zodl device pass: restore + send + pending-appears (poke path) + progress feel (catch-up
  should hold ~100%, restore resumes position after relaunch).

## 3 · macOS PLATFORM (layout/foundations) — F-1 done → ACTIVE: the startup pops
- Foundations verdicts → `secant-ios-wallet/docs/macos/FOUNDATIONS_F1_VERDICTS.md`
  (MacCard = keep+contract, one latent single-slot bug; FixedSidebarWidth = fragility 5/5;
  presentation-registry = the structural investment).
- ✅ **startup pops FIXED + Lukas-verified (2026-07-02)** — (a) centering pop: scene
  `.defaultSize` + state-restoration off + width-purge (`zodlmac_internalApp` + ConfigView);
  (b) sidebar width: restoration removal exposed that restoration had BEEN the late-corrector →
  round-2 fix pins the CONTENT (`.frame(width: sidebarWidth)` in MacSplitView sidebar) so frame 1
  is 240 by construction; FixedSidebarWidth demoted to divider/drag enforcement only.
  **UNCOMMITTED in Zodl** (Lukas verified visually; commit word pending).
- Parked within track: F-2 sandbox adjudications (the sidebar field evidence pre-answers part of
  F-2(b): the pure-SwiftUI pin works, FixedSidebarWidth is a retirement candidate),
  F-3 registry/contract hardening, F-4 a11y.

## 4 · PARKED (nothing in flight)
✅ ~~Published-slipstream-repo re-sync + crate version bump~~ — **DONE + PUSHED 2026-07-02:
v0.3 re-extract live at github.com/LukasKorba/slipstream (`4ac5a1f5`, tag `v0.3.0`)**; gate
green standalone (180+29). Still parked: iPad branch reconciliation ·
Keystone in-app browser (structural, superseded by F-2(a) adjudication) · STATE.md NEXT-ACTION
refresh · committing the audit/plan docs themselves (untracked, say the word).

## Standing facts
Branches: SDK `slipstream` @ 17e7a63e **PUSHED** (2026-07-02, Lukas's go) · slipstream repo @
4ac5a1f5 **PUSHED + tagged v0.3.0** · Zodl `slipstream-macos` @ 518c57f5 (layout pops
`f8dc6637` + Beta4 wave `518c57f5`; NOT pushed — Zodl push not yet authorized).
LocalPackages: FULL all-slice FFI rebuild done 2026-07-02 (v0.3 engine in every slice) —
iPhone/iPad/Mac device builds all current.
Lukas's own WIP (never touched): Zodl pbxproj/eye-PNGs/WalletAccountsSheet/SmartBannerStore@~552/
SwapForm/WalletBalancesView/WalletConfig; SDK docs/slipstream/*.md edits.
