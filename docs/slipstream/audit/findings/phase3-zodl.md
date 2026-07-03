# Phase 3 — Zodl macOS findings — IN PROGRESS

> Lenses: 3A seed/keychain (DONE) · 3B send paths (DONE) · 3C+3E restore-UX/privacy (DONE) ·
> 3D+3F platform sweep + release hygiene (running). Lead verifies all P0/P1 claims before acceptance.

## ⚠ SYNTHESIS: the restore-desync defense is ASYMMETRIC (feeds Phase 4 item #2)
Three verified facts that must be read together:
1. **App guard EXISTS** (3A, HIGH confidence): the restore flow checks
   `isSeedRelevantToAnyDerivedAccount(seedBytes)` BEFORE any keychain write
   (RestoreWalletCoordFlowCoordinator:51-83); mismatch → `differentSeed()` alert → "Start over" →
   `sdkSynchronizer.wipe()` → keychain reset (RootInitialization:633-716). The [#1024] guard.
2. **SDK has NO guard** (Phase 2 SDK-P0-1, verified): `Initializer.swift:461` silently keeps the old
   account for a mismatched seed. Any path around the app guard desyncs silently.
3. **Field bug still open** (Zodl task P0-1): "restore silent no-op (Update→Reset→Restore)" happened
   ON DEVICE despite the guard — so the Update→Reset→Restore SEQUENCE has a hole the flow-level guard
   doesn't cover (candidates: reset's async wipe racing the follow-on restore prepare; partial reset
   [the pre-`ab64efec` keychain-delete no-op era]; a restore entry point that skips the coordinator
   guard). → **Phase 4 must trace the Reset→Restore ordering** and pin the hole.
Verdict stands: SDK-P0-1 remains the systemic fix (SDK-owned seed↔account validation); the app guard
is a strong but single-flow mitigation.

## 3A — seed & keychain (verdicts final)
- **No P0.** Seed-at-rest posture verified STRONG: SE-wrapped only (post-migration), migration
  crash-safe (plaintext deleted only after verify-read; retried next launch), ALL keychain items
  `WhenUnlockedThisDeviceOnly` (no iCloud sync — implicit via accessibility class),
  `mutationQuery` fix correct, resetZashi deletes ciphertext + SE key + DBs (doubly-dead).
- **Seed-input hardening S1-S3 verified implemented** with correct lifecycles (SecureEventInput
  balanced; capture-exclusion restored on exit; clipboard wipe normalized-match, macOS-only by design).
  S4-S7 remain roadmap (P3).
- **Step-3b launch fingerprint guard**: documented as INTENTIONALLY omitted on macOS
  (KEYCHAIN_SE_HARDENING.md:90-95 — launch re-check would prompt every launch; restore-time guard is
  the defense). Audit accepts the rationale BUT notes it leans on the app guard being airtight — see
  synthesis above; an SDK-side non-prompting fingerprint check (UFVK compare, no SE decrypt) would
  close it without prompts. Fold into SDK-P0-1's fix design.
- **ZODL-3 [P3]** PrimedSeedBox plaintext String not zeroable (Swift String, heap; <10min lifetime,
  typically ~100ms) — acknowledged S7 roadmap item.
- **ZODL-4 [P3]** Explicit `kSecAttrSynchronizable=false` belt-and-suspenders missing (implicitly
  blocked today by ThisDeviceOnly).
- **ZODL-5 [P3]** LAContext created off-main for SE decrypt (SecureEnclaveLiveKey:139) — works
  field-proven; Apple guidance prefers main; note only.
- **ZODL-6 [P2, acknowledged design]** Voting hotkey stays plaintext in keychain (vote-power-only
  threat model, documented decision).

## 3C+3E — restore UX + privacy (verdicts final)
- **Privacy verdict, definitive**: ZERO analytics/telemetry/crash SDKs (grep-confirmed none of
  Firebase-analytics/Sentry/Crashlytics/Amplitude/Mixpanel/Bugsnag; Firebase config present but
  `IS_ANALYTICS_ENABLED=false`); no print/NSLog; `Redactable` redacts sensitive types in RELEASE;
  exchange-rate (CMC) is OPT-IN and Tor-aware (`httpRequestOverTor` when enabled); Tor default OFF,
  user-driven ON; third-party endpoints (CMC, voting, Keystone, Near/swap) all consent-gated.
- **Restore UX truthful**: `walletStatus` derived from SDK `isRecovering` (RootInitialization:140-145),
  authoritative over the legacy diagnostic UserDefaults flags; progress capped at 99.9% until real
  completion; stuck-banner fix confirmed (`.upToDate` closes p3/p4/p45 + blocks-counter reset).
- **SmartBanner machine**: deterministic chain, no wedge/starve found; the account-switch shield race
  mitigation (uncommitted) audited as-on-disk and sound; priority4 suppressed on macOS deliberately.
- **ZODL-7 [P3]** Finish deleting legacy `udIsRestoringWallet`/`udIsResyncingWallet` (diagnostic-only,
  cannot contradict UI today; planned Phase-2 cleanup).
- **REFUTED (lead)**: "CMC API key in repo" — `PartnerKeys.plist` is gitignored (only the accessor
  `PartnerKeys.swift` is tracked); key never enters git. Verified-OK.

## 3A/3C/3E verified-OK (added to coverage)
Seed storage/migration/wipe chain; S1-S3; recovery-phrase blur-hide (both platforms); no-analytics;
no sensitive logging; Tor opt-in; redaction in release; camera-only entitlement surface (QR scan).

## 3B — send/transaction paths (verdicts final, spot-check in Phase 4)

### App-bug verdicts (pairs with SDK-8)
- **P0-2d "live pending not appearing" [P1 | confirmed, app+SDK]**: after
  `createAndSubmitProposedTransactions` succeeds, `SendConfirmationStore.swift:326-328` sets the UI
  result and does NOTHING else — no insert into the shared transactions array. The pending
  constructor `TransactionState(pendingSendId:zecAmount:)` (TransactionState.swift:335-346) exists but
  is only used by the details screen. RootTransactions re-fetches only on sync events
  (RootTransactions.swift:22-30, 55-63). Combined with SDK-8 (no pending emission), a fresh send is
  invisible until the next sync/mine. **Fix pair**: SDK-8 (emit foundTransactions on submit) + app
  optimistic insert at the `.success` case (dedupe by txid when the real row lands).
- **P0-2a "$0 send never appears" [verdict: no value filter exists app-side]**: confirmed no
  zero/dust filter in the app's Activity mapping (and SDK has none) — so a $0 send is *valid* and its
  invisibility in the pending window is the SAME gap as P0-2d. CAVEAT (Phase 4 / device): if Lukas's
  $0 send stays invisible even AFTER mining, there is a second cause not yet found — needs a device
  check (does it appear post-mining?).

### Other findings
- **ZODL-1 [P2] Post-submit crash window**: txids are not persisted before the success screen; a
  crash after broadcast leaves the tx invisible until the next sync finds it on-chain (eventually
  consistent, bad UX). Fix: persist submitted txids on `.sendDone`; reconcile on launch.
- **ZODL-2 [P3] Double-submit protection is UI-state only** (`isSending` lock set synchronously before
  auth at SendConfirmationStore.swift:270-282) — adequate (new proposal required to resend), note only.

### 3B verified-OK
1. **Spend auth gate (macOS)**: `.sendTapped` → `isSending=true` → SE-decrypt auth
   (`authenticateForSeedDecrypt(.sendFunds)` / `exportWallet(reason:)`) — no code path reaches
   sendTriggered/exportWallet without it; auth failure → `.stopSending`. No unauthorized-spend path.
2. **Keystone PCZT**: build→redact→proofs→scan→submit guards BOTH pcztWithProofs+pcztWithSigs
   (SendConfirmationStore.swift:571) — partial-sig submission impossible; reject/cancel resets PCZTs.
3. **Amount/fee/memo/recipient plumbing**: rounding safe, fee locked at proposal, memo char-limit +
   no-memo-to-transparent, address validated at entry AND proposal.
4. Proposal discarded safely on app-kill pre-send; self-send rendering correct; fee cannot silently
   change between confirm and submit.
