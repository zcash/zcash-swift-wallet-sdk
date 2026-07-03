# Zodl / Slipstream / SDK — Full Audit Report
**2026-07-01 · autonomous audit (Fable 5) · read-only · commissioned by Lukas.**
Method: 14 parallel read-only lenses across 3 layers, every P0/P1 re-verified against source by the
lead. Detail lives in `findings/phase{1,2,3}-*.md`; this is the consolidated deliverable.

---

## Executive summary

**The engine is sound, the SDK has one real P0, the macOS app is secure & private.** Across three
layers I found **1 confirmed systemic P0** (restore seed↔account desync — already a known field bug,
now pinned to exact lines) and **1 contingent P0/P1** (Keystone reconcile via NULL nullifier — one
device query from certainty). Everything else is P1-and-below. The agents proposed **9 "P0"s total; I
refuted 7 against source** — the surviving list is small and real.

**Confidence by repo:**
- **slipstream engine (Rust)** — HIGH. Atomic persistence (proven), serialized passes, supervised
  panics, bounded/retried network, zero sensitive logging, darkside/GPU compiled out of release. No
  confirmed P0. Weakness: robustness at boundaries (event-ring loss, mempool session fragility) + one
  reconcile question.
- **SDK (Swift)** — HIGH on the recovery/balance machinery (verified end-to-end), MEDIUM overall
  because of the restore-desync P0 and the missing pending-tx emission path.
- **Zodl macOS** — HIGH on security & privacy (seed handling, zero analytics, hardening), HIGH on
  platform-port correctness (the sweep found no new gaps beyond the two already-fixed). Ship-blockers
  are the two uncommitted Keystone fixes.

---

## Prioritized fix plan

### P0 — do first

**P0-A · Restore seed↔account desync (SDK, systemic).** `Initializer.swift:461-462` creates an account
only when the accounts table is empty; restoring a *different* seed over an existing wallet silently
keeps the old account → keychain seed B vs data.db account A → app shows A's balance AND receive
address (you can receive funds you can't spend), send fails ZRUST0002. The Zodl app has a *partial*
guard (`resolveRestore` seed-relevance check before keychain write → wipe on mismatch,
RestoreWalletCoordFlowCoordinator:51-83), but the SDK has none, and the open field bug **P0-1
"Update→Reset→Restore no-op" proves a sequencing hole survives the app guard.**
→ **Fix (SDK-owned, closes the class):** at prepare/init, when `seed != nil` and accounts exist,
derive the seed's UFVK fingerprint and compare to the stored account; on mismatch throw a dedicated
error (app decides wipe) or wipe-and-recreate. This is also the non-prompting version of the
deferred SE "step 3b" fingerprint guard. During implementation, trace the exact Reset→Restore ordering
in RootInitialization (resetZashiSDKSucceeded:654 → restoreWallet:358) to confirm the app-side hole.

**P0-B — ✅ CLOSED 2026-07-01 (fix wave, device DB queried read-only).** nf-NULL REFUTED: all 159
notes (43 zodl + 116 keystone) have nf populated — imported accounts are fine. The 5 currently-stuck
`reconciled=0` txs (heights 3397096-3397101, just below recover_until 3397149/150) each carry 1-2
nullifiers that can NEVER link: **external senders' spends inside txs that pay us, and/or spends of
pre-birthday notes** (origin never scanned). Mid-restore, "our note not yet scanned" (hold) and
"never ours" (permanent) are indistinguishable from the DB — the view is inherently approximate, so
the recovery-scoped display gate (`c6bc6b9d`) is the CORRECT fix, not a workaround. Residual: transient
under-count of external receives in the recovery balance, self-heals at completion. Action: document
the invariant in reconcile.rs + test capturing the external-receive permanent dangle. NO view change.
Original (now-superseded) hypothesis follows for the record:
~~**P0-B (contingent) · Keystone reconcile via NULL nullifier (engine↔SDK).**~~ The reconcile view links a
spend only when the spent note's `nf` is present in `*_received_notes` (reconcile.rs `RECONCILE_VIEW_SQL`).
If UFVK-imported (Keystone) accounts have `nf = NULL`, their spends stay `reconciled=0` **forever** →
(1) txs vanish from Activity — your original bug, currently masked by the display gate `c6bc6b9d`; (2)
Keystone recovery balance reads 0 for the whole restore (SlipstreamSynchronizer `recoveryAccountBalances`).
Account-scoping is NOT the cause (refuted — nf is globally unique, view anchored to our txs).
→ **Decisive test (run against a device data.db with a Keystone account that has sent):**
```sql
SELECT 'sapling' pool, COUNT(*) total, SUM(nf IS NULL) nf_null FROM sapling_received_notes
UNION ALL
SELECT 'orchard', COUNT(*), SUM(nf IS NULL) FROM orchard_received_notes;
```
If `nf_null > 0` for the Keystone account → confirmed; fix at `scan.rs:524 reseed_nullifiers` (ensure
it covers imported accounts) and/or make the view treat "spent note row exists for the tx's account"
as reconciled even when nf is NULL. If `nf_null = 0`, the trigger is elsewhere (locator/tx_index) —
the query redirects the hunt. Until confirmed, the display gate keeps it harmless day-to-day.

**P0-C · Commit the two Keystone macOS fixes (Zodl, already written, uncommitted).** Without them,
Keystone shield is dead on macOS and the signing QR wipes on window minimize. Ship-blockers.
Files: MacSplitView.swift (presenter), SendConfirmationStore.swift:208 (pcztForUI), + reject-dismiss
(RootCoordinator) + back button (SignWithKeystoneCoordFlowView). Pending your device test.

### P1 — correctness / robustness that bites users

- **P1-A · No `busy_timeout` anywhere in the engine** (wallet_session.rs opens 3 connections, none set
  it) — the engine half of the SQLITE_BUSY uncatchable-`try!` crash. **Commit your uncommitted
  SimpleConnectionProvider busyTimeout=5s (Swift half) AND add `busy_timeout` to the 3 engine
  connections.** Both halves needed.
- **P1-B · Live pending tx never appears (P0-2d)** — SDK has no pending emission (foundTransactions
  fires on mine/enhance only), and the app never optimistically inserts the pending row (the
  `TransactionState(pendingSendId:)` constructor exists but is unused for Activity). Fix pair: SDK emit
  on submit + app optimistic insert at the `.success` case (dedupe by txid). Same gap explains
  **"$0 send never appears" (P0-2a)** — no value filter exists; it's just invisible in the pending
  window. (Device check: does the $0 send appear AFTER mining? If not, there's a second cause.)
- **P1-C · `rewind()` misses the cache/counter resets `wipe()` does** — post-rewind balance/summary
  serve stale cache. Mirror wipe's reset block. Trivial.
- **P1-D · stop()→start() ordering inversion** can abort a freshly-started pass (detached
  `Task{engine.stop()}`). Await the pending stop at the top of start(). (No DB risk — engine pass_lock.)

### P2 — robustness (engine boundaries + SDK isolation)
Event ring drops oldest at 64 with no log (FoundTransactions loss — SDK DB-resync compensates at pass
end; add the log) · mempool session dies on one bad decrypt (isolate per-tx) · enhancement round aborts
on one bad tx · mempool open has no handshake timeout · verify.rs `height as u32` truncation on hostile
server data · FFI panic mid-mutating-call leaves handle state un-rolled-back · SlipstreamSynchronizer is
a `class` with cross-task mutable state (actor-ize for Swift 6) · post-submit crash window (persist
txids before success screen).

### P3 — hygiene
Published slipstream repo has diverged (reconcile.rs entirely unpublished + 6 files) · crate versions
all `0.0.1` vs "v0.2.5" in notes · STATE.md NEXT ACTION stale (fix WAS committed 6f2153f0) ·
MIGRATING.md missing the WalletInitMode-removal breaking change · finish deleting legacy
`udIsRestoringWallet` · confirm the macOS iCloud CloudDocuments entitlement (inherited from Zashi)
touches nothing sensitive · explicit `kSecAttrSynchronizable=false` belt-and-suspenders · rename/doc
`dangerously_trust_everyone` (it's fs-mistrust file perms, NOT TLS).

---

## Verified-OK coverage (what's proven sound — the confidence map)

**Engine:** atomic block persistence (rows+trees+scan-queue in ONE txn), pass serialization (restart-
safe, test-proven), reorg rewind (mirrors upstream, capped+backoff), write-behind barriers, panic
supervision (→Error(2) events, never silent), **zero sensitive data in logs** (crate-wide),
bounded/retried network (direct 6×, treestate 3×, fetch workers, unary+stream timeouts; Tor never
falls back; mempool non-fatal), TLS webpki roots, exhaustive error taxonomy, safe arithmetic/indexing,
FFI null-safety + by-value snapshot + strict UTF-8, darkside+GPU compiled OUT of release, reconcile
view correctly scoped to our txs.

**SDK:** recovery gate end-to-end (fail-safe latch can't wedge, monotonic floor, gate-before-balance),
foundTransactions dual-path compensates ring drops, wipe() ordering+file-deletion+loud-failure,
prepare() idempotency, **zero `try!`/`as!`/force-unwrap/fatalError on mainline**, `[send-debug]` logs
already removed, all ZRUST error codes defined, 78 offline tests (~85% of critical behaviors).

**Zodl macOS:** seed SE-wrapped only + crash-safe migration + ALL keychain items ThisDeviceOnly (no
iCloud sync), seed-input hardening S1–S3 correct, recovery-phrase blur-hide both platforms,
**spend is SE-auth-gated with no bypass path**, Keystone PCZT can't submit partial signatures,
double-submit locked, amount/fee/memo/address plumbing sound, restore UX truthful (isRecovering-derived),
SmartBanner machine no wedge/starve, **ZERO analytics/telemetry/crash SDKs**, no sensitive logging,
Tor opt-in, redaction in release, camera-only permission surface, **platform sweep found no new
iOS-only-presenter gaps** beyond the two already fixed.

---

## Adversarial verification — what I killed
9 agent "P0"s → 2 survive. Refuted with source evidence: engine flush-atomicity "crash window" (it's
one txn); "Tor skips CA verification" (fs-mistrust file perms, not TLS); darkside-in-release (not in
default features); GPU unwraps (feature off in release); reconcile cross-account nf bug (nf globally
unique + tx-anchored view); enhancedTxs counter-reuse (documented invariant); stop-race and
importAccount-try? "P0"s (engine serializes / deliberate documented tradeoff). Full refutation log in
each phase file so they don't resurface.

## Open items needing a device (not resolvable from source)
1. **P0-B nf query** above — the single most valuable check; decides Keystone recovery correctness.
2. Does the **$0 send** appear post-mining? (Distinguishes "pending-window gap" from a second cause.)
3. Confirm **Sandbox/Hardened-Runtime = YES** in Xcode Signing&Capabilities (build settings show 6
   matches; verify the sense).

## Status
Phases 0–4 complete. Fix wave is a separate, Lukas-triggered effort — the P0s are flagged; nothing was
changed by this audit. Resume anchor: `AUDIT_STATE.md`.
