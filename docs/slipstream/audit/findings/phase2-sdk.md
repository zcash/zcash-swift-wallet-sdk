# Phase 2 — SDK (Swift) findings — COMPLETE (2026-07-01)

> Lenses: 2A+2B lifecycle/isRecovering · 2C+2D balances/transactions · 2E+2F restore/rewind/DB ·
> 2G hygiene/privacy. All P0/P1 claims verified by lead against source; refutations documented.
> Severity: P0 funds/seed/crash-mainline · P1 correctness/privacy · P2 robustness · P3 hygiene.

## Verdict (SDK confidence statement)
**One confirmed P0** — the restore seed↔account desync (below), a known field gap now audit-confirmed
as still present. Everything else is P1-and-below. The recovery machinery (isRecovering gate,
fail-safe latch, monotonic floor, recovery balances, reconcile display gate) is **verified sound
end-to-end**; the slipstream Swift tree has **zero force-unwraps/try!/fatalError on mainline paths**,
clean logging privacy, all error codes defined, ~85% offline-test coverage of critical behaviors,
and the `[send-debug]` TEMP logs are ALREADY REMOVED (stale memory note).

## Confirmed P0

### SDK-P0-1 [P0 | VERIFIED by lead] Restore with a new seed silently no-ops → seed↔account desync (funds-loss adjacent)
- **Initializer.swift:461-462**: `let existingAccounts = try await rustBackend.listAccounts();
  if let seed, existingAccounts.isEmpty { …create account… }` — with a NEW seed and a non-empty
  accounts table the block is skipped entirely: no account creation, **no seed↔account validation,
  no error**. The derivation comment even documents the assumption ("account already exists → existing
  wallet → just open it") — nothing enforces that the keychain seed matches the stored account.
- **Impact chain** (matches the 2026-06-27 field report): restore over an existing wallet → keychain
  holds seed B, data.db still holds seed A's account → UI shows seed A's balance AND RECEIVE ADDRESS
  (user can receive funds they cannot spend) → send fails ZRUST0002. Funds-loss adjacent.
- **Fix (SDK-owned, app-independent)**: at prepare/initialize, when `seed != nil` and accounts exist,
  derive the UFVK/fingerprint from the seed and compare to the stored account; on mismatch either
  throw a dedicated ZcashError (app decides wipe) or wipe-and-recreate per policy. Plus doc: apps must
  wipe() before restoring a different seed. (Zodl-side wipe-on-restore checked in Phase 3.)
- Confidence HIGH. → Fix wave item #1.

## P1

### SDK-1 [P1] stop()→start() ordering inversion can kill a fresh pass
- SlipstreamSynchronizer.swift:369-380: sync `stop()` detaches `Task { await engine.stop() }`; a rapid
  `start()` can enqueue engine.start() first → the late stop aborts the NEW pass. No DB risk (engine
  pass_lock, Phase 1) — worst case a killed pass until next poll/start. Fix: await the pending stop
  at the top of start(). (Downgraded from agent P0.)

### SDK-5 [P1] rewind() misses the cache/counter resets that wipe() performs
- rewind (~:1238-1244) calls truncateToChainState but does NOT reset `cachedSummary`,
  `lastSummaryFinishDate`, `lastLoggedRecoveryTotal`, `recoveryReleasedByError`, `lastRangesCompleted`
  (wipe does, :1277-1296). Post-rewind balance/summary reads serve pre-rewind cache until the next
  pass; boundary-summary refresh comparison can mis-fire. Fix: mirror wipe's reset block. Trivial.

### SDK-6 [P1 | contingent — folds into ENG-2] Keystone recovery balance frozen if imported-account nf rows are NULL
- recoveryAccountBalances() (:482, 776, 798-820) sums Σ delta over MINED **RECONCILED** txs; if a
  UFVK-imported account's spends never reconcile (ENG-2 premise), that account reports 0 for the whole
  restore, silently (missing key → `?? .zero`). Severity rides on the ENG-2 device-DB verification
  (Phase 4 #1). Mitigation regardless: log-once when an account has mined txs but zero reconciled.

## P2

### SDK-7 [P2 | verified] paginatedTransactions bypasses the reconcile display gate
- :1035 `PagedTransactionRepositoryBuilder.build(...)` returns an unfiltered repo while allTransactions
  (:1039) and find(from:) (:1043) apply `droppingUnreconciled`. During recovery, any UI using the paged
  path can show provisional (phantom-able) txs. Fix: decorate the paged repo or document the contract.
  (Phase 3 checks whether Zodl uses it.)

### SDK-8 [P2] No pending-tx emission path in the slipstream synchronizer — probable root of app bug "live pending state not appearing"
- foundTransactions fires on enhancedTxs advance / SyncDone; a freshly-SUBMITTED (unmined) tx surfaces
  only when the engine next sees it (mempool session → decrypt_and_store → tick). ENG-5 (mempool
  session dies on one bad tx) compounds it. The old SDKSynchronizer path had pending-tx streams.
  Fix options: emit foundTransactions on submit success (from the stored pending row), or poll pending
  rows in tickPoll. → cross-checked in Phase 3 (where does Zodl's Activity get pending rows?).

### SDK-2 [P2] SlipstreamSynchronizer is a class, not an actor — cross-task mutable state
- :32 `public final class`; `currentlyRecovering`/`cachedSummary`/`isRunning`/counters written from the
  poll task, read from API callers. Benign-in-practice on arm64; Swift-6 strict concurrency will reject.
  Fix: actor-ize (mirrors SDKSynchronizer) or single-executor confinement.

### SDK-9 [P2] Recovery balance clamps negative sums to zero silently
- +PureHelpers.swift:140-147: `max(0, net)` — a negative Σ (possible transiently with self-sends
  mid-backfill) is hidden; if persistently negative it signals a reconcile inconsistency. Fix: keep the
  clamp, add a log-once when net < 0.

## P3
- **SDK-3** importAccount `try? await start()` — deliberate + documented ("a restart hiccup must never
  fail an otherwise-successful import"); optional: log the discarded error. Not a defect.
- **SDK-4** Engine handle free contract: close() nil-ing + deinit backstop verified; document "exactly
  once via close()" (pairs ENG-9).
- **SDK-10** Recovery gate can hold last state if ALL summary fetches fail without a terminal engine
  state — marginal (Error latch covers the real wedge); optional failure-counter release.
- **SDK-11** MIGRATING.md missing the WalletInitMode-removal breaking change (CHANGELOG has the
  commits; MIGRATING has no prepare() signature guide). Write the migration section.
- **SDK-12** `SlipstreamEngine` is public but internal-only in practice — consider internal next major.
- **SDK-13** Counter-reset invariant (engine counters monotonic per handle; SDK mirrors reset only at
  wipe/switchTo) is correct but undocumented — one comment prevents a future "fix" from breaking it.
  (2C/2D's counter-reuse P2 REFUTED on this basis: reset sites align with handle lifecycle.)

## App-bug verdicts (from SDK evidence, for the Zodl fix list)
- **"$0 send never appears" (P0-2a)**: NOT an SDK filter — recoveryBalances/find() have no value
  filter; a fee-only send is a small negative delta and passes. Prime suspect: app-side value/dust
  filter or sent/received bucketing. → Phase 3 confirms in Zodl.
- **"live pending/swapping state missing" (P0-2d)**: SDK gap SDK-8 above (+ ENG-5). Fix belongs in SDK.

## Refuted / reclassified agent claims
- 2A/2B "P0 stop race" → P1 SDK-1 (engine serializes; recovery automatic).
- 2A/2B "P0 importAccount try?" → P3 SDK-3 (documented deliberate tradeoff).
- 2A/2B "P1 didSet races" → superseded by SDK-2 (isolation posture; didSet itself is sync).
- 2C/2D "P2 enhancedTxs counter re-use" → REFUTED; documented invariant (SDK-13).
- 2C/2D "P0 Keystone frozen balance" → contingent P1 (SDK-6) pending ENG-2 verification — the SQL/nf
  premise is engine-side; do not double-count as an SDK P0.

## Verified-OK (SDK invariants checked and sound)
1. **[send-debug] TEMP logs REMOVED** (grep zero hits — stale memory note corrected).
2. **No `try!` / `as!` / force-unwrap / fatalError** anywhere in the slipstream Swift tree.
3. **Recovery gate end-to-end** (pure derivation, Error latch, reset-on-start, per-tick resolve,
   gate-before-balance ordering).
4. **foundTransactions dual path** compensates FFI ring drops at pass end (closes Phase-1 OQ-2).
5. **wipe()** ordering + file deletion (data.db, -wal, -shm, fsBlockDb) + loud failure propagation.
6. **prepare() idempotency** — initDataDb idempotent Rust-side; no Swift-side double-migration.
7. **Error codes** ZRUST0093-0097 all defined/generated; state==2 → rustSlipstreamSyncFailed(tip).
8. **Logging privacy** — heights/counts only; the one ZEC-amount log is .debug-level (acceptable).
9. **Monotonic recovery progress floor** + stall watchdog (log-only, no auto-restart).
10. **SimpleConnectionProvider busyTimeout=5s (uncommitted WIP) validated correct & complete —
    recommend commit** (pairs with ENG-1's engine-side timeout).
11. **Chain-tip flag parity** with the old sync path (no double-mark; SDKFlags reset on stop).
12. **Offline tests**: 78 tests, ~85% of critical slipstream behaviors (gaps: isolated init-mode
    derivation units, full importAccount e2e).

## Open questions carried forward
- OQ-6 (→P3): does Zodl wipe() before restore (app side of SDK-P0-1)? Where does Zodl's Activity get
  pending rows (SDK-8)? Does Zodl use paginatedTransactions (SDK-7)? Any app-side $0-value filter (P0-2a)?
- OQ-1 (→P4, unchanged): device-DB nf check for the Keystone account (decides ENG-2/SDK-6 severity).
