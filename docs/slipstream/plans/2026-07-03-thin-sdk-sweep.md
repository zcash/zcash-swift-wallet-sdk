# Engine API v2.1 — the thin-host sweep (boundary review, round 2)

**2026-07-03 · Autonomous deep analysis (Lukas: "ideally, the SDK is a thin layer… SDK does
almost no computation or math — go through slipstream related things, make a plan and spec").
Status: DRAFT — awaiting Lukas approval (one gate, same discipline as Phase A).
Companions: `ENGINE_API_V2.md` (§0 = the approved v2 contract + vetoes — all respected here),
`2026-07-01-engine-sdk-boundary-review.md` (round 1), the balance postmortems.**

---

## 1. Goal and the thin-host definition

After v2 (Phases B/D/E), the SDK still contains ~550 lines of wallet **math, derived wallet
state, and sync policy**. This sweep names every remaining piece, sinks what belongs in the
engine, and pins what legitimately stays.

**Definition — a THIN host does exactly four jobs:**
1. **Marshalling** — FFI calls, one-line SELECTs over engine-owned views (Channel 2).
2. **Delivery** — Combine/async surface, poll timer, platform lifecycle (start/stop hooks).
3. **Keys & broadcast** — seed handling, keychain, signing, submission (v2 §2 items 8–9,
   deliberate).
4. **Files & platform resources** — DB paths, wipe/rewind file orchestration, bundled
   checkpoints.

Everything else — anything that *derives wallet truth* (progress %, balances, recovery state,
visibility, "did the tx set change", "is the tip fresh") — is engine domain. The v2 promise
("zero wallet math in your code") is the acceptance test.

**Non-goals:** no public `Synchronizer` API change; no schema tables (the §0 veto stands); no
touching the frozen old-SDK sync path; transparent-pool engine ownership (flagged v3, §5).

---

## 2. Archaeology round 2 — every remaining SDK computation, with verdict

Everything below survives in today's `SlipstreamSynchronizer.swift` (1630 lines),
`+PureHelpers.swift` (287), `+StallWatchdog.swift` (65), `TransactionDao` (2 view reads),
`Initializer.initialize` (~95-line slipstream branch).

| # | What (where) | Kind | Verdict | Sinks via |
|---|---|---|---|---|
| R1 | **`zcashlc_slipstream_wallet_summary` NEVER CONSUMED** — `getAccountsBalances` still branches host-side (recovering → DAO Σ-view read + `recoveryAccountBalance(net:)` mapping; else → legacy `getWalletSummary`); `recoveryAccountBalances()` re-runs per recovery tick | **Phase-D gap** — the FFI exists (rust/src/lib.rs:4646), complete with phase resolution + fail-safe | **CONSUME IT** | D-1 |
| R2 | `cachedSummary` lifecycle + fetch cadence policy (`summaryFetchInterval`, `kickSummaryFetchIfNeeded`, `kickBoundarySummaryFetchIfNeeded`, `applySummaryFetchResult`, one-in-flight guards, 3 s/20 s timeouts, T5.5 no-fetch-while-syncing, F2 boundary trigger off `rangesCompleted`) — ~150 lines + `withTaskTimeout` | Sync-cost POLICY (rations the expensive shard walk) | **ENGINE** — the engine knows its own boundaries/state first-hand; the unified summary FFI should ration internally (cache between boundaries, never walk mid-scan, refresh on Done/boundary/idle-interval) so hosts may call it *whenever they like, cheaply* | E-1 |
| R3 | `[#1591]` stale-tip spendable masking parity: `chainTipAtRunStart`, `chainTipMarkedThisRun`, `markChainTipFlagIfNeeded`, pure `shouldMarkChainTipUpdated`, `SDKFlags.sdkStarted/sdkStopped` 120 s window interplay — ~70 lines reproducing `UpdateChainTipAction` semantics | Derived wallet truth ("is the tip fresh enough to trust spendable?") | **ENGINE** — the engine is the thing refreshing the tip (`engine.rs` update ordering); the unified summary masks spendable itself while ITS pass hasn't refreshed the tip. The Swift-side mask keyed on `SDKFlags` never fires for slipstream once balances stop flowing through the legacy wrapper | E-2 |
| R4 | First-suggest silence compensations ×3: (a) `currentlyRecovering` seeded from `isRecovering(summary)` in prepare/start + the D-2 adopt-guard in tickPoll; (b) pre-first-suggest progress hold via `summaryProgress(cachedSummary)`; (c) `initialState(from:)` warm cold-launch emission math | Derived wallet truth papering over the engine's known §0 gap ("before the first suggest round the snapshot lies") | **ENGINE** — seed `is_recovering` + `progress_permille` AT OPEN from the persisted DB (`recover_until_height` presence + scan-queue/summary equivalents). The snapshot must be truthful from `open()`, not from the first suggest round | E-3 |
| R5 | `composeProgress` + `summaryProgress` (PureHelpers) — a verbatim replica of old-SDK `ScanAction` progress math | Wallet MATH (the exact class v2 §0.3 said `progress_permille` REPLACES) | **DELETE** — dies with R4; nothing else calls it once the snapshot is truthful from open | E-3 |
| R6 | foundTransactions decision strategy: `lastEnhancedCount` counter-watch, SyncDone(tag-3) fallback, recovery incremental-reveal + `lastSurfacedReconciledCount` dedup, `wasRecovering` edge detection — 3 branches, ~60 lines | Derived truth ("did the *visible* tx set change?") | **ENGINE** — snapshot gains monotonic `tx_set_version` (u64, additive at end per padding convention): bumps exactly when enhancement/reconcile/mempool/submit-poke changes the visible set. Host rule becomes one line: version changed → fetch + emit. Delivery (Combine) stays host per v2 §2 #4 | E-4 |
| R7 | `forceCounterProgressUntilDone` + `counterProgress` (importAccount re-scan must read 0→100; the session-monotonic floor masks it) | Progress POLICY compensating engine-side floor behavior | **ENGINE** — re-baseline the session floor when the scan scope EXPANDS (new account's birthday below the frontier ⇒ min_birthday drops ⇒ reset floor + emit a fresh pass denominator). The import re-scan then reads as a genuine climb through the blessed `progress_permille`, no host bypass | E-5 |
| R8 | importAccount orchestration: host fetches chain tip (lightwalletd), maps checkpoint → treestate, sets `recoverUntil = tip`, clears caches, restarts the pass — ~45 lines | Provisioning POLICY + transport | **ENGINE (primitive)** — `restore_anchor` FFI: engine returns {tip, treestate} using ITS transport with the offline fallback POLICY inside (checkpoint floor, `max(…, birthday+1)`); plus pass-restart-on-scope-change folded into E-5. Host keeps the *account creation call* (UFVK/seed stay host — v2 §2 #8) | E-6 |
| R9 | Initializer restore/new derivation (~50 of its 95 lines): tip fetch + offline `recover_until` fallback (syncLogsMac9 fix), reorg-safe treestate fetch for NEW (`tip − maxReorgSize`), server-height reconciliation | Same class as R8 — provisioning policy + transport | **ENGINE (same primitive)** — `restore_anchor(intent: restore(birthday) | new)` returns the anchor; the derived-mode logging + `createAccount(seed:…)` call stay host (seed never crosses). The *decision table* (existing/restore/new) is 6 lines and stays host — it is interface, not math | E-6 |
| R10 | `recoveryAccountBalance(net:)` Direction-B mapping + `zecString` + `lastLoggedRecoveryTotal` log-dedup | Wallet math + diagnostics | **DELETE** — the unified FFI already applies the identical mapping Rust-side (its doc: "the SDK's field-validated Direction-B mapping") | D-1 |
| R11 | `droppingUnreconciled` + `reconciledVisible` + `TransactionDao.unreconciledTxids()` (view read + Set filter) | The §0-amended one-line host rule (`visible = reconciled OR NOT is_recovering`) | **STAYS HOST** — approved shape; a view cannot read the snapshot flag (why `v_tx_visible` died with the table veto). Revisit only if a state table is ever un-vetoed | — |
| R12 | `transactionsWithState` (state from `latestHeight` via `Overview.getState`) | Presentation mapping over host types | **STAYS HOST** (thin: one map) | — |
| R13 | Stall watchdog: predicate `isSyncStalled` + threshold + loud log | Host POLICY on the engine-measured `stalledSeconds` (v2 §2 #6 split, already done) | **STAYS HOST** (1-line predicate) | — |
| R14 | `PendingStopSlot`, poll timer, actor plumbing, `.stopped` emission rules | Platform concurrency/delivery | **STAYS HOST** | — |
| R15 | Seed↔account guard (ZINIT0006), `isSeedRelevantToAnyDerivedAccount`, keychain | Keys | **STAYS HOST** (v2 §2 #8) | — |
| R16 | Broadcast/submission (`submitTransactions`, multi-server #1757, `evaluateBestOf`, `switchTo(endpoint:)`) | Shared SDK transport policy | **STAYS HOST** (v2 §5 decision; revisit only with an engine-transport unification RFC) | — |
| R17 | Transparent trio (`refreshUTXOs`, `checkSingleUseTransparentAddresses`, `updateTransparentAddressTransactions`, `fetchUTXOsBy`) — service fetch → `putUTXOs` orchestration | Transport + upstream calls | **STAYS HOST for v2.1; flagged v3** — sinks naturally the day the engine owns the transparent pool (roadmap); do not build a temporary half-move | — |
| R18 | `estimateBirthdayHeight`/`estimateTimestamp` (bundled-checkpoint interpolation), `rescanFrom`, `rewind`/`wipe` file orchestration, ZcashError mapping, `debugDatabase` | Platform resources + host files + debug | **STAYS HOST** | — |

**The round-2 pattern:** round 1 moved the *semantics* down but left three leaks — a built-but-
unconsumed FFI (R1), policies that exist only because the snapshot lies before the first suggest
round (R4/R5), and policies that exist only because the engine doesn't react to scope changes
(R7/R8/R9). Close those three classes and the remaining Swift is marshalling + delivery.

---

## 3. The deliverables (all additive; C-ABI padding convention respected)

### D-1 — Consume the unified summary (SDK-only, NO FFI rebuild) ⭐ first, cheapest
**AMENDED AT IMPLEMENTATION (2026-07-03):** the unrationed FFI runs the full summary walk per
call ON THE ENGINE ACTOR (serialization with `close()` is what makes it use-after-free-proof),
so it must not ride the hot paths — mid-scan it would starve `snapshot()`/`drainEvents()`
polls, and per-recovery-tick it would resurrect the T5.5 parasite. Phase-1 scope is therefore
the COLD paths, and the R10 deletions move to Phase 2 (E-1 is the enabler, not an optimization):
- Shared `WalletSummary.fromFFI` + `withSpendableMasked()` extraction (legacy wrapper refactored
  onto them, behavior-identical).
- `SlipstreamEngine.walletSummary()` + `unifiedWalletSummary()` (mask applied host-side until E-2).
- CONSUMED AT: `prepare()` seed (a mid-restore relaunch now seeds recovery-SAFE balances — a
  correctness improvement over the legacy seed), the state≠1 cadence fetch, and
  `getAccountsBalances()` when not recovering (value-identical passthrough).
- STAYS UNTIL E-1: the per-recovery-tick view read (+ `recoveryAccountBalance(net:)` mapping,
  `TransactionDao.recoveryBalances()`) and the mid-scan boundary fetch (legacy `@DBActor` call —
  safe: its balances are never surfaced while recovering, and equal the unified passthrough
  otherwise).
- Field value now: lib.rs:4646 is exercised on device (prepare + idle) before Phase 2 leans on it.

### E-1 — Cadence inside the summary FFI (engine)
`zcashlc_slipstream_wallet_summary` gains an internal refresh policy keyed on the engine's own
state: never walk while Syncing; refresh at range boundaries (`rangesCompleted` is its own
counter), on Done, and at an idle TTL; serve the cached summary otherwise. Host calls become
unconditional. Deletes SDK R2 (~150 lines + timeouts + task lifecycle).

### E-2 — Tip freshness as an engine fact (`snapshot.tip_fresh`) — REVISED AT IMPLEMENTATION
Original shape ("mask inside the FFI") is UNIMPLEMENTABLE without an ABI break: the C
`AccountBalance` is an array-element struct (appending an `awaiting_resolution` field changes
the stride), so the mask's awaiting-resolution shift cannot be expressed FFI-side. Revised
split: the ENGINE owns the FACT — `snapshot.tip_fresh` (end-appended, padding-stable),
computed with the exact `shouldMarkChainTipUpdated` semantics at the source (tip captured at
`start()`, fresh on tip-change or Done, survives <120 s stop→start hops) — and the host keeps
the 3-line `withSpendableMasked()` transform keyed on it. Still deletes all of SDK R3 (the
derivation machinery + `SDKFlags` parity calls); recovery balances are never masked (parity).

### E-3 — Truthful-from-open snapshot (engine)
At `open()`: seed `is_recovering` from persisted `recover_until_height` vs frontier, and seed
`progress_permille`'s floor from the persisted scan state (the same inputs the first suggest
round would use). Contract addition to HOSTING.md: *"the snapshot is truthful from open — hosts
must not compensate."* Deletes SDK R4+R5 (~120 lines incl. `composeProgress`/`summaryProgress`/
`isRecovering(summary)`; `initialState` becomes a trivial snapshot→state mapping).

### E-4 — `tx_set_version` (engine, snapshot field, additive at end)
Monotonic u64 bumped on: enhancement writes, reconcile transitions, mempool/submit poke
(tag-5 sources). Host: `version != last → fetch + emit foundTransactions`. Deletes SDK R6.

### E-5 — Scope-expansion re-baseline (engine)
On a suggest round whose min-birthday dropped (imported account) or whose queue grew beyond the
session floor's basis: reset the session-monotonic floor + expose the new pass denominator.
Deletes SDK R7 (`forceCounterProgressUntilDone`, `counterProgress`).

### E-6 — `restore_anchor` primitive (engine FFI)
`zcashlc_slipstream_restore_anchor(intent)` → `{height, treestate}`:
- `restore(birthday)` → tip via engine transport; offline fallback = bundled-checkpoint floor
  with `max(checkpoint, birthday+1)` (the syncLogsMac9 rule, moved verbatim);
- `new` → reorg-safe `tip − maxReorgSize` treestate fetch.
Consumed by `Initializer.initialize` (restore/new branches) and `importAccount`. Keys never
cross; the host keeps `createAccount`/`importAccount` calls and the 6-line mode table.
Note: checkpoints/treestates are currently a host bundle — the engine fetches treestate from
lightwalletd (it already speaks to it); the host passes its bundled checkpoint only as the
offline fallback input.

---

## 4. What the SDK looks like after (the acceptance shape)

`SlipstreamSynchronizer` ≈ 950–1050 lines (from 1630): FFI pass-throughs, Combine delivery,
poll timer, keys/broadcast, files. `+PureHelpers` ≈ 60–80 lines (from 287): `transactionsWithState`,
`isSyncStalled`, `reconciledVisible`, `PendingStopSlot`. **Grep-list that must return empty:**
`composeProgress`, `summaryProgress`, `isRecovering(`, `recoveryAccountBalance`,
`recoveryBalances`, `forceCounterProgressUntilDone`, `counterProgress`,
`shouldMarkChainTipUpdated`, `kickSummaryFetch`, `cachedSummary`.
Estimated net deletion: **~550 lines of policy/math → ~80 lines of consumption.**

Every deliverable lands in the engine/FFI where the CLI (second host) and Android inherit it —
the CLI gains a `watch --summary` assertion per E-1/E-3 as the second-host acceptance proof.

---

## 5. Phases and gates

| Phase | Scope | Rebuild | Gate |
|---|---|---|---|
| **1** | D-1 (consume unified summary) | none (FFI shipped in current slice) | swift build + OfflineTests + device restore-climb |
| **2** | E-1 + E-2 (summary cadence + tip mask, engine) | full FFI | cargo tests (cadence + mask) + CLI summary probe + device catch-up/restore |
| **3** | E-3 (truthful-from-open) + delete R4/R5 | full FFI | cold-launch device matrix: synced-relaunch / mid-restore-relaunch / fresh; Tor cold start (the multi-tick window) |
| **4** | E-4 (`tx_set_version`) + delete R6 | full FFI | cargo ring/version tests + device: send/receive/restore-reveal + post-submit pending row |
| **5** | E-5 + E-6 (+ delete R7/R8/R9 policy) | full FFI | importAccount 0→100 device test (Keystone add w/ old birthday); offline-restore fallback unit test |
| — | STATE.md + HOSTING.md + book updates | — | per phase, same commit |

Order rationale: Phase 1 is pure consumption (no Rust risk) and immediately validates the
crate-side summary in the field; 2–3 kill the biggest host-state machinery; 4–5 are independent
and can reorder. Each phase leaves main green (dual gates: cargo + swift + OfflineTests + lint;
FFI phases end with `init-local-ffi.sh` full build before PR per CLAUDE.md).

## 6. Risks
- **E-3 seed correctness** (worst-case: a wrong from-open flag re-opens the phantom window) —
  mitigated by replaying the 4→8→4 restore fixture + the D-2 guard stays until device-proven,
  then deletes in the same phase.
- **E-1 cadence regressions on A10-class devices** (the T5.5 parasite must not return) —
  the no-walk-while-Syncing rule is a hard invariant in the Rust policy, crate-tested.
- **E-6 transport coupling** (Initializer currently uses SDK `lightWalletService` incl. Tor
  mode) — the engine already owns Tor-aware transport (orchestration lift); anchor fetches ride
  it. SDK service stays for legacy path only.
- **Veto compliance**: no new tables; snapshot additions are end-appended; views unchanged.

## 7. Decision requested (the one gate)
Approve §3 D-1/E-1…E-6 as the v2.1 scope (or strike items). Phase 1 can start immediately on
approval — it is SDK-only and deletes the largest duplicated math today.
