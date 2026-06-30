# Slipstream — Release notes

> Release notes for the Slipstream sync engine (the `slipstream` branch). Slipstream is a
> prototype behind `useSlipstreamSynchronizer`; the old `SDKSynchronizer` remains the default,
> supported path. Shared with the team for review.

## Version history

- **v0.1–v0.2** — the engine rewrite: parallel `GetBlockRange` fetch → in-memory scan → sparse
  in-memory commitment tree + write-behind persist lane. ~**12×** faster than the old SDK (A14
  iPad **25:11 → 2:05**). Shipped; the standalone engine is tagged **`v0.2.0`**.
- **v0.2.5** — **restore & correctness hardening** (this release, 2026-06-30): balance and
  transaction reporting during a restore made correct and **robust to a mid-sync / mid-restore
  kill & resume**, plus network-stall resilience and an init-flow simplification. SDK-side; the
  engine data model is unchanged (the only schema object added is one droppable read-only
  `VIEW`). Details ↓.
- **v0.3** — GPU subtree offload. Built + measured, then **PARKED**: a narrow ~1.1× win that
  regresses high-core devices, so it ships gate-OFF. Algorithmic **work reduction** (decrypt /
  combine), not concurrency, is the real next lever.

---

## v0.2.5 — restore & correctness hardening (2026-06-30)

The headline: during a recent-first restore the wallet now reports a **truthful, never-inflated
balance and transaction list, and the whole thing survives being killed mid-restore** — kill the
app mid-restore, reopen, and it resumes and converges to the *exact same* balance + tx history
(field-validated). All SDK-side; the frozen engine and its on-disk data model are unchanged.

### Added
- **`SynchronizerState.isRecovering`** — a durable, self-correcting "this wallet is restoring"
  signal derived from the persisted `recover_until` height (survives kill/restart; no flag to
  keep in sync).
- Slipstream-owned read-only `VIEW` `slipstream_v_tx_reconciled` — zero rows of its own,
  droppable, data byte-identical to a stock `zcash_client_sqlite` DB (see the reconcile-view
  rationale doc).

### Changed
- **Restore balance** is now `Σ account_balance_delta` over the wallet's **reconciled, mined**
  transactions — it counts only settled value, so it **climbs 0 → true and can never over-count**
  (no more 4 → 8 → 4), and stays consistent with the visible Activity by construction.
- **Restore transactions** surface the moment their delta is final; the transiently-ambiguous
  ones (a recent spend of a not-yet-scanned note) are held back, so no phantom "+receive" flashes.
- **Init flow is derived by the SDK** (account exists ⇒ open, birthday ⇒ restore, none ⇒ new) —
  clients no longer pass a `WalletInitMode`.

### Fixed
- **Mid-sync / mid-restore kill & resume** — hardened + field-proven: the restore identity and
  progress are durable across an app kill, and the balance / tx list converge identically on resume.
- **Network-stall resilience** — a transient server outage no longer restarts the whole pass: the
  direct-connect path retries (capped backoff) and the displayed restore progress never regresses.
- **Server-down at restore start** — if lightwalletd is unreachable when a restore is initiated,
  `recover_until` falls back to the latest bundled checkpoint instead of `NULL`, so the wallet
  keeps its "restoring" identity (banner + gating) instead of showing a raw, fluttering balance.
- Removed an inert `slipstream_v_balance_overcount` view (it could not observe the over-count it
  targeted); the recovery balance is derived from the reconcile set instead.

**Deep dives (for the core team):** balance — `2026-06-30-balance-recovery-postmortem.md`;
transactions / the one schema view — `2026-06-29-reconcile-view-rationale.md`.

---

## v0.2 (P8 — Hardening & Productization)

Engine build at draft: `2026-06-16.t84-devmem`.

### CHANGELOG.md draft entry (when published)

### Added
- **`SlipstreamSynchronizer`** — an actor-based `Synchronizer` implementation backed by the
  new Rust Slipstream sync engine (sparse in-memory commitment tree + write-behind persist
  lane). Selected via `useSlipstreamSynchronizer`; the existing `SDKSynchronizer` is
  unchanged and remains the default/supported path.
- **In-foreground tip-following** (T8.1): a wallet left open at tip keeps tracking the chain
  (jittered 10–30 s probe; a cheap `GetLatestBlock` gates a full catch-up pass) without an
  app-lifecycle restart.
- **At-tip mempool detection** (T8.2): incoming wallet transactions appear as 0-confirmation
  (pending) while still in the mempool, via `GetMempoolStream` + `decrypt_and_store_transaction`,
  surfaced through the existing `foundTransactions` stream. Non-fatal (a failing stream
  disables mempool for the handle and keeps tip-polling).
- **Warm cold-launch reporting** (T8.3.5): on a fresh app launch of an already-synced wallet
  the balance and a truthful sync progress are shown immediately (from the persisted wallet
  summary), instead of momentarily flashing a zero balance / 0 % progress.
- **Device-memory-aware budgets** (T8.4): on memory-constrained devices (<3 GiB) the engine
  automatically derates its fetch/decode budget so spam-era (2022) historic restores do not
  exhaust memory. A `--memory-budget-bytes` flag is available in the `slipstream` CLI.
- **`slipstream` CLI** flags: `--follow`, `--memory-budget-bytes`, plus the existing
  `--sparse`, `--write-behind`, `--chunk-split-bytes` kill switches/tuning.

### Changed
- Transparent-address enhancement now services open-ended `TransactionsInvolvingAddress`
  requests by clamping them to the chain tip, instead of skipping them (T8.5).

### Fixed
- `start()` before `prepare()` now throws `ZcashError.synchronizerNotPrepared` (parity with
  `SDKSynchronizer`) instead of surfacing an internal `rustSlipstreamNotOpen`; a `stop()`
  before `prepare()` no longer mutates the prepared state (T8.3).

---

## MIGRATING.md draft entry (when published)

These are behavioral/API notes for adopters who switch a flow from `SDKSynchronizer` to
`SlipstreamSynchronizer`. Both conform to the `Synchronizer` protocol; the surface is
intentionally compatible, with the following deltas:

- **Progress is poll/counter-based, not summary-based.** During a sync pass the reported
  `.syncing(progress, spendable)` derives from engine counters (and, at cold launch / between
  passes, from the persisted wallet summary) rather than a per-tick `getWalletSummary`. The
  fraction is the wallet's GLOBAL progress; a small catch-up reads ~100 % rather than 0 %.
- **Tip-following changes the state cadence.** At tip the synchronizer reports `.synced`
  between passes and a brief `.syncing` during each catch-up pass — there is no new
  `Following` state code (unknown codes already map to `.disconnected` on older clients).
- **Mempool is at-tip-only and 0-conf.** Incoming mempool txs are stored with
  `mined_height = nil` (rendered as 0 confirmations / pending) and converge to their mined
  height when the block is scanned. This is *not* bug-for-bug identical to `SDKSynchronizer`
  (which stores them with the server tip height); both render as 0-confirmation.
- **No Tor on Slipstream paths (yet).** Slipstream fetch/scan/enhance uses direct TLS. A
  Tor-enabled wallet that switches to Slipstream loses Tor routing for sync traffic until the
  arti-channel integration lands. (Out of scope for P8 — see the gaps chapter.)

### FFI surface additions (`libzcashlc`)
- `zcashlc_slipstream_open` gained a trailing `uint64_t total_memory_bytes` parameter (the
  host physical-memory hint; `0` = unknown → defaults). All other `zcashlc_slipstream_*`
  entry points are unchanged. The Swift `SlipstreamEngine.open(network:)` surface is
  unchanged — it reads `ProcessInfo.physicalMemory` internally.

---

## Flag-gating story (publication gate)

`useSlipstreamSynchronizer.enabledByDefault` controls whether Zodl uses the new engine. The
documented matrix (STATE.md Blockers):

| Build destination | flag | rationale |
|---|---|---|
| User's own dev devices | `true` | every field session exercises the new engine |
| Any handoff / TestFlight / external build | `false` (revert first) | LOCAL-ONLY prototype; old SDK is supported |
| Publication | decision deferred to release review | needs the P8 field record + sign-off |

Publication of these notes is gated on: (1) the [needs-user] device validations (synced-wallet
cold launch + 0-conf receive; iPad A10 spam-era restore survival), and (2) the user lifting
the no-push policy.
