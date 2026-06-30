# Restore-balance reporting — re-think (supersedes the over-count-view spec)

**Status:** IMPLEMENTED + field-validated (2026-06-30, syncLogsMac11/12) — **SDK-only, no
FFI rebuild** (reuses the already-shipped `slipstream_v_tx_reconciled` view). swift build +
**546 OfflineTests / 0** + SwiftLint (no new violations) + **cargo `slipstream-core` 169/0**.
This is the focused design; the full narrative of every approach tried and why each failed
is the post-mortem [`2026-06-30-balance-recovery-postmortem.md`](2026-06-30-balance-recovery-postmortem.md).
Supersedes the earlier over-count-view approach (the `slipstream_v_balance_overcount` view
was **proven inert** and removed — see "Why the over-count view fails" below). NOTE: a v1
checkpoint cache keyed on `fullyScannedHeight` froze the balance at 0 for the whole restore
(the engine emits no summary mid-pass); fixed by recomputing every tick — see "When it makes
sense" below.

## The problem (user's framing)

During a recent-first **restore**, the displayed balance is wrong in a way that
reads as a bug: it climbs **4 → 8 → 4** (over-count), or shows **0 ZEC next to a
visible 4 ZEC transaction**. The user's bar, in their words:

- The goal is **not** the perfect/instant balance. Just **report *some* balance**.
- Compute it **at sensible checkpoints** (a scan range finished, transactions
  discovered) — **not per frame / per %**.
- A mid-run value that **pops up and down and converges** is fine and expected
  (the old SDK did exactly this).
- **`0` until the end is acceptable.** A **broken/over-counted** value is the enemy.
- **The SDK must not persist anything.** No frozen-snapshot-to-disk.
- Ship **Beta 3 ASAP** — minimal, reliable, stable.

## Root cause (confirmed, upstream-inherent)

`get_wallet_summary` balance = **sum of unspent notes**. Its own doc-comment
(librustzcash `zcash_client_backend/src/data_api.rs`, stable for years):

> "The balances reported … **may overestimate** … in the case that the spend of a
> previously received shielded note **has not yet been detected** by the process of
> scanning the chain."

In recent-first scanning the backfill discovers an **old receipt before its
spend** (the spend block sits in the not-yet-scanned gap), so the receipt counts
as unspent → over-count. `spendable_value` is **not** safe either: a note's
witness can become constructible (its shard is scanned) before its spend is seen,
so the over-count "flips" from the pending bucket into spendable mid-backfill.

### Why the old SDK never over-counts (the model to borrow)

Linear scan keeps a **chronological invariant**: balance reflects only
`[birthday .. fullyScannedHeight]`, the **contiguous-from-birthday** frontier. If a
receipt is counted (≤ frontier), its spend (≥ receipt height) is **also** ≤ frontier,
so it is never missed. `block_fully_scanned` (zcash_client_sqlite `wallet.rs:3208`)
defines exactly this: the end of the earliest "Scanned" range **iff that range
starts at/before birthday**, else `None`. Slipstream already exposes it as
`WalletSummary.fullyScannedHeight`, and the `Historic` backfill **advances** it
from birthday upward during recovery.

### Why the over-count *view* fails

`slipstream_v_balance_overcount` tried to *detect* the double-counted notes via
`nullifier_map`. But during the gap the spend's block is **unscanned**, so its
nullifier is **not in `nullifier_map`** yet → the view finds nothing (field:
`viewOvercountAccts=0` while balance read 8). It is structurally inert. Removed.

## Decision — Direction B: balance = Σ delta over **reconciled** transactions

During recovery, surface, per account:

```
balance = Σ account_balance_delta   over v_transactions
          WHERE mined_height IS NOT NULL
            AND the txid is RECONCILED (not in slipstream_v_tx_reconciled WHERE reconciled = 0)
```

**Why this is correct and never over-counts:** a tx is marked `reconciled = 0`
*exactly when* it has a dangling shielded spend — which is *exactly* the condition
that makes its `account_balance_delta` transiently wrong (a spend reads as a phantom
`+receive`). So **`reconciled = 1` ⟹ that tx's delta is final/correct.** Summing
only correct deltas can never over-count; it converges to the true total as the
backfill links the dangling spends.

**Why B over the alternatives:**

- **vs. frontier-gate (A′ — sum notes ≤ `fullyScannedHeight`):** A′ is also
  over-count-free, but it can **lag Activity** — a genuine *recent* receive (height
  > frontier) shows in the transaction list yet is excluded from the balance →
  reproduces the very "tx visible but balance 0" complaint. B is **consistent with
  Activity by construction**: the balance is the sum of exactly the deltas of the
  transactions the user can see (both gate on the same reconcile view).
- **vs. `0` until `is_synced` (C — ZIP-315 strict):** correct but no mid-run
  feedback. B degrades to C naturally early on (nothing reconciled yet ⇒ 0) and
  then *improves* on it (shows real, growing, consistent values).

**Properties:** stateless (pure read), **no persistence**, **no in-memory freeze**,
**SDK-only** (reuses the already-shipped, Android-inherited `slipstream_v_tx_reconciled`
view + core `v_transactions`) ⇒ **no FFI rebuild for the balance fix**. Includes
transparent uniformly (delta spans pools 0/2/3, net of fees). At completion all txs
reconcile ⇒ B == the true total == the live summary ⇒ smooth handoff, no jump.

### UX mapping

The net per-account balance is surfaced as `orchardBalance.spendableValue` (other
buckets zero) so every consumer reads it correctly:
`AccountBalance.total()` = net (Zodl home `totalBalance`), available shielded = net
(SmartBanner / WalletBalances). The "Restoring N%" SmartBanner is the progress
affordance. Breakdown-by-pool is cosmetically collapsed to Orchard *during recovery
only* — accepted (headline correctness > breakdown fidelity mid-restore).

### "When it makes sense", not per frame

`recoveryBalances()` is recomputed from the live DB on every recovery tick. **(v1 keyed
the recompute on `fullyScannedHeight`; that was a bug — the engine emits no summary
mid-pass, so the frontier is stale for the whole backfill and the balance froze at its
initial 0 until completion: field syncLogsMac10, 2026-06-30.)** The reconcile state
advances via *both* scanning and TIA enhancement (a transparent-heavy wallet updates
during enhancement while `scannedBlocks` is stalled), so no cheap checkpoint signal
reliably tracks it; the query is a cheap SUM over `v_transactions`, and the surfaced
value only moves on a real reconcile, so the display does not churn (the log fires once
per change). This is what makes the balance *climb* during the restore (field showed
25/32 txs reconciled mid-backfill) instead of sitting at 0.

## Phases

- **R1 (SDK DAO):** `TransactionRepository.recoveryBalances() -> [AccountUUID: Zatoshi]`
  + `TransactionDao` raw SQL (defensive `[:]` if the view is absent). Regenerate mock.
- **R2 (Synchronizer):** replace `reconciledRecoveryBalances()` internals with
  `recoveryBalances()` → `recoveryAccountBalance(net:)` pure helper; cache on
  `fullyScannedHeight`. Delete the DIAGNOSTIC dump, `recoveryDiagnosticSQL`,
  `lastDiagnosticLiveTotal`, `reducingShieldedSpendable`, and the `balanceOvercount` read.
- **R3 (Engine cleanup):** remove `BALANCE_OVERCOUNT_VIEW_*` /
  `create_balance_overcount_view` / its 3 tests from `reconcile.rs` and the call in
  `wallet_session.rs`. Keep `slipstream_v_tx_reconciled`. (Inert until the slice is
  rebuilt; the balance fix does not depend on the rebuild.)
- **R4 (Tests):** OfflineTest for `recoveryAccountBalance(net:)`; extend
  `SlipstreamReconcileReadTests` with a recovery-balance read asserting Σ excludes
  unreconciled txids and clamps ≥ 0.
- **R5 (Verify):** swift build + OfflineTests + SwiftLint + `cargo test`; regen mocks;
  rebuild all FFI slices (restores iOS/iPad, applies the engine cleanup). Update STATE.md.

## Kept / unchanged

`isRecovering`, `monotonicRecoveryProgress`, the recover-until checkpoint fallback
(server-down restore fix), and `slipstream_v_tx_reconciled` (transactions) all stay.
Non-recovery balance still passes through the live summary unchanged. Old SDK path
untouched (Rule #11).
