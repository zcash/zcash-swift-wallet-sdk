# Post-mortem: restore-balance reporting in Slipstream

**Status:** RESOLVED + field-validated (2026-06-30, syncLogsMac11/Mac12).
**Scope:** how the wallet balance is reported *during a recent-first restore* (the
deep-recovery window). Steady-state (synced) balance was never affected.
**Audience:** anyone who touches Slipstream balance/Activity, or hits a similar
"value looks wrong while syncing" problem. This is the authoritative write-up; the
focused design lives in [`2026-06-29-balance-recovery-rethink.md`](2026-06-29-balance-recovery-rethink.md).

---

## TL;DR

During a restore the displayed balance was wrong in ways that read as a bug — it
climbed **4 → 8 → 4** (over-count), or showed **0 ZEC next to a visible 4 ZEC
transaction**. We tried **five** fixes over several days; each failed for an
instructive reason. The working solution (**Direction B**) is:

> During recovery, surface per account **`Σ account_balance_delta` over the wallet's
> MINED, RECONCILED transactions** (reusing the `slipstream_v_tx_reconciled` view),
> **recomputed from the live DB on every tick**.

It is SDK-only (no engine/FFI change), stateless (no persistence, no frozen
snapshot), never over-counts, and is consistent with the visible Activity by
construction. Field result: balance climbs `0 → 4.01` and settles to `4.0066` (true
net, after the wallet's historical fees), never inflating; identical on cold restore
and on kill-and-resume.

---

## The problem

### Symptoms (what the user saw)
- **Over-count:** balance `4 → 8 → 4` during a restore; "I saw 8 ZEC :(".
- **Phantom receives:** Activity briefly showed a `+ZEC` that didn't exist.
- **Zero-with-activity:** `0 ZEC` balance next to a visible `4 ZEC` transaction —
  "feels like a bug even though I know it's complex under the hood".
- **Stuck zero:** in one iteration, `0` for the entire restore, correct only at the end.

### The product bar (user's words, the spec we were actually held to)
- The goal is **not** the perfect/instant balance — just **report *some* balance**.
- Update it **when it makes sense** (a range done, txs discovered), **not per frame**.
- A mid-run value that **pops up/down and converges is fine** (the old SDK did this).
- **`0` until the end is acceptable.** A **broken/over-counted value is the enemy.**
- The **SDK must not persist anything.**

## Why this is fundamentally hard

`get_wallet_summary` reports balance as the **sum of unspent notes**. A note counts
as unspent until the wallet has *seen its spend*. librustzcash documents (and has for
years) that this **over-estimates during partial scan**:

> "The balances reported … may overestimate … in the case that the spend of a
> previously received shielded note has not yet been detected by the process of
> scanning the chain." — `zcash_client_backend` `WalletSummary` doc

**Recent-first / spend-before-sync** makes this visible: the scheduler scans a recent
block that **spends** an older note **before** it scans the older block that
**received** it. In the gap, the received note (once backfilled) counts as unspent —
together with the change its spend produced — so the balance reads ~2× truth.

The **old (linear) SDK never showed this** because of a *chronological invariant*: it
scans contiguously from the birthday, so its balance only ever reflects
`[birthday .. fullyScannedHeight]`. If a receipt is counted, its spend (which is at a
*higher* height) is also within the scanned range — so a counted note can never have
an unseen spend. Recent-first breaks that invariant by design.

**The over-count is upstream-inherent, not a Slipstream bug.** The engine has been
frozen since 2026-06-17; the *worsening* over time was data growth, not a regression.
So every fix had to live in the **consumer** (SDK), reshaping *what we report*, not
*how the engine scans*.

---

## Approaches we tried (and why each failed)

### 1. Freeze-and-hold the early spendable balance
**Idea:** capture the spendable balance at the first read (before the over-count
appears) and **hold** it frozen through the backfill; release at `recovery=100%`.
**Why it seemed right:** spendable is ~correct very early; holding avoids the climb.
**Why it failed:** fragile on two axes — (a) it depended on capturing at *exactly* the
right instant (too late ⇒ you freeze the over-count); (b) it depended on `isRecovering`
being correct. When the lightwalletd server was unreachable at restore init,
`recover_until` was written `NULL`, which made `recoveryProgress` read *complete* ⇒
`isRecovering = false` ⇒ the gate **never engaged** ⇒ the raw, fluttering `8/5` balance
was shown with no "Restoring" banner at all (syncLogsMac9). A frozen snapshot is also
*stateful* — the very thing the user later vetoed.

> Spin-off fix (kept): the server-down `recover_until = NULL` hole is closed
> independently — `Initializer` now falls back to the latest bundled checkpoint so a
> restore **keeps its identity** (banner + recovery gating) even with a dead server.
> See `Initializer.initialize`. This is necessary regardless of the balance approach.

### 2. Gate the freeze on a "clean scanned fraction"
**Idea:** only trust/freeze the balance once a clean fraction of the recovery range is
scanned (`recoveryScannedFraction ≥ threshold`).
**Why it failed:** a fresh restore **froze at ~1%** (just under the threshold) and a
kill-and-resume showed `0`. Threshold tuning is a losing game — there is no fraction at
which the *recent-first* partial balance is reliably correct.

### 3. Subtract the over-count using unreconciled-**transaction-delta** values
**Idea:** during recovery, `live − Σ(account_balance_delta of unreconciled txs)`.
**Why it failed:** `account_balance_delta` is an **Activity** signal (a per-tx
movement), **not** a balance over-count. Subtracting it **zeroed a correct balance**
(mac6: "reconciled 0.0000 — live 4.0052 − overcount 4.0052"). Wrong quantity entirely.

### 4. Subtract the over-count using an engine **nullifier view**
**Idea:** a Slipstream-owned SQL view (`slipstream_v_balance_overcount`) summing, per
account, received notes whose nullifier is present in `nullifier_map` (proof the note
was spent on-chain) but which have **no spend-link row** — the exact double-counted
value — and subtract it.
**Why it seemed right:** it targets the precise double-counted notes, note-level and exact.
**Why it failed (the subtle one):** it is **structurally inert**. During the recent-first
gap, the *spend's block is itself unscanned*, so its nullifier is **not yet in
`nullifier_map`**. The view therefore finds **nothing** while the balance still reads 8.
Proven in the field with a one-shot DB dump: `viewOvercount = 0` while `live = 8.0152`
(mac7/mac9). You **cannot detect** the over-counted notes mid-gap — there is no DB
signal for "a spend exists in a block we haven't scanned." This view was removed.

### 5. Capture-correct-balance + **persist** + hold across kill
**Idea:** capture the correct balance once, persist it to disk, replay it during
recovery (survives kill/restart).
**Why it failed:** **vetoed by product constraint** — "the SDK should not persist
anything." (It would also still need to *know* when the captured value is correct,
re-introducing problem #1's timing question.)

### 6. **Direction B** — sum only the transactions whose delta is already correct
**Idea:** stop trying to *detect and subtract* the phantom. Instead, **only count what
is already correct.** A transaction is `reconciled = 0` in `slipstream_v_tx_reconciled`
*exactly when* it has a dangling shielded spend — which is *exactly* the condition that
makes its `account_balance_delta` transiently wrong. Therefore **`reconciled = 1 ⟹ that
tx's delta is final**, and `Σ` over reconciled, mined txs can **never** over-count.
**This is the working approach** — but it took two iterations to land the *trigger*:

- **6a (failed): recompute only when `fullyScannedHeight` advances.** A premature
  optimization. The engine **emits no summary mid-pass**, so that frontier sits at the
  birthday for the *entire* backfill. The checkpoint cache never invalidated ⇒ the
  balance **froze at its initial `0`** until completion (syncLogsMac10) — even though the
  reconcile gate was visibly advancing (`surfacing 0/8 → 25/32`) the whole time. The
  *value* was right; the *trigger* read a signal that doesn't move.
- **6b (works): recompute from the live DB every recovery tick.** The reconcile state
  advances via **both** scanning **and** TIA enhancement (a transparent-heavy wallet
  updates during enhancement while `scannedBlocks` is stalled), so there is no cheap
  "checkpoint" that reliably tracks it. The query is a cheap `SUM` over `v_transactions`;
  the surfaced value only moves on a real reconcile, so the display does not churn (the
  log is guarded to once-per-change).

---

## The final solution

```
recovery balance (per account)
  = Σ account_balance_delta
    FROM v_transactions
    WHERE mined_height IS NOT NULL
      AND the txid is RECONCILED (not in slipstream_v_tx_reconciled WHERE reconciled = 0)
```

- **Where:** `TransactionDao.recoveryBalances()` (the SQL) → `SlipstreamSynchronizer
  .recoveryAccountBalances()` (recompute every recovery tick, wrap each account net via
  `recoveryAccountBalance(net:)`). Non-recovery balance still passes through the live
  summary unchanged.
- **Surfacing:** the per-account net is placed in `orchardBalance.spendableValue` (other
  buckets zero) so every consumer reads it: `total()` = net (Zodl home `totalBalance`),
  available = net (SmartBanner / WalletBalances). Clamped ≥ 0. Transparent is already
  folded into the delta, so `unshielded` stays zero (no double-count).
- **Properties:** SDK-only (no FFI/engine change — reuses the already-shipped reconcile
  view + core `v_transactions`, so Android inherits the approach); **stateless** (pure
  read each tick, no persistence, no frozen snapshot); recovery identity (banner/gating)
  comes from `isRecovering`, untouched.

### Alternatives considered *within* the re-think
- **A′ — frontier-gate** (sum notes received ≤ `fullyScannedHeight`). Also over-count-free
  and is literally the old-SDK model, BUT it needs the **contiguous** frontier, which the
  engine does not report mid-pass (same staleness that broke 6a). Not viable without an
  engine change. It can also lag Activity for a genuine recent receive.
- **C — `0` until `is_synced`** (ZIP-315 strict). Correct but no mid-run feedback.
  Direction B degrades to this naturally early on, then *improves* on it.

---

## Why we believe it works

1. **Correctness invariant (never over-counts).** `reconciled = 1 ⟹ delta final`. A
   delta is only wrong when a spend is unattributed, which is exactly what marks a tx
   unreconciled. Summing only final deltas cannot exceed the truth. Worst case it
   *under*-counts (a held tx's funds appear late) — which the product bar explicitly
   accepts ("0 is fine; broken is the enemy").
2. **Consistency with Activity by construction.** Balance and Activity are driven by the
   *same* reconcile gate, so you can never see a transaction whose value isn't in the
   balance (the original "4 ZEC tx but 0 balance" complaint is structurally impossible).
3. **Convergence to truth.** As the backfill links dangling spends, held txs reconcile
   and join the sum; at completion all are reconciled and `Σ` equals the live total, so
   the handoff to the live summary is seamless (no jump).
4. **Field evidence.**
   - **mac11 (cold restore):** `0 → 4.0100 → 4.0095 → 4.0068 → 4.0066`. Steps *down*
     toward truth as the held self-send/shield txs link and their fees are accounted —
     **never up past ~4.01**, never `8`. 25/32 txs reconciled mid-backfill; the held 7
     are net-near-zero internal transfers, so the climbing number tracked true.
   - **mac12 (restore → kill → reopen → finish):** identical convergence to `4.0066`;
     two `recovery ACTIVE` phases (the durable `recover_until` signal survived the kill),
     no reset-to-weird-state, no double-count on resume.
   - Both: `recovery COMPLETE`, `scan queue empty — sync complete`, **zero errors/panics**.
5. **Grounded in canon, not invented.** It reproduces the property the old (linear) SDK
   relied on (only count what's been fully resolved), matches ZIP-315's "report a distinct
   confirmed-spendable" guidance, and mirrors Zashi's spendable-first display.

---

## Trade-offs & known limits

- **Transient under-count.** If the user's funds momentarily live inside a *held*
  dangling-spend tx, that portion shows late (worst case at completion). Accepted:
  under-count ≫ over-count. In practice the held txs are net-near-zero internal
  transfers, so the visible number tracks close to true (field-confirmed).
- **Pool breakdown collapsed to Orchard during recovery.** The whole net is surfaced as
  orchard spendable; the per-pool *breakdown screen* is cosmetically wrong only while
  restoring (the headline is right; the "Restoring" banner gives context). Live breakdown
  is exact post-recovery.
- **Recompute every tick.** A `SUM` over `v_transactions` per recovery tick. Trivial for
  realistic wallets (tens–hundreds of txs); a whale (10k+ txs) could see a few tens of ms
  per tick *during recovery only*. Optimize later if a whale profile demands it (e.g. an
  incremental delta cache keyed on a signal that genuinely tracks reconciliation).
- **Transparent dangling.** We rely on the engine invariant that transparent spends link
  by outpoint at scan time and never dangle (`reconcile.rs`); transparent value is thus
  taken from the delta without a separate gate.

---

## Lessons learned

1. **Don't subtract a phantom you can't observe.** Approaches 3 and 4 both tried to
   *detect and remove* the over-count; the detector either measured the wrong thing
   (tx-delta) or could not see the cause at all (the spend's block is unscanned ⇒ no
   `nullifier_map` row). **Counting only what's provably correct** beat subtracting what
   might be wrong.
2. **The trigger is as important as the value.** 6a had the right number and still showed
   `0` for an entire restore because it recomputed on a signal (`fullyScannedHeight`) that
   doesn't move mid-pass. When a value looks "stuck", suspect the *recompute trigger*, not
   just the formula.
3. **Premature caching caused two of the failures.** The frozen snapshot (#1) and the
   frontier-keyed cache (#6a) both broke. For a value derived from a continuously-changing
   DB, **recompute from source** unless profiling proves you must cache — and if you cache,
   key on a signal you've *verified* advances.
4. **Field logs are not optional.** The one-shot DB dump proved approach #4 inert; the
   `balance: recovery …` log (guarded, once-per-change) localized #6a's freeze in one read.
   Keep cheap, structured, change-gated observability in the recovery path.
5. **Match the canonical wallet before inventing.** The answer was latent in the old SDK's
   chronological invariant, librustzcash's `WalletSummary` doc, ZIP-315, and Zashi. The
   research phase (those four sources) is what reframed the problem from "correct the
   number" to "only report the resolved part."
6. **Respect the product constraint as a design input.** "No persistence" wasn't an
   obstacle; it forced the *stateless* framing that turned out cleaner and more robust than
   any frozen/persisted snapshot.

---

## References
- Design spec: [`2026-06-29-balance-recovery-rethink.md`](2026-06-29-balance-recovery-rethink.md)
- Code: `Sources/ZcashLightClientKit/DAO/TransactionDao.swift` (`recoveryBalances`),
  `…/Repository/TransactionRepository.swift`, `…/Slipstream/SlipstreamSynchronizer.swift`
  (`recoveryAccountBalances`) + `…+PureHelpers.swift` (`recoveryAccountBalance`),
  `…/Initializer.swift` (server-down `recover_until` fallback),
  `slipstream/core/src/reconcile.rs` (`slipstream_v_tx_reconciled`; the inert
  `slipstream_v_balance_overcount` removed here).
- Tests: `Tests/OfflineTests/SlipstreamReconcileReadTests.swift` (DAO read),
  `…/SlipstreamOfflineTests.swift` (`recoveryAccountBalance`).
- Field logs: syncLogsMac5/6/7/9 (failures), syncLogsMac10 (the trigger bug),
  syncLogsMac11/12 (the working fix).
- Upstream: librustzcash `WalletSummary` doc; ZIP-315; `block_fully_scanned`
  (`zcash_client_sqlite/src/wallet.rs`).
