# `slipstream_v_tx_reconciled` — rationale & compatibility note

**Audience:** librustzcash / zcash_client_sqlite core team (data-model review).
**Status:** shipped in slipstream SDK (branch `slipstream`), commit `9890860e`. Seeking core-team awareness/approval of the one schema addition described below.
**Date:** 2026-06-29.

---

## TL;DR

Slipstream adds **one SQLite `VIEW`** to `data.db` — `slipstream_v_tx_reconciled`. A view is a **stored query, not a table**: it holds **zero rows of its own** and is recomputed on every read from the existing upstream tables. Therefore:

- **The data is 100% byte-identical to a stock `zcash_client_sqlite` database.** No new table, no new column, no new row, no migration-version bump, no change to any upstream object.
- The **only** divergence from a stock DB is a single extra row in `sqlite_master` of `type='view'`.
- **Drop the view and the database is identical to stock**, losing zero information — the view derives entirely from `nullifier_map`, `tx_locator_map`, `transactions`, and `{sapling,orchard}_received_notes`.
- The slipstream **golden oracle still passes 1:1** (it row-diffs every `type='table'`; views are excluded by construction).

So the accurate one-liner is: *"data is identical; the schema carries one zero-data view that slipstream owns and could drop at any time."* — **not** *"slipstream adds a table."*

---

## What exactly was added

A view created idempotently by the engine in `WalletSession::open`, immediately after upstream's `init_wallet_db` runs its migrations:

```sql
CREATE VIEW IF NOT EXISTS slipstream_v_tx_reconciled AS
SELECT t.txid AS txid,
       NOT EXISTS (
           SELECT 1
           FROM nullifier_map nm
           JOIN tx_locator_map tl
               ON tl.block_height = nm.block_height AND tl.tx_index = nm.tx_index
           WHERE tl.txid = t.txid
             AND ( (nm.spend_pool = 2 AND NOT EXISTS (SELECT 1 FROM sapling_received_notes s WHERE s.nf = nm.nf))
                OR (nm.spend_pool = 3 AND NOT EXISTS (SELECT 1 FROM orchard_received_notes o WHERE o.nf = nm.nf)) )
       ) AS reconciled
FROM transactions t;
```

- **Persistence:** the view *definition* persists in `sqlite_master` across restarts (created with `IF NOT EXISTS`, so re-running is a no-op). It is **not** a temp table and **not** scoped to a sync session.
- **Stored data:** none. Every `SELECT … FROM slipstream_v_tx_reconciled` re-evaluates the query against the live upstream tables.
- **Namespacing:** the `slipstream_` prefix avoids any collision with current or future upstream object names.
- **`spend_pool` codes** follow upstream `pool_code` (`wallet/encoding.rs`): `2` = Sapling, `3` = Orchard. Transparent spends can't produce this transient and are intentionally excluded.

---

## The problem it solves

Slipstream scans **recent-first** (spend-before-sync): the recent block that *spends* an old note is scanned before the old block where that note was *received*. During that window, upstream's `v_transactions` computes a transient **positive** `account_balance_delta` for a self-send, so the wallet UI shows a phantom **"+receive"** that later flips to "sent".

This is **upstream-inherent**, not a slipstream bug: `v_transactions` builds the spend side of the delta **only** through `v_received_output_spends → {sapling,orchard}_received_note_spends` (`zcash_client_sqlite-0.21.0` `wallet/db.rs:1027-1048`), and that link only exists once the spent note has been *received*. Until then, the spend contributes 0 and the change reads as income. The wallet's "is this transaction's delta final yet?" question simply isn't answerable from `v_transactions` alone.

The missing signal *does* exist in the DB: an observed-but-unlinked spend lives in `nullifier_map` with no matching `{sapling,orchard}_received_notes.nf`. The view surfaces exactly that, per txid. The SDK then shows a transaction as soon as it reconciles and holds only the still-ambiguous ones — "sooner **and** correct" — instead of the previous workaround of hiding the **entire** Activity until `recovery_progress` hit 100%.

## Why a view (design rationale)

We considered four options. The view is the least invasive that actually works:

| Option | data.db impact | Verdict |
|---|---|---|
| **Edit upstream `v_transactions`** to expose finality | none (it's a view) but **forks upstream's migration** | ✗ Forking the core schema — exactly what we avoid. |
| **Maintain a real table** during scan (insert/delete reconciliation rows) | **new table + rows**, writes on the 12× hot scan path, must stay oracle-identical across both oracle runs | ✗ Hot-path risk + a genuine data divergence. |
| **A slipstream-owned VIEW** (chosen) | **+1 zero-data view**, data byte-identical, oracle-invisible, off the hot path | ✓ Minimal, centralized in the engine, Android inherits it for free. |
| **No view — inline the SELECT in each client** (see below) | **none at all** (100% identical schema *and* data) | ◐ Pristine DB, but every client (iOS/Android/…) re-implements the join. |

The view's properties:

- **Data byte-identical** → the golden oracle (`oracle.rs::semantic_diff`, row-diffs every `type='table'`) is unaffected; views are not enumerated.
- **Zero scan-hot-path cost** — it's read on the SDK's *read-only* connection, never on the engine's scan/persist thread; sync speed is untouched.
- **No FFI/header change** → any host inherits it (Android gets it the moment it opens a slipstream DB).
- **Correct at cold launch with the engine not running** — a fully-synced wallet has no dangling spends, so every tx reads `reconciled = 1` and the SDK renders the full list immediately, without waiting for the engine.
- **Graceful degradation** — SQLite resolves a view's referenced tables lazily (at `SELECT`, not at `CREATE`). If a future upstream renamed/removed `nullifier_map` or the `nf` columns, the `CREATE VIEW` still succeeds and the read fails *softly*; the SDK catches it and returns an empty set (`unreconciledTxids()` → `[]`), i.e. falls back to today's "show everything" behavior. No crash, no corruption.

## The one divergence, stated honestly

A stock-SDK `data.db` and a slipstream `data.db` now differ by **exactly one `sqlite_master` row** (the view). Anything that asserts *schema* identity (a strict migration validator, or a hypothetical future upstream that fingerprints `sqlite_master`) would observe it. Functionally it is inert: upstream's `init_wallet_db`, migrations, and all reads never inspect or depend on it; it only ever runs `CREATE VIEW IF NOT EXISTS` after upstream is done.

**The fully-pristine alternative** is the last row in the table above: drop the view entirely and have the SDK run the same `SELECT` inline against the upstream tables. Then `data.db` is 100% identical (schema *and* data) and there is nothing for the core team to approve. The cost is that the join logic — and its coupling to upstream's internal tables — lives in *every* client codebase (Swift today, Kotlin later) instead of one audited place in the engine. The view trades one inert schema object for single-sourcing that logic.

## What we'd want from the core team

1. **Awareness/approval** of the single zero-data view in a slipstream-produced `data.db`, OR
2. a preference for the **inline-no-view** alternative (we can switch; it's a few lines and removes the only schema divergence), OR
3. a suggestion for a blessed upstream seam (e.g. an official "is this transaction's balance delta final under non-linear scan?" predicate) that would let every consumer drop both the view and the inline join.

Either of (1)/(2) is cheap for us. (3) is the long-term-clean answer if the core team wants to support spend-before-sync consumers first-class.
