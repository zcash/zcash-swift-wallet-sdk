# Engine API v2 — the boundary design (Phase A deliverable)
**2026-07-01 · Boundary review Phase A · Status: APPROVED WITH AMENDMENTS (Lukas, 2026-07-02) —
Phase B unblocked. Companion: `2026-07-01-engine-sdk-boundary-review.md` (the plan), the two
balance postmortems (2026-06-29/30), the 2026-07-01 audit.**

## §0 — Review outcome (2026-07-02, supersedes §9 where they differ)
1. **Naming**: approved as proposed.
2. **`slipstream_state` table: VETOED for now** (new tables need core-team approval; goal = zero
   schema change, ideally). AMENDMENT: `is_recovering` moves to the FFI SNAPSHOT (no DB change);
   `slipstream_v_tx_visible` is DROPPED from v2 — visibility becomes the documented one-line host
   rule `visible = reconciled OR NOT snapshot.is_recovering` (HOSTING.md). VIEWs are read as
   acceptable under the shipped-reconcile-view precedent (additive, oracle-invisible, no table
   changes) — `slipstream_v_recovery_balance` stays. If that reading is wrong, it too converts to a
   documented host query.
3. **`progress_permille` REPLACES the SDK's % math entirely** (not parallel paths).
4. **Event tag: reuse tag-5** for the notify poke, as recommended.
5. **REVISED 2026-07-02 (Lukas): unified summary FFI JOINS Phase B.** Background: the existing
   `zcashlc_get_wallet_summary` is not broken — it over-counts during recent-first restore by
   upstream's documented design ("may overestimate… spend not yet detected"). Rather than leave the
   phase-resolution as a host rule, Phase B adds **`zcashlc_slipstream_wallet_summary`** (name final
   at impl): one call that RESOLVES the phases internally — recovering → per-account
   Σ-reconciled-delta balances (the `slipstream_v_recovery_balance` semantics) + recovery progress;
   not recovering → upstream `get_wallet_summary` values passed through. "Anybody can call it and
   get correct values" at every phase; the view remains as the documented SQL-level primitive for
   hosts that prefer SELECTs. This removes the last line of host wallet-math from the v2 contract.
Also approved 2026-07-02: SDK fix wave committed; submit stays host-side (§5 accepted).

---

## 1. The contract slipstream v2 makes to ANY host

> Open the wallet DB through slipstream, drive the handle, and render wallet state by SELECTing
> documented views + reading the snapshot. You get: a balance that **never over-shows**, a
> transaction list that **never shows phantoms**, restore/recovery state that **cannot wedge**,
> and **kill/restart continuity** — with **zero wallet math in your code.**

Today the Swift SDK delivers those four properties itself, in ~hundreds of lines that took 5-7
failed iterations (the postmortems document why: upstream `get_wallet_summary` *by design*
over-estimates during recent-first scanning, and nothing engine-side exported a safe alternative).
Any second host would have to rediscover all of it. v2 moves the semantics down.

## 2. Archaeology — what the SDK grew, and the verdict on each

| # | SDK mechanism (where) | Why it exists | Verdict | v2 disposition |
|---|---|---|---|---|
| 1 | `recoveryBalances()` Σ reconciled deltas (TransactionDao) + per-tick recompute (SlipstreamSynchronizer) | upstream summary over-counts mid-restore; engine exported no safe balance | **ENGINE GAP** | → view `slipstream_v_recovery_balance` (§4.2) |
| 2 | `droppingUnreconciled` recovery-scoped display gate (SlipstreamSynchronizer) | reconcile view is a primitive; the *policy* (only-while-recovering, per audit P0-B invariant) had no home | **ENGINE GAP** | → view `slipstream_v_tx_visible` (§4.3) |
| 3 | `isRecovering` derivation + Error fail-safe latch + monotonic progress floor (+PureHelpers) | engine never said "I am recovering"; host derived it from summary polling and had to armor it | **ENGINE GAP** | → snapshot `is_recovering` + `progress_permille` (§4.4) |
| 4 | foundTransactions strategy: counter-primary / SyncDone-fallback / incremental reveal / post-submit emission | event ring loses events; no "tx set changed" signal; submit invisible to engine | **ENGINE GAP** (ring + signal) / **HOST** (Combine delivery) | → never-drop event set + `notify_tx_change` poke (§4.5) |
| 5 | Warm-start progress seeding from cached summary (start()) | pass-local counters reset to 0 on a catch-up pass → % jumped backwards | **ENGINE GAP** | → engine seeds pass progress baseline (§4.4) |
| 6 | Stall watchdog B4 (poll-side timer) | engine knows "no progress" first-hand; host inferred it | **ENGINE GAP** (signal) / **HOST** (policy) | → snapshot `stalled_seconds`; host keeps log-vs-restart policy |
| 7 | Mid-sync-kill continuity | ALREADY engine-owned (passes resume from DB — audit-verified). SDK only adds presentation warm-start | **ALREADY RIGHT** + item 5 closes the presentation gap | — |
| 8 | Seed↔account guard, keychain, key derivation, proposal/signing | keys must never enter the engine | **HOST** (stays) | engine keeps `seed_relevance` primitive only |
| 9 | Broadcast/submission (transactionEncoder, multi-server #1757) | deliberate shared host logic | **HOST for v2** — see §5 decision | + the §4.5 poke |
| 10 | Combine/state surface, SDKFlags legacy parity, wipe file-orchestration, ZcashError mapping | host platform integration | **HOST** (stays) | thins in Phase D |

The pattern across every ENGINE GAP: **the data was in data.db; the semantics weren't exported.**

## 3. The architecture: two channels, both contractual

- **Channel 1 — the handle (FFI/crate API):** control (open/start/stop/free), the by-value
  snapshot (liveness + progress + recovery flag), the event ring (edge signals). Small, hot, C-ABI.
- **Channel 2 — versioned SQL views over data.db (the READ surface):** wallet *data* semantics —
  balance, visibility, reconciliation. Hosts SELECT; no FFI marshalling of lists. This is already
  the de-facto pattern (`slipstream_v_tx_reconciled` shipped it); v2 promotes it to a **contract**:
  documented, versioned, crate-tested. It is what makes "solution for everybody" real — any
  language with sqlite bindings gets the full semantics with zero binding work.

## 4. The target surface (all ADDITIVE — nothing existing changes shape)

### 4.1 `slipstream_state` table (new, engine-maintained, one row)
`(schema_version INTEGER, recovery_active INTEGER, updated_tip INTEGER)` — written by the engine at
pass boundaries (where it already computes recovery span from `accounts.recover_until_height` vs the
scanned frontier). Powers §4.3's policy in pure SQL and gives ANY host `is_recovering` without FFI.
Requires one golden-oracle allowlist entry (the allowlist exists for exactly this).
*Alternative considered:* derive recovery-activity inside the view from scan_queue — rejected:
replicates upstream progress math in SQL, fragile across upstream migrations. The single-row state
table is the honest export of something the engine already knows.

### 4.2 `slipstream_v_recovery_balance` (new view — moves archaeology #1 down)
Exactly today's SDK SQL, relocated + crate-tested:
`SELECT account_uuid, SUM(account_balance_delta) FROM v_transactions WHERE mined_height IS NOT NULL
AND <reconciled> GROUP BY account_uuid`. Guarantee (tested with a recent-first restore replay,
including the postmortem's 4→8→4 scenario): **never over-shows; converges to true net; consistent
with visible Activity by construction.** Host rule collapses to: recovering → SELECT this; else →
normal summary.

### 4.3 `slipstream_v_tx_visible` (new view — moves archaeology #2 down)
`visible = reconciled OR NOT slipstream_state.recovery_active` — the recovery-scoped display policy
(and the audit P0-B invariant: permanent dangles surface the moment recovery ends) encoded once, in
SQL, for every host. `slipstream_v_tx_reconciled` remains as the documented primitive beneath it.

### 4.4 Snapshot v2 (fields appended at END — existing padding-stability convention)
```
pub is_recovering: u8,        // engine-computed; includes today's SDK fail-safe semantics:
                              //   Error(2) terminal → 0 (a dead pass can never wedge "Restoring"),
                              //   Done with recovery span incomplete handling, latch reset on start.
pub progress_permille: u16,   // 0..=1000, monotonic within a pass, warm-seeded at begin_pass from
                              //   DB-derived overall progress (kills the reset-to-0% class, item 5;
                              //   subsumes the SDK's monotonicRecoveryProgress floor).
pub stalled_seconds: u32,     // seconds since last forward progress while state==Syncing; 0 otherwise.
```
Raw counters stay (hosts that want their own math keep it); `progress_permille` is the blessed path.

**[v2.1 E-3 amendment — CONTRACT] The snapshot is truthful from `open()` — hosts must not
compensate.** `zcashlc_slipstream_open` (and any Rust host, via `scheduler::seed_progress_from_wallet`)
seeds `is_recovering`, the permille floor, `chain_tip` and `spendable_hint` from the PERSISTED wallet
(the same inputs the first suggest round would use), so there is no pre-first-suggest window in which
the snapshot lies (mid-restore relaunch reads recovering + its resume position from the very first
poll). A wallet with no accounts seeds nothing — the zero snapshot is itself the truth. Freshness
(`tip_fresh`, v2.1 E-2) is counter-based (`Progress::tip_refreshes`, bumped only after a live
`update_chain_tip` succeeds): a DB-seeded tip is persisted state, never proof of freshness.

### 4.5 Events v2
- **Never-drop set:** ring overflow may evict tags 1/2 (started/progress) but NEVER 3/4/5
  (done/error/found-transactions) — evict oldest droppable instead; `tracing::warn!` on overflow
  (audit ENG-4).
- **`zcashlc_slipstream_notify_tx_change(handle)`** (new, trivial): the host pokes after storing a
  tx itself (post-submit). Engine responds by emitting tag-5 through the normal channel — every
  host's event loop sees pending sends immediately and uniformly. (Replaces the SDK-side
  emitPostSubmitTransactions added in the fix wave; that code retires in Phase D.)
- Mempool/scan/enhance stores already flow through engine emissions — unchanged.

### 4.6 Engine-internal moves (no surface, big host-simplification)
Error-latch semantics into the `is_recovering` computation; warm-start baseline into `begin_pass`;
stall clock into the progress struct. Each arrives with crate tests replaying the exact field
scenarios from the postmortems (stuck-0%, stuck-100%, 4→8→4, kill-and-resume).

## 5. The submit-ownership decision (recommendation: HOST keeps broadcast in v2)
Moving broadcast into the engine would unify pending tracking — but it duplicates a transport stack
(the host already owns multi-server submission as *deliberately shared* logic, #1757), doubles the
error surface, and drags proposal/signing context toward the engine boundary (keys must never
cross). The §4.5 poke closes the only real gap (event visibility) for one FFI function. **Revisit
only if a second host actually re-implements submission pain** — that evidence doesn't exist yet.

## 6. Migration map (what the Swift SDK deletes in Phase E)
| SDK code | Replaced by |
|---|---|
| TransactionDao.recoveryBalances SQL + per-tick recompute + `lastLoggedRecoveryTotal` | SELECT `slipstream_v_recovery_balance` |
| `droppingUnreconciled` + `unreconciledTxids()` + recovery gating of Activity fetches | SELECT via `slipstream_v_tx_visible` |
| `isRecovering(cachedSummary)` + `resolveRecoveryGate` + `recoveryReleasedByError` latch + monotonic floor + summary-poll kick for the gate | `snapshot.is_recovering` + `progress_permille` |
| Warm-start seeding (`summaryProgress(cachedSummary)` at start) | engine warm-seeded permille |
| Stall watchdog timer plumbing | `snapshot.stalled_seconds` (host keeps the log line) |
| `emitPostSubmitTransactions()` (fix-wave) | `notify_tx_change` poke |
| Paginated-path filter gap (audit SDK-7) | moot — paged repo reads the visible view |
Each deletion = one commit, OfflineTests green, field-scenario parity checked. SlipstreamSynchronizer
also actor-izes here (audit SDK-2) — far easier once this state machinery is gone.

## 7. Versioning & compatibility
Views + state table versioned via `slipstream_state.schema_version` (v2 = 1); additive-only
evolution; names are forever (Android will read them). Snapshot grows only at the end. All v2 pieces
ship BEFORE any SDK consumption (plan Phase B → D ordering), so the app never sits on unproven code.

## 8. Acceptance (Phase C): `slipstream-cli watch`
New subcommand: opens a wallet DB + handle, renders per-account balance + visible tx list + recovery
state, live, using ONLY §3's two channels — through a full restore and a mid-restore kill/restart.
**If `watch` needs any wallet math, v2 is wrong and iterates.** When it passes, the contract in §1
is demonstrated, not asserted.

## 9. Open questions for Lukas (answer on review — then Phase B starts)
1. **Naming:** `slipstream_v_tx_visible` / `slipstream_v_recovery_balance` / `slipstream_state` OK?
   (Names are forever.)
2. **State table vs SQL-derived** recovery_active (§4.1): I recommend the table; veto if you want
   zero new tables in data.db despite the allowlist.
3. **`progress_permille`:** replace the SDK's % math entirely (recommended) or keep both paths?
4. **Event tag 6 (`TxSetChanged`)** as a distinct tag vs reusing tag-5 FoundTransactions for the
   poke (recommended: reuse 5 — hosts already handle it).
5. **Scope check:** anything you want IN v2 that isn't here (e.g., wallet-summary-over-FFI so hosts
   skip the legacy `zcashlc_get_wallet_summary` entirely)? I left summary on the legacy surface for
   v2 to keep scope tight; flag if you want it pulled in.
