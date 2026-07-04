# Beta 4 = Release Candidate 1 — the six-gate device session

**2026-07-03.** Beta 4 is the first release candidate. This is the go/no-go gate: the six
non-negotiable rows from [`SCENARIO_MATRIX.md`](SCENARIO_MATRIX.md), arranged as ONE
continuous ~90-minute session on the Mac. Every other matrix 🟡 is ship-safe for an RC
(mileage / unit-tested / benign failure mode / revival backstop) and gets its checkmark
during the RC soak instead.

**Rule:** any gate that fails → grab the log, stop the session, send it over. A pass →
flip the matrix row(s) to ✅ with today's date.

> **2026-07-04 field note (first partial run):** Gate-3/4's first attempt caught a real hole —
> the aborted pass's write-behind commit outlived `engine.stop()` (`spawn_blocking` is
> uncancellable), collided with the new pass ("database is locked") and could clobber the
> import's force-rescan re-queue. Two outcomes: the **revival loop had its first field win**
> (sync self-resumed in 15 s, exactly the contract), and the hole is now CLOSED at the source
> (writer-gate drain in stop/start). **Re-run Gates 3/4 on the drain build**, and treat the
> 07-04 morning wallet as tainted for Keystone completeness (a scan window may have been
> skipped) — Gate 6's wipe → restore covers it, or disconnect + re-add the Keystone.

## Precondition — the RC build

- SDK `slipstream` @ `73d5de27` (tree clean; crates **0.3.6**; macOS + iOS FFI slices
  rebuilt against it).
- Zodl `slipstream-macos`, scheme **`zodlmac-internal`** — commit your in-flight Zodl edits
  first so the RC cut is reproducible; the SDK side is done.
- No new FFI symbols this wave — if Xcode acts stale: Cmd+Shift+K, Reset Package Caches.

## Gate 1 · S33 — your wedged wallet self-heals (first launch does this by itself)

Launch the RC build over the wallet that is currently wedged from the Keystone test.

- ✅ Log shows `scan queue: dropped orphaned historic ranges (below every account birthday)`
  once, near startup.
- ✅ Sync proceeds as a plain catch-up (minutes), **not** a deep-history grind; no error
  dialog; no "Restoring" identity (the Keystone account is gone).

## Gate 2 · S39 + S38 — money paths (hop mask + send)

1. Quit and reopen the app within 120 s (or stop/start via background-foreground).
   - ✅ Send screen shows spendable immediately — **no** "awaiting resolution" mask
     (engine `tip_fresh` survived the hop).
2. Send a small amount.
   - ✅ Pending row appears in Activity within one poll tick of Send confirmation.
   - ✅ Within a few blocks the row transitions to mined/confirmed on its own
     (`tx_set_version` bump on the status write — no relaunch needed).

## Gate 3 · S19 — Keystone import with an OLD birthday (synced wallet)

Add the Keystone with a deep birthday (BD2 far below your seed's BD1).

- ✅ "Restoring" banner engages and climbs **0→100 as a genuine climb** — engine log:
  `scan scope expanded — session progress floor re-baselined (re-scan reads as a genuine climb)`.
- ✅ Balance/Activity reveal reconciled-only during the climb (never inflate).

## Gate 4 · S28 — disconnect the Keystone MID-restore (the fix of the week)

While Gate 3's restore is visibly running, disconnect the Keystone immediately.

- ✅ Expected: **no error dialog at all** (the delete now stops the engine first).
- ✅ Acceptable: at most ONE `rustSlipstreamSyncFailed` dialog, followed by log
  `session stays alive — reviving after non-transient failure` and sync self-resuming
  within ≤30 s. **Unacceptable: any state requiring an app restart.**
- ✅ "Restoring" banner clears (only the KS was recovering); KS rows leave Activity within
  one tick; log shows the prune line at restart and **no deep-history ranges afterward**.

## Gate 5 · S15 — resync (rewind) while a pass is active

Trigger resync from Settings while the wallet is actively syncing (during the Gate 3/4
aftermath catch-up is fine).

- ✅ No error; re-scan reads as a climb (same re-baseline log); wallet lands Done with
  balances intact. A failed rewind (if the network blips) must leave sync RUNNING, not dead.

## Gate 6 · S2 + S21 + S3 — fresh restore, import DURING it, truthful relaunch

This one destroys state — last on purpose. It is also the **silent-loss check for H2**,
the one gate where "looks fine" is not enough: verify amounts.

1. Wipe → restore your seed (deep birthday). Watch the restore start (S2).
2. **While the seed restore is running**, add the Keystone (any birthday) — S21/H2.
   - ✅ Import completes (spinner may wait a few seconds — that's the serialization);
     log: `importAccount: wasRunning=true → restarting sync pass now to surface the re-scan`.
   - ✅ Still "Restoring" after the import; progress keeps climbing.
3. Let BOTH accounts finish completely.
   - ✅ **THE CHECK: Keystone balance AND transaction list are COMPLETE** — compare against
     the wallet's known contents. A missing tx/amount here = H2 failure = hard stop.
   - ✅ Seed account balance matches its known total (e.g. the 4.0052 reference).
4. Kill the app; relaunch (S3).
   - ✅ First frame is truthful: ~100 %, real balances, no 0 % flash, no `[:]` flash, no
     "Restoring" flicker.

## After the session

| Result | Action |
|---|---|
| 6/6 pass | Beta 4 ships as RC1. Flip S2/S3/S15/S19/S21/S28/S33/S38/S39 to ✅ in the matrix. Remaining 🟡s green out during the RC soak (matrix Setups A–C at leisure). |
| Any fail | Log → me. The matrix row tells us which mechanism is implicated; nothing else ships until it's root-caused. |

Public (App-Store, slipstream-default) release stays gated on: full matrix green + a
multi-day daily-driver soak on RC1 — the same bar as deleting the old engine.
