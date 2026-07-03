# Slipstream Scenario Matrix — every lifecycle × interruption × account-set combination

**2026-07-03 · The finish-line document.** One row per reachable scenario; each row carries the
expected behavior, the code mechanism that guarantees it, a coverage verdict, and the device
step that turns it green. The goal: ✅ in every row before slipstream ships as the default engine.

## How to read

| Verdict | Meaning |
|---|---|
| ✅ | Mechanism in code **and** proven (unit/darkside test, or already device-validated in the field) |
| 🟡 | Mechanism in code, reasoning below is solid, **needs its device checkmark** (no direct test yet) |
| 🔴 | **Gap found in analysis** — fix shape included; do not trust until fixed + tested |
| ⬜ | Out of scope for this wave (noted why) |

**Dimensions collapsed honestly.** The raw cross-product (operation × sync-phase × birthday-class
× interruption-kind) is ~500 cells; most collapse into equivalence classes because the engine has
exactly one durability story: *the scan queue + wallet DB are the only truth; every pass start
re-derives everything from them* (`WalletSession::open` → façade seed → suggest round). So "killed
during download" ≡ "killed during scan" ≡ "killed during enhance" for resume purposes — the
difference is only how much cheap work is repeated. Rows below state which class they stand for.

**Naming.** BD1 = the seed account's birthday. BD2 = the imported (Keystone) account's birthday.
"Restoring" = `is_recovering` true (queued work below some account's `recover_until`).
"Mid-X" = while a sync pass is actively fetching/scanning/enhancing.

---

## F1 · Single account, happy paths

| # | Scenario | Expected | Mechanism | Verdict |
|---|---|---|---|---|
| S1 | Create NEW wallet (birthday ≈ tip) → sync | No "Restoring" identity (`recover_until` NULL via nil-birthday prepare); quick sync to tip; reorg-safe anchor tip−100 | E-6 `AnchorIntent::New` (anchor.rs); WalletInitMode-removal derivation (Initializer) | ✅ field-proven |
| S2 | Restore seed BD1 (deep) → full restore completes | "Restoring" from first pass; progress 0→100 monotonic; balance climbs, never over-counts; Activity reveals reconciled-only; banner clears at Done | recover_until = live tip (E-6); blessed `progressPermille`; Σ-reconciled recovery balance; reconcile view + visibility gate; fail-safe latch | ✅ device-proven repeatedly (v0.2.5 era + Beta3) |
| S3 | Relaunch a SYNCED wallet (cold start, idle) | First emission already truthful: ~100 %, real tip, balances — no 0 %/`[:]` flash, no "Restoring" flicker | E-3 truthful-from-open seed (`seed_progress_from_wallet` at `zcashlc_slipstream_open`) | 🟡 in the standing Phases-1–5 device pass |
| S4 | Catch-up after days offline | Floor seeds ≈100 % (small queue), quick pass, no restore identity | E-3 floor math (`global_floor_permille`); is_recovering false (no recover_until below) | 🟡 same pass |

## F2 · Interrupting a single-account restore

| # | Scenario | Expected | Mechanism | Verdict |
|---|---|---|---|---|
| S5 | stop()/start() hop mid-restore (bg/fg) | Resume from queue position; spendable mask honors <120 s hop (`tip_fresh` survives) | pendingStop chain + [audit SDK-1] ordering; E-2 tip_refreshes counter; FFI stop timestamp | ✅ unit-tested (stop/start ordering) + 🟡 device (the <120 s hop) |
| S6 | App **KILLED** mid-restore (any phase: download/scan/enhance — one class) | Relaunch resumes from the persisted scan queue; first emission shows "Restoring" + climbed % + climbed balance (not 0) | WAL + atomic per-range commits (write-behind txn); E-3 open-seed; queue = durable truth | ✅ mechanism (restart-resume validated 2026-06-27 nuttycom thread) + 🟡 the E-3 first-emission part rides the device pass |
| S7 | Network LOSS mid-restore (transient) | No error dialog; Disconnected between attempts; auto-resume (direct retries transients; Tor never falls back to direct) | T8.7 ladder + `connect_direct_with_retry` (993319c0); Tor bootstrap retry loop | ✅ device-validated (normal-restore, 2026-06-29) |
| S8 | NON-transient failure mid-restore (wallet/logic class) | ONE error dialog; engine stays alive; self-resumes in ≤15–30 s (first revival); repeated failure → retry ≤ every 5 min | **NEW** revival loop (`wedge_revival_backoff`, session.rs); SDK polls through state 2 | 🟡 **NEW — needs device** (kill-Keystone repro now lands here and should self-heal) |
| S9 | Kill during a revival backoff | Relaunch starts a fresh session immediately (backoff not persisted — deliberate) | revival state is in-memory only | ✅ by construction |
| S10 | Restore on Tor from cold (bootstrap slow) | No 0 % dip while bootstrapping; Disconnected → Syncing; never silently downgrades to direct | E-3 seed pre-network; Tor bootstrap loop (never-direct policy) | 🟡 device pass |

## F3 · Maintenance operations

| # | Scenario | Expected | Mechanism | Verdict |
|---|---|---|---|---|
| S11 | wipe() while idle | All DB files gone (data.db + -wal/-shm + fsBlockDbRoot); state `.zero`; fresh prepare works | wipeImpl order: stopPolling → engine.stop → **engine.close (handle freed BEFORE deletion)** → Swift conns closed → delete | ✅ order verified in code; long-standing path |
| S12 | wipe() **mid-restore** | Same — no zombie engine writes after file deletion | engine.close precedes deletion; orphan write-behind commit targets a freed… **see note** | 🟡 note: an uncancellable in-flight `spawn_blocking` commit could hold its own connection while files unlink — POSIX keeps the inode alive until close, so it writes into an orphaned inode and vanishes; no new-file corruption. Device-check: wipe mid-restore → fresh restore starts clean |
| S13 | App killed **mid-wipe** | Worst case: partial deletion. data.db gone + stale -wal → SQLite resets a mismatched WAL on next create; wallet re-initializes fresh; keychain (app-owned) untouched → Zodl re-runs its own reset | SQLite WAL salt/checksum semantics; prepare re-creates DB | 🟡 reasoning solid; cheap to device-check |
| S14 | rewind() (resync) while idle | Truncate to checkpoint; re-scan reads as genuine climb (queue re-grows = scope expansion → floor re-baselines) | truncateToChainState + E-5 re-baseline | 🟡 device |
| S15 | rewind() **mid-restore / mid-sync** | **GAP.** `rewindImpl` truncates WITHOUT stopping the engine — the in-flight pass's façade/plan reference blocks above the truncation; its next commit can write against truncated chain state. Old SDK stopped the processor inside rewind; slipstream lost that. | — | 🔴 **H1**: serialize exactly like deleteAccount — `engine.stop()` → truncate → `if wasRunning start()`. 4 lines, recipe proven today. (Zodl's resync flow may stop first app-side, which masks it — the SDK contract must not rely on that.) |
| S16 | switchTo(endpoint) mid-restore | Stop → reopen handle on new server → resume from queue (durable, server-agnostic); tx-version mirror reset | switchTo sequence (verified: stopPolling → engine.stop → reopen → restart) | ✅ code-verified; 🟡 one device datapoint |
| S17 | Tor toggle in settings | Next start() picks up `sdkFlags.torEnabled` (dir passed per-start) | `slipstreamTorDirPath()` read at start | ✅ code-verified |

## F4 · Keystone ADD — birthday-ordering classes (his BD1/BD2 ask)

Upstream fact that anchors this family (`zcash_client_sqlite::wallet::add_account`): an import
**force re-queues the ENTIRE [BD2, chain_tip] span as Historic — including already-Scanned
regions** — so the new account's notes are found even in blocks previously scanned for other
accounts. `recover_until` = tip via the E-6 anchor. Ignored rows fill [Sapling, BD2) non-forcibly.

| # | Scenario (wallet state × BD class) | Expected | Mechanism | Verdict |
|---|---|---|---|---|
| S18 | SYNCED + import KS, **BD2 ≈ tip** | Near-no-op re-scan; brief or no "Restoring" | tiny force-requeue span | 🟡 trivial device check |
| S19 | SYNCED + import KS, **BD2 < BD1** (older — his headline class: request BD2→tip when coverage began at BD1) | Deep restore [BD2 → tip]; banner climbs 0→100 as a genuine climb (floor re-baselines on scope expansion); balance/Activity reveal reconciled-only | E-5 `rebaseline_floor_if_scope_expanded` (≥50 ‰ drop); force-requeue; recover_until=tip ⇒ is_recovering true | 🟡 explicitly on the Phases-1–5 device list |
| S20 | SYNCED + import KS, **BD2 > BD1** (newer) | Re-scan only [BD2, tip] (subset); quick; no false deep-restore | same, smaller span; no re-baseline trigger (seed within epsilon) | 🟡 device |
| S21 | **RESTORING** (seed mid-restore) + import KS, any BD | Import lands (waits ≤15 s if writer busy), pass restarts, merged queue, still "Restoring", both accounts complete with ALL notes | busy_timeout (P1b); pass_lock serialized restart (5ee74ee8); force-requeue; **but see S22** | 🔴 **capped by S22** |
| S22 | The S21 race, precisely | **GAP.** `importAccount` does NOT stop the engine before its DB write. Interleaving: import commits its force-Historic re-queue for range R → the old pass's in-flight (uncancellable `spawn_blocking`) commit then marks R **Scanned** → R is never re-scanned with the KS key → **silently missing KS notes** in R. (Delete got serialization today; import didn't.) | — | 🔴 **H2**: same 4-line recipe — `engine.stop()` → anchor+import → restart. With the engine stopped first, any orphan commit lands BEFORE the import txn (both serialize on the SQLite write lock), so the force-requeue is guaranteed last = correct. |
| S23 | Re-add same KS after disconnect (B4-12 re-test) | Clean re-import (no collision — the delete removed the account); full KS re-scan; no dialog | fresh add_account; busy_timeout (22add7cd + P1b) | 🟡 device re-test pending |
| S24 | Double-add same KS **without** disconnect | Clean error surfaced (no half-state) | upstream `AccountCollision` → FFI error → ZcashError | ✅ upstream-guaranteed; Zodl UI should also prevent |
| S25 | Import while OFFLINE | Import succeeds with recovery identity intact: recover_until = max(bundled checkpoint, BD2+1); syncs when online; never a silent direct fetch when Tor is on | E-6 `offline_anchor` (anchor.rs) + offline tests | ✅ unit-tested; 🟡 one device datapoint |
| S26 | Import canceled mid-QR flow | No account row created; zero state change | import only fires on completed scan (Zodl) | ✅ trivially |

## F5 · Keystone REMOVE — the B4-16 family (fixed today)

| # | Scenario | Expected | Mechanism | Verdict |
|---|---|---|---|---|
| S27 | Disconnect KS while SYNCED (idle) | Account + its txs gone; Activity drops rows ≤1 tick; no queue garbage (nothing below BD1 queued when synced) | serialized delete + `notifyTxChange` (tx_set_version); prune no-op fast path | 🟡 device |
| S28 | Disconnect KS **during its restore** (the repro) | No pass error (engine stopped first); orphaned deep ranges pruned at restart; banner clears if only KS was recovering; NO hours-long grind. Leftover cost: the [BD1, tip] force-rescan rows survive the prune (indistinguishable from legitimate seed work) — bounded by the seed's own span, correctness-neutral re-scan | P1a prune (`scan_queue.rs`) + P1b serialize + revival as backstop | 🟡 **the headline re-test** |
| S29 | Disconnect KS while BOTH restoring (seed also mid-restore) | Seed restore continues uninterrupted (restart resumes queue ≥ BD1); recovering stays true via seed's recover_until; only sub-BD1 rows pruned | prune predicate = MIN(remaining birthdays) — exactly right for this case | 🟡 device |
| S30 | Disconnect → immediate re-add (stress loop) | Each cycle clean: delete serialized → prune → re-import → fresh grind | P1a+P1b + S23 path | 🟡 device stress |
| S31 | App killed mid-disconnect (after delete commit, before restart) | Relaunch heals itself: `WalletSession::open` prunes at every open | prune-at-open (tested end-to-end: `open_prunes_orphaned_ranges`) | ✅ unit-tested |
| S32 | Disconnect while engine is in **Error/revival backoff** | `engine.stop()` aborts the sleeping session; delete clean; restart fresh | tokio sleep abort-safe (pass_lock release test) | ✅ by construction + lock test |
| S33 | Wallet ALREADY wedged in the field (pre-fix queue garbage) | First launch of this build prunes it at open; sync resumes as plain catch-up | prune-at-open | ✅ unit-tested (the open-heals test) + 🟡 confirm on your wedged device wallet |

## F6 · Failure / revival semantics (new today)

| # | Scenario | Expected | Mechanism | Verdict |
|---|---|---|---|---|
| S34 | One-shot non-transient error (any cause) | 1 dialog; self-resume ≤15–30 s | revival ladder attempt 1 = 15 s | 🟡 device (S28 doubles as this) |
| S35 | PERSISTENT non-transient error (e.g. genuinely corrupt DB) | Dialog per failure episode; retries forever at ≤5 min cadence (cheap); app restart also always works | capped ladder; state truthful between attempts | ✅ by construction — accepted posture |
| S36 | PANIC in a pass | Error(2); **NOT revived** (deliberate — panic loops are bugs, not weather); app restart required | supervisor converts; revival scoped to Err only | ✅ documented decision; panics are also the class 5ee74ee8 removed |
| S37 | User acts during revival backoff (send/import/delete/start) | Any start()-class action aborts the sleeping task and proceeds immediately — backoff never blocks the user | abort-safe sleep + pass_lock | ✅ by construction |

## F7 · Spend / receive during sync states

| # | Scenario | Expected | Mechanism | Verdict |
|---|---|---|---|---|
| S38 | Send DURING restore (spend-before-sync) | Spendable appears early (notes + tree data ready); propose/submit works; pending row in Activity ≤1 tick; mined transition surfaces | spend-before-sync scan order; E-4 tx_set_version (submit poke + status-write bump) | 🟡 Phases-1–5 device list |
| S39 | Send right after a <120 s stop/start hop | Spendable NOT masked (tip still fresh) | E-2 `tip_fresh` stop-timestamp rule | 🟡 same list |
| S40 | Receive while RESTORING | Found when the scan reaches its block (recent-first ⇒ quickly); revealed once reconciled — no phantom rows | reconcile visibility gate (recovery-scoped since c6bc6b9d) | ✅ device-validated (false-receive fix, 0c828cce) |
| S41 | Receive while SYNCED (0-conf) | Mempool hit surfaces ≤1 tick | mempool session + tx_set_version bump on stored hit | ✅ field-proven + E-4 test |
| S42 | Keystone shield mid-states (banner correctness) | Banner survives minimize, dies on disconnect, no stale re-show | Zodl-side (B4-17 + ShieldingProcessor.reset, 632e84ef) | ✅ fixed + smoke-tested; Harry QA pending |

## F8 · Deliberately out of scope (stated, not forgotten)

| # | What | Why |
|---|---|---|
| X1 | Multiple Keystone / >2 accounts | Zodl exposes one KS today; prune + upstream logic already generalize (MIN over birthdays), untested beyond 2 |
| X2 | Reorg mid-restore | Engine-internal via upstream Verify ranges + tip−100 anchor; oracle + darkside covered; not host-visible |
| X3 | Seed restored OVER an existing different wallet | Blocked at prepare by the ZINIT0006 seed↔account guard (imported-only exempt) — its own tested path |
| X4 | Disk-full during scan | Surfaces as non-transient → S35 posture applies |

---

## The two 🔴 hardenings (both are today's proven recipe)

1. **H1 — rewind must serialize with the engine.** `rewindImpl`: `let wasRunning = isRunning;
   await engine.stop()` before `truncateToChainState`, `if wasRunning { try? await start() }`
   after. Restores old-SDK parity (its `blockProcessor.rewind` stopped internally).
2. **H2 — importAccount must serialize with the engine.** Same wrap around the
   anchor+`rustBackend.importAccount` block. Kills the missing-notes race (S22): with the
   engine stopped, any orphan write-behind commit necessarily lands BEFORE the import's
   force-rescan re-queue, so the re-queue is last-writer = correct.

Both are ~4 lines each + no FFI change. After H1/H2, every 🔴 in this matrix becomes 🟡.

## Device-test script (one sitting, orders the 🟡s efficiently)

**Setup A — seed restore lifecycle** (fresh wallet, deep BD1):
1. Restore → watch first emission (S2), kill mid-restore → relaunch (S6), airplane-mode blip (S7).
2. Let it finish → relaunch synced (S3) → stop/start hop <120 s → send (S39).

**Setup B — Keystone lifecycle** (on the synced Setup-A wallet):
3. Import KS with BD2 < BD1 → banner climbs (S19) → disconnect mid-restore (S28 = S34) →
   confirm self-resume + no grind → re-add (S23/S30) → let finish → disconnect synced (S27).
4. Import KS with BD2 ≈ tip (S18), then with BD2 > BD1 (S20). Offline import once (S25).
5. (After H2) repeat step 3's import while Setup-A is mid-restore (S21).

**Setup C — maintenance + failure**:
6. rewind idle (S14); (after H1) rewind mid-sync (S15). switchTo mid-restore (S16).
7. wipe mid-restore (S12) → fresh restore; kill mid-wipe if reproducible (S13).
8. Your currently-wedged wallet: first launch of this build = S33.

Marking a row green: edit this file's verdict to ✅ with the date — this document is the
single source of truth for "are we done".
