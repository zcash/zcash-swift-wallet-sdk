# Engine↔SDK Boundary Review — "Slipstream for everybody"
**Commissioned 2026-07-01 by Lukas. Status: PHASE A COMPLETE → `ENGINE_API_V2.md` AWAITING LUKAS
REVIEW (5 open questions at its end). Phases B-F blocked on that review. Resume anchor: this file +
AUDIT_STATE.md pointer.**

## Why (Lukas's brief, distilled)
The engine has been frozen for weeks while every piece of user-facing sync UX — balance during
restore, transactions during restore, mid-sync-kill continuity, pending visibility, "mined but not
fully confirmed" — was delivered on the SDK side, several of them through 5-7 failed iterations.
The data was ALWAYS already in data.db. That is the diagnostic: the engine ships the *data* but not
the *semantics*, so every host must re-derive balance/visibility policy and will re-make the same
mistakes. Slipstream should be a solution for everybody: a new host (Kotlin, CLI, anyone) picks up
the crate and gets a correct wallet — never over-showing, never under-showing — without duplicating
a single line of balance math. The SDK should be a thin interface.

## The classification test
For every mechanism the SDK grew, ask: **"would a second host need this?"**
- YES → it is engine semantics living in the wrong layer → candidate to move down.
- NO (keys, keychain, Combine surface, app lifecycle, legacy-SDK parity) → host policy → stays.

## Acceptance criterion (the whole review in one sentence)
**`slipstream/cli` must be able to display correct balance + transaction list during a live restore
(and across a kill/restart) using ONLY the engine's public surface — zero host-side wallet math.**
When the CLI can, Android can, and the Swift SDK collapses to a thin adapter.

## Inventory to classify (from the 2026-07-01 audit + session history — the "patch archaeology")
Each item gets: current home → verdict (engine/host/duplicated) → target API → migration risk.
1. `recoveryAccountBalances()` — Σ account_balance_delta over mined+reconciled txs, per tick
   (SlipstreamSynchronizer + TransactionDao SQL). **Prime move-down candidate**: engine-owned view
   (`slipstream_v_recovery_balance`) or balance fields in the FFI snapshot. Never-overshoot balance
   becomes a crate guarantee, not a host skill.
2. Reconcile visibility policy — the VIEW is already engine-owned (reconcile.rs), but the POLICY
   (apply only while recovering) lives in Swift (`droppingUnreconciled` gate). Candidate: encode the
   policy in SQL (`slipstream_v_tx_visible`: unreconciled rows hidden only while
   `accounts.recover_until_height` is above the fully-scanned frontier) → hosts just SELECT.
   Note the P0-B invariant (permanent dangles are expected residue) — the view doc already captures it.
3. `isRecovering` + fail-safe Error latch + monotonic recovery-progress floor — engine knows its own
   terminal state; candidate: `snapshot.is_recovering: u8` + engine-side monotonic progress, so a
   host cannot wedge or regress even if it consumes snapshots naively.
4. foundTransactions strategy (counter-advance primary / SyncDone fallback / incremental reveal
   during recovery / NEW post-submit emission) — candidate: engine event `TransactionsChanged`
   emitted on every DB tx-set mutation (scan, enhance, mempool, and — if submit moves down — submit),
   with the ring-overflow criticality fix (never drop tag-4/5) from audit ENG-4.
5. Progress mapping (pass-local counters → % with warm-start seeding) — partial candidate: engine
   emits a stable 0-1000 progress integer per pass incl. warm-start; host just renders.
6. Mid-sync-kill continuity — engine ALREADY resumes from DB (audit-verified); what the SDK adds is
   presentation continuity (cached summary warm start). Verdict likely: engine exposes
   `wallet_summary()` over FFI (it may already — verify) and the SDK cache becomes a pure memo.
7. Stall watchdog (B4) — engine knows "no progress for N s" better than a poller; candidate:
   `snapshot.stalled_seconds` field. Host keeps the policy (log vs restart).
8. Submission — today host-side (transactionEncoder). OPEN DESIGN QUESTION: move broadcast (not
   signing! keys never enter the engine) into the engine so mempool/pending/resubmit unify with sync.
   Big scope; decide in Phase A, do not assume.
9. Chain-tip flag (SDKFlags parity), seed↔account guard, wipe orchestration, Combine surface,
   ZcashError mapping — HOST (stay). The guard's relevance primitive is already an engine FFI.
10. Duplicated-code sweep: TransactionDao SQL vs engine queries; two sources of truth for
    "wallet summary"; progress derivations in +PureHelpers vs events.rs counters.

## Phases (each one session-chunk, checkpointed, all buildable/testable on this Mac)
- **A — Boundary design doc (no code).** Walk the inventory + the two postmortems
  (2026-06-29-balance-recovery-rethink, 2026-06-30-balance-recovery-postmortem) — the "patch
  archaeology": for each mechanism, was it compensating for an engine gap, a wrong abstraction, or
  genuine host policy? Output: `ENGINE_API_V2.md` — the target FFI surface (snapshot fields, views,
  events), migration table, and the submit-ownership decision. Lukas reviews THIS doc (the one
  approval gate in the whole plan).
- **B — Engine API v2, additive.** Implement the agreed views/snapshot fields/events in the crate
  with engine-side tests (crate already has 170; every moved behavior arrives WITH its test —
  including a never-overshoot balance test replaying the recent-first restore that took 5-7 SDK
  iterations). Nothing removed; SDK untouched; FFI bumped.
- **C — CLI as second host (the proof).** Teach `slipstream/cli` to render balance + tx list during
  a live (darkside or mainnet) restore using only the new surface. If the CLI needs ANY wallet math,
  the API is wrong — iterate B. This is the step that certifies "solution for everybody".
- **D — SDK thins out.** SlipstreamSynchronizer consumes the v2 surface behind the SAME public
  Synchronizer API (zero Zodl churn). OfflineTests keep passing; behavior parity checked against
  the recorded field scenarios (restore over-count, vanish-tx, stuck-100%).
- **E — Delete the dead machinery.** Remove superseded SDK mechanisms (recovery balance SQL, gate
  plumbing where replaced, duplicate progress math), one commit per deletion so any regression
  bisects instantly. Also: actor-ize SlipstreamSynchronizer (audit SDK-2) as part of the slim-down.
- **F — Cross-host doc.** `docs/slipstream/HOSTING.md`: "how to build a wallet on slipstream" —
  the crate's promises (never-overshoot balance, visibility semantics, kill-resume) stated as
  contracts with pointers to the tests that enforce them.

## Risks / constraints
- Engine is published + stable; every move-down is ADDITIVE first (B), consumed later (D), deleted
  last (E) — the shipped app never sits on an unproven layer.
- Android-future benefits directly, but that also means view/FFI names are forever — Phase A names
  them carefully.
- The old SDK sync path stays frozen (CLAUDE.md rule); this touches only the slipstream path.
- Cost control: Phases A and D are inline (no agent fan-out); B/C are normal coding sessions.
- FFI changes require full `init-local-ffi.sh` before any PR (CLAUDE.md rule).

## Out of scope (tracked elsewhere)
Zodl macOS foundations review (see `secant-ios-wallet/docs/macos/FOUNDATIONS_REVIEW_PLAN.md`);
publishing/version hygiene (audit ENG-16/17); the uncommitted fix-wave items.
