# Phase 1 — Engine (Rust) findings — COMPLETE (2026-07-01)

> Method: 6 parallel read-only lenses (1A pipeline, 1B persistence, 1C wallet semantics, 1D network,
> 1E failure modes, 1F FFI) + 1G hygiene done directly. Every P0/P1 agent claim was re-verified by the
> lead against source before acceptance; refuted claims are documented below so they aren't re-litigated.
> Severity: P0 funds/seed/crash-mainline · P1 correctness/privacy · P2 robustness · P3 hygiene.

## Verdict (engine confidence statement)
**No confirmed P0 in the engine.** Core money-paths hold: block persistence is single-transaction
atomic (rows + shardtree flush + scan-queue in ONE SQLite txn — proven at persist.rs:543→930), passes
are serialized, reorg rewind mirrors upstream, panics are supervised into Error(2) events (never
silent), no sensitive material is logged, network calls are bounded and retried, darkside/GPU are
compile-gated out of release. **Two P1s stand**: the reconcile view's nf-population/scoping question
(the likely root of the vanished-Keystone-tx bug) and the absent busy_timeout on every engine DB
connection (one half of the cross-layer SQLITE_BUSY hazard).

## Surviving findings

### ENG-1 [P1 | verified] No busy_timeout on ANY engine SQLite connection
- `grep busy_timeout slipstream/core/src/` → none. wallet_session.rs:40-67 opens 3 connections
  (pre-open PRAGMA conn, WalletDb, reconcile-view side conn); none set a busy handler.
- Impact: (a) engine writer can error on BUSY if any other connection (Swift reader in WAL edge
  cases, checkpointing) holds it; (b) this is the engine half of the known Swift-side
  `try!`-uncatchable-crash hazard (SDK half in Phase 2; Lukas's uncommitted busyTimeout=5s WIP).
- Fix: set `busy_timeout` (≥250ms) on all three engine connections at open. Cheap, additive.
- Confidence H.

### ENG-2 [P1 | OPEN — root-cause candidate for the vanished-Keystone-tx bug] Reconcile view: nf population + account scoping
- View (reconcile.rs:49-66): tx unreconciled iff a `nullifier_map` row at its locator has **no**
  `sapling/orchard_received_notes` row with `nf = nm.nf`. Two structural questions:
  1. **nf-population invariant (lead's hypothesis)**: `received_notes.nf` requires deriving the
     nullifier (needs nk + note position). If a **UFVK-imported (Keystone) account**'s note rows ever
     carry `nf = NULL` (or nf arrives late, post-witness), that account's SPENDS dangle **forever** →
     exactly the field bug: fully-synced wallet, fresh Zodl↔Keystone txs stuck reconciled=0. The SDK's
     recovery-gate (c6bc6b9d) made this harmless for display, but during a REAL recovery those txs are
     hidden and excluded from the recovery balance Σ — Keystone recovery under-reports.
  2. **Account scoping (agent 1C)**: nf match is not account-scoped. Direction note: un-scoped matching
     is MORE permissive (any account's note reconciles the tx), so it cannot cause stuck-unreconciled —
     it could only mask; but it makes semantics accidental in multi-account DBs (Zodl+Keystone coexist).
- Tests cover dangling→linked and unrelated-nf (reconcile.rs:134-225) but NOT multi-account and NOT
  nf-NULL note rows.
- Fix direction: (a) inspect a device data.db (Keystone account: `SELECT nf IS NULL FROM
  sapling_received_notes/orchard_received_notes WHERE account_id = keystone`), (b) add a rust test:
  two accounts + spend with nf-NULL note row, (c) amend view: treat a spend as reconciled when the
  spent note row EXISTS for the spending tx's account even if nf is NULL, or populate nf for imported
  accounts. → Phase 4 verification item #1.
- Confidence M (mechanism confirmed in SQL; which trigger fires in the field needs the DB look).

### ENG-3 [P2 | verified] verify.rs truncating height cast on server data
- verify.rs:24,36 `at: b.height as u32` — CompactBlock.height is u64 from the server; silent wrap on
  malicious/broken input; `at` feeds reorg recovery (`truncate_to_height(at-10)`) → wrong-rewind storm.
- Fix: `u32::try_from(...).map_err(→ MisbehavingServer)`. Confidence H (fix trivial; exploit unlikely).

### ENG-4 [P2 | verified] FFI event ring drops oldest at 64 with no overflow log — FoundTransactions loss possible
- ffi_handle.rs:179-182 (+ supervisor push path 165-169): FIFO drop at cap, no criticality distinction,
  no warn. Swift has a DB-resync fallback ("resilient foundTransactions emission") — Phase 2 confirms
  it fully compensates; regardless, log overflow + consider never dropping tag-4/5.
- Confidence H (behavior), M (user impact).

### ENG-5 [P2 | verified] Mempool: one failed decrypt_and_store kills the session; dedupe set can clear
- mempool.rs:131-132 error propagates → session ends; seen-set clears at cap (87-89); if server doesn't
  replay, a pending tx is invisible until its block is scanned. Plausibly feeds app bugs "$0 send never
  appears" / "live pending state missing" (Phase 2 verdict pending).
- Fix: per-tx isolate + skip-on-error, keep session alive. Confidence M.

### ENG-6 [P2 | verified] Enhancement: single txid-fetch/apply error aborts the whole round
- enhance.rs:155-157 `?` propagation; pass-level retry (bounded) is the only recovery; a persistently
  bad tx starves the rest. Fix: per-tx isolation + failure counter. Confidence M.

### ENG-7 [P2 | verified] open_mempool_stream has no open-handshake timeout
- grpc.rs:291-303: headers arrive lazily by design, so the open await can hang on a dead-but-accepted
  flow; session idle (60s) bounds first MESSAGE, not the open. Fix: separate ~10s open timeout treated
  as connection failure. Confidence M.

### ENG-8 [P2 | downgraded from agent P0] Panic mid-mutating FFI call leaves handle state un-rolled-back
- lib.rs:4428/4539/4610: catch_panic returns default; handle stays alive; a start() that panicked
  half-way can leave state inconsistent (no UB — memory safe). Fix: on caught panic in mutating calls,
  force state to Error/Idle or set a poison flag. Confidence M.

### ENG-9 [P2 | verified] FFI hardening: drain buffer stride contract + free() double-free reliance on Swift discipline
- lib.rs:4623 copy_nonoverlapping trusts caller stride; free has no generation guard (lib.rs:4644-48).
  Swift actor discipline currently guarantees both. Fix: doc the contract + optional freed-flag.
- Confidence M.

### ENG-10 [P2 | verified, mitigated] Snapshot torn reads (Relaxed atomics)
- ffi_handle.rs:186-207: fields read independently; cross-field consistency not guaranteed → progress
  can transiently mis-compute. SDK's monotonic progress floor already absorbs regressions (Phase 2
  confirms coverage). Fix optional: document; UI must clamp. Confidence H (behavior), L (impact).

### ENG-11 [P3] spendable_hint resets per pass; Historic-only pass would leave it 0
- events.rs:149 begin_pass reset; safe under upstream suggest_scan_ranges contract (ChainTip first);
  document the contract dependency or make it session-monotonic. (1A, M.)

### ENG-12 [P3] `dangerously_trust_everyone` is fs-mistrust (file permissions), not TLS — rename/doc; macOS=false path worth a bootstrap check
- connector.rs:80-86 + lib.rs:4498 `cfg!(target_os = "ios")`. NOT a CA bypass (1D's P0 refuted).
  On macOS the flag is false → arti enforces dir permissions in the sandbox container; if Tor bootstrap
  ever fails on macOS with permission errors, this is where to look.

### ENG-13 [P3] endpoint.tls=false silently allows plaintext HTTP
- grpc.rs:144-157: by design for dev; add a WARN when tls=false on a non-loopback host.

### ENG-14 [P3] Golden oracle is blind to VIEWs (by design) — view correctness rests on its unit tests only
- oracle.rs table-only diff; reconcile view has tests (good) but see ENG-2 gaps. Optional: second
  allowlist for views.

### ENG-15 [P3] Enhancement/address queries share one Tor client (one circuit) per pass — linkability tradeoff
- enhance.rs:377/ mempool fresh-client asymmetry; mirrors upstream SDK; document the tradeoff (the
  addresses go to the same lightwalletd anyway; circuit rotation would only unlink at the network layer).

### ENG-16 [P3 | verified] Published repo diverged from shipping engine
- reconcile.rs entirely unpublished; connector/fetch/ffi_handle/lib/session/wallet_session differ vs
  github.com/LukasKorba/slipstream @1865d6f. Fix: re-publish + define cadence.

### ENG-17 [P3 | verified] Crate versions all 0.0.1; "v0.2.5" exists only in RELEASE_NOTES.md
- Fix: version bump discipline or workspace version + git tags on the public repo.

### ENG-18 [P3 | verified] docs/slipstream/STATE.md "NEXT ACTION" stale
- Says the 06-30 balance fix is uncommitted; it landed as 6f2153f0. Update the header.

## Refuted / reclassified agent claims (do not re-litigate)
- **1B "P0 tree flush after row writes (crash window)" — REFUTED**: rows + flush_sapling/flush_orchard +
  notify_scan_complete all inside ONE `inner.transactionally` closure (persist.rs:543→930, explicit
  "SAME txn" comment). Crash ⇒ full rollback. Becomes verified-OK #1.
- **1B "P1 db_checkpoints stale after mid-flush crash" — REFUTED for crash** (process dies, maps are
  in-memory, re-seeded from consistent SQLite on restart). Error-continue path: pass fails → session
  restart re-seeds. No stale-continue window found.
- **1B "P1 nullifier tracked after note insert" — REFUTED**: ordering inside one txn is externally
  invisible; no mid-txn reader of nullifier_map exists on that connection.
- **1D "P0 Tor skips CA verification" — REFUTED**: flag is arti fs-mistrust (file permissions), not TLS.
  → ENG-12 (P3).
- **1D "P3 darkside may ship in release" — CLOSED**: `darkside = []` not in default features; FFI dep
  pulls no features (repo Cargo.toml). Verified-OK.
- **1E "P0 GPU unwraps" — RECLASSIFIED unreachable-in-release**: `gpu` feature off by default; release
  libzcashlc has zero wgpu (Cargo.toml comment, B0.1 verified). Remains a B1 backlog item for GPU builds.

## Verified-OK coverage (engine invariants checked and sound)
1. **Atomic block persistence** — rows+trees+scan-queue in one txn (persist.rs:543-930).
2. **Pass serialization** — pass_lock outermost in run_session; restart-safe; test-proven (session.rs:197-209, 594-624).
3. **Reorg recovery** — ScanContinuity → truncate(at−10), ≤5 consecutive, backoff 500ms×n cap 3s (scheduler.rs:213-290).
4. **Write-behind barriers** — all early returns land at the drain; stashed unit intentionally dropped (range re-suggested) (scan.rs:200-241).
5. **Panic supervision** — spawn_supervised converts panics to Error(2)+event; test-proven; poison-recovery uniform (ffi_handle.rs:135-174; session.rs:171-177).
6. **Logging privacy** — no seeds/keys/addresses/amounts/memos in production logs (crate-wide sweep).
7. **Network resilience** — bounded retry/backoff on direct connect (6×, exp cap), treestate (3×), fetch workers (3× zero-progress), unary 30s timeouts, stream idle 30s, per-sub-chunk 120s progress deadline; Tor NEVER falls back to direct; mempool failure non-fatal to follow loop.
8. **TLS** — webpki roots on direct TLS connections; darkside compile-gated.
9. **Error taxonomy** — transient/fatal classification exhaustive; no cause-loss (error.rs:39-48).
10. **Arithmetic/indexing** — saturating/clamped math, bounds-safe tree/chunk indexing (1E sweep; ~45 unwraps all test-only).
11. **Snapshot/null-safety at FFI** — null-checked handles, by-value snapshot, UTF-8 strict decode, config numeric validation + device-memory derating.
12. **Reconcile view logic** for the single-account software case — dangling→linked transitions test-covered.

## Open questions carried to Phase 2/4
- OQ-1 (→P4 #1): device-DB check of Keystone-account `received_notes.nf` NULLness (ENG-2 trigger).
- OQ-2 (→P2): does Swift's DB-resync fully compensate event-ring drops (ENG-4)?
- OQ-3 (→P2): Swift polling — any dependence on cross-field snapshot consistency (ENG-10)?
- OQ-4 (→P4): upstream suggest_scan_ranges contract for spendable_hint (ENG-11).
- OQ-5 (→P2): who on the Swift side writes data.db (BUSY exposure both directions, ENG-1)?
