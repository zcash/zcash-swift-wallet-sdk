# Phase 3 — Completeness: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (or executing-plans). Checkboxes are execution aids — STATE.md is the completion record.
> Before ANY task: read `docs/slipstream/STATE.md` + `docs/slipstream/CONVENTIONS.md`. LOCAL-ONLY: never push, never create remote issues/PRs.

**Goal:** The engine produces a COMPLETE wallet: enhanced transactions (full tx data via concurrent fetches), transparent UTXOs, reorg recovery at the tip, and an honest progress surface with per-stage timing — gated by **G3: parity with the Swift-oracle expectations on darkside fixtures, including enhanced fields** (mainnet-seed parity recorded as needs-user).

**Architecture:** New modules `enhance` (transaction_data_requests loop: concurrent gRPC fetches, serial DB applies) and `transparent` (upstream refresh_utxos port). `scan` gains a STRUCTURED continuity error; `scheduler` gains the upstream reorg arm (truncate → re-suggest). `engine` wires: transparent refresh → scan loop → enhancement; and exposes a shared `Progress` (atomics) that the CLI renders. SyncReport gains per-stage wall-clock (Decision-Log requirement for G5).

**Task remap vs ROADMAP P3 index** (record in STATE): T3.1=grpc additions; T3.2=enhancer (ROADMAP T3.1); T3.3=transparent/UTXO (T3.2); T3.4=reorg recovery (deferred TODO from T2.5 — must exist before P4's darkside reorg subset); T3.5=events/progress + stage timing (T3.3); T3.6=G3 parity + gate (T3.4).

## Verified code-reality facts (2026-06-10)

- Enhancement applies via `decrypt_and_store_transaction(&network, &mut db, &tx, mined_height)`; tx parsing: `Transaction::read(tx_bytes, BranchId::Sapling)` — branch ID is irrelevant for decrypt/serialize/txid (copy the load-bearing comment from `rust/src/lib.rs:2045-2051`). Mined-height semantics (`rust/src/lib.rs:2059-2068`): `>0 → Some(h)`, else `None` (mempool/fork).
- Status updates: `db.set_transaction_status(txid, TransactionStatus::{TxidNotRecognized|NotInMainChain|Mined(BlockHeight)})` (`rust/src/lib.rs:3015-3037`); requests: `db.transaction_data_requests() -> Vec<TransactionDataRequest>` (`lib.rs:3057`; variant semantics mirrored by the OLD SDK's Swift enhancer `Sources/ZcashLightClientKit/Block/Enhance/BlockEnhancer.swift:94-171` — GetStatus → fetch+set_status; Enhancement → fetch+(decrypt_and_store | set_status TxidNotRecognized); TransactionsInvolvingAddress → taddr-txid stream + decrypt_and_store, with the same skip-guards for unsupported filters).
- UTXO refresh: port registry `zcash_client_backend-0.22.0/src/sync.rs:475-534` verbatim-adapted (`WalletTransparentOutput::from_parts` + `db.put_received_transparent_utxo`); per-account start height via `db.utxo_query_height(account_id)` (sync.rs:113-121); runs BEFORE shielded scanning (sync.rs comment).
- Reorg arm: registry sync.rs:404-418 — `Err(ChainError::Scan(err)) if err.is_continuity_error()` → compute rewind → `db.truncate_to_height(rewind_height)` → re-suggest. Read that exact region for the rewind computation when implementing.
- grpc needs three new calls (tor.rs precedents at rust/src/tor.rs:142-286): `get_transaction(TxFilter{hash: txid, ..})`, `get_taddress_txids(TransparentAddressBlockFilter)` (stream), `get_address_utxos_stream/get_address_utxos` (stream) — proto types in `zcash_client_backend::proto::service`.
- Darkside reorg fixtures exist: `Tests/TestUtils/DarkSideWalletService.swift:13-15` (before-reorg/after-small-reorg/after-large-large URLs); the Swift `ReOrgTests` are the behavioral oracle.
- Memo/fee oracle for enhanced fields: `Tests/DarksideTests/BalanceTests.swift` + `DarksideSanityCheckTests.swift` (the 663174 tx carries a memo in some tests — extract exact expectations at implement time; if the fixture txs have no asserted memo in Swift, assert raw-tx presence + fee/expiry fields only).
- Per-stage timing requirement: STATE Decision Log 2026-06-10 ("SyncReport carries counts, not per-stage wall-clock — P3 must add timing for honest G5 bound reporting").

**File structure:**

```
slipstream/core/src/grpc.rs          # MODIFY (T3.1): + get_transaction, get_taddress_txids, get_address_utxos
slipstream/core/src/enhance.rs       # CREATE (T3.2)
slipstream/core/src/transparent.rs   # CREATE (T3.3)
slipstream/core/src/scan.rs          # MODIFY (T3.4): structured continuity error
slipstream/core/src/error.rs         # MODIFY (T3.4): + ScanContinuity { at }
slipstream/core/src/scheduler.rs     # MODIFY (T3.4): reorg arm; (T3.5) stage timing
slipstream/core/src/events.rs        # MODIFY (T3.5): Progress atomics + Snapshot wiring
slipstream/core/src/engine.rs        # MODIFY (T3.2/3/5): wiring + Progress exposure
slipstream/cli/src/main.rs           # MODIFY (T3.5): live ticker + richer summary
slipstream/core/tests/darkside_sync.rs    # EXTEND (T3.6): enhanced-field asserts
slipstream/core/tests/darkside_reorg.rs   # CREATE (T3.4)
docs/slipstream/STATE.md             # per task
```

---

### Task 3.1: grpc additions (fetch-tx, taddr-txids, address-utxos)

- [ ] Add to `grpc.rs` (mirror existing wrapper style; types from `zcash_client_backend::proto::service`):

```rust
use zcash_client_backend::proto::service::{
    GetAddressUtxosArg, GetAddressUtxosReply, RawTransaction, TransparentAddressBlockFilter,
    TxFilter,
};

/// Fetch a full transaction by txid. Returns the raw bytes + mined height
/// (0 = mempool, per lightwalletd conventions; see rust/src/lib.rs:2053-2068).
pub async fn get_transaction(
    client: &mut LwdClient,
    txid: [u8; 32],
) -> Result<RawTransaction, SlipstreamError> {
    Ok(client
        .get_transaction(TxFilter { hash: txid.to_vec(), ..Default::default() })
        .await
        .map_err(|e| transport_err("get_transaction", e))?
        .into_inner())
}

/// Stream raw transactions involving a transparent address in a height range.
pub async fn get_taddress_txids(
    client: &mut LwdClient,
    filter: TransparentAddressBlockFilter,
) -> Result<Vec<RawTransaction>, SlipstreamError> {
    client
        .get_taddress_txids(filter)
        .await
        .map_err(|e| transport_err("get_taddress_txids", e))?
        .into_inner()
        .map_err(|e| SlipstreamError::Transport(format!("taddress txid stream: {e}")))
        .try_collect()
        .await
}

/// Collect UTXOs for the given transparent addresses from `start_height`.
pub async fn get_address_utxos(
    client: &mut LwdClient,
    addresses: Vec<String>,
    start_height: u64,
) -> Result<Vec<GetAddressUtxosReply>, SlipstreamError> {
    client
        .get_address_utxos_stream(GetAddressUtxosArg {
            addresses,
            start_height,
            max_entries: 0,
        })
        .await
        .map_err(|e| transport_err("get_address_utxos", e))?
        .into_inner()
        .map_err(|e| SlipstreamError::Transport(format!("utxo stream: {e}")))
        .try_collect()
        .await
}
```
BINDING: exact proto field names (TxFilter/GetAddressUtxosArg) — check `zcash_client_backend::proto::service` generated source or tor.rs usage; adjust + report. Hermetic tests: none meaningful (typed pass-throughs); darkside/live cover later. Run suites + clippy. STATE T3.1 done; NEXT T3.2. Commit `[#1755] slipstream: grpc transaction/taddr/utxo wrappers`.

---

### Task 3.2: `enhance` — transaction_data_requests loop

- [ ] Create `slipstream/core/src/enhance.rs`:

```rust
//! Enhancement: turn detected transactions into complete wallet records by
//! fetching full tx data. Fetches run with bounded concurrency; DB applies are
//! serial (&mut session). Semantics mirror the old SDK's BlockEnhancer and the
//! TransactionDataRequest contract (see plan facts for oracles).

use futures_util::{StreamExt, stream::FuturesOrdered};
use tracing::{debug, info, warn};
use zcash_client_backend::data_api::{
    TransactionDataRequest, TransactionStatus, WalletRead,
    wallet::decrypt_and_store_transaction,
};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

use crate::{
    error::SlipstreamError,
    grpc::{self, LwdClient},
    wallet_session::WalletSession,
};

#[derive(Debug, Default, Clone)]
pub struct EnhanceStats {
    pub requests: u64,
    pub txs_stored: u64,
    pub statuses_set: u64,
    pub skipped: u64,
}

const FETCH_CONCURRENCY: usize = 8;

/// Drain all transaction data requests. Loops because applying responses can
/// enqueue follow-up requests; bounded to a few rounds to guarantee progress.
pub async fn run_enhancement(
    session: &mut WalletSession,
    client: &mut LwdClient,
    network: zcash_protocol::consensus::Network,
) -> Result<EnhanceStats, SlipstreamError> {
    let mut stats = EnhanceStats::default();
    for round in 0..3 {
        let requests = session
            .db_mut()
            .transaction_data_requests()
            .map_err(|e| SlipstreamError::Wallet(format!("transaction_data_requests: {e}")))?;
        if requests.is_empty() {
            break;
        }
        debug!(round, count = requests.len(), "enhancement round");
        stats.requests += requests.len() as u64;

        // Partition: txid-fetches run concurrently; address-window requests serial.
        let mut fetches = FuturesOrdered::new();
        let mut address_reqs = Vec::new();
        for req in requests {
            match req {
                TransactionDataRequest::GetStatus(txid) => {
                    let mut c = client.clone();
                    fetches.push_back(async move {
                        (txid, false, grpc::get_transaction(&mut c, *txid.as_ref()).await)
                    });
                }
                TransactionDataRequest::Enhancement(txid) => {
                    let mut c = client.clone();
                    fetches.push_back(async move {
                        (txid, true, grpc::get_transaction(&mut c, *txid.as_ref()).await)
                    });
                }
                other => address_reqs.push(other),
            }
        }

        let mut buffered = fetches.buffered_concurrent_helper(FETCH_CONCURRENCY); // BINDING: see note
        while let Some((txid, want_enhance, fetched)) = buffered.next().await {
            match fetched {
                Err(err) => {
                    // lightwalletd returns an error for unknown txids — record per
                    // the GetStatus contract rather than failing the sync.
                    warn!(%err, "tx fetch failed; marking TxidNotRecognized");
                    session
                        .db_mut()
                        .set_transaction_status(txid, TransactionStatus::TxidNotRecognized)
                        .map_err(|e| SlipstreamError::Wallet(format!("set_transaction_status: {e}")))?;
                    stats.statuses_set += 1;
                }
                Ok(raw) => {
                    let mined_height = if raw.height > 0 {
                        u32::try_from(raw.height).ok().map(Into::into)
                    } else {
                        None
                    };
                    if want_enhance {
                        // Branch ID irrelevant here (decrypt/serialize/txid only) —
                        // see rust/src/lib.rs:2045-2051.
                        let tx = Transaction::read(&raw.data[..], BranchId::Sapling)
                            .map_err(|e| SlipstreamError::Wallet(format!("tx parse: {e}")))?;
                        decrypt_and_store_transaction(&network, session.db_mut(), &tx, mined_height)
                            .map_err(|e| SlipstreamError::Wallet(format!("decrypt_and_store: {e}")))?;
                        stats.txs_stored += 1;
                    } else {
                        let status = match mined_height {
                            Some(h) => TransactionStatus::Mined(h),
                            None => TransactionStatus::NotInMainChain,
                        };
                        session
                            .db_mut()
                            .set_transaction_status(txid, status)
                            .map_err(|e| SlipstreamError::Wallet(format!("set_transaction_status: {e}")))?;
                        stats.statuses_set += 1;
                    }
                }
            }
        }

        for req in address_reqs {
            apply_address_request(session, client, &network, req, &mut stats).await?;
        }
    }
    info!(requests = stats.requests, stored = stats.txs_stored, statuses = stats.statuses_set, skipped = stats.skipped, "enhancement done");
    Ok(stats)
}
```
BINDING NOTES: (1) `FuturesOrdered` has no `buffered_concurrent_helper` — that line is a placeholder for the real form: build a `futures_util::stream::iter(request_futs).buffered(FETCH_CONCURRENCY)` over closures, or push into `FuturesUnordered` and accept unordered application (DB applies are independent per txid — unordered is FINE; prefer `FuturesUnordered` + document). Implement the compiling form and report it. (2) `TransactionDataRequest` variant shapes (tuple vs struct, SpendsFromAddress/TransactionsInvolvingAddress naming) differ across versions — mirror what `rust/src/lib.rs` (search `TransactionDataRequest::`) and the Swift enhancer handle; implement `apply_address_request` to mirror BlockEnhancer.swift:124-171: guards for unsupported filters (skip + count `stats.skipped`), then `grpc::get_taddress_txids` over the request's window applying `decrypt_and_store_transaction` per returned raw tx (same mined-height rule). (3) `set_transaction_status` may live behind `WalletWrite` — import accordingly. (4) GetStatus failure→TxidNotRecognized only for NOT-FOUND-style errors; transport-level failures (connection refused) should propagate — distinguish by tonic Status code if accessible from the error string is too lossy; acceptable v0: propagate on connect-class errors from the FIRST request, tolerate per-txid not-found (document choice).
- [ ] Wire into `engine::sync_once` AFTER `run_to_completion`: `let enhance = enhance::run_enhancement(&mut session, &mut client, config.network).await?;` and surface `EnhanceStats` in `SyncOutcome` (new field). CLI summary gains `enhanced: {txs_stored} txs, {statuses_set} statuses`.
- [ ] Tests: hermetic `enhance_stats_default_is_zero`; real coverage in T3.6 darkside asserts. Suites + clippy. STATE T3.2 done; NEXT T3.3. Commit `[#1755] slipstream: enhancement loop (concurrent fetch, serial apply)`.

---

### Task 3.3: `transparent` — UTXO refresh

- [ ] Create `slipstream/core/src/transparent.rs` as a port of registry sync.rs:475-534 (READ it first; adapt to our error type and grpc wrapper):
  - For each `account_id` in `session.db_mut().get_account_ids()`: `let start = db.utxo_query_height(account_id)` (mirror sync.rs:113-121); collect the account's transparent receivers (sync.rs uses `db.get_transparent_receivers(account_id, ...)` — mirror its exact call + filtering); call `grpc::get_address_utxos(...)`; for each reply build `WalletTransparentOutput::from_parts(OutPoint::new(txid, index), TxOut{value, script_pubkey}, mined_height)` exactly as sync.rs:511-533 and `db.put_received_transparent_utxo(&output)`.
  - Returns `TransparentStats { accounts: u64, utxos: u64 }`.
- [ ] Wire into `sync_once` BEFORE the scan loop (upstream ordering, sync.rs:108-121 comment). Surface stats in SyncOutcome + CLI line.
- [ ] BINDING: exact WalletRead method names for receivers (`get_transparent_receivers`) and types (Script/Zatoshis conversions) — mirror sync.rs verbatim; report deviations. Suites + clippy. STATE T3.3 done; NEXT T3.4. Commit `[#1755] slipstream: transparent UTXO refresh (upstream port)`.

---

### Task 3.4: Reorg recovery (structured continuity error + scheduler arm + darkside test)

- [ ] `error.rs`: add variant `#[error("scan continuity break at height {at}; rewound to {rewound_to}")] ScanContinuity { at: u32, rewound_to: u32 }`? NO — keep separation: the ERROR carries only `at`; the rewind is the scheduler's action. Add: `#[error("scan continuity break at height {at}")] ScanContinuity { at: u32 }`.
- [ ] `scan.rs`: where scan_cached_blocks's error is stringified, FIRST match the structured case (mirror upstream sync.rs:404): if the error `is_continuity_error()`, return `SlipstreamError::ScanContinuity { at: <err.at_height() as u32> }` — READ the registry `ChainError`/`ScanError` API for the exact accessor (`at_height()`); fall back to the stringified Wallet error otherwise. Apply to BOTH scan_chunks and scan_chunks_from_treestate (shared small helper fn is fine here).
- [ ] `scheduler.rs`: replace the deferred-TODO with the arm: when scan returns `Err(ScanContinuity { at })`: compute `rewind_height` exactly as upstream sync.rs:404-418 (read it; it subtracts a small buffer / uses err height), `session.db_mut().truncate_to_height(rewind_height)` (BINDING: confirm method + its return/error type; it may return the actual height), `warn!(at, rewind_height, "continuity break — truncated, re-suggesting")`, `continue` the loop (re-suggest picks up the repair range). Cap consecutive continuity-loops (e.g. 5) to avoid infinite reorg ping-pong → error out after.
- [ ] `tests/darkside_reorg.rs` (`#![cfg(feature = "darkside")]`, `#[ignore]`): oracle = Swift `Tests/DarksideTests/ReOrgTests.swift` (READ it for the before/after dataset pair + apply heights + expected post-reorg facts). Flow: stage before-reorg dataset → apply → full pipeline sync (the T2.7-style direct-pipeline driver, reusing its helpers — extract shared test-util into `tests/common/mod.rs` if cleaner) → re-stage after-small-reorg → apply → run the pipeline AGAIN over the new suggested ranges → assert: sync completes, no error, and the wallet's tx/balance facts match the Swift oracle's post-reorg expectations. The SECOND run must hit the ScanContinuity arm (assert via the SyncReport or a counter that truncate happened — add a `reorgs_recovered: u64` to SyncReport).
- [ ] Suites + darkside suite (now 4 ignored tests, serial) + clippy. STATE T3.4 done (+notes: rewind computation used, oracle facts); NEXT T3.5. Commit `[#1755] slipstream: reorg recovery (structured continuity error, truncate + re-suggest)`.

---

### Task 3.5: Progress surface + per-stage timing

- [ ] `scheduler.rs`/`scan.rs`/`fetch.rs` already measure pieces (FetchStats.elapsed). Add to `SyncReport`: `fetch_elapsed: Duration, scan_elapsed: Duration, enhance_elapsed: Duration` — accumulate: fetch task's stats.elapsed; scan wall-clock measured around the scan loop per range; enhance measured in engine. Derive `bound()` helper on SyncOutcome: max of the three (+ report idle if all tiny).
- [ ] `events.rs`: implement `Progress` — `pub struct Progress { pub chain_tip: AtomicU64, pub fetched_blocks: AtomicU64, pub scanned_blocks: AtomicU64, pub enhanced_txs: AtomicU64, pub current_range_end: AtomicU64 }` (Arc-shared; Relaxed ordering; doc: poll-only, D8). `engine::sync_once` gains an optional `progress: Option<Arc<Progress>>` param (None = no-op); fetch reorder loop, scan loop, enhance loop bump counters (pass the Arc down — smallest plumbing: add `Option<Arc<Progress>>` params to run_to_completion/scan_chunks/run_enhancement; default None in tests).
- [ ] CLI: `cmd_sync` builds `Arc<Progress>`, spawns a ticker task printing every 2s (`\r`-style single line or plain lines: `fetched X | scanned Y | enhanced Z`), aborts ticker at end; final summary gains per-stage seconds + `bound: fetch|scan|enhance`.
- [ ] Tests: hermetic Progress counter test; Snapshot stays additive. Suites + clippy. STATE T3.5 done; NEXT T3.6. Commit `[#1755] slipstream: progress surface with per-stage timing`.

---

### Task 3.6: G3 parity + phase gate

- [ ] Extend `tests/darkside_sync.rs`: after the engine pipeline run, ALSO run `run_enhancement` (darkside serves GetTransaction — verify; v0.4.9 supports GetTransaction per its era; if NOT, document and assert enhancement against mainnet instead) and assert enhanced fields vs the Swift oracle: read `DarksideSanityCheckTests.swift`/`BalanceTests.swift` for expected raw-tx/fee/memo facts of the 663174/663188 txs; assert what the oracle asserts (at minimum: `transactions.raw IS NOT NULL`, fee column populated; memo if oracle asserts one). Strict equalities.
- [ ] Mainnet parity seed: record in STATE Blockers: `(G3, needs-user) Provide a mainnet UFVK+birthday with known tx history for full differential parity; until then G3 rests on darkside-oracle parity (incl. enhanced fields) + TEST_UFVK 1M-restore (0-tx wallet) consistency.` Run a fresh 50k mainnet sync with enhancement+transparent enabled to prove the full sync_once path end-to-end (record wall-clock delta vs T2.7's 32.4s scan-only baseline → enhancement/UTXO overhead).
- [ ] Phase gate: hermetic suites; darkside suite (4 tests, serial); `swift test --filter OfflineTests` (419/0); STATE: G3 row updated honestly (darkside parity ☑-with-caveat or full ☑ if user seed arrives first); truth-table row for the enhanced 50k run; T3.6 done; session log `P3 COMPLETE`; NEXT ACTION → **T4.0** (Phase 4 iOS docking plan: FFI surface per D8, XCFramework, SlipstreamSynchronizer, Zodl integration — read ROADMAP P4 + Blockers' P4 items: SeedRequired landmine, A/B baseline protocol).
- [ ] Commit `[#1755] slipstream: G3 parity asserts; phase 3 gate recorded`.

## Phase exit criteria (G3)

- [ ] Hermetic suites green (core ~36+, cli ~15+); darkside suite green serially (sync, reorg, roundtrip, 5000-fetch).
- [ ] Reorg recovery exercised by test (reorgs_recovered ≥ 1 asserted).
- [ ] Enhanced-field parity vs Swift oracle asserted strictly; transparent path wired (mainnet 50k full-path run recorded).
- [ ] G3 gate row honest (darkside-parity basis + mainnet-seed needs-user recorded); OfflineTests 419/0; LOCAL-ONLY intact; NEXT → T4.0.
