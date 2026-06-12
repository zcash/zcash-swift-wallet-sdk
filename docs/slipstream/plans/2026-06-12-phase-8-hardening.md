# Phase 8 — Hardening & Productization: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (or executing-plans). Checkboxes are execution aids — STATE.md is the completion record.
> Before ANY task: read `docs/slipstream/STATE.md` + `docs/slipstream/CONVENTIONS.md`. LOCAL-ONLY: never push, never create remote issues/PRs.

**Goal:** close the user-visible product gaps that remain now that the speed chapter is closed (T6.9b2: iPad at compute floor, 8:32 full-auto; "P8 product gaps are now the highest-value work" — STATE session log 2026-06-12). Concretely, burn down the **Open** rows of the book's gaps table (`docs/slipstream/book/19-gaps-roadmap.html` §19.1):

| Gap (ch.19 status table) | P8 task |
|---|---|
| No periodic tip-following (P8 GAP 2) — Open | **T8.1** |
| Mempool detection missing (P8 GAP 1) — Open | **T8.2** |
| `startFailed(.rustSlipstreamNotOpen)` launch wart — Mitigated | **T8.3** |
| A10-class spam-era memory tuning — Open | **T8.4** |
| `TransactionsInvolvingAddress` skip — Open | **T8.5** |
| Flag / productization decisions — Open | **T8.6** (document, don't decide) |
| Tor not wired / L4a decrypt kernel / shardtree fork tier | **explicitly OUT of P8** (see §Out of scope) |
| darkside ≥v0.5 retirement items | stays **recorded-not-done** (T8.6 re-records) |

A wallet left open in the foreground must keep tracking the chain (T8.1), show an incoming transaction while it is still in the mempool (T8.2), never emit a spurious launch error (T8.3), survive an old-wallet restore on a 2 GB device (T8.4), and serve every upstream transparent-history request shape it can (T8.5). T8.6 sweeps the productization documentation.

---

## Verified code-reality facts (2026-06-12 recon — re-verify only if a build error contradicts them)

Versions in play (unchanged from P6): `zcash_client_backend 0.23.0`, `zcash_client_sqlite 0.21.0` under `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/`. Engine baseline: `ENGINE_BUILD = "2026-06-13.l4b-lanepool2"` (`slipstream/core/src/engine.rs:25`). Baseline suites green at HEAD 40bbe8b7: core 139+1ign, cli 23, stress 1.

### A. FFI runner — single-shot today; the T8.1 seam

- `zcashlc_slipstream_start` (`rust/src/lib.rs:4461`): aborts any in-flight task (lib.rs:4475-4477), sets `SyncState::Syncing` (lib.rs:4478), builds `EngineConfig::new(h.network, h.wallet_db_path.clone(), h.endpoint.clone())` (lib.rs:4490-4494 — **no field overrides**; the T8.4 hint applies here), spawns `sync_body` via `spawn_supervised` (lib.rs:4579-4584).
- `sync_body` (lib.rs:4510-4577): emits SyncStarted (tag=1) ONCE → **bounded pass-retry loop** (lib.rs:4521-4547: `sync_once` → on Err, `should_retry(&err, attempt)`; `PASS_RETRY_MAX = 2` at lib.rs:4255; sleeps 5s/15s via `pass_retry_sleep` lib.rs:4260-4265; only `is_transient()` errors retry — `SlipstreamError::is_transient` = `Transport(_)` only, `slipstream/core/src/error.rs:47-49`) → on Ok: `SyncState::Done` + SyncDone event (tag=3, value=txs_stored, lib.rs:4549-4560); on Err: `SyncState::Error(1)` + tag=4/value=1 event (lib.rs:4562-4575). **Then the task ends — nothing re-arms. This is GAP 2.**
- `zcashlc_slipstream_stop` (lib.rs:4601-4613): `task.abort()` + state=Idle. The `task` field is an `AbortHandle`; a supervisor task owns the JoinHandle and converts panics to `Error(2)` + tag=4/value=2 (`spawn_supervised`, `slipstream/core/src/ffi_handle.rs:120-159`). **tokio `sleep` is abort-safe — a follow loop inside `sync_body` is cancelled by the existing stop()/free()/restart paths with zero new plumbing.**
- `SyncState` enum: `Idle / Syncing / Error(u8) / Done` (ffi_handle.rs:63-68); FFI snapshot `state: u8` = 0/1/2/3 (lib.rs:4305, 4319-4320).
- The ufvk argument: Swift always passes `ufvk=nil` (keyless; account imported in `prepare()`) — `SlipstreamSynchronizer.swift:246-249`. The CLI may pass `Some` on first run. `ufvk=Some` makes `sync_once` call `get_tree_state(birthday-1)` + `ensure_account` per pass (engine.rs:152-155) — **follow passes must pass `None`** (idempotent but a wasted RPC otherwise).

### B. What a pass costs at tip (the no-op-pass cost profile; basis for the tip-check fast path)

`engine::sync_once` (`slipstream/core/src/engine.rs:111-243`) in order:
1. `config.validate()`; birthday-0 guard; `begin_pass()` (engine.rs:136-138 — resets RATIO counters scanned/fetched/pass_total/range_end/**spendable**; monotonic deltas enhanced_txs/ranges_completed/reorgs_recovered untouched — `events.rs:144-150`).
2. `WalletSession::open` (DB open + WAL) + `grpc::connect` (TLS, 10s connect timeout, grpc.rs:140-143).
3. **Preflight RPCs**: `get_subtree_roots` (TWO streams, sapling+orchard, ~1.9k roots total ≈ low hundreds of KB; engine.rs:157-158) → `put_subtree_roots` (DB) → `get_latest_block_height` (1 tiny unary; engine.rs:160) → `update_chain_tip` (DB write; engine.rs:161) → `refresh_utxos` (GetAddressUtxos per transparent address — 1+ unary streams; engine.rs:173).
4. `run_to_completion`: `suggest_scan_ranges` — **at tip it returns no ranges and the scheduler exits immediately** (`scheduler.rs:113-117`: `let Some(range) = ranges.first() else { info!("scan queue empty — sync complete"); return Ok(report) }`).
5. Final `run_enhancement` (engine.rs:186-188): one `transaction_data_requests` DB query; gRPC only if requests are pending.

So a no-op pass ≈ 1 TLS connect + ~4-6 RPC round-trips (subtree roots dominate the bytes) + 2 DB writes. Cheap but NOT free → the follow loop's fast path is **`get_latest_block_height` only** (~100 bytes, one unary under the existing 30s deadline, grpc.rs:160-164), full `sync_once` only when the tip advanced.

- All transport awaits already carry hardening1 deadlines: `UNARY_TIMEOUT = 30s`, `STREAM_IDLE_TIMEOUT = 30s` (grpc.rs:35-40); connect 10s (grpc.rs:143).
- Old-SDK precedent for the cadence: `ZcashSDK.defaultPollInterval = 20` (`Sources/ZcashLightClientKit/Constants/ZcashSDK.swift:98`), jittered `random(in: 10...30)` s (`Block/CompactBlockProcessor.swift:74-76`), applied by a repeating timer that re-calls `start()` whenever the processor is idle (CompactBlockProcessor.swift:841-871). The controller's ~20-30 s sleep matches this exactly.

### C. Swift poll contract (what the follow loop's state choices mean for Zodl)

`SlipstreamSynchronizer.tickPoll()` (`Sources/ZcashLightClientKit/Slipstream/SlipstreamSynchronizer.swift:310-438`), 2 s cadence (startPolling, :287-295):
- `state == 3` (Done) → emits `.synced` immediately (:338-352).
- `state == 1` (Syncing) → `.syncing(counterProgress(scanned, passTotal), spendableHint != 0)` (:353-379); `counterProgress` = `min(scanned/max(total,1), 1.0)` (`SlipstreamSynchronizer+PureHelpers.swift:28-31`).
- `state == 2` → `.error(rustSlipstreamSyncFailed(snap.chainTip))`; **any other value → `.disconnected`** (:389-394). ⇒ **a new state code (e.g. 4=Following) would render as `.disconnected` in unmodified Swift** — this kills the "new Following state" option unless Swift changes too (see Deviations D3).
- **foundTransactions**: primary path fires whenever `snap.enhancedTxs > lastEnhancedCount` → `transactionRepository.find(offset:0, limit:50, kind:.all)` → `.foundTransactions(txs, nil)` (:420-437). **T8.2 only needs to bump the engine's `enhanced_txs` counter on a stored mempool hit — the Swift emission is already wired.**
- **Stall watchdog**: fires only when `state == 1` AND no counter movement ≥120 s (`isSyncStalled`, PureHelpers.swift:156-162) — a follow loop that keeps `state == 3` between passes can never trip it; a real follow pass moves counters.
- `begin_pass()` resets `spendable_hint` → during each follow pass, Swift's Syncing branch reports `spendable=false` until the ChainTip range completes (`scheduler.rs:315-318` re-latches within the pass). Window = pass duration (seconds for a 1-2-block pass). Same class as the old SDK's periodic re-sync recomputing progress per pass. Accepted + documented (Deviations D4).
- `SlipstreamSynchronizer.start()` (:232-258) and `stop()` (:265-283): see fact G for the T8.3 wart mechanics.

### D. Old-SDK mempool mechanism (the behavior we are porting)

- `CompactBlockProcessor.start()` spawns `mempoolDetectionTask = Task { await watchMempool() }` **immediately at sync start, concurrent with the sync run** (`Block/CompactBlockProcessor.swift:281-288`); `stop()` cancels it (:290-292).
- `watchMempool()` (:381-392): `while !cancelled { consumeMempoolStream(); sleep 500 ms }`; on error sleep 30 s (connection-hammering prevention).
- `consumeMempoolStream()` (:394-407): `service.getMempoolStream()` → for each `RawTransaction` → `resolveMempools` → non-empty ⇒ `send(.foundTransactions(txs, height..height))`.
- `resolveMempools` (:409-424): `minedHeight = (raw.height == 0 || raw.height > UInt32.max) ? nil : UInt32(raw.height)` → `rustBackend.decryptAndStoreTransaction(txBytes:minedHeight:)` → `transactionRepository.find(rawID:)` decides whether it was a wallet hit.
- Swift service wrapper: `LightWalletGRPCService.getMempoolStream()` = `compactTxStreamer.getMempoolStream(Empty())` (`Modules/Service/GRPC/LightWalletGRPCService.swift:373-383`); protocol surface `Modules/Service/LightWalletService.swift:224`.
- FFI: `zcashlc_decrypt_and_store_transaction` (`rust/src/lib.rs:2031-2079`) parses `Transaction::read(tx_bytes, BranchId::Sapling)` (branch id irrelevant — v4 caches it for non-consensus ops, v5 parses its own; comment lib.rs:2045-2050), maps `mined_height > 0 → Some(h)` / `≤ 0 → None` ("zero indicates the transaction is in the mempool", lib.rs:2053-2068), calls **upstream `decrypt_and_store_transaction`** (lib.rs:2070).

### E. Mempool API availability (client, server, darkside)

- **Our production gRPC client already has the methods.** `grpc.rs` aliases `LwdClient = CompactTxStreamerClient<Channel>` from `zcash_client_backend::proto::service` (grpc.rs:9-21) — that generated client includes `get_mempool_tx` (zcash_client_backend-0.23.0/src/proto/service.rs:797) and `get_mempool_stream` (service.rs:830, route `/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetMempoolStream`). **No protogen work needed.** (Our own protogen output `slipstream/core/src/grpc_generated/darkside.rs:705/736` also carries both — but that module is the darkside control-plane client, feature-gated; production uses the upstream one.)
- **Proto contract**: `GetMempoolStream(Empty) returns (stream RawTransaction)` — "will keep the output stream open while there are mempool transactions. It will close the returned stream when a new block is mined." (`Sources/.../ProtoBuf/proto/service.proto:188-192`). `RawTransaction.height`, **"when returned by GetMempoolStream(), the latest block height"** (service.proto:34-40) — verified in lightwalletd v0.4.9 source: `common/mempool.go` constructs `RawTransaction{Data: txBytes, Height: uint64(g_lastBlockChainInfo.Blocks)}` — i.e. **the CURRENT TIP, never 0**. The stream is fed by a poller that calls `RawRequest("getrawmempool")` (≥2 s throttle) + `getrawtransaction` per new txid, and closes all client streams when the best-block hash changes (mempool.go `GetMempool`). New clients receive the WHOLE current mempool from index 0, then increments (g_txList replay) → **a reconnect re-delivers txs we already saw; dedupe is required.**
- **Darkside v0.4.9 supports it.** Our binary is `v0.4.9-3-g631bb16` (built 2022-02-20; `Tests/lightwalletd/lightwalletd version`). v0.4.9 `common/darkside.go` `darksideRawRequest` handles `"getrawmempool"` (returns txids of **stagedBlocks + stagedTransactions** — staged-but-not-applied) and `"getrawtransaction"` (serves active, then staged blocks, then staged transactions). `GetMempoolStream` goes through the same `common.GetMempool` poller → **stage a tx without applying ⇒ it streams on GetMempoolStream; ApplyStaged a new height ⇒ best-block hash changes ⇒ the stream closes** = a faithful hermetic mempool-then-mined lifecycle. (Server symbols confirmed in the binary: `walletrpc.compactTxStreamerGetMempoolStreamServer`.)

### F. `decrypt_and_store_transaction` — upstream API, relevance gating, and the mined-height subtlety

- Upstream API: `zcash_client_backend::data_api::wallet::decrypt_and_store_transaction(params, data: &mut DbT, tx: &Transaction, mined_height: Option<BlockHeight>) -> Result<(), DbT::Error>` where `DbT: WalletWrite` (`zcash_client_backend-0.23.0/src/data_api/wallet.rs:207-216`). Already imported by the old-SDK FFI (`rust/src/lib.rs:47-52`). `slipstream-core` already depends on `zcash_client_backend` + `zcash_primitives` (`slipstream/core/Cargo.toml` [dependencies]) — `Transaction::read` and `BranchId` are available with **zero new deps**.
- Storage path: sqlite `store_decrypted_tx` (`zcash_client_sqlite-0.21.0/src/lib.rs:1631-1645`; **requires a known chain tip** — errors `ChainHeightUnknown` otherwise; we always call it after at least one completed pass) → generic `ll::wallet::store_decrypted_tx` (`zcash_client_backend-0.23.0/src/data_api/ll/wallet.rs:620`):
  - **Relevance gate**: "If there is no wallet involvement, we don't need to store the transaction" — `funding_account.is_none() && wallet_transparent_outputs.is_empty() && !d_tx.has_decrypted_outputs()` → early `return Ok(())` with NO rows written (ll/wallet.rs:655-662). ⇒ feeding every mempool tx through is safe; only wallet-relevant txs leave rows. **Hit detection** = post-call `WalletRead::get_transaction(txid)` (`data_api.rs:1839`; sqlite impl lib.rs:859) — Some ⇒ stored ⇒ bump `enhanced_txs`. (Mirrors the old SDK's `find(rawID:)`, fact D.)
  - `mined_height = None` ⇒ `observed_height = chain_tip + 1`, NO `set_transaction_status(Mined)` (ll/wallet.rs:665-674) — the row stays unmined/pending. `Some(h)` ⇒ `set_transaction_status(Mined(h))` immediately (ll/wallet.rs:672-674).
- **The subtlety (controller sketch vs old-SDK reality)**: the controller sketch says "mined_height NULL = mempool". The old SDK actually passes **`Some(server tip)`** for GetMempoolStream txs, because lightwalletd sends `height = tip` (fact E) and `resolveMempools` only nils `height == 0` (fact D). That marks a 0-conf tx `Mined(tip)` — a height that is wrong the moment it actually mines at ≥tip+1 (later corrected by scan/`put_tx_meta`). The schema explicitly supports unmined-with-mined_height-set (`zcash_client_sqlite-0.21.0/src/wallet/db.rs:317, 328, 571`; `v_transactions` LEFT JOINs blocks on mined_height, db.rs:1107). **Zodl renders both shapes as 0-confirmation/pending**: `confirmationsWith` returns 0 for `minedHeight == nil` AND for `minedHeight == latestTip` (`secant/Sources/Models/TransactionState.swift:348-354`). Decision: **we pass `mined_height = None`** — semantically correct, matches the controller sketch, avoids storing a known-false height; the follow pass's scan sets the true height when the block arrives. Recorded as Deviation D1 (NOT bug-for-bug old-SDK parity).
- **Oracle argument (why no new oracle level)**: the only write path T8.2 adds is upstream's own `decrypt_and_store_transaction` — the exact audited function the old SDK has called in production for years (`rust/src/lib.rs:2070`), including its `mined_height=None` arm (old SDK uses it for height-0/forked txs, lib.rs:2059-2068). Our golden oracle covers the SCAN pipeline's writes; mempool writes occur only at tip, after the scan surface is quiesced, and converge to the scan's own representation when the tx mines (put_tx_meta on the scanned block). A FULL semantic_diff between a mempool-path wallet and a scan-only wallet is **not** expected clean — `transactions.min_observed_height` legitimately records the observation time (tip+1 at mempool sight vs mined height at scan discovery; ll/wallet.rs:665, db.rs:331) — so T8.2's darkside test asserts the functional columns (raw, mined_height, balance) instead of a blanket clean diff, and the standard scan-path oracles must stay IDENTICAL to prove non-perturbation.

### G. T8.3 wart root cause (start-before-prepare)

- Record (STATE Blockers): Zodl emitted `synchronizerStartFailed(.rustSlipstreamNotOpen)` at app launch before `prepare()` completed; self-recovered.
- `SlipstreamEngine.start()` throws `ZcashError.rustSlipstreamNotOpen` when `handle == nil` (`SlipstreamEngine.swift:89-92`); `open()` runs only from `SlipstreamSynchronizer.prepare()` (SlipstreamSynchronizer.swift:217) AFTER `initializer.initialize(...)`.
- **`SlipstreamSynchronizer.start()` has NO unprepared guard** (:232-258 — goes straight to `engine.start`). Contrast `SDKSynchronizer.start()`: `case .unprepared: throw ZcashError.synchronizerNotPrepared` (`Synchronizer/SDKSynchronizer.swift:189-192`).
- **`SlipstreamSynchronizer.stop()` UNCONDITIONALLY emits `.stopped`** (:265-283) — and `InternalSyncStatus.stopped.isPrepared == true` (only `.unprepared` is false, `Synchronizer.swift:758-764`). Contrast `SDKSynchronizer.stop()`: guards `status != .stopped, != .disconnected` and never force-emits (`SDKSynchronizer.swift:239-256`).
- Zodl sequencing that springs the trap (`secant/Sources/Features/Root/RootInitialization.swift`): `didEnterBackground` → `sdkSynchronizer.stop()` **unconditionally** (:75-76). `willEnterForeground` → if `latestState().syncStatus.isPrepared` → `retryStart` (:69-73); `retryStart` itself re-guards on `isPrepared` (:188-191) → `sdkSynchronizer.start(true)` (:203). **Race**: app launches → `prepareWith` in flight (slow: migrations/Tor) → user backgrounds → `stop()` emits `.stopped` (isPrepared=TRUE despite no open handle) → user foregrounds → both guards pass → `start()` → `engine.start()` → `rustSlipstreamNotOpen`. Self-recovery happens when the normal `initialSetups → initializeSDK → prepareWith → start` chain (:330-374) completes later.
- **Smallest safe fix is SDK-side (two guards in SlipstreamSynchronizer), zero Zodl changes**: (1) `start()` throws `synchronizerNotPrepared` when unprepared (exact SDKSynchronizer parity — Zodl already routes `synchronizerStartFailed` to `.none`, RootInitialization.swift:177-178); (2) `stop()` must not emit `.stopped` over `.unprepared`. With (2), Zodl's existing `isPrepared` guards work as designed and the path is dead; (1) is belt-and-braces for any other caller.

### H. T8.4 memory mechanics

- Tunables: `EngineConfig.memory_budget_bytes` (default 256 MiB, `config.rs:86`; floor 16 MiB, config.rs:120-122) bounds in-flight downloaded block data (wire bytes; decode amplification ~2-3×); `chunk_split_bytes` (default 8 MiB, config.rs:90; floor 1 MiB, config.rs:123-125) bounds one sub-chunk; **the reorder-buffer bound scales automatically**: `AheadGate::new(plan.split_bytes * AHEAD_BUDGET_FACTOR /* =8, fetch.rs:179 */)` (`fetch.rs:568`) — shrinking `chunk_split_bytes` shrinks the ahead budget with no extra knob.
- Field evidence (STATE Blockers, T6.8-S): Mac RSS 1.31→1.84 GB through the spam era on defaults; iPhone 16 Pro (8 GB) fine; **A10 (2 GB, shared with GPU) will jetsam**. Blockers' own sizing suggestion: budget ≈64 MiB + split ≈4 MiB for small devices.
- FFI seam: config is built ONLY at `EngineConfig::new(...)` in `zcashlc_slipstream_start` (rust/src/lib.rs:4490-4494); the handle (`ffi_handle.rs:73-100`) carries open-time parameters (endpoint, db path, network) → **add `total_memory_bytes: u64` to `zcashlc_slipstream_open` + store on the handle + apply scaling in `start`**. Swift call site is ours alone: `SlipstreamEngine.open()` (`SlipstreamEngine.swift:54-79`); the hint is `ProcessInfo.processInfo.physicalMemory` (UInt64). Zero new Rust deps (no `sysinfo`).
- CLI: `--chunk-split-bytes` exists (`slipstream/cli/src/main.rs:61-62`); **`--memory-budget-bytes` does NOT exist yet** — the book ch.19 currently over-claims it ("CLI override: --chunk-split-bytes and --memory-budget-bytes"); T8.4 adds the flag, which also makes the book claim true (T8.6 re-checks).
- iOS Simulator shares Mac RAM — it CANNOT enforce a 2 GB ceiling; the honest acceptance is (a) an instrumented Mac CLI run with the derated budgets through the sandblast region (RSS sampled), and (b) [needs-user] the real A10 935000-birthday restore.

### I. T8.5 — `TransactionsInvolvingAddress` open-ended ranges: what upstream actually generates

- Our skip: `apply_address_request` Guard 1 (`slipstream/core/src/enhance.rs:271-292`) — `block_range_end == None` → warn + skip (dedupe key `"{addr}:open"`). Guards 2 (`request_at` set, :294-315) and 3 (`OutputStatusFilter::Unspent`, :317-334) skip too.
- Old SDK skips the SAME three shapes — `BlockEnhancer.swift:124-143`: "TODO: [#1554] Remove this guard once lightwalletd servers support open-ended ranges" / "[#1551]" requestAt / "[#1552]" Unspent. **Parity is already exact; T8.5 is an upstream-completeness improvement, not a regression fix.**
- Upstream semantics: `block_range_end: Option<BlockHeight>` — "**If set**, only transactions mined at heights less than this height should be returned" (`zcash_client_backend-0.23.0/src/data_api.rs:1131-1135`) ⇒ `None` = unbounded above. The caller contract for the request type (data_api.rs:1181-1196) says to detect involving txs "within the provided block range" via `GetTaddressTxids` and call `notify_address_checked` with the checked-through height. **`zcash_client_backend::sync` (upstream's reference sync loop, src/sync.rs) does not service `transaction_data_requests` at all** (verified: no `TransactionDataRequest` handling in the file) — there is no upstream reference implementation to copy; the correct closed-range conversion is: serve `[block_range_start, current wallet chain height]` (complete as-of-now; lightwalletd's filter takes a CLOSED range) and `notify_address_checked(chain_height)` so the cursor advances and future requests re-cover later heights.
- Wallet chain height without an extra RPC: `WalletRead::chain_height()` (`data_api.rs:1760`; sqlite impl zcash_client_sqlite-0.21.0/src/lib.rs:805 — max of scan_queue) — the engine ran `update_chain_tip` in preflight this pass, so it is current.
- **What generates open-ended requests today** (`zcash_client_sqlite-0.21.0/src/wallet/transparent.rs`, `transaction_data_requests`):
  1. Spend-detection requests (:1782-1799): `block_range_end = Some(min(chain_tip+1, start + DEFAULT_TX_EXPIRY_DELTA + 1))` — **always closed**; already served.
  2. Ephemeral ZIP-320 address checks (:1836-1860): `block_range_end = None` **and** `request_at` possibly set **and** `output_status_filter = Unspent` — i.e. the only open-ended producer ALSO trips guards 2+3. ⇒ converting the range alone does NOT make these serviceable; they continue to be skipped (honest caveat recorded in the ch.19 row + STATE). The conversion still ships: it is correct for any future upstream request shape, and it removes the only structurally-unserviceable guard.

### J. T8.6 productization facts

- Zodl flag: `FeatureFlag.useSlipstreamSynchronizer`, `enabledByDefault: true` with the M1 revert TODO (`secant/Sources/Models/WalletConfig.swift:15-24`); read synchronously at synchronizer construction (`secant/Sources/Dependencies/SDKSynchronizer/SDKSynchronizerLive.swift:54-76`; UserDefaults key `feature_flags_ud_config_cache`, AppDelegate.swift:54-55).
- The book ch.19 table rows to refresh after T8.1-T8.5 land: mempool (Open→Shipped), tip-following (Open→Shipped), A10 memory (Open→Mitigated/Shipped per T8.4 outcome), TIA skip (Open→Mitigated-with-caveat per fact I), launch wart (Mitigated→Fixed). Also fix the ch.19 `--memory-budget-bytes` over-claim (fact H) — failure-first honesty register style.
- MIGRATING.md / CHANGELOG.md live at repo root = old-SDK files; LOCAL-ONLY policy + containment forbid publishing notes there now. Draft release notes live under `docs/slipstream/` until the no-push policy is lifted.
- Error codes: ZRUST0093-0097 already allocated to slipstream (`Error/ZcashErrorCode.swift:263-271`). T8.3 reuses the EXISTING `synchronizerNotPrepared` — **no new error codes anywhere in P8** (no Sourcery run needed).

## Deviations from the controller sketch (say-so section)

1. **T8.2 stores mempool hits with `mined_height = None`, NOT verbatim old-SDK behavior.** The sketch says "mined_height NULL = mempool"; recon (facts D-F) shows the old SDK actually passes `Some(server tip)` because lightwalletd's GetMempoolStream sends `height = tip` (mempool.go) and the Swift mapping only nils `height == 0`. We follow the sketch (and upstream's design intent: `None` ⇒ `observed_height = chain_tip+1`, no false `Mined(tip)` status — ll/wallet.rs:665-674). Zodl renders both shapes identically (0 confirmations — TransactionState.swift:348-354). Consequence: NOT bug-for-bug old-SDK parity on this argument; recorded honestly.
2. **T8.2 runs the mempool stream only at-tip, strictly serialized with sync passes** — the old SDK runs its watcher CONCURRENTLY with sync from `start()` (fact D). Rationale: during a restore the stream is useless work and its writes would contend with the scan's write path (the old SDK relied on Swift `@DBActor` serialization; we have no equivalent cross-task DB serialization in the engine and do not want a second writer beside `sparse_put_blocks`/write-behind). Single-task serialization makes concurrent-writer bugs structurally impossible.
3. **No new `Following` FFI state.** The controller asked "stays Syncing? or new Following state?" — recon (fact C) shows unmodified Swift maps unknown state codes to `.disconnected`, and `state==1` with idle counters for >120 s trips the B4 watchdog. Decision: **Done between passes, Syncing during real passes** — zero FFI/Swift surface change, `.synced` is what Zodl shows at tip (correct), the watchdog never sees an idle Syncing, and the existing tickPoll arms cover everything. The "at-tip" notion T8.2 needs is engine-internal (the follow loop knows it is between passes), not an FFI state.
4. **Progress contract across follow passes = honest per-pass ratio, accepted brief flap.** `begin_pass()` resets ratio counters at each follow pass; a 1-2-block pass shows `.syncing(~0→1, spendable=false)` for a few seconds every ~75 s block cadence (often unobserved between 2 s polls). Mitigation chosen: tip-GATING (no pass at all unless the tip advanced — the flap frequency equals block arrival, same perceived behavior as the old SDK's 10-30 s restart timer). Pre-latching `spendable` across follow passes was considered and REJECTED: it would make the latch lie if a reorg invalidated the tip range mid-pass; the honest window is seconds.
5. **`probe_tip` + loop-in-FFI split** (vs a monolithic core `follow_loop`): the state mutex + event ring live in the FFI handle, and the T6.8-H2 retry ladder already lives in `sync_body` — so the loop body stays in `rust/src/lib.rs` (pure helpers unit-tested there, exactly like `should_retry`), while the only new engine primitives (`engine::probe_tip`, `mempool::run_session`) live in slipstream-core where darkside/CLI tests can exercise them.
6. **Mempool stream idle handling deviates from the blanket 30 s hardening1 rule**: an EMPTY mempool is legitimate silence, indistinguishable from a dead connection. Sessions are bounded by `MEMPOOL_SESSION_IDLE` (60 s) and end with a benign reconnect (not an error); hardening1's 30 s stays on every other stream where silence is pathological. Stream failure is NON-FATAL to following (cap → disable mempool, keep tip-polling).
7. **T8.4 extends the `zcashlc_slipstream_open` signature** rather than adding a setter function. The FFI is prototype-internal (every caller is ours: `SlipstreamEngine.swift:64`); one more parameter keeps the hint immutable-per-handle like endpoint/network, and avoids a stateful setter that could race `start`.
8. **T8.5 scope honesty**: the conversion closes the *guard*, not the user-visible feature — the only upstream producer of open-ended requests also sets `request_at`+`Unspent` (fact I), which remain skipped (same as the old SDK, TODOs #1551/#1552). The ch.19 row closes as "Mitigated (conversion shipped; ephemeral ZIP-320 checks still skipped — same as old SDK)".

## Out of P8 scope (recorded explicitly)

- **Tor integration** (route tonic over arti): own phase if the user wants it; ch.19 row stays Open. The grpc module was built for a swappable channel (`grpc.rs:1-3` header comment).
- **L4a decrypt kernel (column-ECDH)**: PARKED by user (STATE Blockers 2026-06-12).
- **Fork tier** (shardtree `merge_checked` / zcash_client_sqlite L2 raw-SQL): seam-blocked upstream work, stays Parked.
- **darkside ≥v0.5 / zaino upgrade**: recorded-not-done (T8.6 re-records).
- Zodl bgTask follow-on (engine keeps following after BGTask completes until iOS suspends — same class as the old SDK's timer): observe in T8.1 field run; only act if the user reports battery impact.

## File structure

```
rust/src/lib.rs                                  # MODIFY T8.1 (follow loop + helpers in sync_body), T8.2 (mempool session call), T8.4 (open param + scaled config)
slipstream/core/src/engine.rs                    # MODIFY T8.1 (probe_tip; ENGINE_BUILD bumps per task)
slipstream/core/src/grpc.rs                      # MODIFY T8.2 (get_mempool_stream wrapper)
slipstream/core/src/mempool.rs                   # CREATE T8.2 (session loop, dedupe, decrypt+store)
slipstream/core/src/lib.rs                       # MODIFY T8.2 (pub mod mempool)
slipstream/core/src/config.rs                    # MODIFY T8.4 (scaled_for_device_memory)
slipstream/core/src/enhance.rs                   # MODIFY T8.5 (open-ended → closed conversion)
slipstream/core/tests/darkside_follow.rs         # CREATE T8.1 (follow), T8.2 (mempool lifecycle)
slipstream/cli/src/main.rs                       # MODIFY T8.1 (--follow), T8.4 (--memory-budget-bytes)
Sources/ZcashLightClientKit/Slipstream/SlipstreamSynchronizer.swift  # MODIFY T8.3 (two guards)
Sources/ZcashLightClientKit/Slipstream/SlipstreamEngine.swift        # MODIFY T8.4 (physicalMemory hint)
Tests/OfflineTests/SlipstreamOfflineTests.swift  # MODIFY T8.3 (+2), T8.4 (+1 signature smoke)
docs/slipstream/book/19-gaps-roadmap.html        # MODIFY T8.6 (status refresh, failure-first)
docs/slipstream/RELEASE_NOTES_DRAFT.md           # CREATE T8.6 (LOCAL-ONLY notes prep)
docs/slipstream/CONVENTIONS.md                   # MODIFY T8.2 (module list += mempool)
docs/slipstream/STATE.md                         # MODIFY per task
```

---

### Task 8.1: In-foreground tip-following (foundation)

Re-arm the engine after a successful pass: sleep ~25 s → probe the tip with ONE cheap unary → run a full `sync_once` only when the tip advanced. State: Done between passes, Syncing during passes (Deviation D3). Stop/free/restart cancel the loop through the existing AbortHandle (fact A). `begin_pass()` makes repeated passes counter-safe (fact B/C — already shipped in T5.6/T6.8-H2).

- [ ] **Step 1 (core primitive, failing test first):** in `slipstream/core/src/engine.rs` tests add:

```rust
    /// T8.1 — the follow loop's pure re-sync decision.
    #[test]
    fn follow_should_resync_only_when_tip_advances() {
        assert!(!should_resync(3_375_000, 3_374_999)); // tip behind (server lag) → no
        assert!(!should_resync(3_375_000, 3_375_000)); // tip equal → no
        assert!(should_resync(3_375_000, 3_375_001)); // tip advanced → yes
        assert!(!should_resync(0, 0));
    }
```

`cargo test -p slipstream-core follow_should_resync` → compile error. Add to `engine.rs` (near `sync_once`):

```rust
/// True when an observed server tip justifies a new follow pass (T8.1).
/// A server replying with a LOWER tip than the last synced one (load-balanced
/// cluster lag) must NOT trigger a pass — the pass would no-op at best and
/// fight reorg logic at worst; the next probe of a caught-up backend recovers.
pub fn should_resync(last_synced_tip: u64, observed_tip: u64) -> bool {
    observed_tip > last_synced_tip
}

/// One cheap tip probe (T8.1 fast path): connect + GetLatestBlock ONLY —
/// none of the preflight work of a full pass (subtree roots, UTXO refresh).
/// Fresh connection per probe (TLS ~100-300 ms every FOLLOW_POLL; a held
/// connection would need its own keepalive/staleness handling). All awaits
/// carry the hardening1 deadlines (connect 10 s, unary 30 s).
pub async fn probe_tip(config: &EngineConfig) -> Result<u64, SlipstreamError> {
    let mut client = grpc::connect(&config.endpoint).await?;
    grpc::get_latest_block_height(&mut client).await
}
```

- [ ] **Step 2 (FFI loop, helpers + tests first):** in `rust/src/lib.rs` next to the T6.8-H2 constants add:

```rust
/// T8.1 — follow-mode cadence. Sleep between tip probes while at tip.
/// Old-SDK precedent: defaultPollInterval = 20 s, jittered 10–30 s
/// (ZcashSDK.swift:98, CompactBlockProcessor.swift:74-76). 25 s sits in the
/// same band; mainnet blocks arrive ~75 s so we probe ~3× per block.
const FOLLOW_POLL: std::time::Duration = std::time::Duration::from_secs(25);

/// Consecutive follow-iteration transient failures tolerated before the
/// handle surfaces SyncState::Error (a probe failure is most often server
/// weather; following must shrug it off, not die — but an UNBOUNDED silent
/// failure loop would hide a dead server from the user forever).
const FOLLOW_FAILURE_CAP: u32 = 8;
```

Unit tests (same `slipstream_retry_tests`-style module): `follow_poll_is_in_old_sdk_band` (10 ≤ 25 ≤ 30), `follow_failure_cap_is_sane` (≥3). These are constant-contract tests in the spirit of `retry_constants_are_sane`.

- [ ] **Step 3 (the loop):** in `sync_body` (rust/src/lib.rs:4549-4576), today's `match result { Ok → Done+event, Err → Error+event }` becomes: on `Err` — unchanged; on `Ok` — Done + SyncDone event (unchanged), **then enter the follow loop instead of returning**:

```rust
                Ok(outcome) => {
                    // … existing Done + SyncDone push, unchanged …
                    let mut last_tip = outcome.chain_tip;
                    let mut consecutive_failures: u32 = 0;
                    // ── T8.1 follow loop: keep tracking the chain while the app
                    // is foregrounded. stop()/free()/restart abort this task
                    // (AbortHandle), which cancels the sleep/probe safely. When
                    // iOS suspends the process the loop freezes with it and
                    // resumes on foreground (documented; Zodl additionally calls
                    // stop() on didEnterBackground → the loop usually never
                    // survives into the background at all).
                    loop {
                        tokio::time::sleep(FOLLOW_POLL).await;
                        let observed = match slipstream_core::engine::probe_tip(&cfg).await {
                            Ok(t) => { consecutive_failures = 0; t }
                            Err(err) if err.is_transient() => {
                                consecutive_failures += 1;
                                tracing::warn!(%err, consecutive_failures, "follow tip probe failed (transient)");
                                if consecutive_failures > FOLLOW_FAILURE_CAP {
                                    tracing::error!("follow loop giving up after repeated probe failures");
                                    *state.lock().unwrap_or_else(|p| p.into_inner()) = SyncState::Error(1);
                                    push_ring_event(&events, SlipstreamCoreEvent { tag: 4, value: 1 });
                                    return;
                                }
                                continue;
                            }
                            Err(err) => {
                                tracing::error!(%err, "follow tip probe failed (fatal)");
                                *state.lock().unwrap_or_else(|p| p.into_inner()) = SyncState::Error(1);
                                push_ring_event(&events, SlipstreamCoreEvent { tag: 4, value: 1 });
                                return;
                            }
                        };
                        if !slipstream_core::engine::should_resync(last_tip, observed) {
                            continue;
                        }
                        // New block(s): run a full pass. Syncing for the pass
                        // duration only (Deviation D3/D4); keyless (ufvk=None —
                        // the account exists; fact A).
                        *state.lock().unwrap_or_else(|p| p.into_inner()) = SyncState::Syncing;
                        match run_pass_with_retry(&cfg, None, &progress).await {
                            Ok(o) => {
                                last_tip = o.chain_tip;
                                consecutive_failures = 0;
                                *state.lock().unwrap_or_else(|p| p.into_inner()) = SyncState::Done;
                                push_ring_event(&events, SlipstreamCoreEvent { tag: 3, value: o.enhance.txs_stored });
                            }
                            Err(err) => {
                                tracing::error!(%err, failed_at_utc = %slipstream_core::engine::wall_clock_utc(), "follow pass failed");
                                *state.lock().unwrap_or_else(|p| p.into_inner()) = SyncState::Error(1);
                                push_ring_event(&events, SlipstreamCoreEvent { tag: 4, value: 1 });
                                return;
                            }
                        }
                    }
                }
```

Two mechanical refactors this requires (no behavior change — verify with the existing retry tests):
  - Extract the T6.8-H2 retry loop (lib.rs:4521-4547) into `async fn run_pass_with_retry(cfg, ufvk: Option<(&str, u64)>, progress) -> Result<SyncOutcome, SlipstreamError>` and call it for BOTH the initial pass and follow passes (the ladder + warn logs apply identically; `SyncStarted` stays outside, emitted once per `start()`).
  - Extract the duplicated ring-push into `fn push_ring_event(events: &Arc<Mutex<Vec<SlipstreamCoreEvent>>>, e: SlipstreamCoreEvent)` (the cap-then-push at lib.rs:4514-4518/4552-4560/4569-4574 — three copies today).

- [ ] **Step 4 (CLI `--follow` for Mac validation):** `Sync` subcommand gains `#[arg(long, default_value_t = false)] follow: bool`. After the normal `sync_once` summary, when `follow` is set, `cmd_sync` loops: sleep `FOLLOW_POLL`-equivalent (CLI-local const 25 s) → `engine::probe_tip` → `should_resync` → `sync_once(cfg, None, progress)` → print one summary line per pass (`follow pass: +N blocks, tip=T, txs=K`). Ctrl-C exits (tokio main). CLI parse test: `sync_follow_flag_parses`.
- [ ] **Step 5 (darkside follow test):** create `slipstream/core/tests/darkside_follow.rs` (feature `darkside`, `#[ignore]`, serial suite): reuse `darkside_sync.rs` staging helpers — stage chain + fixtures, apply at height H, run the direct pipeline to H; then `stage_blocks_create(H+1, 2)` + `apply_staged(H+2)` (the darkside client already has both — `darkside.rs:68-85`) → assert `engine::probe_tip` returns H+2 and `should_resync(H, H+2)`; run a second `sync_once` (keyless) → assert the wallet's `chain_height()` == H+2 and the new blocks scanned. This proves the exact probe→pass primitive the FFI loop composes. (The FFI loop body itself is exercised by its pure helpers + the Swift/device run — same testing split as T6.8-H2's `should_retry`.)
- [ ] **Step 6:** `ENGINE_BUILD` → `"2026-06-14.t81-follow"`.
- [ ] **Step 7 (gates):** `cargo test -p slipstream-core -p slipstream-cli`; clippy ZERO both feature sets (`cargo clippy -p slipstream-core -p slipstream-cli` and `--features darkside`); darkside serial suite incl. the new test (`cargo test -p slipstream-core --features darkside -- --ignored --test-threads=1` with local lightwalletd); **rust/src/lib.rs touched → `./Scripts/init-local-ffi.sh --macos-only` + `swift test --filter OfflineTests`** (475/0 expected; SPM purge if manifest-cache staleness bites — CONVENTIONS). Mac live validation: `cargo run -p slipstream-cli --release -- sync --server https://zec.rocks:443 --wallet-dir /tmp/t81-follow --ufvk <TEST_UFVK> --birthday <tip-1000> --follow` → watch it go idle at tip, then catch the next real block (~75 s) in one follow pass. Full `./Scripts/init-local-ffi.sh` (3 slices) + tag probe (`strings … | grep t81-follow`) before any device run.
- [ ] **Step 8:** STATE.md (T8.1 row done + session log + NEXT→T8.2; record the Mac follow-pass evidence) + commit:

```bash
git add rust/src/lib.rs slipstream/ docs/slipstream/STATE.md Cargo.lock
git commit -m "[#1755] slipstream: T8.1 in-foreground tip-following (probe_tip fast path + FFI follow loop)"
```

[needs-user] device validation (record in STATE as the T8.1 field protocol): rebuild Zodl (Reset Package Caches + clean; verify `engine_build=2026-06-14.t81-follow` in the log), restore/open a wallet, leave it FOREGROUNDED at tip, send to it from another wallet, wait for the tx to mine → it must appear WITHOUT backgrounding the app (this validates following; 0-conf visibility is T8.2). Watch: a brief `.syncing` flap per block is expected (Deviation D4); battery sanity over ~15 min foreground idle.

---

### Task 8.2: Mempool detection (at-tip 0-conf incoming)

While at tip (between follow passes), hold a `GetMempoolStream` session; decrypt each raw tx via upstream `decrypt_and_store_transaction` with `mined_height=None` (fact F, Deviation D1); on a stored wallet hit bump `enhanced_txs` → Swift's existing foundTransactions path emits (fact C). The stream closing IS the new-block signal (fact E) → probe+pass immediately (better latency than the 25 s poll, which remains the backstop). Mempool failure NEVER kills following (Deviation D6).

- [ ] **Step 1 (grpc wrapper, test-adjacent):** in `grpc.rs` add (mirroring `get_taddress_txids`' shape, but returning the raw stream — the session must react per-message, not collect):

```rust
/// Opens a GetMempoolStream session (T8.2). The server pushes raw mempool
/// transactions as they arrive and CLOSES the stream when a new block is
/// mined (lightwalletd contract, service.proto:188-192). The caller drives
/// the stream with its own idle policy — an empty mempool is legitimately
/// silent, so the blanket 30 s STREAM_IDLE_TIMEOUT does not apply (D6).
pub async fn open_mempool_stream(
    client: &mut LwdClient,
) -> Result<tonic::Streaming<RawTransaction>, SlipstreamError> {
    with_unary_timeout("get_mempool_stream", client.get_mempool_stream(Empty {})).await
}
```

(`with_unary_timeout` already unwraps `Response::into_inner` AND bounds the response-headers wait — grpc.rs:108-120; `RawTransaction`/`Empty` are already imported, grpc.rs:11-15.)

- [ ] **Step 2 (mempool module, failing tests first):** create `slipstream/core/src/mempool.rs` (+ `pub mod mempool;` in lib.rs; CONVENTIONS module list += `mempool`):

```rust
//! At-tip mempool monitoring (T8.2). One session = one GetMempoolStream from
//! connect to server-close; the engine's follow loop runs sessions strictly
//! BETWEEN sync passes (never concurrent with a scan — single-writer by
//! construction). Decryption + storage go through upstream's own
//! decrypt_and_store_transaction (the old SDK's exact write path).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use tracing::{debug, info, warn};
use zcash_client_backend::data_api::{WalletRead, wallet::decrypt_and_store_transaction};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

use crate::{
    config::EngineConfig, error::SlipstreamError, events::Progress, grpc,
    wallet_session::WalletSession,
};

/// A mempool session ends for one of these benign reasons (errors are Err).
#[derive(Debug, PartialEq)]
pub enum SessionEnd {
    /// Server closed the stream — a new block was mined (probe + pass NOW).
    BlockBoundary,
    /// No message for MEMPOOL_SESSION_IDLE — reconnect after a tip probe
    /// (dead-connection vs quiet-mempool are indistinguishable; D6).
    IdleReconnect,
}

/// Idle bound per session. 60 s ≈ block cadence; NOT the hardening1 30 s
/// (an empty mempool is legitimate silence — Deviation D6).
pub const MEMPOOL_SESSION_IDLE: Duration = Duration::from_secs(60);

/// Dedupe-set cap: lightwalletd replays the whole mempool on reconnect
/// (mempool.go g_txList), so `seen` persists across sessions; clear it when
/// it exceeds this bound (mempool churn makes unbounded growth possible).
pub const SEEN_TXIDS_CAP: usize = 4096;

/// Outcome counters for one session (logged; enhanced bump goes to Progress).
#[derive(Debug, Default)]
pub struct SessionStats {
    pub received: u64,
    pub stored_hits: u64,
}

/// Runs one mempool session against `config.endpoint`.
///
/// For each streamed tx: dedupe by txid → parse (`Transaction::read`, branch
/// id irrelevant pre-consensus: rust/src/lib.rs:2045-2050 rationale) →
/// `decrypt_and_store_transaction(…, mined_height=None)` (upstream relevance
/// gate stores ONLY wallet-involving txs — ll/wallet.rs:655-662) → hit check
/// via `WalletRead::get_transaction(txid)` → `progress.add_enhanced(1)` per
/// NEW stored hit (Swift foundTransactions fires off this counter).
///
/// Parse failures on a single tx are logged and SKIPPED (a malformed mempool
/// entry must not kill monitoring); transport errors return Err (the caller
/// applies the non-fatal policy).
pub async fn run_session(
    config: &EngineConfig,
    progress: Option<Arc<Progress>>,
    seen: &mut HashSet<[u8; 32]>,
) -> Result<(SessionEnd, SessionStats), SlipstreamError> {
    let mut session = WalletSession::open(config.network, &config.wallet_db_path)?;
    let mut client = grpc::connect(&config.endpoint).await?;
    let mut stream = grpc::open_mempool_stream(&mut client).await?;
    let mut stats = SessionStats::default();
    if seen.len() > SEEN_TXIDS_CAP {
        seen.clear(); // bounded memory; worst case = one re-emit per live tx
    }
    loop {
        let next = tokio::time::timeout(MEMPOOL_SESSION_IDLE, stream.next()).await;
        let raw = match next {
            Err(_elapsed) => return Ok((SessionEnd::IdleReconnect, stats)),
            Ok(None) => return Ok((SessionEnd::BlockBoundary, stats)),
            Ok(Some(Err(status))) => {
                return Err(SlipstreamError::Transport(format!("mempool stream: {status}")));
            }
            Ok(Some(Ok(raw))) => raw,
        };
        stats.received += 1;
        // NOTE: raw.height is the SERVER TIP, not 0 (lightwalletd mempool.go;
        // fact E). We deliberately pass mined_height=None — Deviation D1.
        let tx = match Transaction::read(&raw.data[..], BranchId::Sapling) {
            Ok(tx) => tx,
            Err(e) => {
                warn!(%e, "mempool tx parse failed — skipping entry");
                continue;
            }
        };
        // TxId: AsRef<[u8; 32]> (zcash_protocol txid.rs:38) — annotate so the
        // deref picks the array impl.
        let txid: [u8; 32] = *tx.txid().as_ref();
        if !seen.insert(txid) {
            continue; // replayed on reconnect — already processed
        }
        decrypt_and_store_transaction(&config.network, session.db_mut(), &tx, None)
            .map_err(|e| SlipstreamError::Wallet(format!("mempool decrypt_and_store: {e}")))?;
        let stored = session
            .db_mut()
            .get_transaction(tx.txid())
            .map_err(|e| SlipstreamError::Wallet(format!("mempool hit check: {e}")))?
            .is_some();
        if stored {
            stats.stored_hits += 1;
            info!(txid = %tx.txid(), "mempool transaction stored (0-conf wallet hit)");
            if let Some(ref p) = progress {
                p.add_enhanced(1);
            }
        } else {
            debug!(txid = %tx.txid(), "mempool transaction not wallet-relevant");
        }
    }
}
```

Hermetic tests in the module: `seen_cap_constant_is_sane` (≥1024), `session_idle_is_longer_than_hardening_unary` (60 > 30, documents D6), plus a dedupe-contract test (pure `HashSet<[u8;32]>` insert semantics on a fixed txid — mirrors `skip_dedupe_counts_unique_keys_only` style). The streaming body is exercised by the darkside test (Step 4) — do NOT mock tonic streams hermetically (no mock-transport precedent in this codebase; the darkside server is the established hermetic-real harness, CONVENTIONS).

- [ ] **Step 3 (wire into the follow loop):** in the T8.1 loop (rust/src/lib.rs), replace the plain `tokio::time::sleep(FOLLOW_POLL).await;` iteration head with the mempool-or-sleep head:

```rust
                        // T8.2: between passes, monitor the mempool. The
                        // server closes the stream on a new block → probe
                        // immediately (lower latency than the 25 s poll).
                        // Mempool failure is NON-FATAL: cap → disable for this
                        // handle, fall back to plain sleep-polling (D6).
                        if mempool_enabled {
                            match slipstream_core::mempool::run_session(&cfg, Some(progress.clone()), &mut seen_txids).await {
                                Ok((end, stats)) => {
                                    mempool_failures = 0;
                                    tracing::debug!(?end, received = stats.received, hits = stats.stored_hits, "mempool session ended");
                                    // BlockBoundary AND IdleReconnect both fall
                                    // through to the tip probe below; a session
                                    // bounds the iteration cadence by itself, no
                                    // extra sleep (probe is cheap; D6).
                                }
                                Err(err) => {
                                    mempool_failures += 1;
                                    tracing::warn!(%err, mempool_failures, "mempool session failed (non-fatal)");
                                    if mempool_failures >= MEMPOOL_FAILURE_CAP {
                                        tracing::warn!("mempool monitoring disabled for this handle (cap reached) — tip polling continues");
                                        mempool_enabled = false;
                                    }
                                    tokio::time::sleep(FOLLOW_POLL).await;
                                }
                            }
                        } else {
                            tokio::time::sleep(FOLLOW_POLL).await;
                        }
```

with loop-locals `let mut mempool_enabled = true; let mut mempool_failures: u32 = 0; let mut seen_txids = std::collections::HashSet::new();` and `const MEMPOOL_FAILURE_CAP: u32 = 5;` (+ constant-sanity unit test). The probe/pass tail of the iteration is unchanged from T8.1.

- [ ] **Step 4 (darkside mempool lifecycle test):** extend `darkside_follow.rs` (`#[ignore]`, serial): stage chain + apply at H → full pipeline sync → **stage the fixture tx at H+1 WITHOUT applying** (darkside `getrawmempool` then serves it; fact E) → `mempool::run_session` with a fresh `seen` set → assert `SessionEnd` returned after receiving ≥1 tx, `stats.stored_hits == 1`, and the wallet now has the tx with **`mined_height` NULL** (hit presence via `WalletRead::get_transaction`; the height via a direct read-only `rusqlite::Connection` on the wallet db: `SELECT mined_height FROM transactions WHERE txid = :txid` — the oracle harness already opens wallet DBs with raw rusqlite, same pattern) → `apply_staged(H+1)` → keyless `sync_once` → assert `mined_height == H+1` and balance includes the fixture amount (**convergence: the scan corrected the row to the same state the scan-only path produces** — the targeted-field differential of fact F). If the darkside binary's GetMempoolStream behaves unexpectedly (e.g. polling cadence makes the test flaky), record the EXACT failure in STATE, mark the test `#[ignore = "darkside mempool flake: <detail>"]`, and fall back to the documented manual validation: CLI `--follow` against mainnet + a real 0-conf send (needs-user) — the limitation goes into Blockers, not under the rug.
- [ ] **Step 5:** `ENGINE_BUILD` → `"2026-06-14.t82-mempool"`. CONVENTIONS module list += `mempool`.
- [ ] **Step 6 (gates — data.db write path touched ⇒ full oracle ladder):** cargo + clippy (both feature sets); darkside serial suite (now incl. follow + mempool tests); hermetic oracles CLEAN (`cargo test -p slipstream-core oracle`); **mainnet tip−2000 oracle `--sparse-b --write-behind-b` → VERDICT IDENTICAL** (proves the scan path is unperturbed; mempool code never runs in the oracle path — this is the non-perturbation gate, fact F); `./Scripts/init-local-ffi.sh --macos-only` + OfflineTests (lib.rs touched); full 3-slice rebuild + tag probe.
- [ ] **Step 7:** STATE.md (T8.2 done + oracle verdicts + darkside mempool evidence + NEXT→T8.3) + commit:

```bash
git add rust/src/lib.rs slipstream/ docs/slipstream/ Cargo.lock
git commit -m "[#1755] slipstream: T8.2 at-tip mempool detection (GetMempoolStream + decrypt_and_store, non-fatal)"
```

[needs-user] field validation: Zodl rebuilt (tag `2026-06-14.t82-mempool` verified), wallet open at tip, send from a non-Slipstream wallet → **the incoming tx must appear while still unmined (0-conf, pending presentation)**, then settle to mined on the next block. This closes P8 GAP 1's user-reported scenario end-to-end.

---

### Task 8.3: `startFailed(.rustSlipstreamNotOpen)` launch wart

Two SDK-side guards restore the SDKSynchronizer state-machine contract; Zodl unchanged (fact G).

- [ ] **Step 1 (failing tests first):** in `Tests/OfflineTests/SlipstreamOfflineTests.swift` add:
  - `testStartBeforePrepareThrowsNotPrepared` — fresh `SlipstreamSynchronizer` (tempdir Initializer, same fixture style as `testWipeSucceedsWhenEngineNeverStarted`), call `start()` WITHOUT `prepare()` → assert it throws `ZcashError.synchronizerNotPrepared` (NOT `rustSlipstreamNotOpen`).
  - `testStopBeforePrepareKeepsUnprepared` — fresh instance, call `stop()` → assert `latestState.internalSyncStatus` is still `.unprepared` (and therefore `isPrepared == false`).

`swift test --filter OfflineTests.SlipstreamOfflineTests` → both fail.
- [ ] **Step 2 (guards):** in `SlipstreamSynchronizer.swift`:
  - `start(retry:)` — first line: `guard latestState.internalSyncStatus.isPrepared else { throw ZcashError.synchronizerNotPrepared }` with a comment citing SDKSynchronizer.swift:189-192 parity and the field record (T5.5 wart). This makes `rustSlipstreamNotOpen` unreachable via the public Synchronizer API (kept for direct `SlipstreamEngine` misuse).
  - `stop()` — wrap the `.stopped` emission: `if latestState.internalSyncStatus.isPrepared { stateSubject.send(…stopped…) }`; the `sdkFlags.sdkStopped()` + `engine.stop()` side effects stay unconditional (mirrors SDKSynchronizer.stop ordering: sdkStopped THEN status guard, SDKSynchronizer.swift:243-249; engine.stop() on a nil handle is already a no-op, SlipstreamEngine.swift:114-116).
- [ ] **Step 3 (gates):** `swift build`; `swift test --filter OfflineTests` (477/0 expected: 475+2); SwiftLint zero new violations (no print, TODO format). Swift-only — no cargo/FFI gates; no Zodl build needed (no Zodl change), but record in STATE that Zodl's `RootInitialization.swift:75-76` unconditional `stop()` is the trigger this hardens against.
- [ ] **Step 4:** STATE.md (T8.3 done — move the Blockers "T5.5 wart" item to resolved with the root-cause chain from fact G; NEXT→T8.4) + commit:

```bash
git add Sources/ZcashLightClientKit/Slipstream/ Tests/OfflineTests/ docs/slipstream/STATE.md
git commit -m "[#1755] slipstream: T8.3 guard start-before-prepare + stop-over-unprepared (launch wart)"
```

---

### Task 8.4: A10 spam-era memory tuning (device-memory-aware budgets)

Scale `memory_budget_bytes` + `chunk_split_bytes` for <3 GiB devices from a Swift-provided physical-memory hint (fact H). The AheadGate scales with the split automatically (fetch.rs:568). No new deps.

- [ ] **Step 1 (pure scaling fn, failing test first):** in `config.rs` tests:

```rust
    #[test]
    fn device_memory_scaling_derates_small_devices() {
        let c = config();
        // Unknown (0) and big devices keep defaults.
        assert_eq!(c.clone().scaled_for_device_memory(0).memory_budget_bytes, EngineConfig::DEFAULT_MEMORY_BUDGET);
        assert_eq!(c.clone().scaled_for_device_memory(8 << 30).chunk_split_bytes, EngineConfig::DEFAULT_CHUNK_SPLIT_BYTES);
        assert_eq!(c.clone().scaled_for_device_memory(3 << 30).memory_budget_bytes, EngineConfig::DEFAULT_MEMORY_BUDGET);
        // Sub-3GiB devices (A10 iPad = 2 GiB) derate to the Blockers sizing.
        let small = c.clone().scaled_for_device_memory((3 << 30) - 1);
        assert_eq!(small.memory_budget_bytes, EngineConfig::SMALL_DEVICE_MEMORY_BUDGET);
        assert_eq!(small.chunk_split_bytes, EngineConfig::SMALL_DEVICE_CHUNK_SPLIT_BYTES);
        small.validate().expect("derated config must validate");
    }
```

Implementation (config.rs, after `validate`):

```rust
    /// Derated budgets for <3 GiB devices (A10-class, 2 GiB shared with GPU).
    /// Sizing from the T6.8-S field record (STATE Blockers): 64 MiB wire
    /// budget ≈ 128–192 MiB decoded (2–3× amplification) + per-range sparse
    /// tree + allocator HWM stays well under the ~1.4 GiB practical jetsam
    /// line on a 2 GiB device. 4 MiB split keeps the AheadGate (8×split =
    /// 32 MiB) and per-sub-chunk RAM proportionally small.
    pub const SMALL_DEVICE_MEMORY_BUDGET: usize = 64 * 1024 * 1024;
    pub const SMALL_DEVICE_CHUNK_SPLIT_BYTES: usize = 4 * 1024 * 1024;
    /// Devices reporting less physical memory than this are derated.
    pub const SMALL_DEVICE_THRESHOLD_BYTES: u64 = 3 << 30;

    /// Applies device-memory-aware budget scaling (T8.4). `total_memory_bytes`
    /// is the host's physical memory (Swift: ProcessInfo.physicalMemory via
    /// the FFI open hint; CLI: flag override instead); 0 = unknown → defaults.
    /// Only ever DERATES — explicit field overrides after this call win.
    #[must_use]
    pub fn scaled_for_device_memory(mut self, total_memory_bytes: u64) -> Self {
        if total_memory_bytes > 0 && total_memory_bytes < Self::SMALL_DEVICE_THRESHOLD_BYTES {
            self.memory_budget_bytes = Self::SMALL_DEVICE_MEMORY_BUDGET;
            self.chunk_split_bytes = Self::SMALL_DEVICE_CHUNK_SPLIT_BYTES;
        }
        self
    }
```

- [ ] **Step 2 (FFI hint):** `zcashlc_slipstream_open` (rust/src/lib.rs:4393) gains a trailing `total_memory_bytes: u64` parameter; store it on `ffi_handle::SlipstreamHandle` (new field `pub total_memory_bytes: u64` + doc); `zcashlc_slipstream_start` builds `EngineConfig::new(…).scaled_for_device_memory(h.total_memory_bytes)` (lib.rs:4490-4494). Doc-comment the parameter (0 = unknown). cbindgen regenerates the header on rebuild — verify `uint64_t total_memory_bytes` appears in `target/Headers/zcashlc.h`'s declaration.
- [ ] **Step 3 (Swift):** `SlipstreamEngine.open()` passes `ProcessInfo.processInfo.physicalMemory` as the new argument (SlipstreamEngine.swift:63-73; the ONLY call site of `zcashlc_slipstream_open`). The Swift API surface (`open(network:)`) is unchanged — the hint is read internally, so the existing OfflineTests smoke tests compile and pass untouched. The engine actor has no Logger — let the Rust side log the hint instead: in `zcashlc_slipstream_open`, `tracing::info!(total_memory_bytes, "slipstream handle opened")` so every device log states it (field-diagnosis value: an A10 log must show ≈2 GiB + derated budgets).
- [ ] **Step 4 (CLI):** `Sync` gains `#[arg(long, default_value_t = slipstream_core::EngineConfig::DEFAULT_MEMORY_BUDGET)] memory_budget_bytes: usize` (validation floor 16 MiB already enforced by `validate()`, config.rs:120-122); thread into `cmd_sync`'s config. Parse test `sync_memory_budget_flag_parses`. (This also makes the book ch.19 claim true — fact H.)
- [ ] **Step 5 (Mac instrumented acceptance):** re-run the T6.8-S protocol, derated: `cargo run -p slipstream-cli --release -- sync --server https://zec.rocks:443 --wallet-dir /tmp/t84-derate --ufvk <TEST_UFVK> --birthday 1700000 --memory-budget-bytes 67108864 --chunk-split-bytes 4194304` for a 600 s timed observation while sampling RSS (`while :; do ps -o rss= -p <pid>; sleep 10; done`). Acceptance: traverses the same sandblasted heights with **peak RSS materially below the T6.8-S 1.84 GB** (expected ≲1.0-1.2 GB: 64 MiB wire ×2-3 decode + tree + HWM) at a recorded blk/min cost. Record BOTH numbers in the truth table (memory is the goal; the throughput cost must be stated, not hidden).
- [ ] **Step 6:** `ENGINE_BUILD` → `"2026-06-14.t84-devmem"`.
- [ ] **Step 7 (gates):** cargo + clippy both feature sets; darkside serial (no behavior change expected — flag defaults); **FFI signature changed → full `./Scripts/init-local-ffi.sh` (all 3 slices; single-slice landmine), header typedef check, OfflineTests after SPM purge**; tag probe per slice.
- [ ] **Step 8:** STATE.md (T8.4 done + truth-table rows + NEXT→T8.5; Blockers item updated: A10 spam-era → "derate shipped, device run pending") + commit:

```bash
git add rust/src/lib.rs slipstream/ Sources/ZcashLightClientKit/Slipstream/ Tests/OfflineTests/ docs/slipstream/ Cargo.lock
git commit -m "[#1755] slipstream: T8.4 device-memory-aware budget scaling (FFI hint + CLI flag + Mac derate acceptance)"
```

[needs-user] the REAL acceptance: iPad A10, fresh framework (tag `2026-06-14.t84-devmem` in log + the open-line `total_memory_bytes` ≈ 2 GiB), 935000-birthday restore — the run that today jetsams. Watch: survival through 1.70-2.00M, peak memory in Xcode's gauge, wall time (expect slower than the simulator's 51:40 — smaller budget + A10; survival is the gate, speed is recorded).

---

### Task 8.5: Transparent enhancement completeness (open-ended range conversion)

Convert Guard 1's skip into a clamped closed range; guards 2+3 unchanged (fact I, Deviation D8).

- [ ] **Step 1 (failing test first):** `enhance.rs` tests:

```rust
    /// T8.5 — open-ended TransactionsInvolvingAddress ranges clamp to the
    /// wallet's current chain height (end-EXCLUSIVE contract per
    /// data_api.rs:1131-1135: "mined at heights LESS than this height").
    #[test]
    fn effective_range_end_clamps_open_ranges_to_tip() {
        use zcash_protocol::consensus::BlockHeight;
        let tip = BlockHeight::from_u32(3_375_000);
        // Closed range passes through untouched.
        assert_eq!(
            effective_range_end(Some(BlockHeight::from_u32(100)), tip),
            BlockHeight::from_u32(100)
        );
        // Open range → tip + 1 (end-exclusive ⇒ includes the tip block).
        assert_eq!(effective_range_end(None, tip), BlockHeight::from_u32(3_375_001));
    }
```

Implementation (enhance.rs, above `apply_address_request`):

```rust
/// Effective end-EXCLUSIVE bound for a TransactionsInvolvingAddress range
/// (T8.5). `None` means "unbounded above" (data_api.rs:1131-1135); the
/// completest answer a lightwalletd can give RIGHT NOW is through the chain
/// tip, so an open range clamps to `chain_height + 1` (end-exclusive). The
/// post-success `notify_address_checked(end - 1)` then records exactly the
/// height we actually checked through, and the wallet re-issues a fresh
/// request covering later heights next pass — no coverage gap.
fn effective_range_end(
    block_range_end: Option<BlockHeight>,
    chain_height: BlockHeight,
) -> BlockHeight {
    block_range_end.unwrap_or(chain_height + 1)
}
```

- [ ] **Step 2 (rewire Guard 1):** in `apply_address_request` (enhance.rs:271-292): replace the `None → skip` arm. New shape: fetch `let chain_height = session.db_mut().chain_height().map_err(…)?` — when `None` (no scanned tip — cannot happen after preflight, but handle it) keep the OLD skip behavior with key `"{addr}:open-no-tip"`; when `Some(tip)`, `let block_range_end = effective_range_end(tia.block_range_end(), tip);` and proceed — the existing `[start, end-1]` closed-filter construction (enhance.rs:336-349) and `notify_address_checked(block_range_end - 1)` flow are reused verbatim. Remove the now-dead `"{addr}:open"` skip-key arm; KEEP guards 2+3 byte-identical. Update the module doc (enhance.rs:16, 246-261) and the `stats.skipped` doc (one fewer skip class).
- [ ] **Step 3 (privacy note unchanged):** the conversion sends the SAME address strings to `GetTaddressTxids` as closed-range requests already do — no new privacy surface; book ch.15's table already states the transparent-address leakage plainly. One-line comment in the code citing ch.15.
- [ ] **Step 4 (gates):** cargo + clippy both feature sets; darkside serial suite (existing transparent/enhancement tests must stay green — closed-range behavior untouched); hermetic oracles CLEAN (enhancement writes ride `decrypt_and_store_transaction`/`notify_address_checked` — same upstream calls, wider range only). Pure slipstream-internal Rust → OfflineTests optional per CONVENTIONS (skip unless other gates already forced a rebuild).
- [ ] **Step 5:** STATE.md (T8.5 done; the fact-I caveat recorded verbatim: ephemeral ZIP-320 checks still skipped via guards 2+3, same as old SDK #1551/#1552; NEXT→T8.6) + commit:

```bash
git add slipstream/ docs/slipstream/STATE.md
git commit -m "[#1755] slipstream: T8.5 clamp open-ended TransactionsInvolvingAddress ranges to chain tip"
```

---

### Task 8.6: Productization sweep (document, don't decide)

- [ ] **Step 1 (flag decision matrix — document only, the user decides):** add to STATE.md (Blockers section, replacing the bare M1 flag-revert line) the matrix:

| Build destination | `useSlipstreamSynchronizer.enabledByDefault` | Rationale |
|---|---|---|
| User's own dev devices (current mode) | `true` (as-is) | every field session exercises the new engine |
| ANY handoff/TestFlight/external build | `false` + revert commit FIRST | LOCAL-ONLY prototype; old SDK is the supported path; flag flips back per-device via the debug menu |
| Publication (policy lifted) | decision deferred to release review | needs the P8 field record + sign-off |

- [ ] **Step 2 (book gaps-chapter refresh — failure-first):** update `docs/slipstream/book/19-gaps-roadmap.html` §19.1 table + the per-gap sections to the POST-P8 truth: tip-following + mempool → Shipped (with the D1/D2 deviations stated plainly: not bug-for-bug old-SDK; at-tip-only; mined_height=None choice), launch wart → Fixed (root cause from fact G, told failure-first), A10 memory → per T8.4 outcome (Shipped-derate + device-run-pending OR Shipped if the user ran it), TIA skip → Mitigated with the fact-I caveat (ephemeral checks still skipped), `--memory-budget-bytes` claim now true (was an over-claim — say so). Do NOT pre-date statuses: write this step ONLY from STATE.md rows that exist at execution time.
- [ ] **Step 3 (release-notes prep, LOCAL-ONLY):** create `docs/slipstream/RELEASE_NOTES_DRAFT.md` — the future MIGRATING.md + CHANGELOG.md entries, drafted but NOT placed in the root files (containment + no-push; fact J): new `SlipstreamSynchronizer` public surface, behavioral deltas vs SDKSynchronizer (poll-based progress, follow mode, mempool at-tip-only, mined_height=None for 0-conf, TIA guard changes), the `zcashlc_slipstream_*` FFI additions, and the flag-gating story. Header states verbatim: "LOCAL-ONLY — move into MIGRATING.md/CHANGELOG.md only when the user lifts the no-push policy."
- [ ] **Step 4 (recorded-not-done re-record):** darkside ≥v0.5/zaino retirement items stay in Blockers untouched; Tor + L4a + fork tier re-asserted as out-of-scope in STATE's P8 section (mirror of §Out of scope).
- [ ] **Step 5 (gates):** docs-only except STATE — but this is the PHASE CLOSE: run the full ladder once — cargo + clippy both feature sets; darkside serial; OfflineTests; framework freshness probe (current ENGINE_BUILD tag). All green = phase exit.
- [ ] **Step 6:** STATE.md (T8.6 done; P8 section marked complete; NEXT ACTION → the needs-user field-validation block: T8.1/T8.2 foreground+0-conf test, T8.4 A10 old-wallet restore) + commit:

```bash
git add docs/slipstream/
git commit -m "[#1755] slipstream: T8.6 productization sweep (flag matrix, gaps-chapter refresh, release-notes draft)"
```

---

## Phase exit criteria

1. **GAP 2 closed**: a wallet open in the foreground tracks the chain without app-lifecycle restarts — Mac CLI `--follow` evidence + [needs-user] device confirmation recorded in STATE; state contract = Done↔Syncing with no new codes; stop/backgrounding cancels the loop via the existing AbortHandle path.
2. **GAP 1 closed**: an incoming mempool tx appears 0-conf (counter→foundTransactions) and converges to mined on the next pass — darkside lifecycle test green (or its limitation honestly recorded + manual protocol executed); mempool failure demonstrably non-fatal (cap → tip-polling continues).
3. **Wart dead**: start-before-prepare throws `synchronizerNotPrepared`; stop cannot forge `isPrepared`; both OfflineTests green; Blockers item closed with root cause.
4. **A10 path exists**: derate ships (pure fn + FFI hint + CLI flag), Mac instrumented run shows the bounded RSS profile with stated throughput cost; [needs-user] A10 935000 restore is the recorded acceptance (pending-user does not block phase close — it blocks calling the gap *resolved*).
5. **TIA open-ended guard removed** with the ephemeral-checks caveat recorded; old-SDK parity preserved or exceeded; darkside enhancement tests green.
6. **Productization documented**: flag matrix, refreshed ch.19 (statuses match STATE reality, failure-first), release-notes draft (LOCAL-ONLY), out-of-scope items re-recorded.
7. **Every commit**: cargo suites + clippy (both feature sets) green; OfflineTests at every FFI/Swift-touching commit and at phase close; oracle ladder (hermetic + mainnet tip−2000 IDENTICAL) at T8.2 (write-path change) — and ENGINE_BUILD bumped + 3-slice rebuild + tag probe before every device handoff.
