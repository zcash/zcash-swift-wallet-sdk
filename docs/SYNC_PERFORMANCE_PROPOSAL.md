# Sync Performance Deep Dive & Architecture Proposal

**Goal:** order-of-magnitude faster sync of ~1M blocks, closing the gap vs. YWallet (warp sync) and Zingo.
**Scope:** architectural changes only — no Swift micro-optimizations.
**Date:** 2026-06-10. Evidence is `file:line` against this repo @ `main` (9122dea6) and crates from the local Cargo registry (`zcash_client_backend 0.22/0.23`, `zcash_client_sqlite 0.20/0.21`).

---

## 1. TL;DR

The Rust core's cryptography is **already parallel and competitive** — trial decryption runs on all cores via rayon (`zcash_client_backend::scan`, `rayon::spawn_fifo`, scan.rs:178; pool initialized in `rust/src/lib.rs` `zcashlc_init_on_load`). The CPU floor for trial-decrypting 1M post-spam blocks on a modern iPhone is **minutes, not hours**.

The hours are spent in *orchestration*. The SDK runs a strictly serial Swift state machine that processes the chain in **100-block units**, and every unit pays:

| Per-100-block batch cost | Where |
|---|---|
| 1 × `GetTreeState` gRPC round-trip **on the scan critical path** | `BlockScanner.swift:61` |
| 2 × fresh SQLite connection opens (wallet DB + block cache DB) | `rust/src/lib.rs` (`wallet_db()` / `block_db()` per FFI call) |
| 1 × scanning-key preparation + frontier re-materialization | `chain.rs:606`, `lib.rs` treestate decode |
| 1 × full SQLite commit in default (DELETE) journal mode — no WAL anywhere | `chain.rs:661` `put_blocks`; no `PRAGMA journal_mode` in zcash_client_sqlite or zcashlc |
| ~400 file-system syscalls: 100 × (stat + atomic create/write/rename), then 100 × open/read in Rust, then 100 × unlink | `FSCompactBlockRepository.swift:71-110`, sqlite crate `chain.rs:301` (`File::open` per block), `ClearAlreadyScannedBlocksAction.swift:28` |
| 100 × protobuf decode in Swift + 100 × re-encode + 100 × re-decode in Rust | gRPC decode; `ZcashCompactBlock.swift:58` (`serializedData()`); FsBlockDb parse |
| 10 × `writeBlocksMetadata` FFI calls (each opening a fresh FsBlockDb connection) | `FSCompactBlockRepository.swift:98-101` |
| 1 × `findForResubmission` SQLite query | `TxResubmissionAction.swift:36` |
| ~6 actor-hopping state transitions + ~20 awaited context mutations | `CompactBlockProcessor.swift:599-695`, `Action.swift` (`ActionContextImpl` actor) |
| every 5th batch: `getWalletSummary` FFI (heavy aggregates, fresh connection) | `ScanAction.swift:75-105` |

For 1M blocks that is **10,000 iterations**. At a conservative 150–400 ms of fixed overhead per iteration, the architecture tax alone is **25–65 minutes**, before any real downloading or scanning happens — and download and scan barely overlap (≤200-block lookahead), so their times *add* instead of *maxing*.

**The fix that moves the needle by a magnitude is structural: move the sync loop into Rust, stream compact blocks from gRPC directly into the scanner through a bounded in-memory cache, and pipeline download / scan / enhance as concurrent tasks.** Everything required is already linked into `libzcashlc` (tonic gRPC client, arti Tor, `BlockCache` trait, `scan_cached_blocks`). This is precisely the architecture YWallet (warp sync) and Zingo use, and the direction upstream `zcash_client_backend::sync::run()` has started (but not finished — see §3.3).

---

## 2. How sync works today (verified)

### 2.1 The state machine

`CompactBlockProcessor.run()` (`CompactBlockProcessor.swift:593`) executes exactly one `Action` at a time. Steady-state cycle **per 100 blocks** (`ZcashSDK.DefaultBatchSize = 100`, ZcashSDK.swift:91):

```
download → scan → clearAlreadyScannedBlocks → enhance → txResubmission → updateChainTip → download → …
```

Range bookkeeping: when a suggested range completes → `clearCache` (wipes the *entire* block cache, `ClearCacheAction.swift:22`) → `processSuggestedScanRanges` (`suggestScanRanges` FFI) → next range. Every 600 s, `UpdateChainTipAction.swift:46-50` additionally stops the downloader, re-fetches the tip, and *also* wipes the whole cache — discarding up to 200 prefetched blocks.

### 2.2 Download path (per block)

1. grpc-swift (NIO, **single event loop**, compression disabled; `LightWalletGRPCService.swift:138-188`) decodes `CompactBlock` protobuf.
2. `ZcashCompactBlock` immediately **re-encodes** it (`serializedData()`, `ZcashCompactBlock.swift:58`).
3. Buffered 100 at a time (`downloadBufferSize`, `CompactBlockProcessor.swift:71`), then written **one file per block** with stat-check + atomic write (= temp file + rename) (`FSCompactBlockRepository.swift:75-102`).
4. Every 10 blocks, a `writeBlocksMetadata` FFI call (fresh SQLite connection each time).
5. The gRPC stream is torn down and rebuilt every 300 blocks (`rebuildStreamAfterBatchesCount = 3`, `BlockDownloader.swift:67,122-141`).
6. `DownloadAction` leashes the downloader to `batchEnd + 2×batchSize` (= 200 blocks of lookahead, `DownloadAction.swift:49-50`) and waits via a **10 ms polling loop** (`BlockDownloader.swift:273-284`).

### 2.3 Scan path (per 100 blocks)

`BlockScanner.swift:47-84`:

1. `service.getTreeState(height-1)` — **a lightwalletd RPC before every scan call**, serial with scanning.
2. `rustBackend.scanBlocks(fromHeight:fromState:limit:100)` → `zcashlc_scan_blocks`:
   - opens fresh `FsBlockDb` + `WalletDb` SQLite connections (per call),
   - decodes the treestate protobuf and re-materializes the frontier,
   - prepares scanning keys (`ScanningKeys::from_account_ufvks`, chain.rs:606),
   - opens + parses 100 block files (File::open per block, sqlite crate chain.rs:301),
   - trial-decrypts (rayon-parallel — the one fast part),
   - inserts commitments into the SQLite-backed shardtree,
   - commits everything in **one transaction** (`put_blocks`, chain.rs:661) under DELETE journal mode.
3. `didScan` closure: 3 awaited `ActionContext` (actor) mutations + `latestBlocksDataProvider.updateScannedData()` (SQLite reads) per batch (`ScanAction.swift:61-69`).
4. Every 5th batch: `getWalletSummary` FFI. The code itself records that throttling this from 1× to 5× "reduced the synchronization time significantly" (`ScanAction.swift:71-74`, TODO #1353) — direct in-repo evidence that per-batch overhead measurably dominates.

### 2.4 Enhancement

Every 1,000 blocks (`DefaultEnhanceBatch`, ZcashSDK.swift:94): `transactionDataRequests()` FFI, then **serial** per-tx `GetTransaction` RPC + `decryptAndStoreTransaction` FFI (fresh connection each) (`BlockEnhancer.swift:77-177`).

### 2.5 What this adds up to (1M blocks ≈ 10,000 batches)

| Cost bucket | Estimate (device, direct connection) |
|---|---|
| 10,000 × `GetTreeState` RTT (50–150 ms eff.) | **8–25 min** |
| ~120,000 SQLite connection opens (scan 2× + metadata 10× per batch) | **5–20 min** |
| ~4M file syscalls + double protobuf encode/parse (1M blocks) | **5–25 min** |
| 10,000 DELETE-journal commits + shardtree blob churn without WAL | **3–10 min** |
| Download/scan non-overlap (download ≈ 2–5 GB for recent 1M blocks) | **+7–30 min** of additive (not overlapped) network time |
| Actor hops, polling waits, stream rebuilds, per-batch queries | **2–6 min** |
| **Architecture tax total** | **~30–110 min** |
| Trial decryption + tree + DB floor (rayon, all cores) | **~5–15 min** |

Numbers are order-of-magnitude estimates (constants need the benchmark in §6), but they match the observed behavior: wall-clock is dominated by overhead that is *independent of the cryptographic work*, which is why wallets with leaner orchestration appear "magically" faster on the same hardware.

---

## 3. Why YWallet and Zingo are faster

(Architecture facts high-confidence; specific benchmark numbers were not re-verifiable offline and are deliberately omitted.)

### 3.1 YWallet — warp sync (hhanh00/zcash-sync, zcash-warp)
- Single Rust process; compact blocks stream from `GetBlockRange` **directly into the scanner in memory**; blocks are never persisted.
- Trial decryption batched across **all cores**.
- Witness/tree work done **once per large chunk** (builds the frontier across the range and updates owned-note witnesses at chunk boundaries) instead of per-block/per-batch tree maintenance.
- One DB transaction per chunk; full transactions/memos fetched outside the hot loop.

### 3.2 Zingo — BlazeSync heritage and zingo-sync
- Pipelined tokio tasks connected by channels: block fetcher ∥ trial-decryption workers ∥ full-tx fetcher ∥ tree maintenance.
- The `zingo-sync` rewrite adds the librustzcash-aligned model with a **pool of scan workers scanning different ranges concurrently** — parallelism *across* ranges, not just within a decryption batch.

### 3.3 Upstream librustzcash already points the same way
`zcash_client_backend::sync::run()` (sync.rs, behind the `sync` feature — **not currently enabled** in our Cargo.toml) implements the whole loop in Rust: subtree roots → chain tip → suggested ranges → download into a `BlockCache` → `scan_cached_blocks` → reorg handling. Its own header lists what it still lacks (sync.rs:1-10): download/scan overlap, enhancement, progress, interruption. The `BlockCache` trait is async and an in-memory implementation is trivial (the doc example *is* one, chain.rs:304).

Notably, the consumers of that loop use `batch_size ≈ 10,000`; the treestate is then fetched ~once per 10k blocks instead of once per 100. Our Swift loop copied the reference shape but at 1/100th the granularity, from the far side of an FFI boundary, with a disk cache in the middle.

**Common denominator of the fast engines:** (1) stream, never persist blocks; (2) pipeline download/decrypt/commit; (3) parallelize across cores (and ranges); (4) amortize tree work over large chunks; (5) commit in large transactions. The SDK currently does none of these; the Rust crates it already ships contain nearly everything needed to do all five.

---

## 4. Proposal

### P0 — Rust-native streaming sync engine (the magnitude lever)

Move the sync hot loop behind the FFI into `libzcashlc`. Swift keeps lifecycle, configuration, events, and UI progress; Rust owns network + scan + persistence.

```
            ┌─────────────────────────── libzcashlc ───────────────────────────┐
 lightwalletd ──tonic stream──▶ downloader task ──bounded channel──▶ scanner task ──▶ WalletDb (WAL)
 (direct or Tor/arti)           (CompactBlock,      (~10k blocks,     scan_cached_blocks
                                 in memory)          tens of MB)      limit≈10k, keys prepped once
                                       │                                   │
                                       │                              detected txids
                                       │                                   ▼
                                       └──────────▶ enhancement task ──GetTransaction (concurrent)──▶ decrypt_and_store
            └── progress/events via FFI callback or polled shared state ──▶ Swift (SDKSynchronizer)
```

Key design points:

1. **In-memory `BlockCache`** implementing `BlockSource` + `BlockCache` (bounded; back-pressure on the tonic stream). No files, no double serialization, no metadata DB, no cache wipes. The FsBlockDb path remains only for migration/fallback.
2. **gRPC in Rust.** `tonic 0.14` + `CompactTxStreamerClient` are already linked and already used for unary calls over Tor (`rust/src/tor.rs`: get_latest_block, get_transaction, get_tree_state, send_transaction). Add `GetBlockRange` streaming, both direct and Tor (arti) flavors — the same `ServiceMode` semantics Swift has today.
3. **Treestate once per range.** Fetch `GetTreeState` at each suggested-range start; thread the resulting `ChainState` forward across chunks inside Rust (`scan_cached_blocks` already returns enough to continue; the assert at chain.rs:583 is satisfied by construction). 10,000 RPCs → ~tens.
4. **Large scan chunks** (`limit` ≈ 5–10k, dynamically capped by outputs-in-flight so spam ranges bound memory): key prep, frontier setup, and the SQLite commit amortize 50–100×.
5. **Persistent DB handles** for the whole sync session (upstream already has a `ffi_database_handle` branch shaped exactly like this — `WalletDbHandle`, `zcashlc_open_wallet_db` — adopt it).
6. **Pipelined enhancement**: detected txids flow to a third task fetching full transactions concurrently (N parallel unary calls; over Tor, N isolated circuits) instead of post-hoc serial round-trips.
7. **Progress without FFI churn**: scanner publishes (height, recovery/scan numerators) into a shared atomic struct; Swift polls it on its UI cadence (or a throttled callback). `getWalletSummary` leaves the hot loop entirely; `#1353` gets solved as a side effect.
8. **Control surface**: `zcashlc_sync_start(handle, config) / _stop / _status`. Cancellation = cooperative flag checked between chunks + tokio task abort for the network side. Reorg/continuity errors reuse upstream's `ChainError` → truncate + re-suggest, identical semantics to today's `isContinuityError` rewind.
9. **Swift layer after P0**: `CompactBlockProcessor`'s action machine reduces to ~3 states (preflight, rustSync, finished); `SDKSynchronizer`'s public API (`stateStream`, `eventStream`, progress) is preserved — adapters translate Rust events. Public API change is minimal to none; `MIGRATING.md` impact limited to cache-directory semantics.

**Expected impact:** sync time approaches `max(download, scan) + ε` instead of `Σ(every stage + 10,000 × fixed overhead)`. With the §2.5 numbers: from ~1.5–3 h to **~10–25 min** for 1M blocks on-device — the order-of-magnitude target — bounded by network bandwidth or CPU, whichever actually dominates on the device/connection.

**Effort/risk:** the largest single project here (new FFI surface, async runtime lifecycle on iOS, background-task interaction, memory bounding). Mitigations: bounded channels (memory), chunk-boundary checkpoints (kill-safety — scan state is durable after every commit exactly as today), feature-flag the engine and keep the legacy path during bring-up, upstream alignment (ECC is moving `sync::run` the same direction; coordinate instead of forking).

### P1 — Interim wins inside the current architecture (independently shippable, weeks not months)

Ordered by value; all are Swift/config/small-FFI changes that survive P0 (items 4–6) or are deleted by it (1–3):

1. **Unleash the downloader.** Set the download limit to the *range end* rather than `batch+200` (`DownloadAction.swift:49-50`), let the existing detached download task run the whole range continuously, and have `ScanAction` consume behind it. The components already support it (`BlockDownloader` is range-driven); this alone converts download+scan from additive to overlapped. Also: stop wiping the cache on the 10-minute `updateChainTip` (`UpdateChainTipAction.swift:50` → skip `clearCache` when the tip simply advanced).
2. **Scan in 5–10k chunks.** Raise the scan `limit` (decouple it from the download buffer size — they're independent knobs accidentally tied to the same constant). Amortizes treestate RTT, key prep, connection opens, and the DB commit by 50–100×. Memory stays bounded (blocks stream from disk inside `scan_cached_blocks`; only the found-notes set accumulates per call). Keep a dynamic cap for spam-era ranges (outputs-based, e.g. ≤2M outputs per call).
3. **Treestate once per range** (with item 2 this is nearly free: one fetch per 10k chunk ≈ 100 total), prefetched concurrently with the previous chunk's scan rather than serially before it.
4. **Persistent DB handles** — adopt upstream's `ffi_database_handle` branch; stop opening SQLite per FFI call (scan, metadata, summary, decrypt).
5. **`PRAGMA journal_mode=WAL` + `synchronous=NORMAL`** on the wallet DB (and fs-cache metadata DB) at open. 10,000 commits in DELETE mode on iOS flash is pure waste; with item 2 the commit count also drops 100×.
6. **De-noise the batch loop:** move `TxResubmissionAction`'s query to its 5-minute timer instead of every batch; replace the 10 ms `waitUntil…` poll with a continuation; batch `writeBlocksMetadata` once per buffer (or drop the metadata DB entirely once item 2 lands — `scan_cached_blocks` only needs files + heights).

**Expected impact:** the three big ones (1–3) remove the per-batch RTT and most fixed costs and overlap network with CPU — realistic **3–6× combined** without touching the architecture. Worth doing even if P0 starts immediately, since it de-risks P0 by isolating the remaining gap.

### P2 — Parallel scanning across ranges (multiplier on top of P0)

Zingo-sync-style: split the historic range into K disjoint sub-ranges; K workers run trial decryption concurrently (read-only against the block stream), a single writer applies results to SQLite/shardtree in height order. Trial decryption parallelizes today only *within* a batch's output set; across-range workers keep all cores busy through low-output stretches and decouple decrypt throughput from commit latency. This needs either upstream support (preferred — ECC has it on the roadmap; the scanning primitives `scan_block`/`BatchRunners` are mostly there) or a custom driver in zcashlc. Biggest payoff on spam-era ranges and future high-usage chain segments. Estimated additional **2–4×** on CPU-bound phases.

### P3 — Enhancement & memo strategy

Concurrent full-tx fetches (bounded fan-out, Tor-isolated circuits when applicable) instead of serial; optionally defer memo/full-tx download off the critical path entirely (fetch-on-view or background backfill), which is a UX/product decision Zodl can make independently of the SDK plumbing.

### Explicit non-goals

- Protocol-level redesigns (full DAGSync, detection keys/PIR, liberated payments) — ecosystem direction, not SDK work.
- Swift-side micro-optimizations (allocator churn, logging cost, actor granularity) — excluded by request; they are noise next to the above.

---

## 5. Suggested phasing

| Phase | Content | Exit criterion |
|---|---|---|
| 0 (now) | Benchmark harness + baseline (see §6) | Reproducible 1M-block wall-clock + stage breakdown on a reference device |
| 1 | P1 items 1–3 (overlap, big chunks, treestate-per-range) | ≥3× vs baseline |
| 1.5 | P1 items 4–6 (handles, WAL, loop de-noising) | measured; mostly hygiene for P0 |
| 2 | P0 engine behind a feature flag (direct gRPC first, Tor second) | parity of correctness tests (Darkside reorg suite) + ≥1 magnitude vs baseline |
| 3 | P2 parallel ranges; P3 enhancement | CPU-bound phases scale with cores |

Coordinate P0/P2 with ECC/upstream early — `sync::run`, the `ffi_database_handle` branch, and the Android SDK have the same disease and the same cure, and a shared Rust engine (this repo's FFI already builds on `zcash_client_backend`) is where upstream is heading anyway.

## 6. Measurement plan (before/with each phase)

1. **Baseline matrix:** mainnet ~1M-block restore (birthday ≈ tip−1M) on a reference iPhone + macOS, direct + Tor, recording wall-clock and per-stage time (extend `SDKMetrics`, which already times actions).
2. **Floor isolation:** pre-download 50k blocks, time `zcashlc_scan_blocks` alone at limit 100 vs 10k → measures the pure crypto+DB floor and directly quantifies the per-call fixed cost.
3. **Network profile:** time-to-download 1M blocks with the current leashed downloader vs. an unleashed stream (P1.1) → quantifies the overlap win.
4. **Chain reality check:** one `GetBlockRange` pass to compute current average compact-block size and outputs/actions per block for the target range (the §2.5 estimates assume ~2–5 KB and ~10–30 outputs/block; pin these).
5. Track regressions with the Darkside test suite (reorgs, continuity errors) at every phase.

## 7. Risks & open questions

- **iOS lifecycle:** a long-lived tokio runtime + streams inside the app process must suspend cleanly (Tor already does this — `zcashlc_tor_set_dormant` precedent). Background execution limits argue *for* faster sync, but the engine needs clean checkpoint/cancel (chunk-boundary commits give this for free).
- **Memory:** bounded block channel (e.g. 10k typical blocks ≈ 30–50 MB; spam-era blocks need an outputs-based bound, not a count-based one).
- **Thermals/battery:** all-core rayon on phones throttles; expose a QoS knob (cap rayon threads when on battery / background).
- **Upstream dependency:** treestate-threading and parallel-range scanning are cleanest with upstream changes; both have working precedents (zingo-sync, warp) and ECC momentum, but timelines aren't ours to set — P0 is designed to not block on them.
- **API stability:** P0 keeps `Synchronizer`'s surface; the casualty is the undocumented assumption that a filesystem block cache exists (`MIGRATING.md` entry + keep `fsBlockCacheRoot` as the engine's scratch dir).

## 8. Evidence index

- Serial state machine: `Sources/ZcashLightClientKit/Block/CompactBlockProcessor.swift:593-699`
- 100-block batch constants: `Sources/ZcashLightClientKit/Constants/ZcashSDK.swift:91,94`; `CompactBlockProcessor.swift:71`
- 200-block download leash + disk wait: `Block/Actions/DownloadAction.swift:49-59`; 10 ms poll: `Block/Download/BlockDownloader.swift:273-284`; stream rebuild every 300 blocks: `BlockDownloader.swift:67,122-141`
- Per-batch treestate RTT: `Block/Scan/BlockScanner.swift:61-63`
- Progress-cost admission + TODO #1353: `Block/Actions/ScanAction.swift:71-74`
- Per-batch SQLite from Swift: `ScanAction.swift:61-69` (context + `updateScannedData`), `TxResubmissionAction.swift:36`
- One-file-per-block + re-encode + metadata FFI per 10: `Entity/ZcashCompactBlock.swift:56-66`, `Block/FilesystemStorage/FSCompactBlockRepository.swift:71-110`
- Cache wipes: `Block/Actions/ClearCacheAction.swift:22`, `UpdateChainTipAction.swift:46-53`
- Fresh connections per FFI call: `rust/src/lib.rs` (`wallet_db`/`block_db` helpers; `zcashlc_scan_blocks`)
- Rayon-parallel trial decryption (already on): `zcash_client_backend-0.22.0/src/scan.rs:178` (`rayon::spawn_fifo`); pool init in `rust/src/lib.rs` (`zcashlc_init_on_load`)
- Single commit per scan call + key prep per call: `zcash_client_backend-0.22.0/src/data_api/chain.rs:606,607,661`
- Per-block `File::open` in Rust block source: `zcash_client_sqlite-0.20.2/src/chain.rs:301`
- No WAL pragma in the stack: absence verified in `zcash_client_sqlite` + `rust/src`
- Upstream Rust sync loop + its gaps: `zcash_client_backend-0.22.0/src/sync.rs:1-10,56,120-220`; `BlockCache` trait + in-memory example: `data_api/chain.rs:304,387`
- Tonic/Tor already linked + unary lightwalletd calls in Rust: `Cargo.toml:24-31,70,79-84`, `rust/src/tor.rs`
- Upstream persistent-handle precedent: branch `feature/ffi_database_handle` (`WalletDbHandle`, `zcashlc_open_wallet_db`)
