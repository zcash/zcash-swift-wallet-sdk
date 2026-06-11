# Phase 6 — Sparse Tree / Batched Persistence: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (or executing-plans). Checkboxes are execution aids — STATE.md is the completion record.
> Before ANY task: read `docs/slipstream/STATE.md` + `docs/slipstream/CONVENTIONS.md`. LOCAL-ONLY: never push, never create remote issues/PRs.

**Goal (G6 goal line):** mainnet ~269k-block restore in **<73 s on iPhone 16 Pro** (today 208 s; Zkool does 73 s) and **<533 s on iPad A10** (today ~1008 s). Stage-split evidence (STATE truth table): scan ≈ 99.9 % of wall time; fetch fully hidden; enhance 0.7 s. Log decomposition (STATE 2026-06-11): trial decryption is ~3–5 % of scan; **~95 % is the persistence path inside `scan_cached_blocks` → `put_blocks`** (shardtree-through-SQLite, per-block checkpoint churn, blocks/nullifier rows, COMMIT overhead).

**The bet:** keep upstream's audited scan kernel and orchestration **unchanged** (`scan_cached_blocks` — batch runners, continuity checks, ScannedBlock production), and swap ONLY the persistence target of its `put_blocks` call: commitment-tree state held in memory per scan range (a `ShardTree` over our own in-memory `ShardStore`, running upstream's own tree logic), flushed to SQLite **once per chunk** in one transaction. Non-tree rows (blocks, nullifier map, notes) keep upstream's exact per-row writes inside the same transaction. Everything stays behind `EngineConfig::sparse_persistence` (default **off**) until the golden oracle is clean.

**Hard constraint (D3):** data.db must remain semantically identical to upstream's output — same tables, same shard rows, same checkpoint semantics, same scan_queue/wallet_blocks state. The golden oracle (T6.2) enforces this empirically; the architecture enforces it structurally (we run upstream's own `ShardTree` logic and upstream's own public `LowLevelWalletWrite` row methods — we reimplement the *orchestration* of `ll::wallet::put_blocks`, not its SQL).

---

## Verified code-reality facts (2026-06-11 — re-verify only if a build error contradicts them)

Versions in play (Cargo.lock): `zcash_client_backend 0.23.0`, `zcash_client_sqlite 0.21.0`, `shardtree 0.6.2`, `incrementalmerkletree 0.8.2`. All registry paths below are under `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/`.

### A. `put_blocks` write-set (the oracle's diff surface and our reimplementation spec)

`WalletWrite::put_blocks` for `WalletDb<Connection>` = `self.transactionally(|wdb| wdb.put_blocks(...))` (`zcash_client_sqlite-0.21.0/src/lib.rs:1288-1294`); the `SqlTransaction` impl delegates to the **generic public** `zcash_client_backend::data_api::ll::wallet::put_blocks` (`lib.rs:1580-1593`). That function (`zcash_client_backend-0.23.0/src/data_api/ll/wallet.rs:235-550`) does, in order, all within ONE SQLite transaction:

1. **Validation** — `initial_block_sequential`: `from_state.block_height()+1 == first.height()` AND `from_state.final_{sapling,orchard}_tree().tree_size() + first.{pool}().commitments().len() == first.{pool}().final_tree_size()` → else `PutBlocksError::NonSequentialBlocks` (ll/wallet.rs:250-267). Per-block height-consecutive check in the loop (ll/wallet.rs:278-287).
2. **Per block** — `put_block_meta(height, hash, time, sapling_final_size, sapling_count, orchard_final_size, orchard_count)` → `wallet::put_block` (`zcash_client_sqlite/src/wallet.rs:4040-4138`): SELECT hash conflict-guard + UPSERT into `blocks` (sets `sapling_tree = x'00'`) + `UPDATE transactions SET block = :height WHERE mined_height = :height`.
3. **Per wallet-relevant tx** (rare) — `put_tx_meta` (INSERT/upsert `transactions(txid, block, mined_height, tx_index, min_observed_height)`, wallet.rs:4217); `queue_tx_retrieval(once(txid), None)` (`tx_retrieval_queue(txid, query_type, dependent_transaction_id)` — no timestamp); `mark_notes_spent` = loops of `mark_{sapling,orchard}_note_spent` (+transparent prevouts: none in compact path) (ll/wallet.rs:931-963); `put_shielded_outputs` per pool (ll/wallet.rs:964-1090): per output match on `transfer_type()` — **`Outgoing` is unreachable in the compact path** (compact outputs decrypt via ivk only); `WalletInternal`/`Incoming` → `detect_{pool}_spend(nf)` for `spent_in`, `put_received_{pool}_note(output, tx_ref, Some(height), spent_in)`, plus `put_sent_output(Recipient::InternalAccount{...})` for `WalletInternal` (and for `Incoming` only when `funding_account` is Some — it is `None` in `put_blocks`, ll/wallet.rs:337/371 pass `None`).
4. **Per block** — `track_block_{sapling,orchard}_nullifiers(height, nullifier_map())` → `insert_nullifier_map` (wallet.rs:4677-4762): per (tx_index, txid, nfs) one SELECT + maybe INSERT `tx_locator_map` + one INSERT per nf into `nullifier_map`. **Every compact tx appears (even with zero nullifiers).**
5. `note_positions` accumulation (ll/wallet.rs:399-417); commitments accumulated via `block.into_commitments()`.
6. **Gap addresses** — `find_involved_accounts(tx_refs)` → `generate_transparent_gap_addresses(account, scope, UnifiedAddressRequest::unsafe_custom(Allow, Allow, Require))` (ll/wallet.rs:440-457).
7. `prune_tracked_nullifiers(PRUNING_DEPTH=100)` (ll/wallet.rs:52, 460-462) → DELETE from nullifier map below fully-scanned−100.
8. **Tree section** (ll/wallet.rs:466-537): `build_subtrees::<_, SHARD_HEIGHT>(Position::from(from_state.final_X_tree().tree_size()), &mut commitments, CHUNK_SIZE=1024)` — rayon `par_chunks_mut(1024)` → `shardtree::LocatedTree::from_iter(start..end, SHARD_HEIGHT.into(), iter)` → `Vec<(LocatedPrunableTree, BTreeMap<BlockHeight, Position>)>` (ll/wallet.rs:1146-1170); cross-pool `checkpoint_positions` + `ensure_checkpoints` (ll/wallet.rs:1173-1226); `update_tree` per pool (ll/wallet.rs:1228-1290): `tree.insert_frontier(frontier, Retention::Checkpoint{id: from_state.block_height(), marking: Marking::Reference})`, then `tree.insert_tree(subtree, checkpoints)` per subtree, then `store_mut().add_checkpoint(h, cp)` for missing checkpoints `> min_checkpoint_id`.
9. `notify_scan_complete(from+1..last+1, &note_positions)` → `wallet::scanning::scan_complete` (`zcash_client_sqlite/src/wallet/scanning.rs:286-378`): scan_queue `replace_queue_entries` (range → `Scanned`, plus `FoundNote` extensions to shard bounds) + `mark_stabilized_notes`.

**Where the time goes** (the churn we eliminate): `ShardTree::insert_tree` does `store.get_shard` → merge → `store.put_shard` per ≤1024-leaf subtree (`shardtree-0.6.2/src/lib.rs:410-455`); against `SqliteShardStore` each get/put deserializes/reserializes the WHOLE shard blob (`{pool}_tree_shards.shard_data`, commitment_tree.rs:372-528). Every `insert_tree`/`insert_frontier` then runs `prune_excess_checkpoints` (lib.rs:404, 452, 550-660): full `with_checkpoints` table walk + per-removed-checkpoint flag-clearing `get_shard`/`put_shard` rounds. `scan_block` emits `Retention::Checkpoint{id: height}` for the last commitment of **every block** (scanning/compact.rs:672-673, 747-749, 807-808) → ~10k checkpoints created + ~9.9k pruned per 10k-block chunk, with `max_checkpoints = PRUNING_DEPTH = 100` (`zcash_client_sqlite/src/lib.rs:2204-2215`). This matches the field evidence (per-1k-batch escalation 3.5→6-7 s on A10).

### B. `scan_cached_blocks` orchestration (what we keep verbatim)

`zcash_client_backend-0.23.0/src/data_api/chain.rs:586-664`: asserts `from_height == from_state.block_height+1`; `data_db.get_unified_full_viewing_keys()` → `ScanningKeys::from_account_ufvks` → `BatchRunners::for_keys(100, ..)` (parallel trial decryption via `rayon::spawn_fifo`, `src/scan.rs:178`); pass 1 feeds blocks to runners + `flush()`; `prior_block_metadata = data_db.block_metadata(from_height-1)`; `nullifiers = Nullifiers::unspent(data_db)` (= `get_{sapling,orchard}_nullifiers(NullifierQuery::Unspent)`); pass 2 `scan_block_with_runners` per block with continuity checks (`check_hash_continuity`: `BlockHeightDiscontinuity` / `PrevHashMismatch`, scanning/compact.rs:191-222) and in-memory `nullifiers.update_with`; finally **one** `data_db.put_blocks(from_state, scanned_blocks)`. Generic over `DbT: WalletWrite` — **this is our injection seam.**

### C. Public-API verdicts (these decide the architecture)

- `scan_block` IS public (`scanning.rs:609`) **but**: `Nullifiers` has NO public constructor except `empty()` (`unspent`/`new`/`extend_*`/`update_with` are pub(crate), scanning.rs:349-462) and `ScannedBlock::from_parts` is pub(crate) (`data_api.rs:2360`) → **a direct-scan_block pipeline cannot do spend detection nor fabricate corrected ScannedBlocks. Dead end.** `BatchRunners`/`scan_block_with_runners` are pub(crate) (scanning.rs:31, compact.rs:176) → bypassing `scan_cached_blocks` also loses parallel decryption.
- `WalletRead` (33 methods, data_api.rs:1609) / `WalletWrite` (24 methods in our feature set, data_api.rs:2930) have NO forwarding impls → a delegating facade must implement them all (mechanical; compiler-enforced).
- Inside `WalletDb::transactionally` (PUBLIC, `zcash_client_sqlite/src/lib.rs:377-393`) we get `&mut WalletDb<SqlTransaction<'_>, &P, &CL, &mut R>`; `SqlTransaction` is a public type (lib.rs:279). On it, ALL `LowLevelWalletWrite`/`LowLevelWalletRead` methods are public trait methods (`zcash_client_backend/src/data_api/ll.rs:116-595`; sqlite impls at zcash_client_sqlite lib.rs:1950-2207) — `put_block_meta`, `put_tx_meta`, `queue_tx_retrieval`, `mark_{pool}_note_spent`, `detect_{pool}_spend`, `put_received_{pool}_note`, `put_sent_output`, `track_block_{pool}_nullifiers`, `prune_tracked_nullifiers`, `find_involved_accounts`, `generate_transparent_gap_addresses`, `notify_scan_complete`. **The full row write-set is publicly reachable.**
- `WalletCommitmentTrees` is implemented for `WalletDb<SqlTransaction>` and **reuses the live transaction** (no nested txn; zcash_client_sqlite lib.rs:2343-2360) — and `ShardTree::store()/store_mut()` are public (`shardtree/src/lib.rs:97-102`), so dirty shards/checkpoints/cap can be flushed through `wdb.with_{pool}_tree_mut(|t| t.store_mut().put_shard(..)/add_checkpoint(..)/remove_checkpoint(..)/put_cap(..))` — **no raw SQL needed for tree tables.** `put_shard` enforces `check_shard_discontinuity` → flush dirty shards in ascending index order (commitment_tree.rs:444-528). `add_checkpoint` is a no-op for identical re-adds and errors `CheckpointConflict` on changed state (commitment_tree.rs:654-740) → changed checkpoints flush as remove+add.
- shardtree batch-API verdict: in-memory accumulation is fully supported — `ShardTree::new(store, max_checkpoints)` public; `MemoryShardStore` exists but uses a dense `Vec` indexed from 0 with `get_shard(idx<first) = Some(empty)` (`shardtree/src/store/memory.rs:36-66`) which would shadow SQLite content → we implement our own small `SparseShardStore` (BTreeMap-backed, read-miss = error for known-but-unloaded shards). `Checkpoint::from_parts/at_position/tree_empty/position/marks_removed/tree_state` all public (`shardtree/src/store.rs:277-311`); `LocatedTree::from_iter` public (`shardtree/src/batch.rs:185`); `read_shard`/`write_shard` public (`zcash_client_backend/src/serialization/shardtree.rs:21,88`) — not needed since flush goes through `ShardStore`, kept for reference.
- `WalletSaplingOutput`/`WalletOrchardOutput` satisfy `ReceivedSaplingOutput`/`ReceivedOrchardOutput` via blanket impls (ll.rs:627-636); `WalletTx` accessors (`txid/sapling_spends/sapling_outputs/orchard_spends/orchard_outputs`) public (wallet.rs:138-171); `ScannedBlock` accessors (`height/block_hash/block_time/transactions/sapling/orchard/into_commitments/to_block_metadata`) public (data_api.rs:2382-2436); `ScannedBundles::{final_tree_size, nullifier_map, commitments}` public (data_api.rs:2312-2328); `PutBlocksError` variants public + `From<PutBlocksError<SqliteClientError, commitment_tree::Error>> for SqliteClientError` (used at zcash_client_sqlite lib.rs:1592); `ChainState::new/empty/block_height/final_*_tree` public (chain.rs:515-573).
- Error path parity: facade `Error = SqliteClientError` → `scan_cached_blocks` errors keep the exact upstream shapes; continuity errors stay `ChainError::Scan(e) if e.is_continuity_error()` → our existing `map_scan_error` (slipstream `scan.rs:75-87`) works **unchanged**.

### D. Truncate / reorg compatibility argument (T6.5 gate)

`truncate_to_height` (`zcash_client_sqlite/src/wallet.rs:3639-3793`): `select_truncation_height` = MAX height ≤ requested that exists in `blocks` AND in `sapling_tree_checkpoints` AND (in `orchard_tree_checkpoints` OR orchard has none); then trims scan_queue to it, un-mines transactions, `tree.truncate_to_checkpoint`, deletes `blocks`/`tx_locator_map` above. **Our design produces the SAME checkpoint stream as upstream**: `scan_block` emits per-block `Retention::Checkpoint` markers; our in-memory `ShardTree` (max_checkpoints=100) ingests them through upstream's own `insert_tree` + `prune_excess_checkpoints` logic; flush materializes the surviving (~last 100 per pool) checkpoints into the same tables. Therefore `select_truncation_height` sees the same candidates, rewinds land on the same heights, and `suggest_scan_ranges` repairs the same gap. There is **no sparser-checkpoint compromise to argue** — checkpoint cadence is inherited, not redesigned. The only behavioral difference is durability granularity: upstream persists tree state once per `scan_cached_blocks` call; so do we (the flush is in the same per-chunk transaction) — crash atomicity is identical.

### E. Our code seams

- `scan_chunks` (slipstream `scan.rs:134-314`): per chunk calls `scan_cached_blocks(&network, &source, session.db_mut(), from_height, &from_state, len)` inside `block_in_place`; from_state threading via prefetch. `scan_chunks_from_treestate` (test/darkside twin, scan.rs:339-408). `WalletSession::db_mut() -> &mut Db`, `Db = WalletDb<Connection, Network, SystemClock, OsRng>` (wallet_session.rs:22, currently private type alias — make `pub(crate)`).
- `scheduler.rs:79-320`: range loop; per-range `run_enhancement` (F3, non-fatal); `report.enhance/enhance_elapsed` accumulation; `scan_wall` measured around `scan_chunks`.
- `run_enhancement(session, client, network, progress)` (enhance.rs:78-174) holds the TransactionsInvolvingAddress skip-dedupe `HashSet<String>` **per call** (enhance.rs:90) — the T6.1 log-spam source under interleaving.
- `EngineConfig` (config.rs:30-65): tunables + `validate()`; FFI builds it via `EngineConfig::new` (rust/src/lib.rs:4409) → new fields with defaults need **no FFI change**. CLI `cmd_sync` (cli/main.rs:165-190) sets streams/chunk.
- CLI subcommands: `Version`, `Fetch`, `Sync` (cli/main.rs:13-56). Benchmarks are CLI subcommands (CONVENTIONS).
- Darkside tests: `tests/darkside_sync.rs` (fixture constants incl. `TX_MAINNET_BLOCK_URL`, `BIRTHDAY_HEIGHT=663150`, `SAPLING_TREE_128607`, `setup_wallet`-style helpers), `tests/darkside_reorg.rs::reorg_recovery_produces_correct_tip` (line 223). Chunk test helper pattern: `CompactBlock { height, hash: vec![h as u8; 32], ..Default::default() }` (chunk.rs:109-110); `Chunk::from_blocks(index, blocks)` (chunk.rs:29).

## Deviations from the controller sketch (say-so section)

1. **T6.3 spike does NOT use direct `scan_block` + manual persistence.** Recon fact C kills it: `Nullifiers` and `ScannedBlock` are not publicly constructible, and bypassing `scan_cached_blocks` would *also* lose `BatchRunners` parallel decryption and the continuity checks we must preserve. Instead the spike measures the same floor through the **facade seam** (upstream kernel retained; only `put_blocks` swapped). This is strictly less risk and the spike code is not throwaway — it *is* the MVP skeleton.
2. **Continuity reimplementation is unnecessary** (sketch asked to "reimplement equivalent checks if we bypass scan_cached_blocks") — we don't bypass it; `map_scan_error` semantics are inherited untouched.
3. **Checkpoint-sparsity argument dissolves** (sketch: "sparser checkpoints at chunk boundaries acceptable IF…") — we keep upstream's per-block checkpoint stream in memory and flush the pruned survivors; final tables match upstream exactly (fact D).
4. **Oracle CLI is `--birthday`-bounded, not `--range A..=B`**: `engine::sync_once` always syncs birthday→tip; an arbitrary sub-range isn't expressible without inventing a new engine mode. Range size is controlled by birthday choice; the harness fails fast on tip-skew between the two runs.
5. **Task numbering**: T6.2 = oracle harness, T6.3 = facade spike + GO/NO-GO, T6.4 = oracle-clean correctness (includes the darkside `scan_chunks_from_treestate` sparse branch — the darkside oracle needs it, so it moves up from T6.5), T6.5 = reorg/truncate, T6.6 = default-ON + device gate prep. The sketch's "darkside-gated test asserting empty diff" cannot exist at T6.2 (no sparse path yet to diff against) — T6.2 ships the harness + hermetic determinism baseline + mutation-detection tests instead; the darkside empty-diff test lands at T6.4 the moment both paths exist.
6. **Row batching is deliberately OUT of the MVP scope.** The sketch's "batched note/nullifier/wallet_blocks writes": recon shows those rows already ride one transaction per chunk (upstream's own `transactionally`), and per-row batching cannot go through the public seam (`wdb` exposes no raw connection). The MVP keeps upstream's exact per-row calls (identity by construction); the T6.3 attribution log (`rows_ms` vs `tree_ms` vs `flush_ms`) decides whether a row-batching follow-up is warranted (threshold: rows > 30 % of the sparse-path chunk time → new task, raw-SQL batch with its own oracle run).

## File structure

```
Cargo.toml                                  # MODIFY (T6.3): + shardtree to [workspace.dependencies]
slipstream/core/
  Cargo.toml                                # MODIFY (T6.3): + shardtree, incrementalmerkletree (workspace = true)
  src/lib.rs                                # MODIFY: wire `oracle` (T6.2), `persist` (T6.3)
  src/config.rs                             # MODIFY: enhance_every_chunks (T6.1); sparse_persistence (T6.3)
  src/enhance.rs                            # MODIFY (T6.1): skipped_keys hoisted to caller
  src/scan.rs                               # MODIFY: interleave (T6.1); sparse branch (T6.3); treestate twin branch (T6.4)
  src/scheduler.rs                          # MODIFY (T6.1): skipped_keys plumb + stage-split accounting
  src/engine.rs                             # MODIFY (T6.1): owns skipped_keys for the pass
  src/oracle.rs                             # CREATE (T6.2): semantic_diff
  src/persist.rs                            # CREATE (T6.3): SparseShardStore, SparseTreeState, SparseFacade, sparse_put_blocks
  tests/darkside_oracle.rs                  # CREATE (T6.4)
  tests/darkside_reorg.rs                   # MODIFY (T6.5): sparse variant
slipstream/cli/src/main.rs                  # MODIFY: Oracle subcommand (T6.2); --sparse (T6.3)
docs/slipstream/STATE.md                    # MODIFY per task
docs/slipstream/CONVENTIONS.md              # MODIFY (T6.3): module-naming list += persist, oracle
```

---

### Task 6.1: RIDER — per-K-chunk enhancement interleave + once-per-sync skip-log dedupe

Independent quick win; ship first. Transactions currently appear at range boundaries only (user-validated: "60 % boundary feels too late"). Run enhancement every K chunks **inside** `scan_chunks` (scanner paused between chunk scans; the fetcher keeps filling the queue concurrently). Rust-only — no FFI/Swift surface changes (verify: `git diff --stat` shows only `slipstream/` + docs), so OfflineTests is not required for this commit.

**Hold-the-line arithmetic (include in commit message body):** iPad A10 field baseline: enhance 0.69 s total per sync. 269k blocks / 10k chunks = 27 chunks; K=3 → 9 interleaved runs + ~2 per-range + 1 final ≈ 12 runs. An empty-queue run is one `transaction_data_requests` query + early break (~ms). Work done early is work not done later. Expected added cost ≪ 1 s vs a 1006 s scan — still ~free.

- [ ] **Step 1 (failing test first):** in `scan.rs` tests add:

```rust
    // T6.1 — interleave cadence helper.
    #[test]
    fn interleave_fires_every_k_chunks() {
        assert!(!should_interleave_enhancement(0, 3));
        assert!(!should_interleave_enhancement(1, 3));
        assert!(!should_interleave_enhancement(2, 3));
        assert!(should_interleave_enhancement(3, 3));
        assert!(!should_interleave_enhancement(4, 3));
        assert!(should_interleave_enhancement(6, 3));
        assert!(should_interleave_enhancement(1, 1));
        assert!(should_interleave_enhancement(2, 1));
    }
```

Run `cargo test -p slipstream-core interleave_fires` → compile error (function missing). Then add to `scan.rs` (above `ScanStats`):

```rust
/// True when an interleaved enhancement run should fire after `chunks_done`
/// completed chunks with cadence `every` (T6.1). Never fires before the first
/// chunk completes.
pub fn should_interleave_enhancement(chunks_done: u64, every: u32) -> bool {
    every > 0 && chunks_done > 0 && chunks_done % u64::from(every) == 0
}
```

- [ ] **Step 2:** `config.rs` — add field + validation + tests:

```rust
    /// Run an interleaved (non-fatal) enhancement pass every N completed chunks
    /// during a range scan, so found transactions surface continuously instead of
    /// only at range boundaries (T6.1). Must be >= 1; the per-range and final
    /// post-loop enhancement runs are unaffected backstops.
    pub enhance_every_chunks: u32,
```

`EngineConfig::new` sets `enhance_every_chunks: 3` (add `pub const DEFAULT_ENHANCE_EVERY_CHUNKS: u32 = 3;`). `validate()`: `if self.enhance_every_chunks == 0 { return Err(SlipstreamError::Config("enhance_every_chunks must be >= 1".into())); }`. Tests: `enhance_every_chunks_zero_rejected`, and extend `defaults_are_valid` with `assert_eq!(config().enhance_every_chunks, 3);`.

- [ ] **Step 3:** `enhance.rs` — hoist the dedupe set to the caller. `run_enhancement` signature becomes:

```rust
pub async fn run_enhancement(
    session: &mut WalletSession,
    client: &mut LwdClient,
    network: Network,
    progress: Option<Arc<Progress>>,
    skipped_keys: &mut HashSet<String>,
) -> Result<EnhanceStats, SlipstreamError> {
```

Delete the local `let mut skipped_address_keys` (enhance.rs:90) and pass `skipped_keys` to `apply_address_request` (which already takes `&mut HashSet<String>`). Update the doc comment: dedupe scope is now **one sync pass** (each unique skip is `warn!`-logged once per pass and counted once in `stats.skipped`; duplicates across all interleaved/per-range/final runs are `debug!` only). The existing hermetic test `skip_dedupe_counts_unique_keys_only` stays valid (pure HashSet contract).

- [ ] **Step 4:** `scan.rs` — `scan_chunks` signature changes from `(…, batch_target_ms: Option<u64>)` to:

```rust
pub async fn scan_chunks(
    session: &mut WalletSession,
    client: &mut LwdClient,
    range_start: u64,
    mut rx: ChunkQueueReceiver,
    progress: Option<Arc<Progress>>,
    config: &EngineConfig,
    skipped_keys: &mut HashSet<String>,
) -> Result<ScanStats, SlipstreamError> {
```

(`use std::collections::HashSet;` + `use crate::config::EngineConfig;` + `use crate::enhance::run_enhancement;`.) Inside, read `let batch_target_ms = config.scan_batch_target_ms;` so the sub-batch logic is textually unchanged. Extend `ScanStats`:

```rust
#[derive(Debug, Default, Clone)]
pub struct ScanStats {
    pub blocks: u64,
    pub chunks: u64,
    pub sapling_received: u64,
    pub orchard_received: u64,
    /// Stats from interleaved (per-K-chunk) enhancement runs (T6.1).
    pub interleaved_enhance: crate::enhance::EnhanceStats,
    /// Wall-clock spent in interleaved enhancement (excluded from scan-stage time).
    pub interleaved_enhance_elapsed: std::time::Duration,
}
```

After the chunk-accounting block (right after `drop(permit);`, scan.rs:304), insert:

```rust
        // T6.1 — interleaved enhancement every K chunks. Non-fatal by design:
        // it is an optimization (progressive tx visibility); the per-range and
        // final post-loop runs are the correctness backstops. from_state
        // threading is untouched (next_state is not read or written here).
        if should_interleave_enhancement(stats.chunks, config.enhance_every_chunks) {
            let started = Instant::now();
            let mut enhance_client = client.clone();
            match run_enhancement(session, &mut enhance_client, network, progress.clone(), skipped_keys).await {
                Ok(es) => {
                    stats.interleaved_enhance.requests += es.requests;
                    stats.interleaved_enhance.txs_stored += es.txs_stored;
                    stats.interleaved_enhance.statuses_set += es.statuses_set;
                    stats.interleaved_enhance.skipped += es.skipped;
                }
                Err(err) => {
                    warn!(%err, chunk_end, "interleaved enhancement failed — continuing scan");
                }
            }
            stats.interleaved_enhance_elapsed += started.elapsed();
        }
```

(`use tracing::warn;` already partially imported — extend the import. `network` is the existing per-chunk local, it is `Copy`.) NOTE: `scan_chunks_from_treestate` is unchanged in this task.

- [ ] **Step 5:** `scheduler.rs` — `run_to_completion` gains `skipped_keys: &mut HashSet<String>` (after `progress`). Update the `scan_chunks` call site (scheduler.rs:162) to `scan_chunks(session, &mut scan_client, start, rx, progress.clone(), config, skipped_keys)`. Update per-range enhancement call (scheduler.rs:290) to pass `skipped_keys`. **Stage-split accounting:** after a successful range, replace `report.scan_elapsed += scan_wall;` with:

```rust
        // T6.1: interleaved-enhancement time is enhancement, not scan.
        report.scan_elapsed += scan_wall.saturating_sub(scan_stats.interleaved_enhance_elapsed);
        report.enhance_elapsed += scan_stats.interleaved_enhance_elapsed;
        report.enhance.requests += scan_stats.interleaved_enhance.requests;
        report.enhance.txs_stored += scan_stats.interleaved_enhance.txs_stored;
        report.enhance.statuses_set += scan_stats.interleaved_enhance.statuses_set;
        report.enhance.skipped += scan_stats.interleaved_enhance.skipped;
```

`ranges_completed` bump stays exactly where it is (semantics unchanged).

- [ ] **Step 6:** `engine.rs` — `sync_once` owns the pass-scoped set: `let mut skipped_keys: std::collections::HashSet<String> = std::collections::HashSet::new();` before `run_to_completion(config, &mut session, progress.clone(), &mut skipped_keys)`; final run becomes `run_enhancement(&mut session, &mut client, config.network, progress.clone(), &mut skipped_keys)`.
- [ ] **Step 7:** update remaining callers: darkside tests call `scan_chunks_from_treestate` (unchanged); grep `run_enhancement(` and `scan_chunks(` across `slipstream/` for any missed site (`tests/darkside_sync.rs::sync_enhancement_stores_raw_fields` calls `run_enhancement` → add a local `&mut HashSet::new()`).
- [ ] **Step 8:** verify: `cargo test -p slipstream-core -p slipstream-cli` (all green, incl. new tests); `cargo clippy -p slipstream-core -p slipstream-cli --all-targets` clean; `cargo clippy -p slipstream-core --features darkside --all-targets` clean; `cargo test -p slipstream-core --features darkside --no-run` compiles.
- [ ] **Step 9:** STATE.md (T6.1 done + session-log line; NEXT → T6.2) + commit:

```bash
git add slipstream/ docs/slipstream/STATE.md
git commit -m "[#1755] slipstream: T6.1 per-K-chunk enhancement interleave + once-per-sync skip-log dedupe"
```

---

### Task 6.2: Golden-oracle harness (BEFORE any persistence code)

A semantic differ for two data.db files + a CLI subcommand that produces two wallets over the same range and diffs them. At this task the two runs are both the upstream path — proving the harness + determinism baseline (and discovering the real cosmetic-diff allowlist empirically). T6.3 flips run B to sparse.

**Cosmetic-diff allowlist (initial, from recon):** *empty.* Recon found NO timestamp columns in the put_blocks write-set (`put_tx_meta` writes `txid, block, mined_height, tx_index, min_observed_height`; `tx_retrieval_queue` has no time column). Candidate suspects if the determinism test fails: account/address creation timestamps (clock-derived) and autoincrement id drift. **Protocol:** any allowlist addition requires (a) reproducing the diff with the determinism test, (b) citing the upstream line that writes the column, (c) a Decision-Log entry. Views and indexes are excluded structurally (only `sqlite_master.type='table'`, name NOT LIKE 'sqlite_%').

- [ ] **Step 1 (failing test first):** create `slipstream/core/src/oracle.rs` with tests at bottom; run `cargo test -p slipstream-core oracle` → fails to compile until the module exists. Full module:

```rust
//! Golden-oracle harness (T6.2): semantic diff of two wallet databases.
//! D3 enforcement — the sparse persistence path must produce a data.db that is
//! row-identical to upstream's, modulo an explicit (currently empty) allowlist.
//! Used by the CLI `oracle` subcommand and the darkside oracle tests.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;

use rusqlite::Connection;
use rusqlite::types::ValueRef;

use crate::error::SlipstreamError;

/// (table, column) pairs excluded from comparison. Keep EMPTY until the
/// determinism test proves a column is non-deterministic; every addition needs
/// a Decision-Log entry citing the upstream write site.
pub const ALLOWLIST: &[(&str, &str)] = &[];

/// Per-table comparison result.
#[derive(Debug, Clone)]
pub struct TableDiff {
    pub table: String,
    pub rows_a: u64,
    pub rows_b: u64,
    /// Canonicalized rows present in A but not B (first 5 kept), and vice versa.
    pub only_in_a: Vec<String>,
    pub only_in_b: Vec<String>,
}

impl TableDiff {
    pub fn is_clean(&self) -> bool {
        self.only_in_a.is_empty() && self.only_in_b.is_empty() && self.rows_a == self.rows_b
    }
}

#[derive(Debug, Default)]
pub struct DiffReport {
    pub tables: Vec<TableDiff>,
}

impl DiffReport {
    pub fn is_clean(&self) -> bool {
        self.tables.iter().all(TableDiff::is_clean)
    }

    /// Human-readable verdict block for CLI printing.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for t in &self.tables {
            if t.is_clean() {
                let _ = writeln!(out, "  OK   {:40} {} rows", t.table, t.rows_a);
            } else {
                let _ = writeln!(
                    out,
                    "  DIFF {:40} A={} B={} (+A {} / +B {})",
                    t.table, t.rows_a, t.rows_b, t.only_in_a.len(), t.only_in_b.len()
                );
                for r in t.only_in_a.iter().take(5) {
                    let _ = writeln!(out, "       only-in-A: {r}");
                }
                for r in t.only_in_b.iter().take(5) {
                    let _ = writeln!(out, "       only-in-B: {r}");
                }
            }
        }
        out
    }
}

fn wallet_err(context: &str, e: impl std::fmt::Display) -> SlipstreamError {
    SlipstreamError::Wallet(format!("oracle {context}: {e}"))
}

fn canonical_value(v: ValueRef<'_>) -> String {
    match v {
        ValueRef::Null => "NULL".into(),
        ValueRef::Integer(i) => i.to_string(),
        ValueRef::Real(r) => format!("{r:?}"),
        ValueRef::Text(t) => format!("'{}'", String::from_utf8_lossy(t)),
        ValueRef::Blob(b) => {
            let mut s = String::with_capacity(2 + b.len() * 2);
            s.push_str("x'");
            for byte in b {
                let _ = write!(s, "{byte:02x}");
            }
            s.push('\'');
            s
        }
    }
}

fn list_tables(conn: &Connection) -> Result<Vec<String>, SlipstreamError> {
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .map_err(|e| wallet_err("list tables", e))?;
    let names = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| wallet_err("list tables", e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| wallet_err("list tables", e))?;
    Ok(names)
}

fn table_columns(conn: &Connection, table: &str) -> Result<Vec<String>, SlipstreamError> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info(\"{table}\")"))
        .map_err(|e| wallet_err("table_info", e))?;
    let cols = stmt
        .query_map([], |r| r.get::<_, String>(1))
        .map_err(|e| wallet_err("table_info", e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| wallet_err("table_info", e))?;
    Ok(cols
        .into_iter()
        .filter(|c| !ALLOWLIST.contains(&(table, c.as_str())))
        .collect())
}

/// Multiset of canonicalized rows for one table.
fn row_multiset(
    conn: &Connection,
    table: &str,
    cols: &[String],
) -> Result<HashMap<String, i64>, SlipstreamError> {
    let col_list = cols
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let mut stmt = conn
        .prepare(&format!("SELECT {col_list} FROM \"{table}\""))
        .map_err(|e| wallet_err("select", e))?;
    let mut rows = stmt.query([]).map_err(|e| wallet_err("query", e))?;
    let mut set: HashMap<String, i64> = HashMap::new();
    while let Some(row) = rows.next().map_err(|e| wallet_err("next", e))? {
        let mut canon = String::new();
        for i in 0..cols.len() {
            let v = row.get_ref(i).map_err(|e| wallet_err("get_ref", e))?;
            let _ = write!(canon, "{}={}|", cols[i], canonical_value(v));
        }
        *set.entry(canon).or_insert(0) += 1;
    }
    Ok(set)
}

/// Semantically diff every table of two wallet databases.
/// Tables are taken from the UNION of both schemas (a missing table shows as a
/// full-table diff). Columns come from DB A's schema (identical migrations are
/// a precondition — both DBs are produced by this crate's WalletSession).
pub fn semantic_diff(db_a: &Path, db_b: &Path) -> Result<DiffReport, SlipstreamError> {
    let a = Connection::open(db_a).map_err(|e| wallet_err("open A", e))?;
    let b = Connection::open(db_b).map_err(|e| wallet_err("open B", e))?;
    let mut tables = list_tables(&a)?;
    for t in list_tables(&b)? {
        if !tables.contains(&t) {
            tables.push(t);
        }
    }
    tables.sort();

    let mut report = DiffReport::default();
    for table in tables {
        let cols = table_columns(&a, &table).or_else(|_| table_columns(&b, &table))?;
        let ms_a = row_multiset(&a, &table, &cols).unwrap_or_default();
        let ms_b = row_multiset(&b, &table, &cols).unwrap_or_default();
        let rows_a: i64 = ms_a.values().sum();
        let rows_b: i64 = ms_b.values().sum();
        let mut only_in_a = vec![];
        let mut only_in_b = vec![];
        for (row, ca) in &ms_a {
            let cb = ms_b.get(row).copied().unwrap_or(0);
            for _ in cb..*ca {
                only_in_a.push(row.clone());
            }
        }
        for (row, cb) in &ms_b {
            let ca = ms_a.get(row).copied().unwrap_or(0);
            for _ in ca..*cb {
                only_in_b.push(row.clone());
            }
        }
        only_in_a.sort();
        only_in_b.sort();
        report.tables.push(TableDiff {
            table,
            rows_a: rows_a as u64,
            rows_b: rows_b as u64,
            only_in_a,
            only_in_b,
        });
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_db(path: &std::path::Path, rows: &[(i64, &str)]) {
        let conn = Connection::open(path).expect("open");
        conn.execute_batch("CREATE TABLE t (a INTEGER, b TEXT); CREATE TABLE u (x BLOB);")
            .expect("schema");
        for (a, b) in rows {
            conn.execute("INSERT INTO t (a, b) VALUES (?1, ?2)", rusqlite::params![a, b])
                .expect("insert");
        }
    }

    #[test]
    fn identical_dbs_diff_clean() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pa = dir.path().join("a.db");
        let pb = dir.path().join("b.db");
        mk_db(&pa, &[(1, "x"), (2, "y")]);
        mk_db(&pb, &[(2, "y"), (1, "x")]); // insertion order must not matter
        let report = semantic_diff(&pa, &pb).expect("diff");
        assert!(report.is_clean(), "expected clean diff:\n{}", report.render());
    }

    #[test]
    fn row_delta_is_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pa = dir.path().join("a.db");
        let pb = dir.path().join("b.db");
        mk_db(&pa, &[(1, "x"), (2, "y")]);
        mk_db(&pb, &[(1, "x"), (2, "z")]);
        let report = semantic_diff(&pa, &pb).expect("diff");
        assert!(!report.is_clean());
        let t = report.tables.iter().find(|t| t.table == "t").expect("table t");
        assert_eq!(t.only_in_a.len(), 1);
        assert_eq!(t.only_in_b.len(), 1);
        assert!(t.only_in_a[0].contains("'y'"));
    }

    #[test]
    fn duplicate_row_multiplicity_is_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pa = dir.path().join("a.db");
        let pb = dir.path().join("b.db");
        mk_db(&pa, &[(1, "x"), (1, "x")]);
        mk_db(&pb, &[(1, "x")]);
        let report = semantic_diff(&pa, &pb).expect("diff");
        let t = report.tables.iter().find(|t| t.table == "t").expect("table t");
        assert!(!t.is_clean());
        assert_eq!(t.rows_a, 2);
        assert_eq!(t.rows_b, 1);
    }

    #[test]
    fn missing_table_is_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pa = dir.path().join("a.db");
        let pb = dir.path().join("b.db");
        mk_db(&pa, &[(1, "x")]);
        let conn = Connection::open(&pb).expect("open");
        conn.execute_batch("CREATE TABLE t (a INTEGER, b TEXT);").expect("schema");
        // table `u` missing in B entirely
        let report = semantic_diff(&pa, &pb).expect("diff");
        assert!(report.tables.iter().any(|t| t.table == "u"));
    }
}
```

- [ ] **Step 2:** wire `pub mod oracle;` into `lib.rs` (alphabetical position). `cargo test -p slipstream-core oracle` → 4 passed.
- [ ] **Step 3 (determinism baseline — the empirical allowlist discovery):** add to `oracle.rs` tests a synthetic end-to-end determinism test. It builds two wallets via the REAL upstream pipeline over identical synthetic blocks and asserts a clean diff. This test is the foundation T6.4 reuses (factor the helpers as `pub(crate)` in a `#[cfg(test)] pub(crate) mod testkit` INSIDE `oracle.rs` is NOT possible for integration tests — put the helpers in `oracle.rs` under `#[cfg(any(test, feature = "darkside"))] pub mod testkit` so darkside tests can reuse them):

```rust
/// Test kit: deterministic synthetic chain + a full upstream-path scan into a
/// fresh wallet. Reused by the hermetic determinism test (T6.2), the hermetic
/// sparse oracle test (T6.4) and the darkside oracle test (T6.4).
#[cfg(any(test, feature = "darkside"))]
pub mod testkit {
    use std::path::Path;

    use zcash_client_backend::data_api::chain::scan_cached_blocks;
    use zcash_client_backend::proto::compact_formats::{
        ChainMetadata, CompactBlock, CompactSaplingOutput, CompactSaplingSpend, CompactTx,
    };
    use zcash_client_backend::proto::service::TreeState;
    use zcash_protocol::consensus::BlockHeight;

    use crate::block_source::MemBlockSource;
    use crate::chunk::Chunk;
    use crate::error::SlipstreamError;
    use crate::wallet_session::{TEST_UFVK, WalletSession};

    /// First synthetic height: above Sapling activation (419_200), below NU5
    /// (1_687_104) so empty Orchard bundles and zero Orchard tree sizes are valid.
    pub const SYNTH_START: u64 = 1_500_000;

    fn h32(tag: u8, n: u64) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v[0] = tag;
        v[1..9].copy_from_slice(&n.to_le_bytes());
        v
    }

    /// Little-endian small integers are canonical Jubjub base-field elements →
    /// valid `cmu` bytes for CompactOutputDescription parsing.
    fn cmu(n: u64) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v[..8].copy_from_slice(&n.to_le_bytes());
        v
    }

    /// Deterministic synthetic chain: `count` linked blocks from SYNTH_START.
    /// Every block has one tx with `outs_per_block` Sapling outputs (random-looking
    /// but fixed ciphertexts that decrypt to nothing) and one foreign Sapling spend
    /// (exercises tx_locator_map/nullifier_map). chain_metadata carries cumulative
    /// Sapling tree sizes starting from 0 (fresh synthetic chain); Orchard stays 0.
    pub fn synth_blocks(count: u64, outs_per_block: u32) -> Vec<CompactBlock> {
        let mut blocks = Vec::with_capacity(count as usize);
        let mut tree_size: u32 = 0;
        let mut cmu_counter: u64 = 1;
        for i in 0..count {
            let height = SYNTH_START + i;
            let outputs = (0..outs_per_block)
                .map(|_| {
                    let o = CompactSaplingOutput {
                        cmu: cmu(cmu_counter),
                        ephemeral_key: h32(0xEE, cmu_counter),
                        ciphertext: vec![0xC7; 52],
                    };
                    cmu_counter += 1;
                    o
                })
                .collect::<Vec<_>>();
            tree_size += outs_per_block;
            let tx = CompactTx {
                index: 0,
                hash: h32(0x77, height),
                fee: 0,
                spends: vec![CompactSaplingSpend { nf: h32(0x4F, height) }],
                outputs,
                actions: vec![],
            };
            blocks.push(CompactBlock {
                proto_version: 0,
                height,
                hash: h32(0xBB, height),
                prev_hash: if i == 0 { vec![0u8; 32] } else { h32(0xBB, height - 1) },
                time: height as u32,
                header: vec![],
                vtx: vec![tx],
                chain_metadata: Some(ChainMetadata {
                    sapling_commitment_tree_size: tree_size,
                    orchard_commitment_tree_size: 0,
                }),
            });
        }
        blocks
    }

    /// Open a fresh wallet at `dir/data.db`, import TEST_UFVK with an empty
    /// treestate birthday at SYNTH_START-1, set the chain tip, and scan `blocks`
    /// through `scan_cached_blocks` in `chunk_size`-block calls — through the
    /// plain WalletDb when `sparse` is false. (T6.4 extends this with the sparse
    /// facade branch; until then `sparse` must be false.)
    pub fn scan_synthetic(
        dir: &Path,
        blocks: Vec<CompactBlock>,
        chunk_size: usize,
        sparse: bool,
    ) -> Result<(), SlipstreamError> {
        assert!(!sparse, "sparse branch lands in T6.4");
        let db_path = dir.join("data.db");
        let mut session = WalletSession::open(crate::Network::MainNetwork, &db_path)?;
        // Same TreeState shape as wallet_session.rs tests (663_149 precedent):
        // 64-char zero hash, empty tree strings = empty frontier birthday.
        let birthday_ts = TreeState {
            network: "main".into(),
            height: 1_499_999, // SYNTH_START - 1
            hash: "0".repeat(64),
            time: 1,
            ..Default::default()
        };
        session.ensure_account(TEST_UFVK, birthday_ts.clone())?;
        let tip = blocks.last().map(|b| b.height).unwrap_or(SYNTH_START);
        session.update_chain_tip(tip)?;

        let mut from_state = birthday_ts
            .to_chain_state()
            .map_err(|e| SlipstreamError::Wallet(format!("chain state: {e}")))?;
        for window in blocks.chunks(chunk_size) {
            let (Some(first), Some(last)) = (window.first(), window.last()) else {
                continue; // chunks() never yields empty windows
            };
            let from_height = u32::try_from(first.height)
                .map_err(|_| SlipstreamError::Wallet("height exceeds u32".into()))?;
            let chunk = Chunk::from_blocks(0, window.to_vec());
            let source = MemBlockSource::new(&chunk);
            let network = session.network;
            scan_cached_blocks(
                &network,
                &source,
                session.db_mut(),
                BlockHeight::from(from_height),
                &from_state,
                window.len(),
            )
            .map_err(|e| SlipstreamError::Wallet(format!("scan_cached_blocks: {e}")))?;
            // from_state for the NEXT window: re-synthesized from the chain's
            // known cmu sequence (no server in hermetic tests).
            from_state = synth_chain_state(last)?;
        }
        Ok(())
    }

    /// ChainState at `last` for the NEXT window: frontier rebuilt by replaying
    /// every cmu of the synthetic chain from the start through `last` (the
    /// global cmu counter makes this exact; cheap at test sizes).
    fn synth_chain_state(
        last: &CompactBlock,
    ) -> Result<zcash_client_backend::data_api::chain::ChainState, SlipstreamError> {
        // Replay all outputs from SYNTH_START..=last.height to build the frontier.
        use incrementalmerkletree::frontier::Frontier;
        let total: u64 = last
            .chain_metadata
            .as_ref()
            .map(|m| m.sapling_commitment_tree_size as u64)
            .unwrap_or(0);
        let mut frontier: Frontier<sapling::Node, { sapling::NOTE_COMMITMENT_TREE_DEPTH }> =
            Frontier::empty();
        for n in 1..=total {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&n.to_le_bytes());
            let node = sapling::Node::from_bytes(bytes);
            let node = Option::<sapling::Node>::from(node)
                .ok_or_else(|| SlipstreamError::Wallet(format!("invalid synth cmu {n}")))?;
            frontier.append(node);
        }
        let mut hash = [0u8; 32];
        hash[0] = 0xBB;
        hash[1..9].copy_from_slice(&last.height.to_le_bytes());
        Ok(zcash_client_backend::data_api::chain::ChainState::new(
            BlockHeight::from(last.height as u32),
            zcash_primitives::block::BlockHash(hash),
            frontier,
            incrementalmerkletree::frontier::Frontier::empty(),
        ))
    }
}
```

Then the determinism test (in `oracle.rs` `#[cfg(test)] mod tests`):

```rust
    /// T6.2 determinism baseline: the SAME synthetic blocks scanned through the
    /// upstream path into two fresh wallets must produce semantically identical
    /// databases. Any diff here = non-deterministic column → allowlist candidate
    /// (protocol in the phase plan).
    #[test]
    fn upstream_path_is_deterministic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let da = dir.path().join("wa");
        let db = dir.path().join("wb");
        std::fs::create_dir_all(&da).unwrap();
        std::fs::create_dir_all(&db).unwrap();
        let blocks = super::testkit::synth_blocks(30, 3);
        super::testkit::scan_synthetic(&da, blocks.clone(), 10, false).expect("scan A");
        super::testkit::scan_synthetic(&db, blocks, 10, false).expect("scan B");
        let report = semantic_diff(&da.join("data.db"), &db.join("data.db")).expect("diff");
        assert!(report.is_clean(), "upstream self-diff not clean:\n{}", report.render());
    }
```

**Binding notes for Step 3** (verify at compile time, record deviations in STATE):
  - `TreeState.height` proto field type: mirror whatever `wallet_session.rs` tests use (`height: 663_149` plain integer literal — copy that form, drop the cast chain shown above).
  - `sapling::Node::from_bytes` returns `CtOption<Node>` — if the name differs, mirror the import used in `grpc.rs` (`sapling::Node::read(&bytes[..])` over a 32-byte slice is the fallback; `HashSer` from `zcash_primitives::merkle_tree` is already a dependency pattern from T2.1).
  - `Frontier::append` returns bool; ignore the return.
  - `CompactTx.fee` field may not exist in this proto version — if the struct has no `fee`, drop the field (use `..Default::default()`).
  - If `Chunk::from_blocks` clones are heavy, fine — test sizes are tiny.
  - The frontier replay assumes every cmu from the chain start; `synth_blocks` guarantees global cmu ordering (cmu_counter is global).
- [ ] **Step 4:** CLI `oracle` subcommand. In `cli/src/main.rs` add to `enum Cmd`:

```rust
    /// Golden-oracle run: sync the same UFVK/birthday twice into two wallet dirs
    /// (A = upstream persistence, B = upstream until T6.3 lands --sparse-b),
    /// then semantically diff the resulting data.db files. Exit 0 = identical.
    Oracle {
        #[arg(long)]
        server: String,
        /// Wallet dir A (created; must not contain data.db).
        #[arg(long)]
        wallet_a: std::path::PathBuf,
        /// Wallet dir B (created; must not contain data.db).
        #[arg(long)]
        wallet_b: std::path::PathBuf,
        #[arg(long)]
        ufvk: String,
        #[arg(long)]
        birthday: u64,
        /// Run B with sparse persistence (T6.3+).
        #[arg(long, default_value_t = false)]
        sparse_b: bool,
        #[arg(long, default_value_t = 4, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
        streams: usize,
        #[arg(long, default_value_t = 10_000)]
        chunk: u32,
    },
```

and the handler (next to `cmd_sync`; reuse its config pattern):

```rust
fn cmd_oracle(
    server: String,
    wallet_a: std::path::PathBuf,
    wallet_b: std::path::PathBuf,
    ufvk: String,
    birthday: u64,
    sparse_b: bool,
    streams: usize,
    chunk: u32,
) {
    let endpoint = parse_server(&server).unwrap_or_else(|e| { eprintln!("{e}"); std::process::exit(2) });
    for d in [&wallet_a, &wallet_b] {
        if d.join("data.db").exists() {
            eprintln!("error: {} already contains data.db — oracle needs fresh wallets", d.display());
            std::process::exit(2);
        }
    }
    let mk_cfg = |dir: &std::path::Path, sparse: bool| {
        let mut cfg = slipstream_core::EngineConfig::new(
            slipstream_core::Network::MainNetwork,
            dir.join("data.db"),
            endpoint.clone(),
        );
        cfg.fetch_streams = streams;
        cfg.chunk_blocks = chunk;
        let _ = sparse; // T6.3 sets cfg.sparse_persistence = sparse;
        cfg
    };
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let verdict = rt.block_on(async {
        println!("oracle: run A (upstream persistence) …");
        let a = slipstream_core::engine::sync_once(&mk_cfg(&wallet_a, false), Some((ufvk.as_str(), birthday)), None).await?;
        println!("oracle: run A done — tip {} in {:.1?}", a.chain_tip, a.elapsed);
        println!("oracle: run B (sparse_b={sparse_b}) …");
        let b = slipstream_core::engine::sync_once(&mk_cfg(&wallet_b, sparse_b), Some((ufvk.as_str(), birthday)), None).await?;
        println!("oracle: run B done — tip {} in {:.1?}", b.chain_tip, b.elapsed);
        if a.chain_tip != b.chain_tip {
            eprintln!("oracle: TIP SKEW (A={} B={}) — rerun when the chain is quiet", a.chain_tip, b.chain_tip);
            std::process::exit(3);
        }
        slipstream_core::oracle::semantic_diff(&wallet_a.join("data.db"), &wallet_b.join("data.db"))
    });
    match verdict {
        Ok(report) => {
            print!("{}", report.render());
            if report.is_clean() {
                println!("oracle: VERDICT IDENTICAL");
            } else {
                println!("oracle: VERDICT DIVERGED");
                std::process::exit(1);
            }
        }
        Err(e) => { eprintln!("oracle failed: {e}"); std::process::exit(1); }
    }
}
```

Wire the match arm in `main()`. Add a CLI parse test (`parses_oracle_subcommand` mirroring `parses_sync_subcommand`).
- [ ] **Step 5:** verify: `cargo test -p slipstream-core -p slipstream-cli` (new: 4 oracle unit + 1 determinism + 1 CLI parse). `cargo clippy` both crates + darkside feature clean. Smoke: `cargo run -p slipstream-cli -- oracle --server http://127.0.0.1:1 --wallet-a /tmp/oa --wallet-b /tmp/ob --ufvk x --birthday 1` → transport error, exit 1.
- [ ] **Step 6:** STATE.md (T6.2 done; determinism verdict + any allowlist additions; NEXT → T6.3) + commit:

```bash
git add slipstream/ docs/slipstream/STATE.md
git commit -m "[#1755] slipstream: T6.2 golden-oracle harness (semantic data.db diff + CLI oracle + determinism baseline)"
```

---

### Task 6.3: Sparse-persistence facade + spike with GO/NO-GO gate

The facade (complete, all arms) behind `EngineConfig::sparse_persistence` (default **off**), plus the A/B measurement that decides the phase. The facade intercepts ONLY `put_blocks`; everything else delegates to `WalletDb`. The tree work runs through upstream's own `ShardTree` against our in-memory store; rows go through upstream's public `LowLevelWalletWrite` methods inside one `transactionally` per chunk.

**GO/NO-GO GATE (controller-mandated, explicit):** on the Mac, G3-canonical conditions (zec.rocks, TEST_UFVK, ~50k-block fresh restore, chunk=10k — `scan_s(off)` ≈ 30 s known), measure `scan_s` flag-off vs flag-on (same range, fresh wallet dirs, back-to-back). **If `scan_s(off) / scan_s(on) < 1.5×, STOP THE PHASE**: record findings + per-section attribution (Step 9 timing log) in STATE.md, revert the default to off permanently, and fall back to the decrypt-kernel investigation (ROADMAP P6 original T6.3 column-ECDH track). The Mac 1.5× threshold is the proxy for the controller's "<2× headroom on device" rule (Mac SSD/CPU make SQLite cheaper than on A10 — if even the Mac shows <1.5×, the device headroom thesis is dead).

- [ ] **Step 1 (deps):** root `Cargo.toml` `[workspace.dependencies]` — append `shardtree = "0.6"` (already in Cargo.lock at 0.6.2 via zcash deps — additive lockfile no-op). `slipstream/core/Cargo.toml` `[dependencies]` — add `shardtree = { workspace = true }`, `incrementalmerkletree = { workspace = true }` (workspace.dependencies Cargo.toml:96) and `zip32 = { workspace = true }` (workspace.dependencies Cargo.toml:38; needed for `zip32::DiversifierIndex`/`zip32::AccountId` in the facade signatures — neither zcash_primitives 0.28 nor zcash_keys 0.14 re-export it). Decision-Log entry: "shardtree/incrementalmerkletree/zip32 promoted to direct slipstream-core deps (same versions as transitive) — required for in-memory ShardTree accumulation + facade signatures (P6)." Root Cargo.toml touched → this task's gate includes `swift test --filter OfflineTests`.
- [ ] **Step 2:** `wallet_session.rs` — change `type Db = …` (line 22) to `pub(crate) type Db = …`.
- [ ] **Step 3:** `config.rs` — add:

```rust
    /// Persist scan results via the sparse in-memory commitment-tree path
    /// (P6, flag-gated): upstream scan kernel unchanged; put_blocks tree work
    /// runs against an in-memory ShardTree flushed once per chunk. Default
    /// false until the golden oracle (T6.2/T6.4) is clean.
    pub sparse_persistence: bool,
```

(default `false` in `new()`; no validation needed). Test: `defaults_are_valid` extended with `assert!(!config().sparse_persistence);`.
- [ ] **Step 4 (failing test first):** create `slipstream/core/src/persist.rs` with the store contract tests below; `cargo test -p slipstream-core persist` fails until the module compiles. Module skeleton + complete store:

```rust
//! Sparse/batched persistence (P6): upstream-identical `put_blocks` semantics
//! with the shardtree state held in memory per scan range and flushed to SQLite
//! once per chunk. The scan kernel (`scan_cached_blocks`) is untouched — this
//! module only swaps the `WalletWrite::put_blocks` target via `SparseFacade`.
//! Flag-gated by `EngineConfig::sparse_persistence`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::num::NonZeroU32;
use std::ops::Range;
use std::time::SystemTime;

use incrementalmerkletree::{Address, Level, Marking, Position, Retention, frontier::Frontier};
use rayon::iter::{IndexedParallelIterator as _, ParallelIterator};
use rayon::slice::ParallelSliceMut as _;
use secrecy::SecretVec;
use shardtree::{
    LocatedPrunableTree, PrunableTree, ShardTree,
    error::ShardTreeError,
    store::{Checkpoint, ShardStore},
};
use tracing::{debug, info};
use transparent::address::TransparentAddress;
use zip32::DiversifierIndex;

use zcash_client_backend::TransferType;
use zcash_client_backend::data_api::{
    AccountBirthday, AccountPurpose, AddressInfo, BlockMetadata, DecryptedTransaction,
    NullifierQuery, ORCHARD_SHARD_HEIGHT, ReceivedTransactionOutput, SAPLING_SHARD_HEIGHT,
    ScannedBlock, SeedRelevance, SentTransaction, TransactionDataRequest, TransactionStatus,
    TransactionsInvolvingAddress, TransparentBalances, WalletCommitmentTrees, WalletRead,
    WalletSummary, WalletWrite, Zip32Derivation,
    chain::ChainState,
    error::FindAccountForAddressError,
    ll::{LowLevelWalletRead, LowLevelWalletWrite, wallet::PutBlocksError},
    scanning::ScanRange,
    wallet::{ConfirmationsPolicy, TargetHeight},
};
use zcash_client_backend::wallet::{
    NoteId, Recipient, TransparentAddressMetadata, WalletTransparentOutput,
};
use zcash_client_sqlite::error::SqliteClientError;
use zcash_keys::address::UnifiedAddress;
use zcash_keys::keys::{
    ReceiverRequirement, UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey,
};
use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::ShieldedProtocol;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::memo::Memo;

use crate::wallet_session::Db;

/// Mirror of upstream's checkpoint retention bound
/// (zcash_client_backend ll/wallet.rs:52 PRUNING_DEPTH = 100, used as
/// max_checkpoints at zcash_client_sqlite lib.rs:2213).
const MAX_CHECKPOINTS: usize = 100;

/// Subtree build chunk size — mirror of ll/wallet.rs:467 CHUNK_SIZE.
const BUILD_CHUNK_SIZE: usize = 1024;

// ── In-memory shard store ──────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum SparseStoreError {
    /// A shard exists in SQLite but was not preloaded — preload-set bug.
    /// Failing loudly here is a D3 guard: silently treating it as absent would
    /// diverge from upstream pruning behavior.
    #[error("shard index {0} exists in the database but was not preloaded")]
    NotPreloaded(u64),
    #[error("operation not supported by the in-memory sparse store: {0}")]
    Unsupported(&'static str),
}

/// ShardStore over BTreeMaps with read-miss policy and dirty tracking.
/// Semantics inherited: all mutations come from upstream's own ShardTree logic.
pub struct SparseShardStore<H> {
    shard_level: Level,
    /// Shard indices present in SQLite at seed time.
    db_shard_indices: BTreeSet<u64>,
    shards: BTreeMap<u64, LocatedPrunableTree<H>>,
    dirty_shards: BTreeSet<u64>,
    cap: PrunableTree<H>,
    cap_dirty: bool,
    checkpoints: BTreeMap<BlockHeight, Checkpoint>,
    /// Mirror of the checkpoint rows in SQLite (for flush diffing).
    db_checkpoints: BTreeMap<BlockHeight, Checkpoint>,
}

impl<H> SparseShardStore<H> {
    pub fn new(shard_height: u8) -> Self {
        Self {
            shard_level: Level::new(shard_height),
            db_shard_indices: BTreeSet::new(),
            shards: BTreeMap::new(),
            dirty_shards: BTreeSet::new(),
            cap: PrunableTree::empty(),
            cap_dirty: false,
            checkpoints: BTreeMap::new(),
            db_checkpoints: BTreeMap::new(),
        }
    }

    /// Checkpoint diff vs the SQLite mirror: (to_remove, to_add).
    /// A checkpoint whose state changed appears in both (remove + re-add),
    /// matching add_checkpoint's CheckpointConflict contract
    /// (zcash_client_sqlite commitment_tree.rs:654-740).
    fn checkpoint_delta(&self) -> (Vec<BlockHeight>, Vec<(BlockHeight, Checkpoint)>) {
        let mut remove = vec![];
        let mut add = vec![];
        for (h, db_cp) in &self.db_checkpoints {
            match self.checkpoints.get(h) {
                None => remove.push(*h),
                Some(mem_cp)
                    if mem_cp.tree_state() != db_cp.tree_state()
                        || mem_cp.marks_removed() != db_cp.marks_removed() =>
                {
                    remove.push(*h);
                    add.push((*h, mem_cp.clone()));
                }
                Some(_) => {}
            }
        }
        for (h, cp) in &self.checkpoints {
            if !self.db_checkpoints.contains_key(h) {
                add.push((*h, cp.clone()));
            }
        }
        (remove, add)
    }
}

impl<H: Clone> ShardStore for SparseShardStore<H> {
    type H = H;
    type CheckpointId = BlockHeight;
    type Error = SparseStoreError;

    fn get_shard(&self, addr: Address) -> Result<Option<LocatedPrunableTree<H>>, Self::Error> {
        let idx = addr.index();
        if let Some(s) = self.shards.get(&idx) {
            return Ok(Some(s.clone()));
        }
        if self.db_shard_indices.contains(&idx) {
            return Err(SparseStoreError::NotPreloaded(idx));
        }
        Ok(None)
    }

    fn last_shard(&self) -> Result<Option<LocatedPrunableTree<H>>, Self::Error> {
        // Invariant: the frontier shard (true last) is always preloaded at seed,
        // so the max loaded/created index is the true last shard.
        Ok(self.shards.values().next_back().cloned())
    }

    fn put_shard(&mut self, subtree: LocatedPrunableTree<H>) -> Result<(), Self::Error> {
        let idx = subtree.root_addr().index();
        self.shards.insert(idx, subtree);
        self.dirty_shards.insert(idx);
        Ok(())
    }

    fn get_shard_roots(&self) -> Result<Vec<Address>, Self::Error> {
        let mut all: BTreeSet<u64> = self.db_shard_indices.clone();
        all.extend(self.shards.keys().copied());
        Ok(all.into_iter().map(|i| Address::from_parts(self.shard_level, i)).collect())
    }

    fn truncate_shards(&mut self, _shard_index: u64) -> Result<(), Self::Error> {
        // Never reached on the insert path; reorg truncation goes through the
        // REAL WalletDb (scheduler reorg arm) and the sparse state is discarded
        // per range. Fail loudly if shardtree internals ever call this.
        Err(SparseStoreError::Unsupported("truncate_shards"))
    }

    fn get_cap(&self) -> Result<PrunableTree<H>, Self::Error> {
        Ok(self.cap.clone())
    }

    fn put_cap(&mut self, cap: PrunableTree<H>) -> Result<(), Self::Error> {
        self.cap = cap;
        self.cap_dirty = true;
        Ok(())
    }

    fn min_checkpoint_id(&self) -> Result<Option<BlockHeight>, Self::Error> {
        Ok(self.checkpoints.keys().next().copied())
    }

    fn max_checkpoint_id(&self) -> Result<Option<BlockHeight>, Self::Error> {
        Ok(self.checkpoints.keys().next_back().copied())
    }

    fn add_checkpoint(&mut self, id: BlockHeight, checkpoint: Checkpoint) -> Result<(), Self::Error> {
        self.checkpoints.insert(id, checkpoint);
        Ok(())
    }

    fn checkpoint_count(&self) -> Result<usize, Self::Error> {
        Ok(self.checkpoints.len())
    }

    fn get_checkpoint_at_depth(
        &self,
        checkpoint_depth: usize,
    ) -> Result<Option<(BlockHeight, Checkpoint)>, Self::Error> {
        // Matches SQLite: ORDER BY checkpoint_id DESC LIMIT 1 OFFSET depth.
        Ok(self
            .checkpoints
            .iter()
            .rev()
            .nth(checkpoint_depth)
            .map(|(id, c)| (*id, c.clone())))
    }

    fn get_checkpoint(&self, id: &BlockHeight) -> Result<Option<Checkpoint>, Self::Error> {
        Ok(self.checkpoints.get(id).cloned())
    }

    fn with_checkpoints<F>(&mut self, limit: usize, mut callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&BlockHeight, &Checkpoint) -> Result<(), Self::Error>,
    {
        for (id, cp) in self.checkpoints.iter().take(limit) {
            callback(id, cp)?;
        }
        Ok(())
    }

    fn for_each_checkpoint<F>(&self, limit: usize, mut callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&BlockHeight, &Checkpoint) -> Result<(), Self::Error>,
    {
        for (id, cp) in self.checkpoints.iter().take(limit) {
            callback(id, cp)?;
        }
        Ok(())
    }

    fn update_checkpoint_with<F>(&mut self, id: &BlockHeight, update: F) -> Result<bool, Self::Error>
    where
        F: Fn(&mut Checkpoint) -> Result<(), Self::Error>,
    {
        if let Some(cp) = self.checkpoints.get_mut(id) {
            update(cp)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn remove_checkpoint(&mut self, id: &BlockHeight) -> Result<(), Self::Error> {
        self.checkpoints.remove(id);
        Ok(())
    }

    fn truncate_checkpoints_retaining(&mut self, _id: &BlockHeight) -> Result<(), Self::Error> {
        Err(SparseStoreError::Unsupported("truncate_checkpoints_retaining"))
    }
}
```

Contract tests (same file, `#[cfg(test)]`):

```rust
#[cfg(test)]
mod store_tests {
    use super::*;
    use incrementalmerkletree::Address;

    type Store = SparseShardStore<sapling::Node>;

    #[test]
    fn miss_on_unknown_index_is_none_but_known_unloaded_errors() {
        let mut s = Store::new(16);
        let addr9 = Address::from_parts(Level::new(16), 9);
        assert!(matches!(s.get_shard(addr9), Ok(None)));
        s.db_shard_indices.insert(9);
        assert!(matches!(s.get_shard(addr9), Err(SparseStoreError::NotPreloaded(9))));
    }

    #[test]
    fn put_shard_marks_dirty_and_serves_reads() {
        let mut s = Store::new(16);
        let addr = Address::from_parts(Level::new(16), 3);
        let tree = LocatedPrunableTree::from_parts(addr, PrunableTree::empty()).expect("empty ok");
        s.put_shard(tree).expect("put");
        assert!(s.dirty_shards.contains(&3));
        assert!(matches!(s.get_shard(addr), Ok(Some(_))));
        assert_eq!(s.last_shard().expect("last").map(|t| t.root_addr().index()), Some(3));
    }

    #[test]
    fn checkpoint_delta_computes_remove_add_change() {
        let mut s = Store::new(16);
        let h = |n: u32| BlockHeight::from(n);
        s.db_checkpoints.insert(h(10), Checkpoint::tree_empty());
        s.db_checkpoints.insert(h(11), Checkpoint::tree_empty());
        s.db_checkpoints.insert(h(12), Checkpoint::at_position(Position::from(5u64)));
        // mem: 10 kept identical, 11 removed, 12 changed, 13 added
        s.checkpoints.insert(h(10), Checkpoint::tree_empty());
        s.checkpoints.insert(h(12), Checkpoint::at_position(Position::from(7u64)));
        s.checkpoints.insert(h(13), Checkpoint::at_position(Position::from(9u64)));
        let (remove, add) = s.checkpoint_delta();
        assert_eq!(remove, vec![h(11), h(12)]);
        let add_ids: Vec<u32> = add.iter().map(|(h, _)| u32::from(*h)).collect();
        assert_eq!(add_ids, vec![12, 13]);
    }

    #[test]
    fn checkpoint_at_depth_matches_desc_offset_semantics() {
        let mut s = Store::new(16);
        for n in [5u32, 7, 9] {
            s.add_checkpoint(BlockHeight::from(n), Checkpoint::tree_empty()).unwrap();
        }
        let (id, _) = s.get_checkpoint_at_depth(0).unwrap().unwrap();
        assert_eq!(u32::from(id), 9);
        let (id, _) = s.get_checkpoint_at_depth(2).unwrap().unwrap();
        assert_eq!(u32::from(id), 5);
        assert!(s.get_checkpoint_at_depth(3).unwrap().is_none());
    }
}
```

(Binding note: `LocatedPrunableTree::from_parts(addr, PrunableTree::empty())` may reject an empty root for a level-16 address — if so, build the test tree via `LocatedPrunableTree::from_parts(Address::from_parts(Level::new(16), 3), PrunableTree::leaf((node, shardtree::RetentionFlags::EPHEMERAL)))`-style smallest constructible value, or fall back to constructing through `shardtree::LocatedTree::from_iter`; mirror whatever compiles, the assertion targets are dirty-tracking and index bookkeeping, not tree contents.)

- [ ] **Step 5:** `SparseTreeState` + seed + flush + `sparse_put_blocks` (same file, continued). The function mirrors `ll::wallet::put_blocks` line-for-line — comments cite the mirrored lines:

```rust
// ── Per-range sparse tree state ────────────────────────────────────────────────

type SaplingSparseTree = ShardTree<
    SparseShardStore<sapling::Node>,
    { sapling::NOTE_COMMITMENT_TREE_DEPTH },
    SAPLING_SHARD_HEIGHT,
>;
type OrchardSparseTree = ShardTree<
    SparseShardStore<orchard::tree::MerkleHashOrchard>,
    { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
    ORCHARD_SHARD_HEIGHT,
>;

/// In-memory tree state for ONE scan range (created per scan_chunks call,
/// dropped at range end / on error — reorg truncation therefore never has to
/// invalidate it explicitly).
#[derive(Default)]
pub struct SparseTreeState {
    sapling: Option<SaplingSparseTree>,
    orchard: Option<OrchardSparseTree>,
}

/// Seed preload set: the shard containing the frontier position, plus every
/// shard referenced by an existing checkpoint position or marks_removed entry
/// (prune_excess_checkpoints can clear flags there — shardtree lib.rs:550-660).
fn preload_indices(
    shard_height: u8,
    frontier_pos: Option<Position>,
    checkpoints: &BTreeMap<BlockHeight, Checkpoint>,
) -> BTreeSet<u64> {
    let level = Level::new(shard_height);
    let mut want = BTreeSet::new();
    if let Some(p) = frontier_pos {
        want.insert(Address::above_position(level, p).index());
    }
    for cp in checkpoints.values() {
        if let Some(p) = cp.position() {
            want.insert(Address::above_position(level, p).index());
        }
        for p in cp.marks_removed() {
            want.insert(Address::above_position(level, *p).index());
        }
    }
    want
}
```

Seed + flush are written twice (per pool) because `with_sapling_tree_mut`/`with_orchard_tree_mut` have distinct hash types — the bodies are mechanical twins. Sapling version (orchard mirrors with `orchard::tree::MerkleHashOrchard`, `ORCHARD_SHARD_HEIGHT`, `final_orchard_tree`, `with_orchard_tree_mut`):

```rust
fn seed_sapling(db: &mut Db, from_state: &ChainState) -> Result<SaplingSparseTree, SqliteClientError> {
    let mut store = SparseShardStore::<sapling::Node>::new(SAPLING_SHARD_HEIGHT);
    let frontier_pos = from_state.final_sapling_tree().value().map(|f| f.position());
    db.with_sapling_tree_mut::<_, _, SqliteClientError>(|tree| {
        let s = tree.store();
        let roots = s.get_shard_roots().map_err(ShardTreeError::Storage)?;
        store.db_shard_indices = roots.iter().map(|a| a.index()).collect();
        let count = s.checkpoint_count().map_err(ShardTreeError::Storage)?;
        let mut cps = BTreeMap::new();
        s.for_each_checkpoint(count, |id, cp| {
            cps.insert(*id, cp.clone());
            Ok(())
        })
        .map_err(ShardTreeError::Storage)?;
        let want = preload_indices(SAPLING_SHARD_HEIGHT, frontier_pos, &cps);
        for idx in want {
            if store.db_shard_indices.contains(&idx) {
                let addr = Address::from_parts(Level::new(SAPLING_SHARD_HEIGHT), idx);
                if let Some(shard) = s.get_shard(addr).map_err(ShardTreeError::Storage)? {
                    store.shards.insert(idx, shard);
                }
            }
        }
        store.cap = s.get_cap().map_err(ShardTreeError::Storage)?;
        store.checkpoints = cps.clone();
        store.db_checkpoints = cps;
        Ok(())
    })?;
    Ok(ShardTree::new(store, MAX_CHECKPOINTS))
}

/// Flush dirty in-memory tree state into the live transaction's SQLite store.
/// Shards ascending (check_shard_discontinuity, commitment_tree.rs:444-481);
/// checkpoint changes as remove+add (CheckpointConflict contract).
fn flush_sapling<P, CL, R>(
    wdb: &mut zcash_client_sqlite::WalletDb<zcash_client_sqlite::SqlTransaction<'_>, P, CL, R>,
    tree: &mut SaplingSparseTree,
) -> Result<(), SqliteClientError>
where
    P: zcash_protocol::consensus::Parameters,
{
    let (remove, add) = tree.store().checkpoint_delta();
    let dirty: Vec<u64> = tree.store().dirty_shards.iter().copied().collect();
    let cap_dirty = tree.store().cap_dirty;
    wdb.with_sapling_tree_mut::<_, _, SqliteClientError>(|sql_tree| {
        for idx in &dirty {
            let shard = tree
                .store()
                .shards
                .get(idx)
                .cloned()
                .ok_or_else(|| ShardTreeError::Storage(
                    zcash_client_sqlite::wallet::commitment_tree::Error::Serialization(
                        std::io::Error::other(format!("dirty shard {idx} missing from memory")),
                    ),
                ))?;
            sql_tree.store_mut().put_shard(shard).map_err(ShardTreeError::Storage)?;
        }
        if cap_dirty {
            sql_tree
                .store_mut()
                .put_cap(tree.store().cap.clone())
                .map_err(ShardTreeError::Storage)?;
        }
        for h in &remove {
            sql_tree.store_mut().remove_checkpoint(h).map_err(ShardTreeError::Storage)?;
        }
        for (h, cp) in &add {
            sql_tree
                .store_mut()
                .add_checkpoint(*h, cp.clone())
                .map_err(ShardTreeError::Storage)?;
        }
        Ok(())
    })?;
    let store = tree.store_mut();
    store.db_checkpoints = store.checkpoints.clone();
    for idx in store.dirty_shards.iter() {
        store.db_shard_indices.insert(*idx);
    }
    store.dirty_shards.clear();
    store.cap_dirty = false;
    Ok(())
}
```

**Binding notes:** (1) field access on `tree.store()` from outside the module works because `flush_sapling`/`seed_sapling` live in the same module as `SparseShardStore` (fields are private-to-module — keep them non-pub). (2) `with_sapling_tree_mut` closures are `FnMut` — captured `&mut store` is fine. (3) the error closures must produce `SqliteClientError: From<ShardTreeError<commitment_tree::Error>>` — that From exists (upstream uses it, wallet.rs:3760-3768). (4) If `zcash_client_sqlite::SqlTransaction`/`WalletDb` generics make the `flush_*` signature painful, inline the flush bodies directly in `sparse_put_blocks`'s `transactionally` closure (the controller accepts that shape; keep the comments).

Then the heart — mirror citations inline:

```rust
/// Upstream-identical put_blocks with in-memory tree accumulation.
/// Mirrors zcash_client_backend-0.23.0 ll/wallet.rs:235-550 section by section;
/// the ONLY substitution is the tree target (SparseShardStore vs SqliteShardStore)
/// plus a flush of the dirty tree delta inside the same transaction.
#[allow(clippy::too_many_lines)]
pub fn sparse_put_blocks(
    inner: &mut Db,
    sparse: &mut SparseTreeState,
    from_state: &ChainState,
    blocks: Vec<ScannedBlock<<Db as WalletRead>::AccountId>>,
) -> Result<(), SqliteClientError> {
    // ll/wallet.rs:245-247.
    let Some(initial_block) = blocks.first() else {
        return Ok(());
    };

    // ── Validation — ll/wallet.rs:249-267 ────────────────────────────────────
    // (usize → u64 is lossless on every supported target; upstream unwraps here.)
    let mut seq = from_state.block_height() + 1 == initial_block.height();
    seq &= from_state.final_sapling_tree().tree_size()
        + initial_block.sapling().commitments().len() as u64
        == u64::from(initial_block.sapling().final_tree_size());
    seq &= from_state.final_orchard_tree().tree_size()
        + initial_block.orchard().commitments().len() as u64
        == u64::from(initial_block.orchard().final_tree_size());
    if !seq {
        return Err(SqliteClientError::from(
            PutBlocksError::<SqliteClientError, zcash_client_sqlite::wallet::commitment_tree::Error>::NonSequentialBlocks {
                prev_height: from_state.block_height(),
                block_height: initial_block.height(),
            },
        ));
    }

    // Seed per-range trees lazily (first chunk of the range), then destructure
    // once — disjoint &mut borrows for the transactionally closure, no expect().
    if sparse.sapling.is_none() {
        sparse.sapling = Some(seed_sapling(inner, from_state)?);
    }
    if sparse.orchard.is_none() {
        sparse.orchard = Some(seed_orchard(inner, from_state)?);
    }
    let SparseTreeState { sapling: Some(sap_tree), orchard: Some(orch_tree) } = sparse else {
        return Err(SqliteClientError::CorruptedData(
            "sparse tree state missing after seed".into(),
        ));
    };

    let t_rows = std::time::Instant::now();
    let mut rows_ms = 0u128;
    let mut tree_ms = 0u128;
    let mut flush_ms = 0u128;

    inner.transactionally::<_, _, SqliteClientError>(|wdb| {
        let mut sapling_commitments = vec![];
        let mut orchard_commitments = vec![];
        let mut last_scanned_height: Option<BlockHeight> = None;
        let mut note_positions: Vec<(ShieldedProtocol, Position)> = vec![];
        let mut tx_refs = HashSet::new();

        for block in blocks.into_iter() {
            // ll/wallet.rs:278-287 — height-consecutive guard.
            if let Some(prev) = last_scanned_height
                && block.height() != prev + 1
            {
                return Err(SqliteClientError::from(
                    PutBlocksError::<SqliteClientError, zcash_client_sqlite::wallet::commitment_tree::Error>::NonSequentialBlocks {
                        prev_height: prev,
                        block_height: block.height(),
                    },
                ));
            }

            // ll/wallet.rs:289-302 — block meta row.
            let sapling_count = u32::try_from(block.sapling().commitments().len())
                .map_err(|_| SqliteClientError::CorruptedData("sapling output count exceeds u32".into()))?;
            let orchard_count = u32::try_from(block.orchard().commitments().len())
                .map_err(|_| SqliteClientError::CorruptedData("orchard action count exceeds u32".into()))?;
            wdb.put_block_meta(
                block.height(),
                block.block_hash(),
                block.block_time(),
                block.sapling().final_tree_size(),
                sapling_count,
                block.orchard().final_tree_size(),
                orchard_count,
            )?;

            for tx in block.transactions() {
                // ll/wallet.rs:304-312.
                let tx_ref = wdb.put_tx_meta(tx, block.height())?;
                tx_refs.insert(tx_ref);
                wdb.queue_tx_retrieval(std::iter::once(tx.txid()), None)?;

                // ll/wallet.rs:931-963 mark_notes_spent (no transparent prevouts
                // in the compact path — upstream passes None.iter()).
                for spend in tx.sapling_spends() {
                    wdb.mark_sapling_note_spent(spend.nf(), tx_ref)?;
                }
                for spend in tx.orchard_spends() {
                    wdb.mark_orchard_note_spent(spend.nf(), tx_ref)?;
                }

                // ll/wallet.rs:964-1090 put_shielded_outputs, compact-path arms
                // only (params=None, funding_account=None — ll/wallet.rs:330-377):
                // Outgoing is impossible for compact outputs (ivk-only decryption).
                for output in tx.sapling_outputs() {
                    match output.transfer_type() {
                        TransferType::Outgoing => {
                            return Err(SqliteClientError::CorruptedData(
                                "unexpected Outgoing transfer type in compact scan output".into(),
                            ));
                        }
                        TransferType::WalletInternal | TransferType::Incoming => {
                            let spent_in = output
                                .nf()
                                .map(|nf| wdb.detect_sapling_spend(nf))
                                .transpose()?
                                .flatten();
                            wdb.put_received_sapling_note(output, tx_ref, Some(block.height()), spent_in)?;
                            if output.transfer_type() == TransferType::WalletInternal {
                                let note: zcash_client_backend::wallet::Note =
                                    output.note().clone().into();
                                let value = note.value();
                                let recipient = Recipient::InternalAccount {
                                    receiving_account: *output.account_id(),
                                    external_address: None,
                                    note: Box::new(note),
                                };
                                wdb.put_sent_output(
                                    *output.account_id(),
                                    tx_ref,
                                    output.index(),
                                    &recipient,
                                    value,
                                    output.memo(),
                                )?;
                            }
                        }
                    }
                }
                for output in tx.orchard_outputs() {
                    match output.transfer_type() {
                        TransferType::Outgoing => {
                            return Err(SqliteClientError::CorruptedData(
                                "unexpected Outgoing transfer type in compact scan output".into(),
                            ));
                        }
                        TransferType::WalletInternal | TransferType::Incoming => {
                            let spent_in = output
                                .nf()
                                .map(|nf| wdb.detect_orchard_spend(nf))
                                .transpose()?
                                .flatten();
                            wdb.put_received_orchard_note(output, tx_ref, Some(block.height()), spent_in)?;
                            if output.transfer_type() == TransferType::WalletInternal {
                                let note: zcash_client_backend::wallet::Note =
                                    output.note().clone().into();
                                let value = note.value();
                                let recipient = Recipient::InternalAccount {
                                    receiving_account: *output.account_id(),
                                    external_address: None,
                                    note: Box::new(note),
                                };
                                wdb.put_sent_output(
                                    *output.account_id(),
                                    tx_ref,
                                    output.index(),
                                    &recipient,
                                    value,
                                    output.memo(),
                                )?;
                            }
                        }
                    }
                }
            }

            // ll/wallet.rs:380-390 — nullifier tracking.
            wdb.track_block_sapling_nullifiers(block.height(), block.sapling().nullifier_map())?;
            wdb.track_block_orchard_nullifiers(block.height(), block.orchard().nullifier_map())?;

            // ll/wallet.rs:399-417 — note positions.
            note_positions.extend(block.transactions().iter().flat_map(|wtx| {
                wtx.sapling_outputs()
                    .iter()
                    .map(|out| (ShieldedProtocol::Sapling, out.note_commitment_tree_position()))
                    .chain(
                        wtx.orchard_outputs()
                            .iter()
                            .map(|out| (ShieldedProtocol::Orchard, out.note_commitment_tree_position())),
                    )
            }));

            last_scanned_height = Some(block.height());
            let block_commitments = block.into_commitments();
            sapling_commitments.extend(block_commitments.sapling.into_iter().map(Some));
            orchard_commitments.extend(block_commitments.orchard.into_iter().map(Some));
        }

        // ll/wallet.rs:440-457 — gap addresses for involved accounts.
        for (account_id, key_scope) in wdb.find_involved_accounts(tx_refs)? {
            if let Some(t_key_scope) = key_scope {
                use ReceiverRequirement::*;
                wdb.generate_transparent_gap_addresses(
                    account_id,
                    t_key_scope,
                    UnifiedAddressRequest::unsafe_custom(Allow, Allow, Require),
                )?;
            }
        }

        // ll/wallet.rs:459-462.
        wdb.prune_tracked_nullifiers(100)?;
        rows_ms = t_rows.elapsed().as_millis();

        if let Some(last_scanned_height) = last_scanned_height {
            let t_tree = std::time::Instant::now();

            // ll/wallet.rs:466-481 — build subtrees (rayon, same chunk size).
            let sapling_subtrees = build_subtrees::<_, SAPLING_SHARD_HEIGHT>(
                Position::from(from_state.final_sapling_tree().tree_size()),
                &mut sapling_commitments,
            );
            let orchard_subtrees = build_subtrees::<_, ORCHARD_SHARD_HEIGHT>(
                Position::from(from_state.final_orchard_tree().tree_size()),
                &mut orchard_commitments,
            );

            // ll/wallet.rs:484-501 — cross-pool checkpoint reconciliation.
            let sapling_cp_pos = checkpoint_positions(&sapling_subtrees);
            let orchard_cp_pos = checkpoint_positions(&orchard_subtrees);
            let missing_sapling = ensure_checkpoints(
                orchard_cp_pos.keys(),
                &sapling_cp_pos,
                from_state.final_sapling_tree(),
            );
            let missing_orchard = ensure_checkpoints(
                sapling_cp_pos.keys(),
                &orchard_cp_pos,
                from_state.final_orchard_tree(),
            );

            // ll/wallet.rs:503-537 update_tree — IN MEMORY (the substitution).
            fn map_sparse_err<E: std::fmt::Debug>(e: E) -> SqliteClientError {
                SqliteClientError::CorruptedData(format!("sparse tree: {e:?}"))
            }
            {
                sap_tree
                    .insert_frontier(
                        from_state.final_sapling_tree().clone(),
                        Retention::Checkpoint { id: from_state.block_height(), marking: Marking::Reference },
                    )
                    .map_err(map_sparse_err)?;
                for (subtree, checkpoints) in sapling_subtrees {
                    sap_tree.insert_tree(subtree, checkpoints).map_err(map_sparse_err)?;
                }
                let min_cp = sap_tree
                    .store()
                    .min_checkpoint_id()
                    .map_err(map_sparse_err)?
                    .ok_or_else(|| SqliteClientError::CorruptedData(
                        "no sapling checkpoint after insert_frontier".into(),
                    ))?;
                for (height, checkpoint) in missing_sapling {
                    if height > min_cp {
                        sap_tree
                            .store_mut()
                            .add_checkpoint(height, checkpoint)
                            .map_err(map_sparse_err)?;
                    }
                }
            }
            {
                orch_tree
                    .insert_frontier(
                        from_state.final_orchard_tree().clone(),
                        Retention::Checkpoint { id: from_state.block_height(), marking: Marking::Reference },
                    )
                    .map_err(map_sparse_err)?;
                for (subtree, checkpoints) in orchard_subtrees {
                    orch_tree.insert_tree(subtree, checkpoints).map_err(map_sparse_err)?;
                }
                let min_cp = orch_tree
                    .store()
                    .min_checkpoint_id()
                    .map_err(map_sparse_err)?
                    .ok_or_else(|| SqliteClientError::CorruptedData(
                        "no orchard checkpoint after insert_frontier".into(),
                    ))?;
                for (height, checkpoint) in missing_orchard {
                    if height > min_cp {
                        orch_tree
                            .store_mut()
                            .add_checkpoint(height, checkpoint)
                            .map_err(map_sparse_err)?;
                    }
                }
            }
            tree_ms = t_tree.elapsed().as_millis();

            // Flush the dirty tree delta + scan-queue update in the SAME txn.
            let t_flush = std::time::Instant::now();
            flush_sapling(wdb, sap_tree)?;
            flush_orchard(wdb, orch_tree)?;
            // ll/wallet.rs:539-547.
            wdb.notify_scan_complete(
                Range { start: from_state.block_height() + 1, end: last_scanned_height + 1 },
                &note_positions,
            )?;
            flush_ms = t_flush.elapsed().as_millis();
        }
        Ok(())
    })?;

    info!(rows_ms, tree_ms, flush_ms, "sparse put_blocks");
    Ok(())
}

// ── Replicas of upstream private helpers (public types only) ──────────────────

/// Mirror of ll/wallet.rs:1146-1170 (private upstream; rebuilt on public API).
fn build_subtrees<H, const SHARD_HEIGHT: u8>(
    start_position: Position,
    commitments: &mut [Option<(H, Retention<BlockHeight>)>],
) -> Vec<(LocatedPrunableTree<H>, BTreeMap<BlockHeight, Position>)>
where
    H: Clone + PartialEq + incrementalmerkletree::Hashable + Send + Sync,
{
    commitments
        .par_chunks_mut(BUILD_CHUNK_SIZE)
        .enumerate()
        .filter_map(|(i, chunk)| {
            let start = start_position + (i * BUILD_CHUNK_SIZE) as u64;
            let end = start + chunk.len() as u64;
            shardtree::LocatedTree::from_iter(
                start..end,
                SHARD_HEIGHT.into(),
                chunk.iter_mut().map(|n| n.take().expect("always Some")),
            )
        })
        .map(|res| (res.subtree, res.checkpoints))
        .collect()
}

/// Mirror of ll/wallet.rs:1173-1183.
fn checkpoint_positions<H>(
    subtrees: &[(LocatedPrunableTree<H>, BTreeMap<BlockHeight, Position>)],
) -> BTreeMap<BlockHeight, Position> {
    subtrees
        .iter()
        .flat_map(|(_, checkpoints)| checkpoints.iter())
        .map(|(k, v)| (*k, *v))
        .collect()
}

/// Mirror of ll/wallet.rs:1184-1226.
fn ensure_checkpoints<'a, H, I: Iterator<Item = &'a BlockHeight>, const DEPTH: u8>(
    ensure_heights: I,
    existing: &BTreeMap<BlockHeight, Position>,
    state_final_tree: &Frontier<H, DEPTH>,
) -> Vec<(BlockHeight, Checkpoint)> {
    ensure_heights
        .flat_map(|ensure_height| {
            existing
                .range::<BlockHeight, _>(..=*ensure_height)
                .last()
                .map_or_else(
                    || {
                        Some((
                            *ensure_height,
                            state_final_tree
                                .value()
                                .map_or_else(Checkpoint::tree_empty, |t| Checkpoint::at_position(t.position())),
                        ))
                    },
                    |(h, position)| {
                        if *h < *ensure_height {
                            Some((*ensure_height, Checkpoint::at_position(*position)))
                        } else {
                            None
                        }
                    },
                )
                .into_iter()
        })
        .collect()
}
```

(`expect("always Some")` inside `build_subtrees` mirrors upstream verbatim and is structurally infallible (each Option is taken exactly once); annotate with `// mirror of upstream; structurally infallible` to satisfy the no-expect convention review. `seed_orchard`/`flush_orchard` are the mechanical twins of the sapling versions.)

- [ ] **Step 6:** `SparseFacade` + trait impls (same file). Delegation is compiler-enforced — `cargo check` reports any missed/mis-signed method; every body is a one-liner:

```rust
// ── WalletWrite facade ─────────────────────────────────────────────────────────

/// Borrows the real WalletDb + the per-range sparse tree state; passes
/// scan_cached_blocks' put_blocks call to sparse_put_blocks and delegates
/// EVERYTHING else verbatim. Error type = SqliteClientError → upstream error
/// shapes (incl. continuity ScanErrors) are preserved bit-for-bit.
pub struct SparseFacade<'a> {
    pub inner: &'a mut Db,
    pub sparse: &'a mut SparseTreeState,
}

impl WalletRead for SparseFacade<'_> {
    type Error = SqliteClientError;
    type AccountId = <Db as WalletRead>::AccountId;
    type Account = <Db as WalletRead>::Account;

    fn get_account_ids(&self) -> Result<Vec<Self::AccountId>, Self::Error> { self.inner.get_account_ids() }
    fn get_account(&self, account_id: Self::AccountId) -> Result<Option<Self::Account>, Self::Error> { self.inner.get_account(account_id) }
    fn get_derived_account(&self, derivation: &Zip32Derivation) -> Result<Option<Self::Account>, Self::Error> { self.inner.get_derived_account(derivation) }
    fn validate_seed(&self, account_id: Self::AccountId, seed: &SecretVec<u8>) -> Result<bool, Self::Error> { self.inner.validate_seed(account_id, seed) }
    fn seed_relevance_to_derived_accounts(&self, seed: &SecretVec<u8>) -> Result<SeedRelevance<Self::AccountId>, Self::Error> { self.inner.seed_relevance_to_derived_accounts(seed) }
    fn get_account_for_ufvk(&self, ufvk: &UnifiedFullViewingKey) -> Result<Option<Self::Account>, Self::Error> { self.inner.get_account_for_ufvk(ufvk) }
    fn list_addresses(&self, account: Self::AccountId) -> Result<Vec<AddressInfo>, Self::Error> { self.inner.list_addresses(account) }
    fn find_account_for_address<P: zcash_protocol::consensus::Parameters>(&self, params: &P, address: &zcash_keys::address::Address) -> Result<Option<Self::AccountId>, FindAccountForAddressError<Self::Error>> { self.inner.find_account_for_address(params, address) }
    fn get_last_generated_address_matching(&self, account: Self::AccountId, address_filter: UnifiedAddressRequest) -> Result<Option<UnifiedAddress>, Self::Error> { self.inner.get_last_generated_address_matching(account, address_filter) }
    fn get_account_birthday(&self, account: Self::AccountId) -> Result<BlockHeight, Self::Error> { self.inner.get_account_birthday(account) }
    fn get_wallet_birthday(&self) -> Result<Option<BlockHeight>, Self::Error> { self.inner.get_wallet_birthday() }
    fn get_wallet_summary(&self, confirmations_policy: ConfirmationsPolicy) -> Result<Option<WalletSummary<Self::AccountId>>, Self::Error> { self.inner.get_wallet_summary(confirmations_policy) }
    fn chain_height(&self) -> Result<Option<BlockHeight>, Self::Error> { self.inner.chain_height() }
    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error> { self.inner.get_block_hash(block_height) }
    fn block_metadata(&self, height: BlockHeight) -> Result<Option<BlockMetadata>, Self::Error> { self.inner.block_metadata(height) }
    fn block_fully_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> { self.inner.block_fully_scanned() }
    fn get_max_height_hash(&self) -> Result<Option<(BlockHeight, BlockHash)>, Self::Error> { self.inner.get_max_height_hash() }
    fn block_max_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> { self.inner.block_max_scanned() }
    fn suggest_scan_ranges(&self) -> Result<Vec<ScanRange>, Self::Error> { self.inner.suggest_scan_ranges() }
    fn get_target_and_anchor_heights(&self, min_confirmations: NonZeroU32) -> Result<Option<(TargetHeight, BlockHeight)>, Self::Error> { self.inner.get_target_and_anchor_heights(min_confirmations) }
    fn get_tx_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error> { self.inner.get_tx_height(txid) }
    fn get_unified_full_viewing_keys(&self) -> Result<HashMap<Self::AccountId, UnifiedFullViewingKey>, Self::Error> { self.inner.get_unified_full_viewing_keys() }
    fn get_memo(&self, note_id: NoteId) -> Result<Option<Memo>, Self::Error> { self.inner.get_memo(note_id) }
    fn get_transaction(&self, txid: TxId) -> Result<Option<Transaction>, Self::Error> { self.inner.get_transaction(txid) }
    fn get_sapling_nullifiers(&self, query: NullifierQuery) -> Result<Vec<(Self::AccountId, sapling::Nullifier)>, Self::Error> { self.inner.get_sapling_nullifiers(query) }
    fn get_orchard_nullifiers(&self, query: NullifierQuery) -> Result<Vec<(Self::AccountId, orchard::note::Nullifier)>, Self::Error> { self.inner.get_orchard_nullifiers(query) }
    fn get_transparent_receivers(&self, account: Self::AccountId, include_change: bool, include_standalone: bool) -> Result<HashMap<TransparentAddress, TransparentAddressMetadata>, Self::Error> { self.inner.get_transparent_receivers(account, include_change, include_standalone) }
    fn get_ephemeral_transparent_receivers(&self, account: Self::AccountId, exposure_depth: u32, exclude_used: bool) -> Result<HashMap<TransparentAddress, TransparentAddressMetadata>, Self::Error> { self.inner.get_ephemeral_transparent_receivers(account, exposure_depth, exclude_used) }
    fn get_transparent_balances(&self, account: Self::AccountId, target_height: TargetHeight, confirmations_policy: ConfirmationsPolicy) -> Result<TransparentBalances, Self::Error> { self.inner.get_transparent_balances(account, target_height, confirmations_policy) }
    fn get_transparent_address_metadata(&self, account: Self::AccountId, address: &TransparentAddress) -> Result<Option<TransparentAddressMetadata>, Self::Error> { self.inner.get_transparent_address_metadata(account, address) }
    fn utxo_query_height(&self, account: Self::AccountId) -> Result<BlockHeight, Self::Error> { self.inner.utxo_query_height(account) }
    fn transaction_data_requests(&self) -> Result<Vec<TransactionDataRequest>, Self::Error> { self.inner.transaction_data_requests() }
    fn get_received_outputs(&self, txid: TxId, target_height: TargetHeight, confirmations_policy: ConfirmationsPolicy) -> Result<Vec<ReceivedTransactionOutput>, Self::Error> { self.inner.get_received_outputs(txid, target_height, confirmations_policy) }
}

impl WalletWrite for SparseFacade<'_> {
    type UtxoRef = <Db as WalletWrite>::UtxoRef;

    fn create_account(&mut self, account_name: &str, seed: &SecretVec<u8>, birthday: &AccountBirthday, key_source: Option<&str>) -> Result<(Self::AccountId, UnifiedSpendingKey), Self::Error> { self.inner.create_account(account_name, seed, birthday, key_source) }
    fn import_account_hd(&mut self, account_name: &str, seed: &SecretVec<u8>, account_index: zip32::AccountId, birthday: &AccountBirthday, key_source: Option<&str>) -> Result<(Self::Account, UnifiedSpendingKey), Self::Error> { self.inner.import_account_hd(account_name, seed, account_index, birthday, key_source) }
    fn import_account_ufvk(&mut self, account_name: &str, unified_key: &UnifiedFullViewingKey, birthday: &AccountBirthday, purpose: AccountPurpose, key_source: Option<&str>) -> Result<Self::Account, Self::Error> { self.inner.import_account_ufvk(account_name, unified_key, birthday, purpose, key_source) }
    fn delete_account(&mut self, account: Self::AccountId) -> Result<(), Self::Error> { self.inner.delete_account(account) }
    fn get_next_available_address(&mut self, account: Self::AccountId, request: UnifiedAddressRequest) -> Result<Option<(UnifiedAddress, DiversifierIndex)>, Self::Error> { self.inner.get_next_available_address(account, request) }
    fn get_address_for_index(&mut self, account: Self::AccountId, diversifier_index: DiversifierIndex, request: UnifiedAddressRequest) -> Result<Option<UnifiedAddress>, Self::Error> { self.inner.get_address_for_index(account, diversifier_index, request) }
    fn update_chain_tip(&mut self, tip_height: BlockHeight) -> Result<(), Self::Error> { WalletWrite::update_chain_tip(self.inner, tip_height) }

    // THE INTERCEPT.
    fn put_blocks(&mut self, from_state: &ChainState, blocks: Vec<ScannedBlock<Self::AccountId>>) -> Result<(), Self::Error> {
        sparse_put_blocks(self.inner, self.sparse, from_state, blocks)
    }

    fn put_received_transparent_utxo(&mut self, output: &WalletTransparentOutput) -> Result<Self::UtxoRef, Self::Error> { self.inner.put_received_transparent_utxo(output) }
    fn store_decrypted_tx(&mut self, received_tx: DecryptedTransaction<Transaction, Self::AccountId>) -> Result<(), Self::Error> { self.inner.store_decrypted_tx(received_tx) }
    fn set_tx_trust(&mut self, txid: TxId, trusted: bool) -> Result<(), Self::Error> { self.inner.set_tx_trust(txid, trusted) }
    fn store_transactions_to_be_sent(&mut self, transactions: &[SentTransaction<Self::AccountId>]) -> Result<(), Self::Error> { self.inner.store_transactions_to_be_sent(transactions) }
    fn truncate_to_height(&mut self, max_height: BlockHeight) -> Result<BlockHeight, Self::Error> { self.inner.truncate_to_height(max_height) }
    fn truncate_to_chain_state(&mut self, chain_state: ChainState) -> Result<(), Self::Error> { self.inner.truncate_to_chain_state(chain_state) }
    fn rewind_to_height(&mut self, max_height: BlockHeight) -> Result<BlockHeight, Self::Error> { self.inner.rewind_to_height(max_height) }
    fn reserve_next_n_ephemeral_addresses(&mut self, account_id: Self::AccountId, n: usize) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, Self::Error> { self.inner.reserve_next_n_ephemeral_addresses(account_id, n) }
    fn set_transaction_status(&mut self, txid: TxId, status: TransactionStatus) -> Result<(), Self::Error> { WalletWrite::set_transaction_status(self.inner, txid, status) }
    fn schedule_next_check(&mut self, address: &TransparentAddress, offset_seconds: u32) -> Result<Option<SystemTime>, Self::Error> { self.inner.schedule_next_check(address, offset_seconds) }
    fn mark_transparent_addresses_exposed(&mut self, exposures: &[(TransparentAddress, BlockHeight)]) -> Result<(), Self::Error> { self.inner.mark_transparent_addresses_exposed(exposures) }
    fn notify_address_checked(&mut self, request: TransactionsInvolvingAddress, as_of_height: BlockHeight) -> Result<(), Self::Error> { self.inner.notify_address_checked(request, as_of_height) }
}
```

**Binding notes:** (a) method LIST is authoritative from `zcash_client_backend-0.23.0/src/data_api.rs:1609-3400` — if rustc reports a missing/extra method (feature-gated drift), delegate it the same way and record the deviation; (b) `output.nf()` comes from the `ReceivedShieldedOutput` trait (ll.rs:618) — import it; (c) `Note::value()`/`Note::receiver()` — `value()` exists on `zcash_client_backend::wallet::Note` (used by upstream at ll/wallet.rs:1019); if the method differs, mirror ll/wallet.rs:1014-1040 verbatim; (d) `WalletSaplingSpend::nf()` accessor public (used by upstream `tx.sapling_spends().iter().map(|spend| spend.nf())`, ll/wallet.rs:318).

- [ ] **Step 7:** wire `pub mod persist;` in `lib.rs`. `scan.rs` — sparse branch in `scan_chunks` only (treestate twin lands T6.4). Add at fn top: `let mut sparse_state = crate::persist::SparseTreeState::default();`. Replace the `scan_result` block:

```rust
            let scan_result = tokio::task::block_in_place(|| {
                let source = MemBlockSource::new(&chunk);
                if config.sparse_persistence {
                    let mut facade = crate::persist::SparseFacade {
                        inner: session.db_mut(),
                        sparse: &mut sparse_state,
                    };
                    scan_cached_blocks(
                        &network,
                        &source,
                        &mut facade,
                        BlockHeight::from(from_height),
                        &from_state,
                        current_batch_len,
                    )
                } else {
                    scan_cached_blocks(
                        &network,
                        &source,
                        session.db_mut(),
                        BlockHeight::from(from_height),
                        &from_state,
                        current_batch_len,
                    )
                }
            });
```

(Both arms return `Result<ScanSummary, ChainError<SqliteClientError, Infallible>>` — they unify; `map_scan_error` continues to work on either.)
- [ ] **Step 8:** CLI — `Sync` gains `#[arg(long, default_value_t = false)] sparse: bool` → `cfg.sparse_persistence = sparse;` in `cmd_sync`; `cmd_oracle`'s `let _ = sparse;` placeholder becomes `cfg.sparse_persistence = sparse;`. CLI tests: `sync_parses_sparse_flag`.
- [ ] **Step 9:** CONVENTIONS.md — naming module list (line ~72) += `persist`, `oracle`.
- [ ] **Step 10:** verify: `cargo test -p slipstream-core -p slipstream-cli` green; `cargo clippy` both crates both feature sets clean; `cargo test -p slipstream-core --features darkside --no-run` compiles; **`swift test --filter OfflineTests`** (root Cargo.toml touched; expect 458/0; SPM landmine fix in CONVENTIONS if LocalPackages error).
- [ ] **Step 11 (THE MEASUREMENT + GATE):** pick a fresh ~50k mainnet range (current tip − 50_000 as birthday). Run back-to-back:

```bash
cargo run -p slipstream-cli --release -- sync --server https://zec.rocks:443 \
  --wallet-dir /tmp/p6-off --ufvk <TEST_UFVK from wallet_session.rs:178> --birthday <tip-50000>
cargo run -p slipstream-cli --release -- sync --server https://zec.rocks:443 \
  --wallet-dir /tmp/p6-on --sparse --ufvk <same> --birthday <same>
```

Record from the `sync stage split` log lines: `scan_s` off vs on, plus per-chunk `sparse put_blocks` attribution (`rows_ms/tree_ms/flush_ms`). **Apply the GATE** (top of task). Record both outcomes + the decision in STATE.md truth table. Repeat once if server variance is suspect (G1 precedent).
- [ ] **Step 12:** STATE.md (T6.3 done + GATE verdict + truth-table rows + Decision-Log dep entry; NEXT → T6.4 on GO) + commit:

```bash
git add Cargo.toml Cargo.lock slipstream/ docs/slipstream/
git commit -m "[#1755] slipstream: T6.3 sparse persistence facade behind flag + A/B spike (GATE: <verdict>)"
```

---

### Task 6.4: Oracle-clean correctness pass

Make the sparse path semantically identical, with note coverage. Three oracles, increasing reality: hermetic synthetic (cargo test), darkside 2-tx fixture (real notes/spends through the full engine pipeline), mainnet 50k CLI run.

- [ ] **Step 1 (failing test first — hermetic sparse oracle):** extend `oracle::testkit::scan_synthetic` to honor `sparse: true` (construct `SparseTreeState` + `SparseFacade` around `session.db_mut()` exactly as scan.rs does; one `SparseTreeState` for the whole call). Then add to `oracle.rs` tests:

```rust
    /// T6.4 hermetic golden oracle: same synthetic blocks, upstream vs sparse
    /// persistence → semantically identical databases. Covers blocks rows,
    /// tx_locator/nullifier_map, tree shards, checkpoints (incl. pruning),
    /// scan_queue. (Note rows are covered by the darkside oracle — synthetic
    /// ciphertexts decrypt to nothing.)
    #[test]
    fn sparse_path_matches_upstream_on_synthetic_chain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let da = dir.path().join("wa");
        let db = dir.path().join("wb");
        std::fs::create_dir_all(&da).unwrap();
        std::fs::create_dir_all(&db).unwrap();
        // 250 blocks * 5 outputs = 1250 commitments, scanned in 50-block calls →
        // exercises multi-chunk seeding, frontier re-insertion and checkpoint
        // pruning (250 checkpoints > MAX_CHECKPOINTS=100).
        let blocks = super::testkit::synth_blocks(250, 5);
        super::testkit::scan_synthetic(&da, blocks.clone(), 50, false).expect("upstream");
        super::testkit::scan_synthetic(&db, blocks, 50, true).expect("sparse");
        let report = semantic_diff(&da.join("data.db"), &db.join("data.db")).expect("diff");
        assert!(report.is_clean(), "sparse vs upstream diverged:\n{}", report.render());
    }
```

Run → expect failure or divergence initially; iterate on `persist.rs` until clean. **Likely first divergences and their fixes** (work the list in order): (1) shard-blob byte differences from `Marking::Reference` annotation handling at the frontier — verify `insert_frontier` is called with identical retention both paths; (2) checkpoint rows for heights pruned in memory but flushed earlier in a prior chunk — the `checkpoint_delta` remove set must cover them (it does — db_checkpoints mirror updated per flush); (3) `subtree_end_height` column of `{pool}_tree_shards` — written ONLY by `put_shard_roots` (commitment_tree.rs:1004+, from server subtree roots), not by scanning; both paths call `put_subtree_roots` identically via the engine — for the hermetic test neither path calls it, so the column stays NULL in both. Record each divergence found + fix in STATE session notes.
- [ ] **Step 2 (darkside pipeline branch):** `scan_chunks_from_treestate` gains a `sparse: bool` parameter (same facade branch around its `scan_cached_blocks` call; one `SparseTreeState` per call). Update existing darkside call sites with `false`.
- [ ] **Step 3 (darkside oracle test — real notes):** create `slipstream/core/tests/darkside_oracle.rs` (feature `darkside`, `#[ignore]`): reuse `darkside_sync.rs`'s constants + staging flow (stage `TX_MAINNET_BLOCK_URL` chain + the two tx fixtures at 663174/663188, apply at 663188+) to run the direct pipeline TWICE into two temp wallets — run A `sparse=false`, run B `sparse=true` (same staged server state; reset darkside between runs and re-stage identically — mirror `sync_finds_fixture_transactions` setup verbatim), then:

```rust
    let report = slipstream_core::oracle::semantic_diff(&wallet_a_db, &wallet_b_db).expect("diff");
    assert!(report.is_clean(), "darkside oracle diverged:\n{}", report.render());
    // Belt-and-braces: the B wallet still finds the fixture txs/balance.
    // (reuse the EXPECTED_TX_COUNT=2 / EXPECTED_BALANCE_ZATOSHI=200_000 asserts)
```

This covers: `transactions`, `sapling_received_notes` (positions, nf, spent linkage), `sent_notes` (WalletInternal arm if fixture has change — receive-only fixtures may not exercise it; note coverage gap in STATE if so), `tx_retrieval_queue`, scan_queue FoundNote extensions.
- [ ] **Step 4 (mainnet oracle):** `cargo run -p slipstream-cli --release -- oracle --server https://zec.rocks:443 --wallet-a /tmp/oa --wallet-b /tmp/ob --sparse-b --ufvk <TEST_UFVK> --birthday <tip-50000>` → `VERDICT IDENTICAL` (rerun on tip-skew exit 3). Record in STATE.
- [ ] **Step 5:** full verify: hermetic suites + clippy (both feature sets) + darkside serial suite (`cargo test -p slipstream-core --features darkside -- --ignored --test-threads=1` with local lightwalletd; all pre-existing 6 + new oracle test green).
- [ ] **Step 6:** STATE.md (T6.4 done; oracle verdicts ×3; divergence log; NEXT → T6.5) + commit:

```bash
git add slipstream/ docs/slipstream/STATE.md
git commit -m "[#1755] slipstream: T6.4 sparse persistence oracle-clean (hermetic + darkside + mainnet verdicts)"
```

---

### Task 6.5: Reorg + truncate compatibility

The gate: `reorg_recovery_produces_correct_tip` UNCHANGED stays green, and a sparse-mode variant passes; truncate+rescan leaves an oracle-clean DB.

**The argument (record verbatim in STATE):** checkpoint cadence is inherited, not redesigned — `scan_block` emits per-block `Retention::Checkpoint` markers (scanning/compact.rs:672-810); our in-memory ShardTree ingests them through upstream's own `insert_tree`/`prune_excess_checkpoints` (max 100, = PRUNING_DEPTH); the flush materializes the surviving checkpoints into the same `{pool}_tree_checkpoints` tables. `truncate_to_height` → `select_truncation_height` (wallet.rs:3639-3668) therefore finds the same MAX(height ≤ requested ∧ in blocks ∧ in checkpoints) and `ScanContinuity{at}` arithmetic (`rewind = at.saturating_sub(10)`, scheduler.rs:209) is untouched. SparseTreeState is per-range (created in scan_chunks, dropped on return) so a truncate between ranges can never observe stale in-memory tree state; within a range, an error abandons the un-flushed delta — the DB remains exactly at the last committed chunk, which is the same crash/abort contract as upstream's per-call `transactionally`.

- [ ] **Step 1:** run the UNCHANGED gate first: darkside serial suite → `reorg_recovery_produces_correct_tip` green (flag defaults off everywhere; this proves no regression from P6 code in default mode).
- [ ] **Step 2 (sparse reorg variant):** in `tests/darkside_reorg.rs`, refactor the scan-pipeline helper (`direct_pipeline_scan`, line 166) to take `sparse: bool` and pass it to `scan_chunks_from_treestate`; the existing test calls it with `false` (zero behavior change — diff must show the existing test body otherwise untouched). Add `#[ignore]` test `reorg_recovery_produces_correct_tip_sparse`: identical flow with `sparse=true` — assert the SAME `ScanContinuity { at: 663201 }`, the SAME truncate-to-663191 recovery, the SAME final tip 663202.
- [ ] **Step 3 (truncate+rescan oracle):** extend the darkside oracle test (or a new `#[ignore]` test in `darkside_oracle.rs`): after the initial sparse sync, `session.db_mut().truncate_to_height(<height 20 below tip>)` then re-scan the gap with `sparse=true`; do the same on the upstream-path wallet; `semantic_diff` → clean. This proves flush-then-truncate-then-reflush converges.
- [ ] **Step 4:** verify: darkside serial suite (now 8+ tests) green; hermetic suites + clippy clean.
- [ ] **Step 5:** STATE.md (T6.5 done; argument recorded; NEXT → T6.6) + commit:

```bash
git add slipstream/ docs/slipstream/STATE.md
git commit -m "[#1755] slipstream: T6.5 reorg + truncate compatibility for sparse persistence (darkside green)"
```

---

### Task 6.6: Default-ON + device gate prep

- [ ] **Step 1:** flip `sparse_persistence` default to `true` in `EngineConfig::new` (doc-comment: oracle-clean as of T6.4/T6.5; flag retained as a kill switch). CLI `--sparse` becomes `#[arg(long, default_value_t = true, action = clap::ArgAction::Set)]` (overridable `--sparse false`). Update `defaults_are_valid` + CLI parse tests. FFI inherits via `EngineConfig::new` (rust/src/lib.rs:4409) — **no FFI signature change, but the XCFramework must be rebuilt for device runs** (three-layer gotcha, CONVENTIONS).
- [ ] **Step 2:** stage-split honesty: `engine.rs` `sync stage split` log gains `sparse = config.sparse_persistence`; per-chunk `sparse put_blocks` attribution log (rows_ms/tree_ms/flush_ms — already landed in T6.3 Step 5) verified present in release builds (info level).
- [ ] **Step 3:** Mac regression row: re-run the T6.3 Step 11 A/B (now default-on vs `--sparse false`) on a fresh ~50k range; record truth-table rows.
- [ ] **Step 4:** full gates: `cargo test -p slipstream-core -p slipstream-cli`; clippy both feature sets; darkside serial suite; `./Scripts/init-local-ffi.sh` (full 3-slice — device runs ahead; mind the single-slice landmine); `swift test --filter OfflineTests` (Rust changed under the FFI → rebuild + test).
- [ ] **Step 5:** STATE.md: T6.6 done; **expected-numbers table (bets, not promises)** + [needs-user] device protocol:

| Device | Today (scan_s) | Decrypt floor (kept kernel) | Persist after P6 (bet) | Total bet | Goal |
|---|---|---|---|---|---|
| iPhone 16 Pro, 269k blk | ~195 s | ~6–10 s | ~15–60 s (Mac ratio × device I/O factor) | **~30–80 s** | <73 s |
| iPad A10, 269k blk | ~1007 s | ~30–50 s | ~80–350 s | **~150–450 s** | <533 s |
| MacBook, 50k blk | ~30 s | ~1–2 s | ~5–15 s | ~8–20 s | (tracking) |

[needs-user]: full rebuild (init-local-ffi.sh all slices + Zodl Reset Package Caches) then the same 269k-block restore on both devices, flag on vs off; STATE truth-table rows + G6 verdict against the 73 s / 533 s goal lines. ROADMAP P6/G6 row updated with MEASURED numbers.
- [ ] **Step 6:** commit:

```bash
git add slipstream/ docs/slipstream/ Cargo.lock
git commit -m "[#1755] slipstream: T6.6 sparse persistence default-on + stage attribution + device gate prep"
```

---

## Phase exit criteria

1. T6.1 interleave shipped: transactions surface every ≤K chunks; stage-split still honest; skip-log warns once per address per sync.
2. Oracle harness exists and is trusted: detects injected row/multiplicity/table deltas; upstream determinism baseline clean (allowlist empirically justified, Decision-Logged).
3. GO/NO-GO recorded with numbers. (NO-GO path: phase stops at T6.3 with findings + decrypt-kernel fallback recorded — that is a VALID phase exit.)
4. On GO: hermetic + darkside + mainnet oracles all `VERDICT IDENTICAL`; `reorg_recovery_produces_correct_tip` green unchanged AND in sparse mode; truncate+rescan oracle clean.
5. Default-on with kill switch; Mac truth-table rows recorded; device expected-numbers table + [needs-user] protocol in STATE; ROADMAP G6 row updated.
6. All along: `cargo test -p slipstream-core -p slipstream-cli` + clippy (both feature sets) green per commit; OfflineTests at FFI/root-manifest-touching commits and at phase close.
