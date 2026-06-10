# Phase 2 — Scan Core: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (or executing-plans). Checkboxes are execution aids — STATE.md is the completion record.
> Before ANY task: read `docs/slipstream/STATE.md` + `docs/slipstream/CONVENTIONS.md`. LOCAL-ONLY: never push, never create remote issues/PRs.

**Goal:** Blocks flowing through the P1 transport get **scanned into a real `zcash_client_sqlite` wallet DB** ("upstream brain, Slipstream body" — decision D2): persistent wallet session (open once, WAL), in-memory `BlockSource`, chunked `scan_cached_blocks`, scheduler v0 over the existing scan-queue, full fetch∥scan pipeline, and a CLI `sync` that proves correctness on darkside fixtures and measures **gate G2: ≥5× the old SDK's wall-clock** on the same machine/server/range.

**Architecture:** New `slipstream-core` modules: `block_source` (MemBlockSource over one chunk), `wallet_session` (WalletDb open-once + WAL + subtree roots + chain tip + account import), `scan` (per-chunk `scan_cached_blocks` with treestate prefetch pipelined behind scanning), `scheduler` (v0: suggested-ranges loop), `engine` (sync_once orchestration). CLI gains `sync`. Scans are serial per-chunk (SQLite single writer; rayon parallelism lives INSIDE upstream's trial decryption); fetch runs concurrently ahead through the P1 chunk queue.

## Verified code-reality facts (2026-06-10 — re-verify only if a build error contradicts them)

- `scan_cached_blocks(&network, &block_source, &mut wallet_db, from_height: BlockHeight, &from_state: &ChainState, limit: usize) -> Result<ScanSummary, _>` — exact call shape at `rust/src/lib.rs:1773-1780`. It asserts `from_height == from_state.block_height + 1` and commits ALL scanned blocks in ONE transaction at the end → **per-call unit stays one chunk (~10k blocks)** to bound memory; whole-range single-call is intentionally NOT used.
- `BlockSource` trait (`zcash_client_backend::data_api::chain`, registry 0.22 src line 216): `fn with_blocks<F, WalletErrT>(&self, from_height: Option<BlockHeight>, limit: Option<usize>, with_block: F) -> Result<(), error::Error<WalletErrT, Self::Error>> where F: FnMut(CompactBlock) -> Result<(), error::Error<WalletErrT, Self::Error>>`.
- `WalletDb::for_path(path, network, SystemClock, OsRng) -> WalletDb<rusqlite::Connection, Network, SystemClock, OsRng>` (`rust/src/lib.rs:128-139`); migrations via `init_wallet_db(&mut db, seed: Option<SecretVec<u8>>)` (`lib.rs:308`). Mirror lib.rs imports for `SystemClock`/`OsRng` paths.
- `TreeState::decode(bytes)?.to_chain_state()? -> ChainState` (`lib.rs:1768-1771`). Our grpc `get_tree_state` already returns the decoded `TreeState` proto — call `.to_chain_state()` directly.
- Account import (keyless): `db.import_account_ufvk(account_name, &ufvk, &birthday, purpose, key_source)` (`lib.rs:599`); `AccountBirthday::from_treestate(treestate, recover_until)` (`lib.rs:557`); UFVK decode + `AccountPurpose` variant: mirror `rust/src/lib.rs:524-600` exactly.
- Wallet ops: `db.update_chain_tip(height)` (`lib.rs:1543`), `db.suggest_scan_ranges()` (`lib.rs:1695`), `db.put_sapling_subtree_roots(start_index, &roots)` / `put_orchard_subtree_roots` (`lib.rs:1454/1507`); subtree-root collection pattern (streaming + `CommitmentTreeRoot::from_parts(BlockHeight::from_u32(r.completing_block_height as u32), sapling::Node::read(&r.root_hash[..])?)`, orchard via `orchard::tree::MerkleHashOrchard::read`) is verbatim in registry `zcash_client_backend-0.22.0/src/sync.rs:222-260`.
- **WAL trick:** `journal_mode=WAL` is a persistent property of the DB FILE — set it with a plain `rusqlite::Connection` BEFORE constructing `WalletDb` (WalletDb doesn't expose its connection).
- **ChainState threading (T2.3 spike PRE-RESOLVED):** option (b) (derive locally) is not free — `ChainState` carries final Sapling/Orchard frontiers, which `WalletDb` does not expose publicly. **Baseline (a) stands:** one `get_tree_state` RPC per chunk boundary (~100 per 1M blocks), PREFETCHED concurrently while the previous chunk scans → zero added latency. Record this as the spike outcome in STATE.md (Decision Log) when T2.4 lands.
- Darkside fixtures with REAL transactions for a known seed exist and are already canonical in this repo: dataset URLs in `Tests/TestUtils/DarkSideWalletService.swift:13-28` (e.g. `basic-reorg/before-reorg.txt`), `saplingActivation: 663150` (`Tests/TestUtils/FakeChainBuilder.swift:28`), seed + expected tx constants greppable in `Tests/TestUtils/` + `Tests/DarksideTests/DarksideSanityCheckTests.swift`. T2.7 reuses them; staging via the existing `StageBlocks(url)` darkside RPC (add tiny `stage_blocks_url` method to DarksideCtl).
- Old-SDK baseline harness candidate: `Tests/PerformanceTests/SynchronizerTests.swift` (network target, not in CI) — T2.7 includes a read-first spike step before choosing the baseline procedure.
- P1 carry-overs to land here (from STATE.md NEXT ACTION): `grpc::get_subtree_roots` wrapper (T2.1); `FetchPlan` start≤end validation (T2.1); CLI polish: reject `--streams 0`, hint `A..B` vs `A..=B` (T2.1).

**New workspace dependencies** (T2.1, append to `[workspace.dependencies]`, mirroring root versions/features EXACTLY):

```toml
zcash_client_sqlite = { version = "0.21", features = ["orchard", "transparent-inputs", "unstable", "serde"] }
zcash_keys = { version = "0.14", features = ["orchard"] }
rusqlite = "0.37"
secrecy = "0.8"
rand = "0.8"
sapling = { package = "sapling-crypto", version = "0.7", default-features = false }
orchard = { version = "0.14", features = ["unstable-voting-circuits"] }
tempfile = "3"          # dev-only usage; listed here for version unity
```

**File structure:**

```
Cargo.toml                              # MODIFY: workspace.dependencies additions above
slipstream/core/
  Cargo.toml                            # MODIFY: new deps (workspace = true); [dev-dependencies] tempfile
  src/lib.rs                            # MODIFY: wire block_source, wallet_session, scan, scheduler, engine
  src/grpc.rs                           # MODIFY: + get_subtree_roots (T2.1)
  src/fetch.rs                          # MODIFY: FetchPlan validation (T2.1)
  src/block_source.rs                   # CREATE (T2.2)
  src/wallet_session.rs                 # CREATE (T2.3)
  src/scan.rs                           # CREATE (T2.4)
  src/scheduler.rs                      # CREATE (T2.5)
  src/engine.rs                         # CREATE (T2.6)
  src/darkside.rs                       # MODIFY: + stage_blocks_url (T2.7)
  tests/darkside_sync.rs                # CREATE (T2.7)
slipstream/cli/src/main.rs              # MODIFY: CLI polish (T2.1); `sync` subcommand (T2.6)
docs/slipstream/STATE.md                # MODIFY per task
```

---

### Task 2.1: P1 carry-overs + `get_subtree_roots` + new workspace deps

**Files:** root `Cargo.toml`, `slipstream/core/Cargo.toml`, `slipstream/core/src/grpc.rs`, `slipstream/core/src/fetch.rs`, `slipstream/cli/src/main.rs`.

- [ ] **Step 1:** Append the new `[workspace.dependencies]` entries (table above) to root `Cargo.toml`. Add to `slipstream/core/Cargo.toml` `[dependencies]`: `zcash_client_sqlite = { workspace = true }`, `zcash_keys = { workspace = true }`, `rusqlite = { workspace = true }`, `secrecy = { workspace = true }`, `rand = { workspace = true }`, `sapling = { workspace = true }`, `orchard = { workspace = true }`; and a new section:
```toml
[dev-dependencies]
tempfile = { workspace = true }
```

- [ ] **Step 2:** `grpc.rs` — add the subtree-roots wrapper (after `get_tree_state`):

```rust
use zcash_client_backend::{
    data_api::chain::CommitmentTreeRoot,
    proto::service::{GetSubtreeRootsArg, ShieldedProtocol},
};
use futures_util::TryStreamExt;

/// Collected subtree roots for both pools (Sapling first, Orchard second).
pub struct SubtreeRoots {
    pub sapling: Vec<CommitmentTreeRoot<sapling::Node>>,
    pub orchard: Vec<CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>>,
}

pub async fn get_subtree_roots(client: &mut LwdClient) -> Result<SubtreeRoots, SlipstreamError> {
    let mut req = GetSubtreeRootsArg::default();
    req.set_shielded_protocol(ShieldedProtocol::Sapling);
    let sapling = client
        .get_subtree_roots(req)
        .await
        .map_err(|e| transport_err("get_subtree_roots(sapling)", e))?
        .into_inner()
        .map_err(|e| SlipstreamError::Transport(format!("subtree root stream: {e}")))
        .and_then(|r| async move {
            let node = sapling::Node::read(&r.root_hash[..])
                .map_err(|e| SlipstreamError::Transport(format!("sapling root: {e}")))?;
            Ok(CommitmentTreeRoot::from_parts(
                zcash_protocol::consensus::BlockHeight::from_u32(r.completing_block_height as u32),
                node,
            ))
        })
        .try_collect()
        .await?;

    let mut req = GetSubtreeRootsArg::default();
    req.set_shielded_protocol(ShieldedProtocol::Orchard);
    let orchard = client
        .get_subtree_roots(req)
        .await
        .map_err(|e| transport_err("get_subtree_roots(orchard)", e))?
        .into_inner()
        .map_err(|e| SlipstreamError::Transport(format!("subtree root stream: {e}")))
        .and_then(|r| async move {
            let node = orchard::tree::MerkleHashOrchard::read(&r.root_hash[..])
                .map_err(|e| SlipstreamError::Transport(format!("orchard root: {e}")))?;
            Ok(CommitmentTreeRoot::from_parts(
                zcash_protocol::consensus::BlockHeight::from_u32(r.completing_block_height as u32),
                node,
            ))
        })
        .try_collect()
        .await?;

    Ok(SubtreeRoots { sapling, orchard })
}
```
(If `set_shielded_protocol`/field names differ, mirror registry `zcash_client_backend-0.22.0/src/sync.rs:222-260` verbatim and record the deviation. `max_entries`/`start_index` default to 0 = all.)

- [ ] **Step 3:** `fetch.rs` — `FetchPlan::new` returns a validated plan:

```rust
    /// `start <= end` is required; violations are a caller bug.
    pub fn new(start: u64, end: u64, chunk_blocks: u32, streams: usize) -> Self {
        assert!(start <= end, "FetchPlan: start {start} > end {end}");
        assert!(chunk_blocks > 0, "FetchPlan: chunk_blocks must be > 0");
        Self {
```
(Keep the rest of the body; an `assert!` is correct here — the scheduler constructs plans from validated ranges, and a wrapping `chunk_count` would OOM. Add test `#[should_panic] fn plan_rejects_inverted_range()`.)

- [ ] **Step 4:** CLI polish in `main.rs`: `--streams` arg gains `value_parser = clap::value_parser!(usize).range(1..)`; `parse_range` error message becomes `format!("range must be start..end (not ..=): {s}")` when the input contains `..=`, plus a test `parse_range_rejects_inclusive_syntax`.
- [ ] **Step 5:** `cargo test -p slipstream-core -p slipstream-cli` → previous suite + new tests green (first build compiles zcash_client_sqlite — minutes, cold). `cargo check` (root) green. Root Cargo.toml changed → run `swift test --filter OfflineTests` (expect 419/0; remember the SPM landmine fix in CONVENTIONS if it fails on LocalPackages).
- [ ] **Step 6:** STATE.md (T2.1 done; NEXT → T2.2) + commit:
```bash
git add Cargo.toml Cargo.lock slipstream/ docs/slipstream/STATE.md
git commit -m "[#1755] slipstream: P2 deps, get_subtree_roots, FetchPlan validation, CLI polish"
```

---

### Task 2.2: `block_source` — MemBlockSource over one chunk

**Files:** Create `slipstream/core/src/block_source.rs`; modify lib.rs.

- [ ] **Step 1:** Create the module:

```rust
//! In-memory BlockSource adapter: serves exactly one transport Chunk to
//! upstream `scan_cached_blocks`. One chunk per scan call keeps the upstream
//! commit (one txn per call) and our memory bounded (decision D2 + plan facts).

use zcash_client_backend::{
    data_api::chain::{BlockSource, error::Error as ChainError},
    proto::compact_formats::CompactBlock,
};
use zcash_protocol::consensus::BlockHeight;

use crate::chunk::Chunk;

/// Never constructed; `MemBlockSource` itself cannot fail.
#[derive(Debug)]
pub struct Unreachable;

impl std::fmt::Display for Unreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unreachable")
    }
}
impl std::error::Error for Unreachable {}

pub struct MemBlockSource<'a> {
    chunk: &'a Chunk,
}

impl<'a> MemBlockSource<'a> {
    pub fn new(chunk: &'a Chunk) -> Self {
        Self { chunk }
    }
}

impl BlockSource for MemBlockSource<'_> {
    type Error = Unreachable;

    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), ChainError<WalletErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), ChainError<WalletErrT, Self::Error>>,
    {
        let from = from_height.map(u64::from).unwrap_or(0);
        let mut served = 0usize;
        for b in &self.chunk.blocks {
            if b.height < from {
                continue;
            }
            if let Some(l) = limit
                && served >= l
            {
                break;
            }
            with_block(b.clone())?;
            served += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::Chunk;

    fn block(height: u64) -> CompactBlock {
        CompactBlock { height, hash: vec![height as u8; 32], ..Default::default() }
    }

    fn collect(src: &MemBlockSource<'_>, from: Option<u64>, limit: Option<usize>) -> Vec<u64> {
        let mut out = Vec::new();
        src.with_blocks::<_, Unreachable>(
            from.map(BlockHeight::from_u32_unchecked_or_panic_helper),
            limit,
            |b| {
                out.push(b.height);
                Ok(())
            },
        )
        .expect("infallible");
        out
    }

    // NOTE: BlockHeight::from(u32) exists; the helper above is pseudocode —
    // implement as `from.map(|h| BlockHeight::from(h as u32))` and delete this note.

    #[test]
    fn serves_all_blocks_in_order() {
        let chunk = Chunk::from_blocks(0, (100..=109).map(block).collect());
        let src = MemBlockSource::new(&chunk);
        assert_eq!(collect(&src, None, None), (100..=109).collect::<Vec<_>>());
    }

    #[test]
    fn respects_from_height_and_limit() {
        let chunk = Chunk::from_blocks(0, (100..=109).map(block).collect());
        let src = MemBlockSource::new(&chunk);
        assert_eq!(collect(&src, Some(105), Some(3)), vec![105, 106, 107]);
    }

    #[test]
    fn from_height_past_end_serves_nothing() {
        let chunk = Chunk::from_blocks(0, (100..=109).map(block).collect());
        let src = MemBlockSource::new(&chunk);
        assert!(collect(&src, Some(200), None).is_empty());
    }
}
```
IMPLEMENTATION NOTE (not a placeholder — a binding instruction): the test helper's `BlockHeight` construction must be `BlockHeight::from(h as u32)`; clean up the pseudocode note in the final code. The generic-error usage `with_blocks::<_, Unreachable>` may need the wallet error type spelled differently — if inference fails, use a unit struct test error; mirror how `FsBlockDb`'s impl tests do it (registry `zcash_client_sqlite-0.20.2/src/chain.rs`).

- [ ] **Step 2:** Wire `pub mod block_source;` in lib.rs. `cargo test -p slipstream-core` → previous + 3 new green.
- [ ] **Step 3:** STATE.md (T2.2 done; NEXT → T2.3) + commit `[#1755] slipstream: MemBlockSource adapter over transport chunks`.

---

### Task 2.3: `wallet_session` — open-once WalletDb, WAL, account import, chain ops

**Files:** Create `slipstream/core/src/wallet_session.rs`; modify lib.rs.

- [ ] **Step 1:** Create the module. Mirror ALL type/constructor details from `rust/src/lib.rs` (imports for `SystemClock`, `OsRng`, `AccountBirthday`, `AccountPurpose`, `UnifiedFullViewingKey`; the `import_account_ufvk` call at lib.rs:599; `init_wallet_db` at lib.rs:308):

```rust
//! Persistent wallet session: ONE WalletDb for the whole sync (decision D2/D3 —
//! unchanged zcash_client_sqlite data model), WAL set on the file before open,
//! migrations run once, chain-state ops (subtree roots, chain tip, scan ranges)
//! and keyless account import (UFVK only, decision D6).

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use tracing::info;
use zcash_client_backend::data_api::{
    AccountBirthday, AccountPurpose, WalletRead, WalletWrite,
    chain::CommitmentTreeRoot, scanning::ScanRange,
};
use zcash_client_backend::proto::service::TreeState;
use zcash_client_sqlite::WalletDb;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::{BlockHeight, Network};

use crate::{error::SlipstreamError, grpc::SubtreeRoots};

// Mirror rust/src/lib.rs:132 — same generics, same clock/rng.
type Db = WalletDb<Connection, Network, zcash_client_sqlite::util::SystemClock, rand::rngs::OsRng>;

pub struct WalletSession {
    pub network: Network,
    db: Db,
}

fn wallet_err(context: &str, e: impl std::fmt::Display) -> SlipstreamError {
    SlipstreamError::Wallet(format!("{context}: {e}"))
}

impl WalletSession {
    /// Sets WAL (a persistent file property) via a plain connection, then opens
    /// the WalletDb ONCE and runs migrations (seedless — keyless engine).
    pub fn open(network: Network, db_path: &Path) -> Result<Self, SlipstreamError> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| wallet_err("create wallet dir", e))?;
        }
        {
            let conn = Connection::open(db_path).map_err(|e| wallet_err("pre-open", e))?;
            let mode: String = conn
                .pragma_update_and_check(None, "journal_mode", "wal", |row| row.get(0))
                .map_err(|e| wallet_err("set WAL", e))?;
            info!(%mode, "journal mode");
            conn.pragma_update(None, "synchronous", "NORMAL")
                .map_err(|e| wallet_err("set synchronous", e))?;
        }
        let mut db = WalletDb::for_path(db_path, network, zcash_client_sqlite::util::SystemClock, rand::rngs::OsRng)
            .map_err(|e| wallet_err("open wallet db", e))?;
        zcash_client_sqlite::wallet::init::init_wallet_db(&mut db, None)
            .map_err(|e| wallet_err("init/migrations", e))?;
        Ok(Self { network, db })
    }

    /// Keyless import: UFVK string + birthday treestate (server-provided at
    /// birthday-1). No-op if any account already exists.
    pub fn ensure_account(
        &mut self,
        ufvk_str: &str,
        birthday_treestate: TreeState,
    ) -> Result<(), SlipstreamError> {
        let existing = self
            .db
            .get_account_ids()
            .map_err(|e| wallet_err("get_account_ids", e))?;
        if !existing.is_empty() {
            return Ok(());
        }
        let ufvk = UnifiedFullViewingKey::decode(&self.network, ufvk_str)
            .map_err(|e| wallet_err("ufvk decode", e))?;
        let birthday = AccountBirthday::from_treestate(birthday_treestate, None)
            .map_err(|_| SlipstreamError::Wallet("invalid birthday treestate".into()))?;
        self.db
            .import_account_ufvk("slipstream", &ufvk, &birthday, AccountPurpose::ViewOnly, None)
            .map_err(|e| wallet_err("import_account_ufvk", e))?;
        info!("account imported (view-only)");
        Ok(())
    }

    pub fn put_subtree_roots(&mut self, roots: &SubtreeRoots) -> Result<(), SlipstreamError> {
        self.db
            .put_sapling_subtree_roots(0, &roots.sapling)
            .map_err(|e| wallet_err("put_sapling_subtree_roots", e))?;
        self.db
            .put_orchard_subtree_roots(0, &roots.orchard)
            .map_err(|e| wallet_err("put_orchard_subtree_roots", e))?;
        Ok(())
    }

    pub fn update_chain_tip(&mut self, height: u64) -> Result<(), SlipstreamError> {
        self.db
            .update_chain_tip(BlockHeight::from(height as u32))
            .map_err(|e| wallet_err("update_chain_tip", e))
    }

    pub fn suggest_scan_ranges(&self) -> Result<Vec<ScanRange>, SlipstreamError> {
        self.db
            .suggest_scan_ranges()
            .map_err(|e| wallet_err("suggest_scan_ranges", e))
    }

    /// Exclusive access for the scan driver (scan_cached_blocks needs &mut).
    pub fn db_mut(&mut self) -> &mut Db {
        &mut self.db
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_sets_wal_and_initializes_schema() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("data.db");
        let _session = WalletSession::open(Network::MainNetwork, &path).expect("open");
        // WAL must persist on the file.
        let conn = Connection::open(&path).expect("reopen");
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .expect("pragma");
        assert_eq!(mode.to_lowercase(), "wal");
    }

    #[test]
    fn ensure_account_imports_once_with_empty_treestate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("data.db");
        let mut s = WalletSession::open(Network::MainNetwork, &path).expect("open");
        // Empty trees at a height = valid birthday treestate (hermetic).
        let ts = TreeState {
            height: 663_149,
            ..Default::default()
        };
        // A real mainnet UFVK is required for decode; use the one embedded in
        // this repo's test utils (grep Tests/TestUtils for "uview1"), or derive
        // once via zcash_keys in this test from the canonical darkside seed.
        // BINDING INSTRUCTION: locate the constant at implement time and inline
        // it here as `const TEST_UFVK: &str = "uview1...";`.
        let ufvk = TEST_UFVK;
        s.ensure_account(ufvk, ts.clone()).expect("first import");
        s.ensure_account(ufvk, ts).expect("idempotent");
        assert_eq!(s.suggest_scan_ranges().expect("ranges").is_empty(), false);
    }
}
```
IMPLEMENTATION NOTES (binding): (1) `pragma_update_and_check` signature — if it differs in rusqlite 0.37, use `query_row("PRAGMA journal_mode=wal", ...)`. (2) `import_account_ufvk` arg list mirrors `rust/src/lib.rs:599` — if `AccountPurpose::ViewOnly` carries fields or `key_source` typing differs, copy lib.rs's exact construction. (3) `TEST_UFVK`: grep `Tests/TestUtils` for a mainnet `uview1`/sapling extfvk constant; if none usable, derive in-test from the darkside seed via `zcash_keys` (test-only derivation does not violate D6). (4) The second test's final assert may need adjusting (a fresh wallet's range suggestions depend on birthday vs tip) — assert on `get_account_ids().len() == 1` instead if simpler.

- [ ] **Step 2:** Wire `pub mod wallet_session;`. `cargo test -p slipstream-core` → previous + 2 new green.
- [ ] **Step 3:** STATE.md (T2.3 done — include WHICH UFVK source was used; NEXT → T2.4) + commit `[#1755] slipstream: wallet session (WAL, migrations, keyless import, chain ops)`.

---

### Task 2.4: `scan` — per-chunk scan_cached_blocks with pipelined treestate prefetch

**Files:** Create `slipstream/core/src/scan.rs`; modify lib.rs.

- [ ] **Step 1:** Create the module:

```rust
//! Scan driver: consumes ordered chunks, runs upstream scan_cached_blocks once
//! per chunk (bounded memory: one commit per chunk), and hides the per-chunk
//! treestate RPC by prefetching the NEXT boundary state while the current
//! chunk scans (spike T2.3 outcome: ChainState must come from the server;
//! prefetch makes its latency invisible).

use tracing::{debug, info};
use zcash_client_backend::data_api::chain::scan_cached_blocks;
use zcash_protocol::consensus::BlockHeight;

use crate::{
    block_source::MemBlockSource,
    chunk::{Chunk, ChunkQueueReceiver},
    error::SlipstreamError,
    grpc::{self, LwdClient},
    wallet_session::WalletSession,
};

#[derive(Debug, Default, Clone)]
pub struct ScanStats {
    pub blocks: u64,
    pub chunks: u64,
    pub sapling_received: u64,
    pub orchard_received: u64,
}

/// Scans every chunk arriving on `rx` (they are ordered and continuity-verified
/// by the fetcher). `range_start` is the first height; the caller provides a
/// client for treestate prefetches.
pub async fn scan_chunks(
    session: &mut WalletSession,
    client: &mut LwdClient,
    range_start: u64,
    mut rx: ChunkQueueReceiver,
) -> Result<ScanStats, SlipstreamError> {
    let mut stats = ScanStats::default();
    // State for the FIRST chunk: boundary just below the range.
    let mut next_state = grpc::get_tree_state(client, range_start - 1).await?;

    while let Some((chunk, permit)) = rx.recv().await {
        let chunk_start = chunk
            .start_height()
            .ok_or_else(|| SlipstreamError::Wallet("empty chunk".into()))?;
        let chunk_end = chunk.end_height().expect("non-empty checked above");

        // Kick off the prefetch for the NEXT boundary while we scan this chunk.
        let prefetch = grpc::get_tree_state(client, chunk_end);

        let from_state = next_state
            .to_chain_state()
            .map_err(|e| SlipstreamError::Wallet(format!("chain state: {e}")))?;
        let network = session.network;
        let len = chunk.blocks.len();

        let summary = {
            let source = MemBlockSource::new(&chunk);
            scan_cached_blocks(
                &network,
                &source,
                session.db_mut(),
                BlockHeight::from(chunk_start as u32),
                &from_state,
                len,
            )
            .map_err(|e| SlipstreamError::Wallet(format!("scan_cached_blocks: {e}")))?
        };
        stats.blocks += len as u64;
        stats.chunks += 1;
        stats.sapling_received += summary.received_sapling_note_count() as u64;
        stats.orchard_received += summary.received_orchard_note_count() as u64;
        debug!(chunk_start, chunk_end, len, "chunk scanned");

        drop(permit); // release byte budget only after the scan committed
        next_state = prefetch.await?;
    }
    info!(blocks = stats.blocks, chunks = stats.chunks, "scan done");
    Ok(stats)
}
```
IMPLEMENTATION NOTES (binding): (1) `expect` in non-test code is forbidden — replace the `chunk_end` expect with a proper error or restructure (`let (Some(start), Some(end)) = ... else { return Err(...) }`). (2) `ScanSummary` accessor names: `received_sapling_note_count()` etc. — verify against registry `chain.rs:470-500`; orchard accessors are feature-gated (enabled here). (3) `scan_cached_blocks` is synchronous/blocking (SQLite + rayon decryption) — for P2's CLI this runs on the tokio worker; acceptable for the prototype, BUT wrap in `tokio::task::block_in_place` to avoid starving the runtime (justify in a comment; spawn_blocking needs 'static and `&mut session` prevents it — block_in_place is the correct tool; requires multi-thread runtime, which the CLI builds). (4) The prefetch is a plain future polled concurrently via... it is NOT polled until awaited — to actually overlap, spawn it: `let prefetch = tokio::spawn({ let mut c = client.clone(); async move { grpc::get_tree_state(&mut c, chunk_end).await } });` — `LwdClient` (tonic client) is cheaply cloneable; then `next_state = prefetch.await.map_err(|e| SlipstreamError::Transport(format!("prefetch task: {e}")))??;`. Apply this corrected form.

- [ ] **Step 2:** Unit-test what's testable hermetically: the module's logic is integration-bound; add `#[test] fn scan_stats_default_is_zero()` plus rely on T2.7's darkside end-to-end. Wire `pub mod scan;`. `cargo test -p slipstream-core` green; `--features darkside --no-run` compiles.
- [ ] **Step 3:** STATE.md (T2.4 done; Decision Log entry: "T2.3 spike resolved: ChainState per chunk boundary from server, prefetched — local derivation not exposed by zcash_client_sqlite"; NEXT → T2.5) + commit `[#1755] slipstream: per-chunk scan driver with pipelined treestate prefetch`.

---

### Task 2.5: `scheduler` — v0 loop over suggested scan ranges

**Files:** Create `slipstream/core/src/scheduler.rs`; modify lib.rs.

- [ ] **Step 1:** Create the module:

```rust
//! Scheduler v0: drive the wallet's own scan-queue (decision D3 — the coverage
//! ledger IS data.db's suggested ranges). For each suggested range, run the
//! fetch∥scan pipeline; re-suggest after each range until the queue is empty.
//! Priority handling (Verify-first) comes for free: suggest_scan_ranges returns
//! Verify ranges first by upstream contract.

use tracing::info;

use crate::{
    chunk::chunk_queue,
    config::EngineConfig,
    error::SlipstreamError,
    fetch::{FetchPlan, FetchStats, run_fetch},
    grpc,
    scan::{ScanStats, scan_chunks},
    wallet_session::WalletSession,
};

#[derive(Debug, Default, Clone)]
pub struct SyncReport {
    pub ranges_processed: u64,
    pub fetch: FetchStatsTotals,
    pub scan: ScanStatsTotals,
}

#[derive(Debug, Default, Clone)]
pub struct FetchStatsTotals {
    pub blocks: u64,
    pub bytes: u64,
}

#[derive(Debug, Default, Clone)]
pub struct ScanStatsTotals {
    pub blocks: u64,
    pub sapling_received: u64,
    pub orchard_received: u64,
}

/// Process every suggested range until none remain. The caller has already
/// run update_chain_tip + put_subtree_roots (engine.rs).
pub async fn run_to_completion(
    config: &EngineConfig,
    session: &mut WalletSession,
) -> Result<SyncReport, SlipstreamError> {
    let mut report = SyncReport::default();
    loop {
        let ranges = session.suggest_scan_ranges()?;
        let Some(range) = ranges.first() else {
            info!("scan queue empty — sync complete");
            return Ok(report);
        };
        let start = u64::from(u32::from(range.block_range().start));
        // block_range().end is EXCLUSIVE (upstream Range semantics).
        let end_exclusive = u64::from(u32::from(range.block_range().end));
        let end = end_exclusive - 1;
        info!(start, end, priority = ?range.priority(), "processing suggested range");

        let (tx, rx) = chunk_queue(config.memory_budget_bytes);
        let plan = FetchPlan::new(start, end, config.chunk_blocks, config.fetch_streams);
        let endpoint = config.endpoint.clone();

        let fetch_task = tokio::spawn(async move { run_fetch(&endpoint, plan, tx).await });

        let mut scan_client = grpc::connect(&config.endpoint).await?;
        let scan_stats: ScanStats =
            scan_chunks(session, &mut scan_client, start, rx).await?;

        let fetch_stats: FetchStats = fetch_task
            .await
            .map_err(|e| SlipstreamError::Transport(format!("fetch task: {e}")))??;

        report.ranges_processed += 1;
        report.fetch.blocks += fetch_stats.blocks;
        report.fetch.bytes += fetch_stats.bytes;
        report.scan.blocks += scan_stats.blocks;
        report.scan.sapling_received += scan_stats.sapling_received;
        report.scan.orchard_received += scan_stats.orchard_received;
    }
}
```
IMPLEMENTATION NOTES (binding): (1) `ScanRange::block_range()` returns `Range<BlockHeight>` (END-EXCLUSIVE) and `priority()` — confirmed by upstream sync.rs usage; the `u32::from(BlockHeight)` conversion exists (`BlockHeight: Into<u32>`); adjust syntax to what compiles (`u32::from(...)` vs `.into()`). (2) Continuity-error handling (scan returns a continuity error → truncate + re-suggest) is DEFERRED to a marked follow-up in T2.7 if the darkside test doesn't need it (linear fresh sync won't hit it); add `// TODO: [#1755] reorg/continuity recovery — port upstream sync.rs scan_blocks error arm` at the scan_chunks call site. (3) Hermetic unit tests for the totals structs only; the loop is exercised by T2.7.

- [ ] **Step 2:** Wire `pub mod scheduler;`. Suites green (`cargo test -p slipstream-core`; darkside `--no-run`).
- [ ] **Step 3:** STATE.md (T2.5 done; NEXT → T2.6) + commit `[#1755] slipstream: scheduler v0 over wallet scan queue with fetch-scan pipeline`.

---

### Task 2.6: `engine::sync_once` + CLI `sync` subcommand

**Files:** Create `slipstream/core/src/engine.rs`; modify lib.rs, `slipstream/cli/src/main.rs`.

- [ ] **Step 1:** `engine.rs`:

```rust
//! Engine v0: one full sync pass (preflight → chain state → scheduler).
//! P3 adds enhancement/transparent/events; P4 wraps this behind FFI.

use std::time::Instant;

use tracing::info;

use crate::{
    config::EngineConfig,
    error::SlipstreamError,
    grpc,
    scheduler::{SyncReport, run_to_completion},
    wallet_session::WalletSession,
};

pub struct SyncOutcome {
    pub report: SyncReport,
    pub elapsed: std::time::Duration,
    pub chain_tip: u64,
}

/// One sync pass. If `ufvk` is Some and the wallet has no accounts, imports it
/// with a birthday at `birthday_height` (treestate fetched from the server).
pub async fn sync_once(
    config: &EngineConfig,
    ufvk: Option<(&str, u64)>,
) -> Result<SyncOutcome, SlipstreamError> {
    config.validate()?;
    let started = Instant::now();

    let mut session = WalletSession::open(config.network, &config.wallet_db_path)?;
    let mut client = grpc::connect(&config.endpoint).await?;

    if let Some((ufvk_str, birthday_height)) = ufvk {
        let birthday_ts = grpc::get_tree_state(&mut client, birthday_height - 1).await?;
        session.ensure_account(ufvk_str, birthday_ts)?;
    }

    let roots = grpc::get_subtree_roots(&mut client).await?;
    session.put_subtree_roots(&roots)?;

    let tip = grpc::get_latest_block_height(&mut client).await?;
    session.update_chain_tip(tip)?;
    info!(tip, "chain tip updated");

    let report = run_to_completion(config, &mut session).await?;

    Ok(SyncOutcome { report, elapsed: started.elapsed(), chain_tip: tip })
}
```

- [ ] **Step 2:** CLI `sync` subcommand (extend `Cmd` + handler, following the existing `fetch` pattern):

```rust
    /// Full sync pass into a wallet database (creates it if absent).
    Sync {
        #[arg(long)]
        server: String,
        /// Wallet directory (data.db lives inside).
        #[arg(long)]
        wallet_dir: std::path::PathBuf,
        /// UFVK to import on first run (required for a fresh wallet).
        #[arg(long)]
        ufvk: Option<String>,
        /// Birthday height for --ufvk import.
        #[arg(long)]
        birthday: Option<u64>,
        #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(usize).range(1..))]
        streams: usize,
        #[arg(long, default_value_t = 10_000)]
        chunk: u32,
    },
```

Handler `cmd_sync` (same runtime pattern as `cmd_fetch`): build `EngineConfig` (network MainNetwork, `wallet_db_path = wallet_dir.join("data.db")`, endpoint from `parse_server`, streams/chunk from args), call `slipstream_core::engine::sync_once(&cfg, ufvk.as_deref().zip(birthday))`, print the outcome:
```text
synced to tip {chain_tip} in {elapsed:.1}s
ranges {ranges_processed} | fetched {fetch.blocks} blocks ({MB} MB) | scanned {scan.blocks} blocks
notes found: sapling {n} orchard {m}
```
Exit 1 with the error on failure. Tests: `parses_sync_subcommand` (+ rejects missing server). NOTE: `ufvk.as_deref().zip(birthday)` produces `Option<(&str, u64)>` — if a UFVK is given without `--birthday`, error out at arg-validation time with a clear message.

- [ ] **Step 3:** Suites green (core + cli). Hermetic smoke of preflight failure paths: `cargo run -p slipstream-cli -- sync --server http://127.0.0.1:1 --wallet-dir /tmp/slipstream-smoke` → clean Transport error, exit 1.
- [ ] **Step 4:** STATE.md (T2.6 done; NEXT → T2.7) + commit `[#1755] slipstream: engine sync_once + CLI sync subcommand`.

---

### Task 2.7: Correctness + G2 measurement

**Files:** Modify `slipstream/core/src/darkside.rs` (+`stage_blocks_url`), create `slipstream/core/tests/darkside_sync.rs`, STATE.md, possibly ROADMAP gate cell.

- [ ] **Step 1:** Add to `DarksideCtl` (mirror existing method style; proto rpc `StageBlocks(DarksideBlocksURL)`):

```rust
    /// Stage REAL pre-baked blocks from a darksidewalletd-test-data URL.
    pub async fn stage_blocks_url(&mut self, url: &str) -> Result<(), SlipstreamError> {
        self.client
            .stage_blocks(crate::darkside_generated::DarksideBlocksUrl { url: url.into() })
            .await
            .map_err(|e| err("stage_blocks", e))?;
        Ok(())
    }
```
(Generated type name may be `DarksideBlocksUrl` or `DarksideBlocksURL` per prost case rules — read the generated file.)

- [ ] **Step 2: Deterministic correctness test** `tests/darkside_sync.rs` (`#![cfg(feature = "darkside")]`, `#[ignore]`): EXTRACT the canonical fixture constants first — grep `Tests/DarksideTests/DarksideSanityCheckTests.swift` + `Tests/TestUtils/` for: the dataset URL it stages (`before-reorg.txt` class), the seed/UFVK it uses, and the expected first-received-tx (txid/height/value). Test flow: darkside `reset` → `stage_blocks_url(<that dataset>)` → `apply_staged(<dataset tip>)` → sleep(2s) → `engine::sync_once` against `http://127.0.0.1:9067` with the canonical UFVK + birthday 663_150 into a tempdir wallet → assert: `SyncOutcome.report.scan.blocks > 0` AND open the wallet db read-only (rusqlite) to assert the expected transaction exists (query `SELECT COUNT(*) FROM transactions` ≥ 1 and, if straightforward, the expected txid hex) and the account balance matches the fixture's expectation. Record EXACT asserted values in the test as named constants with a comment pointing at the Swift source lines they came from.
- [ ] **Step 3:** Run it: start darkside lightwalletd, `cargo test -p slipstream-core --features darkside -- --ignored --test-threads=1` → all 3 darkside tests green (roundtrip, 5000-fetch, sync). Kill lightwalletd. NOTE: `stage_blocks_url` downloads fixture data from raw.githubusercontent.com — network needed (read-only fetch; LOCAL-ONLY policy concerns pushes, not reads).
- [ ] **Step 4: G2 measurement.**
  a. SPIKE (read-only): open `Tests/PerformanceTests/SynchronizerTests.swift` and determine whether it can sync a defined mainnet window with a wall-clock report (what seed/birthday/server it uses; how to invoke: `swift test --filter PerformanceTests` needs the target enabled — check `Package.swift` test target list). If unusable within ~30 min of effort, fall back to: old-SDK baseline = darkside-based timing is NOT comparable; instead run the old SDK via `Tests/NetworkTests`-style sync if available, OR document procedure "Zodl debug build, fresh restore, stopwatch" as the baseline to be captured at P4 and mark G2's old-SDK column "pending P4 measurement" — but FIRST attempt the PerformanceTests route. Record what was done.
  b. Slipstream numbers (always capturable): `cargo run -p slipstream-cli -- sync --server https://zec.rocks:443 --wallet-dir /tmp/slipstream-g2 --ufvk <test UFVK> --birthday <tip-50_000>` → wall-clock for a 50k restore; then a 1M-range run (`--birthday <tip-1_000_000>`, fresh wallet dir) for the absolute number. Record both + stage split (fetch vs scan from the report) in the truth table.
  c. G2 verdict: ratio vs whatever old-SDK baseline was capturable on this machine (≥5× target). If the old-SDK baseline couldn't be captured credibly, record slipstream absolutes + mark G2 "ratio pending P4 A/B" with a Decision Log entry — do NOT fake a baseline.
- [ ] **Step 5:** STATE.md: truth-table rows (50k + 1M + baseline attempts); G2 gate row updated honestly; T2.7 done; phase-gate OfflineTests run (root Cargo.toml changed this phase) + recorded; NEXT ACTION → **T3.0** (Phase 3 Completeness plan: Rust enhancer, transparent/UTXO, events; read ROADMAP P3 + the deferred continuity-recovery TODO). Session log `P2 COMPLETE` (or honest status). Commit `[#1755] slipstream: darkside sync correctness test; gate G2 measured and recorded`.

---

## Phase exit criteria (G2)

- [ ] Hermetic suites green (core ≈ 26+ tests incl. new block_source/wallet_session/cli; 1 ignored network).
- [ ] Darkside suite green serially: roundtrip + 5000-fetch + **deterministic sync with fixture-matched transactions/balance**.
- [ ] CLI `sync` performs a real mainnet restore end-to-end (50k + 1M runs recorded with stage split).
- [ ] G2 gate row updated with measured ratio OR an honest "ratio pending P4 A/B" + Decision Log entry.
- [ ] OfflineTests 419/0 at phase gate; LOCAL-ONLY intact; `main` untouched; STATE.md NEXT → T3.0.
