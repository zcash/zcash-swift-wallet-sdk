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
use tracing::info;
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
    ll::{LowLevelWalletRead, LowLevelWalletWrite, ReceivedShieldedOutput, wallet::PutBlocksError},
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
pub(crate) const BUILD_CHUNK_SIZE: usize = 1024;

/// T6.3b checkpoint-downgrade window, mirroring upstream PRUNING_DEPTH = 100
/// (zcash_client_backend ll/wallet.rs:52, plumbed into the trees as
/// `max_checkpoints` — see MAX_CHECKPOINTS above).
///
/// Upstream's scan stream carries a `Retention::Checkpoint { id }` for EVERY
/// scanned block, but `prune_excess_checkpoints` (shardtree lib.rs:550-660)
/// trims the checkpoint set back to the newest 100 ids on every `insert_tree`
/// call — so within one `put_blocks` call all but the newest ~100 checkpoints
/// are created, walked, and destroyed (≈9,900 create/destroy cycles per
/// 10k-block chunk). The downgrade computes the surviving window up front
/// (per pool, per put_blocks call) and never creates the doomed ones.
///
/// For a pool that checkpoints every block of the batch this is the
/// controller-prescribed `cutoff = last_scanned_block_height - 100`; the exact
/// per-pool form (see [`doomed_checkpoint_cutoff`]) is required because
/// upstream retains the newest 100 ids *of the pool's checkpoint id stream*,
/// which reaches below `last - 100` when a pool checkpoints fewer than 100
/// blocks in that window.
const SPARSE_CHECKPOINT_WINDOW: u64 = 100;
const _: () = assert!(
    SPARSE_CHECKPOINT_WINDOW as usize == MAX_CHECKPOINTS,
    "window must mirror upstream PRUNING_DEPTH / max_checkpoints"
);

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
    /// B0: route the Orchard subtree build to the GPU (feature `gpu`). Default false;
    /// set from `EngineConfig::gpu_subtree` at the scan-path construction site.
    pub(crate) gpu_subtree: bool,
    /// v0.4 census (spec §3.2): shard-touch vs owned-note-shard counts, fed by every
    /// `sparse_put_blocks` call on this state and read out at range end (ScanStats).
    pub(crate) census_sapling: crate::census::ShardCensus,
    pub(crate) census_orchard: crate::census::ShardCensus,
}

impl SparseTreeState {
    /// v0.4 census read-out (spec §3.2) — (sapling, orchard). Production reads
    /// travel via `ScanStats`; this accessor serves tests and direct hosts.
    pub fn census(&self) -> (&crate::census::ShardCensus, &crate::census::ShardCensus) {
        (&self.census_sapling, &self.census_orchard)
    }
}

fn seed_sapling(db: &mut Db, _from_state: &ChainState) -> Result<SaplingSparseTree, SqliteClientError> {
    let mut store = SparseShardStore::<sapling::Node>::new(SAPLING_SHARD_HEIGHT);
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
        // Load ALL shards from SQLite into memory: the scan may access any shard
        // in the scan range (e.g. when a complete subtree boundary is crossed), and
        // returning NotPreloaded for an unloaded-but-known shard would abort the scan.
        // Complete subtrees are stored as a single root-hash node, so the total
        // preload cost is modest even for large trees (≈N * ~100 bytes per shard).
        for addr in &roots {
            let idx = addr.index();
            if let Some(shard) = s.get_shard(*addr).map_err(ShardTreeError::Storage)? {
                store.shards.insert(idx, shard);
            }
        }
        store.cap = s.get_cap().map_err(ShardTreeError::Storage)?;
        store.checkpoints = cps.clone();
        store.db_checkpoints = cps;
        Ok(())
    })?;
    Ok(ShardTree::new(store, MAX_CHECKPOINTS))
}

fn seed_orchard(db: &mut Db, _from_state: &ChainState) -> Result<OrchardSparseTree, SqliteClientError> {
    let mut store = SparseShardStore::<orchard::tree::MerkleHashOrchard>::new(ORCHARD_SHARD_HEIGHT);
    db.with_orchard_tree_mut::<_, _, SqliteClientError>(|tree| {
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
        // Load ALL shards from SQLite into memory: same reasoning as seed_sapling —
        // the scan range may cross shard boundaries for any protocol, and returning
        // NotPreloaded for an unloaded-but-known shard would abort the scan.
        for addr in &roots {
            let idx = addr.index();
            if let Some(shard) = s.get_shard(*addr).map_err(ShardTreeError::Storage)? {
                store.shards.insert(idx, shard);
            }
        }
        store.cap = s.get_cap().map_err(ShardTreeError::Storage)?;
        store.checkpoints = cps.clone();
        store.db_checkpoints = cps;
        Ok(())
    })?;
    Ok(ShardTree::new(store, MAX_CHECKPOINTS))
}

/// Flush dirty in-memory sapling tree state into the live transaction's SQLite store.
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
    // NOTE: do NOT insert dirty shard indices into db_shard_indices here.
    // Flushed shards remain in `shards` (we never clear the in-memory map), so
    // get_shard() finds them via the first check (shards.get(idx)).
    // db_shard_indices must only track shards loaded from SQLite at seed time
    // ("known-but-unloaded" guard); adding flushed shards would cause
    // NotPreloaded errors on the next chunk if shardtree internally calls
    // get_shard for a shard that is now in db_shard_indices but has been
    // evicted or not yet re-populated in `shards`.
    store.dirty_shards.clear();
    store.cap_dirty = false;
    Ok(())
}

/// Flush dirty in-memory orchard tree state into the live transaction's SQLite store.
fn flush_orchard<P, CL, R>(
    wdb: &mut zcash_client_sqlite::WalletDb<zcash_client_sqlite::SqlTransaction<'_>, P, CL, R>,
    tree: &mut OrchardSparseTree,
) -> Result<(), SqliteClientError>
where
    P: zcash_protocol::consensus::Parameters,
{
    let (remove, add) = tree.store().checkpoint_delta();
    let dirty: Vec<u64> = tree.store().dirty_shards.iter().copied().collect();
    let cap_dirty = tree.store().cap_dirty;
    wdb.with_orchard_tree_mut::<_, _, SqliteClientError>(|sql_tree| {
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
    // NOTE: do NOT insert dirty shard indices into db_shard_indices here.
    // See flush_sapling comment — same reasoning applies.
    store.dirty_shards.clear();
    store.cap_dirty = false;
    Ok(())
}

/// Upstream-identical put_blocks with in-memory tree accumulation.
/// Mirrors zcash_client_backend-0.23.0 ll/wallet.rs:235-550 section by section;
/// the ONLY substitution is the tree target (SparseShardStore vs SqliteShardStore)
/// plus a flush of the dirty tree delta inside the same transaction.
#[allow(clippy::too_many_lines)]
// sapling::Note / orchard::Note do not implement Copy; clippy false-positive on .clone()
#[allow(clippy::clone_on_copy)]
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
    let gpu_on = sparse.gpu_subtree;
    let SparseTreeState {
        sapling: Some(sap_tree),
        orchard: Some(orch_tree),
        census_sapling,
        census_orchard,
        ..
    } = sparse
    else {
        return Err(SqliteClientError::CorruptedData(
            "sparse tree state missing after seed".into(),
        ));
    };

    let t_rows = std::time::Instant::now();
    let mut rows_ms = 0u128;
    let mut tree_ms = 0u128;
    let mut sap_tree_ms = 0u128;
    let mut orch_tree_ms = 0u128;
    let mut sap_split = PoolTimers::default();
    let mut orch_split = PoolTimers::default();
    let mut flush_ms = 0u128;
    let mut downgraded = 0u64;

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

            // ── T6.3b checkpoint downgrade — cross-pool dependency boundary ───
            // The two cp_pos maps MUST be computed serially before the per-pool
            // pipeline: ensure_checkpoints is CROSS-POOL (missing_sapling uses
            // orchard_cp_pos.keys(); missing_orchard uses sapling_cp_pos.keys()).
            // Both maps come from immutable commitment slices so the two
            // stream_checkpoint_positions calls are independent, but their results
            // must both exist before we can compute the cross-pool ensure-heights.
            // Everything below (downgrade → build_subtrees → insert_frontier →
            // insert_tree loops → ensure_add) is fully per-pool and runs in
            // parallel via rayon::join.
            //
            // Full (pre-downgrade) checkpoint position maps, computed straight
            // from the commitment streams. These are EXACTLY the maps upstream's
            // `checkpoint_positions(&subtrees)` would extract (from_iter records
            // every Checkpoint retention as id → position, shardtree
            // batch.rs:204) — but they must be taken BEFORE the downgrade:
            // `ensure_checkpoints` below needs upstream-identical inputs, since
            // a filtered `existing` map would remap an ensure-height whose
            // nearest own-pool checkpoint lies below the cutoff onto the
            // frontier position instead of that checkpoint's position.
            let sapling_cp_pos = stream_checkpoint_positions(
                Position::from(from_state.final_sapling_tree().tree_size()),
                &sapling_commitments,
            );
            let orchard_cp_pos = stream_checkpoint_positions(
                Position::from(from_state.final_orchard_tree().tree_size()),
                &orchard_commitments,
            );

            // ll/wallet.rs:484-501 — cross-pool checkpoint reconciliation, on
            // the FULL pre-downgrade maps (upstream-identical). Computed here,
            // before the per-pool parallel section, because each pool's
            // ensure_checkpoints call needs the OTHER pool's cp_pos map.
            // The `height > min_cp` filter in the add loops below keeps the
            // surviving add-set identical to upstream's: with the downgrade, the
            // post-insert min checkpoint id equals upstream's post-prune min (the
            // cutoff computation above is that same retained-set minimum), so
            // only ids ≥ cutoff can reach the checkpoint tables.
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

            // ── T6.8 parallel per-pool tree work ──────────────────────────────
            // sapling and orchard operate on completely disjoint state:
            //   - separate SparseShardStore/ShardTree fields (sap_tree / orch_tree)
            //   - separate commitment Vecs (sapling_commitments / orchard_commitments)
            //   - pre-computed, pool-independent ensure-checkpoint Vecs above
            // rayon::join uses work-stealing from the global pool; nested rayon
            // is safe (upstream's build_subtrees already uses par_chunks internally).
            // Each side returns Result — both results are checked after join
            // (no unwrap/expect).
            //
            // Cutoff per pool, per put_blocks call: the minimum of the newest
            // SPARSE_CHECKPOINT_WINDOW checkpoint ids that will exist at the end
            // of this call (already-stored ids ∪ the frontier id ∪ this batch's
            // new ids) — i.e. exactly the post-prune retained set upstream's
            // iterative oldest-first pruning leaves behind. Every Checkpoint
            // retention below it is doomed and gets downgraded to the residue
            // prune_excess_checkpoints would leave anyway (Marked survives the
            // CHECKPOINT-flag clear; everything else becomes Ephemeral).
            let frontier_id = from_state.block_height();

            // Capture immutable per-pool inputs before the split-borrow.
            let sap_start = Position::from(from_state.final_sapling_tree().tree_size());
            let orch_start = Position::from(from_state.final_orchard_tree().tree_size());
            let sap_frontier = from_state.final_sapling_tree().clone();
            let orch_frontier = from_state.final_orchard_tree().clone();
            let frontier_checkpoint_id = frontier_id;

            // v0.4 census (spec §3.2): record shard touches + owned-note shards for
            // this call BEFORE the per-pool parallel section (serial, trivial cost).
            census_sapling.feed(
                u64::from(sap_start),
                sapling_commitments.len() as u64,
                note_positions
                    .iter()
                    .filter(|(p, _)| *p == ShieldedProtocol::Sapling)
                    .map(|(_, pos)| u64::from(*pos)),
            );
            census_orchard.feed(
                u64::from(orch_start),
                orchard_commitments.len() as u64,
                note_positions
                    .iter()
                    .filter(|(p, _)| *p == ShieldedProtocol::Orchard)
                    .map(|(_, pos)| u64::from(*pos)),
            );

            fn map_sparse_err<E: std::fmt::Debug>(e: E) -> SqliteClientError {
                SqliteClientError::CorruptedData(format!("sparse tree: {e:?}"))
            }

            let (sap_result, orch_result) = rayon::join(
                || -> Result<(u64, PoolTimers), SqliteClientError> {
                    let t_pool = std::time::Instant::now();
                    let mut timers = PoolTimers::default();
                    // Downgrade doomed checkpoints (T6.3b).
                    let t = std::time::Instant::now();
                    let sap_downgraded = doomed_checkpoint_cutoff(
                        sap_tree.store().checkpoints.keys().copied(),
                        frontier_id,
                        sapling_cp_pos.keys().copied(),
                    )
                    .map_or(0, |cutoff| {
                        downgrade_doomed_checkpoints(&mut sapling_commitments, cutoff)
                    });
                    timers.downgrade_ms = t.elapsed().as_millis();

                    // ll/wallet.rs:466-481 — build subtrees (rayon par_chunks, same chunk size).
                    let t = std::time::Instant::now();
                    let sapling_subtrees =
                        build_subtrees::<_, SAPLING_SHARD_HEIGHT>(sap_start, &mut sapling_commitments);
                    timers.build_ms = t.elapsed().as_millis();

                    // ll/wallet.rs:503-537 update_tree — IN MEMORY (the substitution).
                    let t = std::time::Instant::now();
                    sap_tree
                        .insert_frontier(
                            sap_frontier,
                            Retention::Checkpoint {
                                id: frontier_checkpoint_id,
                                marking: Marking::Reference,
                            },
                        )
                        .map_err(map_sparse_err)?;
                    timers.frontier_ms = t.elapsed().as_millis();
                    let t = std::time::Instant::now();
                    for (subtree, checkpoints) in sapling_subtrees {
                        sap_tree.insert_tree(subtree, checkpoints).map_err(map_sparse_err)?;
                    }
                    timers.insert_ms = t.elapsed().as_millis();
                    let t = std::time::Instant::now();
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
                    timers.ensure_ms = t.elapsed().as_millis();
                    timers.total_ms = t_pool.elapsed().as_millis();
                    Ok((sap_downgraded, timers))
                },
                || -> Result<(u64, PoolTimers), SqliteClientError> {
                    let t_pool = std::time::Instant::now();
                    let mut timers = PoolTimers::default();
                    // Downgrade doomed checkpoints (T6.3b).
                    let t = std::time::Instant::now();
                    let orch_downgraded = doomed_checkpoint_cutoff(
                        orch_tree.store().checkpoints.keys().copied(),
                        frontier_id,
                        orchard_cp_pos.keys().copied(),
                    )
                    .map_or(0, |cutoff| {
                        downgrade_doomed_checkpoints(&mut orchard_commitments, cutoff)
                    });
                    timers.downgrade_ms = t.elapsed().as_millis();

                    // ll/wallet.rs:466-481 — build subtrees (rayon par_chunks, same chunk size).
                    let t = std::time::Instant::now();
                    let orchard_subtrees =
                        build_orchard_subtrees(gpu_on, orch_start, &mut orchard_commitments);
                    timers.build_ms = t.elapsed().as_millis();

                    // ll/wallet.rs:503-537 update_tree — IN MEMORY (the substitution).
                    let t = std::time::Instant::now();
                    orch_tree
                        .insert_frontier(
                            orch_frontier,
                            Retention::Checkpoint {
                                id: frontier_checkpoint_id,
                                marking: Marking::Reference,
                            },
                        )
                        .map_err(map_sparse_err)?;
                    timers.frontier_ms = t.elapsed().as_millis();
                    let t = std::time::Instant::now();
                    for (subtree, checkpoints) in orchard_subtrees {
                        orch_tree.insert_tree(subtree, checkpoints).map_err(map_sparse_err)?;
                    }
                    timers.insert_ms = t.elapsed().as_millis();
                    let t = std::time::Instant::now();
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
                    timers.ensure_ms = t.elapsed().as_millis();
                    timers.total_ms = t_pool.elapsed().as_millis();
                    Ok((orch_downgraded, timers))
                },
            );
            // Propagate errors from both sides after join (no unwrap/expect).
            let (sap_downgraded, sap_timers) = sap_result?;
            let (orch_downgraded, orch_timers) = orch_result?;
            downgraded = sap_downgraded + orch_downgraded;
            sap_tree_ms = sap_timers.total_ms;
            orch_tree_ms = orch_timers.total_ms;
            sap_split = sap_timers;
            orch_split = orch_timers;

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

    // sap_tree_ms/orch_tree_ms are the per-pool closure wall times INSIDE the join:
    // tree_ms ≈ max(sap, orch) when the join truly runs in parallel, ≈ sap + orch when
    // it degenerates to serial (single-thread rayon pool) — this distinguishes
    // "lopsided pools" from "no parallelism" directly in device logs.
    info!(rows_ms, tree_ms, sap_tree_ms, orch_tree_ms, flush_ms, downgraded, "sparse put_blocks");
    // T6.8-L3b sub-attribution: per-pool pipeline split (one line per pool, per chunk).
    // The dominant orchard sub-bucket decides the L3b optimization target.
    info!(
        downgrade_ms = orch_split.downgrade_ms,
        build_ms = orch_split.build_ms,
        frontier_ms = orch_split.frontier_ms,
        insert_ms = orch_split.insert_ms,
        ensure_ms = orch_split.ensure_ms,
        total_ms = orch_split.total_ms,
        "sparse orchard tree split"
    );
    info!(
        downgrade_ms = sap_split.downgrade_ms,
        build_ms = sap_split.build_ms,
        frontier_ms = sap_split.frontier_ms,
        insert_ms = sap_split.insert_ms,
        ensure_ms = sap_split.ensure_ms,
        total_ms = sap_split.total_ms,
        "sparse sapling tree split"
    );
    Ok(())
}

// ── Replicas of upstream private helpers (public types only) ──────────────────

/// Mirror of ll/wallet.rs:1146-1170 (private upstream; rebuilt on public API).
pub(crate) fn build_subtrees<H, const SHARD_HEIGHT: u8>(
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
                // mirror of upstream; structurally infallible (each Option is taken exactly once)
                chunk.iter_mut().map(|n| n.take().expect("always Some")),
            )
        })
        .map(|res| (res.subtree, res.checkpoints))
        .collect()
}

/// Orchard subtree build, routed to the GPU when `gpu` is true (feature `gpu` + the
/// `gpu_subtree` flag); otherwise the CPU `build_subtrees`. Output is byte-identical either
/// way (gpu_subtree.rs + the `gpu_subtree_build_matches_cpu` test + the engine oracle).
#[cfg(feature = "gpu")]
fn build_orchard_subtrees(
    gpu: bool,
    start: Position,
    commitments: &mut [Option<(orchard::tree::MerkleHashOrchard, Retention<BlockHeight>)>],
) -> Vec<(LocatedPrunableTree<orchard::tree::MerkleHashOrchard>, BTreeMap<BlockHeight, Position>)> {
    if gpu {
        crate::gpu_subtree::build_subtrees_gpu::<ORCHARD_SHARD_HEIGHT>(start, commitments)
    } else {
        build_subtrees::<_, ORCHARD_SHARD_HEIGHT>(start, commitments)
    }
}

#[cfg(not(feature = "gpu"))]
fn build_orchard_subtrees(
    _gpu: bool,
    start: Position,
    commitments: &mut [Option<(orchard::tree::MerkleHashOrchard, Retention<BlockHeight>)>],
) -> Vec<(LocatedPrunableTree<orchard::tree::MerkleHashOrchard>, BTreeMap<BlockHeight, Position>)> {
    build_subtrees::<_, ORCHARD_SHARD_HEIGHT>(start, commitments)
}

/// Equivalent of ll/wallet.rs:1173-1183 `checkpoint_positions`, computed
/// directly from a commitment stream instead of from the built subtrees:
/// `LocatedTree::from_iter` records every `Retention::Checkpoint` it consumes
/// as id → leaf position (shardtree batch.rs:204), and positions are assigned
/// sequentially from the start position — so this map is identical to the one
/// upstream extracts post-build. Needed pre-build so the T6.3b downgrade can
/// run between map extraction and subtree construction.
fn stream_checkpoint_positions<H>(
    start: Position,
    commitments: &[Option<(H, Retention<BlockHeight>)>],
) -> BTreeMap<BlockHeight, Position> {
    commitments
        .iter()
        .enumerate()
        .filter_map(|(i, c)| {
            c.as_ref().and_then(|(_, retention)| match retention {
                Retention::Checkpoint { id, .. } => Some((*id, start + i as u64)),
                _ => None,
            })
        })
        .collect()
}

/// T6.3b: the cutoff id below which a `Retention::Checkpoint` created in this
/// `sparse_put_blocks` call is doomed — i.e. cannot survive upstream's
/// `prune_excess_checkpoints` (oldest-first removal down to
/// [`SPARSE_CHECKPOINT_WINDOW`] entries, re-run on every `insert_tree` call).
///
/// The retained set at the end of the call is the newest
/// `SPARSE_CHECKPOINT_WINDOW` distinct ids out of (already-stored checkpoint
/// ids ∪ the from_state frontier checkpoint id ∪ this batch's new checkpoint
/// ids); the cutoff is that set's minimum. `None` when the union fits inside
/// the window (nothing is doomed — e.g. sub-100-block batches).
fn doomed_checkpoint_cutoff(
    existing: impl Iterator<Item = BlockHeight>,
    frontier_id: BlockHeight,
    new_ids: impl Iterator<Item = BlockHeight>,
) -> Option<BlockHeight> {
    let mut union: BTreeSet<BlockHeight> = existing.collect();
    union.insert(frontier_id);
    union.extend(new_ids);
    union
        .iter()
        .rev()
        .nth(SPARSE_CHECKPOINT_WINDOW as usize - 1)
        .copied()
}

/// T6.8-L3b sub-attribution: wall-time split of one pool's in-memory tree
/// pipeline inside its rayon::join closure. All values are milliseconds;
/// `total_ms` is the whole-closure wall time (≈ sum of the buckets).
#[derive(Debug, Default, Clone, Copy)]
struct PoolTimers {
    /// `doomed_checkpoint_cutoff` + `downgrade_doomed_checkpoints`.
    downgrade_ms: u128,
    /// `build_subtrees` (upstream's par_chunks subtree construction).
    build_ms: u128,
    /// `insert_frontier`.
    frontier_ms: u128,
    /// The `insert_tree` loop over built subtrees.
    insert_ms: u128,
    /// `min_checkpoint_id` + the missing-checkpoint add loop.
    ensure_ms: u128,
    /// Whole-closure wall time.
    total_ms: u128,
}

/// T6.3b: downgrade doomed checkpoint retentions in place (ids strictly below
/// `cutoff`) to the exact residue upstream's prune cycle would leave on the
/// leaf: clearing the CHECKPOINT flag preserves MARKED and leaves everything
/// else EPHEMERAL (shardtree lib.rs:550-660 + RetentionFlags at
/// prunable.rs:55-67). The from_state frontier insert's checkpoint
/// (`Marking::Reference`, applied by the update_tree mirror, never present in
/// these streams — scanning.rs:777-786 emits only `Marked`/`None` markings)
/// and all ids at/above the cutoff are untouched. Returns the downgrade count.
fn downgrade_doomed_checkpoints<H>(
    commitments: &mut [Option<(H, Retention<BlockHeight>)>],
    cutoff: BlockHeight,
) -> u64 {
    let mut downgraded = 0u64;
    for slot in commitments.iter_mut().flatten() {
        if let Retention::Checkpoint { id, marking } = &slot.1
            && *id < cutoff
        {
            slot.1 = match marking {
                Marking::Marked => Retention::Marked,
                _ => Retention::Ephemeral,
            };
            downgraded += 1;
        }
    }
    downgraded
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

// ── T6.9 L4b: write-behind persistence pipelining ──────────────────────────────
//
// Depth-1 pipeline: chunk N's commit (the EXACT `sparse_put_blocks` logic — rows
// + in-memory tree mutation + flush, one atomic `transactionally` per put_blocks
// call, strictly serial N before N+1) runs on a persist lane while the scan task
// decrypts chunk N+1. With chunk N uncommitted, chunk N+1's `scan_cached_blocks`
// reads the wallet DB — its COMPLETE read surface (recon 2026-06-12, every call
// site cited on the methods below) is served by `WriteBehindFacade` from a
// pending-aware merged view; every read OUTSIDE that surface fails loudly
// (`unvirtualized`) so upstream read-surface drift can never become a silent
// stale read. Tree-state ownership: the per-range `SparseTreeState` lives in the
// `PersistLane` (insert + flush stay together inside each deferred commit); the
// scan side never touches it.

/// Account id alias of the production wallet DB (zcash_client_sqlite AccountUuid).
type DbAccountId = <Db as WalletRead>::AccountId;

/// One deferred persist unit: everything `sparse_put_blocks` needs, captured at
/// `put_blocks` time. `from_state` is the server-provided treestate for this
/// unit's lower boundary (independent of DB state — unaffected by deferral).
pub struct PendingPersist {
    pub from_state: ChainState,
    pub blocks: Vec<ScannedBlock<DbAccountId>>,
    /// First/last block height of the unit (log attribution only).
    pub first_height: u64,
    pub last_height: u64,
}

/// Mirror of upstream `Nullifiers::update_with` for ONE block's worth of deltas
/// (zcash_client_backend-0.23.0/src/scanning.rs:435-464): retain-then-extend,
/// applied per block in block order. Generic so the semantics are unit-testable
/// without `ScannedBlock` values (which are not publicly constructible).
pub(crate) fn apply_nullifier_delta<A: Copy, Nf: PartialEq + Copy>(
    set: &mut Vec<(A, Nf)>,
    spent: &[Nf],
    found: &[(A, Nf)],
) {
    set.retain(|(_, nf)| !spent.contains(nf));
    set.extend_from_slice(found);
}

fn unvirtualized(name: &str) -> SqliteClientError {
    SqliteClientError::CorruptedData(format!(
        "write-behind facade: `{name}` is not part of the scan_cached_blocks read surface \
         (T6.9 recon) — refusing to serve a possibly-stale read while a commit is pending"
    ))
}

/// Pending-aware wallet facade for the write-behind scan path. Holds NO database
/// connection: the four reads `scan_cached_blocks` performs are served from
/// state seeded once per range (under the no-pending barrier) and rolled forward
/// at each `put_blocks` stash — the same in-memory threading upstream itself
/// uses BETWEEN BLOCKS of a single call (chain.rs:652-653), extended across one
/// call boundary.
///
/// Read surface of `scan_cached_blocks` (zcash_client_backend-0.23.0
/// data_api/chain.rs:586-664), enumerated:
/// 1. `get_unified_full_viewing_keys` — chain.rs:603-605. Never changed by
///    `put_blocks` (accounts/UFVKs mutate only via account import/create, which
///    cannot run during a range) → served from a per-range cache. EXACT.
/// 2. `block_metadata(from_height - 1)` — chain.rs:614-620, consumed by
///    `check_hash_continuity` (scanning/compact.rs:191-221: prev-height +
///    prev-hash reorg detection) and `PositionTracker::for_compact_block`
///    (compact.rs:400-516: prior tree sizes). With chunk N pending this row is
///    exactly chunk N's last scanned block → served from the stashed tail via
///    `ScannedBlock::to_block_metadata()` — the IDENTICAL value upstream threads
///    between blocks within one call (chain.rs:653). Any other height = loud error.
/// 3. `get_sapling_nullifiers(NullifierQuery::Unspent)` — via
///    `Nullifiers::unspent`, scanning.rs:360-368 ← chain.rs:623. Served from a
///    running unspent view: seeded from the DB at range start, advanced per
///    stashed block by `apply_nullifier_delta` (upstream's own `update_with`
///    semantics, scanning.rs:435-464 — upstream relies on this equivalence for
///    every multi-block call; the SQLite Unspent query at
///    zcash_client_sqlite-0.21.0 wallet/common.rs:155-189 returns the same set
///    for committed scan output: nf NOT NULL ∧ tx mined ∧ not spent by a mined
///    tx). A note FOUND in pending chunk N is therefore visible to chunk N+1's
///    spend detection. Re-seeded from the DB after every enhancement barrier
///    (enhancement may store full txs that add/spend notes).
/// 4. `get_orchard_nullifiers(NullifierQuery::Unspent)` — same as (3),
///    scanning.rs:366.
///
/// Everything else a `WalletRead`/`WalletWrite` impl must provide is NOT called
/// by `scan_cached_blocks`; each such method returns `unvirtualized` (loud
/// fail-fast, exercised by oracle + darkside suites) instead of an approximate
/// or stale answer.
pub struct WriteBehindFacade {
    ufvks: HashMap<DbAccountId, UnifiedFullViewingKey>,
    /// The single height `block_metadata` is allowed to answer for
    /// (= the next scan call's `from_height - 1`).
    prior_meta_height: BlockHeight,
    /// The metadata at `prior_meta_height` (None = known-absent row, e.g. the
    /// first range after birthday — upstream returns None there too).
    prior_meta: Option<BlockMetadata>,
    sapling_nfs: Vec<(DbAccountId, sapling::Nullifier)>,
    orchard_nfs: Vec<(DbAccountId, orchard::note::Nullifier)>,
    stash: Option<PendingPersist>,
}

impl WriteBehindFacade {
    /// Seed the virtualized read state from the committed DB. MUST be called
    /// under the no-pending barrier (range start: nothing stashed or in
    /// flight), so the committed DB is the complete wallet state.
    pub fn seed(db: &Db, range_start: u64) -> Result<Self, SqliteClientError> {
        let prior_height = range_start
            .checked_sub(1)
            .and_then(|h| u32::try_from(h).ok())
            .ok_or_else(|| {
                SqliteClientError::CorruptedData(format!(
                    "write-behind facade: invalid range_start {range_start}"
                ))
            })?;
        let prior_meta_height = BlockHeight::from(prior_height);
        Ok(Self {
            ufvks: db.get_unified_full_viewing_keys()?,
            prior_meta_height,
            prior_meta: db.block_metadata(prior_meta_height)?,
            sapling_nfs: db.get_sapling_nullifiers(NullifierQuery::Unspent)?,
            orchard_nfs: db.get_orchard_nullifiers(NullifierQuery::Unspent)?,
            stash: None,
        })
    }

    /// Re-read both running nullifier views from the committed DB. MUST be
    /// called under a drained barrier (no stash, no in-flight commit) — used
    /// after enhancement runs, which may store fully-decrypted transactions
    /// that add received notes or mark notes spent outside `put_blocks`.
    /// `prior_meta` and the UFVK cache are deliberately NOT re-read:
    /// enhancement never writes the `blocks` table or the accounts table.
    pub fn reseed_nullifiers(&mut self, db: &Db) -> Result<(), SqliteClientError> {
        if self.stash.is_some() {
            return Err(SqliteClientError::CorruptedData(
                "write-behind facade: reseed_nullifiers with an occupied stash".into(),
            ));
        }
        self.sapling_nfs = db.get_sapling_nullifiers(NullifierQuery::Unspent)?;
        self.orchard_nfs = db.get_orchard_nullifiers(NullifierQuery::Unspent)?;
        Ok(())
    }

    /// Take the pending unit stashed by the last `put_blocks` call (if any).
    pub fn take_stash(&mut self) -> Option<PendingPersist> {
        self.stash.take()
    }

    #[cfg(test)]
    fn test_new(prior_meta_height: BlockHeight, prior_meta: Option<BlockMetadata>) -> Self {
        Self {
            ufvks: HashMap::new(),
            prior_meta_height,
            prior_meta,
            sapling_nfs: vec![],
            orchard_nfs: vec![],
            stash: None,
        }
    }
}

impl WalletRead for WriteBehindFacade {
    type Error = SqliteClientError;
    type AccountId = DbAccountId;
    type Account = <Db as WalletRead>::Account;

    // ── The virtualized read surface (see struct docs for citations) ──────────
    fn get_unified_full_viewing_keys(&self) -> Result<HashMap<Self::AccountId, UnifiedFullViewingKey>, Self::Error> { Ok(self.ufvks.clone()) }
    fn block_metadata(&self, height: BlockHeight) -> Result<Option<BlockMetadata>, Self::Error> {
        if height == self.prior_meta_height {
            Ok(self.prior_meta)
        } else {
            Err(SqliteClientError::CorruptedData(format!(
                "write-behind facade: block_metadata({height}) outside the virtualized tail (expected {})",
                self.prior_meta_height
            )))
        }
    }
    fn get_sapling_nullifiers(&self, query: NullifierQuery) -> Result<Vec<(Self::AccountId, sapling::Nullifier)>, Self::Error> {
        match query {
            NullifierQuery::Unspent => Ok(self.sapling_nfs.clone()),
            NullifierQuery::All => Err(unvirtualized("get_sapling_nullifiers(All)")),
        }
    }
    fn get_orchard_nullifiers(&self, query: NullifierQuery) -> Result<Vec<(Self::AccountId, orchard::note::Nullifier)>, Self::Error> {
        match query {
            NullifierQuery::Unspent => Ok(self.orchard_nfs.clone()),
            NullifierQuery::All => Err(unvirtualized("get_orchard_nullifiers(All)")),
        }
    }

    // ── Outside the scan read surface: fail loudly, never approximate ─────────
    fn get_account_ids(&self) -> Result<Vec<Self::AccountId>, Self::Error> { Err(unvirtualized("get_account_ids")) }
    fn get_account(&self, _account_id: Self::AccountId) -> Result<Option<Self::Account>, Self::Error> { Err(unvirtualized("get_account")) }
    fn get_derived_account(&self, _derivation: &Zip32Derivation) -> Result<Option<Self::Account>, Self::Error> { Err(unvirtualized("get_derived_account")) }
    fn validate_seed(&self, _account_id: Self::AccountId, _seed: &SecretVec<u8>) -> Result<bool, Self::Error> { Err(unvirtualized("validate_seed")) }
    fn seed_relevance_to_derived_accounts(&self, _seed: &SecretVec<u8>) -> Result<SeedRelevance<Self::AccountId>, Self::Error> { Err(unvirtualized("seed_relevance_to_derived_accounts")) }
    fn get_account_for_ufvk(&self, _ufvk: &UnifiedFullViewingKey) -> Result<Option<Self::Account>, Self::Error> { Err(unvirtualized("get_account_for_ufvk")) }
    fn list_addresses(&self, _account: Self::AccountId) -> Result<Vec<AddressInfo>, Self::Error> { Err(unvirtualized("list_addresses")) }
    fn find_account_for_address<P: zcash_protocol::consensus::Parameters>(&self, _params: &P, _address: &zcash_keys::address::Address) -> Result<Option<Self::AccountId>, FindAccountForAddressError<Self::Error>> { Err(FindAccountForAddressError::Backend(unvirtualized("find_account_for_address"))) }
    fn get_last_generated_address_matching(&self, _account: Self::AccountId, _address_filter: UnifiedAddressRequest) -> Result<Option<UnifiedAddress>, Self::Error> { Err(unvirtualized("get_last_generated_address_matching")) }
    fn get_account_birthday(&self, _account: Self::AccountId) -> Result<BlockHeight, Self::Error> { Err(unvirtualized("get_account_birthday")) }
    fn get_wallet_birthday(&self) -> Result<Option<BlockHeight>, Self::Error> { Err(unvirtualized("get_wallet_birthday")) }
    fn get_wallet_summary(&self, _confirmations_policy: ConfirmationsPolicy) -> Result<Option<WalletSummary<Self::AccountId>>, Self::Error> { Err(unvirtualized("get_wallet_summary")) }
    fn chain_height(&self) -> Result<Option<BlockHeight>, Self::Error> { Err(unvirtualized("chain_height")) }
    fn get_block_hash(&self, _block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error> { Err(unvirtualized("get_block_hash")) }
    fn block_fully_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> { Err(unvirtualized("block_fully_scanned")) }
    fn get_max_height_hash(&self) -> Result<Option<(BlockHeight, BlockHash)>, Self::Error> { Err(unvirtualized("get_max_height_hash")) }
    fn block_max_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> { Err(unvirtualized("block_max_scanned")) }
    fn suggest_scan_ranges(&self) -> Result<Vec<ScanRange>, Self::Error> { Err(unvirtualized("suggest_scan_ranges")) }
    fn get_target_and_anchor_heights(&self, _min_confirmations: NonZeroU32) -> Result<Option<(TargetHeight, BlockHeight)>, Self::Error> { Err(unvirtualized("get_target_and_anchor_heights")) }
    fn get_tx_height(&self, _txid: TxId) -> Result<Option<BlockHeight>, Self::Error> { Err(unvirtualized("get_tx_height")) }
    fn get_memo(&self, _note_id: NoteId) -> Result<Option<Memo>, Self::Error> { Err(unvirtualized("get_memo")) }
    fn get_transaction(&self, _txid: TxId) -> Result<Option<Transaction>, Self::Error> { Err(unvirtualized("get_transaction")) }
    fn get_transparent_receivers(&self, _account: Self::AccountId, _include_change: bool, _include_standalone: bool) -> Result<HashMap<TransparentAddress, TransparentAddressMetadata>, Self::Error> { Err(unvirtualized("get_transparent_receivers")) }
    fn get_ephemeral_transparent_receivers(&self, _account: Self::AccountId, _exposure_depth: u32, _exclude_used: bool) -> Result<HashMap<TransparentAddress, TransparentAddressMetadata>, Self::Error> { Err(unvirtualized("get_ephemeral_transparent_receivers")) }
    fn get_transparent_balances(&self, _account: Self::AccountId, _target_height: TargetHeight, _confirmations_policy: ConfirmationsPolicy) -> Result<TransparentBalances, Self::Error> { Err(unvirtualized("get_transparent_balances")) }
    fn get_transparent_address_metadata(&self, _account: Self::AccountId, _address: &TransparentAddress) -> Result<Option<TransparentAddressMetadata>, Self::Error> { Err(unvirtualized("get_transparent_address_metadata")) }
    fn utxo_query_height(&self, _account: Self::AccountId) -> Result<BlockHeight, Self::Error> { Err(unvirtualized("utxo_query_height")) }
    fn transaction_data_requests(&self) -> Result<Vec<TransactionDataRequest>, Self::Error> { Err(unvirtualized("transaction_data_requests")) }
    fn get_received_outputs(&self, _txid: TxId, _target_height: TargetHeight, _confirmations_policy: ConfirmationsPolicy) -> Result<Vec<ReceivedTransactionOutput>, Self::Error> { Err(unvirtualized("get_received_outputs")) }
}

impl WalletWrite for WriteBehindFacade {
    type UtxoRef = <Db as WalletWrite>::UtxoRef;

    // THE INTERCEPT: stash instead of committing; advance the virtualized reads.
    fn put_blocks(&mut self, from_state: &ChainState, blocks: Vec<ScannedBlock<Self::AccountId>>) -> Result<(), Self::Error> {
        // Depth-1 invariant FIRST: an occupied stash means the scan loop failed
        // to submit the previous unit — a loop bug, never tolerated silently.
        if self.stash.is_some() {
            return Err(SqliteClientError::CorruptedData(
                "write-behind facade: put_blocks with an occupied stash — depth-1 invariant violated".into(),
            ));
        }
        // Upstream parity: empty input is a no-op (ll/wallet.rs:245-247).
        let (Some(first), Some(last)) = (blocks.first(), blocks.last()) else {
            return Ok(());
        };
        let first_height = u64::from(u32::from(first.height()));
        let last_height = u64::from(u32::from(last.height()));

        // Advance the virtualized prior-block metadata to this unit's tail —
        // identical to upstream's intra-call threading (chain.rs:653).
        self.prior_meta_height = last.height();
        self.prior_meta = Some(last.to_block_metadata());

        // Advance both running nullifier views per block, in block order
        // (upstream update_with parity: retain spends, then extend with found
        // notes whose nullifiers are known — scanning.rs:435-464).
        for b in &blocks {
            let sap_spent: Vec<sapling::Nullifier> = b
                .transactions()
                .iter()
                .flat_map(|tx| tx.sapling_spends().iter().map(|s| *s.nf()))
                .collect();
            let sap_found: Vec<(Self::AccountId, sapling::Nullifier)> = b
                .transactions()
                .iter()
                .flat_map(|tx| tx.sapling_outputs().iter().filter_map(|o| o.nf().map(|nf| (*o.account_id(), *nf))))
                .collect();
            apply_nullifier_delta(&mut self.sapling_nfs, &sap_spent, &sap_found);

            let orch_spent: Vec<orchard::note::Nullifier> = b
                .transactions()
                .iter()
                .flat_map(|tx| tx.orchard_spends().iter().map(|s| *s.nf()))
                .collect();
            let orch_found: Vec<(Self::AccountId, orchard::note::Nullifier)> = b
                .transactions()
                .iter()
                .flat_map(|tx| tx.orchard_outputs().iter().filter_map(|o| o.nf().map(|nf| (*o.account_id(), *nf))))
                .collect();
            apply_nullifier_delta(&mut self.orchard_nfs, &orch_spent, &orch_found);
        }

        self.stash = Some(PendingPersist {
            from_state: from_state.clone(),
            blocks,
            first_height,
            last_height,
        });
        Ok(())
    }

    // ── Outside the scan write surface: fail loudly ────────────────────────────
    fn create_account(&mut self, _account_name: &str, _seed: &SecretVec<u8>, _birthday: &AccountBirthday, _key_source: Option<&str>) -> Result<(Self::AccountId, UnifiedSpendingKey), Self::Error> { Err(unvirtualized("create_account")) }
    fn import_account_hd(&mut self, _account_name: &str, _seed: &SecretVec<u8>, _account_index: zip32::AccountId, _birthday: &AccountBirthday, _key_source: Option<&str>) -> Result<(Self::Account, UnifiedSpendingKey), Self::Error> { Err(unvirtualized("import_account_hd")) }
    fn import_account_ufvk(&mut self, _account_name: &str, _unified_key: &UnifiedFullViewingKey, _birthday: &AccountBirthday, _purpose: AccountPurpose, _key_source: Option<&str>) -> Result<Self::Account, Self::Error> { Err(unvirtualized("import_account_ufvk")) }
    fn delete_account(&mut self, _account: Self::AccountId) -> Result<(), Self::Error> { Err(unvirtualized("delete_account")) }
    fn get_next_available_address(&mut self, _account: Self::AccountId, _request: UnifiedAddressRequest) -> Result<Option<(UnifiedAddress, DiversifierIndex)>, Self::Error> { Err(unvirtualized("get_next_available_address")) }
    fn get_address_for_index(&mut self, _account: Self::AccountId, _diversifier_index: DiversifierIndex, _request: UnifiedAddressRequest) -> Result<Option<UnifiedAddress>, Self::Error> { Err(unvirtualized("get_address_for_index")) }
    fn update_chain_tip(&mut self, _tip_height: BlockHeight) -> Result<(), Self::Error> { Err(unvirtualized("update_chain_tip")) }
    fn put_received_transparent_utxo(&mut self, _output: &WalletTransparentOutput) -> Result<Self::UtxoRef, Self::Error> { Err(unvirtualized("put_received_transparent_utxo")) }
    fn store_decrypted_tx(&mut self, _received_tx: DecryptedTransaction<Transaction, Self::AccountId>) -> Result<(), Self::Error> { Err(unvirtualized("store_decrypted_tx")) }
    fn set_tx_trust(&mut self, _txid: TxId, _trusted: bool) -> Result<(), Self::Error> { Err(unvirtualized("set_tx_trust")) }
    fn store_transactions_to_be_sent(&mut self, _transactions: &[SentTransaction<Self::AccountId>]) -> Result<(), Self::Error> { Err(unvirtualized("store_transactions_to_be_sent")) }
    fn truncate_to_height(&mut self, _max_height: BlockHeight) -> Result<BlockHeight, Self::Error> { Err(unvirtualized("truncate_to_height")) }
    fn truncate_to_chain_state(&mut self, _chain_state: ChainState) -> Result<(), Self::Error> { Err(unvirtualized("truncate_to_chain_state")) }
    fn rewind_to_height(&mut self, _max_height: BlockHeight) -> Result<BlockHeight, Self::Error> { Err(unvirtualized("rewind_to_height")) }
    fn reserve_next_n_ephemeral_addresses(&mut self, _account_id: Self::AccountId, _n: usize) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, Self::Error> { Err(unvirtualized("reserve_next_n_ephemeral_addresses")) }
    fn set_transaction_status(&mut self, _txid: TxId, _status: TransactionStatus) -> Result<(), Self::Error> { Err(unvirtualized("set_transaction_status")) }
    fn schedule_next_check(&mut self, _address: &TransparentAddress, _offset_seconds: u32) -> Result<Option<SystemTime>, Self::Error> { Err(unvirtualized("schedule_next_check")) }
    fn mark_transparent_addresses_exposed(&mut self, _exposures: &[(TransparentAddress, BlockHeight)]) -> Result<(), Self::Error> { Err(unvirtualized("mark_transparent_addresses_exposed")) }
    fn notify_address_checked(&mut self, _request: TransactionsInvolvingAddress, _as_of_height: BlockHeight) -> Result<(), Self::Error> { Err(unvirtualized("notify_address_checked")) }
}

// ── Persist lane ───────────────────────────────────────────────────────────────

/// T6.9b — Thread count for the lane's DEDICATED rayon pool.
///
/// Why 2, not 1:
///   The per-pool `rayon::join` inside `sparse_put_blocks` dispatches the
///   sapling and orchard tree pipelines in PARALLEL (T6.8-L3a). With 1 lane
///   thread, `join` degenerates to serial (left closure runs inline; right
///   waits) — identical to before L3a on the lane. With 2 lane threads, both
///   closures run concurrently inside the lane pool, preserving the ≈10–15%
///   intra-commit parallelism measured at T6.8-L3a while still being fully
///   isolated from the decrypt pool.
///
/// Why not more:
///   The lane executes EXACTLY ONE commit at a time (depth-1 backpressure is
///   structural). Adding a third thread adds no further in-commit parallelism
///   (only 2 independent sub-tasks exist — sap + orch join); it would merely
///   gift spare CPU to the commit while the decrypt side is already competing
///   for the same cores. On a 4-core A10 the budget is 4 threads total; we
///   want the lane to occupy at most 2 so decrypt can fill the other 2.
///
/// Why a DEDICATED pool at all (T6.9b contention fix):
///   Before this change, `rayon::join` in `sparse_put_blocks` used the GLOBAL
///   pool — the same pool the concurrent decrypt tasks (zcash_client_backend
///   BatchRunners, rayon::spawn_fifo) saturate. On a 4-core A10, field
///   evidence (T6.9 iPad log 2026-06-13) showed the lane's tree work queuing
///   behind decrypt tasks: tree wall 12.9s vs per-pool sum 6.7s on one chunk
///   (≈60% inflation due to scheduling contention); depth-1 persist_wait
///   inflated to 259s over the pass, reducing the write-behind benefit by ≈200s.
///   With a lane-owned pool, ALL rayon work inside the commit closure — the
///   `rayon::join` itself AND upstream's `build_subtrees`' `par_chunks` — lands
///   on the lane's 2 threads, never touching the global pool's decrypt workers.
const LANE_POOL_THREADS: usize = 2;

/// Saturation threshold for the lane-pool policy: at or below this many cores,
/// the global rayon pool is assumed decrypt-saturated during overlap.
const LANE_ISOLATION_MAX_CORES: usize = 4;

/// T6.9b2 — saturation-aware lane-pool policy.
///
/// The T6.9 field data cuts both ways: on the 4-core A10 the shared global
/// pool produced ~60% lane-busy inflation (queueing behind decrypt), so a
/// dedicated small pool helps; but on a 10-core Mac the SAME dedicated
/// 2-thread pool starved `build_subtrees` and DOUBLED scan_s (5.58→11.23s
/// measured) because the global pool there has idle capacity the lane should
/// use. Policy: isolate (Some(2)) only on low-core machines where decrypt
/// saturates everything (≤ LANE_ISOLATION_MAX_CORES logical cores); share the
/// global pool (None) elsewhere. A heuristic, honestly labeled: core count is
/// a proxy for "decrypt saturates the pool", which held in every measurement
/// to date (A10=4 pathological, iPhone 6-core and Mac 10-core healthy shared).
fn lane_pool_policy() -> Option<usize> {
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    if cores <= LANE_ISOLATION_MAX_CORES { Some(LANE_POOL_THREADS) } else { None }
}

/// A deferred-commit job: runs against the lane's Db + tree state on a blocking
/// thread. Boxed so lane mechanics (serial order, depth-1 backpressure, error
/// propagation, drain) are unit-testable without `ScannedBlock` values.
pub(crate) type PersistJob =
    Box<dyn FnOnce(&mut Db, &mut SparseTreeState) -> Result<(), SqliteClientError> + Send>;

/// What a finished commit task hands back: lane ownership (Db + tree state)
/// plus the commit's wall time (or its error).
type PersistTaskOutput = (Db, SparseTreeState, Result<std::time::Duration, SqliteClientError>);

/// The write-behind persist lane: owns a SECOND `WalletDb` connection to the
/// same wallet file (WAL), the per-range `SparseTreeState`, and a DEDICATED
/// rayon thread pool (T6.9b, `LANE_POOL_THREADS` = 2). Runs at most ONE
/// deferred commit at a time via `spawn_blocking` (ownership ping-pongs
/// through the task — serialization is structural, not advisory).
///
/// Thread-pool isolation (T6.9b): every commit closure runs via
/// `lane_pool.install(|| …)`. Rayon scoping guarantees ALL nested rayon usage
/// inside — the `rayon::join` (T6.8-L3a) AND upstream `build_subtrees`'
/// `par_chunks` — lands on the lane's 2-thread pool, never on the global
/// pool that decrypt workers saturate. This eliminates the scheduling-
/// contention inflation observed on the 4-core A10 (T6.9 field evidence).
///
/// The INLINE path (write_behind=false) is UNTOUCHED: it calls
/// `sparse_put_blocks` directly (no `spawn_blocking`, no lane pool) so its
/// `rayon::join` keeps using the global pool — inline persist never runs
/// concurrently with decrypt, so there is no pool-queueing pathology there.
///
/// No concurrent-writer hazard by design: while a commit is in flight the scan
/// side performs ZERO database work (all its reads are virtualized by
/// `WriteBehindFacade`), and every other DB user (enhancement, reorg truncate,
/// suggest, summary) runs only behind a `drain()` barrier.
///
/// Failure semantics: a commit error is returned by the NEXT `submit` (or by
/// `drain`), always BEFORE another unit is submitted — the range aborts with
/// the last successful commit fully durable (atomic per-unit transactions).
/// A panic inside a commit task loses the lane connection (`db: None`); any
/// further use errors loudly and the pass fails — the wallet file itself stays
/// consistent (SQLite rolls back the open transaction when the connection drops).
pub struct PersistLane {
    db: Option<Db>,
    sparse: Option<SparseTreeState>,
    /// Dedicated rayon pool (T6.9b), present only when `lane_pool_policy()`
    /// says to isolate (low-core saturated machines). `None` = commits use the
    /// global pool (measured-best on ≥6-core machines — see T6.9b2 policy doc).
    /// Arc so it can be moved into `spawn_blocking` closures cheaply.
    lane_pool: Option<std::sync::Arc<rayon::ThreadPool>>,
    /// [B4-16 drain] When attached (production scan path), every deferred commit holds a
    /// [`crate::events::WalletWriterGate`] for its WHOLE life (tree compute + DB txn), so
    /// the FFI stop()/start() drain can wait out an orphan commit that `task.abort()`
    /// cannot cancel — field-caught landing its Scanned-mark AFTER an importAccount's
    /// force-rescan re-queue, and colliding with the next pass's first writes.
    progress: Option<crate::events::ProgressArc>,
    in_flight: Option<tokio::task::JoinHandle<PersistTaskOutput>>,
    /// (first_height, last_height) of the in-flight unit, for log attribution.
    in_flight_span: (u64, u64),
    /// Depth-N write-behind buffer: pending units not yet spawned. At most ONE
    /// runs at a time (`in_flight`); up to `depth` total may be unpersisted
    /// (in_flight + queued) before the scan side blocks at `submit`. Persist stays
    /// serial + in-order, so deepening this NEVER changes the committed `data.db` —
    /// it only lets scan run further ahead, hiding more persist behind scan.
    queue: std::collections::VecDeque<((u64, u64), PersistJob)>,
    /// Max unpersisted units (in_flight + queued) before `submit` blocks the scan
    /// side. 1 = strict depth-1 backpressure (legacy, byte-for-byte identical
    /// behaviour); higher = scan runs further ahead (memory cost: ≤`depth` buffered
    /// units, each ≈ one chunk's scanned blocks + commitments).
    depth: usize,
    /// Σ scan-side blocked time across all awaits (0 ≈ perfect overlap).
    total_wait: std::time::Duration,
    /// Σ commit wall time measured inside the deferred closures.
    total_busy: std::time::Duration,
}

impl PersistLane {
    /// Open the lane's own connection to the (already-migrated) wallet file.
    pub fn open(
        wallet_db_path: &std::path::Path,
        network: zcash_protocol::consensus::Network,
        depth: usize,
    ) -> Result<Self, crate::error::SlipstreamError> {
        // [B4-16] Same wait-not-die posture as the main connection (wallet_session.rs): a
        // host write (importAccount landing mid-pass) holding the lock made the lane's
        // deferred commit die with an instant SQLITE_BUSY — a NON-transient pass error.
        // Mirror `for_path` (open + array vtab + wrap) with a 15 s busy_timeout.
        let lane_conn = rusqlite::Connection::open(wallet_db_path)
            .map_err(|e| crate::error::SlipstreamError::Wallet(format!("persist lane open: {e}")))?;
        lane_conn
            .busy_timeout(std::time::Duration::from_secs(15))
            .map_err(|e| {
                crate::error::SlipstreamError::Wallet(format!("persist lane busy_timeout: {e}"))
            })?;
        rusqlite::vtab::array::load_module(&lane_conn).map_err(|e| {
            crate::error::SlipstreamError::Wallet(format!("persist lane array module: {e}"))
        })?;
        let db = zcash_client_sqlite::WalletDb::from_connection(
            lane_conn,
            network,
            zcash_client_sqlite::util::SystemClock,
            rand::rngs::OsRng,
        );
        let lane_pool = Self::build_lane_pool(lane_pool_policy())?;
        Ok(Self {
            db: Some(db),
            sparse: Some(SparseTreeState::default()),
            lane_pool,
            progress: None,
            in_flight: None,
            in_flight_span: (0, 0),
            queue: std::collections::VecDeque::new(),
            depth: depth.max(1),
            total_wait: std::time::Duration::ZERO,
            total_busy: std::time::Duration::ZERO,
        })
    }

    /// [B4-16 drain] Attach the handle's shared progress so every deferred commit holds
    /// the writer gate for its whole life. The production scan path attaches; oracle and
    /// test drivers (no stop()/start() drain to serve) may skip.
    pub fn attach_writer_gate(&mut self, progress: crate::events::ProgressArc) {
        self.progress = Some(progress);
    }

    /// Build the optional dedicated lane pool per the given policy.
    /// Factored out so tests can exercise both branches deterministically.
    fn build_lane_pool(
        threads: Option<usize>,
    ) -> Result<Option<std::sync::Arc<rayon::ThreadPool>>, crate::error::SlipstreamError> {
        match threads {
            None => Ok(None),
            Some(n) => Ok(Some(std::sync::Arc::new(
                rayon::ThreadPoolBuilder::new()
                    .num_threads(n)
                    .thread_name(|i| format!("slipstream-lane-{i}"))
                    .build()
                    .map_err(|e| {
                        crate::error::SlipstreamError::Wallet(format!(
                            "persist lane pool build: {e}"
                        ))
                    })?,
            ))),
        }
    }

    pub fn total_wait(&self) -> std::time::Duration {
        self.total_wait
    }

    pub fn total_busy(&self) -> std::time::Duration {
        self.total_busy
    }

    /// v0.4 census (spec §3.2): per-pool shard census accumulated by this lane's
    /// sparse state — (sapling, orchard). Meaningful after `drain()` (lane
    /// quiescent); zeros if the state is checked out mid-commit or never used.
    pub fn census(&self) -> (crate::census::ShardCensus, crate::census::ShardCensus) {
        match &self.sparse {
            Some(s) => (s.census_sapling.clone(), s.census_orchard.clone()),
            None => Default::default(),
        }
    }

    /// Await the in-flight commit, if any (the full barrier when called alone —
    /// see `drain`). Accounts `persist_wait` (scan-side blocked time) and
    /// `persist_busy` (commit wall time), restores Db + tree ownership to the
    /// lane, and propagates the commit's error.
    async fn await_in_flight(&mut self) -> Result<(), crate::error::SlipstreamError> {
        if let Some(handle) = self.in_flight.take() {
            let (first_height, last_height) = self.in_flight_span;
            let waited = std::time::Instant::now();
            let (db, sparse, result) = handle.await.map_err(|e| {
                crate::error::SlipstreamError::Wallet(format!(
                    "write-behind persist task died (panic/cancel): {e}"
                ))
            })?;
            let persist_wait_ms = waited.elapsed().as_millis();
            self.total_wait += waited.elapsed();
            self.db = Some(db);
            self.sparse = Some(sparse);
            let busy = result.map_err(|e| {
                crate::error::SlipstreamError::Wallet(format!(
                    "write-behind deferred put_blocks [{first_height}..={last_height}]: {e}"
                ))
            })?;
            self.total_busy += busy;
            info!(
                persist_wait_ms,
                persist_busy_ms = busy.as_millis(),
                first_height,
                last_height,
                "write-behind persist awaited"
            );
        }
        Ok(())
    }

    /// Total unpersisted units: the in-flight commit (if any) + the queued ones.
    fn pending_count(&self) -> usize {
        usize::from(self.in_flight.is_some()) + self.queue.len()
    }

    /// Spawn the head of the queue IF the lane is idle. No-op when a commit is
    /// already in flight or the queue is empty. Errors loudly if the lane
    /// connection was lost (poisoned by an earlier panic).
    ///
    /// T6.9b: the job runs via `lane_pool.install(|| …)` so ALL nested rayon usage
    /// inside `sparse_put_blocks` (the `rayon::join` for sapling∥orchard and
    /// upstream `build_subtrees`' `par_chunks`) lands on the lane's dedicated pool.
    fn spawn_next(&mut self) -> Result<(), crate::error::SlipstreamError> {
        if self.in_flight.is_some() {
            return Ok(());
        }
        let Some((span, job)) = self.queue.pop_front() else {
            return Ok(());
        };
        let (Some(mut db), Some(mut sparse)) = (self.db.take(), self.sparse.take()) else {
            return Err(crate::error::SlipstreamError::Wallet(
                "write-behind persist lane unusable (connection lost by an earlier failure)".into(),
            ));
        };
        // Arc::clone so the spawn_blocking closure can own a reference to the
        // lane pool without borrowing `self`.  Cheap (atomic ref-count bump).
        let pool = self.lane_pool.clone();
        // [B4-16 drain] Acquired BEFORE the spawn (no window where the commit exists but
        // the counter reads 0) and moved into the closure — held across compute + txn,
        // released by Drop on completion or panic.
        let gate = self.progress.clone().map(crate::events::WalletWriterGate::hold);
        self.in_flight_span = span;
        self.in_flight = Some(tokio::task::spawn_blocking(move || {
            let _gate = gate;
            let started = std::time::Instant::now();
            let result = match pool {
                Some(p) => p.install(|| job(&mut db, &mut sparse)),
                None => job(&mut db, &mut sparse),
            }
            .map(|()| started.elapsed());
            (db, sparse, result)
        }));
        Ok(())
    }

    /// Submit one deferred commit job into the depth-N buffer. Persist stays
    /// serial + IN-ORDER (one commit at a time) — so deepening the buffer never
    /// changes the committed `data.db`. The scan side blocks ONLY once `depth`
    /// units are unpersisted (in_flight + queued). At `depth == 1` this is the
    /// legacy strict depth-1 backpressure: submit(N+1) awaits (and error-propagates)
    /// unit N before spawning N+1 — byte-for-byte identical to the pre-queue lane.
    ///
    /// A commit error aborts the pipeline: the in-flight error is propagated and
    /// the remaining queued units are DROPPED (the range fails; never spawned).
    pub(crate) async fn submit_job(
        &mut self,
        span: (u64, u64),
        job: PersistJob,
    ) -> Result<(), crate::error::SlipstreamError> {
        self.queue.push_back((span, job));
        // Start the next unit immediately if the lane is idle.
        self.spawn_next()?;
        // Backpressure: await + reap + spawn-next until we are at/under `depth`.
        while self.pending_count() > self.depth {
            if let Err(e) = self.await_in_flight().await {
                self.queue.clear();
                return Err(e);
            }
            self.spawn_next()?;
        }
        Ok(())
    }

    /// Submit one pending scan unit: the deferred commit runs the EXACT
    /// `sparse_put_blocks` logic (rows + tree + flush in one transaction).
    pub async fn submit(&mut self, pending: PendingPersist) -> Result<(), crate::error::SlipstreamError> {
        let span = (pending.first_height, pending.last_height);
        self.submit_job(
            span,
            Box::new(move |db, sparse| {
                sparse_put_blocks(db, sparse, &pending.from_state, pending.blocks)
            }),
        )
        .await
    }

    /// Full barrier: drain the ENTIRE pending queue (await each in-flight commit,
    /// spawn the next, in order) and propagate the first error. After `drain`
    /// returns Ok, every submitted unit is durably committed — required before
    /// enhancement, reorg recovery, suggest, summary, and at range end. A commit
    /// error drops the remaining queued units and propagates. At `depth == 1` (and
    /// any time ≤1 unit is pending) this is exactly the legacy single await.
    pub async fn drain(&mut self) -> Result<(), crate::error::SlipstreamError> {
        while self.pending_count() > 0 {
            if let Err(e) = self.await_in_flight().await {
                self.queue.clear();
                return Err(e);
            }
            self.spawn_next()?;
        }
        Ok(())
    }
}

// ── Contract tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod store_tests {
    use super::*;
    use incrementalmerkletree::{Address, Hashable as _};

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
        let tree = LocatedPrunableTree::empty(addr);
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

    // ── T6.3b checkpoint-downgrade helpers ─────────────────────────────────────

    fn heights(range: std::ops::RangeInclusive<u32>) -> impl Iterator<Item = BlockHeight> {
        range.map(BlockHeight::from)
    }

    #[test]
    fn doomed_cutoff_none_when_window_not_exceeded() {
        // 50 existing + frontier + 40 new = 91 distinct ids ≤ 100 → nothing doomed.
        let cutoff = doomed_checkpoint_cutoff(
            heights(1..=50),
            BlockHeight::from(50),
            heights(51..=90),
        );
        assert_eq!(cutoff, None);
    }

    #[test]
    fn doomed_cutoff_is_upstream_retained_min_for_dense_stream() {
        // 100 existing (heights 1..=100, frontier = 100) + 10_000 new
        // (101..=10_100): upstream retains the newest 100 = 10_001..=10_100,
        // i.e. the controller cutoff last_scanned − (WINDOW − 1).
        let cutoff = doomed_checkpoint_cutoff(
            heights(1..=100),
            BlockHeight::from(100),
            heights(101..=10_100),
        );
        assert_eq!(cutoff, Some(BlockHeight::from(10_001)));
    }

    #[test]
    fn doomed_cutoff_reaches_below_window_for_sparse_stream() {
        // A pool with only 30 new checkpoints: upstream's newest-100 keeps 70
        // older ids alive — the cutoff must NOT be last_scanned − 100.
        let cutoff = doomed_checkpoint_cutoff(
            heights(1..=100),
            BlockHeight::from(100),
            heights(10_071..=10_100),
        );
        // union = {1..=100} ∪ {10_071..=10_100} (130 ids); newest 100 =
        // {31..=100} ∪ {10_071..=10_100} → min = 31.
        assert_eq!(cutoff, Some(BlockHeight::from(31)));
    }

    #[test]
    fn downgrade_maps_marked_to_marked_and_plain_to_ephemeral() {
        let h = |n: u32| BlockHeight::from(n);
        let node = sapling::Node::empty_leaf();
        let mut commitments: Vec<Option<(sapling::Node, Retention<BlockHeight>)>> = vec![
            Some((node, Retention::Checkpoint { id: h(10), marking: Marking::Marked })),
            Some((node, Retention::Checkpoint { id: h(11), marking: Marking::None })),
            Some((node, Retention::Checkpoint { id: h(50), marking: Marking::None })),
            Some((node, Retention::Marked)),
            Some((node, Retention::Ephemeral)),
        ];
        let n = downgrade_doomed_checkpoints(&mut commitments, h(50));
        assert_eq!(n, 2);
        assert!(matches!(commitments[0].as_ref().unwrap().1, Retention::Marked));
        assert!(matches!(commitments[1].as_ref().unwrap().1, Retention::Ephemeral));
        // id == cutoff survives (only ids strictly below are doomed).
        assert!(matches!(
            commitments[2].as_ref().unwrap().1,
            Retention::Checkpoint { .. }
        ));
        assert!(matches!(commitments[3].as_ref().unwrap().1, Retention::Marked));
        assert!(matches!(commitments[4].as_ref().unwrap().1, Retention::Ephemeral));
    }

    #[test]
    fn stream_checkpoint_positions_matches_from_iter_extraction() {
        let h = |n: u32| BlockHeight::from(n);
        let node = sapling::Node::empty_leaf();
        let commitments: Vec<Option<(sapling::Node, Retention<BlockHeight>)>> = vec![
            Some((node, Retention::Ephemeral)),
            Some((node, Retention::Checkpoint { id: h(7), marking: Marking::None })),
            Some((node, Retention::Marked)),
            Some((node, Retention::Checkpoint { id: h(8), marking: Marking::Marked })),
        ];
        let map = stream_checkpoint_positions(Position::from(100u64), &commitments);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&h(7)), Some(&Position::from(101u64)));
        assert_eq!(map.get(&h(8)), Some(&Position::from(103u64)));
    }
}

// ── T6.9 write-behind tests ────────────────────────────────────────────────────

#[cfg(test)]
mod write_behind_tests {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use super::*;
    use incrementalmerkletree::frontier::Frontier;

    // ── apply_nullifier_delta: upstream update_with parity (scanning.rs:435-464) ──

    #[test]
    fn nullifier_delta_removes_spent_and_adds_found() {
        let mut set: Vec<(u32, [u8; 4])> = vec![(1, *b"aaaa"), (1, *b"bbbb")];
        // Block: spends "aaaa", finds "cccc".
        apply_nullifier_delta(&mut set, &[*b"aaaa"], &[(1, *b"cccc")]);
        assert_eq!(set, vec![(1, *b"bbbb"), (1, *b"cccc")]);
    }

    /// THE pending-spend case: a note FOUND in (pending) chunk N must be
    /// spendable-detectable in chunk N+1 — its nullifier enters the view at the
    /// stash of N (found), and the spend in N+1 removes it.
    #[test]
    fn nullifier_found_in_pending_block_is_visible_then_spendable() {
        let mut set: Vec<(u32, [u8; 4])> = vec![];
        // Chunk N stash: note found.
        apply_nullifier_delta(&mut set, &[], &[(7, *b"note")]);
        assert_eq!(set, vec![(7, *b"note")], "found note must enter the unspent view");
        // Chunk N+1 stash: the same nullifier spent.
        apply_nullifier_delta(&mut set, &[*b"note"], &[]);
        assert!(set.is_empty(), "spent note must leave the unspent view");
    }

    /// Per-block ordering parity: retain happens BEFORE extend within one block,
    /// so a found-then-spent sequence across two block deltas behaves like
    /// upstream's per-block update_with stream.
    #[test]
    fn nullifier_delta_is_retain_then_extend_per_block() {
        let mut set: Vec<(u32, [u8; 4])> = vec![(1, *b"xxxx")];
        // Same block spends "xxxx" and finds "xxxx" again (degenerate, but
        // order-defining): retain removes first, extend re-adds.
        apply_nullifier_delta(&mut set, &[*b"xxxx"], &[(1, *b"xxxx")]);
        assert_eq!(set, vec![(1, *b"xxxx")]);
    }

    // ── WriteBehindFacade virtualized reads ────────────────────────────────────

    fn test_meta(height: u32) -> BlockMetadata {
        BlockMetadata::from_parts(
            BlockHeight::from(height),
            BlockHash([0xAB; 32]),
            Some(123),
            Some(45),
        )
    }

    #[test]
    fn facade_block_metadata_serves_the_virtualized_tail_only() {
        let f = WriteBehindFacade::test_new(BlockHeight::from(999u32), Some(test_meta(999)));
        let got = f.block_metadata(BlockHeight::from(999u32)).expect("tail height must serve");
        let got = got.expect("metadata present");
        assert_eq!(got.block_height(), BlockHeight::from(999u32));
        assert_eq!(got.block_hash(), BlockHash([0xAB; 32]));
        assert_eq!(got.sapling_tree_size(), Some(123));
        assert_eq!(got.orchard_tree_size(), Some(45));
        // Any other height is a loud error, never a stale read.
        let err = f.block_metadata(BlockHeight::from(998u32)).unwrap_err();
        assert!(err.to_string().contains("outside the virtualized tail"), "got: {err}");
    }

    #[test]
    fn facade_block_metadata_known_absent_returns_none() {
        // Fresh wallet, first range: the seeded row at range_start-1 may be
        // absent — upstream returns None there and skips the continuity check.
        let f = WriteBehindFacade::test_new(BlockHeight::from(500u32), None);
        let got = f.block_metadata(BlockHeight::from(500u32)).expect("seeded height");
        assert!(got.is_none());
    }

    #[test]
    fn facade_unspent_nullifiers_serve_the_running_view_and_all_is_loud() {
        let f = WriteBehindFacade::test_new(BlockHeight::from(1u32), None);
        assert!(f.get_sapling_nullifiers(NullifierQuery::Unspent).expect("unspent").is_empty());
        assert!(f.get_orchard_nullifiers(NullifierQuery::Unspent).expect("unspent").is_empty());
        let err = f.get_sapling_nullifiers(NullifierQuery::All).unwrap_err();
        assert!(err.to_string().contains("not part of the scan_cached_blocks read surface"));
    }

    #[test]
    fn facade_ufvk_cache_is_served() {
        let f = WriteBehindFacade::test_new(BlockHeight::from(1u32), None);
        assert!(f.get_unified_full_viewing_keys().expect("cached").is_empty());
    }

    #[test]
    fn facade_reads_outside_the_surface_fail_loudly() {
        let f = WriteBehindFacade::test_new(BlockHeight::from(1u32), None);
        let err = f.chain_height().unwrap_err();
        assert!(err.to_string().contains("not part of the scan_cached_blocks read surface"));
        let err = f.get_max_height_hash().unwrap_err();
        assert!(err.to_string().contains("get_max_height_hash"));
        let err = f.suggest_scan_ranges().unwrap_err();
        assert!(err.to_string().contains("suggest_scan_ranges"));
    }

    fn empty_chain_state(height: u32) -> ChainState {
        ChainState::new(
            BlockHeight::from(height),
            BlockHash([0u8; 32]),
            Frontier::empty(),
            Frontier::empty(),
        )
    }

    #[test]
    fn facade_put_blocks_rejects_occupied_stash() {
        let mut f = WriteBehindFacade::test_new(BlockHeight::from(1u32), None);
        // Occupy the stash (empty blocks Vec — ScannedBlock is not publicly
        // constructible; the guard fires before the empty-input early return).
        f.stash = Some(PendingPersist {
            from_state: empty_chain_state(1),
            blocks: vec![],
            first_height: 2,
            last_height: 2,
        });
        let err = f.put_blocks(&empty_chain_state(1), vec![]).unwrap_err();
        assert!(err.to_string().contains("depth-1 invariant violated"), "got: {err}");
        // Draining the stash restores put_blocks (empty input = upstream no-op).
        assert!(f.take_stash().is_some());
        f.put_blocks(&empty_chain_state(1), vec![]).expect("empty input is a no-op");
        assert!(f.take_stash().is_none(), "empty input must not stash");
    }

    #[test]
    fn facade_writes_outside_put_blocks_fail_loudly() {
        let mut f = WriteBehindFacade::test_new(BlockHeight::from(1u32), None);
        let err = WalletWrite::update_chain_tip(&mut f, BlockHeight::from(5u32)).unwrap_err();
        assert!(err.to_string().contains("update_chain_tip"));
        let err = f.truncate_to_height(BlockHeight::from(5u32)).unwrap_err();
        assert!(err.to_string().contains("truncate_to_height"));
    }

    // ── PersistLane: serial order, depth-1 backpressure, errors, drain ─────────

    fn lane(dir: &std::path::Path) -> PersistLane {
        PersistLane::open(
            &dir.join("lane.db"),
            zcash_protocol::consensus::Network::MainNetwork,
            1,
        )
        .expect("lane open")
    }

    /// T6.9b: the lane pool must be created with LANE_POOL_THREADS threads.
    /// Verifies that pool construction succeeds and that `install` executes
    /// inside the pool (observed thread count equals configured value).
    #[test]
    fn lane_pool_policy_branches() {
        // T6.9b2: both policy branches construct correctly.
        let isolated = PersistLane::build_lane_pool(Some(LANE_POOL_THREADS))
            .expect("isolated pool builds");
        let observed = isolated.expect("Some pool").current_num_threads();
        assert_eq!(
            observed, LANE_POOL_THREADS,
            "isolated lane pool must have LANE_POOL_THREADS={LANE_POOL_THREADS} threads, got {observed}"
        );
        let shared = PersistLane::build_lane_pool(None).expect("shared-policy builds");
        assert!(shared.is_none(), "None policy must mean global-pool sharing");
        // The runtime policy returns one of the two valid shapes for THIS machine
        // (None on ≥ 6-core machines: shared global pool).
        if let Some(n) = lane_pool_policy() {
            assert_eq!(n, LANE_POOL_THREADS);
        }
    }

    /// Depth-1 backpressure: submit(N+1) must complete unit N first — N+1's
    /// job can never start before N's job finished.
    #[tokio::test]
    async fn lane_submit_awaits_previous_before_spawning_next() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut lane = lane(dir.path());
        let log: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(vec![]));

        let l1 = Arc::clone(&log);
        lane.submit_job(
            (1, 1),
            Box::new(move |_db, _sparse| {
                l1.lock().expect("lock").push("job1-start");
                std::thread::sleep(Duration::from_millis(150));
                l1.lock().expect("lock").push("job1-end");
                Ok(())
            }),
        )
        .await
        .expect("submit 1");

        let submitted = Instant::now();
        let l2 = Arc::clone(&log);
        lane.submit_job(
            (2, 2),
            Box::new(move |_db, _sparse| {
                l2.lock().expect("lock").push("job2-start");
                Ok(())
            }),
        )
        .await
        .expect("submit 2");
        // submit(2) returned only after job1 completed (≥150ms blocked).
        assert!(
            submitted.elapsed() >= Duration::from_millis(140),
            "submit must block on the previous unit (depth-1), elapsed {:?}",
            submitted.elapsed()
        );
        lane.drain().await.expect("drain");

        let order = log.lock().expect("lock").clone();
        assert_eq!(order, vec!["job1-start", "job1-end", "job2-start"], "strictly serial");
        assert!(lane.total_wait() >= Duration::from_millis(140), "wait accounted");
        assert!(lane.total_busy() >= Duration::from_millis(140), "busy accounted");
    }

    /// A failed commit aborts the pipeline: the NEXT submit returns the error
    /// and never spawns its own job.
    #[tokio::test]
    async fn lane_error_propagates_before_next_submit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut lane = lane(dir.path());
        let ran2 = Arc::new(Mutex::new(false));

        lane.submit_job(
            (10, 19),
            Box::new(|_db, _sparse| {
                Err(SqliteClientError::CorruptedData("synthetic commit failure".into()))
            }),
        )
        .await
        .expect("submit of the failing unit itself succeeds");

        let r2 = Arc::clone(&ran2);
        let err = lane
            .submit_job(
                (20, 29),
                Box::new(move |_db, _sparse| {
                    *r2.lock().expect("lock") = true;
                    Ok(())
                }),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("synthetic commit failure"), "got: {err}");
        assert!(err.to_string().contains("10..=19"), "error names the failed unit: {err}");
        assert!(!*ran2.lock().expect("lock"), "unit N+1 must never run after N failed");
        lane.drain().await.expect("drain after error is a no-op (lane restored)");
    }

    /// drain() is the full barrier: it returns only after the in-flight commit
    /// finished, and propagates its error.
    #[tokio::test]
    async fn lane_drain_awaits_in_flight_and_propagates_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut lane = lane(dir.path());
        let done = Arc::new(Mutex::new(false));
        let d = Arc::clone(&done);
        lane.submit_job(
            (1, 5),
            Box::new(move |_db, _sparse| {
                std::thread::sleep(Duration::from_millis(120));
                *d.lock().expect("lock") = true;
                Ok(())
            }),
        )
        .await
        .expect("submit");
        lane.drain().await.expect("drain");
        assert!(*done.lock().expect("lock"), "drain returned before the commit finished");

        // Error path.
        lane.submit_job(
            (6, 9),
            Box::new(|_db, _sparse| Err(SqliteClientError::CorruptedData("late failure".into()))),
        )
        .await
        .expect("submit");
        let err = lane.drain().await.unwrap_err();
        assert!(err.to_string().contains("late failure"));
    }

    #[tokio::test]
    async fn lane_drain_when_idle_is_ok() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut lane = lane(dir.path());
        lane.drain().await.expect("idle drain");
        assert_eq!(lane.total_wait(), Duration::ZERO);
    }

    /// A panicking commit task surfaces as an error and poisons the lane
    /// (connection moved into the dead task) — further submits fail loudly.
    #[tokio::test]
    async fn lane_panic_is_an_error_and_poisons_the_lane() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut lane = lane(dir.path());
        lane.submit_job((1, 1), Box::new(|_db, _sparse| panic!("synthetic panic")))
            .await
            .expect("submit");
        let err = lane.drain().await.unwrap_err();
        assert!(err.to_string().contains("persist task died"), "got: {err}");
        let err = lane
            .submit_job((2, 2), Box::new(|_db, _sparse| Ok(())))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("lane unusable"), "got: {err}");
    }
}
