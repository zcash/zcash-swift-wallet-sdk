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
                // mirror of upstream; structurally infallible (each Option is taken exactly once)
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

// ── Contract tests ─────────────────────────────────────────────────────────────

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
}
