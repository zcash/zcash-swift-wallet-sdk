//! Persistent wallet session: ONE WalletDb for the whole sync (decision D2/D3 —
//! unchanged zcash_client_sqlite data model), WAL set on the file before open,
//! migrations run once, chain-state ops (subtree roots, chain tip, scan ranges)
//! and keyless account import (UFVK only, decision D6).

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use tracing::info;
use zcash_client_backend::data_api::{
    AccountBirthday, AccountPurpose, WalletCommitmentTrees, WalletRead, WalletWrite,
    scanning::ScanRange,
};
use zcash_client_backend::proto::service::TreeState;
use zcash_client_sqlite::WalletDb;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::{BlockHeight, Network};

use crate::{error::SlipstreamError, grpc::SubtreeRoots};

// Mirror rust/src/lib.rs:132 — same generics, same clock/rng.
pub(crate) type Db = WalletDb<Connection, Network, zcash_client_sqlite::util::SystemClock, rand::rngs::OsRng>;

pub struct WalletSession {
    pub network: Network,
    db: Db,
    // Used by seed_block_metadata (cfg(any(test, feature = "darkside")) only).
    #[cfg_attr(not(any(test, feature = "darkside")), allow(dead_code))]
    db_path: PathBuf,
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
            // [audit ENG-1] busy_timeout is per-CONNECTION (never persisted in the file): set it on
            // every connection we open, so a WAL checkpoint or the Swift SDK's concurrent reader
            // (which carries its own 5s timeout) surfaces as a short wait, never an instant
            // SQLITE_BUSY error. The main WalletDb connection is opened internally by
            // zcash_client_sqlite (no public conn access); single-writer discipline makes writer
            // contention impossible there — these side connections are the ones that can race.
            conn.busy_timeout(std::time::Duration::from_secs(5))
                .map_err(|e| wallet_err("set busy_timeout", e))?;
            // Note 1: pragma_update_and_check in rusqlite 0.37 takes Option<&str> for schema_name
            // (not Option<DatabaseName> as in older versions) — plan code compiles as-written.
            let mode: String = conn
                .pragma_update_and_check(None, "journal_mode", "wal", |row| row.get(0))
                .map_err(|e| wallet_err("set WAL", e))?;
            info!(%mode, "journal mode");
            conn.pragma_update(None, "synchronous", "NORMAL")
                .map_err(|e| wallet_err("set synchronous", e))?;
        }
        // [B4-12 / ZRUST0096] Open the MAIN wallet connection ourselves so it gets a
        // busy_timeout — upstream's `for_path` sets NONE, so any competing writer (a host
        // `importAccount` landing mid-pass, or a restart's orphaned write-behind commit:
        // `spawn_blocking` is uncancellable by abort, so it can outlive the pass that
        // spawned it) surfaced as an immediate SQLITE_BUSY → non-transient Wallet error →
        // Error state (the Keystone delete→re-import field failure, 2026-07-02). 15 s —
        // the worst observed device commit is a few seconds (A10): WAITING beats dying.
        // Mirrors upstream `for_path` otherwise (array vtab module, then wrap).
        let wallet_conn = Connection::open(db_path).map_err(|e| wallet_err("open wallet db", e))?;
        wallet_conn
            .busy_timeout(std::time::Duration::from_secs(15))
            .map_err(|e| wallet_err("set busy_timeout (wallet)", e))?;
        rusqlite::vtab::array::load_module(&wallet_conn)
            .map_err(|e| wallet_err("load array vtab", e))?;
        let mut db = WalletDb::from_connection(
            wallet_conn,
            network,
            zcash_client_sqlite::util::SystemClock,
            rand::rngs::OsRng,
        );
        zcash_client_sqlite::wallet::init::init_wallet_db(&mut db, None)
            .map_err(|e| wallet_err("init/migrations", e))?;
        // [#1755] Install the slipstream-owned, read-side reconciliation view
        // (additive; see `reconcile.rs`). It is a VIEW — adds no rows to data.db,
        // never runs on the scan hot path, and is invisible to the golden oracle
        // (which diffs `type='table'` only). Idempotent, so every host inherits it
        // with no FFI change. WAL (set above) permits this short side connection.
        {
            let conn = Connection::open(db_path).map_err(|e| wallet_err("reconcile view open", e))?;
            // [audit ENG-1] same per-connection timeout as the pre-open connection above.
            conn.busy_timeout(std::time::Duration::from_secs(5))
                .map_err(|e| wallet_err("set busy_timeout (reconcile)", e))?;
            crate::reconcile::create_reconcile_view(&conn)?;
        }
        Ok(Self { network, db, db_path: db_path.to_path_buf() })
    }

    /// [API v2 §4.4] The wallet's recovery ceiling: MAX(`accounts.recover_until_height`), or
    /// `None` when no account has one (new wallets / fully non-restore imports). The scheduler
    /// compares suggested ranges against this once per suggest round to drive the snapshot's
    /// `is_recovering`. Read through a short side connection (same pattern as the reconcile view;
    /// WAL permits it) so it needs no upstream API surface.
    pub fn max_recover_until(&self) -> Result<Option<u64>, SlipstreamError> {
        let conn = Connection::open(&self.db_path).map_err(|e| wallet_err("recover_until open", e))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| wallet_err("recover_until busy_timeout", e))?;
        let max: Option<i64> = conn
            .query_row("SELECT MAX(recover_until_height) FROM accounts", [], |row| row.get(0))
            .map_err(|e| wallet_err("recover_until query", e))?;
        Ok(max.and_then(|v| u64::try_from(v).ok()))
    }

    /// [API v2 §4.4 / Phase E] The wallet's oldest account birthday: MIN(`accounts.birthday_height`),
    /// or `None` when no accounts exist. With the chain tip and the remaining scan queue it seeds the
    /// global permille floor once per suggest round (`scheduler::global_floor_permille`). Same
    /// short-side-connection pattern as `max_recover_until`.
    pub fn min_birthday(&self) -> Result<Option<u64>, SlipstreamError> {
        let conn = Connection::open(&self.db_path).map_err(|e| wallet_err("birthday open", e))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| wallet_err("birthday busy_timeout", e))?;
        let min: Option<i64> = conn
            .query_row("SELECT MIN(birthday_height) FROM accounts", [], |row| row.get(0))
            .map_err(|e| wallet_err("birthday query", e))?;
        Ok(min.and_then(|v| u64::try_from(v).ok()))
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
            .map_err(|e| {
                use zcash_client_backend::data_api::BirthdayError;
                let detail = match e {
                    BirthdayError::HeightInvalid(ie) => format!("height invalid: {ie}"),
                    BirthdayError::Decode(io) => format!("decode: {io}"),
                };
                SlipstreamError::Wallet(format!("invalid birthday treestate: {detail}"))
            })?;
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
        let height = u32::try_from(height)
            .map_err(|_| SlipstreamError::Wallet(format!("height {height} exceeds u32")))?;
        self.db
            .update_chain_tip(BlockHeight::from(height))
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

    /// Path of the wallet DB file — used by the write-behind test driver
    /// (`scan_chunks_from_treestate`) to open the persist lane's second
    /// connection. Production `scan_chunks` takes the path from `EngineConfig`.
    #[cfg(any(test, feature = "darkside"))]
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Pre-seed the `blocks` table with a record at `height` carrying `block_hash` and
    /// `sapling_commitment_tree_size`.
    ///
    /// **FOR DARKSIDE TESTS ONLY.** The real `put_block` in zcash_client_sqlite is
    /// `pub(crate)` and goes through the full `put_blocks` pipeline (which requires
    /// already-scanned `ScannedBlock` values). For our darkside workaround we need a
    /// pre-existing block record so that `scan_cached_blocks` finds a non-None
    /// `prior_block_metadata` for the very first block, enabling it to determine the
    /// Sapling note commitment tree size without relying on `chain_metadata` in the
    /// compact blocks (lightwalletd v0.4.9 does not set this field).
    ///
    /// The `block_hash` must equal the `prev_hash` of the first block that will be
    /// scanned, or the chain-continuity check inside `scan_block_with_runners` will
    /// raise `PrevHashMismatch`. Callers should fetch the first block and read its
    /// `prev_hash` to populate this parameter.
    ///
    /// Opens a separate `rusqlite::Connection` to the DB path (WAL mode allows this
    /// concurrently with the WalletDb connection) and upserts the block record.
    #[cfg(any(test, feature = "darkside"))]
    pub fn seed_block_metadata(
        &self,
        height: u64,
        sapling_commitment_tree_size: u32,
        block_hash: &[u8],
    ) -> Result<(), SlipstreamError> {
        let conn = Connection::open(&self.db_path)
            .map_err(|e| wallet_err("seed_block_metadata open", e))?;
        let h = u32::try_from(height)
            .map_err(|_| SlipstreamError::Wallet(format!("height {height} exceeds u32")))?;
        // orchard_commitment_tree_size and counts are 0 (Sapling-only test chain).
        conn.execute(
            "INSERT INTO blocks (
                height, hash, time,
                sapling_commitment_tree_size, sapling_output_count, sapling_tree,
                orchard_commitment_tree_size, orchard_action_count
             ) VALUES (?1, ?2, 0, ?3, 0, x'00', 0, 0)
             ON CONFLICT (height) DO UPDATE
             SET hash = excluded.hash,
                 sapling_commitment_tree_size = excluded.sapling_commitment_tree_size",
            rusqlite::params![h, block_hash, sapling_commitment_tree_size],
        )
        .map_err(|e| wallet_err("seed_block_metadata insert", e))?;
        Ok(())
    }
}

/// TEST_UFVK: mainnet UFVK for the canonical darkside seed used in this repo's test suite.
/// Derived from seed phrase: "still champion voice habit trend flight..." (Tests/TestUtils/Tests+Utils.swift:19)
/// seed bytes base64: "9VDVOZZZOWWHpZtq1Ebridp3Qeux5C+HwiRR0g7Oi7HgnMs8Gfln83+/Q1NnvClcaSwM4ADFL1uZHxypEWlWXg=="
/// Verified in Tests/OfflineTests/DerivationToolTests/DerivationToolMainnetTests.swift:32-39
/// as `expectedViewingKey` derived from the same `seedData`.
///
/// Re-exported here (not just in #[cfg(test)]) for the darkside integration test in
/// tests/darkside_sync.rs which is an integration test binary (not a unit test module)
/// and therefore cannot access items gated behind `#[cfg(test)]`.
#[cfg(any(test, feature = "darkside"))]
pub const TEST_UFVK: &str = concat!(
    "uview17fme6ux853km45g9ep07djpfzeydxxgm22xpmr7arzxyutlusalgpqlx7suga4ahzywfuwz4jclm00u7g8u65qvvdt45kttnfunvschssg3h3g06txs9ja32vx3xa8dej3unnat",
    "gzjvd0vumk37t8es3ludldrtse3q6226ws7eq4q0ywz78nudwpepgdn7jmxz8yvp7k6gxkeynkam0f8aqf9qpeaej55zhkw39x7epayhndul0j4xjttdxxlnwcd09nr8svyx8j0zng0w6",
    "scx3m5unpkaqxcm3hslhlfg4caz7r8d4xy9wm7klkg79w7j0uyzec5s3yje20eg946r6rmkf532nfydu26s8q9ua7mwxw2j2ag7hfcuu652gw6uta03vlm05zju3a9rwc4h367kqzfqrc",
    "z35pdwdk2a7yqnk850un3ujxcvve45ueajgvtr6dj4ufszgqwdy0aedgmkalx2p7qed2suarwkr35dl0c8dnqp3"
);

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
        // TreeState with height + valid hex hash (32 zero bytes) and empty tree strings.
        // to_chain_state() requires a non-empty hex hash; "00" * 32 = 64 chars is accepted.
        // Note: empty sapling_tree / orchard_tree strings decode to empty frontiers — valid for
        // a wallet at or before sapling activation where no notes have been committed yet.
        let ts = TreeState {
            network: "main".into(),
            height: 663_149,
            hash: "0".repeat(64),
            time: 1,
            ..Default::default()
        };
        s.ensure_account(TEST_UFVK, ts.clone()).expect("first import");
        s.ensure_account(TEST_UFVK, ts).expect("idempotent");
        // Note 4: assert on account count (simpler than range-suggestion check on fresh wallet)
        let ids = s.db.get_account_ids().expect("get_account_ids");
        assert_eq!(ids.len(), 1);
    }
}
