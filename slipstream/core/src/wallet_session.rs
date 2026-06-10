//! Persistent wallet session: ONE WalletDb for the whole sync (decision D2/D3 —
//! unchanged zcash_client_sqlite data model), WAL set on the file before open,
//! migrations run once, chain-state ops (subtree roots, chain tip, scan ranges)
//! and keyless account import (UFVK only, decision D6).

use std::path::Path;

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
            // Note 1: pragma_update_and_check in rusqlite 0.37 takes Option<&str> for schema_name
            // (not Option<DatabaseName> as in older versions) — plan code compiles as-written.
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

    // TEST_UFVK: mainnet UFVK for the canonical darkside seed used in this repo's test suite.
    // Derived from seed phrase: "still champion voice habit trend flight..." (Tests/TestUtils/Tests+Utils.swift:19)
    // seed bytes base64: "9VDVOZZZOWWHpZtq1Ebridp3Qeux5C+HwiRR0g7Oi7HgnMs8Gfln83+/Q1NnvClcaSwM4ADFL1uZHxypEWlWXg=="
    // Verified in Tests/OfflineTests/DerivationToolTests/DerivationToolMainnetTests.swift:32-39
    // as `expectedViewingKey` derived from the same `seedData`.
    const TEST_UFVK: &str = concat!(
        "uview17fme6ux853km45g9ep07djpfzeydxxgm22xpmr7arzxyutlusalgpqlx7suga4ahzywfuwz4jclm00u7g8u65qvvdt45kttnfunvschssg3h3g06txs9ja32vx3xa8dej3unnat",
        "gzjvd0vumk37t8es3ludldrtse3q6226ws7eq4q0ywz78nudwpepgdn7jmxz8yvp7k6gxkeynkam0f8aqf9qpeaej55zhkw39x7epayhndul0j4xjttdxxlnwcd09nr8svyx8j0zng0w6",
        "scx3m5unpkaqxcm3hslhlfg4caz7r8d4xy9wm7klkg79w7j0uyzec5s3yje20eg946r6rmkf532nfydu26s8q9ua7mwxw2j2ag7hfcuu652gw6uta03vlm05zju3a9rwc4h367kqzfqrc",
        "z35pdwdk2a7yqnk850un3ujxcvve45ueajgvtr6dj4ufszgqwdy0aedgmkalx2p7qed2suarwkr35dl0c8dnqp3"
    );

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
