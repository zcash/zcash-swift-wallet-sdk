//! Slipstream-owned scan-queue hygiene (additive; the upstream data model is untouched).
//!
//! [B4-16] Upstream `WalletWrite::delete_account` (zcash_client_sqlite 0.21,
//! `wallet.rs::delete_account`) removes the account row and the transaction data solely
//! linked to it — but it NEVER touches `scan_queue`. The historic ranges a deep-birthday
//! import queued survive the deletion, so the engine would grind a full deep restore for
//! viewing keys that no longer exist: hours of wasted scan on a wallet whose remaining
//! accounts cannot have notes down there (an account has no notes below its birthday).
//!
//! [`prune_orphaned_historic_ranges`] restores the queue to the shape it would have if the
//! deleted account had never been imported: it drops `Historic`-priority rows lying
//! ENTIRELY below every remaining account's birthday and trims straddlers to start at that
//! floor. Only `Historic` is touched, deliberately:
//!
//! - `Historic` work below `MIN(accounts.birthday_height)` can only have been justified by
//!   a now-deleted account — upstream never queues Historic ranges below the wallet
//!   birthday, and its own "wallet birthday" notion IS `MIN(birthday_height)` (db.rs).
//! - `FoundNote`/`ChainTip`/`Verify`/`OpenAdjacent` rows are kept even below the floor: a
//!   REMAINING account's shard-completion range (needed for witnesses) may legitimately
//!   start below its birthday — a found note's subtree spans earlier blocks. A stale one
//!   left by the deleted account is bounded by shard size: seconds of scan, not hours.
//! - `Scanned`/`Ignored` rows are bookkeeping, not work — untouched.
//!
//! Called from [`crate::wallet_session::WalletSession::open`] — i.e. at host open AND at
//! every pass start (`engine::sync_once` opens a fresh session) — so a wallet wedged by an
//! earlier delete heals at the next launch, and an in-app delete → restart heals
//! immediately, with no FFI surface. No accounts ⇒ no floor ⇒ no-op. Idempotent, and the
//! hot path (nothing to prune) is a read-only probe that takes no write lock.

use rusqlite::Connection;

use crate::error::SlipstreamError;

/// Upstream's persisted priority code for `ScanPriority::Historic`
/// (zcash_client_sqlite-0.21 `wallet/scanning.rs::priority_code`). Priority codes are a
/// persisted format — changing one upstream would require a DB migration — so pinning the
/// value is stable across the crate versions we track.
const PRIORITY_HISTORIC: i64 = 20;

fn err(context: &str, e: impl std::fmt::Display) -> SlipstreamError {
    SlipstreamError::Wallet(format!("scan-queue prune {context}: {e}"))
}

/// Drop/trim `Historic` scan-queue rows that lie below EVERY remaining account's birthday.
/// Returns the number of rows changed (deleted + trimmed); `Ok(0)` when there are no
/// accounts or nothing qualifies (the common case — a read-only probe, no write lock).
pub fn prune_orphaned_historic_ranges(conn: &Connection) -> Result<u64, SlipstreamError> {
    let floor: Option<i64> = conn
        .query_row("SELECT MIN(birthday_height) FROM accounts", [], |row| row.get(0))
        .map_err(|e| err("min birthday", e))?;
    let Some(floor) = floor else { return Ok(0) };

    // Fast path: `block_range_start < floor` captures exactly the rows the two statements
    // below would touch (fully-below rows AND straddlers). Zero matches — the steady state
    // on every healthy open — means no write transaction is ever taken.
    let orphans: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM scan_queue WHERE priority = ?1 AND block_range_start < ?2",
            rusqlite::params![PRIORITY_HISTORIC, floor],
            |row| row.get(0),
        )
        .map_err(|e| err("probe", e))?;
    if orphans == 0 {
        return Ok(0);
    }

    // One transaction: delete + trim land together. (A crash between them would only leave
    // a straddler the next open trims — idempotent — but atomicity is free here.)
    let tx = conn.unchecked_transaction().map_err(|e| err("begin", e))?;
    let deleted = tx
        .execute(
            "DELETE FROM scan_queue WHERE priority = ?1 AND block_range_end <= ?2",
            rusqlite::params![PRIORITY_HISTORIC, floor],
        )
        .map_err(|e| err("delete", e))?;
    // Non-overlap invariant makes the trimmed start unique: no other row can already
    // start at `floor`, because it would overlap the straddler being trimmed.
    let trimmed = tx
        .execute(
            "UPDATE scan_queue SET block_range_start = ?2 \
             WHERE priority = ?1 AND block_range_start < ?2 AND block_range_end > ?2",
            rusqlite::params![PRIORITY_HISTORIC, floor],
        )
        .map_err(|e| err("trim", e))?;
    tx.commit().map_err(|e| err("commit", e))?;
    Ok((deleted + trimmed) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet_session::{TEST_UFVK, WalletSession};
    use rusqlite::params;
    use zcash_protocol::consensus::Network;

    /// Migrated wallet with ONE account (birthday 663_150 — the treestate is at 663_149),
    /// then the scan queue cleared so tests insert controlled rows only.
    fn fixture_with_account() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("data.db");
        let mut s = WalletSession::open(Network::MainNetwork, &path).expect("open");
        let ts = zcash_client_backend::proto::service::TreeState {
            network: "main".into(),
            height: 663_149,
            hash: "0".repeat(64),
            time: 1,
            ..Default::default()
        };
        s.ensure_account(TEST_UFVK, ts).expect("import account");
        drop(s);
        let conn = Connection::open(&path).expect("conn");
        conn.execute("DELETE FROM scan_queue", []).expect("clear queue");
        (dir, conn)
    }

    fn insert_range(conn: &Connection, start: i64, end: i64, priority: i64) {
        conn.execute(
            "INSERT INTO scan_queue (block_range_start, block_range_end, priority) \
             VALUES (?1, ?2, ?3)",
            params![start, end, priority],
        )
        .expect("insert scan_queue row");
    }

    fn ranges(conn: &Connection) -> Vec<(i64, i64, i64)> {
        let mut stmt = conn
            .prepare(
                "SELECT block_range_start, block_range_end, priority FROM scan_queue \
                 ORDER BY block_range_start",
            )
            .expect("prepare");
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .expect("query")
            .map(|r| r.expect("row"))
            .collect()
    }

    /// The core B4-16 shape: a deleted deep-birthday account left Historic ranges below
    /// the remaining account's birthday (663_150). Fully-below rows are dropped, a
    /// straddler is trimmed to the floor, and Historic-above plus non-Historic-below
    /// (the shard-completion class) are kept. Rows are non-overlapping (queue invariant).
    #[test]
    fn prune_drops_orphaned_historic_keeps_justified_rows() {
        let (_dir, conn) = fixture_with_account();
        insert_range(&conn, 500_000, 550_000, 20); // Historic, fully below → deleted
        insert_range(&conn, 550_000, 600_000, 20); // Historic, fully below → deleted
        insert_range(&conn, 600_000, 700_000, 20); // Historic straddler → trimmed
        insert_range(&conn, 700_000, 710_000, 20); // Historic above floor → kept
        insert_range(&conn, 450_000, 460_000, 40); // FoundNote below floor → kept
        insert_range(&conn, 460_000, 470_000, 10); // Scanned below floor → kept

        let changed = prune_orphaned_historic_ranges(&conn).expect("prune");
        assert_eq!(changed, 3, "2 deleted + 1 trimmed");
        assert_eq!(
            ranges(&conn),
            vec![
                (450_000, 460_000, 40),
                (460_000, 470_000, 10),
                (663_150, 700_000, 20),
                (700_000, 710_000, 20),
            ]
        );
    }

    /// `block_range_end` is EXCLUSIVE: a row ending exactly at the floor covers only
    /// heights strictly below every birthday, so it is dropped whole (not trimmed to an
    /// empty range, which the schema's `start < end` CHECK would reject).
    #[test]
    fn prune_treats_end_at_floor_as_fully_below() {
        let (_dir, conn) = fixture_with_account();
        insert_range(&conn, 600_000, 663_150, 20);
        assert_eq!(prune_orphaned_historic_ranges(&conn).expect("prune"), 1);
        assert!(ranges(&conn).is_empty());
    }

    /// No accounts ⇒ no floor ⇒ strict no-op (a fresh wallet's queue is never touched).
    #[test]
    fn prune_without_accounts_is_noop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("data.db");
        let _s = WalletSession::open(Network::MainNetwork, &path).expect("open");
        let conn = Connection::open(&path).expect("conn");
        insert_range(&conn, 100_000, 200_000, 20);

        assert_eq!(prune_orphaned_historic_ranges(&conn).expect("prune"), 0);
        assert_eq!(ranges(&conn), vec![(100_000, 200_000, 20)]);
    }

    /// A second run finds nothing (and, per the fast path, takes no write transaction).
    #[test]
    fn prune_is_idempotent() {
        let (_dir, conn) = fixture_with_account();
        insert_range(&conn, 500_000, 600_000, 20);
        assert_eq!(prune_orphaned_historic_ranges(&conn).expect("first"), 1);
        assert_eq!(prune_orphaned_historic_ranges(&conn).expect("second"), 0);
    }

    /// End-to-end proof of the hook: `WalletSession::open` itself heals a wedged wallet —
    /// the exact field path (app relaunch after a mid-restore account delete).
    #[test]
    fn open_prunes_orphaned_ranges() {
        let (dir, conn) = fixture_with_account();
        insert_range(&conn, 500_000, 600_000, 20);
        drop(conn);

        let path = dir.path().join("data.db");
        let _s = WalletSession::open(Network::MainNetwork, &path).expect("re-open");
        let conn = Connection::open(&path).expect("conn");
        let below: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM scan_queue WHERE priority = 20 AND block_range_start < 663_150",
                [],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(below, 0, "open() must prune the orphaned historic range");
    }
}
