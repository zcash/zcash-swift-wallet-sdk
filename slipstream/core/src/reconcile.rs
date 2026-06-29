//! Slipstream-owned, read-side transaction reconciliation view (additive).
//!
//! During a recent-first restore the scheduler scans a recent block that spends
//! an older note BEFORE the block where that note was received. Until the older
//! block is scanned, upstream's `v_transactions` has no `*_received_note_spends`
//! row for the spend, so the spend contributes 0 to `account_balance_delta` and
//! a self-send's change reads as a phantom "+receive" (the delta is transiently
//! positive, then flips negative once the spent note is linked). The evidence
//! that a spend exists but is not yet linked lives in `nullifier_map` (the
//! observed nullifier) with no matching `*_received_notes.nf`.
//!
//! `slipstream_v_tx_reconciled` exposes, per wallet txid, whether the tx still
//! has such a dangling shielded spend. A consumer (the SDK) can hold an
//! unreconciled tx out of the Activity list until its delta is final, then
//! reveal it — surfacing genuine receives and already-linked sends *sooner*
//! while keeping the ambiguous change-vs-receive tx hidden until it is *correct*.
//!
//! This is a VIEW (computed on read): it adds NO rows to `data.db`, never runs
//! on the scan/persist hot path, and is invisible to the golden oracle (which
//! diffs `type='table'` only — see `oracle::semantic_diff`). It is created
//! idempotently at every wallet open, so any host of the engine (iOS, Android,
//! CLI) inherits it with no FFI surface change. A fully-synced wallet has no
//! dangling spends, so every tx reads `reconciled = 1` — correct at cold start
//! with the engine not even running.

use rusqlite::Connection;

use crate::error::SlipstreamError;

/// Name of the reconciliation view (kept in sync with [`RECONCILE_VIEW_SQL`]).
pub const RECONCILE_VIEW_NAME: &str = "slipstream_v_tx_reconciled";

/// `CREATE VIEW IF NOT EXISTS` for the per-tx reconciliation signal.
///
/// `reconciled = 0` iff the tx has an observed shielded spend (a `nullifier_map`
/// row at the tx's locator) whose note has not yet been received (no
/// `*_received_notes` row carries that nullifier). `spend_pool` follows upstream
/// `pool_code` (zcash_client_sqlite `wallet/encoding.rs:34`): 2 = Sapling,
/// 3 = Orchard. Transparent spends never produce this transient (their inputs
/// are linked by outpoint at scan time, not by a later-scanned origin block), so
/// they are intentionally not considered here.
///
/// The `FROM transactions t` anchor keeps the result to *our* wallet's txs:
/// `nullifier_map` records every nullifier in a scanned block (including other
/// parties' spends), but only our txs have a row in `transactions`, so a
/// non-wallet `tl.txid` simply has no `t` to match. The test is "is the note
/// received yet", NOT "is the nullifier still tracked", so it is robust to
/// `prune_tracked_nullifiers` timing.
pub const RECONCILE_VIEW_SQL: &str = "CREATE VIEW IF NOT EXISTS slipstream_v_tx_reconciled AS
SELECT t.txid AS txid,
       NOT EXISTS (
           SELECT 1
           FROM nullifier_map nm
           JOIN tx_locator_map tl
               ON tl.block_height = nm.block_height
              AND tl.tx_index = nm.tx_index
           WHERE tl.txid = t.txid
             AND (
                 (nm.spend_pool = 2
                  AND NOT EXISTS (SELECT 1 FROM sapling_received_notes s WHERE s.nf = nm.nf))
                 OR
                 (nm.spend_pool = 3
                  AND NOT EXISTS (SELECT 1 FROM orchard_received_notes o WHERE o.nf = nm.nf))
             )
       ) AS reconciled
FROM transactions t";

/// Create (idempotently) the reconciliation view on an already-migrated wallet
/// database. Called once per [`crate::wallet_session::WalletSession::open`].
pub fn create_reconcile_view(conn: &Connection) -> Result<(), SlipstreamError> {
    conn.execute_batch(RECONCILE_VIEW_SQL)
        .map_err(|e| SlipstreamError::Wallet(format!("create reconcile view: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet_session::WalletSession;
    use rusqlite::{OptionalExtension, params};
    use zcash_protocol::consensus::Network;

    /// Open a migrated wallet DB (which also installs the reconcile view), and
    /// hand back a plain connection with foreign-key enforcement OFF so the test
    /// can insert only the columns the view reads.
    fn fixture() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("data.db");
        let _session = WalletSession::open(Network::MainNetwork, &path).expect("open");
        let conn = Connection::open(&path).expect("conn");
        conn.pragma_update(None, "foreign_keys", false).expect("fk off");
        (dir, conn)
    }

    fn reconciled(conn: &Connection, txid: &[u8]) -> Option<i64> {
        conn.query_row(
            "SELECT reconciled FROM slipstream_v_tx_reconciled WHERE txid = ?1",
            params![txid],
            |r| r.get(0),
        )
        .optional()
        .expect("query view")
    }

    /// Record our spending tx `txid` at locator (height, 0) plus the observed
    /// shielded spend of `nf` in pool `spend_pool`. The spent note is NOT yet
    /// received — the recent-first "dangling" state.
    fn insert_dangling_spend(conn: &Connection, id_tx: i64, txid: &[u8], height: i64, spend_pool: i64, nf: &[u8]) {
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, mined_height, tx_index, min_observed_height) VALUES (?1, ?2, ?3, 0, ?3)",
            params![id_tx, txid, height],
        )
        .expect("insert transaction");
        conn.execute(
            "INSERT INTO tx_locator_map (block_height, tx_index, txid) VALUES (?1, 0, ?2)",
            params![height, txid],
        )
        .expect("insert tx_locator_map");
        conn.execute(
            "INSERT INTO nullifier_map (spend_pool, nf, block_height, tx_index) VALUES (?1, ?2, ?3, 0)",
            params![spend_pool, nf, height],
        )
        .expect("insert nullifier_map");
    }

    #[test]
    fn sapling_spend_dangling_then_linked() {
        let (_dir, conn) = fixture();
        let txid = vec![0xAAu8; 32];
        let nf = vec![0xBBu8; 32];

        insert_dangling_spend(&conn, 1, &txid, 200, 2, &nf);
        assert_eq!(reconciled(&conn, &txid), Some(0), "sapling dangling spend -> unreconciled");

        // The older block is scanned: the note carrying `nf` is received -> the
        // spend links -> the tx's delta is now final.
        conn.execute(
            "INSERT INTO sapling_received_notes
                (transaction_id, output_index, account_id, diversifier, value, rcm, nf, is_change)
             VALUES (1, 0, 1, x'00', 0, x'00', ?1, 0)",
            params![nf],
        )
        .expect("insert sapling_received_notes");
        assert_eq!(reconciled(&conn, &txid), Some(1), "sapling linked spend -> reconciled");
    }

    #[test]
    fn orchard_spend_dangling_then_linked() {
        let (_dir, conn) = fixture();
        let txid = vec![0xCCu8; 32];
        let nf = vec![0xDDu8; 32];

        insert_dangling_spend(&conn, 1, &txid, 300, 3, &nf);
        assert_eq!(reconciled(&conn, &txid), Some(0), "orchard dangling spend -> unreconciled");

        conn.execute(
            "INSERT INTO orchard_received_notes
                (transaction_id, action_index, account_id, diversifier, value, rho, rseed, nf, is_change)
             VALUES (1, 0, 1, x'00', 0, x'00', x'00', ?1, 0)",
            params![nf],
        )
        .expect("insert orchard_received_notes");
        assert_eq!(reconciled(&conn, &txid), Some(1), "orchard linked spend -> reconciled");
    }

    #[test]
    fn pure_receive_with_no_spends_is_reconciled_immediately() {
        let (_dir, conn) = fixture();
        let txid = vec![0xEEu8; 32];
        // A genuine incoming receive: tx recorded, but no nullifier_map row (it
        // spends nothing of ours). Must read reconciled from the first scan.
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, mined_height, tx_index, min_observed_height) VALUES (1, ?1, 400, 0, 400)",
            params![txid],
        )
        .expect("insert transaction");
        conn.execute(
            "INSERT INTO tx_locator_map (block_height, tx_index, txid) VALUES (400, 0, ?1)",
            params![txid],
        )
        .expect("insert tx_locator_map");
        assert_eq!(reconciled(&conn, &txid), Some(1), "pure receive -> reconciled");
    }

    #[test]
    fn unrelated_nullifier_does_not_taint_our_tx() {
        // A dangling spend that belongs to a DIFFERENT (non-wallet) tx position
        // must not mark our reconciled receive as unreconciled.
        let (_dir, conn) = fixture();
        let ours = vec![0x11u8; 32];
        let theirs_nf = vec![0x22u8; 32];

        // Our pure receive at (500, 0).
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, mined_height, tx_index, min_observed_height) VALUES (1, ?1, 500, 0, 500)",
            params![ours],
        )
        .expect("insert transaction");
        conn.execute(
            "INSERT INTO tx_locator_map (block_height, tx_index, txid) VALUES (500, 0, ?1)",
            params![ours],
        )
        .expect("insert tx_locator_map");
        // A nullifier observed at a different locator (500, 7) that has no row in
        // `transactions` (not our tx). It must not affect our (500, 0) tx.
        conn.execute(
            "INSERT INTO tx_locator_map (block_height, tx_index, txid) VALUES (500, 7, x'99')",
            [],
        )
        .expect("insert other tx_locator_map");
        conn.execute(
            "INSERT INTO nullifier_map (spend_pool, nf, block_height, tx_index) VALUES (2, ?1, 500, 7)",
            params![theirs_nf],
        )
        .expect("insert other nullifier_map");

        assert_eq!(reconciled(&conn, &ours), Some(1), "unrelated dangling spend must not taint our tx");
    }
}
