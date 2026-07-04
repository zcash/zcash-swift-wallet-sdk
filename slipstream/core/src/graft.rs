//! v0.4 Plan A — the graft buffer (spec §4, plan Task 5).
//!
//! `slipstream_graft_buffer` holds the raw commitments of still-open, note-free
//! shards so their build can be deferred to the shard-close verdict (graft the
//! server root / build). It is a slipstream-owned side table in `data.db`,
//! written over a SIDE connection (the established engine-owned-table pattern —
//! upstream `WalletDb` never exposes its connection).
//!
//! ## Restart-safety contract (ordering + idempotency, NOT shared-transaction)
//! Appends run BEFORE the chunk's main `put_blocks` transaction commits, keyed
//! `(pool, shard_index, position)` with INSERT OR REPLACE:
//! - crash between append and main-commit → the range is still unscanned →
//!   rescan re-appends byte-identical rows onto the same keys — harmless;
//! - crash after main-commit, before a close-verdict cleanup → stale rows for a
//!   built shard → the accumulator's seed rule ("store already has internals →
//!   passthrough") drops + deletes them — self-healing.
//!
//! The invariant "block marked scanned ⇒ its commitments are in the shard store
//! OR in this buffer" therefore holds at every crash point.

use incrementalmerkletree::{Marking, Retention};
use rusqlite::{Connection, params};
use zcash_client_sqlite::error::SqliteClientError;
use zcash_primitives::merkle_tree::HashSer;
use zcash_protocol::{ShieldedProtocol, consensus::BlockHeight};

/// One buffered commitment row.
pub(crate) type BufferRow<H> = (u64, H, Retention<BlockHeight>);

fn pool_code(pool: ShieldedProtocol) -> i64 {
    match pool {
        ShieldedProtocol::Sapling => 2,
        ShieldedProtocol::Orchard => 3,
    }
}

fn corrupt(msg: impl Into<String>) -> SqliteClientError {
    SqliteClientError::CorruptedData(msg.into())
}

/// Lazily create the buffer table. Called only on graft-ON paths so flag-OFF
/// runs leave the database byte-identical.
pub(crate) fn ensure_buffer_table(conn: &Connection) -> Result<(), SqliteClientError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS slipstream_graft_buffer (
            pool INTEGER NOT NULL,
            shard_index INTEGER NOT NULL,
            position INTEGER NOT NULL,
            commitment BLOB NOT NULL,
            retention_kind INTEGER NOT NULL,
            checkpoint_height INTEGER,
            marking INTEGER,
            PRIMARY KEY (pool, shard_index, position)
        ) WITHOUT ROWID",
    )?;
    Ok(())
}

fn encode_retention(r: &Retention<BlockHeight>) -> (i64, Option<i64>, Option<i64>) {
    match r {
        Retention::Ephemeral => (0, None, None),
        Retention::Marked => (1, None, None),
        Retention::Checkpoint { id, marking } => {
            let m = match marking {
                Marking::None => 0,
                Marking::Marked => 1,
                Marking::Reference => 2,
            };
            (2, Some(i64::from(u32::from(*id))), Some(m))
        }
        Retention::Reference => (3, None, None),
    }
}

fn decode_retention(
    kind: i64,
    checkpoint_height: Option<i64>,
    marking: Option<i64>,
) -> Result<Retention<BlockHeight>, SqliteClientError> {
    Ok(match kind {
        0 => Retention::Ephemeral,
        1 => Retention::Marked,
        2 => {
            let h = checkpoint_height
                .ok_or_else(|| corrupt("graft buffer: checkpoint row without height"))?;
            let h = u32::try_from(h).map_err(|_| corrupt("graft buffer: height out of range"))?;
            let marking = match marking.unwrap_or(0) {
                0 => Marking::None,
                1 => Marking::Marked,
                2 => Marking::Reference,
                other => return Err(corrupt(format!("graft buffer: bad marking {other}"))),
            };
            Retention::Checkpoint { id: BlockHeight::from(h), marking }
        }
        3 => Retention::Reference,
        other => return Err(corrupt(format!("graft buffer: bad retention kind {other}"))),
    })
}

/// Append rows for one shard (INSERT OR REPLACE — idempotent under rescan).
pub(crate) fn append_rows<H: HashSer>(
    conn: &Connection,
    pool: ShieldedProtocol,
    shard_index: u64,
    rows: &[BufferRow<H>],
) -> Result<(), SqliteClientError> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut stmt = conn.prepare_cached(
        "INSERT OR REPLACE INTO slipstream_graft_buffer
         (pool, shard_index, position, commitment, retention_kind, checkpoint_height, marking)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;
    for (position, hash, retention) in rows {
        let mut bytes = vec![];
        hash.write(&mut bytes).map_err(|e| corrupt(format!("graft buffer: hash ser: {e}")))?;
        let (kind, height, marking) = encode_retention(retention);
        stmt.execute(params![
            pool_code(pool),
            shard_index as i64,
            *position as i64,
            bytes,
            kind,
            height,
            marking
        ])?;
    }
    Ok(())
}

/// Load one shard's buffered rows, ordered by position. Empty vec when the
/// table doesn't exist yet (flag just turned on) or holds nothing for the shard.
pub(crate) fn load_shard<H: HashSer>(
    conn: &Connection,
    pool: ShieldedProtocol,
    shard_index: u64,
) -> Result<Vec<BufferRow<H>>, SqliteClientError> {
    if !buffer_table_exists(conn)? {
        return Ok(vec![]);
    }
    let mut stmt = conn.prepare_cached(
        "SELECT position, commitment, retention_kind, checkpoint_height, marking
         FROM slipstream_graft_buffer
         WHERE pool = ?1 AND shard_index = ?2
         ORDER BY position ASC",
    )?;
    let rows = stmt.query_map(params![pool_code(pool), shard_index as i64], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, Option<i64>>(3)?,
            row.get::<_, Option<i64>>(4)?,
        ))
    })?;
    let mut out = vec![];
    for row in rows {
        let (position, bytes, kind, height, marking) = row?;
        let hash = H::read(&bytes[..]).map_err(|e| corrupt(format!("graft buffer: hash de: {e}")))?;
        out.push((position as u64, hash, decode_retention(kind, height, marking)?));
    }
    Ok(out)
}

/// Drop one shard's buffer (close-verdict cleanup — graft installed or built).
pub(crate) fn delete_shard(
    conn: &Connection,
    pool: ShieldedProtocol,
    shard_index: u64,
) -> Result<(), SqliteClientError> {
    if !buffer_table_exists(conn)? {
        return Ok(());
    }
    conn.execute(
        "DELETE FROM slipstream_graft_buffer WHERE pool = ?1 AND shard_index = ?2",
        params![pool_code(pool), shard_index as i64],
    )?;
    Ok(())
}

/// Rewind support (plan Task 9): drop every buffered row at or above `min_position`.
pub(crate) fn delete_from_position(
    conn: &Connection,
    pool: ShieldedProtocol,
    min_position: u64,
) -> Result<(), SqliteClientError> {
    if !buffer_table_exists(conn)? {
        return Ok(());
    }
    conn.execute(
        "DELETE FROM slipstream_graft_buffer WHERE pool = ?1 AND position >= ?2",
        params![pool_code(pool), min_position as i64],
    )?;
    Ok(())
}

fn shards_table(pool: ShieldedProtocol) -> &'static str {
    match pool {
        ShieldedProtocol::Sapling => "sapling_tree_shards",
        ShieldedProtocol::Orchard => "orchard_tree_shards",
    }
}

/// v0.4 Plan A Task 8 — the graft verdict's source of truth: the server root
/// for `shard_index`, as ingested by the pass-start `put_subtree_roots`
/// (engine.rs:180). Upstream writes it into `{pool}_tree_shards.root_hash`
/// with `ON CONFLICT DO UPDATE SET root_hash = …` (commitment_tree.rs:1090),
/// so the column is populated for every COMPLETED shard even when local
/// `shard_data` already exists. `None` = no row, NULL root (local-only shard),
/// or the table absent — every "no root" shape falls back to build.
pub(crate) fn server_root<H: HashSer>(
    conn: &Connection,
    pool: ShieldedProtocol,
    shard_index: u64,
) -> Result<Option<H>, SqliteClientError> {
    use rusqlite::OptionalExtension as _;
    let table = shards_table(pool);
    let bytes: Option<Option<Vec<u8>>> = conn
        .query_row(
            &format!("SELECT root_hash FROM {table} WHERE shard_index = ?1"),
            [shard_index as i64],
            |r| r.get(0),
        )
        .optional()
        .or_else(|e| match e {
            // Table absent (fresh test wallets before any migration touch):
            // treat as "no root", never as an error.
            rusqlite::Error::SqliteFailure(_, Some(ref m)) if m.contains("no such table") => {
                Ok(None)
            }
            other => Err(other),
        })?;
    match bytes.flatten() {
        Some(b) => Ok(Some(
            H::read(&b[..]).map_err(|e| corrupt(format!("server root de: {e}")))?,
        )),
        None => Ok(None),
    }
}

fn buffer_table_exists(conn: &Connection) -> Result<bool, SqliteClientError> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='slipstream_graft_buffer'",
        [],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::tree::MerkleHashOrchard;
    use incrementalmerkletree::Hashable as _;

    fn mem_conn() -> Connection {
        Connection::open_in_memory().expect("in-memory conn")
    }

    fn h(n: u8) -> MerkleHashOrchard {
        // Distinct valid nodes: hash the empty leaf up n levels.
        let mut v = MerkleHashOrchard::empty_leaf();
        for level in 0..n {
            v = MerkleHashOrchard::combine(incrementalmerkletree::Level::from(level), &v, &v);
        }
        v
    }

    fn all_retentions() -> Vec<Retention<BlockHeight>> {
        vec![
            Retention::Ephemeral,
            Retention::Marked,
            Retention::Reference,
            Retention::Checkpoint { id: BlockHeight::from(123), marking: Marking::None },
            Retention::Checkpoint { id: BlockHeight::from(456), marking: Marking::Marked },
            Retention::Checkpoint { id: BlockHeight::from(789), marking: Marking::Reference },
        ]
    }

    #[test]
    fn append_load_round_trip_ordered_all_retentions() {
        let conn = mem_conn();
        ensure_buffer_table(&conn).expect("table");
        let rows: Vec<BufferRow<MerkleHashOrchard>> = all_retentions()
            .into_iter()
            .enumerate()
            .map(|(i, r)| (1000 + i as u64, h(i as u8), r))
            .collect();
        // Append out of order to prove ORDER BY, not insertion order.
        let mut shuffled = rows.clone();
        shuffled.reverse();
        append_rows(&conn, ShieldedProtocol::Orchard, 7, &shuffled).expect("append");
        let loaded: Vec<BufferRow<MerkleHashOrchard>> =
            load_shard(&conn, ShieldedProtocol::Orchard, 7).expect("load");
        assert_eq!(loaded, rows);
    }

    #[test]
    fn append_is_idempotent_under_rescan() {
        let conn = mem_conn();
        ensure_buffer_table(&conn).expect("table");
        let rows: Vec<BufferRow<MerkleHashOrchard>> =
            vec![(5, h(1), Retention::Ephemeral), (6, h(2), Retention::Marked)];
        append_rows(&conn, ShieldedProtocol::Orchard, 0, &rows).expect("append 1");
        append_rows(&conn, ShieldedProtocol::Orchard, 0, &rows).expect("append 2 (rescan)");
        let loaded: Vec<BufferRow<MerkleHashOrchard>> =
            load_shard(&conn, ShieldedProtocol::Orchard, 0).expect("load");
        assert_eq!(loaded, rows, "REPLACE semantics — no duplicates, same content");
    }

    #[test]
    fn pools_and_shards_are_disjoint_and_delete_is_scoped() {
        let conn = mem_conn();
        ensure_buffer_table(&conn).expect("table");
        let row = |p: u64| vec![(p, h(0), Retention::Ephemeral)];
        append_rows(&conn, ShieldedProtocol::Orchard, 1, &row(10)).expect("o1");
        append_rows(&conn, ShieldedProtocol::Orchard, 2, &row(70_000)).expect("o2");
        append_rows(&conn, ShieldedProtocol::Sapling, 1, &row(11)).expect("s1");
        delete_shard(&conn, ShieldedProtocol::Orchard, 1).expect("delete o1");
        let o1: Vec<BufferRow<MerkleHashOrchard>> =
            load_shard(&conn, ShieldedProtocol::Orchard, 1).expect("load o1");
        let o2: Vec<BufferRow<MerkleHashOrchard>> =
            load_shard(&conn, ShieldedProtocol::Orchard, 2).expect("load o2");
        let s1: Vec<BufferRow<sapling::Node>> =
            load_shard(&conn, ShieldedProtocol::Sapling, 1).expect("load s1");
        assert!(o1.is_empty());
        assert_eq!(o2.len(), 1);
        assert_eq!(s1.len(), 1, "sapling shard 1 untouched by orchard delete");
    }

    #[test]
    fn missing_table_reads_as_empty_and_deletes_noop() {
        let conn = mem_conn();
        let loaded: Vec<BufferRow<MerkleHashOrchard>> =
            load_shard(&conn, ShieldedProtocol::Orchard, 3).expect("load");
        assert!(loaded.is_empty());
        delete_shard(&conn, ShieldedProtocol::Orchard, 3).expect("delete noop");
        delete_from_position(&conn, ShieldedProtocol::Orchard, 0).expect("rewind noop");
    }

    #[test]
    fn server_root_reads_ingested_roots_and_handles_all_no_root_shapes() {
        let conn = mem_conn();
        // Missing table → None (not an error).
        let none: Option<MerkleHashOrchard> =
            server_root(&conn, ShieldedProtocol::Orchard, 3).expect("missing table");
        assert!(none.is_none());
        // Mini replica of the upstream shards schema (commitment_tree.rs).
        conn.execute_batch(
            "CREATE TABLE orchard_tree_shards (
                shard_index INTEGER PRIMARY KEY,
                subtree_end_height INTEGER,
                root_hash BLOB,
                shard_data BLOB
            )",
        )
        .expect("ddl");
        // Missing row → None.
        let none: Option<MerkleHashOrchard> =
            server_root(&conn, ShieldedProtocol::Orchard, 3).expect("missing row");
        assert!(none.is_none());
        // NULL root_hash (locally-built shard) → None.
        conn.execute("INSERT INTO orchard_tree_shards (shard_index) VALUES (7)", [])
            .expect("null row");
        let none: Option<MerkleHashOrchard> =
            server_root(&conn, ShieldedProtocol::Orchard, 7).expect("null root");
        assert!(none.is_none());
        // Ingested root (HashSer bytes, exactly what put_shard_roots writes) → Some.
        let root = h(4);
        let mut bytes = vec![];
        use zcash_primitives::merkle_tree::HashSer as _;
        root.write(&mut bytes).expect("ser");
        conn.execute(
            "INSERT INTO orchard_tree_shards (shard_index, root_hash) VALUES (3, ?1)",
            [bytes],
        )
        .expect("root row");
        let got: Option<MerkleHashOrchard> =
            server_root(&conn, ShieldedProtocol::Orchard, 3).expect("read root");
        assert_eq!(got, Some(root));
        // Pools are disjoint: sapling table absent → None even though orchard has data.
        let none: Option<sapling::Node> =
            server_root(&conn, ShieldedProtocol::Sapling, 3).expect("other pool");
        assert!(none.is_none());
    }

    #[test]
    fn rewind_deletes_at_and_above_position() {
        let conn = mem_conn();
        ensure_buffer_table(&conn).expect("table");
        let rows: Vec<BufferRow<MerkleHashOrchard>> = (0..4u64)
            .map(|i| (100 + i, h(0), Retention::Ephemeral))
            .collect();
        append_rows(&conn, ShieldedProtocol::Orchard, 0, &rows).expect("append");
        delete_from_position(&conn, ShieldedProtocol::Orchard, 102).expect("rewind");
        let loaded: Vec<BufferRow<MerkleHashOrchard>> =
            load_shard(&conn, ShieldedProtocol::Orchard, 0).expect("load");
        assert_eq!(loaded.iter().map(|r| r.0).collect::<Vec<_>>(), vec![100, 101]);
    }
}
