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
///
/// # ALLOWLIST entries (Decision-Log in STATE.md)
///
/// - `("accounts", "uuid")`: random `Uuid::new_v4()` generated at account-import time.
///   Write site: `zcash_client_sqlite-0.21.0/src/wallet.rs:464` (`let account_uuid =
///   AccountUuid(Uuid::new_v4())`). Non-deterministic by design — it is a stable
///   per-account opaque identity, not part of the scan output. Oracle correctness is
///   unaffected because all scan tables (blocks, sapling_tree_*, orchard_tree_*,
///   nullifier_map, tx_locator_map, scan_queue, etc.) remain clean.
pub const ALLOWLIST: &[(&str, &str)] = &[("accounts", "uuid")];

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
        for (i, col) in cols.iter().enumerate() {
            let v = row.get_ref(i).map_err(|e| wallet_err("get_ref", e))?;
            let _ = write!(canon, "{col}={}|", canonical_value(v));
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
            // Deviation from plan: CompactTx uses `txid` not `hash` in
            // zcash_client_backend-0.23.0/src/proto/compact_formats.rs:70.
            let tx = CompactTx {
                index: 0,
                txid: h32(0x77, height),
                fee: 0,
                spends: vec![CompactSaplingSpend { nf: h32(0x4F, height) }],
                outputs,
                actions: vec![],
                ..Default::default()
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
    /// plain WalletDb when `sparse` is false, through the `SparseFacade`
    /// (exactly as scan.rs::scan_chunks does, with ONE `SparseTreeState` for the
    /// whole call = one scan range) when `sparse` is true.
    pub fn scan_synthetic(
        dir: &Path,
        blocks: Vec<CompactBlock>,
        chunk_size: usize,
        sparse: bool,
    ) -> Result<(), SlipstreamError> {
        let lens: Vec<usize> = blocks.chunks(chunk_size).map(<[CompactBlock]>::len).collect();
        scan_synthetic_windows(dir, blocks, &lens, sparse)
    }

    /// Like [`scan_synthetic`] but scans in explicit variable-length windows
    /// (T6.8-S): each entry of `window_lens` is one `scan_cached_blocks` call,
    /// mirroring the engine's byte-budget-split sub-chunks. `window_lens` must
    /// sum to `blocks.len()`.
    pub fn scan_synthetic_windows(
        dir: &Path,
        blocks: Vec<CompactBlock>,
        window_lens: &[usize],
        sparse: bool,
    ) -> Result<(), SlipstreamError> {
        if window_lens.iter().sum::<usize>() != blocks.len() {
            return Err(SlipstreamError::Wallet(format!(
                "window_lens sum {} != blocks {}",
                window_lens.iter().sum::<usize>(),
                blocks.len()
            )));
        }
        let mut sparse_state = crate::persist::SparseTreeState::default();
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
        let mut offset = 0usize;
        for len in window_lens {
            let window = &blocks[offset..offset + len];
            offset += len;
            let (Some(first), Some(last)) = (window.first(), window.last()) else {
                continue; // zero-length windows are skipped (degenerate input)
            };
            let from_height = u32::try_from(first.height)
                .map_err(|_| SlipstreamError::Wallet("height exceeds u32".into()))?;
            let chunk = Chunk::from_blocks(0, window.to_vec());
            let source = MemBlockSource::new(&chunk);
            let network = session.network;
            if sparse {
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
                    window.len(),
                )
                .map_err(|e| SlipstreamError::Wallet(format!("scan_cached_blocks (sparse): {e}")))?;
            } else {
                scan_cached_blocks(
                    &network,
                    &source,
                    session.db_mut(),
                    BlockHeight::from(from_height),
                    &from_state,
                    window.len(),
                )
                .map_err(|e| SlipstreamError::Wallet(format!("scan_cached_blocks: {e}")))?;
            }
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
        use zcash_primitives::merkle_tree::HashSer;
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
            // Deviation from plan's sapling::Node::from_bytes (CtOption):
            // grpc.rs uses sapling::Node::read(&bytes[..]) via HashSer — same pattern here.
            let node = sapling::Node::read(&bytes[..])
                .map_err(|e| SlipstreamError::Wallet(format!("invalid synth cmu {n}: {e}")))?;
            let _ = frontier.append(node);
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

    /// T6.3b hermetic identity proof: the SAME synthetic chain scanned through
    /// the upstream path (A) and the sparse facade with the checkpoint
    /// downgrade (B) must produce semantically identical databases. 3 chunks of
    /// 1000 blocks each: ~1000 per-block sapling checkpoints per put_blocks
    /// call against the 100-checkpoint window, so the doomed-checkpoint cutoff
    /// fires in every chunk (~900 downgrades each) and the cross-chunk carry
    /// (previous chunk's surviving checkpoints + missing-checkpoint table
    /// entries) is exercised twice.
    #[test]
    fn sparse_path_matches_upstream_on_synthetic_chain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let da = dir.path().join("wa");
        let db = dir.path().join("wb");
        std::fs::create_dir_all(&da).unwrap();
        std::fs::create_dir_all(&db).unwrap();
        let blocks = super::testkit::synth_blocks(3000, 3);
        super::testkit::scan_synthetic(&da, blocks.clone(), 1000, false).expect("upstream scan");
        super::testkit::scan_synthetic(&db, blocks, 1000, true).expect("sparse scan");
        let report = semantic_diff(&da.join("data.db"), &db.join("data.db")).expect("diff");
        assert!(
            report.is_clean(),
            "sparse-vs-upstream diff not clean:\n{}",
            report.render()
        );
    }

    /// T6.8-S hermetic identity proof for VARIABLE (byte-budget-split) chunking:
    /// a dense ("sandblasting"-shaped) synthetic chain — every block several
    /// times the split threshold in wire size — is split into many small
    /// variable windows by the REAL `ChunkSplitter` (the same decisions the
    /// fetch workers make in the spam era), then scanned through BOTH
    /// persistence paths at those identical boundaries: A = upstream WalletDb,
    /// B = SparseFacade (production default). A CLEAN diff proves the sparse
    /// path stays oracle-clean under dense, tiny, variable chunking.
    ///
    /// Methodology note (discovered building this test): chunk boundaries ARE
    /// observable in the wallet DB on the UPSTREAM path itself, by design —
    /// (1) `put_blocks` prunes `nullifier_map` on every call at
    /// fully-scanned-height − PRUNING_DEPTH (zcash_client_backend-0.23.0
    /// data_api/ll/wallet.rs:460-463 → zcash_client_sqlite-0.21.0 lib.rs:2054),
    /// so finer chunking prunes a rolling cache earlier; (2) shard-blob bytes
    /// encode the insert/prune batch history. Cross-chunking byte-comparison is
    /// therefore upstream-false; the oracle compares the two PATHS at EQUAL
    /// boundaries (same as T6.2+ methodology and the CLI oracle, where both
    /// runs share one config).
    #[test]
    fn split_chunking_matches_upstream_on_dense_chain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let da = dir.path().join("wa");
        let db = dir.path().join("wb");
        std::fs::create_dir_all(&da).unwrap();
        std::fs::create_dir_all(&db).unwrap();
        // 80 blocks × 20 sapling outputs ≈ 2.5 KB wire per block: dense-era
        // shape relative to a 6 KiB split threshold (~2-block sub-chunks).
        // Sized for the always-green loop: split COUNT (not absolute output
        // volume) is what exercises the variable-boundary machinery.
        let blocks = super::testkit::synth_blocks(80, 20);

        // Derive the window lengths from the production splitter.
        let mut lens: Vec<usize> = Vec::new();
        let mut splitter = crate::fetch::ChunkSplitter::new(6 * 1024);
        for b in blocks.clone() {
            if let Some((sub, _bytes)) = splitter.push(b) {
                lens.push(sub.len());
            }
        }
        if let Some((sub, _bytes)) = splitter.finish() {
            lens.push(sub.len());
        }
        assert!(lens.len() >= 30, "dense chain must split into many sub-chunks, got {}", lens.len());
        assert_eq!(lens.iter().sum::<usize>(), blocks.len(), "no block lost by the splitter");

        super::testkit::scan_synthetic_windows(&da, blocks.clone(), &lens, false)
            .expect("upstream scan at split boundaries");
        super::testkit::scan_synthetic_windows(&db, blocks, &lens, true)
            .expect("sparse scan at split boundaries");
        let report = semantic_diff(&da.join("data.db"), &db.join("data.db")).expect("diff");
        assert!(
            report.is_clean(),
            "split-chunking sparse-vs-upstream diff not clean:\n{}",
            report.render()
        );
    }
}
