//! T6.4 darkside oracle: the sparse persistence path must produce a data.db that
//! is semantically identical to the upstream path for a chain with REAL wallet notes.
//!
//! Test design (per plan §6.4 Step 3):
//!   - Mirror `sync_finds_fixture_transactions` staging verbatim
//!     (TX_MAINNET_BLOCK_URL chain + two tx fixtures at 663174/663188).
//!   - Run the direct pipeline TWICE into two separate temp wallets:
//!     - Run A: sparse = false  (upstream path)
//!     - Run B: sparse = true   (SparseFacade / in-memory shardtree path)
//!   - Reset darkside between runs and re-stage identically.
//!   - `semantic_diff(wallet_a_db, wallet_b_db)` must be clean.
//!   - Belt-and-braces: wallet B still finds the same 2 txs / 200000 zatoshi balance.
//!
//! Coverage this oracle adds:
//!   - `transactions` rows (put_tx_meta, queue_tx_retrieval)
//!   - `sapling_received_notes` (positions, nf, spent linkage from find_wallet_tx)
//!   - `tx_retrieval_queue` rows
//!   - scan_queue FoundNote extensions from notify_scan_complete
//!   - Tree tables: sapling_tree_shards, sapling_tree_checkpoints (with real note commitments)
//!
//! Start the darkside lightwalletd first (from repo root):
//!   Tests/lightwalletd/lightwalletd --no-tls-very-insecure --data-dir /tmp \
//!     --darkside-very-insecure --log-file /tmp/t64-lwd.log
//! Then: cargo test -p slipstream-core --features darkside -- --ignored --test-threads=1
#![cfg(feature = "darkside")]

use std::time::Duration;

use futures_util::StreamExt;
use rusqlite::Connection;
use slipstream_core::{
    chunk::chunk_queue,
    config::{EngineConfig, Endpoint},
    darkside::DarksideCtl,
    fetch::{FetchPlan, run_fetch},
    grpc,
    oracle::semantic_diff,
    scan::scan_chunks_from_treestate,
    wallet_session::{WalletSession, TEST_UFVK},
};
use zcash_client_backend::proto::service::{BlockId, BlockRange, TreeState};
use zcash_protocol::consensus::Network;

// ---------------------------------------------------------------------------
// Constants — mirror darkside_sync.rs exactly.
// ---------------------------------------------------------------------------

fn darkside_endpoint() -> Endpoint {
    Endpoint { host: "127.0.0.1".into(), port: 9067, tls: false }
}

const BIRTHDAY_HEIGHT: u64 = 663_150;

const TX_MAINNET_BLOCK_URL: &str =
    "https://raw.githubusercontent.com/zcash-hackworks/darksidewalletd-test-data/master/basic-reorg/663150.txt";

const TX_663174_URL: &str =
    "https://raw.githubusercontent.com/zcash-hackworks/darksidewalletd-test-data/master/transactions/recv/8f064d23c66dc36e32445e5f3b50e0f32ac3ddb78cff21fb521eb6c19c07c99a.txt";

const TX_663188_URL: &str =
    "https://raw.githubusercontent.com/zcash-hackworks/darksidewalletd-test-data/master/transactions/recv/15a677b6770c5505fb47439361d3d3a7c21238ee1a6874fdedad18ae96850590.txt";

const APPLY_HEIGHT: i32 = 663_188;
const START_SAPLING_TREE_SIZE: u32 = 128_607;

const EXPECTED_TX_COUNT: i64 = 2;
const EXPECTED_BALANCE_ZATOSHI: i64 = 200_000;

/// Hex-encoded CommitmentTree for 128607 leaves — identical to darkside_sync.rs.
const SAPLING_TREE_128607: &str = concat!(
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    "00",
    "10",
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    "00",
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    "00",
    "00",
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    "00",
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
);

// ---------------------------------------------------------------------------
// Shared staging helper
// ---------------------------------------------------------------------------

/// Stage the standard darkside fixture chain (TX_MAINNET_BLOCK_URL + two tx
/// fixtures at 663174/663188, applied at 663188).  Mirrors the setup in
/// `sync_finds_fixture_transactions` verbatim.
async fn stage_fixture_chain(ctl: &mut DarksideCtl) {
    ctl.reset_with_tree_sizes(START_SAPLING_TREE_SIZE, 0)
        .await
        .expect("darkside reset");
    ctl.stage_blocks_url(TX_MAINNET_BLOCK_URL)
        .await
        .expect("stage 663150 block");
    ctl.stage_blocks_create(663_151, 100)
        .await
        .expect("stage empty blocks");
    ctl.stage_transactions_url(TX_663174_URL, 663_174)
        .await
        .expect("stage tx at 663174");
    ctl.stage_transactions_url(TX_663188_URL, 663_188)
        .await
        .expect("stage tx at 663188");
    ctl.apply_staged(APPLY_HEIGHT).await.expect("apply staged");
    // Darkside propagates asynchronously — wait 2 s (Swift pattern).
    tokio::time::sleep(Duration::from_secs(2)).await;
}

/// Run the direct scan pipeline into `db_path` with `sparse` flag.
/// Mirrors `sync_finds_fixture_transactions` step-by-step.
async fn run_pipeline(ep: &Endpoint, db_path: &std::path::Path, sparse: bool) {
    let mut cfg = EngineConfig::new(Network::MainNetwork, db_path.to_path_buf(), ep.clone());
    cfg.chunk_blocks = 100;
    cfg.fetch_streams = 2;

    let mut session = WalletSession::open(Network::MainNetwork, db_path).expect("open wallet");

    let birthday_ts = TreeState {
        network: "main".into(),
        height: BIRTHDAY_HEIGHT - 1,
        hash: "0".repeat(64),
        time: 1,
        sapling_tree: SAPLING_TREE_128607.into(),
        ..Default::default()
    };
    session.ensure_account(TEST_UFVK, birthday_ts).expect("ensure_account");

    let mut client = grpc::connect(ep).await.expect("grpc connect");
    let chain_tip = grpc::get_latest_block_height(&mut client)
        .await
        .expect("get_latest_block_height");
    session.update_chain_tip(chain_tip).expect("update_chain_tip");

    // Pre-seed block 663149 metadata (v0.4.9 workaround).
    let block_663149_hash: Vec<u8> = {
        let req = BlockRange {
            start: Some(BlockId { height: BIRTHDAY_HEIGHT, hash: vec![] }),
            end:   Some(BlockId { height: BIRTHDAY_HEIGHT, hash: vec![] }),
            ..Default::default()
        };
        let mut stream = client
            .get_block_range(req)
            .await
            .expect("get_block_range for birthday")
            .into_inner();
        let first_block = stream.next().await
            .expect("stream should yield birthday block")
            .expect("block 663150 ok");
        first_block.prev_hash
    };
    assert_eq!(block_663149_hash.len(), 32, "prev_hash should be 32 bytes");
    session
        .seed_block_metadata(BIRTHDAY_HEIGHT - 1, START_SAPLING_TREE_SIZE, &block_663149_hash)
        .expect("seed_block_metadata");

    let initial_scan_state = TreeState {
        network: "main".into(),
        height: BIRTHDAY_HEIGHT - 1,
        hash: "0".repeat(64),
        time: 1,
        sapling_tree: SAPLING_TREE_128607.into(),
        ..Default::default()
    };

    let (tx, rx) = chunk_queue(cfg.memory_budget_bytes);
    let plan = FetchPlan::new(BIRTHDAY_HEIGHT, chain_tip, cfg.chunk_blocks, cfg.fetch_streams);
    let fetch_ep = ep.clone();
    let fetch_task = tokio::spawn(async move { run_fetch(&fetch_ep, plan, tx, None).await });

    scan_chunks_from_treestate(&mut session, BIRTHDAY_HEIGHT, initial_scan_state, rx, sparse)
        .await
        .expect("scan_chunks_from_treestate");

    let _ = fetch_task.await.expect("fetch task join").expect("fetch stats");
}

// ---------------------------------------------------------------------------
// The darkside oracle test
// ---------------------------------------------------------------------------

/// T6.4 REAL-NOTES oracle: upstream vs sparse paths produce identical databases
/// for a chain containing real wallet-note transactions.
///
/// Two separate wallet dirs; darkside reset + re-staged between runs to ensure
/// both wallets see a bit-identical server response.
///
/// Asserts:
///   1. `semantic_diff` is clean (D3 requirement).
///   2. Wallet B (sparse) still detects EXPECTED_TX_COUNT=2 transactions.
///   3. Wallet B (sparse) still has balance = EXPECTED_BALANCE_ZATOSHI=200000 zatoshi.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires local darkside lightwalletd + internet (fixture URLs)"]
async fn sparse_pipeline_matches_upstream_on_darkside_fixture() {
    let ep = darkside_endpoint();

    // ── Run A: upstream path ─────────────────────────────────────────────────
    let dir_a = tempfile::tempdir().expect("tempdir A");
    let db_a = dir_a.path().join("data.db");
    {
        let mut ctl = DarksideCtl::connect(&ep).await.expect("darkside connect");
        stage_fixture_chain(&mut ctl).await;
    }
    run_pipeline(&ep, &db_a, false).await;

    // ── Run B: sparse path — reset + re-stage identically ────────────────────
    let dir_b = tempfile::tempdir().expect("tempdir B");
    let db_b = dir_b.path().join("data.db");
    {
        let mut ctl = DarksideCtl::connect(&ep).await.expect("darkside connect");
        stage_fixture_chain(&mut ctl).await;
    }
    run_pipeline(&ep, &db_b, true).await;

    // ── Oracle: semantic diff ─────────────────────────────────────────────────
    let report = semantic_diff(&db_a, &db_b).expect("semantic_diff");
    assert!(
        report.is_clean(),
        "darkside oracle diverged (sparse vs upstream):\n{}",
        report.render()
    );

    // ── Belt-and-braces: wallet B still has the right notes/balance ───────────
    let conn_b = Connection::open_with_flags(
        &db_b,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open wallet B read-only");

    let tx_count: i64 = conn_b
        .query_row("SELECT COUNT(*) FROM transactions", [], |r| r.get(0))
        .expect("query tx count");
    assert_eq!(
        tx_count, EXPECTED_TX_COUNT,
        "wallet B (sparse): expected {EXPECTED_TX_COUNT} transactions, got {tx_count}. \
         Source: BalanceTests.swift:888"
    );

    let balance: Option<i64> = conn_b
        .query_row(
            "SELECT SUM(value) FROM sapling_received_notes \
             WHERE id NOT IN (SELECT sapling_received_note_id FROM sapling_received_note_spends)",
            [],
            |r| r.get(0),
        )
        .expect("query sparse balance");
    assert_eq!(
        balance.unwrap_or(0),
        EXPECTED_BALANCE_ZATOSHI,
        "wallet B (sparse): expected balance {EXPECTED_BALANCE_ZATOSHI} zatoshi, got {balance:?}. \
         Source: BalanceTests.swift:889"
    );
}
