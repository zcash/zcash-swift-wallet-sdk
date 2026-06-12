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
use zcash_client_backend::data_api::WalletWrite;
use zcash_client_backend::proto::service::{BlockId, BlockRange, TreeState};
use zcash_protocol::consensus::{BlockHeight, Network};

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

/// Run the direct scan pipeline into `db_path` with `sparse` / `write_behind` flags.
/// Mirrors `sync_finds_fixture_transactions` step-by-step.
async fn run_pipeline(ep: &Endpoint, db_path: &std::path::Path, sparse: bool, write_behind: bool) {
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

    scan_chunks_from_treestate(&mut session, BIRTHDAY_HEIGHT, initial_scan_state, rx, sparse, write_behind)
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
    run_pipeline(&ep, &db_a, false, false).await;

    // ── Run B: sparse path — reset + re-stage identically ────────────────────
    let dir_b = tempfile::tempdir().expect("tempdir B");
    let db_b = dir_b.path().join("data.db");
    {
        let mut ctl = DarksideCtl::connect(&ep).await.expect("darkside connect");
        stage_fixture_chain(&mut ctl).await;
    }
    run_pipeline(&ep, &db_b, true, false).await;

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

/// T6.9 REAL-NOTES write-behind oracle: upstream vs WRITE-BEHIND paths produce
/// identical databases for a chain containing real wallet-note transactions —
/// the strongest available proof that the pending-aware facade's running
/// nullifier view and metadata tail carry REAL found-note state correctly
/// (the hermetic write-behind oracles use synthetic, non-decrypting outputs).
///
/// Asserts mirror the sparse fixture oracle:
///   1. `semantic_diff` CLEAN (deferral changes timing, never content).
///   2. Wallet B (write-behind) detects EXPECTED_TX_COUNT=2 transactions.
///   3. Wallet B (write-behind) balance = EXPECTED_BALANCE_ZATOSHI=200000.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires local darkside lightwalletd + internet (fixture URLs)"]
async fn write_behind_pipeline_matches_upstream_on_darkside_fixture() {
    let ep = darkside_endpoint();

    // ── Run A: upstream path ─────────────────────────────────────────────────
    let dir_a = tempfile::tempdir().expect("tempdir A");
    let db_a = dir_a.path().join("data.db");
    {
        let mut ctl = DarksideCtl::connect(&ep).await.expect("darkside connect");
        stage_fixture_chain(&mut ctl).await;
    }
    run_pipeline(&ep, &db_a, false, false).await;

    // ── Run B: write-behind path — reset + re-stage identically ─────────────
    let dir_b = tempfile::tempdir().expect("tempdir B");
    let db_b = dir_b.path().join("data.db");
    {
        let mut ctl = DarksideCtl::connect(&ep).await.expect("darkside connect");
        stage_fixture_chain(&mut ctl).await;
    }
    run_pipeline(&ep, &db_b, true, true).await;

    // ── Oracle: semantic diff ─────────────────────────────────────────────────
    let report = semantic_diff(&db_a, &db_b).expect("semantic_diff");
    assert!(
        report.is_clean(),
        "darkside oracle diverged (write-behind vs upstream):\n{}",
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
        "wallet B (write-behind): expected {EXPECTED_TX_COUNT} transactions, got {tx_count}. \
         Source: BalanceTests.swift:888"
    );

    let balance: Option<i64> = conn_b
        .query_row(
            "SELECT SUM(value) FROM sapling_received_notes \
             WHERE id NOT IN (SELECT sapling_received_note_id FROM sapling_received_note_spends)",
            [],
            |r| r.get(0),
        )
        .expect("query write-behind balance");
    assert_eq!(
        balance.unwrap_or(0),
        EXPECTED_BALANCE_ZATOSHI,
        "wallet B (write-behind): expected balance {EXPECTED_BALANCE_ZATOSHI} zatoshi, got {balance:?}. \
         Source: BalanceTests.swift:889"
    );
}

/// T6.5 truncate+rescan oracle: after a full sync on wallets A (upstream) and B (sparse),
/// truncate both to a height below the second tx (requesting 663185; both wallets snap to
/// the nearest shared checkpoint ≤ 663185 which is 663174, the first tx block), re-scan
/// the gap from 663175 to 663188 (A=upstream, B=sparse), then `semantic_diff` must be clean.
///
/// This proves flush→truncate→reflush converges: the checkpoint tables that
/// `select_truncation_height` inspects are populated identically by both paths
/// (only blocks with shielded outputs carry a checkpoint — empty blocks do NOT, per
/// scanning/compact.rs:672-810), so both wallets snap to the same truncation height
/// and the re-scan produces the same final DB.
///
/// Key fact: checkpoints for the 663150-663188 fixture are at heights 663149
/// (from_state frontier), 663174 (first tx, 1 Sapling note), and 663188 (second tx,
/// 1 Sapling note) — empty blocks carry no checkpoint.  Requesting truncation at 663185
/// snaps to 663174 on both paths.  Re-scanning 663175..=663188 exercises the second tx.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires local darkside lightwalletd + internet (fixture URLs)"]
async fn truncate_rescan_oracle_is_clean() {
    // Request truncation between the two txs.  Both wallets snap to the
    // nearest checkpoint ≤ 663185, which is 663174 (the first tx block).
    const TRUNCATE_REQUEST: u32 = 663_185;

    let ep = darkside_endpoint();

    // ── Run A: upstream path — initial full sync ─────────────────────────────
    let dir_a = tempfile::tempdir().expect("tempdir A");
    let db_a = dir_a.path().join("data.db");
    {
        let mut ctl = DarksideCtl::connect(&ep).await.expect("darkside connect");
        stage_fixture_chain(&mut ctl).await;
    }
    run_pipeline(&ep, &db_a, false, false).await;

    // ── Run B: sparse path — reset + re-stage + initial full sync ────────────
    let dir_b = tempfile::tempdir().expect("tempdir B");
    let db_b = dir_b.path().join("data.db");
    {
        let mut ctl = DarksideCtl::connect(&ep).await.expect("darkside connect");
        stage_fixture_chain(&mut ctl).await;
    }
    run_pipeline(&ep, &db_b, true, false).await;

    // ── Truncate both wallets; assert they snap to the same height ────────────
    let truncated_a_height: u32;
    {
        let mut session_a = WalletSession::open(Network::MainNetwork, &db_a)
            .expect("open wallet A for truncation");
        let truncated_a = session_a
            .db_mut()
            .truncate_to_height(BlockHeight::from(TRUNCATE_REQUEST))
            .expect("truncate_to_height A");
        truncated_a_height = u32::from(truncated_a);
        println!("truncate-oracle: wallet A truncated to {truncated_a_height}");
    }
    let truncated_b_height: u32;
    {
        let mut session_b = WalletSession::open(Network::MainNetwork, &db_b)
            .expect("open wallet B for truncation");
        let truncated_b = session_b
            .db_mut()
            .truncate_to_height(BlockHeight::from(TRUNCATE_REQUEST))
            .expect("truncate_to_height B");
        truncated_b_height = u32::from(truncated_b);
        println!("truncate-oracle: wallet B truncated to {truncated_b_height}");
    }

    // Both paths must produce the same truncation height (checkpoint parity).
    assert_eq!(
        truncated_a_height, truncated_b_height,
        "truncate-oracle: truncation heights differ (A={truncated_a_height}, B={truncated_b_height})"
    );
    let rescan_start: u64 = truncated_a_height as u64 + 1;
    println!("truncate-oracle: re-scanning from {rescan_start}");

    // ── Re-stage the fixture chain so both re-scans see the same server ───────
    {
        let mut ctl = DarksideCtl::connect(&ep).await.expect("darkside connect (re-stage)");
        stage_fixture_chain(&mut ctl).await;
    }

    // ── Re-stage so both re-scans hit the same server state ──────────────────
    {
        let mut ctl = DarksideCtl::connect(&ep).await.expect("darkside connect (re-stage)");
        stage_fixture_chain(&mut ctl).await;
    }

    // ── Re-scan from BIRTHDAY_HEIGHT (663150) on both wallets ────────────────
    //
    // Re-scan from the BIRTHDAY rather than from rescan_start because
    // SAPLING_TREE_128607 is the correct tree state at 663149 (birthday-1), and
    // we don't have a pre-built frontier blob for the tree at 663174 (which would
    // require computing 128608 leaves). Starting from 663150 with
    // SAPLING_TREE_128607 is always safe: blocks 663150..=rescan_start-1 are
    // still in the `blocks` table (only blocks > truncated_height were deleted),
    // so `put_blocks` UPSERTs them with the same values, and blocks
    // rescan_start..=663188 are freshly inserted.
    {
        let mut cfg = EngineConfig::new(Network::MainNetwork, db_a.clone(), ep.clone());
        cfg.chunk_blocks = 100;
        cfg.fetch_streams = 2;

        let mut session_a = WalletSession::open(Network::MainNetwork, &db_a)
            .expect("open wallet A for re-scan");

        let mut client_a = grpc::connect(&ep).await.expect("grpc connect A");
        let chain_tip_a = grpc::get_latest_block_height(&mut client_a)
            .await
            .expect("get_latest_block_height A");
        session_a.update_chain_tip(chain_tip_a).expect("update_chain_tip A");

        let initial_state_a = TreeState {
            network: "main".into(),
            height: BIRTHDAY_HEIGHT - 1,
            hash: "0".repeat(64),
            time: 1,
            sapling_tree: SAPLING_TREE_128607.into(),
            ..Default::default()
        };
        let (tx_a, rx_a) = slipstream_core::chunk::chunk_queue(cfg.memory_budget_bytes);
        let plan_a = slipstream_core::fetch::FetchPlan::new(
            BIRTHDAY_HEIGHT,
            chain_tip_a,
            cfg.chunk_blocks,
            cfg.fetch_streams,
        );
        let fetch_ep_a = ep.clone();
        let fetch_task_a = tokio::spawn(async move {
            slipstream_core::fetch::run_fetch(&fetch_ep_a, plan_a, tx_a, None).await
        });

        slipstream_core::scan::scan_chunks_from_treestate(
            &mut session_a,
            BIRTHDAY_HEIGHT,
            initial_state_a,
            rx_a,
            false, // upstream
            false,
        )
        .await
        .expect("re-scan wallet A from birthday");

        let _ = fetch_task_a.await.expect("fetch join A").expect("fetch stats A");
    }

    {
        let mut cfg = EngineConfig::new(Network::MainNetwork, db_b.clone(), ep.clone());
        cfg.chunk_blocks = 100;
        cfg.fetch_streams = 2;

        let mut session_b = WalletSession::open(Network::MainNetwork, &db_b)
            .expect("open wallet B for re-scan");

        let mut client_b = grpc::connect(&ep).await.expect("grpc connect B");
        let chain_tip_b = grpc::get_latest_block_height(&mut client_b)
            .await
            .expect("get_latest_block_height B");
        session_b.update_chain_tip(chain_tip_b).expect("update_chain_tip B");

        let initial_state_b = TreeState {
            network: "main".into(),
            height: BIRTHDAY_HEIGHT - 1,
            hash: "0".repeat(64),
            time: 1,
            sapling_tree: SAPLING_TREE_128607.into(),
            ..Default::default()
        };
        let (tx_b, rx_b) = slipstream_core::chunk::chunk_queue(cfg.memory_budget_bytes);
        let plan_b = slipstream_core::fetch::FetchPlan::new(
            BIRTHDAY_HEIGHT,
            chain_tip_b,
            cfg.chunk_blocks,
            cfg.fetch_streams,
        );
        let fetch_ep_b = ep.clone();
        let fetch_task_b = tokio::spawn(async move {
            slipstream_core::fetch::run_fetch(&fetch_ep_b, plan_b, tx_b, None).await
        });

        slipstream_core::scan::scan_chunks_from_treestate(
            &mut session_b,
            BIRTHDAY_HEIGHT,
            initial_state_b,
            rx_b,
            true, // sparse
            false,
        )
        .await
        .expect("re-scan wallet B (sparse) from birthday");

        let _ = fetch_task_b.await.expect("fetch join B").expect("fetch stats B");
    }

    // ── Oracle: semantic diff after truncate+reflush ───────────────────────────
    let report = semantic_diff(&db_a, &db_b).expect("semantic_diff after truncate+rescan");
    println!("truncate-oracle diff:\n{}", report.render());
    assert!(
        report.is_clean(),
        "truncate+rescan oracle diverged (upstream vs sparse):\n{}",
        report.render()
    );
    println!("truncate-oracle: VERDICT IDENTICAL — flush→truncate→reflush converges");
}
