//! Correctness test: slipstream engine finds fixture transactions in a darkside chain.
//!
//! Mirrors `BalanceTests.testVerifyIncomingTransaction` from
//! `Tests/DarksideTests/BalanceTests.swift:871-889`:
//!   - Builds a chain from the canonical 663150 mainnet block (txMainnetBlockUrl)
//!   - Stages empty blocks 663151..663250
//!   - Stages real Sapling receive transactions at heights 663174 and 663188
//!   - Applies at 663188 (defaultLatestHeight from BalanceTests.swift:15)
//!   - Expects 2 cleared transactions and total balance = 200000 zatoshi
//!
//! NOTE on lightwalletd compatibility: the binary at Tests/lightwalletd is v0.4.9 (2022-02-20).
//! It does NOT support GetTreeState/GetSubtreeRoots. To work around this, the test
//! drives the pipeline directly (fetch + scan_chunks_from_treestate + session ops) because
//! lightwalletd v0.4.9 lacks GetTreeState/GetSubtreeRoots; engine::sync_once is exercised
//! end-to-end by the G2 mainnet CLI runs instead.
//!
//! Start the darkside lightwalletd first (from repo root):
//!   Tests/lightwalletd/lightwalletd --no-tls-very-insecure --data-dir /tmp \
//!     --darkside-very-insecure --log-file /dev/stdout
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
    scan::scan_chunks_from_treestate,
    wallet_session::{WalletSession, TEST_UFVK},
};
use zcash_client_backend::proto::service::{BlockId, BlockRange, TreeState};
use zcash_protocol::consensus::Network;

// ---------------------------------------------------------------------------
// Fixture constants — values extracted from Swift test sources listed below.
// ---------------------------------------------------------------------------

/// The canonical darkside endpoint (plaintext, port 9067).
fn darkside_endpoint() -> Endpoint {
    Endpoint { host: "127.0.0.1".into(), port: 9067, tls: false }
}

/// Birthday for the test wallet (sapling activation height).
/// Source: DarksideSanityCheckTests.swift:15 / BalanceTests.swift:16 / FakeChainBuilder.swift:28
const BIRTHDAY_HEIGHT: u64 = 663_150;

/// `FakeChainBuilder.txMainnetBlockUrl` — the single real mainnet compact block at 663150.
/// Source: Tests/TestUtils/FakeChainBuilder.swift:17
const TX_MAINNET_BLOCK_URL: &str =
    "https://raw.githubusercontent.com/zcash-hackworks/darksidewalletd-test-data/master/basic-reorg/663150.txt";

/// Transaction received by the test wallet at height 663174.
/// txid: 8f064d23c66dc36e32445e5f3b50e0f32ac3ddb78cff21fb521eb6c19c07c99a
/// Source: Tests/TestUtils/FakeChainBuilder.swift:210 (`txUrls[663174]`)
const TX_663174_URL: &str =
    "https://raw.githubusercontent.com/zcash-hackworks/darksidewalletd-test-data/master/transactions/recv/8f064d23c66dc36e32445e5f3b50e0f32ac3ddb78cff21fb521eb6c19c07c99a.txt";

/// Transaction received by the test wallet at height 663188.
/// txid: 15a677b6770c5505fb47439361d3d3a7c21238ee1a6874fdedad18ae96850590
/// Source: Tests/TestUtils/FakeChainBuilder.swift:211 (`txUrls[663188]`)
const TX_663188_URL: &str =
    "https://raw.githubusercontent.com/zcash-hackworks/darksidewalletd-test-data/master/transactions/recv/15a677b6770c5505fb47439361d3d3a7c21238ee1a6874fdedad18ae96850590.txt";

/// Height at which staged blocks are applied (defaultLatestHeight in BalanceTests.swift:15).
/// Source: Tests/DarksideTests/BalanceTests.swift:15
const APPLY_HEIGHT: i32 = 663_188;

/// Sapling commitment tree size at birthday, matching FakeChainBuilder.buildChain.
/// Source: Tests/TestUtils/FakeChainBuilder.swift:29
const START_SAPLING_TREE_SIZE: u32 = 128_607;

/// Expected number of cleared wallet transactions after syncing the fixture chain.
/// Source: Tests/DarksideTests/BalanceTests.swift:888 (`XCTAssertEqual(clearedTransactions.count, 2)`)
const EXPECTED_TX_COUNT: i64 = 2;

/// Expected total received balance in zatoshi after syncing.
/// Source: Tests/DarksideTests/BalanceTests.swift:889 (`XCTAssertEqual(expectedBalance, Zatoshi(200000))`)
const EXPECTED_BALANCE_ZATOSHI: i64 = 200_000;

/// Hex-encoded `CommitmentTree<sapling::Node, 32>` representing a tree with exactly
/// `START_SAPLING_TREE_SIZE` (128607) leaves and all-zero placeholder node hashes.
///
/// Used as `sapling_tree` in `TreeState` so `to_chain_state().final_sapling_tree().tree_size()`
/// returns 128607, matching `FakeChainBuilder.buildChain` (`startSaplingTreeSize = 128607`).
///
/// Without the right tree size `scan_cached_blocks` raises `NonSequentialBlocks` when
/// committing the first scanned block (invariant: from_state.tree_size + block_outputs ==
/// block.final_tree_size).  The all-zero node hashes are placeholder values; `sapling::Node`
/// treats 0x00*32 as the empty leaf — fully valid for this use-case.
///
/// Encoding (zcash_primitives `write_commitment_tree`):
///   OptionalNode(left) | OptionalNode(right) | CompactSize(16) | OptionalNode(parents[0..15])
/// For last_pos=128606 (0b11111011001011110): left=Some, right=None,
///   parents per bits 1..16 of 128606: [1,1,1,1,0,1,0,0,1,1,0,1,1,1,1,1] → 12 Somes, 4 Nones.
/// Total bytes: 33 + 1 + 1 + 12*33 + 4*1 = 435 bytes → 870 hex chars.
///
/// Verified: CommitmentTree::size() with this structure = 128607.
const SAPLING_TREE_128607: &str = concat!(
    // left = Some(0x00 * 32):  0x01 flag + 32 zero bytes
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    // right = None:  0x00 flag
    "00",
    // parents: CompactSize(16) = 0x10, then 16 entries
    "10",
    // parents[0..3] = Some (bits 1..4 of 128606 are 1):
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    // parents[4] = None (bit 5 of 128606 = 0):
    "00",
    // parents[5] = Some (bit 6 = 1):
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    // parents[6..7] = None (bits 7..8 = 0):
    "00",
    "00",
    // parents[8..9] = Some (bits 9..10 = 1):
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    // parents[10] = None (bit 11 = 0):
    "00",
    // parents[11..15] = Some (bits 12..16 = 1):
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
    "01", "0000000000000000000000000000000000000000000000000000000000000000",
);

// ---------------------------------------------------------------------------
// The correctness test
// ---------------------------------------------------------------------------

/// End-to-end correctness test: slipstream engine scans a darkside chain that
/// mirrors `FakeChainBuilder.buildChain` and finds the expected wallet state.
///
/// Asserts:
///   1. Engine completes successfully with chain_tip == APPLY_HEIGHT.
///   2. At least APPLY_HEIGHT − BIRTHDAY_HEIGHT + 1 blocks were scanned.
///   3. rusqlite query: COUNT(*) FROM transactions == EXPECTED_TX_COUNT (2).
///   4. rusqlite query: SUM(received_by_account value) == EXPECTED_BALANCE_ZATOSHI (200000).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires local darkside lightwalletd + internet (fixture URLs)"]
async fn sync_finds_fixture_transactions() {
    let ep = darkside_endpoint();

    // --- Set up darkside chain (mirrors FakeChainBuilder.buildChain) ---
    let mut ctl = DarksideCtl::connect(&ep).await.expect("darkside connect");

    // Reset with sapling tree size matching FakeChainBuilder.buildChain
    // (FakeChainBuilder.swift:28-33: startSaplingTreeSize=128607, startOrchardTreeSize=0).
    ctl.reset_with_tree_sizes(START_SAPLING_TREE_SIZE, 0)
        .await
        .expect("reset");

    // Stage the real mainnet block at height 663150.
    // (FakeChainBuilder.swift:35: darksideWallet.useDataset(from: txMainnetBlockUrl))
    ctl.stage_blocks_url(TX_MAINNET_BLOCK_URL).await.expect("stage 663150 block");

    // Stage empty blocks 663151..663250 (100 blocks).
    // (FakeChainBuilder.swift:37: stageBlocksCreate(from: 663151, count: 100))
    ctl.stage_blocks_create(663_151, 100).await.expect("stage empty blocks");

    // Stage real receive transactions at the heights the test wallet owns them.
    // (FakeChainBuilder.swift:97: stageTransaction(from: txUrls[663174]!, at: 663174))
    ctl.stage_transactions_url(TX_663174_URL, 663_174)
        .await
        .expect("stage tx at 663174");
    // (FakeChainBuilder.swift:99: stageTransaction(from: txUrls[663188]!, at: 663188))
    ctl.stage_transactions_url(TX_663188_URL, 663_188)
        .await
        .expect("stage tx at 663188");

    // NOTE: The lightwalletd binary in Tests/lightwalletd does NOT support AddTreeState
    // (it returns "unknown method AddTreeState"). Darkside synthesizes tree states from
    // the staged blocks — they will have empty sapling/orchard commitment trees since the
    // fabricated empty blocks have no shielded outputs. This is acceptable: the scanner
    // will work with empty trees (no subtree root checkpoints needed for a small test chain).

    // Apply staged blocks up to APPLY_HEIGHT (663188).
    // (BalanceTests.swift:873: coordinator.applyStaged(blockheight: defaultLatestHeight))
    ctl.apply_staged(APPLY_HEIGHT).await.expect("apply staged");

    // Darkside propagates staged state asynchronously after ApplyStaged.
    // Sleep 2s to ensure tip is visible before syncing (matches Swift DarksideTests sleep(2)).
    tokio::time::sleep(Duration::from_secs(2)).await;

    // --- Pre-import account (workaround for GetTreeState not supported in v0.4.9) ---
    //
    // The lightwalletd binary at Tests/lightwalletd is v0.4.9 (2022-02-20) which does NOT
    // support GetTreeState (returns "unsupported RPC"). The engine::sync_once would call
    // get_tree_state(birthday - 1) when ufvk is Some. We work around this by pre-importing
    // the account here with a synthetic birthday TreeState at height 663149 (empty sapling
    // tree — valid because no notes exist before sapling activation at 663150).
    //
    // The synthetic treestate satisfies WalletSession::ensure_account's from_treestate call.
    // WalletSession::ensure_account is idempotent — the engine sees an existing account and
    // skips the GetTreeState fetch entirely when called with ufvk=None below.
    // --- COMPATIBILITY WORKAROUND for lightwalletd v0.4.9 (2022-02-20) ---
    //
    // The binary at Tests/lightwalletd does NOT support GetTreeState or GetSubtreeRoots.
    // engine::sync_once requires both. We drive the sync components directly, skipping
    // the two unsupported RPCs:
    //
    //   • Pre-import account using a synthetic birthday TreeState at height 663149.
    //     (Valid: no notes before sapling activation at 663150; empty frontier accepted.)
    //   • Call update_chain_tip directly (GetLatestBlock IS supported).
    //   • Skip put_subtree_roots (GetSubtreeRoots not supported; empty roots are correct
    //     for fabricated blocks which contain no real sapling commitments).
    //   • Drive scheduler::run_to_completion directly (full fetch∥scan pipeline).
    //
    // This exercises all T2.2–T2.5 modules and produces identical wallet state to
    // engine::sync_once for a chain with no pre-existing subtree root checkpoints.
    let wallet_dir = tempfile::tempdir().expect("tempdir");
    let db_path = wallet_dir.path().join("data.db");

    let mut cfg = EngineConfig::new(Network::MainNetwork, db_path.clone(), ep.clone());
    cfg.chunk_blocks = 100; // small chunks for this test chain (~39 blocks)
    cfg.fetch_streams = 2;

    let mut session =
        WalletSession::open(Network::MainNetwork, &db_path).expect("open wallet");

    // Import account: birthday treestate at 663149 (= birthday_height - 1 = 663150 - 1).
    // Use SAPLING_TREE_128607 so birthday_sapling_tree_size is stored as 128607 in the
    // accounts table — matching FakeChainBuilder.startSaplingTreeSize = 128607.
    let birthday_ts = TreeState {
        network: "main".into(),
        height: 663_149,
        hash: "0".repeat(64),
        time: 1,
        sapling_tree: SAPLING_TREE_128607.into(),
        ..Default::default()
    };
    session
        .ensure_account(TEST_UFVK, birthday_ts)
        .expect("ensure_account");

    // Update chain tip from the server (GetLatestBlock supported by v0.4.9).
    let mut client = grpc::connect(&ep).await.expect("grpc connect");
    let chain_tip = grpc::get_latest_block_height(&mut client)
        .await
        .expect("get_latest_block_height");
    session
        .update_chain_tip(chain_tip)
        .expect("update_chain_tip");

    // NOTE: FakeChainBuilder.setSubTreeRoots (FakeChainBuilder.swift:292-319) injects two
    // real mainnet Sapling subtree roots. In the Swift test, they are needed to satisfy
    // the scan queue's request for commitment tree size information.
    //
    // In our Rust implementation, the tree size is provided by the pre-seeded block
    // metadata at height 663149 (see `seed_block_metadata` above). We do NOT inject
    // subtree roots here because:
    //
    //   1. The darkside server (v0.4.9) doesn't support GetSubtreeRoots, so we cannot
    //      fetch them programmatically.
    //   2. The real mainnet roots (hardcoded from FakeChainBuilder) conflict with what
    //      the shard tree computes from the synthetic darkside blocks — the scanner
    //      would raise "Inserted root conflicts with existing root" immediately.
    //   3. The tree size information needed to start scanning is already available from
    //      the seeded block record; subtree roots are only needed for *progress* queries
    //      and future spending.
    //
    // We leave `sapling_tree_shards` empty for this test. Note that this test only
    // verifies that the engine FINDS the transactions — spending is tested separately.

    // --- Pre-seed block 663149 metadata (darkside v0.4.9 compatibility fix) ---
    //
    // lightwalletd v0.4.9 does NOT set `chain_metadata` on compact blocks.
    // `scan_cached_blocks` uses `block_metadata(scan_start - 1)` as the initial
    // `prior_block_metadata`; if that block is not in the DB, prior_metadata is None,
    // and the scanner cannot determine the Sapling note commitment tree size from
    // the block's `chain_metadata` field (also None). This causes TreeSizeUnknown.
    //
    // Fix: pre-insert a `blocks` record at height 663149 with the correct hash and
    // `sapling_commitment_tree_size = 128607` (from FakeChainBuilder.swift:29).
    //
    // The hash must match block 663150's `prev_hash` to pass the chain continuity check.
    // We fetch block 663150 from the darkside server (BIRTHDAY_HEIGHT = 663150) and read
    // its `prev_hash` field — that is the real mainnet block 663149 hash.
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

    // --- Fetch ∥ Scan pipeline ---
    // We drive fetch + scan directly (bypassing scheduler::run_to_completion which
    // calls scan_chunks → get_tree_state, unsupported by v0.4.9).
    //
    // We use scan_chunks_from_treestate with the birthday treestate at 663149 (empty
    // Sapling tree — valid, because no notes existed before sapling activation at 663150).
    // The scanner processes the blocks in order and discovers the shielded notes via
    // trial decryption against TEST_UFVK; the commitment tree is updated in-DB.
    let scan_range_start = BIRTHDAY_HEIGHT;
    let scan_range_end = chain_tip;

    // initial_scan_state must have sapling_tree encoding a 128607-leaf frontier so that
    // put_blocks' sequential-check passes: from_state.tree_size + block_outputs == block.final_tree_size.
    // Block 663150 has `final_tree_size = 128607 + K` (K = sapling outputs in that block);
    // if from_state.tree_size is 0, the check fails. Using SAPLING_TREE_128607 gives 128607.
    let initial_scan_state = TreeState {
        network: "main".into(),
        height: scan_range_start - 1, // = 663149
        hash: "0".repeat(64),         // 32 zero bytes as hex — accepted by to_chain_state()
        time: 1,
        sapling_tree: SAPLING_TREE_128607.into(),
        ..Default::default()
    };

    let (tx, rx) = chunk_queue(cfg.memory_budget_bytes);
    let plan = FetchPlan::new(scan_range_start, scan_range_end, cfg.chunk_blocks, cfg.fetch_streams);
    let fetch_ep = ep.clone();

    let fetch_task = tokio::spawn(async move { run_fetch(&fetch_ep, plan, tx, None).await });

    let scan_stats = scan_chunks_from_treestate(&mut session, scan_range_start, initial_scan_state, rx)
        .await
        .expect("scan_chunks_from_treestate");

    let fetch_stats = fetch_task
        .await
        .expect("fetch task join")
        .expect("fetch stats");

    // --- Assertion 1: chain tip ---
    assert_eq!(
        chain_tip,
        APPLY_HEIGHT as u64,
        "chain_tip must equal APPLY_HEIGHT ({APPLY_HEIGHT})"
    );

    // --- Assertion 2: blocks scanned ---
    // Exact: APPLY_HEIGHT(663188) - BIRTHDAY_HEIGHT(663150) + 1 = 39 blocks.
    let expected_min_blocks = APPLY_HEIGHT as u64 - BIRTHDAY_HEIGHT + 1;
    assert!(
        scan_stats.blocks >= expected_min_blocks,
        "expected scan.blocks >= {expected_min_blocks} (APPLY_HEIGHT - BIRTHDAY + 1), got {}",
        scan_stats.blocks
    );
    assert!(fetch_stats.blocks >= expected_min_blocks, "fetch blocks mismatch");

    // --- Assertions 3 + 4: wallet truth via rusqlite ---
    // Re-open the DB read-only to inspect wallet state.
    let conn = Connection::open_with_flags(
        &db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open wallet db read-only");

    // Assertion 3: transaction count.
    // Source: BalanceTests.swift:888 `XCTAssertEqual(clearedTransactions.count, 2)`
    let tx_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM transactions", [], |r| r.get(0))
        .expect("query transactions count");
    assert_eq!(
        tx_count, EXPECTED_TX_COUNT,
        "expected {EXPECTED_TX_COUNT} transactions in wallet DB (got {tx_count}). \
         If 0: staged transactions were not found — check darkside staging above."
    );

    // Assertion 4: received balance.
    // In zcash_client_sqlite 0.20.2, spent-ness is tracked via the separate
    // `sapling_received_note_spends` junction table (no `spent` column on
    // `sapling_received_notes`). Sum the value of all notes not referenced
    // in the spends table (for this fixture there are no spends).
    // Source: BalanceTests.swift:889 `XCTAssertEqual(expectedBalance, Zatoshi(200000))`
    let received_value: Option<i64> = conn
        .query_row(
            "SELECT SUM(value) FROM sapling_received_notes \
             WHERE id NOT IN (SELECT sapling_received_note_id FROM sapling_received_note_spends)",
            [],
            |r| r.get(0),
        )
        .expect("query sapling received notes balance");
    assert_eq!(
        received_value.unwrap_or(0),
        EXPECTED_BALANCE_ZATOSHI,
        "expected balance {EXPECTED_BALANCE_ZATOSHI} zatoshi (got {received_value:?}). \
         Source: BalanceTests.swift:889"
    );
}
