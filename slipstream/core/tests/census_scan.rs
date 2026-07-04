//! v0.4 P0 census (#1755): prove the shard census is populated end-to-end by a REAL
//! `scan_cached_blocks` → `SparseFacade` → `sparse_put_blocks` pass over synthetic
//! blocks — not just by unit-feeding the struct. Own integration binary (not in
//! stress_sparse_join.rs, which must own the process-global rayon pool config).
//!
//! Fixture helpers are replicas of `oracle::testkit` (gated `#[cfg(any(test,
//! feature = "darkside"))]`, invisible here) — same provenance as the copies in
//! stress_sparse_join.rs.

use zcash_client_backend::data_api::chain::scan_cached_blocks;
use zcash_client_backend::proto::compact_formats::{
    ChainMetadata, CompactBlock, CompactSaplingOutput, CompactSaplingSpend, CompactTx,
};
use zcash_client_backend::proto::service::TreeState;
use zcash_protocol::consensus::BlockHeight;

use slipstream_core::block_source::MemBlockSource;
use slipstream_core::chunk::Chunk;
use slipstream_core::persist::{SparseFacade, SparseTreeState};
use slipstream_core::wallet_session::WalletSession;

/// See stress_sparse_join.rs for provenance (canonical darkside test seed UFVK).
const TEST_UFVK: &str = concat!(
    "uview17fme6ux853km45g9ep07djpfzeydxxgm22xpmr7arzxyutlusalgpqlx7suga4ahzywfuwz4jclm00u7g8u65qvvdt45kttnfunvschssg3h3g06txs9ja32vx3xa8dej3unnat",
    "gzjvd0vumk37t8es3ludldrtse3q6226ws7eq4q0ywz78nudwpepgdn7jmxz8yvp7k6gxkeynkam0f8aqf9qpeaej55zhkw39x7epayhndul0j4xjttdxxlnwcd09nr8svyx8j0zng0w6",
    "scx3m5unpkaqxcm3hslhlfg4caz7r8d4xy9wm7klkg79w7j0uyzec5s3yje20eg946r6rmkf532nfydu26s8q9ua7mwxw2j2ag7hfcuu652gw6uta03vlm05zju3a9rwc4h367kqzfqrc",
    "z35pdwdk2a7yqnk850un3ujxcvve45ueajgvtr6dj4ufszgqwdy0aedgmkalx2p7qed2suarwkr35dl0c8dnqp3"
);

const SYNTH_START: u64 = 1_500_000;
const BLOCKS: u64 = 4;
const OUTS_PER_BLOCK: u32 = 3;

fn h32(tag: u8, n: u64) -> Vec<u8> {
    let mut v = vec![0u8; 32];
    v[0] = tag;
    v[1..9].copy_from_slice(&n.to_le_bytes());
    v
}

fn cmu(n: u64) -> Vec<u8> {
    let mut v = vec![0u8; 32];
    v[..8].copy_from_slice(&n.to_le_bytes());
    v
}

fn synth_blocks(count: u64, outs_per_block: u32) -> Vec<CompactBlock> {
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

/// One sparse scan of the whole synthetic chain in a single chunk, production
/// layering (`block_in_place` around `scan_cached_blocks` + `SparseFacade`);
/// returns the fed census counts (sapling pool — the synthetic outputs are sapling).
async fn scan_and_census(dir: std::path::PathBuf) -> Result<(u64, u64, u64), String> {
    let blocks = synth_blocks(BLOCKS, OUTS_PER_BLOCK);
    let db_path = dir.join("data.db");
    let mut session = WalletSession::open(slipstream_core::Network::MainNetwork, &db_path)
        .map_err(|e| format!("open: {e}"))?;
    let birthday_ts = TreeState {
        network: "main".into(),
        height: SYNTH_START - 1,
        hash: "0".repeat(64),
        time: 1,
        ..Default::default()
    };
    session
        .ensure_account(TEST_UFVK, birthday_ts.clone())
        .map_err(|e| format!("ensure_account: {e}"))?;
    let tip = blocks.last().map(|b| b.height).unwrap_or(SYNTH_START);
    session.update_chain_tip(tip).map_err(|e| format!("update_chain_tip: {e}"))?;

    let mut sparse_state = SparseTreeState::default();
    let from_state = birthday_ts.to_chain_state().map_err(|e| format!("chain state: {e}"))?;
    let from_height =
        u32::try_from(SYNTH_START).map_err(|_| "height exceeds u32".to_string())?;
    let len = blocks.len();
    let chunk = Chunk::from_blocks(0, blocks);
    let network = session.network;

    tokio::task::block_in_place(|| {
        let source = MemBlockSource::new(&chunk);
        let mut facade = SparseFacade { inner: session.db_mut(), sparse: &mut sparse_state };
        scan_cached_blocks(
            &network,
            &source,
            &mut facade,
            BlockHeight::from(from_height),
            &from_state,
            len,
        )
    })
    .map_err(|e| format!("scan_cached_blocks (sparse): {e}"))?;

    let (sapling, _orchard) = sparse_state.census();
    Ok((sapling.shards(), sapling.noted_shards(), sapling.commitments))
}

/// A fresh wallet scanning a foreign chain: every commitment counted, one shard
/// touched, zero noted shards (the wallet owns nothing in the fixture).
#[test]
fn census_populated_by_sparse_scan() {
    // Multi-thread runtime: block_in_place's contract (same as production FFI).
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");
    let dir = tempfile::tempdir().expect("tempdir");
    // Spawned task = a real runtime worker (block_in_place's contract; the
    // block_on caller thread is not a worker) — same shape as the stress test.
    let (shards, noted, commitments) = rt
        .block_on(async { tokio::spawn(scan_and_census(dir.path().to_path_buf())).await })
        .expect("join")
        .expect("scan");
    assert_eq!(commitments, BLOCKS * u64::from(OUTS_PER_BLOCK));
    assert_eq!(shards, 1, "12 positions all land in shard 0");
    assert_eq!(noted, 0, "fixture wallet owns no notes in the synthetic chain");
}
