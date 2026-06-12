//! A5 stress (failure-path hardening, #1755): hermetic deadlock/livelock hunt for
//! the `rayon::join` path inside `sparse_put_blocks` (T6.8-L3a) under CONSTRAINED
//! rayon pools, called from inside `tokio::task::block_in_place` — the exact
//! layering the iOS FFI uses (4-worker tokio runtime owned by the handle; the
//! scan enters Rust-side via a spawned task; `scan_cached_blocks` runs inside
//! `block_in_place`; `rayon::join` reaches the pool via `in_worker_cold`
//! injection because the calling thread is a tokio worker, not a rayon worker).
//!
//! Field context: a device sync froze at exactly one chunk with state stuck
//! "Syncing" (no logs, no error). One candidate mechanism was a rayon
//! deadlock/livelock in the join path on a constrained/QoS-throttled device
//! pool. This test pins three layerings, 60 iterations total (>= 50), under a
//! watchdog: a hang FAILS the test instead of hanging the suite.
//!
//! This test lives in its own integration-test binary ON PURPOSE: it must own
//! the process's GLOBAL rayon pool configuration (`build_global` succeeds only
//! before any other rayon touch), which is impossible in the shared unit-test
//! process.
//!
//! ## 1-thread x real-outputs exclusion (documented, deliberate)
//!
//! Wrapping the WHOLE `scan_cached_blocks` in `pool.install` on a ONE-thread
//! pool deadlocks BY DESIGN inside upstream's trial-decryption batch runner
//! (zcash_client_backend-0.23.0 scan.rs:178 `rayon::spawn_fifo` + a blocking
//! crossbeam-channel drain on the only worker thread) — a test-harness
//! artifact, NOT a production layering: production enters the scan from a
//! tokio worker thread (never from inside a rayon pool), and the global pool
//! has >= 2 threads on every supported target. The 1-thread variant therefore
//! uses an outputs-free chain (exercises join + frontier mechanics only); the
//! 2-thread variants carry real outputs through the full decrypt + join +
//! par_chunks path.

use std::path::Path;
use std::time::Duration;

use zcash_client_backend::data_api::chain::{ChainState, scan_cached_blocks};
use zcash_client_backend::proto::compact_formats::{
    ChainMetadata, CompactBlock, CompactSaplingOutput, CompactSaplingSpend, CompactTx,
};
use zcash_client_backend::proto::service::TreeState;
use zcash_protocol::consensus::BlockHeight;

use slipstream_core::block_source::MemBlockSource;
use slipstream_core::chunk::Chunk;
use slipstream_core::persist::{SparseFacade, SparseTreeState};
use slipstream_core::wallet_session::WalletSession;

/// Mainnet UFVK for the canonical darkside test seed. Replica of
/// `wallet_session::TEST_UFVK` (gated `#[cfg(any(test, feature = "darkside"))]`,
/// invisible to plain integration tests). Provenance:
/// Tests/OfflineTests/DerivationToolTests/DerivationToolMainnetTests.swift:32-39.
const STRESS_UFVK: &str = concat!(
    "uview17fme6ux853km45g9ep07djpfzeydxxgm22xpmr7arzxyutlusalgpqlx7suga4ahzywfuwz4jclm00u7g8u65qvvdt45kttnfunvschssg3h3g06txs9ja32vx3xa8dej3unnat",
    "gzjvd0vumk37t8es3ludldrtse3q6226ws7eq4q0ywz78nudwpepgdn7jmxz8yvp7k6gxkeynkam0f8aqf9qpeaej55zhkw39x7epayhndul0j4xjttdxxlnwcd09nr8svyx8j0zng0w6",
    "scx3m5unpkaqxcm3hslhlfg4caz7r8d4xy9wm7klkg79w7j0uyzec5s3yje20eg946r6rmkf532nfydu26s8q9ua7mwxw2j2ag7hfcuu652gw6uta03vlm05zju3a9rwc4h367kqzfqrc",
    "z35pdwdk2a7yqnk850un3ujxcvve45ueajgvtr6dj4ufszgqwdy0aedgmkalx2p7qed2suarwkr35dl0c8dnqp3"
);

/// First synthetic height — replica of `oracle::testkit::SYNTH_START` (above
/// Sapling activation, below NU5, so empty Orchard bundles are valid).
const SYNTH_START: u64 = 1_500_000;

fn h32(tag: u8, n: u64) -> Vec<u8> {
    let mut v = vec![0u8; 32];
    v[0] = tag;
    v[1..9].copy_from_slice(&n.to_le_bytes());
    v
}

/// Little-endian small integers are canonical Jubjub base-field elements ->
/// valid `cmu` bytes (replica of `oracle::testkit::cmu`).
fn cmu(n: u64) -> Vec<u8> {
    let mut v = vec![0u8; 32];
    v[..8].copy_from_slice(&n.to_le_bytes());
    v
}

/// Deterministic synthetic chain — replica of `oracle::testkit::synth_blocks`
/// (gated module; see STRESS_UFVK note). `outs_per_block == 0` produces an
/// outputs-free chain (the 1-thread variant).
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

/// ChainState at `last` for the NEXT window — replica of
/// `oracle::testkit::synth_chain_state` (frontier rebuilt by replaying the
/// global cmu sequence; exact because the counter is global).
fn synth_chain_state(last: &CompactBlock) -> Result<ChainState, String> {
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
        let node = sapling::Node::read(&bytes[..]).map_err(|e| format!("synth cmu {n}: {e}"))?;
        let _ = frontier.append(node);
    }
    let mut hash = [0u8; 32];
    hash[0] = 0xBB;
    hash[1..9].copy_from_slice(&last.height.to_le_bytes());
    Ok(ChainState::new(
        BlockHeight::from(last.height as u32),
        zcash_primitives::block::BlockHash(hash),
        frontier,
        incrementalmerkletree::frontier::Frontier::empty(),
    ))
}

/// One full sparse scan of `blocks` into a fresh wallet under `dir`, exactly
/// as scan.rs::scan_chunks layers it: `block_in_place` around
/// `scan_cached_blocks` + `SparseFacade`, ONE `SparseTreeState` per call.
///
/// `pool`: `Some(p)` runs the scan via `p.install` (constrained LOCAL pool —
/// the prescribed A5 shape); `None` runs it directly on the tokio worker
/// thread, so `rayon::join` cold-injects into the GLOBAL pool (production
/// layering; this binary constrains the global pool to 2 threads).
///
/// MUST be called from inside a multi-thread tokio runtime worker
/// (block_in_place requirement — same contract as production scan_chunks).
fn scan_sparse_once(
    dir: &Path,
    blocks: &[CompactBlock],
    chunk_size: usize,
    pool: Option<&rayon::ThreadPool>,
) -> Result<(), String> {
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
        .ensure_account(STRESS_UFVK, birthday_ts.clone())
        .map_err(|e| format!("ensure_account: {e}"))?;
    let tip = blocks.last().map(|b| b.height).unwrap_or(SYNTH_START);
    session.update_chain_tip(tip).map_err(|e| format!("update_chain_tip: {e}"))?;

    let mut sparse_state = SparseTreeState::default();
    let mut from_state = birthday_ts
        .to_chain_state()
        .map_err(|e| format!("chain state: {e}"))?;

    for window in blocks.chunks(chunk_size) {
        let (Some(first), Some(last)) = (window.first(), window.last()) else {
            continue;
        };
        let from_height =
            u32::try_from(first.height).map_err(|_| "height exceeds u32".to_string())?;
        let chunk = Chunk::from_blocks(0, window.to_vec());
        let network = session.network;

        // The production layering: synchronous scan inside block_in_place.
        let mut scan = || {
            let source = MemBlockSource::new(&chunk);
            let mut facade =
                SparseFacade { inner: session.db_mut(), sparse: &mut sparse_state };
            scan_cached_blocks(
                &network,
                &source,
                &mut facade,
                BlockHeight::from(from_height),
                &from_state,
                window.len(),
            )
        };
        tokio::task::block_in_place(|| match pool {
            Some(p) => p.install(scan),
            None => scan(),
        })
        .map_err(|e| format!("scan_cached_blocks (sparse): {e}"))?;

        from_state = synth_chain_state(last)?;
    }
    Ok(())
}

/// All three variants, run sequentially inside a spawned tokio task (a real
/// runtime worker — block_in_place's contract).
fn run_all_variants() -> Result<(), String> {
    // Constrain the GLOBAL pool to 2 threads FIRST. This is the first rayon
    // touch in this test binary's process, so build_global must succeed; 2 is
    // the minimum core count of every supported iOS device.
    rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .thread_name(|i| format!("stress-global-{i}"))
        .build_global()
        .map_err(|e| format!("build_global: {e}"))?;

    // 4 workers — mirrors zcashlc_slipstream_open (rust/src/lib.rs).
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;

    rt.block_on(async {
        tokio::spawn(async move {
            let pool1 = rayon::ThreadPoolBuilder::new()
                .num_threads(1)
                .build()
                .map_err(|e| format!("pool1: {e}"))?;
            let pool2 = rayon::ThreadPoolBuilder::new()
                .num_threads(2)
                .build()
                .map_err(|e| format!("pool2: {e}"))?;

            // Variant 1 — local pool, ONE thread, outputs-free chain (see the
            // 1-thread exclusion note in the module header): rayon::join +
            // insert_frontier mechanics degenerate to depth-first inline
            // execution; 2 sparse_put_blocks per iteration.
            let empty_chain = synth_blocks(200, 0);
            for i in 0..20 {
                let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
                scan_sparse_once(dir.path(), &empty_chain, 100, Some(&pool1))
                    .map_err(|e| format!("variant1 iter {i}: {e}"))?;
            }

            // Variant 2 — local pool, TWO threads, real outputs: the full
            // decrypt (spawn_fifo + channel) + join + par_chunks path under
            // maximum constraint that production can legally reach.
            let real_chain = synth_blocks(100, 2);
            for i in 0..20 {
                let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
                scan_sparse_once(dir.path(), &real_chain, 50, Some(&pool2))
                    .map_err(|e| format!("variant2 iter {i}: {e}"))?;
            }

            // Variant 3 — NO install: production layering. The scan runs on
            // the tokio worker (block_in_place); rayon::join cold-injects into
            // the 2-thread GLOBAL pool via in_worker_cold; the batch runner's
            // spawn_fifo tasks land on the same constrained pool.
            for i in 0..20 {
                let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
                scan_sparse_once(dir.path(), &real_chain, 50, None)
                    .map_err(|e| format!("variant3 iter {i}: {e}"))?;
            }

            Ok::<(), String>(())
        })
        .await
        .map_err(|e| format!("stress task join: {e}"))?
    })
}

/// 60 iterations x 2 sparse_put_blocks each = 120 rayon::join executions under
/// three constrained layerings. A deadlock/livelock FAILS via the watchdog
/// instead of hanging the suite.
#[test]
fn sparse_join_stress_no_deadlock_under_constrained_pools() {
    let (done_tx, done_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    std::thread::spawn(move || {
        let result = std::panic::catch_unwind(run_all_variants)
            .unwrap_or_else(|p| Err(format!("stress body panicked: {p:?}")));
        let _ = done_tx.send(result);
    });
    match done_rx.recv_timeout(Duration::from_secs(240)) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("A5 stress failed: {e}"),
        Err(_) => panic!(
            "A5 stress: deadlock/livelock suspected — rayon::join under constrained pools \
             did not complete within 240s (the silent-freeze candidate mechanism)"
        ),
    }
}
