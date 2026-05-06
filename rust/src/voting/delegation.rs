use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use anyhow::anyhow;
use ff::PrimeField;
use ffi_helpers::panic::catch_panic;
use incrementalmerkletree::Position;
use orchard::tree::MerkleHashOrchard;
use pasta_curves::pallas;
use prost::Message;
use zcash_client_backend::proto::service::TreeState;
use zcash_voting::{self as voting, zkp1};

use crate::{unwrap_exc_or, unwrap_exc_or_null};

use super::db::VotingDatabaseHandle;
use super::ffi_types::{FfiBundleSetupResult, FfiVotingHotkey};
use super::helpers::{
    bytes_from_ptr, json_to_boxed_slice, open_wallet_db_for_tree_ops, str_from_ptr,
    voting_hotkey_to_ffi,
};
use super::json::{
    JsonDelegationPirPrecomputeResult, JsonDelegationProofResult, JsonDelegationSubmission,
    JsonNoteInfo, JsonVotingPczt, JsonWitnessData,
};
use super::progress::ProgressBridge;

// =============================================================================
// VotingDatabase methods — Delegation setup
// =============================================================================

/// Generate a voting hotkey for a round.
///
/// Returns a pointer to `FfiVotingHotkey` on success, or null on error.
/// Call `zcashlc_voting_free_hotkey` to free the returned pointer.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_generate_hotkey(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    seed: *const u8,
    seed_len: usize,
) -> *mut FfiVotingHotkey {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let seed_bytes = unsafe { bytes_from_ptr(seed, seed_len) };

        let hotkey = handle
            .db
            .generate_hotkey(&round_id_str, seed_bytes)
            .map_err(|e| anyhow!("generate_hotkey failed: {}", e))?;

        Ok(Box::into_raw(Box::new(voting_hotkey_to_ffi(hotkey)?)))
    });
    unwrap_exc_or_null(res)
}

/// Set up note bundles for a voting round.
///
/// `notes_json` is a JSON-encoded `Vec<NoteInfo>`.
///
/// Returns a pointer to `FfiBundleSetupResult` on success, or null on error.
/// Call `zcashlc_voting_free_bundle_setup_result` to free the returned pointer.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_setup_bundles(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    notes_json: *const u8,
    notes_json_len: usize,
) -> *mut FfiBundleSetupResult {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let notes_bytes = unsafe { bytes_from_ptr(notes_json, notes_json_len) };
        let json_notes: Vec<JsonNoteInfo> = serde_json::from_slice(notes_bytes)?;
        let core_notes: Vec<voting::NoteInfo> = json_notes.into_iter().map(Into::into).collect();

        let (count, weight) = handle
            .db
            .setup_bundles(&round_id_str, &core_notes)
            .map_err(|e| anyhow!("setup_bundles failed: {}", e))?;

        Ok(Box::into_raw(Box::new(FfiBundleSetupResult {
            bundle_count: count,
            eligible_weight: weight,
        })))
    });
    unwrap_exc_or_null(res)
}

/// Get the number of bundles for a round.
///
/// Returns the bundle count on success (>= 0), or -1 on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_bundle_count(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
) -> i64 {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;

        let count = handle
            .db
            .get_bundle_count(&round_id_str)
            .map_err(|e| anyhow!("get_bundle_count failed: {}", e))?;
        Ok(count as i64)
    });
    unwrap_exc_or(res, -1)
}

/// Build a voting PCZT for a bundle.
///
/// `notes_json` is a JSON-encoded `Vec<NoteInfo>`.
///
/// Returns JSON-encoded `VotingPczt` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_build_pczt(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    notes_json: *const u8,
    notes_json_len: usize,
    fvk_bytes: *const u8,
    fvk_bytes_len: usize,
    hotkey_raw_address: *const u8,
    hotkey_raw_address_len: usize,
    consensus_branch_id: u32,
    coin_type: u32,
    seed_fingerprint: *const u8,
    seed_fingerprint_len: usize,
    account_index: u32,
    round_name: *const u8,
    round_name_len: usize,
    address_index: u32,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let notes_bytes = unsafe { bytes_from_ptr(notes_json, notes_json_len) };
        let json_notes: Vec<JsonNoteInfo> = serde_json::from_slice(notes_bytes)?;
        let core_notes: Vec<voting::NoteInfo> = json_notes.into_iter().map(Into::into).collect();
        let fvk = unsafe { bytes_from_ptr(fvk_bytes, fvk_bytes_len) };
        let hotkey_addr = unsafe { bytes_from_ptr(hotkey_raw_address, hotkey_raw_address_len) };
        let seed_fp_bytes = unsafe { bytes_from_ptr(seed_fingerprint, seed_fingerprint_len) };
        let seed_fp_32: [u8; 32] = seed_fp_bytes.try_into().map_err(|_| {
            anyhow!(
                "seed_fingerprint must be 32 bytes, got {}",
                seed_fp_bytes.len()
            )
        })?;
        let round_name_str = unsafe { str_from_ptr(round_name, round_name_len) }?;

        let pczt = handle
            .db
            .build_governance_pczt(
                &round_id_str,
                bundle_index,
                &core_notes,
                fvk,
                hotkey_addr,
                consensus_branch_id,
                coin_type,
                &seed_fp_32,
                account_index,
                &round_name_str,
                address_index,
            )
            .map_err(|e| anyhow!("build_voting_pczt failed: {}", e))?;

        let json_pczt: JsonVotingPczt = pczt.into();
        json_to_boxed_slice(&json_pczt)
    });
    unwrap_exc_or_null(res)
}

/// Store a tree state for witness generation.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_store_tree_state(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    tree_state_bytes: *const u8,
    tree_state_bytes_len: usize,
) -> i32 {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let ts_bytes = unsafe { bytes_from_ptr(tree_state_bytes, tree_state_bytes_len) };

        handle
            .db
            .store_tree_state(&round_id_str, ts_bytes)
            .map_err(|e| anyhow!("store_tree_state failed: {}", e))?;
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}

/// Generate Merkle inclusion witnesses for notes in a bundle.
///
/// `notes_json` is a JSON-encoded `Vec<NoteInfo>`.
///
/// Returns JSON-encoded `Vec<WitnessData>` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_generate_note_witnesses(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    wallet_db_path: *const u8,
    wallet_db_path_len: usize,
    notes_json: *const u8,
    notes_json_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let wallet_path_str = unsafe { str_from_ptr(wallet_db_path, wallet_db_path_len) }?;
        let notes_bytes = unsafe { bytes_from_ptr(notes_json, notes_json_len) };
        let json_notes: Vec<JsonNoteInfo> = serde_json::from_slice(notes_bytes)?;
        let core_notes: Vec<voting::NoteInfo> = json_notes.into_iter().map(Into::into).collect();

        // Load cached tree state from voting DB and parse frontier
        let wallet_id = handle.db.wallet_id();
        let conn = handle.db.conn();
        let tree_state_bytes =
            voting::storage::queries::load_tree_state(&conn, &round_id_str, &wallet_id)
                .map_err(|e| anyhow!("load_tree_state failed: {}", e))?;
        let params = voting::storage::queries::load_round_params(&conn, &round_id_str, &wallet_id)
            .map_err(|e| anyhow!("load_round_params failed: {}", e))?;
        drop(conn);

        let tree_state = TreeState::decode(tree_state_bytes.as_slice())
            .map_err(|e| anyhow!("failed to decode TreeState protobuf: {}", e))?;
        let orchard_ct = tree_state
            .orchard_tree()
            .map_err(|e| anyhow!("failed to parse orchard tree from TreeState: {}", e))?;
        let frontier_root = orchard_ct.root();
        let frontier = orchard_ct.to_frontier();
        let nonempty_frontier = frontier.take().ok_or_else(|| {
            anyhow!("empty orchard frontier — no orchard activity at snapshot height")
        })?;

        // Generate witnesses from wallet DB shard data + frontier
        let wallet_db = open_wallet_db_for_tree_ops(&wallet_path_str)?;
        let positions: Vec<Position> = core_notes
            .iter()
            .map(|n| Position::from(n.position))
            .collect();
        let checkpoint_height =
            zcash_protocol::consensus::BlockHeight::from_u32(params.snapshot_height as u32);

        let merkle_paths = wallet_db
            .generate_orchard_witnesses_at_historical_height(
                &positions,
                nonempty_frontier,
                checkpoint_height,
            )
            .map_err(|e| {
                anyhow!(
                    "generate_orchard_witnesses_at_historical_height failed: {}",
                    e
                )
            })?;

        // Convert MerklePaths to WitnessData
        let root_bytes = frontier_root.to_bytes().to_vec();
        let witnesses: Vec<voting::WitnessData> = merkle_paths
            .into_iter()
            .zip(core_notes.iter())
            .map(
                |(path, note): (
                    incrementalmerkletree::MerklePath<
                        MerkleHashOrchard,
                        { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
                    >,
                    &voting::NoteInfo,
                )| {
                    let auth_path: Vec<Vec<u8>> = path
                        .path_elems()
                        .iter()
                        .map(|h: &MerkleHashOrchard| h.to_bytes().to_vec())
                        .collect();
                    voting::WitnessData {
                        note_commitment: note.commitment.clone(),
                        position: note.position,
                        root: root_bytes.clone(),
                        auth_path,
                    }
                },
            )
            .collect();

        // Verify and cache in voting DB
        handle
            .db
            .store_witnesses(&round_id_str, bundle_index, &witnesses)
            .map_err(|e| anyhow!("store_witnesses failed: {}", e))?;

        let json_witnesses: Vec<JsonWitnessData> = witnesses.into_iter().map(Into::into).collect();
        json_to_boxed_slice(&json_witnesses)
    });
    unwrap_exc_or_null(res)
}

// =============================================================================
// VotingDatabase methods — Delegation proof
// =============================================================================

// Keep PIR client construction at the SDK boundary so zcash_voting can accept
// an injected transport. Today we use direct Hyper/Rustls; later this is the
// single place to swap in a Tor-backed transport based on SDK configuration.
fn connect_pir_client(pir_url: &str) -> anyhow::Result<voting::PirClientBlocking> {
    voting::PirClientBlocking::with_transport(
        pir_url,
        Arc::new(voting::HyperTransport::new()),
    )
    .map_err(|e| anyhow!("connect to PIR server failed: {}", e))
}

/// Precompute and cache delegation PIR IMT proofs for ZKP #1.
///
/// Returns JSON-encoded `DelegationPirPrecomputeResult` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_precompute_delegation_pir(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    notes_json: *const u8,
    notes_json_len: usize,
    pir_server_url: *const u8,
    pir_server_url_len: usize,
    network_id: u32,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let notes_bytes = unsafe { bytes_from_ptr(notes_json, notes_json_len) };
        let json_notes: Vec<JsonNoteInfo> = serde_json::from_slice(notes_bytes)?;
        let core_notes: Vec<voting::NoteInfo> = json_notes.into_iter().map(Into::into).collect();
        let pir_url = unsafe { str_from_ptr(pir_server_url, pir_server_url_len) }?;
        let pir_client = connect_pir_client(&pir_url)?;

        let result = handle
            .db
            .precompute_delegation_pir(
                &round_id_str,
                bundle_index,
                &core_notes,
                &pir_client,
                network_id,
            )
            .map_err(|e| anyhow!("precompute_delegation_pir failed: {}", e))?;

        let json_result: JsonDelegationPirPrecomputeResult = result.into();
        json_to_boxed_slice(&json_result)
    });
    unwrap_exc_or_null(res)
}

/// Build and prove the real delegation ZKP (#1). Long-running.
///
/// Returns JSON-encoded `DelegationProofResult` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - `progress_callback` must be a valid function pointer (or null to skip progress).
/// - `progress_context` is passed through to the callback unchanged.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_build_and_prove_delegation(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    notes_json: *const u8,
    notes_json_len: usize,
    hotkey_raw_address: *const u8,
    hotkey_raw_address_len: usize,
    pir_server_url: *const u8,
    pir_server_url_len: usize,
    network_id: u32,
    progress_callback: Option<unsafe extern "C" fn(f64, *mut std::ffi::c_void)>,
    progress_context: *mut std::ffi::c_void,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let progress_context = AssertUnwindSafe(progress_context);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let notes_bytes = unsafe { bytes_from_ptr(notes_json, notes_json_len) };
        let json_notes: Vec<JsonNoteInfo> = serde_json::from_slice(notes_bytes)?;
        let core_notes: Vec<voting::NoteInfo> = json_notes.into_iter().map(Into::into).collect();
        let hotkey_addr = unsafe { bytes_from_ptr(hotkey_raw_address, hotkey_raw_address_len) };
        let pir_url = unsafe { str_from_ptr(pir_server_url, pir_server_url_len) }?;
        let pir_client = connect_pir_client(&pir_url)?;

        let reporter: Box<dyn voting::ProofProgressReporter> = match progress_callback {
            Some(cb) => Box::new(ProgressBridge {
                callback: cb,
                context: *progress_context,
            }),
            None => Box::new(voting::NoopProgressReporter),
        };

        let result = handle
            .db
            .build_and_prove_delegation(
                &round_id_str,
                bundle_index,
                &core_notes,
                hotkey_addr,
                &pir_client,
                network_id,
                reporter.as_ref(),
            )
            .map_err(|e| anyhow!("build_and_prove_delegation failed: {}", e))?;

        let json_result: JsonDelegationProofResult = result.into();
        json_to_boxed_slice(&json_result)
    });
    unwrap_exc_or_null(res)
}

/// Get the delegation submission payload using a seed-derived signing key.
///
/// Returns JSON-encoded `DelegationSubmission` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_delegation_submission(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    sender_seed: *const u8,
    sender_seed_len: usize,
    network_id: u32,
    account_index: u32,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let seed = unsafe { bytes_from_ptr(sender_seed, sender_seed_len) };

        let submission = handle
            .db
            .get_delegation_submission(&round_id_str, bundle_index, seed, network_id, account_index)
            .map_err(|e| anyhow!("get_delegation_submission failed: {}", e))?;

        let json_sub: JsonDelegationSubmission = submission.into();
        json_to_boxed_slice(&json_sub)
    });
    unwrap_exc_or_null(res)
}

/// Get the delegation submission payload using a Keystone-provided signature.
///
/// Returns JSON-encoded `DelegationSubmission` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_delegation_submission_with_keystone_sig(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    sig: *const u8,
    sig_len: usize,
    sighash: *const u8,
    sighash_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let sig_bytes = unsafe { bytes_from_ptr(sig, sig_len) };
        let sighash_bytes = unsafe { bytes_from_ptr(sighash, sighash_len) };

        let submission = handle
            .db
            .get_delegation_submission_with_keystone_sig(
                &round_id_str,
                bundle_index,
                sig_bytes,
                sighash_bytes,
            )
            .map_err(|e| anyhow!("get_delegation_submission_with_keystone_sig failed: {}", e))?;

        let json_sub: JsonDelegationSubmission = submission.into();
        json_to_boxed_slice(&json_sub)
    });
    unwrap_exc_or_null(res)
}

/// Store the VAN leaf position after delegation TX is confirmed on chain.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_store_van_position(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    position: u32,
) -> i32 {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;

        handle
            .db
            .store_van_position(&round_id_str, bundle_index, position)
            .map_err(|e| anyhow!("store_van_position failed: {}", e))?;
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}

/// Depth of the IMT non-membership tree: number of authentication path
/// siblings in a PIR-fetched proof. Matches `zcash_voting::ImtProofData::path`
/// and `voting_circuits::delegation::imt::IMT_DEPTH` (29). Kept local because
/// `voting-circuits` is not a direct dependency of this crate and
/// `zcash_voting` does not currently re-export the constant.
const NUM_PATH_ELEMENTS: usize = 29;

/// Wire size of `ImtProofData::path` in bytes: one canonical 32-byte
/// pallas::Base element per IMT depth level.
const PATH_BYTES: usize = NUM_PATH_ELEMENTS * 32;

/// Validate a PIR-fetched IMT non-membership proof bytewise.
///
/// Inputs are the wire format of `zcash_voting::ImtProofData`: 32-byte LE
/// pallas::Base values for the root and the three nf_bounds, a u32 leaf
/// position, and 29 32-byte path siblings.
///
/// Returns 0 if the proof is valid, 1 if it is well-formed but invalid, and -1
/// if inputs are malformed or a panic occurs.
///
/// # Safety
///
/// - `root`, `nullifier`, and `expected_root` must each point to exactly 32 bytes.
/// - `nf_bounds` must point to exactly 96 bytes (3 * 32).
/// - `path` must point to exactly 928 bytes (29 * 32).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_validate_pir_proof(
    root: *const u8,
    nf_bounds: *const u8,
    leaf_pos: u32,
    path: *const u8,
    nullifier: *const u8,
    expected_root: *const u8,
) -> i32 {
    let res = catch_panic(|| {
        let root_bytes: [u8; 32] = unsafe { std::slice::from_raw_parts(root, 32) }
            .try_into()
            .map_err(|_| anyhow!("root must be exactly 32 bytes"))?;
        let nf_bounds_bytes: [u8; 96] = unsafe { std::slice::from_raw_parts(nf_bounds, 96) }
            .try_into()
            .map_err(|_| anyhow!("nf_bounds must be exactly 96 bytes"))?;
        let path_bytes: [u8; PATH_BYTES] = unsafe { std::slice::from_raw_parts(path, PATH_BYTES) }
            .try_into()
            .map_err(|_| anyhow!("path must be exactly {PATH_BYTES} bytes"))?;
        let nullifier_bytes: [u8; 32] = unsafe { std::slice::from_raw_parts(nullifier, 32) }
            .try_into()
            .map_err(|_| anyhow!("nullifier must be exactly 32 bytes"))?;
        let expected_root_bytes: [u8; 32] =
            unsafe { std::slice::from_raw_parts(expected_root, 32) }
                .try_into()
                .map_err(|_| anyhow!("expected_root must be exactly 32 bytes"))?;

        let proof = zcash_voting::ImtProofData {
            root: parse_base(&root_bytes, "root")?,
            nf_bounds: [
                parse_base(&nf_bounds_bytes[0..32], "nf_bounds[0]")?,
                parse_base(&nf_bounds_bytes[32..64], "nf_bounds[1]")?,
                parse_base(&nf_bounds_bytes[64..96], "nf_bounds[2]")?,
            ],
            leaf_pos,
            path: parse_path(&path_bytes)?,
        };

        let nullifier = parse_base(&nullifier_bytes, "nullifier")?;
        let expected_root = parse_base(&expected_root_bytes, "expected_root")?;

        match zkp1::validate_and_convert_pir_proof(proof, nullifier, expected_root) {
            Ok(_) => Ok(0),
            Err(_) => Ok(1),
        }
    });
    unwrap_exc_or(res, -1)
}

fn parse_base(bytes: &[u8], label: &str) -> anyhow::Result<pallas::Base> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("{label} must be exactly 32 bytes"))?;
    Option::from(pallas::Base::from_repr(bytes))
        .ok_or_else(|| anyhow!("{label} is not a canonical pallas::Base encoding"))
}

fn parse_path(bytes: &[u8]) -> anyhow::Result<[pallas::Base; NUM_PATH_ELEMENTS]> {
    let mut path = [pallas::Base::from(0); NUM_PATH_ELEMENTS];
    for (i, chunk) in bytes.chunks_exact(32).enumerate() {
        path[i] = parse_base(chunk, "path element")?;
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden proof generated from zcash_voting's test-only TestImt helper:
    // https://github.com/valargroup/zcash_voting/blob/zcash_voting-v0.5.2/zcash_voting/src/zkp1.rs#L573-L708
    // Keeping the fixture as bytes preserves FFI coverage without direct SDK
    // dev-dependencies on halo2_gadgets or voting-circuits internals.
    const ROOT: &str = "8a9fa2daeb635fbb006af674259cea05e59d71b9a4773e7433942a14ab031801";
    const NF_BOUNDS: &str = "000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";
    const LEAF_POS: u32 = 0;
    const PATH: &str = "f74380b8dc56b22c3d19c3340538fc374793eb8e87708f41ab73175bf12cca36277c1d54340089c6663e1ffa57fb1c4a097e43952509c9386a6522193cdefb2f6b8c704532a36bb22740da9f2831ff31e0645d22787f5c0bce77e3b8d75eaf2843f92cf5b9836a092e0765640c492a4bc84a830621031e28a7857fca2149e833086e0db15e3d4ba38490e912c1fdbe267fedf4a707ccb28d621647ab77e29c307c790e41edc9df0f750fe03799eb7b5ede2c9d833569df4bd43a6b46e2214510f3e160b7b9a3d21fadd88d9316cb35f61fb07404e79b6b019d2fe570d57a8335c17184fa579ec144ca5b7093e61550dd9b9fabfaf9822815509d7df99846d402421cd5367dca2ceaa6610949b3cc3365c8e24eff6b7a430d51f79a42e55be52db6b3d188445aff0456047f951714a26920a0a0d0d02eaef1f802a0ea1394fd1b6c4edd9a05510f352bf6e35450e42c71abba35f1d0853a5c4faaba2861384d1538c031808c91140538602e8454283e9c5cfd47564c267f0815aae2d1dac4842d52f55784572f5a4ddbde392035bbe5619a86ec2db7dbca75ee6081b6dd6ab726f8254dd893ec76266b8b7dc66c70011f958767558a461a6143f0eb100693423819863eeddc19d02343311d5073ce3e931fdb19b745755a7e925818201c6346015827f3a7c07a65bd137df252fbd4379f6ef59601cd19d9c7d89d85634263cc04689b97d136dfa9f2457502788d5407d53d9a04c6d8d8732e7283f9f7b0a3531a728584a001839fc736a82d711de75d4d97b60a1432aa06873dbfada599a73a027fd25eefa6e305a354af3002c07fd283b5bdf1dc00502f0957ef3150ce9e020dfade15e2bfe919f9867c69c69b17c3aae833bf3f71fa6044748daab6779b020535813867047cdf120108e15fcc1257e42709fe6bfdcba82cb43c7be467562211564f02b6c295c7ee794a223f832c9aea620c634cd447c91a102497d1cf7b8a31e97207509990c7253c37300480fd747489cf99cf23d5ab7c7991d1a725714a092f0f453af80b9d7d6828742f9fad934eefea1cd3a281b396e40b3b804e27de3b6fc3b07e82930f463606951a5b0ddcf8b63e4cebf88387f4be2cca1446dd7f3715076183e96f5e260b2008e52fa71f57dbfb958ceaf42d99d54fdf6da7bd343b7ff965aeb8d2753f923ea9d1bf6df39de61763c145550f3748f049ba5a1bb42160420d736b7e3a9f172e40d98e3decff6a759ca472043254f7c639b9fcae001353d53603c500bc474aef03cde95a101a7dde4fccadb8379407e3f479044ef316";
    const NULLIFIER: &str = "0100000000000000000000000000000000000000000000000000000000000000";
    const EXPECTED_ROOT: &str = "8a9fa2daeb635fbb006af674259cea05e59d71b9a4773e7433942a14ab031801";

    fn decode_hex<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), N * 2);
        let mut out = [0u8; N];
        for i in 0..N {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    fn validate(
        proof_root: &[u8; 32],
        nf_bounds: &[u8; 96],
        leaf_pos: u32,
        path: &[u8; PATH_BYTES],
        nullifier: &[u8; 32],
        expected_root: &[u8; 32],
    ) -> i32 {
        unsafe {
            zcashlc_voting_validate_pir_proof(
                proof_root.as_ptr(),
                nf_bounds.as_ptr(),
                leaf_pos,
                path.as_ptr(),
                nullifier.as_ptr(),
                expected_root.as_ptr(),
            )
        }
    }

    #[test]
    fn validate_pir_proof_accepts_valid() {
        let root = decode_hex::<32>(ROOT);
        let nf_bounds = decode_hex::<96>(NF_BOUNDS);
        let path = decode_hex::<PATH_BYTES>(PATH);
        let nullifier = decode_hex::<32>(NULLIFIER);
        let expected_root = decode_hex::<32>(EXPECTED_ROOT);

        assert_eq!(
            validate(
                &root,
                &nf_bounds,
                LEAF_POS,
                &path,
                &nullifier,
                &expected_root
            ),
            0
        );
    }

    #[test]
    fn validate_pir_proof_rejects_root_mismatch() {
        let root = decode_hex::<32>(ROOT);
        let nf_bounds = decode_hex::<96>(NF_BOUNDS);
        let path = decode_hex::<PATH_BYTES>(PATH);
        let nullifier = decode_hex::<32>(NULLIFIER);
        let mut expected_root = decode_hex::<32>(EXPECTED_ROOT);
        expected_root[0] ^= 1;

        assert_eq!(
            validate(
                &root,
                &nf_bounds,
                LEAF_POS,
                &path,
                &nullifier,
                &expected_root
            ),
            1
        );
    }

    #[test]
    fn validate_pir_proof_rejects_corrupted_path() {
        let root = decode_hex::<32>(ROOT);
        let nf_bounds = decode_hex::<96>(NF_BOUNDS);
        let mut path = decode_hex::<PATH_BYTES>(PATH);
        let nullifier = decode_hex::<32>(NULLIFIER);
        let expected_root = decode_hex::<32>(EXPECTED_ROOT);
        path[0] ^= 1;

        assert_eq!(
            validate(
                &root,
                &nf_bounds,
                LEAF_POS,
                &path,
                &nullifier,
                &expected_root
            ),
            1
        );
    }

    #[test]
    fn validate_pir_proof_rejects_non_canonical_field_encoding() {
        let nf_bounds = decode_hex::<96>(NF_BOUNDS);
        let path = decode_hex::<PATH_BYTES>(PATH);
        let non_canonical_root = [0xff; 32];
        let nullifier = decode_hex::<32>(NULLIFIER);
        let expected_root = decode_hex::<32>(EXPECTED_ROOT);

        assert_eq!(
            validate(
                &non_canonical_root,
                &nf_bounds,
                LEAF_POS,
                &path,
                &nullifier,
                &expected_root
            ),
            -1
        );
    }
}
