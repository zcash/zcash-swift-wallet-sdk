use std::panic::AssertUnwindSafe;

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
use incrementalmerkletree::Position;
use orchard::tree::MerkleHashOrchard;
use prost::Message;
use zcash_client_backend::proto::service::TreeState;
use zcash_voting as voting;

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

        let result = handle
            .db
            .precompute_delegation_pir(
                &round_id_str,
                bundle_index,
                &core_notes,
                &pir_url,
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
                &pir_url,
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
