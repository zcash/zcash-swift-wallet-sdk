use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use anyhow::anyhow;
use ff::PrimeField;
use ffi_helpers::panic::catch_panic;
use incrementalmerkletree::Position;
use pasta_curves::pallas;
use prost::Message;
use zcash_client_backend::proto::service::TreeState;
use zcash_voting::{self as voting, zkp1};

use crate::{unwrap_exc_or, unwrap_exc_or_null};

use super::constants::SEED_FINGERPRINT_LEN;
use super::db::VotingDatabaseHandle;
use super::ffi_types::{FfiBundleSetupResult, FfiVotingHotkey};
use super::helpers::{
    bytes_from_ptr, json_to_boxed_slice, open_wallet_db, str_from_ptr, voting_hotkey_to_ffi,
};
use super::json::{
    JsonDelegationPirPrecomputeResult, JsonDelegationProofResult, JsonDelegationSubmission,
    JsonNoteInfo, JsonVotingPczt, JsonWitnessData,
};
use super::progress::ProgressBridge;

/// Validate that a cached lightwalletd `TreeState` is anchored to the voting
/// round it will be used for.
///
/// Witness generation trusts the cached Orchard frontier as the historical
/// checkpoint input. The generated Merkle path can verify against that
/// frontier's own root, so we must also enforce that the frontier is exactly
/// the round snapshot: same block height and same note commitment tree root.
fn validate_cached_tree_state_for_round(
    tree_state: &TreeState,
    orchard_root: &[u8],
    params: &voting::VotingRoundParams,
) -> anyhow::Result<()> {
    if tree_state.height != params.snapshot_height {
        return Err(anyhow!(
            "cached TreeState height {} does not match round snapshot_height {}",
            tree_state.height,
            params.snapshot_height
        ));
    }

    if orchard_root != params.nc_root.as_slice() {
        return Err(anyhow!(
            "cached TreeState orchard root does not match round nc_root"
        ));
    }

    Ok(())
}

// =============================================================================
// VotingDatabase methods — Delegation proof
// =============================================================================

/// Generate a voting hotkey.
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
    seed: *const u8,
    seed_len: usize,
) -> *mut FfiVotingHotkey {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let seed_bytes = unsafe { bytes_from_ptr(seed, seed_len) }?;

        let hotkey = handle
            .db
            .generate_hotkey(seed_bytes)
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
        let notes_bytes = unsafe { bytes_from_ptr(notes_json, notes_json_len) }?;
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
/// Returns the bundle count on success, or -1 on error.
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
        let notes_bytes = unsafe { bytes_from_ptr(notes_json, notes_json_len) }?;
        let json_notes: Vec<JsonNoteInfo> = serde_json::from_slice(notes_bytes)?;
        let core_notes: Vec<voting::NoteInfo> = json_notes.into_iter().map(Into::into).collect();
        let fvk = unsafe { bytes_from_ptr(fvk_bytes, fvk_bytes_len) }?;
        let hotkey_addr = unsafe { bytes_from_ptr(hotkey_raw_address, hotkey_raw_address_len) }?;
        let seed_fp_bytes = unsafe { bytes_from_ptr(seed_fingerprint, seed_fingerprint_len) }?;
        let seed_fp_32: [u8; SEED_FINGERPRINT_LEN] = seed_fp_bytes.try_into().map_err(|_| {
            anyhow!(
                "seed_fingerprint must be {} bytes, got {}",
                SEED_FINGERPRINT_LEN,
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
        let ts_bytes = unsafe { bytes_from_ptr(tree_state_bytes, tree_state_bytes_len) }?;

        handle
            .db
            .store_tree_state(&round_id_str, ts_bytes)
            .map_err(|e| anyhow!("store_tree_state failed: {}", e))?;
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}

/// Generate Merkle inclusion witnesses for the notes in a bundle and cache
/// them in the voting DB.
///
/// `notes_json` is a JSON-encoded `Vec<NoteInfo>`.
///
/// Returns JSON-encoded `Vec<WitnessData>` as `*mut FfiBoxedSlice`, or null on
/// error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - For every `(ptr, len)` byte argument (`round_id`, `wallet_db_path`,
///   `notes_json`): if `len > 0` then `ptr` must be non-null and valid for
///   reads for `len` bytes; if `len == 0`, `ptr` is ignored. An empty
///   `notes_json` is treated as the empty notes list (JSON is not parsed),
///   and produces an empty witness list.
/// - `network_id` must be `0` (testnet) or `1` (mainnet), matching other
///   `zcashlc_*` FFI.
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
    network_id: u32,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let wallet_path_str = unsafe { str_from_ptr(wallet_db_path, wallet_db_path_len) }?;
        let wallet_db = open_wallet_db(&wallet_path_str, network_id)?;
        let notes_bytes = unsafe { bytes_from_ptr(notes_json, notes_json_len) }?;
        let json_notes: Vec<JsonNoteInfo> = if notes_bytes.is_empty() {
            Vec::new()
        } else {
            serde_json::from_slice(notes_bytes)?
        };
        let core_notes: Vec<voting::NoteInfo> = json_notes.into_iter().map(Into::into).collect();

        let (tree_state_bytes, params) = {
            let wallet_id = handle.db.wallet_id();
            let conn = handle.db.conn();
            let tree_state_bytes =
                voting::storage::queries::load_tree_state(&conn, &round_id_str, &wallet_id)
                    .map_err(|e| anyhow!("load_tree_state failed: {}", e))?;
            let params =
                voting::storage::queries::load_round_params(&conn, &round_id_str, &wallet_id)
                    .map_err(|e| anyhow!("load_round_params failed: {}", e))?;
            (tree_state_bytes, params)
        };

        // Decode the tree state
        let tree_state = TreeState::decode(tree_state_bytes.as_slice())
            .map_err(|e| anyhow!("failed to decode TreeState protobuf: {}", e))?;
        let orchard_ct = tree_state
            .orchard_tree()
            .map_err(|e| anyhow!("failed to parse orchard tree from TreeState: {}", e))?;
        let frontier_root = orchard_ct.root();
        let frontier_root_bytes = frontier_root.to_bytes();
        validate_cached_tree_state_for_round(&tree_state, &frontier_root_bytes[..], &params)?;
        let frontier = orchard_ct.to_frontier();
        let nonempty_frontier = frontier.take().ok_or_else(|| {
            anyhow!("empty orchard frontier — no orchard activity at snapshot height")
        })?;

        // Convert note positions to Merkle positions
        let positions: Vec<Position> = core_notes
            .iter()
            .map(|n| Position::from(n.position))
            .collect();

        // `BlockHeight` is u32-backed; `snapshot_height` is u64. A wallet that
        // somehow synced past u32::MAX blocks is impossible in protocol terms,
        // but reject it explicitly rather than silently truncating.
        let snapshot_height = u32::try_from(params.snapshot_height).map_err(|_| {
            anyhow!(
                "snapshot_height {} does not fit in u32",
                params.snapshot_height
            )
        })?;
        let checkpoint_height = zcash_protocol::consensus::BlockHeight::from_u32(snapshot_height);

        // Generate witnesses from wallet DB shard data + frontier
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

        if merkle_paths.len() != core_notes.len() {
            return Err(anyhow!(
                "generated {} Merkle paths for {} notes",
                merkle_paths.len(),
                core_notes.len()
            ));
        }

        // Convert MerklePaths to WitnessData
        let root_bytes = frontier_root_bytes.to_vec();
        let witnesses: Vec<voting::WitnessData> = merkle_paths
            .into_iter()
            .zip(core_notes.iter())
            .map(|(path, note)| {
                let auth_path: Vec<Vec<u8>> = path
                    .path_elems()
                    .iter()
                    .map(|h| h.to_bytes().to_vec())
                    .collect();
                voting::WitnessData {
                    note_commitment: note.commitment.clone(),
                    position: note.position,
                    root: root_bytes.clone(),
                    auth_path,
                }
            })
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

// Keep PIR client construction at the SDK boundary so zcash_voting can accept
// an injected transport. Today we use direct Hyper/Rustls. In the future this will be the
// single place to add a Tor-backed transport based on SDK configuration.
fn connect_pir_client(pir_url: &str) -> anyhow::Result<voting::PirClientBlocking> {
    voting::PirClientBlocking::with_transport(pir_url, Arc::new(voting::HyperTransport::new()))
        .map_err(|e| anyhow!("connect to PIR server failed: {}", e))
}

/// Precompute and cache delegation PIR IMT proofs for the delegation ZKP.
///
/// Returns JSON-encoded `DelegationPirPrecomputeResult` as `*mut FfiBoxedSlice`,
/// or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - For every `(ptr, len)` byte argument (`round_id`, `notes_json`, `pir_server_url`):
///   if `len > 0` then `ptr` must be non-null and valid for reads for `len` bytes; if
///   `len == 0`, `ptr` is ignored. An empty `notes_json` is treated as the empty notes
///   list (JSON is not parsed).
/// - `network_id` must be `0` (testnet) or `1` (mainnet), matching other `zcashlc_*` FFI.
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
        crate::parse_network(network_id)?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let notes_bytes = unsafe { bytes_from_ptr(notes_json, notes_json_len) }?;
        let json_notes: Vec<JsonNoteInfo> = if notes_bytes.is_empty() {
            Vec::new()
        } else {
            serde_json::from_slice(notes_bytes)?
        };
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

/// Build and prove the real delegation ZKP. Long-running.
///
/// Returns JSON-encoded `DelegationProofResult` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - `progress_callback` must be a valid function pointer, or null to skip progress.
///   If provided, it must remain callable until this function returns. It must be
///   thread-safe and reentrant; callers must not assume it runs on the main thread,
///   because progress may be reported from proving worker threads.
/// - `progress_context` is passed to `progress_callback` unchanged. If non-null,
///   it must point to state that remains valid until this function returns. The
///   callback must not store `progress_context` or use it after this function
///   has returned.
/// - The callback must not call back into this voting database handle or perform
///   work that can deadlock or reenter the active proof operation.
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
        crate::parse_network(network_id)?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let notes_bytes = unsafe { bytes_from_ptr(notes_json, notes_json_len) }?;
        let json_notes: Vec<JsonNoteInfo> = serde_json::from_slice(notes_bytes)?;
        let core_notes: Vec<voting::NoteInfo> = json_notes.into_iter().map(Into::into).collect();
        let hotkey_addr = unsafe { bytes_from_ptr(hotkey_raw_address, hotkey_raw_address_len) }?;
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
        crate::parse_network(network_id)?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let seed = unsafe { bytes_from_ptr(sender_seed, sender_seed_len) }?;

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
        let sig_bytes = unsafe { bytes_from_ptr(sig, sig_len) }?;
        let sighash_bytes = unsafe { bytes_from_ptr(sighash, sighash_len) }?;

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

/// Store the VAN leaf position after delegation transaction confirmation.
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
/// Returns 1 if the proof is valid, 0 if it is well-formed but invalid, and -1
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
            Ok(_) => Ok(1),
            Err(_) => Ok(0),
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

    use incrementalmerkletree::frontier::{CommitmentTree, Frontier};
    use incrementalmerkletree::{Position, Retention};
    use orchard::tree::MerkleHashOrchard;
    use zcash_client_backend::data_api::WalletCommitmentTrees;
    use zcash_client_sqlite::wallet::init::WalletMigrator;
    use zcash_client_sqlite::{WalletDb, util::SystemClock};
    use zcash_primitives::merkle_tree::write_commitment_tree;
    use zcash_protocol::consensus::{BlockHeight, Network};
    use zcash_voting::storage::queries;

    use crate::NETWORK_ID_TESTNET;
    use crate::ffi::zcashlc_free_boxed_slice;
    use crate::voting::db::{
        zcashlc_voting_db_free, zcashlc_voting_db_open, zcashlc_voting_set_wallet_id,
    };
    use crate::voting::ffi_types::{
        zcashlc_voting_free_bundle_setup_result, zcashlc_voting_free_hotkey,
    };

    // Golden proof generated from zcash_voting's test-only TestImt helper:
    // https://github.com/valargroup/zcash_voting/blob/zcash_voting-v0.5.3/zcash_voting/src/zkp1.rs#L573-L708
    // Keeping the fixture as bytes preserves FFI coverage without direct SDK
    // dev-dependencies on halo2_gadgets or voting-circuits internals.
    const ROOT: &str = "8a9fa2daeb635fbb006af674259cea05e59d71b9a4773e7433942a14ab031801";
    const NF_BOUNDS: &str = "000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";
    const LEAF_POS: u32 = 0;
    const PATH: &str = "f74380b8dc56b22c3d19c3340538fc374793eb8e87708f41ab73175bf12cca36277c1d54340089c6663e1ffa57fb1c4a097e43952509c9386a6522193cdefb2f6b8c704532a36bb22740da9f2831ff31e0645d22787f5c0bce77e3b8d75eaf2843f92cf5b9836a092e0765640c492a4bc84a830621031e28a7857fca2149e833086e0db15e3d4ba38490e912c1fdbe267fedf4a707ccb28d621647ab77e29c307c790e41edc9df0f750fe03799eb7b5ede2c9d833569df4bd43a6b46e2214510f3e160b7b9a3d21fadd88d9316cb35f61fb07404e79b6b019d2fe570d57a8335c17184fa579ec144ca5b7093e61550dd9b9fabfaf9822815509d7df99846d402421cd5367dca2ceaa6610949b3cc3365c8e24eff6b7a430d51f79a42e55be52db6b3d188445aff0456047f951714a26920a0a0d0d02eaef1f802a0ea1394fd1b6c4edd9a05510f352bf6e35450e42c71abba35f1d0853a5c4faaba2861384d1538c031808c91140538602e8454283e9c5cfd47564c267f0815aae2d1dac4842d52f55784572f5a4ddbde392035bbe5619a86ec2db7dbca75ee6081b6dd6ab726f8254dd893ec76266b8b7dc66c70011f958767558a461a6143f0eb100693423819863eeddc19d02343311d5073ce3e931fdb19b745755a7e925818201c6346015827f3a7c07a65bd137df252fbd4379f6ef59601cd19d9c7d89d85634263cc04689b97d136dfa9f2457502788d5407d53d9a04c6d8d8732e7283f9f7b0a3531a728584a001839fc736a82d711de75d4d97b60a1432aa06873dbfada599a73a027fd25eefa6e305a354af3002c07fd283b5bdf1dc00502f0957ef3150ce9e020dfade15e2bfe919f9867c69c69b17c3aae833bf3f71fa6044748daab6779b020535813867047cdf120108e15fcc1257e42709fe6bfdcba82cb43c7be467562211564f02b6c295c7ee794a223f832c9aea620c634cd447c91a102497d1cf7b8a31e97207509990c7253c37300480fd747489cf99cf23d5ab7c7991d1a725714a092f0f453af80b9d7d6828742f9fad934eefea1cd3a281b396e40b3b804e27de3b6fc3b07e82930f463606951a5b0ddcf8b63e4cebf88387f4be2cca1446dd7f3715076183e96f5e260b2008e52fa71f57dbfb958ceaf42d99d54fdf6da7bd343b7ff965aeb8d2753f923ea9d1bf6df39de61763c145550f3748f049ba5a1bb42160420d736b7e3a9f172e40d98e3decff6a759ca472043254f7c639b9fcae001353d53603c500bc474aef03cde95a101a7dde4fccadb8379407e3f479044ef316";
    const NULLIFIER: &str = "0100000000000000000000000000000000000000000000000000000000000000";
    const EXPECTED_ROOT: &str = "8a9fa2daeb635fbb006af674259cea05e59d71b9a4773e7433942a14ab031801";
    const TEST_ROUND_ID: &str = "round1";
    const TEST_WALLET_ID: &str = "wallet-id";

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

    fn tree_state_at_height(height: u64) -> TreeState {
        TreeState {
            network: "test".to_string(),
            height,
            hash: String::new(),
            time: 0,
            sapling_tree: String::new(),
            orchard_tree: String::new(),
        }
    }

    fn round_params(snapshot_height: u64, nc_root: Vec<u8>) -> voting::VotingRoundParams {
        voting::VotingRoundParams {
            vote_round_id: TEST_ROUND_ID.to_string(),
            snapshot_height,
            ea_pk: vec![0; 32],
            nc_root,
            nullifier_imt_root: vec![0; 32],
        }
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    fn temp_sqlite_path(tag: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "zcashlc_voting_{tag}_{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn open_memory_voting_db() -> *mut VotingDatabaseHandle {
        let path = b":memory:";
        let db = unsafe { zcashlc_voting_db_open(path.as_ptr(), path.len()) };
        assert!(!db.is_null(), "open in-memory voting db");

        let wallet = TEST_WALLET_ID.as_bytes();
        assert_eq!(0, unsafe {
            zcashlc_voting_set_wallet_id(db, wallet.as_ptr(), wallet.len())
        });

        db
    }

    fn init_test_round(db: *mut VotingDatabaseHandle) {
        let handle = unsafe { db.as_ref() }.expect("db handle");
        handle
            .db
            .init_round(&round_params(100, vec![7; 32]), None)
            .expect("insert round");
    }

    fn insert_test_bundle(db: *mut VotingDatabaseHandle, bundle_index: u32) {
        let handle = unsafe { db.as_ref() }.expect("db handle");
        let wallet_id = handle.db.wallet_id();
        let conn = handle.db.conn();
        conn.execute(
            "INSERT INTO bundles (round_id, wallet_id, bundle_index) VALUES (?1, ?2, ?3)",
            rusqlite::params![TEST_ROUND_ID, wallet_id, i64::from(bundle_index)],
        )
        .expect("insert bundle");
    }

    fn merkle_hash(tag: u64) -> MerkleHashOrchard {
        let repr = pallas::Base::from(tag).to_repr();
        MerkleHashOrchard::from_bytes(&repr).expect("small field element is canonical")
    }

    fn tree_state_from_frontier(
        height: u64,
        frontier: &Frontier<MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>,
    ) -> TreeState {
        let commitment_tree = CommitmentTree::from_frontier(frontier);
        let mut orchard_tree_bytes = Vec::new();
        write_commitment_tree(&commitment_tree, &mut orchard_tree_bytes)
            .expect("serialize Orchard tree state");

        TreeState {
            network: "test".to_string(),
            height,
            hash: String::new(),
            time: 0,
            sapling_tree: String::new(),
            orchard_tree: bytes_to_hex(&orchard_tree_bytes),
        }
    }

    fn free(ptr: *mut crate::ffi::BoxedSlice) {
        unsafe { zcashlc_free_boxed_slice(ptr) };
    }

    fn seed_wallet_orchard_tree(
        wallet_path: &std::path::Path,
        snapshot_height: u64,
        later_height: u32,
        marked_positions: &[Position],
    ) -> (
        Frontier<MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>,
        Vec<MerkleHashOrchard>,
    ) {
        let max_position = marked_positions
            .iter()
            .map(|position| u64::from(*position))
            .max()
            .unwrap_or(2);
        let leaf_count = max_position + 3;
        let leaves = (1u64..=leaf_count).map(merkle_hash).collect::<Vec<_>>();
        let mut frontier_tree: Frontier<
            MerkleHashOrchard,
            { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
        > = Frontier::empty();

        let mut wallet_db = WalletDb::for_path(
            wallet_path,
            Network::TestNetwork,
            SystemClock,
            rand::rngs::OsRng,
        )
        .expect("open wallet db");
        WalletMigrator::new()
            .init_or_migrate(&mut wallet_db)
            .expect("initialize wallet db");

        wallet_db
            .with_orchard_tree_mut(|tree| {
                for (i, leaf) in leaves.iter().enumerate() {
                    let retention = if marked_positions
                        .iter()
                        .any(|position| u64::from(*position) == i as u64)
                    {
                        Retention::Marked
                    } else {
                        Retention::Ephemeral
                    };
                    tree.append(*leaf, retention)?;
                    frontier_tree.append(*leaf);
                }

                tree.checkpoint(BlockHeight::from_u32(snapshot_height as u32))?;

                // Advance the wallet past the snapshot so witness generation
                // has to use the cached historical frontier.
                for tag in (leaf_count + 1)..=(leaf_count + 5) {
                    tree.append(merkle_hash(tag), Retention::Ephemeral)?;
                }
                tree.checkpoint(BlockHeight::from_u32(later_height))?;

                Ok::<(), zcash_client_sqlite::error::SqliteClientError>(())
            })
            .expect("seed wallet Orchard tree");

        (frontier_tree, leaves)
    }

    fn store_round_bundle_and_tree_state(
        db: *mut VotingDatabaseHandle,
        snapshot_height: u64,
        bundle_index: u32,
        bundle_positions: &[Position],
        nc_root: Vec<u8>,
        tree_state: &TreeState,
    ) {
        let tree_state_bytes = tree_state.encode_to_vec();
        let handle = unsafe { db.as_ref() }.expect("voting db handle");
        let conn = handle.db.conn();
        let params = round_params(snapshot_height, nc_root);
        let note_positions = bundle_positions
            .iter()
            .map(|position| u64::from(*position))
            .collect::<Vec<_>>();

        queries::insert_round(&conn, TEST_WALLET_ID, &params, None).expect("insert round");
        queries::insert_bundle(
            &conn,
            TEST_ROUND_ID,
            TEST_WALLET_ID,
            bundle_index,
            &note_positions,
        )
        .expect("insert bundle");
        queries::store_tree_state(
            &conn,
            TEST_ROUND_ID,
            TEST_WALLET_ID,
            snapshot_height,
            &tree_state_bytes,
        )
        .expect("store tree state");
    }

    fn note_json_for(position: Position, commitment: MerkleHashOrchard) -> JsonNoteInfo {
        JsonNoteInfo {
            commitment: commitment.to_bytes().to_vec(),
            nullifier: vec![0; 32],
            value: 50_000,
            position: u64::from(position),
            diversifier: vec![0; 11],
            rho: vec![0; 32],
            rseed: vec![0; 32],
            scope: 0,
            ufvk_str: "ufvk-test-fixture".to_string(),
        }
    }

    fn notes_json_for_positions(leaves: &[MerkleHashOrchard], positions: &[Position]) -> Vec<u8> {
        let notes = positions
            .iter()
            .map(|position| note_json_for(*position, leaves[u64::from(*position) as usize]))
            .collect::<Vec<_>>();
        serde_json::to_vec(&notes).expect("serialize notes")
    }

    fn call_generate_note_witnesses(
        db: *mut VotingDatabaseHandle,
        bundle_index: u32,
        wallet_path_bytes: &[u8],
        notes_json_ptr: *const u8,
        notes_json_len: usize,
    ) -> *mut crate::ffi::BoxedSlice {
        unsafe {
            zcashlc_voting_generate_note_witnesses(
                db,
                TEST_ROUND_ID.as_ptr(),
                TEST_ROUND_ID.len(),
                bundle_index,
                wallet_path_bytes.as_ptr(),
                wallet_path_bytes.len(),
                notes_json_ptr,
                notes_json_len,
                NETWORK_ID_TESTNET,
            )
        }
    }

    fn decode_witnesses(ptr: *mut crate::ffi::BoxedSlice) -> Vec<JsonWitnessData> {
        let witnesses =
            serde_json::from_slice(unsafe { (*ptr).as_slice() }).expect("decode witnesses");
        free(ptr);
        witnesses
    }

    fn assert_witnesses_match_positions(
        witnesses: &[JsonWitnessData],
        leaves: &[MerkleHashOrchard],
        positions: &[Position],
        expected_root: &[u8],
    ) {
        assert_eq!(witnesses.len(), positions.len());

        for (witness, position) in witnesses.iter().zip(positions.iter()) {
            let note_leaf = leaves[u64::from(*position) as usize];
            assert_eq!(witness.note_commitment, note_leaf.to_bytes().to_vec());
            assert_eq!(witness.position, u64::from(*position));
            assert_eq!(witness.root, expected_root);
            assert_eq!(witness.auth_path.len(), orchard::NOTE_COMMITMENT_TREE_DEPTH);

            let path = incrementalmerkletree::MerklePath::<
                MerkleHashOrchard,
                { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
            >::from_parts(
                witness
                    .auth_path
                    .iter()
                    .map(|bytes| {
                        let arr: [u8; 32] = bytes.as_slice().try_into().expect("path element size");
                        MerkleHashOrchard::from_bytes(&arr).expect("canonical path element")
                    })
                    .collect(),
                *position,
            )
            .expect("rebuild returned Merkle path");
            assert_eq!(path.root(note_leaf).to_bytes().to_vec(), expected_root);
        }
    }

    fn assert_cached_witnesses_match(
        db: *mut VotingDatabaseHandle,
        bundle_index: u32,
        witnesses: &[JsonWitnessData],
    ) {
        let handle = unsafe { db.as_ref() }.expect("voting db handle");
        let conn = handle.db.conn();
        let cached = queries::load_witnesses(&conn, TEST_ROUND_ID, TEST_WALLET_ID, bundle_index)
            .expect("load cached witnesses");

        assert_eq!(cached.len(), witnesses.len());
        for (cached, returned) in cached.iter().zip(witnesses.iter()) {
            assert_eq!(cached.note_commitment, returned.note_commitment);
            assert_eq!(cached.position, returned.position);
            assert_eq!(cached.root, returned.root);
            assert_eq!(cached.auth_path, returned.auth_path);
        }
    }

    #[test]
    fn delegation_workflow_ffi_rejects_null_db() {
        let round = TEST_ROUND_ID.as_bytes();
        let json = b"[]";
        let bytes = [0u8; 32];

        assert!(
            unsafe {
                zcashlc_voting_generate_hotkey(std::ptr::null_mut(), bytes.as_ptr(), bytes.len())
            }
            .is_null()
        );
        assert!(
            unsafe {
                zcashlc_voting_setup_bundles(
                    std::ptr::null_mut(),
                    round.as_ptr(),
                    round.len(),
                    json.as_ptr(),
                    json.len(),
                )
            }
            .is_null()
        );
        assert_eq!(
            unsafe {
                zcashlc_voting_get_bundle_count(std::ptr::null_mut(), round.as_ptr(), round.len())
            },
            -1
        );
        assert!(
            unsafe {
                zcashlc_voting_build_pczt(
                    std::ptr::null_mut(),
                    round.as_ptr(),
                    round.len(),
                    0,
                    json.as_ptr(),
                    json.len(),
                    bytes.as_ptr(),
                    bytes.len(),
                    bytes.as_ptr(),
                    bytes.len(),
                    0,
                    0,
                    bytes.as_ptr(),
                    bytes.len(),
                    0,
                    round.as_ptr(),
                    round.len(),
                    0,
                )
            }
            .is_null()
        );
        assert_eq!(
            unsafe {
                zcashlc_voting_store_tree_state(
                    std::ptr::null_mut(),
                    round.as_ptr(),
                    round.len(),
                    bytes.as_ptr(),
                    bytes.len(),
                )
            },
            -1
        );
        assert!(
            unsafe {
                zcashlc_voting_build_and_prove_delegation(
                    std::ptr::null_mut(),
                    round.as_ptr(),
                    round.len(),
                    0,
                    json.as_ptr(),
                    json.len(),
                    bytes.as_ptr(),
                    bytes.len(),
                    round.as_ptr(),
                    round.len(),
                    crate::NETWORK_ID_TESTNET,
                    None,
                    std::ptr::null_mut(),
                )
            }
            .is_null()
        );
        assert!(
            unsafe {
                zcashlc_voting_get_delegation_submission(
                    std::ptr::null_mut(),
                    round.as_ptr(),
                    round.len(),
                    0,
                    bytes.as_ptr(),
                    bytes.len(),
                    crate::NETWORK_ID_TESTNET,
                    0,
                )
            }
            .is_null()
        );
        assert!(
            unsafe {
                zcashlc_voting_get_delegation_submission_with_keystone_sig(
                    std::ptr::null_mut(),
                    round.as_ptr(),
                    round.len(),
                    0,
                    bytes.as_ptr(),
                    bytes.len(),
                    bytes.as_ptr(),
                    bytes.len(),
                )
            }
            .is_null()
        );
        assert_eq!(
            unsafe {
                zcashlc_voting_store_van_position(
                    std::ptr::null_mut(),
                    round.as_ptr(),
                    round.len(),
                    0,
                    0,
                )
            },
            -1
        );
    }

    #[test]
    fn generate_hotkey_returns_freeable_ffi_value() {
        let db = open_memory_voting_db();
        let seed = [7u8; 32];

        let hotkey = unsafe { zcashlc_voting_generate_hotkey(db, seed.as_ptr(), seed.len()) };

        assert!(!hotkey.is_null());
        let hotkey_ref = unsafe { hotkey.as_ref() }.expect("hotkey");
        assert_eq!(hotkey_ref.secret_key_len, 32);
        assert_eq!(hotkey_ref.public_key_len, 32);
        assert!(!hotkey_ref.secret_key.is_null());
        assert!(!hotkey_ref.public_key.is_null());
        assert!(!hotkey_ref.address.is_null());

        unsafe {
            zcashlc_voting_free_hotkey(hotkey);
            zcashlc_voting_db_free(db);
        }
    }

    #[test]
    fn generate_hotkey_rejects_short_seed() {
        let db = open_memory_voting_db();
        let seed = [7u8; 31];

        let hotkey = unsafe { zcashlc_voting_generate_hotkey(db, seed.as_ptr(), seed.len()) };

        assert!(hotkey.is_null());
        unsafe { zcashlc_voting_db_free(db) };
    }

    #[test]
    fn setup_bundles_and_count_return_freeable_ffi_value() {
        let db = open_memory_voting_db();
        init_test_round(db);
        let round = TEST_ROUND_ID.as_bytes();
        let notes_json = b"[]";

        let result = unsafe {
            zcashlc_voting_setup_bundles(
                db,
                round.as_ptr(),
                round.len(),
                notes_json.as_ptr(),
                notes_json.len(),
            )
        };

        assert!(!result.is_null());
        let result_ref = unsafe { result.as_ref() }.expect("bundle setup result");
        assert_eq!(result_ref.bundle_count, 0);
        assert_eq!(result_ref.eligible_weight, 0);
        assert_eq!(
            unsafe { zcashlc_voting_get_bundle_count(db, round.as_ptr(), round.len()) },
            0
        );

        unsafe {
            zcashlc_voting_free_bundle_setup_result(result);
            zcashlc_voting_db_free(db);
        }
    }

    #[test]
    fn store_tree_state_and_van_position_accept_existing_round_bundle() {
        let db = open_memory_voting_db();
        init_test_round(db);
        insert_test_bundle(db, 0);
        let round = TEST_ROUND_ID.as_bytes();
        let tree_state = [1u8, 2, 3];

        assert_eq!(
            unsafe {
                zcashlc_voting_store_tree_state(
                    db,
                    round.as_ptr(),
                    round.len(),
                    tree_state.as_ptr(),
                    tree_state.len(),
                )
            },
            0
        );
        assert_eq!(
            unsafe { zcashlc_voting_store_van_position(db, round.as_ptr(), round.len(), 0, 42) },
            0
        );

        unsafe { zcashlc_voting_db_free(db) };
    }

    #[test]
    fn proof_and_submission_calls_reject_invalid_network_id_before_remote_work() {
        let db = open_memory_voting_db();
        let round = TEST_ROUND_ID.as_bytes();
        let notes_json = b"[]";
        let bytes = [0u8; 32];

        assert!(
            unsafe {
                zcashlc_voting_build_and_prove_delegation(
                    db,
                    round.as_ptr(),
                    round.len(),
                    0,
                    notes_json.as_ptr(),
                    notes_json.len(),
                    bytes.as_ptr(),
                    bytes.len(),
                    b"https://example.com/".as_ptr(),
                    20,
                    99,
                    None,
                    std::ptr::null_mut(),
                )
            }
            .is_null()
        );
        assert!(
            unsafe {
                zcashlc_voting_get_delegation_submission(
                    db,
                    round.as_ptr(),
                    round.len(),
                    0,
                    bytes.as_ptr(),
                    bytes.len(),
                    99,
                    0,
                )
            }
            .is_null()
        );

        unsafe { zcashlc_voting_db_free(db) };
    }

    #[test]
    fn cached_tree_state_validation_accepts_matching_round() {
        let root = [7; 32];
        let tree_state = tree_state_at_height(100);
        let params = round_params(100, root.to_vec());

        assert!(validate_cached_tree_state_for_round(&tree_state, &root, &params).is_ok());
    }

    #[test]
    fn cached_tree_state_validation_rejects_height_mismatch() {
        let root = [7; 32];
        let tree_state = tree_state_at_height(99);
        let params = round_params(100, root.to_vec());

        let error = validate_cached_tree_state_for_round(&tree_state, &root, &params)
            .expect_err("height mismatch must be rejected");
        assert!(
            error
                .to_string()
                .contains("does not match round snapshot_height")
        );
    }

    #[test]
    fn cached_tree_state_validation_rejects_root_mismatch() {
        let tree_state = tree_state_at_height(100);
        let params = round_params(100, vec![7; 32]);

        let error = validate_cached_tree_state_for_round(&tree_state, &[8; 32], &params)
            .expect_err("root mismatch must be rejected");
        assert!(error.to_string().contains("does not match round nc_root"));
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
            1
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
            0
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
            0
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

    #[test]
    fn precompute_delegation_pir_rejects_null_db() {
        let result = unsafe {
            zcashlc_voting_precompute_delegation_pir(
                std::ptr::null_mut(),
                std::ptr::null(),
                0,
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                0,
            )
        };

        assert!(result.is_null());
    }

    #[test]
    fn precompute_delegation_pir_rejects_invalid_network_id() {
        let db = open_memory_voting_db();
        let result = unsafe {
            zcashlc_voting_precompute_delegation_pir(
                db,
                b"round1".as_ptr(),
                6,
                0,
                b"[]".as_ptr(),
                2,
                b"https://example.com/".as_ptr(),
                20,
                99,
            )
        };
        assert!(result.is_null());
        unsafe { zcashlc_voting_db_free(db) };
    }

    #[test]
    fn generate_note_witnesses_rejects_null_db() {
        let result = unsafe {
            zcashlc_voting_generate_note_witnesses(
                std::ptr::null_mut(),
                std::ptr::null(),
                0,
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                1,
            )
        };

        assert!(result.is_null());
    }

    #[test]
    fn generate_note_witnesses_rejects_invalid_network_id() {
        let db = open_memory_voting_db();
        // Network id 99 is invalid; the call must reject it before touching
        // the wallet DB at the (non-existent) path.
        let wallet_db_path = b"/nonexistent/wallet.sqlite";
        let result = unsafe {
            zcashlc_voting_generate_note_witnesses(
                db,
                b"round1".as_ptr(),
                6,
                0,
                wallet_db_path.as_ptr(),
                wallet_db_path.len(),
                b"[]".as_ptr(),
                2,
                99,
            )
        };
        assert!(result.is_null());
        unsafe { zcashlc_voting_db_free(db) };
    }

    #[test]
    fn generate_note_witnesses_returns_and_caches_valid_witnesses() {
        const SNAPSHOT_HEIGHT: u64 = 100;
        const LATER_HEIGHT: u32 = 200;
        const BUNDLE_INDEX: u32 = 7;

        let wallet_path = temp_sqlite_path("generate_witnesses_success_wallet");
        let wallet_path_bytes = wallet_path.to_string_lossy().as_bytes().to_vec();
        let note_positions = vec![Position::from(2)];

        let (frontier_tree, leaves) =
            seed_wallet_orchard_tree(&wallet_path, SNAPSHOT_HEIGHT, LATER_HEIGHT, &note_positions);
        let expected_root = frontier_tree.root().to_bytes().to_vec();
        let tree_state = tree_state_from_frontier(SNAPSHOT_HEIGHT, &frontier_tree);

        let db = open_memory_voting_db();
        store_round_bundle_and_tree_state(
            db,
            SNAPSHOT_HEIGHT,
            BUNDLE_INDEX,
            &note_positions,
            expected_root.clone(),
            &tree_state,
        );

        let notes_json = notes_json_for_positions(&leaves, &note_positions);
        let result = call_generate_note_witnesses(
            db,
            BUNDLE_INDEX,
            &wallet_path_bytes,
            notes_json.as_ptr(),
            notes_json.len(),
        );
        assert!(!result.is_null(), "witness generation succeeds");

        let returned = decode_witnesses(result);
        assert_witnesses_match_positions(&returned, &leaves, &note_positions, &expected_root);
        assert_cached_witnesses_match(db, BUNDLE_INDEX, &returned);

        unsafe { zcashlc_voting_db_free(db) };
        let _ = std::fs::remove_file(&wallet_path);
    }

    #[test]
    fn generate_note_witnesses_returns_and_caches_multiple_valid_witnesses() {
        const SNAPSHOT_HEIGHT: u64 = 100;
        const LATER_HEIGHT: u32 = 200;
        const BUNDLE_INDEX: u32 = 8;

        let wallet_path = temp_sqlite_path("generate_witnesses_multi_wallet");
        let wallet_path_bytes = wallet_path.to_string_lossy().as_bytes().to_vec();
        let note_positions = vec![Position::from(1), Position::from(2), Position::from(4)];

        let (frontier_tree, leaves) =
            seed_wallet_orchard_tree(&wallet_path, SNAPSHOT_HEIGHT, LATER_HEIGHT, &note_positions);
        let expected_root = frontier_tree.root().to_bytes().to_vec();
        let tree_state = tree_state_from_frontier(SNAPSHOT_HEIGHT, &frontier_tree);

        let db = open_memory_voting_db();
        store_round_bundle_and_tree_state(
            db,
            SNAPSHOT_HEIGHT,
            BUNDLE_INDEX,
            &note_positions,
            expected_root.clone(),
            &tree_state,
        );

        let notes_json = notes_json_for_positions(&leaves, &note_positions);
        let result = call_generate_note_witnesses(
            db,
            BUNDLE_INDEX,
            &wallet_path_bytes,
            notes_json.as_ptr(),
            notes_json.len(),
        );
        assert!(!result.is_null(), "multi-note witness generation succeeds");

        let returned = decode_witnesses(result);
        assert_witnesses_match_positions(&returned, &leaves, &note_positions, &expected_root);
        assert_cached_witnesses_match(db, BUNDLE_INDEX, &returned);

        unsafe { zcashlc_voting_db_free(db) };
        let _ = std::fs::remove_file(&wallet_path);
    }

    #[test]
    fn generate_note_witnesses_rejects_stale_tree_state_height_through_ffi() {
        const SNAPSHOT_HEIGHT: u64 = 100;
        const LATER_HEIGHT: u32 = 200;
        const BUNDLE_INDEX: u32 = 9;

        let wallet_path = temp_sqlite_path("generate_witnesses_stale_height_wallet");
        let wallet_path_bytes = wallet_path.to_string_lossy().as_bytes().to_vec();
        let note_positions = vec![Position::from(2)];

        let (frontier_tree, leaves) =
            seed_wallet_orchard_tree(&wallet_path, SNAPSHOT_HEIGHT, LATER_HEIGHT, &note_positions);
        let expected_root = frontier_tree.root().to_bytes().to_vec();
        let stale_tree_state = tree_state_from_frontier(SNAPSHOT_HEIGHT - 1, &frontier_tree);

        let db = open_memory_voting_db();
        store_round_bundle_and_tree_state(
            db,
            SNAPSHOT_HEIGHT,
            BUNDLE_INDEX,
            &note_positions,
            expected_root,
            &stale_tree_state,
        );

        let notes_json = notes_json_for_positions(&leaves, &note_positions);
        let result = call_generate_note_witnesses(
            db,
            BUNDLE_INDEX,
            &wallet_path_bytes,
            notes_json.as_ptr(),
            notes_json.len(),
        );

        assert!(result.is_null());
        assert_cached_witnesses_match(db, BUNDLE_INDEX, &[]);

        unsafe { zcashlc_voting_db_free(db) };
        let _ = std::fs::remove_file(&wallet_path);
    }

    #[test]
    fn generate_note_witnesses_rejects_stale_tree_state_root_through_ffi() {
        const SNAPSHOT_HEIGHT: u64 = 100;
        const LATER_HEIGHT: u32 = 200;
        const BUNDLE_INDEX: u32 = 10;

        let wallet_path = temp_sqlite_path("generate_witnesses_stale_root_wallet");
        let wallet_path_bytes = wallet_path.to_string_lossy().as_bytes().to_vec();
        let note_positions = vec![Position::from(2)];

        let (frontier_tree, leaves) =
            seed_wallet_orchard_tree(&wallet_path, SNAPSHOT_HEIGHT, LATER_HEIGHT, &note_positions);
        let mut mismatched_root = frontier_tree.root().to_bytes().to_vec();
        mismatched_root[0] ^= 1;
        let tree_state = tree_state_from_frontier(SNAPSHOT_HEIGHT, &frontier_tree);

        let db = open_memory_voting_db();
        store_round_bundle_and_tree_state(
            db,
            SNAPSHOT_HEIGHT,
            BUNDLE_INDEX,
            &note_positions,
            mismatched_root,
            &tree_state,
        );

        let notes_json = notes_json_for_positions(&leaves, &note_positions);
        let result = call_generate_note_witnesses(
            db,
            BUNDLE_INDEX,
            &wallet_path_bytes,
            notes_json.as_ptr(),
            notes_json.len(),
        );

        assert!(result.is_null());
        assert_cached_witnesses_match(db, BUNDLE_INDEX, &[]);

        unsafe { zcashlc_voting_db_free(db) };
        let _ = std::fs::remove_file(&wallet_path);
    }

    #[test]
    fn generate_note_witnesses_rejects_empty_orchard_frontier() {
        const SNAPSHOT_HEIGHT: u64 = 100;
        const BUNDLE_INDEX: u32 = 11;

        let wallet_path = temp_sqlite_path("generate_witnesses_empty_frontier_wallet");
        let wallet_path_bytes = wallet_path.to_string_lossy().as_bytes().to_vec();
        {
            let mut wallet_db = WalletDb::for_path(
                &wallet_path,
                Network::TestNetwork,
                SystemClock,
                rand::rngs::OsRng,
            )
            .expect("open wallet db");
            WalletMigrator::new()
                .init_or_migrate(&mut wallet_db)
                .expect("initialize wallet db");
        }

        let empty_frontier: Frontier<
            MerkleHashOrchard,
            { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
        > = Frontier::empty();
        let expected_root = empty_frontier.root().to_bytes().to_vec();
        let tree_state = tree_state_from_frontier(SNAPSHOT_HEIGHT, &empty_frontier);
        let note_positions = vec![Position::from(0)];

        let db = open_memory_voting_db();
        store_round_bundle_and_tree_state(
            db,
            SNAPSHOT_HEIGHT,
            BUNDLE_INDEX,
            &note_positions,
            expected_root,
            &tree_state,
        );

        let notes = vec![note_json_for(Position::from(0), merkle_hash(1))];
        let notes_json = serde_json::to_vec(&notes).expect("serialize notes");
        let result = call_generate_note_witnesses(
            db,
            BUNDLE_INDEX,
            &wallet_path_bytes,
            notes_json.as_ptr(),
            notes_json.len(),
        );

        assert!(result.is_null());
        assert_cached_witnesses_match(db, BUNDLE_INDEX, &[]);

        unsafe { zcashlc_voting_db_free(db) };
        let _ = std::fs::remove_file(&wallet_path);
    }

    #[test]
    fn generate_note_witnesses_accepts_zero_len_notes_json() {
        const SNAPSHOT_HEIGHT: u64 = 100;
        const LATER_HEIGHT: u32 = 200;
        const BUNDLE_INDEX: u32 = 12;

        let wallet_path = temp_sqlite_path("generate_witnesses_empty_notes_wallet");
        let wallet_path_bytes = wallet_path.to_string_lossy().as_bytes().to_vec();
        let note_positions = Vec::new();

        let (frontier_tree, _leaves) =
            seed_wallet_orchard_tree(&wallet_path, SNAPSHOT_HEIGHT, LATER_HEIGHT, &note_positions);
        let expected_root = frontier_tree.root().to_bytes().to_vec();
        let tree_state = tree_state_from_frontier(SNAPSHOT_HEIGHT, &frontier_tree);

        let db = open_memory_voting_db();
        store_round_bundle_and_tree_state(
            db,
            SNAPSHOT_HEIGHT,
            BUNDLE_INDEX,
            &note_positions,
            expected_root,
            &tree_state,
        );

        let result =
            call_generate_note_witnesses(db, BUNDLE_INDEX, &wallet_path_bytes, std::ptr::null(), 0);
        assert!(!result.is_null(), "empty notes list succeeds");

        let returned = decode_witnesses(result);
        assert!(returned.is_empty());
        assert_cached_witnesses_match(db, BUNDLE_INDEX, &returned);

        unsafe { zcashlc_voting_db_free(db) };
        let _ = std::fs::remove_file(&wallet_path);
    }
}
