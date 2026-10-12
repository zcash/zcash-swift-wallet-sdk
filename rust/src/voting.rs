//! `zcash_voting` has no release on the NU7 librustzcash pre-releases this crate builds
//! against, so shielded voting is compiled out. Every `zcashlc_voting_*` function keeps its C
//! signature, so the header and its Swift callers are unchanged, and each one fails through the
//! last-error channel. Nothing here allocates, so the free functions in [`ffi_types`] only ever
//! receive null.

// Each stub keeps its original parameter names, so the generated header is unchanged.
#![allow(unused_variables)]

use std::ffi::c_char;
use std::ptr;

use anyhow::anyhow;

pub mod ffi_types;

use ffi_types::{
    FfiBundleSetupResult, FfiRoundState, FfiRoundSummaries, FfiVoteRecords, FfiVotingHotkey,
};

/// Opaque handle to a voting database. `zcashlc_voting_db_open` never returns one.
pub struct VotingDatabaseHandle {
    _private: (),
}

/// Records why the call failed and returns the caller's failure value.
fn unavailable<T>(failure: T) -> T {
    ffi_helpers::update_last_error(anyhow!("Shielded voting is unavailable in this build"));
    failure
}

/// Free a `VotingDatabaseHandle`.
///
/// # Safety
///
/// - If `ptr` is non-null, it must be a pointer previously returned by
///   `zcashlc_voting_db_open` that has not already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_db_free(ptr: *mut VotingDatabaseHandle) {
    if !ptr.is_null() {
        drop(unsafe { Box::from_raw(ptr) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_confirm_vote_submission(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    proposal_id: u32,
    tx_hash: *const u8,
    tx_hash_len: usize,
    events_json: *const u8,
    events_json_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_db_open(
    path: *const u8,
    path_len: usize,
    network_id: u32,
) -> *mut VotingDatabaseHandle {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_set_wallet_id(
    db: *mut VotingDatabaseHandle,
    wallet_id: *const u8,
    wallet_id_len: usize,
) -> i32 {
    unavailable(-1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_generate_hotkey(network_id: u32) -> *mut FfiVotingHotkey {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_setup_bundles(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    notes_json: *const u8,
    notes_json_len: usize,
) -> *mut FfiBundleSetupResult {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_bundle_count(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
) -> i64 {
    unavailable(-1)
}

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
    hotkey_stored_secret: *const u8,
    hotkey_stored_secret_len: usize,
    consensus_branch_id: u32,
    seed_fingerprint: *const u8,
    seed_fingerprint_len: usize,
    account_index: u32,
    round_name: *const u8,
    round_name_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_store_tree_state(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    tree_state_bytes: *const u8,
    tree_state_bytes_len: usize,
) -> i32 {
    unavailable(-1)
}

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
    unavailable(ptr::null_mut())
}

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
    pir_depth: u32,
    tier0_layers: u32,
    tier1_layers: u32,
    poly_len: u32,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_build_and_prove_delegation(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    notes_json: *const u8,
    notes_json_len: usize,
    fvk_bytes: *const u8,
    fvk_bytes_len: usize,
    hotkey_stored_secret: *const u8,
    hotkey_stored_secret_len: usize,
    seed_fingerprint: *const u8,
    seed_fingerprint_len: usize,
    account_index: u32,
    round_name: *const u8,
    round_name_len: usize,
    pir_server_url: *const u8,
    pir_server_url_len: usize,
    pir_depth: u32,
    tier0_layers: u32,
    tier1_layers: u32,
    poly_len: u32,
    progress_callback: Option<unsafe extern "C" fn(f64, *mut std::ffi::c_void)>,
    progress_context: *mut std::ffi::c_void,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_delegation_submission_with_signature(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    sig: *const u8,
    sig_len: usize,
    sighash: *const u8,
    sighash_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_store_van_position(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    position: u32,
) -> i32 {
    unavailable(-1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_validate_pir_proof(
    root: *const u8,
    nf_bounds: *const u8,
    leaf_pos: u32,
    path: *const u8,
    nullifier: *const u8,
    expected_root: *const u8,
) -> i32 {
    unavailable(-1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_wallet_notes(
    db: *mut VotingDatabaseHandle,
    wallet_db_path: *const u8,
    wallet_db_path_len: usize,
    snapshot_height: u64,
    network_id: u32,
    account_uuid: *const u8,
    account_uuid_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_store_delegation_tx_hash(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    tx_hash: *const u8,
    tx_hash_len: usize,
) -> i32 {
    unavailable(-1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_delegation_tx_hash(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_store_vote_tx_hash(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    proposal_id: u32,
    tx_hash: *const u8,
    tx_hash_len: usize,
) -> i32 {
    unavailable(-1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_vote_tx_hash(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    proposal_id: u32,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_record_vc_position(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    proposal_id: u32,
    vc_tree_position: u64,
) -> i32 {
    unavailable(-1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_commitment_bundle(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    proposal_id: u32,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_store_keystone_signature(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    sig: *const u8,
    sig_len: usize,
    sighash: *const u8,
    sighash_len: usize,
    rk: *const u8,
    rk_len: usize,
) -> i32 {
    unavailable(-1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_keystone_signatures(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_clear_recovery_state(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
) -> i32 {
    unavailable(-1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_init_round(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    snapshot_height: u64,
    ea_pk: *const u8,
    ea_pk_len: usize,
    nc_root: *const u8,
    nc_root_len: usize,
    nullifier_imt_root: *const u8,
    nullifier_imt_root_len: usize,
    session_json: *const u8,
    session_json_len: usize,
) -> i32 {
    unavailable(-1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_round_state(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
) -> *mut FfiRoundState {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_list_rounds(
    db: *mut VotingDatabaseHandle,
) -> *mut FfiRoundSummaries {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_votes(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
) -> *mut FfiVoteRecords {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_clear_round(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
) -> i32 {
    unavailable(-1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_delete_skipped_bundles(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    keep_count: u32,
) -> i64 {
    unavailable(-1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_compute_share_nullifier(
    vote_commitment: *const u8,
    primary_blind: *const u8,
    share_index: u32,
) -> *mut c_char {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_record_share_delegation(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    proposal_id: u32,
    share_index: u32,
    sent_to_urls_json: *const u8,
    sent_to_urls_json_len: usize,
    submit_at: u64,
) -> i32 {
    unavailable(-1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_share_delegations(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_unconfirmed_delegations(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_mark_share_confirmed(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    proposal_id: u32,
    share_index: u32,
) -> i32 {
    unavailable(-1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_add_sent_servers(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    proposal_id: u32,
    share_index: u32,
    new_urls_json: *const u8,
    new_urls_json_len: usize,
) -> i32 {
    unavailable(-1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_recover_wire_json(
    commitment_bundle_json: *const u8,
    commitment_bundle_json_len: usize,
    proposal_id: u32,
    share_index: u32,
    vc_tree_position: u64,
    submit_at: u64,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_recoverable_share_indices(
    commitment_bundle_json: *const u8,
    commitment_bundle_json_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_sign_delegation_request(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    fvk_bytes: *const u8,
    fvk_bytes_len: usize,
    hotkey_stored_secret: *const u8,
    hotkey_stored_secret_len: usize,
    seed_fingerprint: *const u8,
    seed_fingerprint_len: usize,
    account_index: u32,
    round_name: *const u8,
    round_name_len: usize,
    seed: *const u8,
    seed_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_sync_vote_tree(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    node_url: *const u8,
    node_url_len: usize,
) -> i64 {
    unavailable(-1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_generate_van_witness(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    anchor_height: u32,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_reset_tree_client(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
) -> i32 {
    unavailable(-1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_warm_proving_caches() -> i32 {
    unavailable(-1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_generate_delegation_inputs(
    sender_seed: *const u8,
    sender_seed_len: usize,
    hotkey_stored_secret: *const u8,
    hotkey_stored_secret_len: usize,
    network_id: u32,
    account_index: u32,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_generate_delegation_inputs_with_fvk(
    fvk_bytes: *const u8,
    fvk_bytes_len: usize,
    hotkey_stored_secret: *const u8,
    hotkey_stored_secret_len: usize,
    network_id: u32,
    seed_fingerprint: *const u8,
    seed_fingerprint_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_extract_pczt_sighash(
    pczt_bytes: *const u8,
    pczt_bytes_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_extract_spend_auth_sig(
    signed_pczt_bytes: *const u8,
    signed_pczt_bytes_len: usize,
    action_index: u32,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_extract_orchard_fvk_from_ufvk(
    ufvk_str: *const u8,
    ufvk_str_len: usize,
    network_id: u32,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_extract_nc_root(
    tree_state_bytes: *const u8,
    tree_state_bytes_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_verify_witness(
    witness_json: *const u8,
    witness_json_len: usize,
) -> i32 {
    unavailable(-1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_commit_vote(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    hotkey_stored_secret: *const u8,
    hotkey_stored_secret_len: usize,
    proposal_id: u32,
    choice: u32,
    num_options: u32,
    vc_tree_position: u64,
    van_auth_path_json: *const u8,
    van_auth_path_json_len: usize,
    van_position: u32,
    anchor_height: u32,
    progress_callback: Option<unsafe extern "C" fn(f64, *mut std::ffi::c_void)>,
    progress_context: *mut std::ffi::c_void,
    single_share: u8,
) -> *mut crate::ffi::BoxedSlice {
    unavailable(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_mark_vote_submitted(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    proposal_id: u32,
    tx_hash: *const u8,
    tx_hash_len: usize,
) -> i32 {
    unavailable(-1)
}
