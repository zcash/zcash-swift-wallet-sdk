use std::panic::AssertUnwindSafe;

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;

use crate::{unwrap_exc_or, unwrap_exc_or_null};

use super::db::VotingDatabaseHandle;
use super::helpers::{bytes_from_ptr, json_to_boxed_slice, str_from_ptr};

// =============================================================================
// Recovery state (TX hashes, bundles, share delegations, keystone sigs)
// =============================================================================

/// Persist the on-chain TX hash of a submitted delegation bundle so
/// crash recovery can find it after app restart.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - `round_id` and `tx_hash` must be valid UTF-8 pointers with their stated lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_store_delegation_tx_hash(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    tx_hash: *const u8,
    tx_hash_len: usize,
) -> i32 {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let tx_hash_str = unsafe { str_from_ptr(tx_hash, tx_hash_len) }?;
        handle
            .db
            .store_delegation_tx_hash(&round_id_str, bundle_index, &tx_hash_str)
            .map_err(|e| anyhow!("store_delegation_tx_hash failed: {}", e))?;
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}

/// Load a previously stored delegation TX hash. Returns a JSON-encoded
/// `Option<String>` — `null` when no row exists for this bundle.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - `round_id` must be a valid UTF-8 pointer with its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_delegation_tx_hash(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let hash = handle
            .db
            .get_delegation_tx_hash(&round_id_str, bundle_index)
            .map_err(|e| anyhow!("get_delegation_tx_hash failed: {}", e))?;
        json_to_boxed_slice(&hash)
    });
    unwrap_exc_or_null(res)
}

/// Persist the on-chain TX hash of a submitted vote (scoped by bundle and
/// proposal) for crash-recovery lookups.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - `round_id` and `tx_hash` must be valid UTF-8 pointers with their stated lengths.
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
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let tx_hash_str = unsafe { str_from_ptr(tx_hash, tx_hash_len) }?;
        handle
            .db
            .store_vote_tx_hash(&round_id_str, bundle_index, proposal_id, &tx_hash_str)
            .map_err(|e| anyhow!("store_vote_tx_hash failed: {}", e))?;
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}

/// Load a previously stored vote TX hash. Returns a JSON-encoded
/// `Option<String>` — `null` when no row exists for this bundle/proposal.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - `round_id` must be a valid UTF-8 pointer with its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_vote_tx_hash(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    proposal_id: u32,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let hash = handle
            .db
            .get_vote_tx_hash(&round_id_str, bundle_index, proposal_id)
            .map_err(|e| anyhow!("get_vote_tx_hash failed: {}", e))?;
        json_to_boxed_slice(&hash)
    });
    unwrap_exc_or_null(res)
}

/// Persist the vote commitment bundle JSON and VC-tree position before TX
/// submission, so share delegation can resume after a crash between TX
/// confirmation and share send-out.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - `round_id` and `bundle_json` must be valid UTF-8 pointers with their stated lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_store_commitment_bundle(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    proposal_id: u32,
    bundle_json: *const u8,
    bundle_json_len: usize,
    vc_tree_position: u64,
) -> i32 {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let json_str = unsafe { str_from_ptr(bundle_json, bundle_json_len) }?;
        handle
            .db
            .store_commitment_bundle(
                &round_id_str,
                bundle_index,
                proposal_id,
                &json_str,
                vc_tree_position,
            )
            .map_err(|e| anyhow!("store_commitment_bundle failed: {}", e))?;
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}

/// Load a stored commitment bundle and its VC-tree position. Returns a
/// JSON-encoded `Option<(String, u64)>` — `null` when no row exists.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - `round_id` must be a valid UTF-8 pointer with its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_commitment_bundle(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    proposal_id: u32,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let result = handle
            .db
            .get_commitment_bundle(&round_id_str, bundle_index, proposal_id)
            .map_err(|e| anyhow!("get_commitment_bundle failed: {}", e))?;
        json_to_boxed_slice(&result)
    });
    unwrap_exc_or_null(res)
}

/// Persist a Keystone-produced PCZT signature (`sig` + `sighash` + `rk`)
/// so it survives app restarts during the delegation-signing workflow.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - `round_id` must be a valid UTF-8 pointer with its stated length.
/// - `sig`, `sighash`, and `rk` must be valid for reads of their stated lengths.
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
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let sig_bytes = unsafe { bytes_from_ptr(sig, sig_len) };
        let sighash_bytes = unsafe { bytes_from_ptr(sighash, sighash_len) };
        let rk_bytes = unsafe { bytes_from_ptr(rk, rk_len) };
        handle
            .db
            .store_keystone_signature(
                &round_id_str,
                bundle_index,
                sig_bytes,
                sighash_bytes,
                rk_bytes,
            )
            .map_err(|e| anyhow!("store_keystone_signature failed: {}", e))?;
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}

/// Load all Keystone signatures stored for a round, returned as a JSON array
/// of `{ bundle_index, sig, sighash, rk }` objects.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - `round_id` must be a valid UTF-8 pointer with its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_keystone_signatures(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let sigs = handle
            .db
            .get_keystone_signatures(&round_id_str)
            .map_err(|e| anyhow!("get_keystone_signatures failed: {}", e))?;

        #[derive(serde::Serialize)]
        struct SigOut {
            bundle_index: u32,
            sig: Vec<u8>,
            sighash: Vec<u8>,
            rk: Vec<u8>,
        }

        let out: Vec<SigOut> = sigs
            .into_iter()
            .map(|s| SigOut {
                bundle_index: s.bundle_index,
                sig: s.sig,
                sighash: s.sighash,
                rk: s.rk,
            })
            .collect();

        json_to_boxed_slice(&out)
    });
    unwrap_exc_or_null(res)
}

/// Remove all recovery-state rows for a round — TX hashes, commitment
/// bundles, and Keystone signatures — once the round is fully submitted
/// and no longer needs crash-recovery metadata.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - `round_id` must be a valid UTF-8 pointer with its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_clear_recovery_state(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
) -> i32 {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        handle
            .db
            .clear_recovery_state(&round_id_str)
            .map_err(|e| anyhow!("clear_recovery_state failed: {}", e))?;
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}
