use std::panic::AssertUnwindSafe;

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;

use crate::{unwrap_exc_or, unwrap_exc_or_null};

use super::db::VotingDatabaseHandle;
use super::helpers::{json_to_boxed_slice, str_from_ptr};
use super::json::JsonVanWitness;

// =============================================================================
// VotingDatabase methods — Tree sync
// =============================================================================

/// Sync the vote commitment tree from a chain node.
///
/// Returns the latest synced block height on success (>= 0), or -1 on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_sync_vote_tree(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    node_url: *const u8,
    node_url_len: usize,
) -> i64 {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let url = unsafe { str_from_ptr(node_url, node_url_len) }?;

        let height = handle
            .tree_sync
            .sync(&handle.db, &round_id_str, &url)
            .map_err(|e| anyhow!("sync_vote_tree failed: {}", e))?;
        Ok(height as i64)
    });
    unwrap_exc_or(res, -1)
}

/// Generate a VAN Merkle witness for ZKP #2.
///
/// Returns JSON-encoded `VanWitness` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_generate_van_witness(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    anchor_height: u32,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;

        let witness = handle
            .tree_sync
            .generate_van_witness(&handle.db, &round_id_str, bundle_index, anchor_height)
            .map_err(|e| anyhow!("generate_van_witness failed: {}", e))?;

        let json_witness: JsonVanWitness = witness.into();
        json_to_boxed_slice(&json_witness)
    });
    unwrap_exc_or_null(res)
}

/// Drop the in-memory TreeClient so the next `sync_vote_tree()` call
/// creates a fresh one.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_reset_tree_client(
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
            .tree_sync
            .reset(&round_id_str)
            .map_err(|e| anyhow!("reset_tree_client failed: {}", e))?;
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}
