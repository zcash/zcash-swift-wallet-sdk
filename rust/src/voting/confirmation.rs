use std::panic::AssertUnwindSafe;

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
use zcash_voting as voting;

use crate::unwrap_exc_or_null;

use super::db::VotingDatabaseHandle;
use super::helpers::{bytes_from_ptr, json_to_boxed_slice, str_from_ptr};

/// Record a confirmed cast-vote transaction in one durable step.
///
/// Thin passthrough to `zcash_voting::confirmation::confirm_vote_submission`:
/// the crate parses the confirmation events, records the transaction hash,
/// advances the vote-authority-note position and records the vote-commitment
/// tree position inside a single database transaction, then returns both
/// positions. The FFI adds no parsing, no phase tracking and no state of its
/// own — in particular it does not split the `leaf_index` attribute, which is
/// the crate's job.
///
/// `events_json` is the confirmation-events array the wallet's chain client
/// returned, serialized as JSON: a list of
/// `{"type": "...", "attributes": [{"key": "...", "value": "..."}]}` objects,
/// which is exactly `Vec<zcash_voting::confirmation::TxEvent>`.
///
/// Returns JSON-encoded `zcash_voting::wire::VoteConfirmation` as
/// `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - For every `(ptr, len)` byte argument (`round_id`, `tx_hash`,
///   `events_json`): if `len > 0` then `ptr` must be non-null and valid for
///   reads for `len` bytes; if `len == 0`, `ptr` is ignored.
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
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let tx_hash_str = unsafe { str_from_ptr(tx_hash, tx_hash_len) }?;
        let events_bytes = unsafe { bytes_from_ptr(events_json, events_json_len) }?;
        let events: Vec<voting::confirmation::TxEvent> = serde_json::from_slice(events_bytes)?;

        let confirmation = voting::confirmation::confirm_vote_submission(
            &handle.db,
            &round_id_str,
            bundle_index,
            proposal_id,
            &tx_hash_str,
            &events,
        )
        .map_err(|e| anyhow!("confirm_vote_submission failed: {}", e))?;

        json_to_boxed_slice(&confirmation)
    });
    unwrap_exc_or_null(res)
}
