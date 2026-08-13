use std::collections::HashMap;
use std::ffi::CString;
use std::panic::AssertUnwindSafe;

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
use zcash_voting as voting;

use crate::{unwrap_exc_or, unwrap_exc_or_null};

use super::db::VotingDatabaseHandle;
use super::ffi_types::{
    FfiRoundState, FfiRoundSummaries, FfiRoundSummary, FfiVoteRecord, FfiVoteRecords,
};
use super::helpers::{bytes_from_ptr, round_phase_to_u32, str_from_ptr};

/// Initialize a voting round.
///
/// The round is persisted with the database handle's network, so that governance
/// PCZT consensus branch identifiers can later be validated against the round's
/// snapshot. The network is fixed when the handle is opened
/// (`zcashlc_voting_db_open`) rather than passed here, so a round cannot be
/// initialized against a network the handle disagrees with.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - String/byte parameters must be valid for their stated lengths.
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
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let ea_pk_bytes = unsafe { bytes_from_ptr(ea_pk, ea_pk_len) }?.to_vec();
        let nc_root_bytes = unsafe { bytes_from_ptr(nc_root, nc_root_len) }?.to_vec();
        let nullifier_imt_root_bytes =
            unsafe { bytes_from_ptr(nullifier_imt_root, nullifier_imt_root_len) }?.to_vec();

        let session = if session_json.is_null() || session_json_len == 0 {
            None
        } else {
            Some(unsafe { str_from_ptr(session_json, session_json_len) }?)
        };

        let params = voting::VotingRoundParams {
            vote_round_id: round_id_str,
            snapshot_height,
            ea_pk: ea_pk_bytes,
            nc_root: nc_root_bytes,
            nullifier_imt_root: nullifier_imt_root_bytes,
        };

        voting::validate_round_params(&params)
            .map_err(|e| anyhow!("invalid round params: {}", e))?;

        handle
            .db
            .init_round(handle.network, &params, session.as_deref())
            .map_err(|e| anyhow!("init_round failed: {}", e))?;
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}

/// Get the state of a voting round.
///
/// Returns a pointer to `FfiRoundState` on success, or null on error.
/// Call `zcashlc_voting_free_round_state` to free the returned pointer.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_round_state(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
) -> *mut FfiRoundState {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;

        let state = handle
            .db
            .get_round_state(&round_id_str)
            .map_err(|e| anyhow!("get_round_state failed: {}", e))?;

        let phase = round_phase_to_u32(state.phase);
        let round_id =
            CString::new(state.round_id).map_err(|e| anyhow!("invalid round_id string: {}", e))?;
        let hotkey_address = state
            .hotkey_address
            .map(|addr| {
                CString::new(addr).map_err(|e| anyhow!("invalid hotkey_address string: {}", e))
            })
            .transpose()?;
        let ffi_state = FfiRoundState {
            round_id: round_id.into_raw(),
            phase,
            snapshot_height: state.snapshot_height,
            hotkey_address: hotkey_address
                .map(CString::into_raw)
                .unwrap_or(std::ptr::null_mut()),
            delegated_weight: state.delegated_weight.map_or(-1, |w| w as i64),
            proof_generated: state.proof_generated,
        };

        Ok(Box::into_raw(Box::new(ffi_state)))
    });
    unwrap_exc_or_null(res)
}

/// List all voting rounds.
///
/// Returns a pointer to `FfiRoundSummaries` on success, or null on error.
/// Call `zcashlc_voting_free_round_summaries` to free the returned pointer.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_list_rounds(
    db: *mut VotingDatabaseHandle,
) -> *mut FfiRoundSummaries {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;

        let rounds = handle
            .db
            .list_rounds()
            .map_err(|e| anyhow!("list_rounds failed: {}", e))?;

        struct OwnedRoundSummary {
            round_id: CString,
            phase: u32,
            snapshot_height: u64,
            created_at: u64,
        }

        let owned_rounds: Vec<OwnedRoundSummary> = rounds
            .into_iter()
            .map(|s| {
                let phase = round_phase_to_u32(s.phase);
                Ok(OwnedRoundSummary {
                    round_id: CString::new(s.round_id)
                        .map_err(|e| anyhow!("invalid round_id string: {}", e))?,
                    phase,
                    snapshot_height: s.snapshot_height,
                    created_at: s.created_at,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let ffi_rounds: Vec<FfiRoundSummary> = owned_rounds
            .into_iter()
            .map(|s| FfiRoundSummary {
                round_id: s.round_id.into_raw(),
                phase: s.phase,
                snapshot_height: s.snapshot_height,
                created_at: s.created_at,
            })
            .collect();

        let (ptr, len) = crate::ptr_from_vec(ffi_rounds);
        Ok(Box::into_raw(Box::new(FfiRoundSummaries { ptr, len })))
    });
    unwrap_exc_or_null(res)
}

/// Get vote records for a round.
///
/// Returns a pointer to `FfiVoteRecords` on success, or null on error.
/// Call `zcashlc_voting_free_vote_records` to free the returned pointer.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_votes(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
) -> *mut FfiVoteRecords {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;

        let votes = handle
            .db
            .get_votes(&round_id_str)
            .map_err(|e| anyhow!("get_votes failed: {}", e))?;

        // `VoteRecord` no longer carries a submission flag; submission is one
        // step of the vote's lifecycle phase, which is loaded separately and
        // keyed by the same bundle/proposal pair.
        let phases: HashMap<(u32, u32), voting::phases::VotePhase> = handle
            .db
            .vote_phases(&round_id_str)
            .map_err(|e| anyhow!("vote_phases failed: {}", e))?
            .into_iter()
            .map(|(bundle_index, proposal_id, phase)| ((bundle_index, proposal_id), phase))
            .collect();

        let ffi_votes: Vec<FfiVoteRecord> = votes
            .into_iter()
            .map(|v| {
                let phase = phases
                    .get(&(v.bundle_index, v.proposal_id))
                    .ok_or_else(|| {
                        anyhow!(
                            "no lifecycle phase recorded for bundle {} proposal {}",
                            v.bundle_index,
                            v.proposal_id
                        )
                    })?;
                Ok(FfiVoteRecord {
                    proposal_id: v.proposal_id,
                    bundle_index: v.bundle_index,
                    choice: v.choice,
                    // A confirmed vote was necessarily submitted first, so both
                    // terminal phases report as submitted.
                    submitted: matches!(
                        phase,
                        voting::phases::VotePhase::Submitted | voting::phases::VotePhase::Confirmed
                    ),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let (ptr, len) = crate::ptr_from_vec(ffi_votes);
        Ok(Box::into_raw(Box::new(FfiVoteRecords { ptr, len })))
    });
    unwrap_exc_or_null(res)
}

/// Clear all data for a voting round.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_clear_round(
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
            .clear_round(&round_id_str)
            .map_err(|e| anyhow!("clear_round failed: {}", e))?;
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}

/// Delete bundle rows with index >= `keep_count`, removing skipped bundles.
///
/// Since `zcash_voting` 3.0 this fails for rounds holding capability-imported
/// bundles: the imported batch is atomic, so it must be replaced via
/// `zcashlc_voting_clear_round` and a complete re-import instead of partial
/// deletion. Locally prepared rounds are unaffected.
///
/// Returns the number of deleted rows on success, or -1 on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_delete_skipped_bundles(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    keep_count: u32,
) -> i64 {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;

        let deleted = handle
            .db
            .delete_skipped_bundles(&round_id_str, keep_count)
            .map_err(|e| anyhow!("delete_skipped_bundles failed: {}", e))?;
        Ok(deleted as i64)
    });
    unwrap_exc_or(res, -1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::voting::db::zcashlc_voting_db_free;
    use crate::voting::test_helpers::open_memory_db;

    /// Builds a round id that satisfies `validate_round_params`, which requires
    /// 64 lowercase hex characters encoding a canonical Pallas field element.
    /// `tag` distinguishes the ids so that each case gets its own round.
    fn hex_round_id(tag: u8) -> String {
        format!("{tag:02x}{}", "00".repeat(31))
    }

    fn init_round(
        db: *mut VotingDatabaseHandle,
        round_id: &[u8],
        ea_pk: &[u8],
        nc_root: &[u8],
        nullifier_imt_root: &[u8],
    ) -> i32 {
        unsafe {
            zcashlc_voting_init_round(
                db,
                round_id.as_ptr(),
                round_id.len(),
                123,
                ea_pk.as_ptr(),
                ea_pk.len(),
                nc_root.as_ptr(),
                nc_root.len(),
                nullifier_imt_root.as_ptr(),
                nullifier_imt_root.len(),
                std::ptr::null(),
                0,
            )
        }
    }

    fn round_exists(db: *mut VotingDatabaseHandle, round_id: &[u8]) -> bool {
        let state =
            unsafe { zcashlc_voting_get_round_state(db, round_id.as_ptr(), round_id.len()) };
        if state.is_null() {
            false
        } else {
            unsafe { crate::voting::ffi_types::zcashlc_voting_free_round_state(state) };
            true
        }
    }

    #[test]
    fn init_round_rejects_invalid_round_param_lengths_without_persisting() {
        let db = open_memory_db();
        let valid = [7u8; 32];

        let bad_ea_pk = hex_round_id(1);
        let bad_nc_root = hex_round_id(2);
        let bad_nullifier_root = hex_round_id(3);
        let cases = [
            (bad_ea_pk.as_bytes(), &valid[..31], &valid[..], &valid[..]),
            (bad_nc_root.as_bytes(), &valid[..], &valid[..31], &valid[..]),
            (
                bad_nullifier_root.as_bytes(),
                &valid[..],
                &valid[..],
                &valid[..31],
            ),
        ];

        for (round_id, ea_pk, nc_root, nullifier_imt_root) in cases {
            let code = init_round(db, round_id, ea_pk, nc_root, nullifier_imt_root);
            assert_eq!(code, -1);
            assert!(!round_exists(db, round_id));
        }

        unsafe { zcashlc_voting_db_free(db) };
    }

    #[test]
    fn get_votes_reports_submission_from_the_vote_lifecycle_phase() {
        use crate::voting::recovery::zcashlc_voting_store_vote_tx_hash;
        use crate::voting::test_helpers::insert_round_and_bundle;

        let db = open_memory_db();
        let round_id = b"round";
        insert_round_and_bundle(db, "round");

        // `zcash_voting` writes vote rows only as a side effect of a real
        // `vote::commit`, so the row is seeded through the public storage query
        // layer.
        {
            let handle = unsafe { db.as_ref() }.expect("voting db handle");
            voting::storage::queries::store_vote(
                &handle.db.conn(),
                "round",
                &handle.db.wallet_id(),
                0,
                0,
                1,
                &[0xaa; 32],
            )
            .expect("insert vote");
        }

        let records = unsafe { zcashlc_voting_get_votes(db, round_id.as_ptr(), round_id.len()) };
        assert!(!records.is_null());
        let slice = unsafe { std::slice::from_raw_parts((*records).ptr, (*records).len) };
        assert_eq!(slice.len(), 1);
        assert_eq!(slice[0].choice, 1);
        assert!(!slice[0].submitted);
        unsafe { crate::voting::ffi_types::zcashlc_voting_free_vote_records(records) };

        let tx_hash = b"vote-tx";
        assert_eq!(
            unsafe {
                zcashlc_voting_store_vote_tx_hash(
                    db,
                    round_id.as_ptr(),
                    round_id.len(),
                    0,
                    0,
                    tx_hash.as_ptr(),
                    tx_hash.len(),
                )
            },
            0
        );

        let records = unsafe { zcashlc_voting_get_votes(db, round_id.as_ptr(), round_id.len()) };
        assert!(!records.is_null());
        let slice = unsafe { std::slice::from_raw_parts((*records).ptr, (*records).len) };
        assert_eq!(slice.len(), 1);
        assert!(slice[0].submitted);
        unsafe { crate::voting::ffi_types::zcashlc_voting_free_vote_records(records) };

        unsafe { zcashlc_voting_db_free(db) };
    }

    #[test]
    fn init_round_accepts_valid_round_param_lengths() {
        let db = open_memory_db();
        let round_id = hex_round_id(4);
        let round_id = round_id.as_bytes();
        let valid = [7u8; 32];

        let code = init_round(db, round_id, &valid, &valid, &valid);

        assert_eq!(code, 0);
        assert!(round_exists(db, round_id));

        unsafe { zcashlc_voting_db_free(db) };
    }

    #[test]
    fn delete_skipped_bundles_deletes_from_locally_prepared_rounds() {
        use crate::voting::test_helpers::insert_round_and_bundle;

        let db = open_memory_db();
        let round_id = b"round";
        insert_round_and_bundle(db, "round");

        let deleted = unsafe {
            zcashlc_voting_delete_skipped_bundles(db, round_id.as_ptr(), round_id.len(), 0)
        };
        assert_eq!(deleted, 1);

        unsafe { zcashlc_voting_db_free(db) };
    }

    /// Pins the `zcash_voting` 3.0 atomicity guard: an imported-capability
    /// batch cannot be partially deleted, only replaced via a round clear and
    /// a complete re-import.
    #[test]
    fn delete_skipped_bundles_rejects_imported_capability_rounds() {
        use crate::voting::test_helpers::insert_round_and_bundle;

        let db = open_memory_db();
        let round_id = b"round";
        insert_round_and_bundle(db, "round");

        // Simulate a capability-imported bundle through the storage
        // discriminator the crate documents: imported bundles are exactly
        // those persisted without note positions (local preparation always
        // stores them; rc.5 databases therefore never trip this guard).
        {
            let handle = unsafe { db.as_ref() }.expect("voting db handle");
            handle
                .db
                .conn()
                .execute("UPDATE bundles SET note_positions_blob = NULL", [])
                .expect("mark bundle as capability-imported");
        }

        let deleted = unsafe {
            zcashlc_voting_delete_skipped_bundles(db, round_id.as_ptr(), round_id.len(), 0)
        };
        assert_eq!(deleted, -1);

        unsafe { zcashlc_voting_db_free(db) };
    }
}
