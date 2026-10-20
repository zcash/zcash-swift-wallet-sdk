use std::panic::AssertUnwindSafe;

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
use zcash_voting as voting;

use crate::{unwrap_exc_or, unwrap_exc_or_null};

use super::db::VotingDatabaseHandle;
use super::helpers::{bytes_from_ptr, json_to_boxed_slice, str_from_ptr};
use super::json::JsonVoteCommit;
use super::progress::ProgressBridge;

/// Build, sign, and persist a cast-vote commitment for one proposal.
///
/// This single entry point replaces the former three-call sequence of
/// `zcashlc_voting_build_vote_commitment`, `zcashlc_voting_sign_cast_vote` and
/// `zcashlc_voting_build_share_payloads`, together with
/// `zcashlc_voting_encrypt_shares`. `zcash_voting` absorbed all four steps into
/// `vote::commit` and made the intermediate steps private, so the sequence can
/// no longer be driven from outside the crate. Nothing is lost by that: the
/// returned `enc_shares` are the ciphertexts the vote proof commits to, and the
/// call is idempotent, so a repeated call for the same
/// `(round_id, bundle_index, proposal_id)` returns the persisted recovery
/// bundle instead of rebuilding the proof.
///
/// `hotkey_stored_secret` is the app-owned voting hotkey secret previously
/// returned as `FfiVotingHotkey::stored_secret`, not wallet seed material; it
/// replaces the `hotkey_seed` parameter of the superseded entry points. The
/// network the vote is signed for is taken from this hotkey, so `network_id`
/// must match the network the round was initialized with.
///
/// `van_auth_path_json` is a JSON-encoded `Vec<Vec<u8>>` holding exactly
/// `voting::vote::VAN_AUTH_PATH_LEN` siblings of 32 bytes each.
///
/// Returns JSON-encoded `JsonVoteCommit` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - For every `(ptr, len)` byte argument, if `len > 0` then `ptr` must be
///   non-null and valid for reads for `len` bytes; if `len == 0`, `ptr` is ignored.
/// - `progress_callback` must be a valid function pointer, or null to skip
///   progress. If provided, it must remain callable until this function returns.
///   It must be thread-safe and reentrant; callers must not assume it runs on
///   the main thread, because progress may be reported from proving worker threads.
/// - `progress_context` is passed to `progress_callback` unchanged. If non-null,
///   it must point to state that remains valid until this function returns. The
///   callback must not store `progress_context` or use it after this function returns.
/// - The callback must not call back into this voting database handle or perform
///   work that can deadlock or reenter the active proof operation.
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
    let db = AssertUnwindSafe(db);
    let progress_context = AssertUnwindSafe(progress_context);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;

        let network = handle.network;
        let stored_secret =
            unsafe { bytes_from_ptr(hotkey_stored_secret, hotkey_stored_secret_len) }?;
        let hotkey = voting::VotingHotkey::from_stored_secret(stored_secret, network)
            .map_err(|e| anyhow!("failed to reconstruct voting hotkey: {}", e))?;

        let auth_path_bytes =
            unsafe { bytes_from_ptr(van_auth_path_json, van_auth_path_json_len) }?;
        let auth_path: Vec<Vec<u8>> = serde_json::from_slice(auth_path_bytes)?;
        // `VanWitness::from_wire` owns the sibling-count and sibling-width
        // checks, so the FFI layer does not duplicate them.
        let witness = voting::vote::VanWitness::from_wire(&auth_path, van_position, anchor_height)
            .map_err(|e| anyhow!("invalid VAN witness: {}", e))?;

        let draft = voting::vote::DraftVote {
            proposal_id,
            choice,
            num_options,
            vc_tree_position,
            single_share: single_share != 0,
        };

        // `ProgressBridge` implements `ProgressReporter`, for which `zcash_voting`
        // blanket-implements `VoteCommitStageReporter`. The concrete type must
        // therefore be boxed as the stage reporter directly, because one trait
        // object does not coerce to another.
        let stages: Box<dyn voting::types::VoteCommitStageReporter> = match progress_callback {
            Some(cb) => Box::new(ProgressBridge {
                callback: cb,
                context: *progress_context,
            }),
            None => Box::new(voting::NoopProgressReporter),
        };

        let commit = voting::vote::commit(
            &handle.db,
            &round_id_str,
            bundle_index,
            &draft,
            &witness,
            voting::vote::VoteSigner::hotkey(&hotkey),
            stages.as_ref(),
        )
        .map_err(|e| anyhow!("vote commit failed: {}", e))?;

        json_to_boxed_slice(&JsonVoteCommit::from(commit))
    });
    unwrap_exc_or_null(res)
}

/// Record the cast-vote transaction hash for a specific proposal and bundle.
///
/// The transaction hash is now required: a vote is recorded as submitted by
/// persisting the transaction that carried it, so that a restarted wallet can
/// resume polling for that transaction rather than rebuilding the vote.
///
/// Returns 0 on success, or -1 on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - For each `(ptr, len)` byte argument, if `len > 0` then `ptr` must be
///   non-null and valid for reads for `len` bytes; if `len == 0`, `ptr` is
///   ignored.
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
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;

        let tx_hash_str = unsafe { str_from_ptr(tx_hash, tx_hash_len) }?;

        voting::vote::record_submission(
            &handle.db,
            &round_id_str,
            bundle_index,
            proposal_id,
            &tx_hash_str,
        )
        .map_err(|e| anyhow!("record_submission failed: {}", e))?;
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::voting::constants::CANONICAL_FIELD_LEN;
    use crate::voting::db::zcashlc_voting_db_free;
    use crate::voting::test_helpers::open_memory_db;
    use voting::vote::VAN_AUTH_PATH_LEN;

    /// A stored hotkey secret that `zcash_voting` accepts, produced the same way
    /// a wallet would produce it rather than by guessing at the encoding.
    fn valid_stored_secret() -> Vec<u8> {
        voting::hotkey::generate_random_voting_hotkey(voting::Network::Mainnet)
            .expect("generate hotkey")
            .stored_secret()
            .to_vec()
    }

    fn well_formed_auth_path_json() -> Vec<u8> {
        let auth_path = vec![vec![0u8; CANONICAL_FIELD_LEN]; VAN_AUTH_PATH_LEN];
        serde_json::to_vec(&auth_path).expect("auth path json")
    }

    fn call_commit_vote(
        db: *mut VotingDatabaseHandle,
        round_id: &[u8],
        stored_secret: &[u8],
        auth_path_json: &[u8],
    ) -> *mut crate::ffi::BoxedSlice {
        unsafe {
            zcashlc_voting_commit_vote(
                db,
                round_id.as_ptr(),
                round_id.len(),
                0,
                stored_secret.as_ptr(),
                stored_secret.len(),
                1,
                0,
                2,
                0,
                auth_path_json.as_ptr(),
                auth_path_json.len(),
                0,
                0,
                None,
                std::ptr::null_mut(),
                0,
            )
        }
    }

    #[test]
    fn vote_database_ffi_rejects_null_db() {
        let round = b"round";
        let stored_secret = valid_stored_secret();
        let auth_path_json = well_formed_auth_path_json();
        let tx_hash = b"0000000000000000000000000000000000000000000000000000000000000000";

        assert!(
            call_commit_vote(std::ptr::null_mut(), round, &stored_secret, &auth_path_json)
                .is_null()
        );

        assert_eq!(
            unsafe {
                zcashlc_voting_mark_vote_submitted(
                    std::ptr::null_mut(),
                    round.as_ptr(),
                    round.len(),
                    0,
                    1,
                    tx_hash.as_ptr(),
                    tx_hash.len(),
                )
            },
            -1
        );
    }

    #[test]
    fn commit_vote_rejects_malformed_auth_path_json() {
        let db = open_memory_db();
        let round = b"round";
        let stored_secret = valid_stored_secret();
        let invalid_json = b"not json";

        let result = call_commit_vote(db, round, &stored_secret, invalid_json);

        unsafe { zcashlc_voting_db_free(db) };
        assert!(
            result.is_null(),
            "malformed van_auth_path_json must be rejected"
        );
    }

    #[test]
    fn commit_vote_rejects_wrong_sized_auth_path_sibling() {
        let db = open_memory_db();
        let round = b"round";
        let stored_secret = valid_stored_secret();
        let mut auth_path = vec![vec![0u8; CANONICAL_FIELD_LEN]; VAN_AUTH_PATH_LEN];
        auth_path[0].pop();
        let auth_path_json = serde_json::to_vec(&auth_path).expect("auth path json");

        let result = call_commit_vote(db, round, &stored_secret, &auth_path_json);

        unsafe { zcashlc_voting_db_free(db) };
        assert!(result.is_null());
    }

    #[test]
    fn commit_vote_rejects_wrong_length_auth_path() {
        let db = open_memory_db();
        let round = b"round";
        let stored_secret = valid_stored_secret();
        let auth_path = vec![vec![0u8; CANONICAL_FIELD_LEN]; VAN_AUTH_PATH_LEN - 1];
        let auth_path_json = serde_json::to_vec(&auth_path).expect("auth path json");

        let result = call_commit_vote(db, round, &stored_secret, &auth_path_json);

        unsafe { zcashlc_voting_db_free(db) };
        assert!(result.is_null());
    }

    #[test]
    fn commit_vote_rejects_wrong_sized_stored_secret() {
        let db = open_memory_db();
        let round = b"round";
        let short_secret = [0x42u8; CANONICAL_FIELD_LEN];
        let auth_path_json = well_formed_auth_path_json();

        let result = call_commit_vote(db, round, &short_secret, &auth_path_json);

        unsafe { zcashlc_voting_db_free(db) };
        assert!(result.is_null());
    }

    #[test]
    fn mark_vote_submitted_rejects_missing_vote_row() {
        let db = open_memory_db();
        let round = b"round";
        let tx_hash = b"0000000000000000000000000000000000000000000000000000000000000000";

        let result = unsafe {
            zcashlc_voting_mark_vote_submitted(
                db,
                round.as_ptr(),
                round.len(),
                0,
                1,
                tx_hash.as_ptr(),
                tx_hash.len(),
            )
        };

        unsafe { zcashlc_voting_db_free(db) };
        assert_eq!(result, -1);
    }

    // The former `mark_vote_submitted_marks_existing_vote_row` test is gone: it
    // depended on `VotingDb::insert_vote_fixture` to plant a vote row and on
    // `VoteRecord::submitted` to observe the result, and `zcash_voting` removed
    // both. A vote row can now only come from a real `vote::commit`, whose proof
    // makes it unsuitable for a unit test, and submission state is exposed as a
    // `VotePhase` rather than a flag. Coverage for that path belongs with the
    // integration tests that can afford to prove a vote.
}
