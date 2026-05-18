use std::panic::AssertUnwindSafe;

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
use zcash_voting as voting;

use crate::{unwrap_exc_or, unwrap_exc_or_null};

use super::constants::{CANONICAL_FIELD_LEN, MIN_SEED_LEN, VOTE_ROUND_ID_HEX_LEN};
use super::db::VotingDatabaseHandle;
use super::helpers::{bytes_from_ptr, json_to_boxed_slice, str_from_ptr};
use super::json::{
    JsonCastVoteSignature, JsonSharePayload, JsonVoteCommitmentBundle, JsonWireEncryptedShare,
};
use super::progress::ProgressBridge;

/// Encrypt voting shares for a round.
///
/// `shares_json` is a JSON-encoded `Vec<u64>`.
///
/// Returns JSON-encoded `Vec<WireEncryptedShare>` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - For every `(ptr, len)` byte argument, if `len > 0` then `ptr` must be
///   non-null and valid for reads for `len` bytes; if `len == 0`, `ptr` is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_encrypt_shares(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    shares_json: *const u8,
    shares_json_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let shares_bytes = unsafe { bytes_from_ptr(shares_json, shares_json_len) }?;
        let shares: Vec<u64> = serde_json::from_slice(shares_bytes)?;

        let encrypted = handle
            .db
            .encrypt_shares(&round_id_str, &shares)
            .map_err(|e| anyhow!("encrypt_shares failed: {}", e))?;

        let json_shares: Vec<JsonWireEncryptedShare> =
            encrypted.into_iter().map(Into::into).collect();
        json_to_boxed_slice(&json_shares)
    });
    unwrap_exc_or_null(res)
}

/// Build a vote commitment proof for a proposal.
///
/// `van_auth_path_json` is a JSON-encoded `Vec<Vec<u8>>`, where each element is 32 bytes.
///
/// Returns JSON-encoded `VoteCommitmentBundle` as `*mut FfiBoxedSlice`, or null on error.
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
pub unsafe extern "C" fn zcashlc_voting_build_vote_commitment(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    hotkey_seed: *const u8,
    hotkey_seed_len: usize,
    network_id: u32,
    proposal_id: u32,
    choice: u32,
    num_options: u32,
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
        let seed = unsafe { bytes_from_ptr(hotkey_seed, hotkey_seed_len) }?;
        require_min_seed_len(seed, "hotkey_seed")?;
        let auth_path_bytes =
            unsafe { bytes_from_ptr(van_auth_path_json, van_auth_path_json_len) }?;
        let auth_path_vecs: Vec<Vec<u8>> = serde_json::from_slice(auth_path_bytes)?;
        let auth_path: Vec<[u8; CANONICAL_FIELD_LEN]> = auth_path_vecs
            .into_iter()
            .map(|v| {
                v.try_into().map_err(|_| {
                    anyhow!("each auth_path sibling must be {CANONICAL_FIELD_LEN} bytes")
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let reporter: Box<dyn voting::ProofProgressReporter> = match progress_callback {
            Some(cb) => Box::new(ProgressBridge {
                callback: cb,
                context: *progress_context,
            }),
            None => Box::new(voting::NoopProgressReporter),
        };

        let bundle = handle
            .db
            .build_vote_commitment(
                &round_id_str,
                bundle_index,
                seed,
                network_id,
                proposal_id,
                choice,
                num_options,
                &auth_path,
                van_position,
                anchor_height,
                single_share != 0,
                reporter.as_ref(),
            )
            .map_err(|e| anyhow!("build_vote_commitment failed: {}", e))?;

        let json_bundle: JsonVoteCommitmentBundle = bundle.into();
        json_to_boxed_slice(&json_bundle)
    });
    unwrap_exc_or_null(res)
}

/// Build share payloads for delegated share submission.
///
/// `commitment_json` is the JSON-encoded `VoteCommitmentBundle` returned by
/// `zcashlc_voting_build_vote_commitment`. Its `enc_shares` field is extracted
/// to wire-share form before reconstructing the core commitment, ensuring
/// helper payloads are built from the ciphertexts committed by the vote proof.
///
/// Returns JSON-encoded `Vec<SharePayload>` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - For every `(ptr, len)` byte argument, if `len > 0` then `ptr` must be
///   non-null and valid for reads for `len` bytes; if `len == 0`, `ptr` is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_build_share_payloads(
    db: *mut VotingDatabaseHandle,
    commitment_json: *const u8,
    commitment_json_len: usize,
    vote_decision: u32,
    num_options: u32,
    vc_tree_position: u64,
    single_share: u8,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;

        let commitment_bytes = unsafe { bytes_from_ptr(commitment_json, commitment_json_len) }?;
        let json_commitment: JsonVoteCommitmentBundle = serde_json::from_slice(commitment_bytes)?;
        if json_commitment.enc_shares.is_empty() {
            return Err(anyhow!("commitment enc_shares must not be empty"));
        }
        let wire_shares: Vec<voting::WireEncryptedShare> = json_commitment
            .enc_shares
            .iter()
            .cloned()
            .map(Into::into)
            .collect();
        let core_commitment = json_commitment.into_core_without_encrypted_shares();

        let payloads = handle
            .db
            .build_share_payloads(
                &wire_shares,
                &core_commitment,
                vote_decision,
                num_options,
                vc_tree_position,
                single_share != 0,
            )
            .map_err(|e| anyhow!("build_share_payloads failed: {}", e))?;

        let json_payloads: Vec<JsonSharePayload> = payloads.into_iter().map(Into::into).collect();
        json_to_boxed_slice(&json_payloads)
    });
    unwrap_exc_or_null(res)
}

/// Mark a vote as submitted for a specific proposal and bundle.
///
/// Returns 0 on success, or -1 on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - For the `(round_id, round_id_len)` byte argument, if `round_id_len > 0`
///   then `round_id` must be non-null and valid for reads for `round_id_len`
///   bytes; if `round_id_len == 0`, `round_id` is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_mark_vote_submitted(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    proposal_id: u32,
) -> i32 {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;

        handle
            .db
            .mark_vote_submitted(&round_id_str, bundle_index, proposal_id)
            .map_err(|e| anyhow!("mark_vote_submitted failed: {}", e))?;
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}

/// Sign a cast-vote transaction.
///
/// Takes fields from `VoteCommitmentBundle` plus the hotkey seed and computes
/// the spend authorization signature.
/// `vote_round_id_hex` must encode exactly 32 bytes as ASCII hex. `r_vpk_bytes`,
/// `van_nullifier`, `vote_authority_note_new`, `vote_commitment`, and
/// `alpha_v` must each be exactly 32 bytes.
///
/// Returns JSON-encoded `CastVoteSignature` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - For every `(ptr, len)` byte argument, if `len > 0` then `ptr` must be
///   non-null and valid for reads for `len` bytes; if `len == 0`, `ptr` is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_sign_cast_vote(
    hotkey_seed: *const u8,
    hotkey_seed_len: usize,
    network_id: u32,
    vote_round_id_hex: *const u8,
    vote_round_id_hex_len: usize,
    r_vpk_bytes: *const u8,
    r_vpk_bytes_len: usize,
    van_nullifier: *const u8,
    van_nullifier_len: usize,
    vote_authority_note_new: *const u8,
    vote_authority_note_new_len: usize,
    vote_commitment: *const u8,
    vote_commitment_len: usize,
    proposal_id: u32,
    anchor_height: u32,
    alpha_v: *const u8,
    alpha_v_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    let res = catch_panic(|| {
        let seed = unsafe { bytes_from_ptr(hotkey_seed, hotkey_seed_len) }?;
        require_min_seed_len(seed, "hotkey_seed")?;
        let round_id = unsafe { str_from_ptr(vote_round_id_hex, vote_round_id_hex_len) }?;
        let r_vpk = unsafe { bytes_from_ptr(r_vpk_bytes, r_vpk_bytes_len) }?;
        let van_nf = unsafe { bytes_from_ptr(van_nullifier, van_nullifier_len) }?;
        let van_new =
            unsafe { bytes_from_ptr(vote_authority_note_new, vote_authority_note_new_len) }?;
        let vc = unsafe { bytes_from_ptr(vote_commitment, vote_commitment_len) }?;
        let alpha = unsafe { bytes_from_ptr(alpha_v, alpha_v_len) }?;

        if round_id.len() != VOTE_ROUND_ID_HEX_LEN {
            return Err(anyhow!(
                "vote_round_id_hex must be {} hex characters, got {}",
                VOTE_ROUND_ID_HEX_LEN,
                round_id.len()
            ));
        }
        require_ascii_hex(&round_id, "vote_round_id_hex")?;
        require_32_bytes(r_vpk, "r_vpk_bytes")?;
        require_32_bytes(van_nf, "van_nullifier")?;
        require_32_bytes(van_new, "vote_authority_note_new")?;
        require_32_bytes(vc, "vote_commitment")?;
        require_32_bytes(alpha, "alpha_v")?;

        let sig = voting::vote_commitment::sign_cast_vote(
            seed,
            network_id,
            &round_id,
            r_vpk,
            van_nf,
            van_new,
            vc,
            proposal_id,
            anchor_height,
            alpha,
        )
        .map_err(|e| anyhow!("sign_cast_vote failed: {}", e))?;

        let json_sig: JsonCastVoteSignature = sig.into();
        json_to_boxed_slice(&json_sig)
    });
    unwrap_exc_or_null(res)
}

fn require_32_bytes(bytes: &[u8], name: &str) -> anyhow::Result<()> {
    if bytes.len() != CANONICAL_FIELD_LEN {
        return Err(anyhow!(
            "{} must be {} bytes, got {}",
            name,
            CANONICAL_FIELD_LEN,
            bytes.len()
        ));
    }
    Ok(())
}

fn require_min_seed_len(bytes: &[u8], name: &str) -> anyhow::Result<()> {
    if bytes.len() < MIN_SEED_LEN {
        return Err(anyhow!(
            "{} must be at least {} bytes, got {}",
            name,
            MIN_SEED_LEN,
            bytes.len()
        ));
    }
    Ok(())
}

fn require_ascii_hex(value: &str, name: &str) -> anyhow::Result<()> {
    if value.len() % 2 != 0 {
        return Err(anyhow!(
            "{name} must contain an even number of hex characters"
        ));
    }
    if !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("{name} must contain only ASCII hex characters"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ffi::zcashlc_free_boxed_slice;
    use crate::voting::db::zcashlc_voting_db_free;
    use crate::voting::test_helpers::{insert_round_and_bundle, open_memory_db};
    use pasta_curves::{
        group::{Group, GroupEncoding},
        pallas,
    };
    use serde::de::DeserializeOwned;

    fn decode_boxed_json<T: DeserializeOwned>(ptr: *mut crate::ffi::BoxedSlice) -> T {
        assert!(!ptr.is_null());
        let json = unsafe { (*ptr).as_slice() }.to_vec();
        let value = serde_json::from_slice(&json).expect("decode boxed JSON");
        unsafe { zcashlc_free_boxed_slice(ptr) };
        value
    }

    fn insert_round_with_valid_ea_pk(db: *mut VotingDatabaseHandle, round_id: &str) {
        let handle = unsafe { db.as_ref() }.expect("voting db handle");
        let params = voting::VotingRoundParams {
            vote_round_id: round_id.to_string(),
            snapshot_height: 123,
            ea_pk: pallas::Point::generator().to_bytes().to_vec(),
            nc_root: vec![8u8; 32],
            nullifier_imt_root: vec![9u8; 32],
        };
        handle.db.init_round(&params, None).expect("insert round");
    }

    #[test]
    fn vote_database_ffi_rejects_null_db() {
        let round = b"round";
        let json = b"[]";
        let bytes = [0u8; CANONICAL_FIELD_LEN];

        assert!(
            unsafe {
                zcashlc_voting_encrypt_shares(
                    std::ptr::null_mut(),
                    round.as_ptr(),
                    round.len(),
                    json.as_ptr(),
                    json.len(),
                )
            }
            .is_null()
        );

        assert!(
            unsafe {
                zcashlc_voting_build_vote_commitment(
                    std::ptr::null_mut(),
                    round.as_ptr(),
                    round.len(),
                    0,
                    bytes.as_ptr(),
                    bytes.len(),
                    0,
                    1,
                    0,
                    2,
                    json.as_ptr(),
                    json.len(),
                    0,
                    0,
                    None,
                    std::ptr::null_mut(),
                    0,
                )
            }
            .is_null()
        );

        assert!(
            unsafe {
                zcashlc_voting_build_share_payloads(
                    std::ptr::null_mut(),
                    json.as_ptr(),
                    json.len(),
                    0,
                    2,
                    0,
                    0,
                )
            }
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
                )
            },
            -1
        );
    }

    #[test]
    fn vote_database_ffi_rejects_malformed_json_inputs() {
        let db = open_memory_db();
        let round = b"round";
        let invalid_json = b"not json";
        let seed = [0x42u8; 64];

        let malformed_shares_result = unsafe {
            zcashlc_voting_encrypt_shares(
                db,
                round.as_ptr(),
                round.len(),
                invalid_json.as_ptr(),
                invalid_json.len(),
            )
        };

        let malformed_auth_path_result = unsafe {
            zcashlc_voting_build_vote_commitment(
                db,
                round.as_ptr(),
                round.len(),
                0,
                seed.as_ptr(),
                seed.len(),
                0,
                1,
                0,
                2,
                invalid_json.as_ptr(),
                invalid_json.len(),
                0,
                0,
                None,
                std::ptr::null_mut(),
                0,
            )
        };

        let malformed_commitment_result = unsafe {
            zcashlc_voting_build_share_payloads(
                db,
                invalid_json.as_ptr(),
                invalid_json.len(),
                0,
                2,
                0,
                0,
            )
        };

        unsafe { zcashlc_voting_db_free(db) };
        assert!(
            malformed_shares_result.is_null(),
            "malformed shares_json must be rejected"
        );
        assert!(
            malformed_auth_path_result.is_null(),
            "malformed van_auth_path_json must be rejected"
        );
        assert!(
            malformed_commitment_result.is_null(),
            "malformed commitment_json must be rejected"
        );
    }

    #[test]
    fn encrypt_shares_returns_encrypted_shares() {
        let db = open_memory_db();
        let round = b"round";
        insert_round_with_valid_ea_pk(db, "round");
        let shares_json = serde_json::to_vec(&vec![1u64, 4]).expect("serialize shares");

        let result = unsafe {
            zcashlc_voting_encrypt_shares(
                db,
                round.as_ptr(),
                round.len(),
                shares_json.as_ptr(),
                shares_json.len(),
            )
        };
        let shares: Vec<JsonWireEncryptedShare> = decode_boxed_json(result);

        unsafe { zcashlc_voting_db_free(db) };
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].share_index, 0);
        assert_eq!(shares[1].share_index, 1);
        assert_eq!(shares[0].c1.len(), CANONICAL_FIELD_LEN);
        assert_eq!(shares[0].c2.len(), CANONICAL_FIELD_LEN);
        assert_eq!(shares[1].c1.len(), CANONICAL_FIELD_LEN);
        assert_eq!(shares[1].c2.len(), CANONICAL_FIELD_LEN);
    }

    #[test]
    fn mark_vote_submitted_rejects_missing_vote_row() {
        let db = open_memory_db();
        let round = b"round";

        let result =
            unsafe { zcashlc_voting_mark_vote_submitted(db, round.as_ptr(), round.len(), 0, 1) };

        unsafe { zcashlc_voting_db_free(db) };
        assert_eq!(result, -1);
    }

    #[test]
    fn mark_vote_submitted_marks_existing_vote_row() {
        let db = open_memory_db();
        let round = b"round";
        insert_round_and_bundle(db, "round");
        let handle = unsafe { db.as_ref() }.expect("voting db handle");
        handle
            .db
            .insert_vote_fixture("round", 0, 1, 2, &[0xaa; 32])
            .expect("insert vote");

        let result =
            unsafe { zcashlc_voting_mark_vote_submitted(db, round.as_ptr(), round.len(), 0, 1) };
        let votes = handle.db.get_votes("round").expect("get votes");

        unsafe { zcashlc_voting_db_free(db) };
        assert_eq!(result, 0);
        assert_eq!(votes.len(), 1);
        assert_eq!(votes[0].bundle_index, 0);
        assert_eq!(votes[0].proposal_id, 1);
        assert_eq!(votes[0].choice, 2);
        assert!(votes[0].submitted);
    }

    #[test]
    fn build_vote_commitment_rejects_wrong_sized_auth_path_sibling() {
        let db = open_memory_db();
        let round = b"round";
        let seed = [0x42u8; 64];
        let auth_path_json =
            serde_json::to_vec(&vec![vec![0u8; CANONICAL_FIELD_LEN - 1]]).expect("auth path json");

        let result = unsafe {
            zcashlc_voting_build_vote_commitment(
                db,
                round.as_ptr(),
                round.len(),
                0,
                seed.as_ptr(),
                seed.len(),
                0,
                1,
                0,
                2,
                auth_path_json.as_ptr(),
                auth_path_json.len(),
                0,
                0,
                None,
                std::ptr::null_mut(),
                0,
            )
        };

        unsafe { zcashlc_voting_db_free(db) };
        assert!(result.is_null());
    }

    #[test]
    fn build_vote_commitment_rejects_short_seed() {
        let db = open_memory_db();
        let round = b"round";
        let seed = b"short";
        let auth_path_json = b"[]";

        let result = unsafe {
            zcashlc_voting_build_vote_commitment(
                db,
                round.as_ptr(),
                round.len(),
                0,
                seed.as_ptr(),
                seed.len(),
                0,
                1,
                0,
                2,
                auth_path_json.as_ptr(),
                auth_path_json.len(),
                0,
                0,
                None,
                std::ptr::null_mut(),
                0,
            )
        };

        unsafe { zcashlc_voting_db_free(db) };
        assert!(result.is_null());
    }

    #[test]
    fn sign_cast_vote_rejects_short_seed() {
        let seed = b"short";
        let round_id_hex = b"0000000000000000000000000000000000000000000000000000000000000000";
        let bytes = [0u8; CANONICAL_FIELD_LEN];

        let result = unsafe {
            zcashlc_voting_sign_cast_vote(
                seed.as_ptr(),
                seed.len(),
                0,
                round_id_hex.as_ptr(),
                round_id_hex.len(),
                bytes.as_ptr(),
                bytes.len(),
                bytes.as_ptr(),
                bytes.len(),
                bytes.as_ptr(),
                bytes.len(),
                bytes.as_ptr(),
                bytes.len(),
                1,
                0,
                bytes.as_ptr(),
                bytes.len(),
            )
        };

        assert!(result.is_null());
    }

    fn call_sign_cast_vote(
        round_id_hex: &[u8],
        r_vpk: &[u8],
        van_nullifier: &[u8],
        vote_authority_note_new: &[u8],
        vote_commitment: &[u8],
        alpha_v: &[u8],
    ) -> *mut crate::ffi::BoxedSlice {
        let seed = [0x42u8; 64];
        unsafe {
            zcashlc_voting_sign_cast_vote(
                seed.as_ptr(),
                seed.len(),
                0,
                round_id_hex.as_ptr(),
                round_id_hex.len(),
                r_vpk.as_ptr(),
                r_vpk.len(),
                van_nullifier.as_ptr(),
                van_nullifier.len(),
                vote_authority_note_new.as_ptr(),
                vote_authority_note_new.len(),
                vote_commitment.as_ptr(),
                vote_commitment.len(),
                1,
                0,
                alpha_v.as_ptr(),
                alpha_v.len(),
            )
        }
    }

    #[test]
    fn sign_cast_vote_returns_signature_for_valid_inputs() {
        let round_id_hex = b"0000000000000000000000000000000000000000000000000000000000000000";
        let bytes = [0u8; CANONICAL_FIELD_LEN];

        let result = call_sign_cast_vote(round_id_hex, &bytes, &bytes, &bytes, &bytes, &bytes);
        let signature: JsonCastVoteSignature = decode_boxed_json(result);

        assert_eq!(signature.vote_auth_sig.len(), 64);
    }

    #[test]
    fn sign_cast_vote_rejects_short_canonical_fields() {
        let round_id_hex = b"0000000000000000000000000000000000000000000000000000000000000000";
        let bytes = [0u8; CANONICAL_FIELD_LEN];
        let short = [0u8; CANONICAL_FIELD_LEN - 1];

        assert!(
            call_sign_cast_vote(b"00", &bytes, &bytes, &bytes, &bytes, &bytes).is_null(),
            "short round_id_hex must be rejected"
        );
        assert!(
            call_sign_cast_vote(round_id_hex, &short, &bytes, &bytes, &bytes, &bytes).is_null(),
            "short r_vpk_bytes must be rejected"
        );
        assert!(
            call_sign_cast_vote(round_id_hex, &bytes, &short, &bytes, &bytes, &bytes).is_null(),
            "short van_nullifier must be rejected"
        );
        assert!(
            call_sign_cast_vote(round_id_hex, &bytes, &bytes, &short, &bytes, &bytes).is_null(),
            "short vote_authority_note_new must be rejected"
        );
        assert!(
            call_sign_cast_vote(round_id_hex, &bytes, &bytes, &bytes, &short, &bytes).is_null(),
            "short vote_commitment must be rejected"
        );
        assert!(
            call_sign_cast_vote(round_id_hex, &bytes, &bytes, &bytes, &bytes, &short).is_null(),
            "short alpha_v must be rejected"
        );
    }

    #[test]
    fn sign_cast_vote_rejects_long_canonical_fields() {
        let round_id_hex = b"0000000000000000000000000000000000000000000000000000000000000000";
        let bytes = [0u8; CANONICAL_FIELD_LEN];
        let long = [0u8; CANONICAL_FIELD_LEN + 1];

        assert!(
            call_sign_cast_vote(
                b"000000000000000000000000000000000000000000000000000000000000000000",
                &bytes,
                &bytes,
                &bytes,
                &bytes,
                &bytes,
            )
            .is_null(),
            "long round_id_hex must be rejected"
        );
        assert!(
            call_sign_cast_vote(round_id_hex, &bytes, &bytes, &bytes, &long, &bytes).is_null(),
            "long vote_commitment must be rejected"
        );
    }

    #[test]
    fn sign_cast_vote_rejects_non_hex_round_id() {
        let round_id_hex = b"000000000000000000000000000000000000000000000000000000000000000g";
        let bytes = [0u8; CANONICAL_FIELD_LEN];

        assert!(
            call_sign_cast_vote(round_id_hex, &bytes, &bytes, &bytes, &bytes, &bytes).is_null(),
            "non-hex round_id_hex must be rejected"
        );
    }

    #[test]
    fn require_ascii_hex_rejects_odd_length() {
        assert!(require_ascii_hex("abc", "test_hex").is_err());
    }

    #[test]
    fn build_share_payloads_rejects_commitment_without_bound_shares() {
        let db = open_memory_db();
        let commitment = JsonVoteCommitmentBundle {
            van_nullifier: vec![0u8; 32],
            vote_authority_note_new: vec![1u8; 32],
            vote_commitment: vec![2u8; 32],
            proposal_id: 1,
            proof: vec![3u8; 32],
            enc_shares: Vec::new(),
            anchor_height: 10,
            vote_round_id: "round".to_string(),
            shares_hash: vec![4u8; 32],
            share_blinds: vec![vec![5u8; 32]],
            share_comms: vec![vec![6u8; 32]],
            r_vpk_bytes: vec![7u8; 32],
            alpha_v: vec![8u8; 32],
        };
        let json = serde_json::to_vec(&commitment).expect("serialize commitment");

        let result = unsafe {
            zcashlc_voting_build_share_payloads(db, json.as_ptr(), json.len(), 0, 2, 0, 0)
        };

        unsafe { zcashlc_voting_db_free(db) };
        assert!(result.is_null());
    }

    #[test]
    fn build_share_payloads_returns_payloads_for_bound_shares() {
        let db = open_memory_db();
        let commitment = JsonVoteCommitmentBundle {
            van_nullifier: vec![0u8; 32],
            vote_authority_note_new: vec![1u8; 32],
            vote_commitment: vec![2u8; 32],
            proposal_id: 1,
            proof: vec![3u8; 32],
            enc_shares: vec![
                JsonWireEncryptedShare {
                    c1: vec![0xc1; 32],
                    c2: vec![0xc2; 32],
                    share_index: 0,
                },
                JsonWireEncryptedShare {
                    c1: vec![0xd1; 32],
                    c2: vec![0xd2; 32],
                    share_index: 1,
                },
            ],
            anchor_height: 10,
            vote_round_id: "round".to_string(),
            shares_hash: vec![4u8; 32],
            share_blinds: vec![vec![5u8; 32], vec![6u8; 32]],
            share_comms: vec![vec![7u8; 32], vec![8u8; 32]],
            r_vpk_bytes: vec![9u8; 32],
            alpha_v: vec![10u8; 32],
        };
        let json = serde_json::to_vec(&commitment).expect("serialize commitment");

        let result = unsafe {
            zcashlc_voting_build_share_payloads(db, json.as_ptr(), json.len(), 1, 2, 42, 0)
        };
        let payloads: Vec<JsonSharePayload> = decode_boxed_json(result);

        unsafe { zcashlc_voting_db_free(db) };
        assert_eq!(payloads.len(), 2);
        assert_eq!(payloads[0].proposal_id, 1);
        assert_eq!(payloads[0].vote_decision, 1);
        assert_eq!(payloads[0].tree_position, 42);
        assert_eq!(payloads[0].enc_share.share_index, 0);
        assert_eq!(payloads[1].enc_share.share_index, 1);
        assert_eq!(payloads[0].all_enc_shares.len(), 2);
        assert_eq!(payloads[0].primary_blind, vec![5u8; 32]);
        assert_eq!(payloads[1].primary_blind, vec![6u8; 32]);
    }
}
