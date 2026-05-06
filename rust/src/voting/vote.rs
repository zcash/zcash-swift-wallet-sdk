use std::panic::AssertUnwindSafe;

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
use zcash_voting as voting;

use crate::{unwrap_exc_or, unwrap_exc_or_null};

use super::db::VotingDatabaseHandle;
use super::helpers::{bytes_from_ptr, json_to_boxed_slice, str_from_ptr};
use super::json::{
    JsonCastVoteSignature, JsonSharePayload, JsonVoteCommitmentBundle, JsonWireEncryptedShare,
};
use super::progress::ProgressBridge;

// =============================================================================
// VotingDatabase methods — Voting
// =============================================================================

/// Encrypt voting shares for a round.
///
/// `shares_json` is a JSON-encoded `Vec<u64>`.
///
/// Returns JSON-encoded `Vec<EncryptedShare>` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
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
        let shares_bytes = unsafe { bytes_from_ptr(shares_json, shares_json_len) };
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

/// Build a vote commitment (ZKP #2) for a proposal.
///
/// `van_auth_path_json` is a JSON-encoded `Vec<Vec<u8>>` (each element is 32 bytes).
///
/// Returns JSON-encoded `VoteCommitmentBundle` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - `progress_callback` must be a valid function pointer (or null to skip progress).
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
        let seed = unsafe { bytes_from_ptr(hotkey_seed, hotkey_seed_len) };
        let auth_path_bytes = unsafe { bytes_from_ptr(van_auth_path_json, van_auth_path_json_len) };
        let auth_path_vecs: Vec<Vec<u8>> = serde_json::from_slice(auth_path_bytes)?;
        let auth_path: Vec<[u8; 32]> = auth_path_vecs
            .into_iter()
            .map(|v| {
                v.try_into()
                    .map_err(|_| anyhow!("each auth_path sibling must be 32 bytes"))
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
/// `enc_shares_json` is JSON-encoded `Vec<WireEncryptedShare>`.
/// `commitment_json` is JSON-encoded `VoteCommitmentBundle`.
///
/// Returns JSON-encoded `Vec<SharePayload>` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_build_share_payloads(
    db: *mut VotingDatabaseHandle,
    enc_shares_json: *const u8,
    enc_shares_json_len: usize,
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

        let shares_bytes = unsafe { bytes_from_ptr(enc_shares_json, enc_shares_json_len) };
        let json_shares: Vec<JsonWireEncryptedShare> = serde_json::from_slice(shares_bytes)?;
        let wire_shares: Vec<voting::WireEncryptedShare> =
            json_shares.into_iter().map(Into::into).collect();

        let commitment_bytes = unsafe { bytes_from_ptr(commitment_json, commitment_json_len) };
        let json_commitment: JsonVoteCommitmentBundle = serde_json::from_slice(commitment_bytes)?;
        let core_commitment: voting::VoteCommitmentBundle = json_commitment.into();

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

/// Mark a vote as submitted for a specific proposal/bundle.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
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
/// Takes fields from `VoteCommitmentBundle` plus hotkey seed and computes
/// the spend auth signature.
///
/// Returns JSON-encoded `CastVoteSignature` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - All pointer/length pairs must be valid.
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
        let seed = unsafe { bytes_from_ptr(hotkey_seed, hotkey_seed_len) };
        let round_id = unsafe { str_from_ptr(vote_round_id_hex, vote_round_id_hex_len) }?;
        let r_vpk = unsafe { bytes_from_ptr(r_vpk_bytes, r_vpk_bytes_len) };
        let van_nf = unsafe { bytes_from_ptr(van_nullifier, van_nullifier_len) };
        let van_new =
            unsafe { bytes_from_ptr(vote_authority_note_new, vote_authority_note_new_len) };
        let vc = unsafe { bytes_from_ptr(vote_commitment, vote_commitment_len) };
        let alpha = unsafe { bytes_from_ptr(alpha_v, alpha_v_len) };

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
