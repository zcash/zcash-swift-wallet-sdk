use std::ffi::CString;
use std::fmt::Write as _;
use std::os::raw::c_char;
use std::panic::AssertUnwindSafe;

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
use serde::{Deserialize, Serialize};
use zcash_voting as voting;

use crate::{unwrap_exc_or, unwrap_exc_or_null};

use super::constants::CANONICAL_FIELD_LEN;
use super::db::VotingDatabaseHandle;
use super::helpers::{bytes_from_ptr, json_to_boxed_slice, str_from_ptr};

/// JSON representation for share delegation records crossing the FFI boundary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonShareDelegationRecord {
    pub round_id: String,
    pub bundle_index: u32,
    pub proposal_id: u32,
    pub share_index: u32,
    pub sent_to_urls: Vec<String>,
    /// Hex-encoded share reveal nullifier, matching
    /// `zcashlc_voting_compute_share_nullifier`.
    pub nullifier: String,
    pub confirmed: bool,
    pub submit_at: u64,
    pub created_at: u64,
}

impl From<voting::ShareDelegationRecord> for JsonShareDelegationRecord {
    fn from(r: voting::ShareDelegationRecord) -> Self {
        Self {
            round_id: r.round_id,
            bundle_index: r.bundle_index,
            proposal_id: r.proposal_id,
            share_index: r.share_index,
            sent_to_urls: r.sent_to_urls,
            nullifier: bytes_to_hex(&r.nullifier),
            confirmed: r.confirmed,
            submit_at: r.submit_at,
            created_at: r.created_at,
        }
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut hex, "{b:02x}").expect("writing to a String cannot fail");
    }
    hex
}

/// Compute the share reveal nullifier from client-known inputs.
///
/// Returns the 32-byte nullifier as a hex string (64 chars), or null on error.
///
/// # Safety
///
/// - `vote_commitment` must point to exactly 32 bytes.
/// - `primary_blind` must point to exactly 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_compute_share_nullifier(
    vote_commitment: *const u8,
    primary_blind: *const u8,
    share_index: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let vc: [u8; CANONICAL_FIELD_LEN] =
            unsafe { std::slice::from_raw_parts(vote_commitment, CANONICAL_FIELD_LEN) }
                .try_into()
                .map_err(|_| {
                    anyhow!("vote_commitment must be exactly {CANONICAL_FIELD_LEN} bytes")
                })?;
        let blind: [u8; CANONICAL_FIELD_LEN] =
            unsafe { std::slice::from_raw_parts(primary_blind, CANONICAL_FIELD_LEN) }
                .try_into()
                .map_err(|_| {
                    anyhow!("primary_blind must be exactly {CANONICAL_FIELD_LEN} bytes")
                })?;

        let nullifier = voting::share::compute_nullifier(&vc, share_index, &blind)
            .map_err(|e| anyhow!("compute_share_nullifier failed: {}", e))?;

        let hex_str = bytes_to_hex(&nullifier);
        let c_str = CString::new(hex_str).map_err(|e| anyhow!("null byte in hex string: {}", e))?;
        Ok(c_str.into_raw())
    });
    unwrap_exc_or_null(res)
}

/// Record a share delegation after sending to helper servers.
///
/// The share's nullifier is derived internally from the round's recovery state
/// rather than supplied by the caller, so a caller cannot record a nullifier
/// that disagrees with the share it belongs to.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - String params must be valid UTF-8 pointers with correct lengths.
/// - `sent_to_urls_json` must be a JSON array of strings.
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
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let urls_bytes = unsafe { bytes_from_ptr(sent_to_urls_json, sent_to_urls_json_len) }?;
        let sent_to_urls: Vec<String> = serde_json::from_slice(urls_bytes)?;

        voting::share::record(
            &handle.db,
            &round_id_str,
            bundle_index,
            proposal_id,
            share_index,
            &sent_to_urls,
            submit_at,
        )
        .map_err(|e| anyhow!("share::record failed: {}", e))?;
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}

/// Get all share delegations for a round.
///
/// Returns a JSON array of `JsonShareDelegationRecord`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_share_delegations(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;

        let records = handle
            .db
            .get_share_delegations(&round_id_str)
            .map_err(|e| anyhow!("get_share_delegations failed: {}", e))?;

        let json_records: Vec<JsonShareDelegationRecord> =
            records.into_iter().map(Into::into).collect();
        json_to_boxed_slice(&json_records)
    });
    unwrap_exc_or_null(res)
}

/// Get unconfirmed share delegations for a round.
///
/// Returns a JSON array of `JsonShareDelegationRecord`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_unconfirmed_delegations(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;

        let records = handle
            .db
            .get_unconfirmed_delegations(&round_id_str)
            .map_err(|e| anyhow!("get_unconfirmed_delegations failed: {}", e))?;

        let json_records: Vec<JsonShareDelegationRecord> =
            records.into_iter().map(Into::into).collect();
        json_to_boxed_slice(&json_records)
    });
    unwrap_exc_or_null(res)
}

/// Mark a share delegation as confirmed on-chain.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_mark_share_confirmed(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    proposal_id: u32,
    share_index: u32,
) -> i32 {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;

        handle
            .db
            .mark_share_confirmed(&round_id_str, bundle_index, proposal_id, share_index)
            .map_err(|e| anyhow!("mark_share_confirmed failed: {}", e))?;
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}

/// Append new server URLs to a share delegation's `sent_to_urls`.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - `new_urls_json` must be a JSON array of strings.
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
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let urls_bytes = unsafe { bytes_from_ptr(new_urls_json, new_urls_json_len) }?;
        let new_urls: Vec<String> = serde_json::from_slice(urls_bytes)?;

        handle
            .db
            .add_sent_servers(
                &round_id_str,
                bundle_index,
                proposal_id,
                share_index,
                &new_urls,
            )
            .map_err(|e| anyhow!("add_sent_servers failed: {}", e))?;
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}

/// Rebuild one helper-server share payload as the crate's own wire JSON.
///
/// Thin passthrough to `zcash_voting::share::recover_wire_json`: the crate
/// parses the persisted recovery bundle, selects the requested share, binds the
/// confirmed vote-commitment-tree position and the scheduled submission time
/// into it, and serializes the result with its own `VoteShareWire` codec. No
/// second commit happens, and the FFI shapes nothing: the returned bytes are
/// the helper payload verbatim.
///
/// `commitment_bundle_json` is the recovery JSON previously read with
/// `zcashlc_voting_get_commitment_bundle`.
///
/// Returns the UTF-8 wire JSON as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - If `commitment_bundle_json_len > 0` then `commitment_bundle_json` must be
///   non-null and valid for reads for that many bytes; if it is `0`, the pointer
///   is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_recover_wire_json(
    commitment_bundle_json: *const u8,
    commitment_bundle_json_len: usize,
    proposal_id: u32,
    share_index: u32,
    vc_tree_position: u64,
    submit_at: u64,
) -> *mut crate::ffi::BoxedSlice {
    let res = catch_panic(|| {
        let bundle_json =
            unsafe { str_from_ptr(commitment_bundle_json, commitment_bundle_json_len) }?;

        let wire_json = voting::share::recover_wire_json(
            &bundle_json,
            proposal_id,
            share_index,
            vc_tree_position,
            submit_at,
        )
        .map_err(|e| anyhow!("recover_wire_json failed: {}", e))?;

        Ok(crate::ffi::BoxedSlice::some(wire_json.into_bytes()))
    });
    unwrap_exc_or_null(res)
}

/// List the share indices recoverable from a persisted vote recovery bundle.
///
/// Thin passthrough to `zcash_voting::vote::parse_recovery` +
/// `zcash_voting::share::recover_payloads`: the crate parses the bundle and
/// applies its own single-share slicing (one share when `single_share`, all
/// of them otherwise), and this wrapper reads off each recovered payload's
/// `enc_share.share_index`. Crash recovery uses this list instead of guessing
/// a share count from `single_share` alone (`singleShare ? 1 : numOptions`),
/// so a caller-side guess can never under- or over-deliver relative to what
/// the crate actually reconstructs.
///
/// `commitment_bundle_json` is the recovery JSON previously read with
/// `zcashlc_voting_get_commitment_bundle`.
///
/// Returns a JSON array of `u32` share indices as `*mut FfiBoxedSlice`, or
/// null on error.
///
/// # Safety
///
/// - If `commitment_bundle_json_len > 0` then `commitment_bundle_json` must be
///   non-null and valid for reads for that many bytes; if it is `0`, the pointer
///   is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_recoverable_share_indices(
    commitment_bundle_json: *const u8,
    commitment_bundle_json_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    let res = catch_panic(|| {
        let bundle_json =
            unsafe { str_from_ptr(commitment_bundle_json, commitment_bundle_json_len) }?;

        let bundle = voting::vote::parse_recovery(&bundle_json)
            .map_err(|e| anyhow!("parse_recovery failed: {}", e))?;
        let payloads = voting::share::recover_payloads(&bundle)
            .map_err(|e| anyhow!("recover_payloads failed: {}", e))?;

        let indices: Vec<u32> = payloads
            .into_iter()
            .map(|payload| payload.enc_share.share_index)
            .collect();

        json_to_boxed_slice(&indices)
    });
    unwrap_exc_or_null(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::zcashlc_free_boxed_slice;
    use crate::voting::db::zcashlc_voting_db_free;
    use crate::voting::test_helpers::{insert_round_and_bundle, open_memory_db};

    // A test asserting that an invalid caller-supplied nullifier is rejected
    // used to live here. `share::record` now derives the nullifier from the
    // round's recovery state, so callers cannot supply one at all and there is
    // no longer a malformed-input case to exercise.

    // The former round-trip test asserted that a caller-supplied hex nullifier
    // came back unchanged. `share::record` now derives the nullifier from the
    // vote's persisted recovery bundle, which only a real `vote::commit` writes
    // — `zcash_voting` exposes a public reader for that bundle but no writer.
    // A successful record therefore cannot be staged from a unit test, so the
    // boundary that remains testable is the failure below.

    #[test]
    fn record_share_delegation_rejects_a_vote_that_was_never_committed() {
        let db = open_memory_db();
        let round_id = b"round";
        insert_round_and_bundle(db, "round");
        let urls_json = br#"["https://helper.example"]"#;

        // The round and bundle exist, but no vote has been committed for them,
        // so there is no recovery bundle to derive a share nullifier from.
        // Recording must fail rather than persist a share with no provenance.
        let code = unsafe {
            zcashlc_voting_record_share_delegation(
                db,
                round_id.as_ptr(),
                round_id.len(),
                0,
                0,
                0,
                urls_json.as_ptr(),
                urls_json.len(),
                0,
            )
        };
        assert_eq!(code, -1);

        let result =
            unsafe { zcashlc_voting_get_share_delegations(db, round_id.as_ptr(), round_id.len()) };
        assert!(!result.is_null());
        let json = unsafe { (*result).as_slice() }.to_vec();
        let records: Vec<JsonShareDelegationRecord> =
            serde_json::from_slice(&json).expect("share delegation records");
        assert!(
            records.is_empty(),
            "a rejected record must not leave a partial row behind"
        );

        unsafe { zcashlc_free_boxed_slice(result) };
        unsafe { zcashlc_voting_db_free(db) };
    }

    fn field_bytes(value: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = value;
        bytes
    }

    /// Build a `VoteRecoveryBundle` whose encrypted shares carry exactly
    /// `share_indices`, in that order — mirroring `zcash_voting`'s own
    /// `share.rs` fixture, generalized so both the single-share and
    /// multi-share cases below can reuse it.
    fn recovery_bundle_with_share_indices(
        single_share: bool,
        share_indices: &[u32],
    ) -> voting::vote::VoteRecoveryBundle {
        let encrypted_shares: Vec<voting::types::EncryptedShare> = share_indices
            .iter()
            .enumerate()
            .map(|(i, &share_index)| voting::types::EncryptedShare {
                c1: vec![0x21 + i as u8; 32],
                c2: vec![0x22 + i as u8; 32],
                share_index,
                plaintext_value: 5,
                randomness: vec![0x23 + i as u8; 32],
            })
            .collect();
        let share_blinds: Vec<[u8; 32]> = (0..encrypted_shares.len())
            .map(|i| field_bytes(1 + i as u8))
            .collect();
        let share_comms: Vec<[u8; 32]> = (0..encrypted_shares.len())
            .map(|i| [0x51 + i as u8; 32])
            .collect();

        // Canonical 64-char lowercase-hex round id, matching the crate's own
        // `share.rs` fixture: since 3.0.0-rc.3, `serialize_recovery` and
        // `parse_recovery` validate `vote_round_id` as a canonical Pallas
        // field element, so a placeholder like "round1" no longer round-trips.
        voting::vote::VoteRecoveryBundle {
            vote_round_id: "01".repeat(32),
            bundle_index: 0,
            proposal_id: 1,
            vote_decision: 2,
            anchor_height: 123,
            vc_tree_position: 456,
            single_share,
            num_options: 4,
            van_nullifier: [0x10; 32],
            vote_authority_note_new: [0x11; 32],
            vote_commitment: [0x12; 32],
            proof: vec![0x13; 96],
            shares_hash: [0x14; 32],
            r_vpk: [0x15; 32],
            alpha_v: [0x16; 32],
            vote_auth_sig: [0x17; 64],
            encrypted_shares,
            share_blinds,
            share_comms,
        }
    }

    /// Call the FFI under test and decode its `Vec<u32>` JSON response,
    /// failing the test outright if the pointer comes back null.
    fn recoverable_share_indices(bundle: &voting::vote::VoteRecoveryBundle) -> Vec<u32> {
        let json = voting::vote::serialize_recovery(bundle).expect("serialize recovery bundle");
        let json_bytes = json.as_bytes();
        let ptr = unsafe {
            zcashlc_voting_recoverable_share_indices(json_bytes.as_ptr(), json_bytes.len())
        };
        assert!(!ptr.is_null(), "expected recoverable share indices, got null");
        let result_bytes = unsafe { (*ptr).as_slice() }.to_vec();
        unsafe { zcashlc_free_boxed_slice(ptr) };
        serde_json::from_slice(&result_bytes).expect("share indices json")
    }

    #[test]
    fn recoverable_share_indices_single_share_mode_returns_only_the_first_share() {
        // Four built shares whose indices are deliberately not 0..3 in order,
        // so a passing assertion proves the FFI reports the crate's actual
        // sliced share index rather than a hardcoded 0.
        let bundle = recovery_bundle_with_share_indices(true, &[9, 2, 4, 11]);

        let indices = recoverable_share_indices(&bundle);

        assert_eq!(
            indices,
            vec![9],
            "single-share mode must recover exactly the first built share's own index"
        );
    }

    #[test]
    fn recoverable_share_indices_multi_share_mode_returns_every_built_share() {
        // Six built shares against a four-option proposal: the recovered
        // count must track the shares actually built, not `num_options` —
        // the caller-side guess this FFI replaces.
        let share_indices: Vec<u32> = (0..6).collect();
        let bundle = recovery_bundle_with_share_indices(false, &share_indices);

        let indices = recoverable_share_indices(&bundle);

        assert_eq!(indices, share_indices);
    }

    #[test]
    fn recoverable_share_indices_rejects_malformed_json() {
        let malformed = b"{ this is not valid json";

        let ptr = unsafe {
            zcashlc_voting_recoverable_share_indices(malformed.as_ptr(), malformed.len())
        };

        assert!(ptr.is_null(), "malformed recovery JSON must return null");
    }
}
