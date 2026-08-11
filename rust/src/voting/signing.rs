use std::panic::AssertUnwindSafe;

use anyhow::anyhow;
use ff::PrimeField;
use ffi_helpers::panic::catch_panic;
use pasta_curves::pallas;
use serde::Serialize;
use zcash_voting as voting;
use zip32::AccountId;

use crate::unwrap_exc_or_null;

use super::constants::SEED_FINGERPRINT_LEN;
use super::db::VotingDatabaseHandle;
use super::helpers::{bytes_from_ptr, json_to_boxed_slice, str_from_ptr, usk_from_seed};

/// The detached SpendAuth signature this wallet produced for one delegation
/// bundle, with the sighash it covers.
///
/// Not a mirror of any `zcash_voting` wire type: the crate has no type for a
/// bare `(signature, sighash)` pair, because it never sees the signing step.
/// This is the FFI's own two-field return envelope, so it lives here rather
/// than in `json.rs`.
#[derive(Serialize)]
struct JsonDelegationSignature {
    sig: Vec<u8>,
    sighash: Vec<u8>,
}

/// Sign one delegation bundle's PCZT sighash with the account's own Orchard
/// SpendAuth key.
///
/// This implements `zcash_voting`'s own prescribed software-wallet recipe; it
/// is not an SDK invention. The crate stopped deriving account keys and signing
/// on the caller's behalf in 2.0 and documents the replacement on
/// `delegate::DelegationSigningRequest` (rc.5 `src/delegate.rs:405-410`): a
/// software wallet uses `account_index`, `network`, `sighash` and `alpha` to
/// derive its account SpendAuth key locally, randomizes it, signs `sighash`,
/// and passes the resulting signature back. The crate README states the same
/// under "Secret boundaries" (`README.md:235-241`). The derive → randomize →
/// sign body below is transcribed from the crate authors' own reference wallet,
/// Vizor (`chainapsis/vizor-wallet`, `rust/src/wallet/voting/delegation.rs:318-349`),
/// which ships it with a signature-verifying round-trip test.
///
/// Two calls make one delegation submission: this one produces the signature,
/// then `zcashlc_voting_get_delegation_submission_with_signature` consumes it.
/// The sighash returned here is not decorative — the crate checks it against
/// the sighash it stored at setup and refuses the submission if they disagree.
/// The Keystone flow differs only in where the signature comes from.
///
/// `fvk_bytes`, `hotkey_stored_secret`, `seed_fingerprint`, `account_index` and
/// `round_name` are the same delegation-key inputs
/// `zcashlc_voting_build_and_prove_delegation` takes, because the crate loads
/// the signing request through the same `DelegationKeys` value that built the
/// PCZT.
///
/// # Key material
///
/// `seed` is wallet root seed material — the only voting FFI entry point that
/// takes it. It is borrowed for the duration of the call through
/// `bytes_from_ptr` and never copied into an owned buffer, so there is nothing
/// here to zeroize; the caller owns the allocation and its lifetime, exactly as
/// for every other voting FFI byte input. It is never logged, never persisted
/// and never handed to `zcash_voting`: only the locally derived randomized key
/// touches it, and only the 64-byte detached signature leaves this function.
///
/// Returns JSON-encoded `{"sig": [..64], "sighash": [..32]}` as
/// `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - For every `(ptr, len)` byte argument (`round_id`, `fvk_bytes`,
///   `hotkey_stored_secret`, `seed_fingerprint`, `round_name`, `seed`): if
///   `len > 0` then `ptr` must be non-null and valid for reads for `len` bytes;
///   if `len == 0`, `ptr` is ignored.
/// - `seed` must remain valid and unmutated for the duration of the call. The
///   callee neither retains nor frees it.
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
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let fvk = unsafe { bytes_from_ptr(fvk_bytes, fvk_bytes_len) }?;
        let hotkey_secret =
            unsafe { bytes_from_ptr(hotkey_stored_secret, hotkey_stored_secret_len) }?;
        let seed_fp_bytes = unsafe { bytes_from_ptr(seed_fingerprint, seed_fingerprint_len) }?;
        let seed_fp_32: [u8; SEED_FINGERPRINT_LEN] = seed_fp_bytes.try_into().map_err(|_| {
            anyhow!(
                "seed_fingerprint must be {} bytes, got {}",
                SEED_FINGERPRINT_LEN,
                seed_fp_bytes.len()
            )
        })?;
        let round_name_str = unsafe { str_from_ptr(round_name, round_name_len) }?;
        let seed_bytes = unsafe { bytes_from_ptr(seed, seed_len) }?;

        let hotkey = voting::VotingHotkey::from_stored_secret(hotkey_secret, handle.network)
            .map_err(|e| anyhow!("failed to reconstruct voting hotkey: {}", e))?;
        let keys = voting::delegate::DelegationKeys::with_voting_hotkey(
            fvk.to_vec(),
            &hotkey,
            seed_fp_32,
            account_index,
            round_name_str,
        )
        .map_err(|e| anyhow!("failed to build delegation keys: {}", e))?;

        let request =
            voting::delegate::signing_request(&handle.db, &round_id_str, bundle_index, &keys)
                .map_err(|e| anyhow!("signing_request failed: {}", e))?;

        // Bind the request to this exact wallet seed before deriving any keys.
        let seed_fp = zip32::fingerprint::SeedFingerprint::from_seed(seed_bytes)
            .ok_or_else(|| anyhow!("seed length is not valid for ZIP-32"))?;
        if seed_fp.to_bytes() != request.seed_fingerprint {
            return Err(anyhow!(
                "wallet seed fingerprint does not match the delegation signing request"
            ));
        }

        // The request's network is the round's stored network: the crate
        // validated `keys.network` (which came from `handle.network` through
        // the hotkey) against it before answering. Asserting it here is what
        // makes deriving through the SDK's own `usk_from_seed(handle.network_id,
        // ..)` provably equivalent to deriving from `request.network` directly,
        // and it fails closed if a later release sources that field elsewhere.
        if request.network != handle.network {
            return Err(anyhow!(
                "delegation signing request network does not match the open voting database"
            ));
        }

        let account = AccountId::try_from(request.account_index).map_err(|_| {
            anyhow!(
                "account_index must be < 2^31, got {}",
                request.account_index
            )
        })?;
        let usk = usk_from_seed(handle.network_id, seed_bytes, account)
            .map_err(|e| anyhow!("failed to derive sender UnifiedSpendingKey: {}", e))?;
        let ask = orchard::keys::SpendAuthorizingKey::from(usk.orchard());

        // The alpha randomizer must decode as a canonical Pallas scalar.
        let alpha = Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(request.alpha))
            .ok_or_else(|| anyhow!("delegation alpha is not a canonical Pallas scalar"))?;

        // Sign the request's own sighash with the randomized spend auth key.
        let rsk = ask.randomize(&alpha);
        let sig = rsk.sign(rand::rngs::OsRng, &request.sighash);
        let sig_bytes: [u8; 64] = (&sig).into();

        json_to_boxed_slice(&JsonDelegationSignature {
            sig: sig_bytes.to_vec(),
            sighash: request.sighash.to_vec(),
        })
    });
    unwrap_exc_or_null(res)
}
