use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
use prost::Message;
use zcash_client_backend::proto::service::TreeState;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::{MAIN_NETWORK, TEST_NETWORK};
use zcash_voting as voting;
use zip32::AccountId;

use crate::{unwrap_exc_or, unwrap_exc_or_null};

use super::helpers::{
    bytes_from_ptr, derive_hotkey_side_inputs, json_to_boxed_slice, str_from_ptr, usk_from_seed,
};
use super::json::{JsonDelegationInputs, JsonWitnessData};

// =============================================================================
// Free functions (no VotingDatabase needed)
// =============================================================================

/// Warm process-lifetime proving-key caches used by voting proofs.
///
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_warm_proving_caches() -> i32 {
    let res = catch_panic(|| {
        voting::warm_proving_caches();
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}

/// Decompose a weight into power-of-two components.
///
/// Returns JSON-encoded `Vec<u64>` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// No pointer parameters.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_decompose_weight(
    weight: u64,
) -> *mut crate::ffi::BoxedSlice {
    let res = catch_panic(|| {
        let components = voting::decompose::decompose_weight(weight);
        json_to_boxed_slice(&components)
    });
    unwrap_exc_or_null(res)
}

/// Generate delegation inputs from sender seed and hotkey seed.
///
/// Returns JSON-encoded `DelegationInputs` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `sender_seed` and `hotkey_seed` must be valid for their stated lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_generate_delegation_inputs(
    sender_seed: *const u8,
    sender_seed_len: usize,
    hotkey_seed: *const u8,
    hotkey_seed_len: usize,
    network_id: u32,
    account_index: u32,
) -> *mut crate::ffi::BoxedSlice {
    let res = catch_panic(|| {
        let sender = unsafe { bytes_from_ptr(sender_seed, sender_seed_len) };
        let hotkey = unsafe { bytes_from_ptr(hotkey_seed, hotkey_seed_len) };

        if sender.len() < 32 {
            return Err(anyhow!(
                "sender_seed must be at least 32 bytes, got {}",
                sender.len()
            ));
        }
        if hotkey.len() < 32 {
            return Err(anyhow!(
                "hotkey_seed must be at least 32 bytes, got {}",
                hotkey.len()
            ));
        }

        let account = AccountId::try_from(account_index)
            .map_err(|_| anyhow!("account_index must be < 2^31, got {}", account_index))?;

        // Derive sender Orchard FVK
        let sender_usk = usk_from_seed(network_id, sender, account)
            .map_err(|e| anyhow!("failed to derive sender UnifiedSpendingKey: {}", e))?;

        let sender_fvk = sender_usk
            .to_unified_full_viewing_key()
            .orchard()
            .ok_or_else(|| anyhow!("sender UFVK is missing Orchard component"))?
            .to_bytes()
            .to_vec();

        let hotkey_inputs = derive_hotkey_side_inputs(hotkey, network_id, account)?;

        let seed_fp = zip32::fingerprint::SeedFingerprint::from_seed(sender)
            .ok_or_else(|| anyhow!("failed to compute seed fingerprint (seed too short?)"))?;

        let inputs = JsonDelegationInputs {
            fvk_bytes: sender_fvk,
            g_d_new_x: hotkey_inputs.g_d_new_x,
            pk_d_new_x: hotkey_inputs.pk_d_new_x,
            hotkey_raw_address: hotkey_inputs.hotkey_raw_address,
            hotkey_public_key: hotkey_inputs.hotkey_public_key,
            hotkey_address: hotkey_inputs.hotkey_address,
            seed_fingerprint: seed_fp.to_bytes().to_vec(),
        };
        json_to_boxed_slice(&inputs)
    });
    unwrap_exc_or_null(res)
}

/// Generate delegation inputs using an explicit FVK instead of deriving from sender seed.
///
/// Returns JSON-encoded `DelegationInputs` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_generate_delegation_inputs_with_fvk(
    fvk_bytes: *const u8,
    fvk_bytes_len: usize,
    hotkey_seed: *const u8,
    hotkey_seed_len: usize,
    network_id: u32,
    account_index: u32,
    seed_fingerprint: *const u8,
    seed_fingerprint_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    let res = catch_panic(|| {
        let fvk = unsafe { bytes_from_ptr(fvk_bytes, fvk_bytes_len) }.to_vec();
        let hotkey = unsafe { bytes_from_ptr(hotkey_seed, hotkey_seed_len) };
        let seed_fp = unsafe { bytes_from_ptr(seed_fingerprint, seed_fingerprint_len) }.to_vec();

        if fvk.len() != 96 {
            return Err(anyhow!("fvk_bytes must be 96 bytes, got {}", fvk.len()));
        }
        if hotkey.len() < 32 {
            return Err(anyhow!(
                "hotkey_seed must be at least 32 bytes, got {}",
                hotkey.len()
            ));
        }
        if seed_fp.len() != 32 {
            return Err(anyhow!(
                "seed_fingerprint must be 32 bytes, got {}",
                seed_fp.len()
            ));
        }

        let account = AccountId::try_from(account_index)
            .map_err(|_| anyhow!("account_index must be < 2^31, got {}", account_index))?;

        let hotkey_inputs = derive_hotkey_side_inputs(hotkey, network_id, account)?;

        let inputs = JsonDelegationInputs {
            fvk_bytes: fvk,
            g_d_new_x: hotkey_inputs.g_d_new_x,
            pk_d_new_x: hotkey_inputs.pk_d_new_x,
            hotkey_raw_address: hotkey_inputs.hotkey_raw_address,
            hotkey_public_key: hotkey_inputs.hotkey_public_key,
            hotkey_address: hotkey_inputs.hotkey_address,
            seed_fingerprint: seed_fp,
        };
        json_to_boxed_slice(&inputs)
    });
    unwrap_exc_or_null(res)
}

/// Extract the ZIP-244 shielded sighash from finalized PCZT bytes.
///
/// Returns the 32-byte sighash as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `pczt_bytes` must be valid for reads of `pczt_bytes_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_extract_pczt_sighash(
    pczt_bytes: *const u8,
    pczt_bytes_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    let res = catch_panic(|| {
        let bytes = unsafe { bytes_from_ptr(pczt_bytes, pczt_bytes_len) };
        let sighash = voting::action::extract_pczt_sighash(bytes)
            .map_err(|e| anyhow!("extract_pczt_sighash failed: {}", e))?;
        Ok(crate::ffi::BoxedSlice::some(sighash.to_vec()))
    });
    unwrap_exc_or_null(res)
}

/// Extract a spend auth signature from a signed PCZT.
///
/// Returns the signature bytes as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `signed_pczt_bytes` must be valid for reads of `signed_pczt_bytes_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_extract_spend_auth_sig(
    signed_pczt_bytes: *const u8,
    signed_pczt_bytes_len: usize,
    action_index: u32,
) -> *mut crate::ffi::BoxedSlice {
    let res = catch_panic(|| {
        let bytes = unsafe { bytes_from_ptr(signed_pczt_bytes, signed_pczt_bytes_len) };
        let sig = voting::action::extract_spend_auth_sig(bytes, action_index as usize)
            .map_err(|e| anyhow!("extract_spend_auth_sig failed: {}", e))?;
        Ok(crate::ffi::BoxedSlice::some(sig.to_vec()))
    });
    unwrap_exc_or_null(res)
}

/// Extract the 96-byte Orchard FVK from a UFVK string.
///
/// Returns the raw 96-byte Orchard FVK as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `ufvk_str` must be valid for reads of `ufvk_str_len` bytes (UTF-8 encoded).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_extract_orchard_fvk_from_ufvk(
    ufvk_str: *const u8,
    ufvk_str_len: usize,
    network_id: u32,
) -> *mut crate::ffi::BoxedSlice {
    let res = catch_panic(|| {
        let ufvk_string = unsafe { str_from_ptr(ufvk_str, ufvk_str_len) }?;

        let ufvk = match network_id {
            0 => UnifiedFullViewingKey::decode(&MAIN_NETWORK, &ufvk_string),
            1 => UnifiedFullViewingKey::decode(&TEST_NETWORK, &ufvk_string),
            _ => {
                return Err(anyhow!(
                    "invalid network_id {}, expected 0 (mainnet) or 1 (testnet)",
                    network_id
                ));
            }
        }
        .map_err(|e| anyhow!("failed to decode UFVK string: {}", e))?;

        let orchard_fvk = ufvk
            .orchard()
            .ok_or_else(|| anyhow!("UFVK has no Orchard component"))?;
        Ok(crate::ffi::BoxedSlice::some(
            orchard_fvk.to_bytes().to_vec(),
        ))
    });
    unwrap_exc_or_null(res)
}

/// Extract the Orchard note commitment tree root from a protobuf-encoded TreeState.
///
/// Returns the 32-byte nc_root as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `tree_state_bytes` must be valid for reads of `tree_state_bytes_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_extract_nc_root(
    tree_state_bytes: *const u8,
    tree_state_bytes_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    let res = catch_panic(|| {
        let bytes = unsafe { bytes_from_ptr(tree_state_bytes, tree_state_bytes_len) };
        let tree_state = TreeState::decode(bytes)
            .map_err(|e| anyhow!("failed to decode TreeState protobuf: {}", e))?;
        let orchard_ct = tree_state
            .orchard_tree()
            .map_err(|e| anyhow!("failed to parse orchard tree from TreeState: {}", e))?;
        let nc_root = orchard_ct.root().to_bytes().to_vec();
        Ok(crate::ffi::BoxedSlice::some(nc_root))
    });
    unwrap_exc_or_null(res)
}

/// Verify a Merkle witness.
///
/// `witness_json` is a JSON-encoded `WitnessData`.
///
/// Returns 1 if valid, 0 if invalid, -1 on error.
///
/// # Safety
///
/// - `witness_json` must be valid for reads of `witness_json_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_verify_witness(
    witness_json: *const u8,
    witness_json_len: usize,
) -> i32 {
    let res = catch_panic(|| {
        let bytes = unsafe { bytes_from_ptr(witness_json, witness_json_len) };
        let json_witness: JsonWitnessData = serde_json::from_slice(bytes)?;
        let core_witness: voting::WitnessData = json_witness.into();

        let valid = voting::witness::verify_witness(&core_witness)
            .map_err(|e| anyhow!("verify_witness failed: {}", e))?;
        Ok(if valid { 1 } else { 0 })
    });
    unwrap_exc_or(res, -1)
}
