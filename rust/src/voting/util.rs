use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
use prost::Message;
use zcash_client_backend::proto::service::TreeState;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_voting as voting;
use zip32::AccountId;

use crate::{unwrap_exc_or, unwrap_exc_or_null};

use super::constants::{ORCHARD_FVK_LEN, SEED_FINGERPRINT_LEN};
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

/// Generate delegation inputs from a sender seed and a stored hotkey secret.
///
/// Returns JSON-encoded `DelegationInputs` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `sender_seed` and `hotkey_stored_secret` must be valid for their stated lengths.
/// - `hotkey_stored_secret` is the app-owned material returned as
///   `FfiVotingHotkey::stored_secret`, not wallet seed material.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_generate_delegation_inputs(
    sender_seed: *const u8,
    sender_seed_len: usize,
    hotkey_stored_secret: *const u8,
    hotkey_stored_secret_len: usize,
    network_id: u32,
    account_index: u32,
) -> *mut crate::ffi::BoxedSlice {
    let res = catch_panic(|| {
        let sender = unsafe { bytes_from_ptr(sender_seed, sender_seed_len) }?;
        let hotkey = unsafe { bytes_from_ptr(hotkey_stored_secret, hotkey_stored_secret_len) }?;

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

        // `hotkey` is the stored hotkey secret, from which zcash_voting derives
        // the hotkey's Orchard address at a fixed account and address index.
        let hotkey_inputs = derive_hotkey_side_inputs(hotkey, network_id)?;

        let seed_fp = zip32::fingerprint::SeedFingerprint::from_seed(sender)
            .ok_or_else(|| anyhow!("failed to compute seed fingerprint (seed too short?)"))?;

        let inputs = JsonDelegationInputs {
            fvk_bytes: sender_fvk,
            g_d_new_x: hotkey_inputs.g_d_new_x,
            pk_d_new_x: hotkey_inputs.pk_d_new_x,
            hotkey_raw_address: hotkey_inputs.hotkey_raw_address,
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
    hotkey_stored_secret: *const u8,
    hotkey_stored_secret_len: usize,
    network_id: u32,
    seed_fingerprint: *const u8,
    seed_fingerprint_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    let res = catch_panic(|| {
        let fvk = unsafe { bytes_from_ptr(fvk_bytes, fvk_bytes_len) }?.to_vec();
        let hotkey = unsafe { bytes_from_ptr(hotkey_stored_secret, hotkey_stored_secret_len) }?;
        let seed_fp = unsafe { bytes_from_ptr(seed_fingerprint, seed_fingerprint_len) }?.to_vec();

        if fvk.len() != ORCHARD_FVK_LEN {
            return Err(anyhow!(
                "fvk_bytes must be {} bytes, got {}",
                ORCHARD_FVK_LEN,
                fvk.len()
            ));
        }
        if seed_fp.len() != SEED_FINGERPRINT_LEN {
            return Err(anyhow!(
                "seed_fingerprint must be {} bytes, got {}",
                SEED_FINGERPRINT_LEN,
                seed_fp.len()
            ));
        }

        // `hotkey` is the stored hotkey secret, from which zcash_voting derives
        // the hotkey's Orchard address at a fixed account and address index.
        let hotkey_inputs = derive_hotkey_side_inputs(hotkey, network_id)?;

        let inputs = JsonDelegationInputs {
            fvk_bytes: fvk,
            g_d_new_x: hotkey_inputs.g_d_new_x,
            pk_d_new_x: hotkey_inputs.pk_d_new_x,
            hotkey_raw_address: hotkey_inputs.hotkey_raw_address,
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
        let bytes = unsafe { bytes_from_ptr(pczt_bytes, pczt_bytes_len) }?;
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
        let bytes = unsafe { bytes_from_ptr(signed_pczt_bytes, signed_pczt_bytes_len) }?;
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

        let network = crate::parse_network(network_id)?;
        let ufvk = UnifiedFullViewingKey::decode(&network, &ufvk_string)
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

/// Extract the Ironwood note commitment tree root from a protobuf-encoded TreeState.
///
/// Voting rounds anchor to the Ironwood pool — `zcash_voting 2.0` supports no
/// other shielded protocol — so a round's `nc_root` is the root of the Ironwood
/// tree, not the Orchard one. They are distinct pools with distinct trees whose
/// roots never coincide on a live chain, so reading the wrong field does not
/// degrade gracefully: it fails every round, always.
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
        let bytes = unsafe { bytes_from_ptr(tree_state_bytes, tree_state_bytes_len) }?;
        let tree_state = TreeState::decode(bytes)
            .map_err(|e| anyhow!("failed to decode TreeState protobuf: {}", e))?;
        let ironwood_ct = tree_state
            .ironwood_tree()
            .map_err(|e| anyhow!("failed to parse ironwood tree from TreeState: {}", e))?;
        let nc_root = ironwood_ct.root().to_bytes().to_vec();
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
        let bytes = unsafe { bytes_from_ptr(witness_json, witness_json_len) }?;
        let json_witness: JsonWitnessData = serde_json::from_slice(bytes)?;
        let core_witness: voting::WitnessData = json_witness.into();

        let valid = voting::witness::verify_witness(&core_witness)
            .map_err(|e| anyhow!("verify_witness failed: {}", e))?;
        Ok(if valid { 1 } else { 0 })
    });
    unwrap_exc_or(res, -1)
}

#[cfg(test)]
mod tests {
    use ff::PrimeField;
    use incrementalmerkletree::frontier::{CommitmentTree, Frontier};
    use orchard::tree::{Anchor, MerkleHashOrchard};
    use pasta_curves::pallas;
    use prost::Message;
    use zcash_client_backend::proto::service::TreeState;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_primitives::merkle_tree::write_commitment_tree;
    use zcash_protocol::consensus::Network;

    use super::*;
    use crate::{NETWORK_ID_MAINNET, NETWORK_ID_TESTNET};

    fn free(ptr: *mut crate::ffi::BoxedSlice) {
        unsafe { crate::ffi::zcashlc_free_boxed_slice(ptr) };
    }

    fn boxed_slice_to_vec(ptr: *mut crate::ffi::BoxedSlice) -> Vec<u8> {
        assert!(!ptr.is_null(), "expected non-null BoxedSlice");
        let bytes = unsafe { (*ptr).as_slice() }.to_vec();
        free(ptr);
        bytes
    }

    fn derive_test_ufvk(network: Network) -> (String, [u8; ORCHARD_FVK_LEN]) {
        let seed = [0u8; 32];
        let account = AccountId::try_from(0).expect("account 0");
        let usk = UnifiedSpendingKey::from_seed(&network, &seed, account).expect("from_seed");
        let ufvk = usk.to_unified_full_viewing_key();
        let ufvk_str = ufvk.encode(&network);
        let orchard_bytes = ufvk.orchard().expect("orchard present").to_bytes();
        (ufvk_str, orchard_bytes)
    }

    fn derive_orchard_fvk_bytes(network: Network, seed: &[u8], account_index: u32) -> Vec<u8> {
        let account = AccountId::try_from(account_index).expect("account");
        let usk = UnifiedSpendingKey::from_seed(&network, seed, account).expect("from_seed");
        usk.to_unified_full_viewing_key()
            .orchard()
            .expect("orchard fvk")
            .to_bytes()
            .to_vec()
    }

    /// A stored hotkey secret of the exact length `zcash_voting` requires.
    ///
    /// Voting hotkeys are app-owned random material rather than wallet-derived
    /// keys, so tests fabricate a secret directly instead of deriving one.
    fn hotkey_stored_secret(fill: u8) -> Vec<u8> {
        vec![fill; voting::hotkey::VOTING_HOTKEY_STORED_SECRET_LEN]
    }

    /// The hotkey's Orchard address, derived the only way it can now be: from
    /// the stored secret, via `zcash_voting`.
    fn hotkey_raw_address_for(secret: &[u8], network: voting::Network) -> Vec<u8> {
        voting::VotingHotkey::from_stored_secret(secret, network)
            .expect("stored secret")
            .raw_orchard_address()
            .to_vec()
    }

    fn delegation_inputs_from_ptr(ptr: *mut crate::ffi::BoxedSlice) -> JsonDelegationInputs {
        let json = boxed_slice_to_vec(ptr);
        serde_json::from_slice(&json).expect("delegation inputs json")
    }

    #[test]
    fn generate_delegation_inputs_uses_sender_account_and_stored_hotkey_secret() {
        let sender_seed = [1u8; 32];
        let hotkey_secret = hotkey_stored_secret(2);
        let result = unsafe {
            zcashlc_voting_generate_delegation_inputs(
                sender_seed.as_ptr(),
                sender_seed.len(),
                hotkey_secret.as_ptr(),
                hotkey_secret.len(),
                NETWORK_ID_MAINNET,
                1,
            )
        };

        let inputs = delegation_inputs_from_ptr(result);

        assert_eq!(
            inputs.fvk_bytes,
            derive_orchard_fvk_bytes(Network::MainNetwork, &sender_seed, 1),
            "sender FVK should use the caller's account_index"
        );
        assert_ne!(
            inputs.fvk_bytes,
            derive_orchard_fvk_bytes(Network::MainNetwork, &sender_seed, 0),
            "sender FVK should not be forced to account 0"
        );
        assert_eq!(
            inputs.hotkey_raw_address,
            hotkey_raw_address_for(&hotkey_secret, voting::Network::Mainnet),
            "hotkey address should come from the stored hotkey secret"
        );
    }

    #[test]
    fn generate_delegation_inputs_rejects_wrong_length_hotkey_secret() {
        let sender_seed = [1u8; 32];
        // A wallet-style 32-byte seed is no longer accepted: the hotkey secret
        // has its own fixed length, and silently reinterpreting a seed as one
        // would derive an address the caller never generated.
        let too_short = [2u8; 32];
        let result = unsafe {
            zcashlc_voting_generate_delegation_inputs(
                sender_seed.as_ptr(),
                sender_seed.len(),
                too_short.as_ptr(),
                too_short.len(),
                NETWORK_ID_MAINNET,
                1,
            )
        };

        assert!(result.is_null());
    }

    #[test]
    fn generate_delegation_inputs_with_fvk_uses_stored_hotkey_secret() {
        let sender_seed = [1u8; 32];
        let hotkey_secret = hotkey_stored_secret(2);
        let fvk = derive_orchard_fvk_bytes(Network::MainNetwork, &sender_seed, 1);
        let seed_fp = zip32::fingerprint::SeedFingerprint::from_seed(&sender_seed)
            .expect("seed fingerprint")
            .to_bytes();
        let result = unsafe {
            zcashlc_voting_generate_delegation_inputs_with_fvk(
                fvk.as_ptr(),
                fvk.len(),
                hotkey_secret.as_ptr(),
                hotkey_secret.len(),
                NETWORK_ID_MAINNET,
                seed_fp.as_ptr(),
                seed_fp.len(),
            )
        };

        let inputs = delegation_inputs_from_ptr(result);

        assert_eq!(
            inputs.fvk_bytes, fvk,
            "explicit sender FVK should pass through unchanged"
        );
        assert_eq!(
            inputs.hotkey_raw_address,
            hotkey_raw_address_for(&hotkey_secret, voting::Network::Mainnet),
            "hotkey address should come from the stored hotkey secret"
        );
    }

    #[test]
    fn delegation_inputs_hotkey_address_is_independent_of_the_sender() {
        // The hotkey address must depend only on the hotkey secret. If it ever
        // tracked the sender's account, two accounts delegating to the same
        // hotkey would produce different delegation targets.
        let hotkey_secret = hotkey_stored_secret(2);
        let expected = hotkey_raw_address_for(&hotkey_secret, voting::Network::Mainnet);

        for (sender_fill, account_index) in [(1u8, 0u32), (3u8, 1u32), (4u8, 7u32)] {
            let sender_seed = [sender_fill; 32];
            let result = unsafe {
                zcashlc_voting_generate_delegation_inputs(
                    sender_seed.as_ptr(),
                    sender_seed.len(),
                    hotkey_secret.as_ptr(),
                    hotkey_secret.len(),
                    NETWORK_ID_MAINNET,
                    account_index,
                )
            };
            let inputs = delegation_inputs_from_ptr(result);
            assert_eq!(inputs.hotkey_raw_address, expected);
        }
    }

    #[test]
    fn extract_orchard_fvk_returns_orchard_bytes_for_valid_mainnet_ufvk() {
        let (ufvk_str, expected) = derive_test_ufvk(Network::MainNetwork);
        let result = unsafe {
            zcashlc_voting_extract_orchard_fvk_from_ufvk(
                ufvk_str.as_ptr(),
                ufvk_str.len(),
                NETWORK_ID_MAINNET,
            )
        };

        assert!(!result.is_null(), "expected non-null BoxedSlice");
        let actual = unsafe { (*result).as_slice() }.to_vec();
        free(result);

        assert_eq!(
            actual.len(),
            ORCHARD_FVK_LEN,
            "Orchard FVK must be {ORCHARD_FVK_LEN} bytes"
        );
        assert_eq!(actual, expected.to_vec(), "FVK bytes must match");
    }

    #[test]
    fn extract_orchard_fvk_returns_orchard_bytes_for_valid_testnet_ufvk() {
        let (ufvk_str, expected) = derive_test_ufvk(Network::TestNetwork);
        let result = unsafe {
            zcashlc_voting_extract_orchard_fvk_from_ufvk(
                ufvk_str.as_ptr(),
                ufvk_str.len(),
                NETWORK_ID_TESTNET,
            )
        };

        assert!(!result.is_null(), "expected non-null BoxedSlice");
        let actual = unsafe { (*result).as_slice() }.to_vec();
        free(result);

        assert_eq!(
            actual.len(),
            ORCHARD_FVK_LEN,
            "Orchard FVK must be {ORCHARD_FVK_LEN} bytes"
        );
        assert_eq!(actual, expected.to_vec(), "FVK bytes must match");
    }

    #[test]
    fn extract_orchard_fvk_rejects_mainnet_ufvk_with_testnet_network_id() {
        let (ufvk_str, _expected) = derive_test_ufvk(Network::MainNetwork);
        let result = unsafe {
            zcashlc_voting_extract_orchard_fvk_from_ufvk(
                ufvk_str.as_ptr(),
                ufvk_str.len(),
                NETWORK_ID_TESTNET,
            )
        };

        assert!(result.is_null());
    }

    #[test]
    fn extract_orchard_fvk_rejects_null_pointer_with_nonzero_len() {
        let result = unsafe {
            zcashlc_voting_extract_orchard_fvk_from_ufvk(std::ptr::null(), 5, NETWORK_ID_MAINNET)
        };

        assert!(result.is_null());
    }

    #[test]
    fn extract_orchard_fvk_rejects_invalid_network_id() {
        let (ufvk_str, _expected) = derive_test_ufvk(Network::MainNetwork);
        let result = unsafe {
            zcashlc_voting_extract_orchard_fvk_from_ufvk(ufvk_str.as_ptr(), ufvk_str.len(), 99)
        };

        assert!(result.is_null());
    }

    #[test]
    fn extract_orchard_fvk_rejects_non_ufvk_string() {
        let bogus = b"not a ufvk";
        let result = unsafe {
            zcashlc_voting_extract_orchard_fvk_from_ufvk(
                bogus.as_ptr(),
                bogus.len(),
                NETWORK_ID_MAINNET,
            )
        };

        assert!(result.is_null());
    }

    #[test]
    fn extract_orchard_fvk_rejects_empty_input() {
        let result = unsafe {
            zcashlc_voting_extract_orchard_fvk_from_ufvk(std::ptr::null(), 0, NETWORK_ID_MAINNET)
        };

        assert!(result.is_null());
    }

    #[test]
    fn extract_pczt_sighash_rejects_invalid_pczt_bytes() {
        let bogus = b"not a pczt";

        let result = unsafe { zcashlc_voting_extract_pczt_sighash(bogus.as_ptr(), bogus.len()) };

        assert!(result.is_null());
    }

    #[test]
    fn extract_spend_auth_sig_rejects_invalid_pczt_bytes() {
        let bogus = b"not a signed pczt";

        let result =
            unsafe { zcashlc_voting_extract_spend_auth_sig(bogus.as_ptr(), bogus.len(), 0) };

        assert!(result.is_null());
    }

    #[test]
    fn extract_nc_root_returns_empty_ironwood_root_for_empty_tree_state() {
        let tree_state = TreeState {
            network: "main".to_string(),
            height: 1,
            hash: "00".repeat(32),
            time: 0,
            sapling_tree: String::new(),
            orchard_tree: String::new(),
            ironwood_tree: String::new(),
        };
        let tree_state_bytes = tree_state.encode_to_vec();

        let result = unsafe {
            zcashlc_voting_extract_nc_root(tree_state_bytes.as_ptr(), tree_state_bytes.len())
        };

        let root = boxed_slice_to_vec(result);
        assert_eq!(root.len(), 32);
        assert_eq!(root, Anchor::empty_tree().to_bytes().to_vec());
    }

    const TREE_DEPTH: u8 = orchard::NOTE_COMMITMENT_TREE_DEPTH as u8;

    /// A distinguishable Orchard-tree leaf built from a small field element.
    fn merkle_hash(tag: u64) -> MerkleHashOrchard {
        let repr = pallas::Base::from(tag).to_repr();
        MerkleHashOrchard::from_bytes(&repr).expect("small field element is canonical")
    }

    /// A commitment-tree frontier holding one leaf per tag.
    fn frontier_with(tags: &[u64]) -> Frontier<MerkleHashOrchard, TREE_DEPTH> {
        let mut frontier = Frontier::empty();
        for tag in tags {
            assert!(frontier.append(merkle_hash(*tag)));
        }
        frontier
    }

    /// The hex tree-state encoding `TreeState` carries for a frontier.
    fn tree_hex(frontier: &Frontier<MerkleHashOrchard, TREE_DEPTH>) -> String {
        let commitment_tree = CommitmentTree::from_frontier(frontier);
        let mut tree_bytes = Vec::new();
        write_commitment_tree(&commitment_tree, &mut tree_bytes)
            .expect("serialize note commitment tree state");
        hex::encode(tree_bytes)
    }

    /// Voting rounds are anchored to the **Ironwood** note commitment tree, so
    /// when the cached `TreeState` carries both pools the extracted `nc_root`
    /// must be the Ironwood root, not the Orchard one. This is the second half
    /// of the `8a40d1f9` fix that the `eea6cde8` merge lost; without it, nothing
    /// in the suite notices which field this FFI reads.
    #[test]
    fn extract_nc_root_returns_ironwood_root_when_both_trees_present() {
        let orchard_frontier = frontier_with(&[1, 2, 3]);
        let ironwood_frontier = frontier_with(&[7, 8]);
        assert_ne!(
            orchard_frontier.root().to_bytes(),
            ironwood_frontier.root().to_bytes(),
            "test needs distinguishable roots"
        );
        let tree_state = TreeState {
            network: "test".to_string(),
            height: 100,
            hash: String::new(),
            time: 0,
            sapling_tree: String::new(),
            orchard_tree: tree_hex(&orchard_frontier),
            ironwood_tree: tree_hex(&ironwood_frontier),
        };
        let tree_state_bytes = tree_state.encode_to_vec();

        let result = unsafe {
            zcashlc_voting_extract_nc_root(tree_state_bytes.as_ptr(), tree_state_bytes.len())
        };

        let root = boxed_slice_to_vec(result);
        assert_eq!(
            root,
            ironwood_frontier.root().to_bytes().to_vec(),
            "nc_root must come from the Ironwood tree"
        );
    }

    #[test]
    fn verify_witness_returns_zero_for_wrong_root() {
        let witness = JsonWitnessData {
            note_commitment: vec![0; 32],
            position: 0,
            root: Anchor::empty_tree().to_bytes().to_vec(),
            auth_path: (0..32).map(|_| vec![0; 32]).collect(),
        };
        let witness_json = serde_json::to_vec(&witness).expect("witness json");

        let result =
            unsafe { zcashlc_voting_verify_witness(witness_json.as_ptr(), witness_json.len()) };

        assert_eq!(result, 0);
    }
}
