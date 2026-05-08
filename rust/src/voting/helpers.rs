use std::ffi::CString;

use anyhow::anyhow;
use orchard::note::ExtractedNoteCommitment;
use serde::Serialize;
use zcash_client_sqlite::util::SystemClock;
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_protocol::consensus::{self, Network};
use zcash_voting as voting;
use zip32::{AccountId, Scope};

use super::ffi_types::FfiVotingHotkey;

// =============================================================================
// Helper functions
// =============================================================================

pub(super) const MIN_SEED_LEN: usize = 32;

/// Borrow a byte slice from a raw `(ptr, len)` pair.
///
/// When `len == 0`, returns an empty slice without reading `ptr`, so `ptr` may be null.
///
/// Centralizing the null + length check here lets every voting FFI byte input - strings,
/// JSON payloads, anything else - share one boundary contract instead of open-coding it
/// per call site. `str_from_ptr` delegates to this helper.
///
/// # Safety
///
/// When `len > 0`, `ptr` must be non-null and valid for reads for `len` bytes, and the
/// memory must not be mutated for the duration of the call. The returned slice must not
/// outlive the underlying allocation.
pub(super) unsafe fn bytes_from_ptr<'a>(ptr: *const u8, len: usize) -> anyhow::Result<&'a [u8]> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(anyhow!("FFI pointer is null but length is non-zero"));
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Parse a UTF-8 string from a raw pointer and length.
///
/// When `len == 0`, returns the empty string without reading `ptr`, so `ptr` may be null.
///
/// # Safety
///
/// Same contract as `bytes_from_ptr`.
pub(super) unsafe fn str_from_ptr(ptr: *const u8, len: usize) -> anyhow::Result<String> {
    let bytes = unsafe { bytes_from_ptr(ptr, len) }?;
    Ok(std::str::from_utf8(bytes)?.to_string())
}

/// Return JSON-serialized bytes as `*mut ffi::BoxedSlice`.
pub(super) fn json_to_boxed_slice<T: Serialize>(
    value: &T,
) -> anyhow::Result<*mut crate::ffi::BoxedSlice> {
    let json = serde_json::to_vec(value)?;
    Ok(crate::ffi::BoxedSlice::some(json))
}

/// Convert a librustzcash ReceivedNote (orchard) into zcash_voting's NoteInfo.
///
/// Requires the account's UFVK and network to compute the nullifier and
/// encode the UFVK string.
pub(super) fn received_note_to_note_info<P: consensus::Parameters>(
    note: &zcash_client_backend::wallet::ReceivedNote<
        zcash_client_sqlite::ReceivedNoteId,
        orchard::note::Note,
    >,
    ufvk: &UnifiedFullViewingKey,
    network: &P,
) -> anyhow::Result<voting::NoteInfo> {
    let orchard_note = note.note();
    let fvk = ufvk
        .orchard()
        .ok_or_else(|| anyhow!("UFVK has no Orchard component"))?;

    let nullifier = orchard_note.nullifier(fvk);
    // `voting::NoteInfo::commitment` is the wire-form (extracted) cmx, not the affine
    // note commitment, so the affine value is converted here before serialization.
    let cmx: ExtractedNoteCommitment = orchard_note.commitment().into();

    // Extract raw fields
    let diversifier = orchard_note.recipient().diversifier().as_array().to_vec();
    let value = orchard_note.value().inner();
    let rho = orchard_note.rho().to_bytes().to_vec();
    let rseed = orchard_note.rseed().as_bytes().to_vec();
    let position = u64::from(note.note_commitment_tree_position());
    let scope = match note.spending_key_scope() {
        Scope::External => 0u32,
        Scope::Internal => 1u32,
    };
    let ufvk_str = ufvk.encode(network);

    Ok(voting::NoteInfo {
        commitment: cmx.to_bytes().to_vec(),
        nullifier: nullifier.to_bytes().to_vec(),
        value,
        position,
        diversifier,
        rho,
        rseed,
        scope,
        ufvk_str,
    })
}

/// Open the wallet database.
pub(super) fn open_wallet_db(
    wallet_db_path: &str,
    network_id: u32,
) -> anyhow::Result<
    zcash_client_sqlite::WalletDb<rusqlite::Connection, Network, SystemClock, rand::rngs::OsRng>,
> {
    let network = crate::parse_network(network_id)?;
    zcash_client_sqlite::WalletDb::for_path(wallet_db_path, network, SystemClock, rand::rngs::OsRng)
        .map_err(|e| anyhow!("failed to open wallet DB: {}", e))
}

#[allow(dead_code)]
pub(super) fn round_phase_to_u32(phase: voting::storage::RoundPhase) -> u32 {
    use voting::storage::RoundPhase::*;

    match phase {
        Initialized => 0,
        HotkeyGenerated => 1,
        DelegationConstructed => 2,
        DelegationProved => 3,
        VoteReady => 4,
    }
}

pub(super) fn usk_from_seed(
    network_id: u32,
    seed: &[u8],
    account: AccountId,
) -> anyhow::Result<UnifiedSpendingKey> {
    if seed.len() < MIN_SEED_LEN {
        return Err(anyhow!(
            "seed must be at least {} bytes, got {}",
            MIN_SEED_LEN,
            seed.len()
        ));
    }

    let network = crate::parse_network(network_id)?;
    let usk = UnifiedSpendingKey::from_seed(&network, seed, account)
        .map_err(|e| anyhow!("failed to derive UnifiedSpendingKey: {}", e))?;

    Ok(usk)
}

pub(super) struct HotkeySideInputs {
    pub(super) g_d_new_x: Vec<u8>,
    pub(super) pk_d_new_x: Vec<u8>,
    pub(super) hotkey_raw_address: Vec<u8>,
    pub(super) hotkey_public_key: Vec<u8>,
    pub(super) hotkey_address: String,
}

pub(super) fn derive_hotkey_side_inputs(
    hotkey_seed: &[u8],
    network_id: u32,
    hotkey_account: AccountId,
) -> anyhow::Result<HotkeySideInputs> {
    let hotkey_usk = usk_from_seed(network_id, hotkey_seed, hotkey_account)
        .map_err(|e| anyhow!("failed to derive hotkey UnifiedSpendingKey: {}", e))?;

    let hotkey_ufvk = hotkey_usk.to_unified_full_viewing_key();
    let hotkey_orchard_fvk = hotkey_ufvk
        .orchard()
        .ok_or_else(|| anyhow!("hotkey UFVK is missing Orchard component"))?;

    let app_hotkey = voting::hotkey::generate_hotkey(hotkey_seed)
        .map_err(|e| anyhow!("generate_hotkey failed: {}", e))?;
    let hotkey_addr = hotkey_orchard_fvk.address_at(0u32, Scope::External);
    let hotkey_raw_address = hotkey_addr.to_raw_address_bytes().to_vec();

    let hotkey_addr_43: [u8; 43] = hotkey_raw_address
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("address serialization must be 43 bytes"))?;
    let (g_d_new_x, pk_d_new_x) =
        voting::action::derive_hotkey_x_coords_from_raw_address(&hotkey_addr_43)
            .map_err(|e| anyhow!("derive_hotkey_x_coords failed: {}", e))?;

    Ok(HotkeySideInputs {
        g_d_new_x: g_d_new_x.to_vec(),
        pk_d_new_x: pk_d_new_x.to_vec(),
        hotkey_raw_address,
        hotkey_public_key: app_hotkey.public_key,
        hotkey_address: app_hotkey.address,
    })
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Convert a `voting::VotingHotkey` to the FFI representation.
#[allow(dead_code)]
pub(super) fn voting_hotkey_to_ffi(
    hotkey: voting::VotingHotkey,
) -> anyhow::Result<FfiVotingHotkey> {
    let (sk_ptr, sk_len) = crate::ptr_from_vec(hotkey.secret_key);
    let (pk_ptr, pk_len) = crate::ptr_from_vec(hotkey.public_key);
    let address = CString::new(hotkey.address)
        .map_err(|e| anyhow!("invalid hotkey address string: {}", e))?
        .into_raw();
    Ok(FfiVotingHotkey {
        secret_key: sk_ptr,
        secret_key_len: sk_len,
        public_key: pk_ptr,
        public_key_len: pk_len,
        address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus::{MAIN_NETWORK, TEST_NETWORK};

    #[test]
    fn bytes_from_ptr_zero_len_accepts_null() {
        let bytes = unsafe { bytes_from_ptr(std::ptr::null(), 0) }.expect("empty");
        assert!(bytes.is_empty());
    }

    #[test]
    fn bytes_from_ptr_rejects_null_when_nonzero_len() {
        let err = unsafe { bytes_from_ptr(std::ptr::null(), 3) }.expect_err("null");
        assert!(err.to_string().contains("null"));
    }

    #[test]
    fn str_from_ptr_zero_len_accepts_null() {
        let s = unsafe { str_from_ptr(std::ptr::null(), 0) }.expect("empty");
        assert!(s.is_empty());
    }

    #[test]
    fn str_from_ptr_rejects_null_when_nonzero_len() {
        let err = unsafe { str_from_ptr(std::ptr::null(), 3) }.expect_err("null");
        assert!(err.to_string().contains("null"));
    }

    #[test]
    fn usk_from_seed_uses_sdk_network_ids() {
        let seed = [7u8; 32];
        let account = AccountId::try_from(0).expect("account 0");

        let mainnet_usk = usk_from_seed(1, &seed, account).expect("mainnet usk");
        let expected_mainnet =
            UnifiedSpendingKey::from_seed(&MAIN_NETWORK, &seed, account).expect("mainnet seed");
        assert_eq!(
            mainnet_usk
                .to_unified_full_viewing_key()
                .encode(&MAIN_NETWORK),
            expected_mainnet
                .to_unified_full_viewing_key()
                .encode(&MAIN_NETWORK)
        );

        let testnet_usk = usk_from_seed(0, &seed, account).expect("testnet usk");
        let expected_testnet =
            UnifiedSpendingKey::from_seed(&TEST_NETWORK, &seed, account).expect("testnet seed");
        assert_eq!(
            testnet_usk
                .to_unified_full_viewing_key()
                .encode(&TEST_NETWORK),
            expected_testnet
                .to_unified_full_viewing_key()
                .encode(&TEST_NETWORK)
        );
    }

    #[test]
    fn usk_from_seed_rejects_short_seed() {
        let seed = [7u8; MIN_SEED_LEN - 1];
        let account = AccountId::try_from(0).expect("account 0");

        let err = usk_from_seed(1, &seed, account).expect_err("short seed");

        assert!(
            err.to_string()
                .contains("seed must be at least 32 bytes, got 31")
        );
    }
}
