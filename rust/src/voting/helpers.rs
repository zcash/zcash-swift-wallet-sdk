use std::ffi::CString;

use anyhow::anyhow;
use orchard::note::ExtractedNoteCommitment;
use serde::Serialize;
use zcash_client_sqlite::util::SystemClock;
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_protocol::consensus::{self, MAIN_NETWORK, Network, TEST_NETWORK};
use zcash_voting as voting;
use zip32::{AccountId, Scope};

use super::ffi_types::FfiVotingHotkey;

// =============================================================================
// Helper functions
// =============================================================================

/// Parse a UTF-8 string from raw pointer + length.
///
/// # Safety
///
/// - `ptr` must be non-null and valid for reads for `len` bytes.
/// - The memory referenced by `ptr` must not be mutated for the duration of the call.
pub(super) unsafe fn str_from_ptr(ptr: *const u8, len: usize) -> anyhow::Result<String> {
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    Ok(std::str::from_utf8(bytes)?.to_string())
}

/// Parse a byte slice from raw pointer + length.
///
/// # Safety
///
/// - `ptr` must be non-null and valid for reads for `len` bytes.
/// - The memory referenced by `ptr` must not be mutated for the duration of the call.
pub(super) unsafe fn bytes_from_ptr<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    unsafe { std::slice::from_raw_parts(ptr, len) }
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

    // Compute nullifier from note + full viewing key
    let nullifier = orchard_note.nullifier(fvk);

    // Compute cmx (extracted note commitment)
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

/// Open the wallet database and return a network value.
pub(super) fn open_wallet_db(
    wallet_db_path: &str,
    network_id: u32,
) -> anyhow::Result<(
    zcash_client_sqlite::WalletDb<rusqlite::Connection, Network, SystemClock, rand::rngs::OsRng>,
    Network,
)> {
    let network = match network_id {
        0 => Network::MainNetwork,
        1 => Network::TestNetwork,
        _ => return Err(anyhow!("invalid network_id {}", network_id)),
    };
    let wallet_db = zcash_client_sqlite::WalletDb::for_path(
        wallet_db_path,
        network,
        SystemClock,
        rand::rngs::OsRng,
    )
    .map_err(|e| anyhow!("failed to open wallet DB: {}", e))?;
    Ok((wallet_db, network))
}

/// Open the wallet database for tree operations that do not consult the
/// `Network` type parameter. `WalletDb` still requires a network value, so we
/// use mainnet here and keep the invariant local to this helper.
pub(super) fn open_wallet_db_for_tree_ops(
    wallet_db_path: &str,
) -> anyhow::Result<
    zcash_client_sqlite::WalletDb<rusqlite::Connection, Network, SystemClock, rand::rngs::OsRng>,
> {
    zcash_client_sqlite::WalletDb::for_path(
        wallet_db_path,
        Network::MainNetwork,
        SystemClock,
        rand::rngs::OsRng,
    )
    .map_err(|e| anyhow!("failed to open wallet DB for tree operations: {}", e))
}

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
    let usk = match network_id {
        0 => UnifiedSpendingKey::from_seed(&MAIN_NETWORK, seed, account),
        1 => UnifiedSpendingKey::from_seed(&TEST_NETWORK, seed, account),
        _ => {
            return Err(anyhow!(
                "invalid network_id {}, expected 0 (mainnet) or 1 (testnet)",
                network_id
            ));
        }
    }
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
    account: AccountId,
) -> anyhow::Result<HotkeySideInputs> {
    let hotkey_usk = usk_from_seed(network_id, hotkey_seed, account)
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
