#![allow(clippy::missing_safety_doc)]

//! Hand-rolled C FFI for the voting functionality.
//!
//! Follows the same patterns as `lib.rs` and `ffi.rs`:
//! - Functions: `#[unsafe(no_mangle)] pub unsafe extern "C" fn zcashlc_voting_*()`
//! - Error handling: `catch_panic()` + `unwrap_exc_or_null()` / `unwrap_exc_or()`
//! - Opaque pointers: `Box::into_raw(Box::new(obj))` to create, `Box::from_raw(ptr)` to free
//! - Complex types: JSON serialization via serde across the FFI boundary
//! - Simple return types: `#[repr(C)]` structs

use std::ffi::CString;
use std::os::raw::c_char;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
use incrementalmerkletree::Position;
use orchard::note::ExtractedNoteCommitment;
use orchard::tree::MerkleHashOrchard;
use prost::Message;
use serde::{Deserialize, Serialize};
use zcash_client_backend::proto::service::TreeState;
use zcash_client_sqlite::util::SystemClock;
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_protocol::consensus::{self, MAIN_NETWORK, Network, TEST_NETWORK};
use zip32::{AccountId, Scope};

use librustvoting as voting;
use voting::storage::VotingDb;
use voting::tree_sync::VoteTreeSync;

use crate::{unwrap_exc_or, unwrap_exc_or_null};

// =============================================================================
// Helper functions
// =============================================================================

/// Parse a UTF-8 string from raw pointer + length.
///
/// # Safety
///
/// - `ptr` must be non-null and valid for reads for `len` bytes.
/// - The memory referenced by `ptr` must not be mutated for the duration of the call.
unsafe fn str_from_ptr(ptr: *const u8, len: usize) -> anyhow::Result<String> {
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    Ok(std::str::from_utf8(bytes)?.to_string())
}

/// Parse a byte slice from raw pointer + length.
///
/// # Safety
///
/// - `ptr` must be non-null and valid for reads for `len` bytes.
/// - The memory referenced by `ptr` must not be mutated for the duration of the call.
unsafe fn bytes_from_ptr<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    unsafe { std::slice::from_raw_parts(ptr, len) }
}


/// Return JSON-serialized bytes as `*mut ffi::BoxedSlice`.
fn json_to_boxed_slice<T: Serialize>(value: &T) -> anyhow::Result<*mut crate::ffi::BoxedSlice> {
    let json = serde_json::to_vec(value)?;
    Ok(crate::ffi::BoxedSlice::some(json))
}

/// Convert a librustzcash ReceivedNote (orchard) into librustvoting's NoteInfo.
///
/// Requires the account's UFVK and network to compute the nullifier and
/// encode the UFVK string.
fn received_note_to_note_info<P: consensus::Parameters>(
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
fn open_wallet_db(
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

// =============================================================================
// Serde-compatible types for JSON serialization across the FFI boundary
// =============================================================================

/// JSON-serializable NoteInfo.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonNoteInfo {
    pub commitment: Vec<u8>,
    pub nullifier: Vec<u8>,
    pub value: u64,
    pub position: u64,
    pub diversifier: Vec<u8>,
    pub rho: Vec<u8>,
    pub rseed: Vec<u8>,
    pub scope: u32,
    pub ufvk_str: String,
}

impl From<JsonNoteInfo> for voting::NoteInfo {
    fn from(n: JsonNoteInfo) -> Self {
        Self {
            commitment: n.commitment,
            nullifier: n.nullifier,
            value: n.value,
            position: n.position,
            diversifier: n.diversifier,
            rho: n.rho,
            rseed: n.rseed,
            scope: n.scope,
            ufvk_str: n.ufvk_str,
        }
    }
}

impl From<voting::NoteInfo> for JsonNoteInfo {
    fn from(n: voting::NoteInfo) -> Self {
        Self {
            commitment: n.commitment,
            nullifier: n.nullifier,
            value: n.value,
            position: n.position,
            diversifier: n.diversifier,
            rho: n.rho,
            rseed: n.rseed,
            scope: n.scope,
            ufvk_str: n.ufvk_str,
        }
    }
}

/// JSON-serializable GovernancePczt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonGovernancePczt {
    pub pczt_bytes: Vec<u8>,
    pub rk: Vec<u8>,
    pub alpha: Vec<u8>,
    pub nf_signed: Vec<u8>,
    pub cmx_new: Vec<u8>,
    pub gov_nullifiers: Vec<Vec<u8>>,
    pub van: Vec<u8>,
    pub van_comm_rand: Vec<u8>,
    pub dummy_nullifiers: Vec<Vec<u8>>,
    pub rho_signed: Vec<u8>,
    pub padded_cmx: Vec<Vec<u8>>,
    pub rseed_signed: Vec<u8>,
    pub rseed_output: Vec<u8>,
    pub action_bytes: Vec<u8>,
    pub action_index: u32,
    /// padded_note_secrets: list of [rho, rseed] pairs
    pub padded_note_secrets: Vec<Vec<Vec<u8>>>,
    pub pczt_sighash: Vec<u8>,
}

impl From<voting::GovernancePczt> for JsonGovernancePczt {
    fn from(g: voting::GovernancePczt) -> Self {
        Self {
            pczt_bytes: g.pczt_bytes,
            rk: g.rk,
            alpha: g.alpha,
            nf_signed: g.nf_signed,
            cmx_new: g.cmx_new,
            gov_nullifiers: g.gov_nullifiers,
            van: g.van,
            van_comm_rand: g.van_comm_rand,
            dummy_nullifiers: g.dummy_nullifiers,
            rho_signed: g.rho_signed,
            padded_cmx: g.padded_cmx,
            rseed_signed: g.rseed_signed,
            rseed_output: g.rseed_output,
            action_bytes: g.action_bytes,
            action_index: g.action_index as u32,
            padded_note_secrets: g
                .padded_note_secrets
                .into_iter()
                .map(|(rho, rseed)| vec![rho, rseed])
                .collect(),
            pczt_sighash: g.pczt_sighash,
        }
    }
}

/// JSON-serializable WitnessData.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonWitnessData {
    pub note_commitment: Vec<u8>,
    pub position: u64,
    pub root: Vec<u8>,
    pub auth_path: Vec<Vec<u8>>,
}

impl From<voting::WitnessData> for JsonWitnessData {
    fn from(w: voting::WitnessData) -> Self {
        Self {
            note_commitment: w.note_commitment,
            position: w.position,
            root: w.root,
            auth_path: w.auth_path,
        }
    }
}

impl From<JsonWitnessData> for voting::WitnessData {
    fn from(w: JsonWitnessData) -> Self {
        Self {
            note_commitment: w.note_commitment,
            position: w.position,
            root: w.root,
            auth_path: w.auth_path,
        }
    }
}

/// JSON-serializable DelegationProofResult.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonDelegationProofResult {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<Vec<u8>>,
    pub nf_signed: Vec<u8>,
    pub cmx_new: Vec<u8>,
    pub gov_nullifiers: Vec<Vec<u8>>,
    pub van_comm: Vec<u8>,
    pub rk: Vec<u8>,
}

impl From<voting::DelegationProofResult> for JsonDelegationProofResult {
    fn from(r: voting::DelegationProofResult) -> Self {
        Self {
            proof: r.proof,
            public_inputs: r.public_inputs,
            nf_signed: r.nf_signed,
            cmx_new: r.cmx_new,
            gov_nullifiers: r.gov_nullifiers,
            van_comm: r.van_comm,
            rk: r.rk,
        }
    }
}

/// JSON-serializable DelegationSubmission.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonDelegationSubmission {
    pub rk: Vec<u8>,
    pub spend_auth_sig: Vec<u8>,
    pub sighash: Vec<u8>,
    pub nf_signed: Vec<u8>,
    pub cmx_new: Vec<u8>,
    pub gov_comm: Vec<u8>,
    pub gov_nullifiers: Vec<Vec<u8>>,
    pub proof: Vec<u8>,
    pub vote_round_id: String,
}

impl From<voting::DelegationSubmissionData> for JsonDelegationSubmission {
    fn from(d: voting::DelegationSubmissionData) -> Self {
        Self {
            rk: d.rk,
            spend_auth_sig: d.spend_auth_sig,
            sighash: d.sighash,
            nf_signed: d.nf_signed,
            cmx_new: d.cmx_new,
            gov_comm: d.gov_comm,
            gov_nullifiers: d.gov_nullifiers,
            proof: d.proof,
            vote_round_id: d.vote_round_id,
        }
    }
}

impl From<voting::EncryptedShare> for JsonWireEncryptedShare {
    fn from(s: voting::EncryptedShare) -> Self {
        Self {
            c1: s.c1,
            c2: s.c2,
            share_index: s.share_index,
        }
    }
}

impl From<JsonWireEncryptedShare> for voting::WireEncryptedShare {
    fn from(s: JsonWireEncryptedShare) -> Self {
        Self {
            c1: s.c1,
            c2: s.c2,
            share_index: s.share_index,
        }
    }
}

/// JSON-serializable VoteCommitmentBundle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonVoteCommitmentBundle {
    pub van_nullifier: Vec<u8>,
    pub vote_authority_note_new: Vec<u8>,
    pub vote_commitment: Vec<u8>,
    pub proposal_id: u32,
    pub proof: Vec<u8>,
    pub enc_shares: Vec<JsonWireEncryptedShare>,
    pub anchor_height: u32,
    pub vote_round_id: String,
    pub shares_hash: Vec<u8>,
    pub share_blinds: Vec<Vec<u8>>,
    pub share_comms: Vec<Vec<u8>>,
    pub r_vpk_bytes: Vec<u8>,
    pub alpha_v: Vec<u8>,
}

impl From<voting::VoteCommitmentBundle> for JsonVoteCommitmentBundle {
    fn from(b: voting::VoteCommitmentBundle) -> Self {
        Self {
            van_nullifier: b.van_nullifier,
            vote_authority_note_new: b.vote_authority_note_new,
            vote_commitment: b.vote_commitment,
            proposal_id: b.proposal_id,
            proof: b.proof,
            enc_shares: b.enc_shares.into_iter().map(Into::into).collect(),
            anchor_height: b.anchor_height,
            vote_round_id: b.vote_round_id,
            shares_hash: b.shares_hash,
            share_blinds: b.share_blinds,
            share_comms: b.share_comms,
            r_vpk_bytes: b.r_vpk_bytes,
            alpha_v: b.alpha_v,
        }
    }
}

impl From<JsonVoteCommitmentBundle> for voting::VoteCommitmentBundle {
    fn from(b: JsonVoteCommitmentBundle) -> Self {
        Self {
            van_nullifier: b.van_nullifier,
            vote_authority_note_new: b.vote_authority_note_new,
            vote_commitment: b.vote_commitment,
            proposal_id: b.proposal_id,
            proof: b.proof,
            // enc_shares with secrets are not sent across FFI; wire shares are
            // passed separately to build_share_payloads, so this is unused.
            enc_shares: Vec::new(),
            anchor_height: b.anchor_height,
            vote_round_id: b.vote_round_id,
            shares_hash: b.shares_hash,
            share_blinds: b.share_blinds,
            share_comms: b.share_comms,
            r_vpk_bytes: b.r_vpk_bytes,
            alpha_v: b.alpha_v,
        }
    }
}

/// Wire-safe encrypted share that omits secret fields (plaintext_value, randomness).
/// Used in SharePayload which is sent to the helper server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonWireEncryptedShare {
    pub c1: Vec<u8>,
    pub c2: Vec<u8>,
    pub share_index: u32,
}

/// JSON-serializable SharePayload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonSharePayload {
    pub shares_hash: Vec<u8>,
    pub proposal_id: u32,
    pub vote_decision: u32,
    pub enc_share: JsonWireEncryptedShare,
    pub tree_position: u64,
    pub all_enc_shares: Vec<JsonWireEncryptedShare>,
    pub share_comms: Vec<Vec<u8>>,
    pub primary_blind: Vec<u8>,
}

impl From<voting::SharePayload> for JsonSharePayload {
    fn from(p: voting::SharePayload) -> Self {
        Self {
            shares_hash: p.shares_hash,
            proposal_id: p.proposal_id,
            vote_decision: p.vote_decision,
            enc_share: JsonWireEncryptedShare {
                c1: p.enc_share.c1,
                c2: p.enc_share.c2,
                share_index: p.enc_share.share_index,
            },
            tree_position: p.tree_position,
            all_enc_shares: p.all_enc_shares
                .into_iter()
                .map(|s| JsonWireEncryptedShare {
                    c1: s.c1,
                    c2: s.c2,
                    share_index: s.share_index,
                })
                .collect(),
            share_comms: p.share_comms,
            primary_blind: p.primary_blind,
        }
    }
}

impl From<voting::WireEncryptedShare> for JsonWireEncryptedShare {
    fn from(s: voting::WireEncryptedShare) -> Self {
        Self {
            c1: s.c1,
            c2: s.c2,
            share_index: s.share_index,
        }
    }
}

/// JSON-serializable CastVoteSignature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonCastVoteSignature {
    pub vote_auth_sig: Vec<u8>,
}

impl From<voting::CastVoteSignature> for JsonCastVoteSignature {
    fn from(s: voting::CastVoteSignature) -> Self {
        Self {
            vote_auth_sig: s.vote_auth_sig,
        }
    }
}

/// JSON-serializable DelegationInputs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonDelegationInputs {
    pub fvk_bytes: Vec<u8>,
    pub g_d_new_x: Vec<u8>,
    pub pk_d_new_x: Vec<u8>,
    pub hotkey_raw_address: Vec<u8>,
    pub hotkey_public_key: Vec<u8>,
    pub hotkey_address: String,
    pub seed_fingerprint: Vec<u8>,
}

/// JSON-serializable VanWitness.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonVanWitness {
    pub auth_path: Vec<Vec<u8>>,
    pub position: u32,
    pub anchor_height: u32,
}

impl From<voting::tree_sync::VanWitness> for JsonVanWitness {
    fn from(w: voting::tree_sync::VanWitness) -> Self {
        Self {
            auth_path: w.auth_path.iter().map(|h| h.to_vec()).collect(),
            position: w.position,
            anchor_height: w.anchor_height,
        }
    }
}

// =============================================================================
// Progress callback
// =============================================================================

/// C function pointer type for proof progress reporting.
pub type VotingProgressCallback =
    unsafe extern "C" fn(progress: f64, context: *mut std::ffi::c_void);

/// Bridges a C function pointer to the `ProofProgressReporter` trait.
struct ProgressBridge {
    callback: VotingProgressCallback,
    context: *mut std::ffi::c_void,
}

// SAFETY: The caller guarantees the context pointer is valid for the duration
// of the proof operation and that the callback is thread-safe.
unsafe impl Send for ProgressBridge {}
unsafe impl Sync for ProgressBridge {}

impl voting::ProofProgressReporter for ProgressBridge {
    fn on_progress(&self, progress: f64) {
        unsafe { (self.callback)(progress, self.context) }
    }
}

// =============================================================================
// #[repr(C)] structs for simple, frequently-accessed return types
// =============================================================================

/// Round state returned by `zcashlc_voting_get_round_state`.
#[repr(C)]
pub struct FfiRoundState {
    round_id: *mut c_char,
    /// 0=Initialized, 1=HotkeyGenerated, 2=DelegationConstructed,
    /// 3=DelegationProved, 4=VoteReady
    phase: u32,
    snapshot_height: u64,
    /// Nullable — null if no hotkey has been generated yet.
    hotkey_address: *mut c_char,
    /// -1 if None, otherwise the delegated weight value.
    delegated_weight: i64,
    proof_generated: bool,
}

/// Voting hotkey returned by `zcashlc_voting_generate_hotkey`.
#[repr(C)]
pub struct FfiVotingHotkey {
    secret_key: *mut u8,
    secret_key_len: usize,
    public_key: *mut u8,
    public_key_len: usize,
    address: *mut c_char,
}

/// Bundle setup result returned by `zcashlc_voting_setup_bundles`.
#[repr(C)]
pub struct FfiBundleSetupResult {
    bundle_count: u32,
    eligible_weight: u64,
}

/// Round summary for list display.
#[repr(C)]
pub struct FfiRoundSummary {
    round_id: *mut c_char,
    phase: u32,
    snapshot_height: u64,
    created_at: u64,
}

/// Array of round summaries.
#[repr(C)]
pub struct FfiRoundSummaries {
    ptr: *mut FfiRoundSummary,
    len: usize,
}

/// Vote record for a single proposal/bundle.
#[repr(C)]
pub struct FfiVoteRecord {
    proposal_id: u32,
    bundle_index: u32,
    choice: u32,
    submitted: bool,
}

/// Array of vote records.
#[repr(C)]
pub struct FfiVoteRecords {
    ptr: *mut FfiVoteRecord,
    len: usize,
}

// =============================================================================
// A. VotingDatabase opaque handle
// =============================================================================

/// Opaque handle wrapping the voting database and tree sync state.
pub struct VotingDatabaseHandle {
    db: Arc<VotingDb>,
    tree_sync: VoteTreeSync,
}

/// Open a voting database at the given path.
///
/// Returns an opaque `*mut VotingDatabaseHandle` on success, or null on error.
///
/// # Safety
///
/// - `path` must be non-null and valid for reads for `path_len` bytes.
/// - The memory referenced by `path` must not be mutated for the duration of the call.
/// - Call `zcashlc_voting_db_free` to free the returned handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_db_open(
    path: *const u8,
    path_len: usize,
) -> *mut VotingDatabaseHandle {
    let res = catch_panic(|| {
        let path_str = unsafe { str_from_ptr(path, path_len) }?;
        let db = VotingDb::open(&path_str)
            .map_err(|e| anyhow!("Error opening voting database: {}", e))?;
        Ok(Box::into_raw(Box::new(VotingDatabaseHandle {
            db: Arc::new(db),
            tree_sync: VoteTreeSync::new(),
        })))
    });
    unwrap_exc_or_null(res)
}

/// Free a VotingDatabaseHandle.
///
/// # Safety
///
/// - If `ptr` is non-null, it must be a pointer previously returned by
///   `zcashlc_voting_db_open` that has not already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_db_free(ptr: *mut VotingDatabaseHandle) {
    if !ptr.is_null() {
        let s: Box<VotingDatabaseHandle> = unsafe { Box::from_raw(ptr) };
        drop(s);
    }
}

/// Set the wallet identifier for all subsequent voting operations.
/// Must be called after `zcashlc_voting_db_open` and before any round operations.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - `wallet_id` must be valid for reads of `wallet_id_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_set_wallet_id(
    db: *mut VotingDatabaseHandle,
    wallet_id: *const u8,
    wallet_id_len: usize,
) -> i32 {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let wallet_id_str = unsafe { str_from_ptr(wallet_id, wallet_id_len) }?;
        handle.db.set_wallet_id(&wallet_id_str);
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}

// =============================================================================
// Free functions for #[repr(C)] return types
// =============================================================================

/// Free an `FfiRoundState` value.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct returned by
///   `zcashlc_voting_get_round_state`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_free_round_state(ptr: *mut FfiRoundState) {
    if !ptr.is_null() {
        let s: Box<FfiRoundState> = unsafe { Box::from_raw(ptr) };
        if !s.round_id.is_null() {
            drop(unsafe { CString::from_raw(s.round_id) });
        }
        if !s.hotkey_address.is_null() {
            drop(unsafe { CString::from_raw(s.hotkey_address) });
        }
        drop(s);
    }
}

/// Free an `FfiVotingHotkey` value.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct returned by
///   `zcashlc_voting_generate_hotkey` or `zcashlc_voting_generate_hotkey_standalone`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_free_hotkey(ptr: *mut FfiVotingHotkey) {
    if !ptr.is_null() {
        let s: Box<FfiVotingHotkey> = unsafe { Box::from_raw(ptr) };
        if !s.secret_key.is_null() {
            crate::free_ptr_from_vec(s.secret_key, s.secret_key_len);
        }
        if !s.public_key.is_null() {
            crate::free_ptr_from_vec(s.public_key, s.public_key_len);
        }
        if !s.address.is_null() {
            drop(unsafe { CString::from_raw(s.address) });
        }
        drop(s);
    }
}

/// Free an `FfiBundleSetupResult` value.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct returned by
///   `zcashlc_voting_setup_bundles`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_free_bundle_setup_result(ptr: *mut FfiBundleSetupResult) {
    if !ptr.is_null() {
        let s: Box<FfiBundleSetupResult> = unsafe { Box::from_raw(ptr) };
        drop(s);
    }
}

/// Free an `FfiRoundSummaries` value.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct returned by
///   `zcashlc_voting_list_rounds`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_free_round_summaries(ptr: *mut FfiRoundSummaries) {
    if !ptr.is_null() {
        let s: Box<FfiRoundSummaries> = unsafe { Box::from_raw(ptr) };
        if !s.ptr.is_null() {
            let summaries =
                unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(s.ptr, s.len)) };
            for summary in summaries.iter() {
                if !summary.round_id.is_null() {
                    drop(unsafe { CString::from_raw(summary.round_id) });
                }
            }
            drop(summaries);
        }
        drop(s);
    }
}

/// Free an `FfiVoteRecords` value.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct returned by
///   `zcashlc_voting_get_votes`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_free_vote_records(ptr: *mut FfiVoteRecords) {
    if !ptr.is_null() {
        let s: Box<FfiVoteRecords> = unsafe { Box::from_raw(ptr) };
        if !s.ptr.is_null() {
            let records =
                unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(s.ptr, s.len)) };
            drop(records);
        }
        drop(s);
    }
}

// =============================================================================
// B. VotingDatabase methods — Round management
// =============================================================================

/// Initialize a voting round.
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
        let handle = unsafe { db.as_ref() }
            .ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let ea_pk_bytes = unsafe { bytes_from_ptr(ea_pk, ea_pk_len) }.to_vec();
        let nc_root_bytes = unsafe { bytes_from_ptr(nc_root, nc_root_len) }.to_vec();
        let nullifier_imt_root_bytes =
            unsafe { bytes_from_ptr(nullifier_imt_root, nullifier_imt_root_len) }.to_vec();

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

        handle
            .db
            .init_round(&params, session.as_deref())
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
        let handle = unsafe { db.as_ref() }
            .ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;

        let state = handle
            .db
            .get_round_state(&round_id_str)
            .map_err(|e| anyhow!("get_round_state failed: {}", e))?;

        let phase = match state.phase {
            voting::storage::RoundPhase::Initialized => 0,
            voting::storage::RoundPhase::HotkeyGenerated => 1,
            voting::storage::RoundPhase::DelegationConstructed => 2,
            voting::storage::RoundPhase::DelegationProved => 3,
            voting::storage::RoundPhase::VoteReady => 4,
        };

        let ffi_state = FfiRoundState {
            round_id: CString::new(state.round_id)
                .map_err(|e| anyhow!("invalid round_id string: {}", e))?
                .into_raw(),
            phase,
            snapshot_height: state.snapshot_height,
            hotkey_address: match state.hotkey_address {
                Some(addr) => CString::new(addr)
                    .map_err(|e| anyhow!("invalid hotkey_address string: {}", e))?
                    .into_raw(),
                None => std::ptr::null_mut(),
            },
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

        let ffi_rounds: Vec<FfiRoundSummary> = rounds
            .into_iter()
            .map(|s| {
                let phase = match s.phase {
                    voting::storage::RoundPhase::Initialized => 0,
                    voting::storage::RoundPhase::HotkeyGenerated => 1,
                    voting::storage::RoundPhase::DelegationConstructed => 2,
                    voting::storage::RoundPhase::DelegationProved => 3,
                    voting::storage::RoundPhase::VoteReady => 4,
                };
                FfiRoundSummary {
                    round_id: CString::new(s.round_id).unwrap().into_raw(),
                    phase,
                    snapshot_height: s.snapshot_height,
                    created_at: s.created_at,
                }
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

        let ffi_votes: Vec<FfiVoteRecord> = votes
            .into_iter()
            .map(|v| FfiVoteRecord {
                proposal_id: v.proposal_id,
                bundle_index: v.bundle_index,
                choice: v.choice,
                submitted: v.submitted,
            })
            .collect();

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
/// Returns the number of deleted rows on success (>= 0), or -1 on error.
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

// =============================================================================
// B. VotingDatabase methods — Wallet notes
// =============================================================================

/// Get wallet notes eligible for voting at the given snapshot height.
///
/// Returns JSON-encoded `Vec<NoteInfo>` as `*mut FfiBoxedSlice`, or null on error.
///
/// When `account_uuid` is non-null and 16 bytes, it is used directly to look up the
/// account. Otherwise falls back to positional `account_index` into `get_account_ids()`.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - `wallet_db_path` must be a valid path for reads of `wallet_db_path_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_wallet_notes(
    db: *mut VotingDatabaseHandle,
    wallet_db_path: *const u8,
    wallet_db_path_len: usize,
    snapshot_height: u64,
    network_id: u32,
    account_uuid: *const u8,
    account_uuid_len: usize,
    account_index: i64,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let _handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let wallet_path_str = unsafe { str_from_ptr(wallet_db_path, wallet_db_path_len) }?;

        let (wallet_db, network) = open_wallet_db(&wallet_path_str, network_id)?;

        use zcash_client_backend::data_api::WalletRead;
        let target_id = if !account_uuid.is_null() && account_uuid_len == 16 {
            let uuid_bytes = unsafe { bytes_from_ptr(account_uuid, account_uuid_len) };
            let arr: [u8; 16] = uuid_bytes
                .try_into()
                .map_err(|_| anyhow!("account_uuid must be 16 bytes"))?;
            zcash_client_sqlite::AccountUuid::from_uuid(uuid::Uuid::from_bytes(arr))
        } else {
            // Legacy fallback: positional index into account list.
            let acct_idx = if account_index < 0 {
                None
            } else {
                Some(account_index as u32)
            };
            let account_ids = wallet_db.get_account_ids()?;
            match acct_idx {
                Some(idx) => account_ids
                    .get(idx as usize)
                    .copied()
                    .ok_or_else(|| anyhow!("account_index {} out of range (wallet has {} accounts)", idx, account_ids.len()))?,
                None => *account_ids
                    .first()
                    .ok_or_else(|| anyhow!("no accounts in wallet"))?,
            }
        };
        let account = wallet_db
            .get_account(target_id)?
            .ok_or_else(|| anyhow!("account not found"))?;

        use zcash_client_backend::data_api::Account;
        let ufvk = account.ufvk()
            .ok_or_else(|| anyhow!("account has no UFVK"))?;
        let account_uuid = account.id();

        let height = zcash_protocol::consensus::BlockHeight::from_u32(snapshot_height as u32);
        let received_notes = wallet_db
            .get_orchard_notes_at_snapshot(account_uuid, height)
            .map_err(|e| anyhow!("get_orchard_notes_at_snapshot failed: {}", e))?;

        let mut json_notes = Vec::with_capacity(received_notes.len());
        for rn in &received_notes {
            let note_info = received_note_to_note_info(rn, ufvk, &network)?;
            json_notes.push(JsonNoteInfo::from(note_info));
        }
        json_to_boxed_slice(&json_notes)
    });
    unwrap_exc_or_null(res)
}

// =============================================================================
// B. VotingDatabase methods — Delegation setup
// =============================================================================

/// Generate a voting hotkey for a round.
///
/// Returns a pointer to `FfiVotingHotkey` on success, or null on error.
/// Call `zcashlc_voting_free_hotkey` to free the returned pointer.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_generate_hotkey(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    seed: *const u8,
    seed_len: usize,
) -> *mut FfiVotingHotkey {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let seed_bytes = unsafe { bytes_from_ptr(seed, seed_len) };

        let hotkey = handle
            .db
            .generate_hotkey(&round_id_str, seed_bytes)
            .map_err(|e| anyhow!("generate_hotkey failed: {}", e))?;

        Ok(Box::into_raw(Box::new(voting_hotkey_to_ffi(hotkey))))
    });
    unwrap_exc_or_null(res)
}

/// Set up note bundles for a voting round.
///
/// `notes_json` is a JSON-encoded `Vec<NoteInfo>`.
///
/// Returns a pointer to `FfiBundleSetupResult` on success, or null on error.
/// Call `zcashlc_voting_free_bundle_setup_result` to free the returned pointer.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_setup_bundles(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    notes_json: *const u8,
    notes_json_len: usize,
) -> *mut FfiBundleSetupResult {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let notes_bytes = unsafe { bytes_from_ptr(notes_json, notes_json_len) };
        let json_notes: Vec<JsonNoteInfo> = serde_json::from_slice(notes_bytes)?;
        let core_notes: Vec<voting::NoteInfo> = json_notes.into_iter().map(Into::into).collect();

        let (count, weight) = handle
            .db
            .setup_bundles(&round_id_str, &core_notes)
            .map_err(|e| anyhow!("setup_bundles failed: {}", e))?;

        Ok(Box::into_raw(Box::new(FfiBundleSetupResult {
            bundle_count: count,
            eligible_weight: weight,
        })))
    });
    unwrap_exc_or_null(res)
}

/// Get the number of bundles for a round.
///
/// Returns the bundle count on success (>= 0), or -1 on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_bundle_count(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
) -> i64 {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;

        let count = handle
            .db
            .get_bundle_count(&round_id_str)
            .map_err(|e| anyhow!("get_bundle_count failed: {}", e))?;
        Ok(count as i64)
    });
    unwrap_exc_or(res, -1)
}

/// Build a governance PCZT for a bundle.
///
/// `notes_json` is a JSON-encoded `Vec<NoteInfo>`.
///
/// Returns JSON-encoded `GovernancePczt` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - All pointer/length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_build_governance_pczt(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    notes_json: *const u8,
    notes_json_len: usize,
    fvk_bytes: *const u8,
    fvk_bytes_len: usize,
    hotkey_raw_address: *const u8,
    hotkey_raw_address_len: usize,
    consensus_branch_id: u32,
    coin_type: u32,
    seed_fingerprint: *const u8,
    seed_fingerprint_len: usize,
    account_index: u32,
    round_name: *const u8,
    round_name_len: usize,
    address_index: u32,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let notes_bytes = unsafe { bytes_from_ptr(notes_json, notes_json_len) };
        let json_notes: Vec<JsonNoteInfo> = serde_json::from_slice(notes_bytes)?;
        let core_notes: Vec<voting::NoteInfo> = json_notes.into_iter().map(Into::into).collect();
        let fvk = unsafe { bytes_from_ptr(fvk_bytes, fvk_bytes_len) };
        let hotkey_addr = unsafe { bytes_from_ptr(hotkey_raw_address, hotkey_raw_address_len) };
        let seed_fp_bytes = unsafe { bytes_from_ptr(seed_fingerprint, seed_fingerprint_len) };
        let seed_fp_32: [u8; 32] = seed_fp_bytes.try_into().map_err(|_| {
            anyhow!("seed_fingerprint must be 32 bytes, got {}", seed_fp_bytes.len())
        })?;
        let round_name_str = unsafe { str_from_ptr(round_name, round_name_len) }?;

        let pczt = handle
            .db
            .build_governance_pczt(
                &round_id_str,
                bundle_index,
                &core_notes,
                fvk,
                hotkey_addr,
                consensus_branch_id,
                coin_type,
                &seed_fp_32,
                account_index,
                &round_name_str,
                address_index,
            )
            .map_err(|e| anyhow!("build_governance_pczt failed: {}", e))?;

        let json_pczt: JsonGovernancePczt = pczt.into();
        json_to_boxed_slice(&json_pczt)
    });
    unwrap_exc_or_null(res)
}

/// Store a tree state for witness generation.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_store_tree_state(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    tree_state_bytes: *const u8,
    tree_state_bytes_len: usize,
) -> i32 {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let ts_bytes = unsafe { bytes_from_ptr(tree_state_bytes, tree_state_bytes_len) };

        handle
            .db
            .store_tree_state(&round_id_str, ts_bytes)
            .map_err(|e| anyhow!("store_tree_state failed: {}", e))?;
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}

/// Generate Merkle inclusion witnesses for notes in a bundle.
///
/// `notes_json` is a JSON-encoded `Vec<NoteInfo>`.
///
/// Returns JSON-encoded `Vec<WitnessData>` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_generate_note_witnesses(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    wallet_db_path: *const u8,
    wallet_db_path_len: usize,
    notes_json: *const u8,
    notes_json_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let wallet_path_str = unsafe { str_from_ptr(wallet_db_path, wallet_db_path_len) }?;
        let notes_bytes = unsafe { bytes_from_ptr(notes_json, notes_json_len) };
        let json_notes: Vec<JsonNoteInfo> = serde_json::from_slice(notes_bytes)?;
        let core_notes: Vec<voting::NoteInfo> = json_notes.into_iter().map(Into::into).collect();

        // Load cached tree state from voting DB and parse frontier
        let wallet_id = handle.db.wallet_id();
        let conn = handle.db.conn();
        let tree_state_bytes = voting::storage::queries::load_tree_state(&conn, &round_id_str, &wallet_id)
            .map_err(|e| anyhow!("load_tree_state failed: {}", e))?;
        let params = voting::storage::queries::load_round_params(&conn, &round_id_str, &wallet_id)
            .map_err(|e| anyhow!("load_round_params failed: {}", e))?;
        drop(conn);

        let tree_state = TreeState::decode(tree_state_bytes.as_slice())
            .map_err(|e| anyhow!("failed to decode TreeState protobuf: {}", e))?;
        let orchard_ct = tree_state.orchard_tree()
            .map_err(|e| anyhow!("failed to parse orchard tree from TreeState: {}", e))?;
        let frontier_root = orchard_ct.root();
        let frontier = orchard_ct.to_frontier();
        let nonempty_frontier = frontier.take()
            .ok_or_else(|| anyhow!("empty orchard frontier — no orchard activity at snapshot height"))?;

        // Generate witnesses from wallet DB shard data + frontier
        let (wallet_db, _network) = open_wallet_db(&wallet_path_str, 0)?; // network_id not needed for tree ops
        let positions: Vec<Position> = core_notes
            .iter()
            .map(|n| Position::from(n.position))
            .collect();
        let checkpoint_height = zcash_protocol::consensus::BlockHeight::from_u32(params.snapshot_height as u32);

        let merkle_paths = wallet_db
            .generate_orchard_witnesses_at_frontier(&positions, nonempty_frontier, checkpoint_height)
            .map_err(|e| anyhow!("generate_orchard_witnesses_at_frontier failed: {}", e))?;

        // Convert MerklePaths to WitnessData
        let root_bytes = frontier_root.to_bytes().to_vec();
        let witnesses: Vec<voting::WitnessData> = merkle_paths
            .into_iter()
            .zip(core_notes.iter())
            .map(|(path, note): (incrementalmerkletree::MerklePath<MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>, &voting::NoteInfo)| {
                let auth_path: Vec<Vec<u8>> = path.path_elems()
                    .iter()
                    .map(|h: &MerkleHashOrchard| h.to_bytes().to_vec())
                    .collect();
                voting::WitnessData {
                    note_commitment: note.commitment.clone(),
                    position: note.position,
                    root: root_bytes.clone(),
                    auth_path,
                }
            })
            .collect();

        // Verify and cache in voting DB
        handle.db.store_witnesses(&round_id_str, bundle_index, &witnesses)
            .map_err(|e| anyhow!("store_witnesses failed: {}", e))?;

        let json_witnesses: Vec<JsonWitnessData> =
            witnesses.into_iter().map(Into::into).collect();
        json_to_boxed_slice(&json_witnesses)
    });
    unwrap_exc_or_null(res)
}

// =============================================================================
// B. VotingDatabase methods — Delegation proof
// =============================================================================

/// Build and prove the real delegation ZKP (#1). Long-running.
///
/// Returns JSON-encoded `DelegationProofResult` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - `progress_callback` must be a valid function pointer (or null to skip progress).
/// - `progress_context` is passed through to the callback unchanged.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_build_and_prove_delegation(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    notes_json: *const u8,
    notes_json_len: usize,
    hotkey_raw_address: *const u8,
    hotkey_raw_address_len: usize,
    pir_server_url: *const u8,
    pir_server_url_len: usize,
    network_id: u32,
    progress_callback: Option<unsafe extern "C" fn(f64, *mut std::ffi::c_void)>,
    progress_context: *mut std::ffi::c_void,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let progress_context = AssertUnwindSafe(progress_context);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let notes_bytes = unsafe { bytes_from_ptr(notes_json, notes_json_len) };
        let json_notes: Vec<JsonNoteInfo> = serde_json::from_slice(notes_bytes)?;
        let core_notes: Vec<voting::NoteInfo> = json_notes.into_iter().map(Into::into).collect();
        let hotkey_addr = unsafe { bytes_from_ptr(hotkey_raw_address, hotkey_raw_address_len) };
        let pir_url = unsafe { str_from_ptr(pir_server_url, pir_server_url_len) }?;

        let reporter: Box<dyn voting::ProofProgressReporter> = match progress_callback {
            Some(cb) => Box::new(ProgressBridge {
                callback: cb,
                context: *progress_context,
            }),
            None => Box::new(voting::NoopProgressReporter),
        };

        let result = handle
            .db
            .build_and_prove_delegation(
                &round_id_str,
                bundle_index,
                &core_notes,
                hotkey_addr,
                &pir_url,
                network_id,
                reporter.as_ref(),
            )
            .map_err(|e| anyhow!("build_and_prove_delegation failed: {}", e))?;

        let json_result: JsonDelegationProofResult = result.into();
        json_to_boxed_slice(&json_result)
    });
    unwrap_exc_or_null(res)
}

/// Get the delegation submission payload using a seed-derived signing key.
///
/// Returns JSON-encoded `DelegationSubmission` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_delegation_submission(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    sender_seed: *const u8,
    sender_seed_len: usize,
    network_id: u32,
    account_index: u32,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let seed = unsafe { bytes_from_ptr(sender_seed, sender_seed_len) };

        let submission = handle
            .db
            .get_delegation_submission(
                &round_id_str,
                bundle_index,
                seed,
                network_id,
                account_index,
            )
            .map_err(|e| anyhow!("get_delegation_submission failed: {}", e))?;

        let json_sub: JsonDelegationSubmission = submission.into();
        json_to_boxed_slice(&json_sub)
    });
    unwrap_exc_or_null(res)
}

/// Get the delegation submission payload using a Keystone-provided signature.
///
/// Returns JSON-encoded `DelegationSubmission` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_get_delegation_submission_with_keystone_sig(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    sig: *const u8,
    sig_len: usize,
    sighash: *const u8,
    sighash_len: usize,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let sig_bytes = unsafe { bytes_from_ptr(sig, sig_len) };
        let sighash_bytes = unsafe { bytes_from_ptr(sighash, sighash_len) };

        let submission = handle
            .db
            .get_delegation_submission_with_keystone_sig(
                &round_id_str,
                bundle_index,
                sig_bytes,
                sighash_bytes,
            )
            .map_err(|e| {
                anyhow!(
                    "get_delegation_submission_with_keystone_sig failed: {}",
                    e
                )
            })?;

        let json_sub: JsonDelegationSubmission = submission.into();
        json_to_boxed_slice(&json_sub)
    });
    unwrap_exc_or_null(res)
}

/// Store the VAN leaf position after delegation TX is confirmed on chain.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_store_van_position(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    position: u32,
) -> i32 {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;

        handle
            .db
            .store_van_position(&round_id_str, bundle_index, position)
            .map_err(|e| anyhow!("store_van_position failed: {}", e))?;
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}

// =============================================================================
// B. VotingDatabase methods — Voting
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
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let progress_context = AssertUnwindSafe(progress_context);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let seed = unsafe { bytes_from_ptr(hotkey_seed, hotkey_seed_len) };
        let auth_path_bytes =
            unsafe { bytes_from_ptr(van_auth_path_json, van_auth_path_json_len) };
        let auth_path_vecs: Vec<Vec<u8>> = serde_json::from_slice(auth_path_bytes)?;
        let auth_path: Vec<[u8; 32]> = auth_path_vecs
            .into_iter()
            .map(|v| {
                v.try_into().map_err(|_| {
                    anyhow!("each auth_path sibling must be 32 bytes")
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
        let json_commitment: JsonVoteCommitmentBundle =
            serde_json::from_slice(commitment_bytes)?;
        let core_commitment: voting::VoteCommitmentBundle = json_commitment.into();

        let payloads = handle
            .db
            .build_share_payloads(
                &wire_shares,
                &core_commitment,
                vote_decision,
                num_options,
                vc_tree_position,
            )
            .map_err(|e| anyhow!("build_share_payloads failed: {}", e))?;

        let json_payloads: Vec<JsonSharePayload> =
            payloads.into_iter().map(Into::into).collect();
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

// =============================================================================
// B. VotingDatabase methods — Tree sync
// =============================================================================

/// Sync the vote commitment tree from a chain node.
///
/// Returns the latest synced block height on success (>= 0), or -1 on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_sync_vote_tree(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    node_url: *const u8,
    node_url_len: usize,
) -> i64 {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let url = unsafe { str_from_ptr(node_url, node_url_len) }?;

        let height = handle
            .tree_sync
            .sync(&handle.db, &round_id_str, &url)
            .map_err(|e| anyhow!("sync_vote_tree failed: {}", e))?;
        Ok(height as i64)
    });
    unwrap_exc_or(res, -1)
}

/// Generate a VAN Merkle witness for ZKP #2.
///
/// Returns JSON-encoded `VanWitness` as `*mut FfiBoxedSlice`, or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_generate_van_witness(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    anchor_height: u32,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;

        let witness = handle
            .tree_sync
            .generate_van_witness(&handle.db, &round_id_str, bundle_index, anchor_height)
            .map_err(|e| anyhow!("generate_van_witness failed: {}", e))?;

        let json_witness: JsonVanWitness = witness.into();
        json_to_boxed_slice(&json_witness)
    });
    unwrap_exc_or_null(res)
}

/// Drop the in-memory TreeClient so the next `sync_vote_tree()` call
/// creates a fresh one.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_reset_tree_client(
    db: *mut VotingDatabaseHandle,
) -> i32 {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;

        handle
            .tree_sync
            .reset()
            .map_err(|e| anyhow!("reset_tree_client failed: {}", e))?;
        Ok(0)
    });
    unwrap_exc_or(res, -1)
}

// =============================================================================
// C. Free functions (no VotingDatabase needed)
// =============================================================================

/// Generate a standalone voting hotkey (no database needed).
///
/// Returns a pointer to `FfiVotingHotkey` on success, or null on error.
/// Call `zcashlc_voting_free_hotkey` to free the returned pointer.
///
/// # Safety
///
/// - `seed` must be non-null and valid for reads for `seed_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_generate_hotkey_standalone(
    seed: *const u8,
    seed_len: usize,
) -> *mut FfiVotingHotkey {
    let res = catch_panic(|| {
        let seed_bytes = unsafe { bytes_from_ptr(seed, seed_len) };
        let hotkey = voting::hotkey::generate_hotkey(seed_bytes)
            .map_err(|e| anyhow!("generate_hotkey failed: {}", e))?;
        Ok(Box::into_raw(Box::new(voting_hotkey_to_ffi(hotkey))))
    });
    unwrap_exc_or_null(res)
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
        let sender_usk = match network_id {
            0 => UnifiedSpendingKey::from_seed(&MAIN_NETWORK, sender, account),
            1 => UnifiedSpendingKey::from_seed(&TEST_NETWORK, sender, account),
            _ => {
                return Err(anyhow!(
                    "invalid network_id {}, expected 0 (mainnet) or 1 (testnet)",
                    network_id
                ))
            }
        }
        .map_err(|e| anyhow!("failed to derive sender UnifiedSpendingKey: {}", e))?;

        let sender_fvk = sender_usk
            .to_unified_full_viewing_key()
            .orchard()
            .ok_or_else(|| anyhow!("sender UFVK is missing Orchard component"))?
            .to_bytes()
            .to_vec();

        // Derive hotkey-side Orchard material
        let hotkey_usk = match network_id {
            0 => UnifiedSpendingKey::from_seed(&MAIN_NETWORK, hotkey, account),
            1 => UnifiedSpendingKey::from_seed(&TEST_NETWORK, hotkey, account),
            _ => unreachable!("network_id validated above"),
        }
        .map_err(|e| anyhow!("failed to derive hotkey UnifiedSpendingKey: {}", e))?;

        let hotkey_ufvk = hotkey_usk.to_unified_full_viewing_key();
        let hotkey_orchard_fvk = hotkey_ufvk
            .orchard()
            .ok_or_else(|| anyhow!("hotkey UFVK is missing Orchard component"))?;

        let app_hotkey = voting::hotkey::generate_hotkey(hotkey)
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

        let seed_fp = zip32::fingerprint::SeedFingerprint::from_seed(sender)
            .ok_or_else(|| anyhow!("failed to compute seed fingerprint (seed too short?)"))?;

        let inputs = JsonDelegationInputs {
            fvk_bytes: sender_fvk,
            g_d_new_x: g_d_new_x.to_vec(),
            pk_d_new_x: pk_d_new_x.to_vec(),
            hotkey_raw_address,
            hotkey_public_key: app_hotkey.public_key,
            hotkey_address: app_hotkey.address,
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
            return Err(anyhow!(
                "fvk_bytes must be 96 bytes, got {}",
                fvk.len()
            ));
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

        // Derive hotkey-side Orchard material
        let hotkey_usk = match network_id {
            0 => UnifiedSpendingKey::from_seed(&MAIN_NETWORK, hotkey, account),
            1 => UnifiedSpendingKey::from_seed(&TEST_NETWORK, hotkey, account),
            _ => {
                return Err(anyhow!(
                    "invalid network_id {}, expected 0 (mainnet) or 1 (testnet)",
                    network_id
                ))
            }
        }
        .map_err(|e| anyhow!("failed to derive hotkey UnifiedSpendingKey: {}", e))?;

        let hotkey_ufvk = hotkey_usk.to_unified_full_viewing_key();
        let hotkey_orchard_fvk = hotkey_ufvk
            .orchard()
            .ok_or_else(|| anyhow!("hotkey UFVK is missing Orchard component"))?;

        let app_hotkey = voting::hotkey::generate_hotkey(hotkey)
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

        let inputs = JsonDelegationInputs {
            fvk_bytes: fvk,
            g_d_new_x: g_d_new_x.to_vec(),
            pk_d_new_x: pk_d_new_x.to_vec(),
            hotkey_raw_address,
            hotkey_public_key: app_hotkey.public_key,
            hotkey_address: app_hotkey.address,
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
                ))
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
        let orchard_ct = tree_state.orchard_tree()
            .map_err(|e| anyhow!("failed to parse orchard tree from TreeState: {}", e))?;
        let nc_root = orchard_ct.root().to_bytes().to_vec();
        Ok(crate::ffi::BoxedSlice::some(nc_root))
    });
    unwrap_exc_or_null(res)
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
        let van_new = unsafe { bytes_from_ptr(vote_authority_note_new, vote_authority_note_new_len) };
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

/// Return the voting FFI version string.
///
/// The caller must free the returned string with `zcashlc_string_free`.
///
/// # Safety
///
/// No pointer parameters.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_version() -> *mut c_char {
    let res = catch_panic(|| {
        let version = env!("CARGO_PKG_VERSION");
        let c_str = CString::new(version)
            .map_err(|e| anyhow!("version string contains null byte: {}", e))?;
        Ok(c_str.into_raw())
    });
    unwrap_exc_or_null(res)
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Convert a `voting::VotingHotkey` to the FFI representation.
fn voting_hotkey_to_ffi(hotkey: voting::VotingHotkey) -> FfiVotingHotkey {
    let (sk_ptr, sk_len) = crate::ptr_from_vec(hotkey.secret_key);
    let (pk_ptr, pk_len) = crate::ptr_from_vec(hotkey.public_key);
    let address = CString::new(hotkey.address).unwrap().into_raw();
    FfiVotingHotkey {
        secret_key: sk_ptr,
        secret_key_len: sk_len,
        public_key: pk_ptr,
        public_key_len: pk_len,
        address,
    }
}
