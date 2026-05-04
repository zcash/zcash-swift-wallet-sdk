use std::ffi::CString;
use std::os::raw::c_char;

// =============================================================================
// #[repr(C)] structs for simple, frequently-accessed return types
// =============================================================================

/// Round state returned by `zcashlc_voting_get_round_state`.
#[repr(C)]
pub struct FfiRoundState {
    pub(super) round_id: *mut c_char,
    /// 0=Initialized, 1=HotkeyGenerated, 2=DelegationConstructed,
    /// 3=DelegationProved, 4=VoteReady
    pub(super) phase: u32,
    pub(super) snapshot_height: u64,
    /// Nullable — null if no hotkey has been generated yet.
    pub(super) hotkey_address: *mut c_char,
    /// -1 if None, otherwise the delegated weight value.
    pub(super) delegated_weight: i64,
    pub(super) proof_generated: bool,
}

/// Voting hotkey returned by `zcashlc_voting_generate_hotkey`.
#[repr(C)]
pub struct FfiVotingHotkey {
    pub(super) secret_key: *mut u8,
    pub(super) secret_key_len: usize,
    pub(super) public_key: *mut u8,
    pub(super) public_key_len: usize,
    pub(super) address: *mut c_char,
}

/// Bundle setup result returned by `zcashlc_voting_setup_bundles`.
#[repr(C)]
pub struct FfiBundleSetupResult {
    pub(super) bundle_count: u32,
    pub(super) eligible_weight: u64,
}

/// Round summary for list display.
#[repr(C)]
pub struct FfiRoundSummary {
    pub(super) round_id: *mut c_char,
    pub(super) phase: u32,
    pub(super) snapshot_height: u64,
    pub(super) created_at: u64,
}

/// Array of round summaries.
#[repr(C)]
pub struct FfiRoundSummaries {
    pub(super) ptr: *mut FfiRoundSummary,
    pub(super) len: usize,
}

/// Vote record for a single proposal/bundle.
#[repr(C)]
pub struct FfiVoteRecord {
    pub(super) proposal_id: u32,
    pub(super) bundle_index: u32,
    pub(super) choice: u32,
    pub(super) submitted: bool,
}

/// Array of vote records.
#[repr(C)]
pub struct FfiVoteRecords {
    pub(super) ptr: *mut FfiVoteRecord,
    pub(super) len: usize,
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
