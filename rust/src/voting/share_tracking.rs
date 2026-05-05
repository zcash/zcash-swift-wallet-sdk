use std::ffi::CString;
use std::os::raw::c_char;

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
use zcash_voting as voting;

use crate::unwrap_exc_or_null;

use super::helpers::bytes_from_ptr;

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
        let vc = unsafe { bytes_from_ptr(vote_commitment, 32) };
        let blind = unsafe { bytes_from_ptr(primary_blind, 32) };

        let nullifier = voting::share_tracking::compute_share_nullifier(vc, share_index, blind)
            .map_err(|e| anyhow!("compute_share_nullifier failed: {}", e))?;

        let hex_str: String = nullifier.iter().map(|b| format!("{:02x}", b)).collect();
        let c_str = CString::new(hex_str).map_err(|e| anyhow!("null byte in hex string: {}", e))?;
        Ok(c_str.into_raw())
    });
    unwrap_exc_or_null(res)
}
