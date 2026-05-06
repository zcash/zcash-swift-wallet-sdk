use std::panic::AssertUnwindSafe;

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;

use crate::unwrap_exc_or_null;

use super::db::VotingDatabaseHandle;
use super::helpers::{
    bytes_from_ptr, json_to_boxed_slice, open_wallet_db, received_note_to_note_info, str_from_ptr,
};
use super::json::JsonNoteInfo;

// =============================================================================
// VotingDatabase methods — Wallet notes
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
                Some(idx) => account_ids.get(idx as usize).copied().ok_or_else(|| {
                    anyhow!(
                        "account_index {} out of range (wallet has {} accounts)",
                        idx,
                        account_ids.len()
                    )
                })?,
                None => *account_ids
                    .first()
                    .ok_or_else(|| anyhow!("no accounts in wallet"))?,
            }
        };
        let account = wallet_db
            .get_account(target_id)?
            .ok_or_else(|| anyhow!("account not found"))?;

        use zcash_client_backend::data_api::Account;
        let ufvk = account
            .ufvk()
            .ok_or_else(|| anyhow!("account has no UFVK"))?;
        let account_uuid = account.id();

        let height = zcash_protocol::consensus::BlockHeight::from_u32(snapshot_height as u32);
        let received_notes = wallet_db
            .get_unspent_orchard_notes_at_historical_height(account_uuid, height)
            .map_err(|e| {
                anyhow!(
                    "get_unspent_orchard_notes_at_historical_height failed: {}",
                    e
                )
            })?;

        let mut json_notes = Vec::with_capacity(received_notes.len());
        for rn in &received_notes {
            let note_info = received_note_to_note_info(rn, ufvk, &network)?;
            json_notes.push(JsonNoteInfo::from(note_info));
        }
        json_to_boxed_slice(&json_notes)
    });
    unwrap_exc_or_null(res)
}
