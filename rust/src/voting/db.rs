use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
use zcash_voting as voting;
use zcash_voting::storage::VotingDb;
use zcash_voting::tree_sync::VoteTreeSync;

use crate::{unwrap_exc_or, unwrap_exc_or_null};

use super::helpers::str_from_ptr;

/// Opaque handle wrapping the voting database and its tree-sync state.
pub struct VotingDatabaseHandle {
    pub(super) db: Arc<VotingDb>,
    pub(super) tree_sync: VoteTreeSync,
    pub(super) network: voting::types::Network,
    pub(super) network_id: u32,
}

/// Open a voting database at the given path.
///
/// Returns an opaque `*mut VotingDatabaseHandle` on success, or null on error.
///
/// # Safety
///
/// - For the `(path, path_len)` byte argument: if `path_len > 0` then `path` must be
///   non-null and valid for reads for `path_len` bytes; if `path_len == 0`, `path` is
///   ignored.
/// - Call `zcashlc_voting_db_free` to free the returned handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_db_open(
    path: *const u8,
    path_len: usize,
    network_id: u32,
) -> *mut VotingDatabaseHandle {
    let res = catch_panic(|| {
        let path_str = unsafe { str_from_ptr(path, path_len) }?;
        // zcash_voting persists each round's wallet network, so the handle
        // carries it from open time (0 = testnet, 1 = mainnet, and the
        // custom/regtest network slot). The custom slot's voting identity must
        // follow the registered base network — a modified-mainnet chain votes
        // with mainnet hotkeys and HRPs — so derive it from CUSTOM_PARAMS via
        // `parse_network` (which also errors if the custom network was never
        // configured) rather than assuming Regtest.
        let network = match network_id {
            crate::NETWORK_ID_TESTNET => voting::types::Network::Testnet,
            crate::NETWORK_ID_MAINNET => voting::types::Network::Mainnet,
            crate::NETWORK_ID_REGTEST => {
                use zcash_protocol::consensus::{NetworkType, Parameters};
                match crate::parse_network(network_id)?.network_type() {
                    NetworkType::Main => voting::types::Network::Mainnet,
                    NetworkType::Test => voting::types::Network::Testnet,
                    NetworkType::Regtest => voting::types::Network::Regtest,
                }
            }
            other => return Err(anyhow!("invalid network id {other} for voting database")),
        };
        let db = VotingDb::open(&path_str)
            .map_err(|e| anyhow!("Error opening voting database: {}", e))?;
        Ok(Box::into_raw(Box::new(VotingDatabaseHandle {
            db: Arc::new(db),
            tree_sync: VoteTreeSync::new(),
            network,
            network_id,
        })))
    });
    unwrap_exc_or_null(res)
}

/// Free a `VotingDatabaseHandle`.
///
/// # Safety
///
/// - If `ptr` is non-null, it must be a pointer previously returned by
///   `zcashlc_voting_db_open` that has not already been freed.
/// - Calling this twice on the same non-null pointer, or on any pointer not obtained
///   from `zcashlc_voting_db_open`, is undefined behavior.
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
/// - For the `(wallet_id, wallet_id_len)` byte argument: if `wallet_id_len > 0` then
///   `wallet_id` must be non-null and valid for reads for `wallet_id_len` bytes; if
///   `wallet_id_len == 0`, `wallet_id` is ignored.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_open_rejects_invalid_utf8_path() {
        let invalid_path = [0xff];
        let handle =
            unsafe { zcashlc_voting_db_open(invalid_path.as_ptr(), invalid_path.len(), 1) };
        assert!(handle.is_null());
    }

    #[test]
    fn db_open_rejects_invalid_network_id() {
        // The network is validated once, here, so no database-bound call has to
        // re-check it: the handle cannot exist for a network that does not.
        let path = b":memory:";
        let db = unsafe { zcashlc_voting_db_open(path.as_ptr(), path.len(), 99) };
        assert!(db.is_null(), "unknown network id must not open a handle");
    }

    #[test]
    fn db_free_accepts_null() {
        unsafe { zcashlc_voting_db_free(std::ptr::null_mut()) };
    }

    #[test]
    fn set_wallet_id_rejects_null_db() {
        let code = unsafe { zcashlc_voting_set_wallet_id(std::ptr::null_mut(), b"x".as_ptr(), 1) };
        assert_eq!(code, -1);
    }

    /// The custom slot's voting identity must follow the registered base
    /// network: a modified-mainnet chain keeps mainnet hotkeys and HRPs. This
    /// is the only test that touches the process-global custom-network slot —
    /// keep it that way (parallel tests share the global).
    #[test]
    fn db_open_custom_network_derives_voting_network_from_base() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "zcashlc_voting_db_custom_network_{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let path_bytes = path.to_string_lossy().as_bytes().to_vec();

        // Before zcashlc_set_custom_network runs, the custom slot has no base
        // to derive the voting network from — opening must fail, not silently
        // fall back to Regtest.
        let unconfigured = unsafe {
            zcashlc_voting_db_open(
                path_bytes.as_ptr(),
                path_bytes.len(),
                crate::NETWORK_ID_REGTEST,
            )
        };
        assert!(
            unconfigured.is_null(),
            "custom slot must not open before the custom network is configured"
        );

        // Modified-mainnet: base identity mainnet, custom activation heights.
        assert!(crate::zcashlc_set_custom_network(
            1, 347_500, 419_200, 653_600, 903_000, 1_046_400, 1_687_104, 2_726_400, 3_146_400,
            3_364_600, 3_428_143,
        ));

        let db = unsafe {
            zcashlc_voting_db_open(
                path_bytes.as_ptr(),
                path_bytes.len(),
                crate::NETWORK_ID_REGTEST,
            )
        };
        assert!(!db.is_null(), "open voting db at {:?}", path);
        let network = unsafe { (*db).network };
        assert_eq!(
            network,
            voting::types::Network::Mainnet,
            "base-mainnet custom network must map to the mainnet voting identity"
        );
        unsafe { zcashlc_voting_db_free(db) };
        let _ = std::fs::remove_file(&path);
    }
}
