use std::convert::TryInto;
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

use zcash_client_backend::{address::UnifiedAddress, data_api};
use zcash_client_sqlite::AccountUuid;
use zcash_protocol::{consensus::Network, value::ZatBalance};
use zip32::DiversifierIndex;

use crate::{free_ptr_from_vec, free_ptr_from_vec_with, ptr_from_vec, zcashlc_string_free};

pub(crate) mod sys;

/// A struct that contains a 16-byte account uuid along with key derivation metadata for that
/// account.
///
/// A returned value containing the all-zeros seed fingerprint and/or u32::MAX for the
/// hd_account_index indicates that no derivation metadata is available.
#[repr(C)]
pub struct Account {
    uuid_bytes: [u8; 16],
    account_name: *mut c_char,
    key_source: *mut c_char,
    seed_fingerprint: [u8; 32],
    hd_account_index: u32,
}

impl Account {
    pub(crate) const NOT_FOUND: Account = Account {
        uuid_bytes: [0u8; 16],
        account_name: ptr::null_mut(),
        key_source: ptr::null_mut(),
        seed_fingerprint: [0u8; 32],
        hd_account_index: u32::MAX,
    };

    pub(crate) fn from_account(
        account: &impl zcash_client_backend::data_api::Account<AccountId = AccountUuid>,
    ) -> Self {
        let derivation = account.source().key_derivation();
        Account {
            uuid_bytes: account.id().expose_uuid().into_bytes(),
            account_name: account.name().map_or(ptr::null_mut(), |name| {
                CString::new(name).unwrap().into_raw()
            }),
            key_source: account
                .source()
                .key_source()
                .map_or(ptr::null_mut(), |s| CString::new(s).unwrap().into_raw()),
            seed_fingerprint: derivation.map_or([0u8; 32], |d| d.seed_fingerprint().to_bytes()),
            hd_account_index: derivation.map_or(u32::MAX, |d| d.account_index().into()),
        }
    }
}

/// Frees an [`Account`] value
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`Account`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_account(ptr: *mut Account) {
    if !ptr.is_null() {
        let account: Box<Account> = unsafe { Box::from_raw(ptr) };
        if !(account.account_name.is_null()) {
            unsafe { zcashlc_string_free(account.account_name) }
        }
        if !(account.key_source.is_null()) {
            unsafe { zcashlc_string_free(account.key_source) }
        }
        drop(account);
    }
}

/// A struct that contains a 16-byte account uuid.
#[repr(C)]
pub struct Uuid {
    uuid_bytes: [u8; 16],
}

impl Uuid {
    pub(crate) fn new(account_uuid: AccountUuid) -> Self {
        Uuid {
            uuid_bytes: account_uuid.expose_uuid().into_bytes(),
        }
    }
}

/// Frees a [`Uuid`] value
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`Uuid`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_ffi_uuid(ptr: *mut Uuid) {
    if !ptr.is_null() {
        let key: Box<Uuid> = unsafe { Box::from_raw(ptr) };
        drop(key);
    }
}

/// A struct that contains a pointer to, and length information for, a heap-allocated
/// slice of [`Uuid`] values.
///
/// # Safety
///
/// - `ptr` must be non-null and must be valid for reads for `len * mem::size_of::<Uuid>()`
///   many bytes, and it must be properly aligned. This means in particular:
///   - The entire memory range pointed to by `ptr` must be contained within a single allocated
///     object. Slices can never span across multiple allocated objects.
///   - `ptr` must be non-null and aligned even for zero-length slices.
///   - `ptr` must point to `len` consecutive properly initialized values of type
///     [`Uuid`].
/// - The total size `len * mem::size_of::<Uuid>()` of the slice pointed to
///   by `ptr` must be no larger than isize::MAX. See the safety documentation of pointer::offset.
#[repr(C)]
pub struct Accounts {
    ptr: *mut Uuid,
    len: usize, // number of elems
}

impl Accounts {
    pub fn ptr_from_vec(v: Vec<Uuid>) -> *mut Self {
        let (ptr, len) = ptr_from_vec(v);
        Box::into_raw(Box::new(Accounts { ptr, len }))
    }
}

/// Frees an array of [`Uuid`] values as allocated by `zcashlc_list_accounts`.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`Accounts`].
///   See the safety documentation of [`Accounts`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_accounts(ptr: *mut Accounts) {
    if !ptr.is_null() {
        let s: Box<Accounts> = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(s.ptr, s.len);
        drop(s);
    }
}

/// A struct that contains an account identifier along with a pointer to the binary encoding
/// of an associated key.
///
/// # Safety
///
/// - `encoding` must be non-null and must point to an array of `encoding_len` bytes.
#[repr(C)]
pub struct BinaryKey {
    account_uuid: [u8; 16],
    encoding: *mut u8,
    encoding_len: usize,
}

impl BinaryKey {
    pub(crate) fn new(account_uuid: AccountUuid, key_bytes: Vec<u8>) -> Self {
        let (encoding, encoding_len) = ptr_from_vec(key_bytes);
        BinaryKey {
            account_uuid: account_uuid.expose_uuid().into_bytes(),
            encoding,
            encoding_len,
        }
    }
}

/// Frees a [`BinaryKey`] value
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`BinaryKey`].
///   See the safety documentation of [`BinaryKey`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_binary_key(ptr: *mut BinaryKey) {
    if !ptr.is_null() {
        let key: Box<BinaryKey> = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(key.encoding, key.encoding_len);
        drop(key);
    }
}

/// A struct that contains an account identifier along with a pointer to the string encoding
/// of an associated key.
///
/// # Safety
///
/// - `encoding` must be non-null and must point to a null-terminated UTF-8 string.
#[repr(C)]
pub struct EncodedKey {
    account_uuid: [u8; 16],
    encoding: *mut c_char,
}

impl EncodedKey {
    pub(crate) fn new(account_uuid: AccountUuid, key_str: &str) -> Self {
        EncodedKey {
            account_uuid: account_uuid.expose_uuid().into_bytes(),
            encoding: CString::new(key_str).unwrap().into_raw(),
        }
    }
}

/// A struct that contains a pointer to, and length information for, a heap-allocated
/// slice of [`EncodedKey`] values.
///
/// # Safety
///
/// - `ptr` must be non-null and must be valid for reads for `len * mem::size_of::<EncodedKey>()`
///   many bytes, and it must be properly aligned. This means in particular:
///   - The entire memory range pointed to by `ptr` must be contained within a single allocated
///     object. Slices can never span across multiple allocated objects.
///   - `ptr` must be non-null and aligned even for zero-length slices.
///   - `ptr` must point to `len` consecutive properly initialized values of type
///     [`EncodedKey`].
/// - The total size `len * mem::size_of::<EncodedKey>()` of the slice pointed to
///   by `ptr` must be no larger than isize::MAX. See the safety documentation of pointer::offset.
/// - See the safety documentation of [`EncodedKey`]
#[repr(C)]
pub struct EncodedKeys {
    ptr: *mut EncodedKey,
    len: usize, // number of elems
}

impl EncodedKeys {
    pub fn ptr_from_vec(v: Vec<EncodedKey>) -> *mut Self {
        let (ptr, len) = ptr_from_vec(v);
        Box::into_raw(Box::new(EncodedKeys { ptr, len }))
    }
}

/// Frees an array of [`EncodedKey`] values as allocated by `zcashlc_list_transparent_receivers`.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`EncodedKeys`].
///   See the safety documentation of [`EncodedKeys`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_keys(ptr: *mut EncodedKeys) {
    if !ptr.is_null() {
        let s: Box<EncodedKeys> = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec_with(s.ptr, s.len, |k| unsafe { zcashlc_string_free(k.encoding) });
        drop(s);
    }
}

/// A struct that contains a subtree root.
///
/// # Safety
///
/// - `root_hash_ptr` must be non-null and must be valid for reads for `root_hash_ptr_len`
///   bytes, and it must have an alignment of `1`.
/// - The total size `root_hash_ptr_len` of the slice pointed to by `root_hash_ptr` must
///   be no larger than `isize::MAX`. See the safety documentation of `pointer::offset`.
#[repr(C)]
pub struct SubtreeRoot {
    pub(crate) root_hash_ptr: *mut u8,
    pub(crate) root_hash_ptr_len: usize,
    pub(crate) completing_block_height: u32,
}

/// A struct that contains a pointer to, and length information for, a heap-allocated
/// slice of [`SubtreeRoot`] values.
///
/// # Safety
///
/// - `ptr` must be non-null and must be valid for reads for `len * mem::size_of::<SubtreeRoot>()`
///   many bytes, and it must be properly aligned. This means in particular:
///   - The entire memory range pointed to by `ptr` must be contained within a single
///     allocated object. Slices can never span across multiple allocated objects.
///   - `ptr` must be non-null and aligned even for zero-length slices.
///   - `ptr` must point to `len` consecutive properly initialized values of type
///     [`SubtreeRoot`].
/// - The total size `len * mem::size_of::<SubtreeRoot>()` of the slice pointed to
///   by `ptr` must be no larger than isize::MAX. See the safety documentation of
///   `pointer::offset`.
/// - See the safety documentation of [`SubtreeRoot`]
#[repr(C)]
pub struct SubtreeRoots {
    pub(crate) ptr: *mut SubtreeRoot,
    pub(crate) len: usize, // number of elems
}

/// Balance information for a value within a single pool in an account.
#[repr(C)]
pub struct Balance {
    /// The value in the account that may currently be spent; it is possible to compute witnesses
    /// for all the notes that comprise this value, and all of this value is confirmed to the
    /// required confirmation depth.
    spendable_value: i64,

    /// The value in the account of shielded change notes that do not yet have sufficient
    /// confirmations to be spendable.
    change_pending_confirmation: i64,

    /// The value in the account of all remaining received notes that either do not have sufficient
    /// confirmations to be spendable, or for which witnesses cannot yet be constructed without
    /// additional scanning.
    value_pending_spendability: i64,
}

impl Balance {
    pub(crate) fn new(balance: &data_api::Balance) -> Self {
        Self {
            spendable_value: ZatBalance::from(balance.spendable_value()).into(),
            change_pending_confirmation: ZatBalance::from(balance.change_pending_confirmation())
                .into(),
            value_pending_spendability: ZatBalance::from(balance.value_pending_spendability())
                .into(),
        }
    }
}

/// Balance information for a single account.
///
/// The sum of this struct's fields is the total balance of the account.
#[repr(C)]
pub struct AccountBalance {
    account_uuid: [u8; 16],

    /// The value of unspent Sapling outputs belonging to the account.
    sapling_balance: Balance,

    /// The value of unspent Orchard outputs belonging to the account.
    orchard_balance: Balance,

    /// The value of all unspent transparent outputs belonging to the account,
    /// irrespective of confirmation depth.
    ///
    /// Unshielded balances are not subject to confirmation-depth constraints, because the
    /// only possible operation on a transparent balance is to shield it, it is possible
    /// to create a zero-conf transaction to perform that shielding, and the resulting
    /// shielded notes will be subject to normal confirmation rules.
    unshielded: i64,
}

impl AccountBalance {
    pub(crate) fn new((account_uuid, balance): (&AccountUuid, &data_api::AccountBalance)) -> Self {
        Self {
            account_uuid: account_uuid.expose_uuid().into_bytes(),
            sapling_balance: Balance::new(balance.sapling_balance()),
            orchard_balance: Balance::new(balance.orchard_balance()),
            unshielded: ZatBalance::from(balance.unshielded_balance().total()).into(),
        }
    }
}

/// A struct that contains details about scan progress.
///
/// When `denominator` is zero, the numerator encodes a non-progress indicator:
/// - 0: progress is unknown.
/// - 1: an error occurred.
#[repr(C)]
pub struct ScanProgress {
    numerator: u64,
    denominator: u64,
}

/// A type representing the potentially-spendable value of unspent outputs in the wallet.
///
/// The balances reported using this data structure may overestimate the total spendable
/// value of the wallet, in the case that the spend of a previously received shielded note
/// has not yet been detected by the process of scanning the chain. The balances reported
/// using this data structure can only be certain to be unspent in the case that
/// [`Self::is_synced`] is true, and even in this circumstance it is possible that a newly
/// created transaction could conflict with a not-yet-mined transaction in the mempool.
///
/// # Safety
///
/// - `account_balances` must be non-null and must be valid for reads for
///   `account_balances_len * mem::size_of::<AccountBalance>()` many bytes, and it must
///   be properly aligned. This means in particular:
///   - The entire memory range pointed to by `account_balances` must be contained within
///     a single allocated object. Slices can never span across multiple allocated objects.
///   - `account_balances` must be non-null and aligned even for zero-length slices.
///   - `account_balances` must point to `len` consecutive properly initialized values of
///     type [`AccountBalance`].
/// - The total size `account_balances_len * mem::size_of::<AccountBalance>()` of the
///   slice pointed to by `account_balances` must be no larger than `isize::MAX`. See the
///   safety documentation of `pointer::offset`.
/// - `scan_progress` must, if non-null, point to a struct having the layout of
///   [`ScanProgress`].
#[repr(C)]
pub struct WalletSummary {
    account_balances: *mut AccountBalance,
    account_balances_len: usize,
    chain_tip_height: i32,
    fully_scanned_height: i32,
    scan_progress: *mut ScanProgress,
    next_sapling_subtree_index: u64,
    next_orchard_subtree_index: u64,
}

impl WalletSummary {
    pub(crate) fn some(summary: data_api::WalletSummary<AccountUuid>) -> anyhow::Result<*mut Self> {
        let (account_balances, account_balances_len) = {
            let account_balances: Vec<AccountBalance> = summary
                .account_balances()
                .iter()
                .map(|(account_uuid, balance)| {
                    Ok::<_, anyhow::Error>(AccountBalance::new((account_uuid, balance)))
                })
                .collect::<Result<_, _>>()?;

            ptr_from_vec(account_balances)
        };

        let scan_progress = if let Some(recovery_progress) = summary.progress().recovery() {
            Box::into_raw(Box::new(ScanProgress {
                numerator: *summary.progress().scan().numerator() + *recovery_progress.numerator(),
                denominator: *summary.progress().scan().denominator()
                    + *recovery_progress.denominator(),
            }))
        } else {
            Box::into_raw(Box::new(ScanProgress {
                numerator: *summary.progress().scan().numerator(),
                denominator: *summary.progress().scan().denominator(),
            }))
        };

        Ok(Box::into_raw(Box::new(Self {
            account_balances,
            account_balances_len,
            chain_tip_height: u32::from(summary.chain_tip_height()) as i32,
            fully_scanned_height: u32::from(summary.fully_scanned_height()) as i32,
            scan_progress,
            next_sapling_subtree_index: summary.next_sapling_subtree_index(),
            next_orchard_subtree_index: summary.next_orchard_subtree_index(),
        })))
    }

    pub(crate) fn none() -> *mut Self {
        Box::into_raw(Box::new(Self {
            account_balances: ptr::null_mut(),
            account_balances_len: 0,
            chain_tip_height: 0,
            fully_scanned_height: -1,
            scan_progress: ptr::null_mut(),
            next_sapling_subtree_index: 0,
            next_orchard_subtree_index: 0,
        }))
    }
}

/// Frees an [`WalletSummary`] value.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`WalletSummary`].
///   See the safety documentation of [`WalletSummary`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_wallet_summary(ptr: *mut WalletSummary) {
    if !ptr.is_null() {
        let summary = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(summary.account_balances, summary.account_balances_len);
        if !summary.scan_progress.is_null() {
            let progress = unsafe { Box::from_raw(summary.scan_progress) };
            drop(progress);
        }
        drop(summary);
    }
}

/// A struct that contains the start (inclusive) and end (exclusive) of a range of blocks
/// to scan.
#[repr(C)]
pub struct ScanRange {
    pub(crate) start: i32,
    pub(crate) end: i32,
    pub(crate) priority: u8,
}

/// A struct that contains a pointer to, and length information for, a heap-allocated
/// slice of [`ScanRange`] values.
///
/// # Safety
///
/// - `ptr` must be non-null and must be valid for reads for `len * mem::size_of::<ScanRange>()`
///   many bytes, and it must be properly aligned. This means in particular:
///   - The entire memory range pointed to by `ptr` must be contained within a single
///     allocated object. Slices can never span across multiple allocated objects.
///   - `ptr` must be non-null and aligned even for zero-length slices.
///   - `ptr` must point to `len` consecutive properly initialized values of type
///     [`ScanRange`].
/// - The total size `len * mem::size_of::<ScanRange>()` of the slice pointed to
///   by `ptr` must be no larger than isize::MAX. See the safety documentation of
///   `pointer::offset`.
#[repr(C)]
pub struct ScanRanges {
    ptr: *mut ScanRange,
    len: usize, // number of elems
}

impl ScanRanges {
    pub fn ptr_from_vec(v: Vec<ScanRange>) -> *mut Self {
        let (ptr, len) = ptr_from_vec(v);
        Box::into_raw(Box::new(ScanRanges { ptr, len }))
    }
}

/// Frees an array of [`ScanRange`] values as allocated by `zcashlc_suggest_scan_ranges`.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`ScanRanges`].
///   See the safety documentation of [`ScanRanges`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_scan_ranges(ptr: *mut ScanRanges) {
    if !ptr.is_null() {
        let s: Box<ScanRanges> = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(s.ptr, s.len);
        drop(s);
    }
}

/// Metadata about modifications to the wallet state made in the course of scanning a set
/// of blocks.
#[repr(C)]
pub struct ScanSummary {
    scanned_start: i32,
    scanned_end: i32,
    spent_sapling_note_count: u64,
    received_sapling_note_count: u64,
}

impl ScanSummary {
    pub(crate) fn new(scan_summary: data_api::chain::ScanSummary) -> *mut Self {
        let scanned_range = scan_summary.scanned_range();

        Box::into_raw(Box::new(Self {
            scanned_start: u32::from(scanned_range.start) as i32,
            scanned_end: u32::from(scanned_range.end) as i32,
            spent_sapling_note_count: scan_summary.spent_sapling_note_count() as u64,
            received_sapling_note_count: scan_summary.received_sapling_note_count() as u64,
        }))
    }
}

/// Frees a [`ScanSummary`] value.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`ScanSummary`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_scan_summary(ptr: *mut ScanSummary) {
    if !ptr.is_null() {
        let summary = unsafe { Box::from_raw(ptr) };
        drop(summary);
    }
}

#[repr(C)]
pub struct BlockMeta {
    pub(crate) height: u32,
    pub(crate) block_hash_ptr: *mut u8,
    pub(crate) block_hash_ptr_len: usize,
    pub(crate) block_time: u32,
    pub(crate) sapling_outputs_count: u32,
    pub(crate) orchard_actions_count: u32,
}

#[repr(C)]
pub struct BlocksMeta {
    pub(crate) ptr: *mut BlockMeta,
    pub(crate) len: usize, // number of elems
}

impl BlocksMeta {
    pub fn ptr_from_vec(v: Vec<BlockMeta>) -> *mut Self {
        let (ptr, len) = ptr_from_vec(v);
        Box::into_raw(Box::new(BlocksMeta { ptr, len }))
    }
}

/// A struct that optionally contains a pointer to, and length information for, a
/// heap-allocated boxed slice.
///
/// This is an FFI representation of `Option<Box<[u8]>>`.
///
/// # Safety
///
/// - If `ptr` is non-null, it must be valid for reads for `len` bytes, and it must have
///   an alignment of `1`.
/// - The memory referenced by `ptr` must not be mutated for the lifetime of the struct
///   (up until [`zcashlc_free_boxed_slice`] is called with it).
/// - The total size `len` must be no larger than `isize::MAX`. See the safety
///   documentation of `pointer::offset`.
///   - When `ptr` is null, `len` should be zero.
#[repr(C)]
pub struct BoxedSlice {
    ptr: *mut u8,
    len: usize,
}

impl BoxedSlice {
    pub(crate) fn some(v: Vec<u8>) -> *mut Self {
        let (ptr, len) = ptr_from_vec(v);
        Box::into_raw(Box::new(BoxedSlice { ptr, len }))
    }

    pub(crate) fn none() -> *mut Self {
        Box::into_raw(Box::new(Self {
            ptr: ptr::null_mut(),
            len: 0,
        }))
    }
}

/// Frees a [`BoxedSlice`].
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of
///   [`BoxedSlice`]. See the safety documentation of [`BoxedSlice`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_boxed_slice(ptr: *mut BoxedSlice) {
    if !ptr.is_null() {
        let s: Box<BoxedSlice> = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(s.ptr, s.len);
        drop(s);
    }
}

/// A struct that contains a pointer to, and length information for, a heap-allocated
/// slice of `[u8; 32]` arrays.
///
/// # Safety
///
/// - `ptr` must be non-null and must be valid for reads for `len * mem::size_of::<[u8; 32]>()`
///   many bytes, and it must be properly aligned. This means in particular:
///   - The entire memory range pointed to by `ptr` must be contained within a single
///     allocated object. Slices can never span across multiple allocated objects.
///   - `ptr` must be non-null and aligned even for zero-length slices.
///   - `ptr` must point to `len` consecutive properly initialized values of type
///     `[u8; 32]`.
/// - The total size `len * mem::size_of::<[u8; 32]>()` of the slice pointed to
///   by `ptr` must be no larger than isize::MAX. See the safety documentation of
///   `pointer::offset`.
#[repr(C)]
pub struct TxIds {
    ptr: *mut [u8; 32],
    len: usize, // number of elems
}

impl TxIds {
    pub fn ptr_from_vec(v: Vec<[u8; 32]>) -> *mut Self {
        let (ptr, len) = ptr_from_vec(v);
        Box::into_raw(Box::new(TxIds { ptr, len }))
    }
}

/// Frees an array of `[u8; 32]` values as allocated by `zcashlc_create_proposed_transactions`.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`TxIds`].
///   See the safety documentation of [`TxIds`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_txids(ptr: *mut TxIds) {
    if !ptr.is_null() {
        let s: Box<TxIds> = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(s.ptr, s.len);
        drop(s);
    }
}

/// Metadata about the status of a transaction obtained by inspecting the chain state.
#[repr(C, u8)]
pub enum TransactionStatus {
    /// The requested transaction ID was not recognized by the node.
    TxidNotRecognized,
    /// The requested transaction ID corresponds to a transaction that is recognized by the node,
    /// but is in the mempool or is otherwise not mined in the main chain (but may have been mined
    /// on a fork that was reorged away).
    NotInMainChain,
    /// The requested transaction ID corresponds to a transaction that has been included in the
    /// block at the provided height.
    Mined(u32),
}

/// A request for transaction data enhancement, spentness check, or discovery
/// of spends from a given transparent address within a specific block range.
#[repr(C, u8)]
pub enum TransactionDataRequest {
    /// Information about the chain's view of a transaction is requested.
    ///
    /// The caller evaluating this request on behalf of the wallet backend should respond to this
    /// request by determining the status of the specified transaction with respect to the main
    /// chain; if using `lightwalletd` for access to chain data, this may be obtained by
    /// interpreting the results of the [`GetTransaction`] RPC method. It should then call
    /// [`WalletWrite::set_transaction_status`] to provide the resulting transaction status
    /// information to the wallet backend.
    ///
    /// [`GetTransaction`]: crate::proto::service::compact_tx_streamer_client::CompactTxStreamerClient::get_transaction
    GetStatus([u8; 32]),
    /// Transaction enhancement (download of complete raw transaction data) is requested.
    ///
    /// The caller evaluating this request on behalf of the wallet backend should respond to this
    /// request by providing complete data for the specified transaction to
    /// [`wallet::decrypt_and_store_transaction`]; if using `lightwalletd` for access to chain
    /// state, this may be obtained via the [`GetTransaction`] RPC method. If no data is available
    /// for the specified transaction, this should be reported to the backend using
    /// [`WalletWrite::set_transaction_status`]. A [`TransactionDataRequest::Enhancement`] request
    /// subsumes any previously existing [`TransactionDataRequest::GetStatus`] request.
    ///
    /// [`GetTransaction`]: crate::proto::service::compact_tx_streamer_client::CompactTxStreamerClient::get_transaction
    Enhancement([u8; 32]),
    /// Information about transactions that receive or spend funds belonging to the specified
    /// transparent address is requested.
    ///
    /// Fully transparent transactions, and transactions that do not contain either shielded inputs
    /// or shielded outputs belonging to the wallet, may not be discovered by the process of chain
    /// scanning; as a consequence, the wallet must actively query to find transactions that spend
    /// such funds. Ideally we'd be able to query by [`OutPoint`] but this is not currently
    /// functionality that is supported by the light wallet server.
    ///
    /// The caller evaluating this request on behalf of the wallet backend should respond to this
    /// request by detecting transactions involving the specified address within the provided block
    /// range; if using `lightwalletd` for access to chain data, this may be performed using the
    /// [`GetTaddressTxids`] RPC method. It should then call [`wallet::decrypt_and_store_transaction`]
    /// for each transaction so detected.
    ///
    /// [`GetTaddressTxids`]: crate::proto::service::compact_tx_streamer_client::CompactTxStreamerClient::get_taddress_txids
    SpendsFromAddress {
        address: *mut c_char,
        block_range_start: u32,
        /// An optional end height; no end height is represented as `-1`
        block_range_end: i64,
    },
}

/// A struct that contains a pointer to, and length information for, a heap-allocated
/// slice of [`TransactionDataRequest`] values.
///
/// # Safety
///
/// - `ptr` must be non-null and must be valid for reads for `len * mem::size_of::<TransactionDataRequest>()`
///   many bytes, and it must be properly aligned. This means in particular:
///   - The entire memory range pointed to by `ptr` must be contained within a single allocated
///     object. Slices can never span across multiple allocated objects.
///   - `ptr` must be non-null and aligned even for zero-length slices.
///   - `ptr` must point to `len` consecutive properly initialized values of type
///     [`TransactionDataRequest`].
/// - The total size `len * mem::size_of::<TransactionDataRequest>()` of the slice pointed to
///   by `ptr` must be no larger than isize::MAX. See the safety documentation of pointer::offset.
/// - See the safety documentation of [`TransactionDataRequest`]
#[repr(C)]
pub struct TransactionDataRequests {
    ptr: *mut TransactionDataRequest,
    len: usize, // number of elems
}

impl TransactionDataRequests {
    pub fn ptr_from_vec(v: Vec<TransactionDataRequest>) -> *mut Self {
        let (ptr, len) = ptr_from_vec(v);
        Box::into_raw(Box::new(TransactionDataRequests { ptr, len }))
    }
}

/// Frees an array of [`TransactionDataRequest`] values as allocated by `zcashlc_transaction_data_requests`.
///
/// # Safety
///
/// - `ptr` if `ptr` is non-null it must point to a struct having the layout of [`TransactionDataRequests`].
///   See the safety documentation of [`TransactionDataRequests`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_transaction_data_requests(ptr: *mut TransactionDataRequests) {
    if !ptr.is_null() {
        let s: Box<TransactionDataRequests> = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec_with(s.ptr, s.len, |req| {
            if let TransactionDataRequest::SpendsFromAddress { address, .. } = req {
                unsafe { zcashlc_string_free(*address) }
            }
        });
        drop(s);
    }
}

/// A decimal suitable for converting into an `NSDecimalNumber`.
#[repr(C)]
pub struct Decimal {
    mantissa: u64,
    exponent: i16,
    is_sign_negative: bool,
}

impl Decimal {
    pub(crate) fn from_rust(d: rust_decimal::Decimal) -> Option<Self> {
        d.mantissa().abs().try_into().ok().map(|mantissa| Self {
            mantissa,
            exponent: -(d.scale() as i16),
            is_sign_negative: d.is_sign_negative(),
        })
    }
}

/// A struct that contains a Zcash unified address, along with the diversifier index used to
/// generate that address.
#[repr(C)]
pub struct Address {
    address: *mut c_char,
    diversifier_index_bytes: [u8; 11],
}

impl Address {
    pub(crate) fn new(
        network: &Network,
        address: UnifiedAddress,
        diversifier_index: DiversifierIndex,
    ) -> Self {
        let address_str = address.encode(network);
        Self {
            address: CString::new(address_str).unwrap().into_raw(),
            diversifier_index_bytes: *diversifier_index.as_bytes(),
        }
    }
}

/// Frees an [`Address`] value
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`Address`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_ffi_address(ptr: *mut Address) {
    if !ptr.is_null() {
        let ffi_address: Box<Address> = unsafe { Box::from_raw(ptr) };
        if !(ffi_address.address.is_null()) {
            unsafe { zcashlc_string_free(ffi_address.address) }
        }
        drop(ffi_address);
    }
}
