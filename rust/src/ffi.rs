use std::convert::TryInto;
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

use anyhow::{Context, anyhow};
use bytes::Bytes;
use transparent::address::TransparentAddress;
use zcash_client_backend::{address::UnifiedAddress, data_api, encoding::AddressCodec as _};
use zcash_client_sqlite::AccountUuid;
use zcash_protocol::{consensus::Parameters, value::ZatBalance};
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
    ufvk: *mut c_char,
    uivk: *mut c_char,
}

impl Account {
    pub(crate) const NOT_FOUND: Account = Account {
        uuid_bytes: [0u8; 16],
        account_name: ptr::null_mut(),
        key_source: ptr::null_mut(),
        seed_fingerprint: [0u8; 32],
        hd_account_index: u32::MAX,
        ufvk: ptr::null_mut(),
        uivk: ptr::null_mut(),
    };

    pub(crate) fn from_account(
        account: &impl zcash_client_backend::data_api::Account<AccountId = AccountUuid>,
        params: &impl zcash_protocol::consensus::Parameters,
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
            ufvk: account.ufvk().map_or(ptr::null_mut(), |ufvk| {
                CString::new(ufvk.encode(params)).unwrap().into_raw()
            }),
            uivk: account.ufvk().map_or(ptr::null_mut(), |ufvk| {
                let uivk = ufvk.to_unified_incoming_viewing_key();
                CString::new(uivk.encode(params)).unwrap().into_raw()
            }),
        }
    }
}

/// Frees an [`Account`] value
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`Account`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_account(ptr: *mut Account) {
    if !ptr.is_null() {
        let account: Box<Account> = unsafe { Box::from_raw(ptr) };
        if !(account.account_name.is_null()) {
            unsafe { zcashlc_string_free(account.account_name) }
        }
        if !(account.key_source.is_null()) {
            unsafe { zcashlc_string_free(account.key_source) }
        }
        if !(account.ufvk.is_null()) {
            unsafe { zcashlc_string_free(account.ufvk) }
        }
        if !(account.uivk.is_null()) {
            unsafe { zcashlc_string_free(account.uivk) }
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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

    /// The value in the account that is currently locked by an explicit output lock (e.g. the
    /// migration residual locked via `zcashlc_migration_lock_residual`) and therefore excluded
    /// from `spendable_value`. Locked value still belongs to the account: it is part of the
    /// account's total (the sum of this struct's fields), it just cannot be selected for spending
    /// until it is unlocked.
    locked_value: i64,
}

impl Balance {
    pub(crate) fn new(balance: &data_api::Balance) -> Self {
        Self {
            spendable_value: ZatBalance::from(balance.spendable_value()).into(),
            change_pending_confirmation: ZatBalance::from(balance.change_pending_confirmation())
                .into(),
            value_pending_spendability: ZatBalance::from(balance.value_pending_spendability())
                .into(),
            locked_value: ZatBalance::from(balance.locked_value()).into(),
        }
    }

    /// [Slipstream API v2] An all-zero pool balance.
    pub(crate) fn zero() -> Self {
        Self {
            spendable_value: 0,
            change_pending_confirmation: 0,
            value_pending_spendability: 0,
            locked_value: 0,
        }
    }

    /// [Slipstream API v2] A pool balance carrying only a spendable value (the recovery
    /// override's single-number shape).
    pub(crate) fn from_spendable(spendable_value: i64) -> Self {
        Self {
            spendable_value,
            change_pending_confirmation: 0,
            value_pending_spendability: 0,
            locked_value: 0,
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

    /// The value of unspent Ironwood (Orchard note-version V3) outputs belonging to the account.
    ironwood_balance: Balance,

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
            ironwood_balance: Balance::new(balance.ironwood_balance()),
            unshielded: ZatBalance::from(balance.unshielded_balance().total()).into(),
        }
    }

    /// [Slipstream API v2 §0-5] The account's UUID bytes, for matching against
    /// `ext_slipstream_v_recovery_balance.account_uuid`.
    pub(crate) fn uuid_bytes(&self) -> &[u8; 16] {
        &self.account_uuid
    }

    /// [Slipstream API v2 §0-5] Recovery override — during a restore the only safe number is the
    /// per-account Σ of FINAL (reconciled) tx deltas, which the engine's recovery view reports
    /// WITHOUT a pool breakdown. So the whole net (clamped ≥ 0) is surfaced as one pool's
    /// `spendable_value` — `total()` == net for every consumer — and the per-pool breakdown is
    /// deliberately collapsed for the duration of recovery (headline correctness over breakdown
    /// fidelity). Transparent is already folded into the delta sum, so `unshielded` is zeroed to
    /// avoid double-counting.
    ///
    /// WHICH pool carries it matters once Ironwood exists, because hosts gate the "Migration
    /// Required" prompt on a nonzero ORCHARD balance. Post-activation the split is genuinely
    /// unknown here — a restored legacy wallet's value is Orchard, a post-activation wallet's is
    /// Ironwood — so the collapse goes to Ironwood, which fails safe: the prompt stays quiet
    /// during the (≤120 s) recovery window rather than telling a user to migrate on the strength
    /// of a guess, and the genuine prompt arrives with the real per-pool summary moments later.
    /// Before activation there is no Ironwood and no migration, so the net stays in Orchard.
    pub(crate) fn override_with_recovery_net(&mut self, net_zat: i64, ironwood_active: bool) {
        let net = Balance::from_spendable(net_zat.max(0));
        self.sapling_balance = Balance::zero();
        if ironwood_active {
            self.orchard_balance = Balance::zero();
            self.ironwood_balance = net;
        } else {
            self.orchard_balance = net;
            self.ironwood_balance = Balance::zero();
        }
        self.unshielded = 0;
    }

    /// [#1806] Build a balance carrying ONLY the recovery-view net, for the post-restore hold's
    /// synthesized summary (see [`WalletSummary::recovery_hold`]). Mirrors
    /// [`Self::override_with_recovery_net`], including which pool carries the collapsed net.
    pub(crate) fn recovery_only(
        account_uuid: [u8; 16],
        net_zat: i64,
        ironwood_active: bool,
    ) -> Self {
        let mut balance = Self {
            account_uuid,
            sapling_balance: Balance::zero(),
            orchard_balance: Balance::zero(),
            ironwood_balance: Balance::zero(),
            unshielded: 0,
        };
        balance.override_with_recovery_net(net_zat, ironwood_active);
        balance
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
/// - `recovery_progress` must, if non-null, point to a struct having the layout of
///   [`ScanProgress`].
#[repr(C)]
pub struct WalletSummary {
    account_balances: *mut AccountBalance,
    account_balances_len: usize,
    chain_tip_height: i32,
    fully_scanned_height: i32,
    scan_progress: *mut ScanProgress,
    recovery_progress: *mut ScanProgress,
    next_sapling_subtree_index: u64,
    next_orchard_subtree_index: u64,
    next_ironwood_subtree_index: u64,
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

        let scan_progress = Box::into_raw(Box::new(ScanProgress {
            numerator: *summary.progress().scan().numerator(),
            denominator: *summary.progress().scan().denominator(),
        }));

        let recovery_progress = if let Some(recovery_progress) = summary.progress().recovery() {
            Box::into_raw(Box::new(ScanProgress {
                numerator: *recovery_progress.numerator(),
                denominator: *recovery_progress.denominator(),
            }))
        } else {
            ptr::null_mut()
        };

        Ok(Box::into_raw(Box::new(Self {
            account_balances,
            account_balances_len,
            chain_tip_height: u32::from(summary.chain_tip_height()) as i32,
            fully_scanned_height: u32::from(summary.fully_scanned_height()) as i32,
            scan_progress,
            recovery_progress,
            next_sapling_subtree_index: summary.next_sapling_subtree_index(),
            next_orchard_subtree_index: summary.next_orchard_subtree_index(),
            next_ironwood_subtree_index: summary.next_ironwood_subtree_index(),
        })))
    }

    pub(crate) fn none() -> *mut Self {
        Box::into_raw(Box::new(Self {
            account_balances: ptr::null_mut(),
            account_balances_len: 0,
            chain_tip_height: 0,
            fully_scanned_height: -1,
            scan_progress: ptr::null_mut(),
            recovery_progress: ptr::null_mut(),
            next_sapling_subtree_index: 0,
            next_orchard_subtree_index: 0,
            next_ironwood_subtree_index: 0,
        }))
    }

    /// [Slipstream API v2 §0-5] Mutable view of the marshalled per-account balances, for the
    /// recovery override. Safe because the array was allocated by [`Self::some`] and is owned
    /// by this struct until [`zcashlc_free_wallet_summary`].
    pub(crate) fn account_balances_mut(&mut self) -> &mut [AccountBalance] {
        if self.account_balances.is_null() {
            &mut []
        } else {
            unsafe {
                std::slice::from_raw_parts_mut(self.account_balances, self.account_balances_len)
            }
        }
    }

    /// [#1806] Synthesize a balance-only summary for the post-restore hold: when the upstream
    /// `get_wallet_summary` transiently returns `None` right after a restore's
    /// `is_recovering 1→0` flip, the engine still holds the recovered notes in its reconciled
    /// recovery view. Rather than serve empty balances (which vanish the just-restored funds),
    /// this surfaces the per-account recovery nets. `fully_scanned_height` MUST stay ≥ 0 — the
    /// Swift bridge (`WalletSummary.fromFFI`) drops any summary with `fully_scanned_height < 0` as
    /// "no data yet" — so the caller passes the last-known real scanned/chain-tip heights (clamped
    /// here defensively). Scan-progress pointers are null: this is a pure balance carrier, and the
    /// Slipstream host derives sync progress from the engine snapshot, never from these fields.
    pub(crate) fn recovery_hold(
        balances: Vec<AccountBalance>,
        chain_tip_height: i32,
        fully_scanned_height: i32,
    ) -> *mut Self {
        let (account_balances, account_balances_len) = ptr_from_vec(balances);
        Box::into_raw(Box::new(Self {
            account_balances,
            account_balances_len,
            chain_tip_height: chain_tip_height.max(0),
            // Clamp ≥ 0: the Swift bridge drops any summary with `fully_scanned_height < 0`.
            fully_scanned_height: fully_scanned_height.max(0),
            scan_progress: ptr::null_mut(),
            recovery_progress: ptr::null_mut(),
            next_sapling_subtree_index: 0,
            next_orchard_subtree_index: 0,
            next_ironwood_subtree_index: 0,
        }))
    }
}

/// Frees an [`WalletSummary`] value.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`WalletSummary`].
///   See the safety documentation of [`WalletSummary`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_wallet_summary(ptr: *mut WalletSummary) {
    if !ptr.is_null() {
        let summary = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(summary.account_balances, summary.account_balances_len);
        if !summary.scan_progress.is_null() {
            let progress = unsafe { Box::from_raw(summary.scan_progress) };
            drop(progress);
        }
        if !summary.recovery_progress.is_null() {
            let progress = unsafe { Box::from_raw(summary.recovery_progress) };
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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

    /// Borrow the slice contents. Intended for crate-internal use (notably tests).
    ///
    /// # Safety
    ///
    /// Same invariants as the [`BoxedSlice`] struct documentation: `ptr` must be valid
    /// for reads of `len` bytes (or `len == 0`).
    #[cfg(test)]
    pub(crate) unsafe fn as_slice(&self) -> &[u8] {
        if self.len == 0 || self.ptr.is_null() {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
        }
    }
}

/// Frees a [`BoxedSlice`].
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of
///   [`BoxedSlice`]. See the safety documentation of [`BoxedSlice`].
#[unsafe(no_mangle)]
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
pub struct SymmetricKeys {
    ptr: *mut [u8; 32],
    len: usize, // number of elems
}

impl SymmetricKeys {
    pub fn ptr_from_vec(v: Vec<[u8; 32]>) -> *mut Self {
        let (ptr, len) = ptr_from_vec(v);
        Box::into_raw(Box::new(SymmetricKeys { ptr, len }))
    }
}

pub type TxIds = SymmetricKeys;

/// Transaction data stored by the wallet, with the bytes required for broadcast.
///
/// A null `raw` pointer represents an unknown transaction or one whose raw bytes are unavailable.
/// `expiry_height` is the consensus value; zero means that transaction expiry is disabled.
#[repr(C)]
pub struct TransactionData {
    pub txid: [u8; 32],
    pub raw: *mut u8,
    pub raw_len: usize,
    pub expiry_height: u32,
}

impl TransactionData {
    pub(crate) fn from_parts(txid: [u8; 32], raw_bytes: Vec<u8>, expiry_height: u32) -> *mut Self {
        let (raw, raw_len) = ptr_from_vec(raw_bytes);
        Box::into_raw(Box::new(Self {
            txid,
            raw,
            raw_len,
            expiry_height,
        }))
    }

    pub(crate) fn unavailable(txid: [u8; 32]) -> *mut Self {
        Box::into_raw(Box::new(Self {
            txid,
            raw: ptr::null_mut(),
            raw_len: 0,
            expiry_height: 0,
        }))
    }
}

/// Frees a [`TransactionData`] and its serialized transaction bytes.
///
/// # Safety
///
/// - `ptr` must either be null or point to a value returned by
///   [`crate::zcashlc_get_transaction`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_transaction_data(ptr: *mut TransactionData) {
    if !ptr.is_null() {
        let transaction_data = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(transaction_data.raw, transaction_data.raw_len);
        drop(transaction_data);
    }
}

/// Frees an array of `[u8; 32]` values.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of
///   [`SymmetricKeys`]. See the safety documentation of [`SymmetricKeys`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_symmetric_keys(ptr: *mut SymmetricKeys) {
    if !ptr.is_null() {
        let s: Box<SymmetricKeys> = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(s.ptr, s.len);
        drop(s);
    }
}

/// Frees an array of `[u8; 32]` values as allocated by `zcashlc_create_proposed_transactions`.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`TxIds`].
///   See the safety documentation of [`TxIds`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_txids(ptr: *mut TxIds) {
    unsafe { zcashlc_free_symmetric_keys(ptr) };
}

/// Specifies how a "spend max" request should be evaluated.
#[repr(C)]
pub enum MaxSpendMode {
    /// `MaxSpendable` will target to spend all _currently_ spendable funds where it
    /// could be the case that the wallet has received other funds that are not
    /// confirmed and therefore not spendable yet and the caller evaluates that as
    /// an acceptable scenario.
    MaxSpendable,
    /// `Everything` will target to spend **all funds** and will fail if there are
    /// unspendable funds in the wallet or if the wallet is not yet synced.
    Everything,
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

/// A type describing the mined-ness of transactions that should be returned in response to a
/// [`TransactionDataRequest`].
///
/// cbindgen:prefix-with-name
#[repr(C)]
pub enum TransactionStatusFilter {
    /// Only mined transactions should be returned.
    Mined,
    /// Only mempool transactions should be returned.
    Mempool,
    /// Both mined transactions and transactions in the mempool should be returned.
    All,
}

impl TransactionStatusFilter {
    pub(crate) fn from_rust(filter: data_api::TransactionStatusFilter) -> Self {
        match filter {
            data_api::TransactionStatusFilter::Mined => Self::Mined,
            data_api::TransactionStatusFilter::Mempool => Self::Mempool,
            data_api::TransactionStatusFilter::All => Self::All,
        }
    }
}

/// A type used to filter transactions to be returned in response to a [`TransactionDataRequest`],
/// in terms of the spentness of the transaction's transparent outputs.
///
/// cbindgen:prefix-with-name
#[repr(C)]
pub enum OutputStatusFilter {
    /// Only transactions that have currently-unspent transparent outputs should be returned.
    Unspent,
    /// All transactions corresponding to the data request should be returned, irrespective of
    /// whether or not those transactions produce transparent outputs that are currently unspent.
    All,
}

impl OutputStatusFilter {
    pub(crate) fn from_rust(filter: data_api::OutputStatusFilter) -> Self {
        match filter {
            data_api::OutputStatusFilter::Unspent => Self::Unspent,
            data_api::OutputStatusFilter::All => Self::All,
        }
    }
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
    TransactionsInvolvingAddress {
        /// The address to request transactions and/or UTXOs for.
        address: *mut c_char,
        /// Only transactions mined at heights greater than or equal to this height should be
        /// returned.
        block_range_start: u32,
        /// Only transactions mined at heights less than this height should be returned.
        ///
        /// Either a `u32` value, or `-1` representing no end height.
        block_range_end: i64,
        /// If `request_at` is non-negative, the caller evaluating this request should attempt to
        /// retrieve transaction data related to the specified address at a time that is as close
        /// as practical to the specified instant, and in a fashion that decorrelates this request
        /// to a light wallet server from other requests made by the same caller.
        ///
        /// `-1` is the only negative value, meaning "unset".
        ///
        /// This may be ignored by callers that are able to satisfy the request without exposing
        /// correlations between addresses to untrusted parties; for example, a wallet application
        /// that uses a private, trusted-for-privacy supplier of chain data can safely ignore this
        /// field.
        request_at: i64,
        /// The caller should respond to this request only with transactions that conform to the
        /// specified transaction status filter.
        tx_status_filter: TransactionStatusFilter,
        /// The caller should respond to this request only with transactions containing outputs
        /// that conform to the specified output status filter.
        output_status_filter: OutputStatusFilter,
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_transaction_data_requests(ptr: *mut TransactionDataRequests) {
    if !ptr.is_null() {
        let s: Box<TransactionDataRequests> = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec_with(s.ptr, s.len, |req| {
            if let TransactionDataRequest::TransactionsInvolvingAddress { address, .. } = req {
                unsafe { zcashlc_string_free(*address) }
            }
        });
        drop(s);
    }
}

/// What level of sleep to put a Tor client into.
#[repr(C)]
pub enum TorDormantMode {
    /// The client functions as normal, and background tasks run periodically.
    Normal,
    /// Background tasks are suspended, conserving CPU usage. Attempts to use the client will
    /// wake it back up again.
    Soft,
}

/// An exchange for which we know how to query the ZEC-USD exchange rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum ZecUsdExchange {
    Binance,
    CoinEx,
    Coinbase,
    DigiFinex,
    Gemini,
    Kraken,
    KuCoin,
    Mexc,
    Xt,
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
        network: &impl Parameters,
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_ffi_address(ptr: *mut Address) {
    if !ptr.is_null() {
        let ffi_address: Box<Address> = unsafe { Box::from_raw(ptr) };
        if !(ffi_address.address.is_null()) {
            unsafe { zcashlc_string_free(ffi_address.address) }
        }
        drop(ffi_address);
    }
}

/// A struct that contains a ZIP 325 Account Metadata Key.
pub struct AccountMetadataKey {
    pub(crate) inner: zip32::registered::SecretKey,
}

impl AccountMetadataKey {
    pub(crate) fn new(inner: zip32::registered::SecretKey) -> *mut Self {
        Box::into_raw(Box::new(AccountMetadataKey { inner }))
    }
}

/// Frees an AccountMetadataKey value
///
/// # Safety
///
/// - `ptr` must either be null or point to a struct having the layout of [`AccountMetadataKey`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_account_metadata_key(ptr: *mut AccountMetadataKey) {
    if !ptr.is_null() {
        let key: Box<AccountMetadataKey> = unsafe { Box::from_raw(ptr) };
        drop(key);
    }
}

/// An HTTP header for a request.
///
/// Memory is managed by Swift.
#[repr(C)]
pub struct HttpRequestHeader {
    /// The header name as a C string.
    pub(crate) name: *const c_char,

    /// The header value as a C string.
    pub(crate) value: *const c_char,
}

/// An HTTP header from a response.
///
/// Memory is managed by Rust.
#[repr(C)]
pub struct HttpResponseHeader {
    /// The header name as a C string.
    name: *mut c_char,

    /// The header value as a C string.
    value: *mut c_char,
}

/// A struct that contains an HTTP response.
#[repr(C)]
pub struct HttpResponseBytes {
    /// The response's status.
    status: u16,

    /// The response's version.
    version: *mut c_char,

    /// A pointer to a list of the response's headers.
    headers_ptr: *mut HttpResponseHeader,

    /// The length of the data in `headers_ptr`.
    headers_len: usize,

    /// A pointer to the HTTP body bytes.
    body_ptr: *mut u8,

    /// The length of the data in `body_ptr`.
    body_len: usize,
}

impl HttpResponseBytes {
    pub(crate) fn from_rust(response: http::Response<Bytes>) -> anyhow::Result<*mut Self> {
        let (parts, body) = response.into_parts();

        let headers = parts
            .headers
            .into_iter()
            .scan(None, |cur_name, (name, value)| {
                // Update the current header name in the iterator.
                if name.is_some() {
                    *cur_name = name;
                }

                Some(value.to_str().map_err(|e| anyhow!(e)).and_then(|value| {
                    Ok((
                        CString::new(cur_name.as_ref().expect("present").as_str().to_owned())?,
                        CString::new(value.to_owned())?,
                    ))
                }))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let (headers_ptr, headers_len) = ptr_from_vec(
            headers
                .into_iter()
                .map(|(name, value)| HttpResponseHeader {
                    name: name.into_raw(),
                    value: value.into_raw(),
                })
                .collect(),
        );

        let (body_ptr, body_len) = ptr_from_vec(body.to_vec());

        Ok(Box::into_raw(Box::new(HttpResponseBytes {
            status: parts.status.as_u16(),
            version: CString::new(format!("{:?}", parts.version))
                .unwrap()
                .into_raw(),
            headers_ptr,
            headers_len,
            body_ptr,
            body_len,
        })))
    }
}

/// Frees an HttpResponseBytes value
///
/// # Safety
///
/// - `ptr` must either be null or point to a struct having the layout of [`HttpResponseBytes`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_http_response_bytes(ptr: *mut HttpResponseBytes) {
    if !ptr.is_null() {
        let response: Box<HttpResponseBytes> = unsafe { Box::from_raw(ptr) };
        unsafe { zcashlc_string_free(response.version) }
        free_ptr_from_vec_with(response.headers_ptr, response.headers_len, |header| {
            unsafe { zcashlc_string_free(header.name) };
            unsafe { zcashlc_string_free(header.value) };
        });
        free_ptr_from_vec(response.body_ptr, response.body_len);
        drop(response);
    }
}

/// A description of the policy that is used to determine what notes are available for spending,
/// based upon the number of confirmations (the number of blocks in the chain since and including
/// the block in which a note was produced.)
///
/// See [`ZIP 315`] for details including the definitions of "trusted" and "untrusted" notes.
///
/// # Note
///
/// `trusted` and `untrusted` are both meant to be non-zero values.
/// `0` will be treated as a request for a default value.
///
/// [`ZIP 315`]: https://zips.z.cash/zip-0315
#[repr(C)]
pub struct ConfirmationsPolicy {
    /// The number of confirmations required before trusted notes may be spent. NonZero, set this
    /// and `untrusted` to zero to accept the default value for each.
    pub(crate) trusted: u32,
    /// The number of confirmations required before untrusted notes may be spent. NonZero, set this
    /// and `trusted` both to zero to accept the default value for each.
    pub(crate) untrusted: u32,
    /// A flag that enables selection of zero-conf transparent UTXOs for spends in shielding
    /// transactions.
    pub(crate) allow_zero_conf_shielding: bool,
}

/// The default confirmations policy according to [`ZIP 315`].
///
/// * Require 3 confirmations for "trusted" transaction outputs (outputs produced by the wallet)
/// * Require 10 confirmations for "untrusted" outputs (those sent to the wallet by external/third
///   parties)
/// * Allow zero-conf shielding of transparent UTXOs irrespective of their origin, but treat the
///   resulting shielding transaction's outputs as though the original transparent UTXOs had
///   instead been received as untrusted shielded outputs.
///
/// [`ZIP 315`]: https://zips.z.cash/zip-0315
impl Default for ConfirmationsPolicy {
    fn default() -> Self {
        ConfirmationsPolicy {
            trusted: 3,
            untrusted: 10,
            allow_zero_conf_shielding: true,
        }
    }
}

impl TryFrom<ConfirmationsPolicy> for data_api::wallet::ConfirmationsPolicy {
    type Error = anyhow::Error;

    fn try_from(value: ConfirmationsPolicy) -> Result<Self, Self::Error> {
        // Ensure the confirmations are symmetrical in requesting a default
        if value.trusted == 0 {
            anyhow::ensure!(
                value.untrusted == 0,
                "Trusted and untrusted confirmations must both be zero to default properly"
            );

            let def = data_api::wallet::ConfirmationsPolicy::default();
            data_api::wallet::ConfirmationsPolicy::new(
                def.trusted(),
                def.untrusted(),
                value.allow_zero_conf_shielding,
            )
        } else {
            data_api::wallet::ConfirmationsPolicy::new(
                value
                    .trusted
                    .try_into()
                    .context("Trusted confirmations must be non-zero")?,
                value
                    .untrusted
                    .try_into()
                    .context("Untrusted confirmations must be non-zero")?,
                value.allow_zero_conf_shielding,
            )
        }
        .map_err(|e| anyhow::anyhow!("Could not construct ConfirmationsPolicy: {e}"))
    }
}

/// A single-use transparent address, along with metadata about the address's use within the
/// wallet's ephemeral gap limit.
#[repr(C)]
pub struct SingleUseTaddr {
    pub(crate) address: *mut c_char,
    pub(crate) gap_position: u32,
    pub(crate) gap_limit: u32,
}

impl SingleUseTaddr {
    pub(crate) fn from_rust(
        network: &impl Parameters,
        address: &TransparentAddress,
        gap_position: u32,
        gap_limit: u32,
    ) -> *mut Self {
        let address_str = address.encode(&network);
        Box::into_raw(Box::new(SingleUseTaddr {
            address: CString::new(address_str).unwrap().into_raw(),
            gap_position,
            gap_limit,
        }))
    }
}

/// Frees an [`SingleUseTaddr`] value.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`SingleUseTaddr`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_single_use_taddr(ptr: *mut SingleUseTaddr) {
    if !ptr.is_null() {
        let res = unsafe { Box::from_raw(ptr) };
        unsafe { zcashlc_string_free(res.address) }
        drop(res)
    }
}

/// The result of checking for UTXOs received by an ephemeral address.
///
/// cbindgen:prefix-with-name
#[repr(C, u8)]
pub enum AddressCheckResult {
    /// No UTXOs were found as a result of the check.
    NotFound,
    /// UTXOs were found for the given address.
    Found { address: *mut c_char },
}

impl AddressCheckResult {
    pub(crate) fn from_rust(
        network: &impl Parameters,
        found: Option<TransparentAddress>,
    ) -> *mut Self {
        let res = match found {
            None => AddressCheckResult::NotFound,
            Some(addr) => {
                let addr_str = addr.encode(&network);
                AddressCheckResult::Found {
                    address: CString::new(addr_str).unwrap().into_raw(),
                }
            }
        };

        Box::into_raw(Box::new(res))
    }
}

/// Frees an [`AddressCheckResult`] value.
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`AddressCheckResult`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_address_check_result(ptr: *mut AddressCheckResult) {
    if !ptr.is_null() {
        let res = unsafe { Box::from_raw(ptr) };
        if let AddressCheckResult::Found { address } = *res {
            unsafe { zcashlc_string_free(address) }
        };
        drop(res)
    }
}

#[cfg(test)]
mod recovery_hold_tests {
    use super::*;

    #[test]
    fn recovery_only_puts_clamped_net_in_orchard_spendable_before_activation() {
        let b = AccountBalance::recovery_only([7u8; 16], 12_345, false);
        assert_eq!(b.uuid_bytes(), &[7u8; 16]);
        assert_eq!(b.orchard_balance.spendable_value, 12_345);
        assert_eq!(b.orchard_balance.value_pending_spendability, 0);
        assert_eq!(b.sapling_balance.spendable_value, 0);
        assert_eq!(b.ironwood_balance.spendable_value, 0);
        assert_eq!(b.unshielded, 0);
    }

    /// Post-activation the collapsed net goes to Ironwood, so a host gating "Migration Required"
    /// on a nonzero ORCHARD balance is not told to migrate on the strength of a guess (the
    /// recovery view has no pool breakdown to make an honest one from).
    #[test]
    fn recovery_only_puts_clamped_net_in_ironwood_after_activation() {
        let b = AccountBalance::recovery_only([7u8; 16], 12_345, true);
        assert_eq!(b.ironwood_balance.spendable_value, 12_345);
        assert_eq!(b.orchard_balance.spendable_value, 0);
        assert_eq!(b.sapling_balance.spendable_value, 0);
        assert_eq!(b.unshielded, 0);
    }

    #[test]
    fn recovery_only_clamps_negative_net_to_zero() {
        let b = AccountBalance::recovery_only([1u8; 16], -5, false);
        assert_eq!(b.orchard_balance.spendable_value, 0);
    }

    #[test]
    fn recovery_hold_synthesizes_balances_with_nonnegative_scanned_height() {
        let entries = vec![
            AccountBalance::recovery_only([1u8; 16], 100, false),
            AccountBalance::recovery_only([2u8; 16], 200, false),
        ];
        let ptr = WalletSummary::recovery_hold(entries, 2_800_000, 2_799_900);
        // SAFETY: freshly built by `recovery_hold`; freed below.
        let summary = unsafe { &mut *ptr };
        assert!(summary.fully_scanned_height >= 0);
        assert_eq!(summary.fully_scanned_height, 2_799_900);
        assert_eq!(summary.chain_tip_height, 2_800_000);
        assert_eq!(summary.account_balances_mut().len(), 2);
        unsafe { zcashlc_free_wallet_summary(ptr) };
    }

    #[test]
    fn recovery_hold_clamps_negative_scanned_height_so_swift_keeps_it() {
        let ptr = WalletSummary::recovery_hold(Vec::new(), 0, -1);
        // SAFETY: freshly built by `recovery_hold`; freed below.
        let summary = unsafe { &mut *ptr };
        assert!(summary.fully_scanned_height >= 0);
        assert_eq!(summary.account_balances_mut().len(), 0);
        unsafe { zcashlc_free_wallet_summary(ptr) };
    }

    // ── serve_wallet_summary: the extracted serve path driven with a real fixture DB (C1) ────
    //
    // These drive the REAL serve path (classify → gate → decide → build), not just the pure
    // decision function — the seam the reviewer flagged: a STALE cached `Some` at the flip must
    // route to a synthesized hold, never release. `build_upstream` is injected so the marshalling
    // of a real upstream `Some` (which needs a `data_api::WalletSummary` the harness cannot
    // fabricate) is stubbed with a distinctive sentinel; the DB reads hit a real fixture SQLite.

    use crate::{
        HoldLatch, POST_FLIP_HOLD_CAP, UpstreamKind, classify_upstream, serve_wallet_summary,
    };
    use std::time::{Duration, Instant};

    fn acct(n: u8) -> [u8; 16] {
        [n; 16]
    }

    /// A temp wallet DB carrying the two tables the serve path reads: the recovery-view balances
    /// and `v_transactions` (for the unmined-spend gate). Returns its path; caller removes it.
    fn temp_wallet_db(
        recovery: &[([u8; 16], i64)],
        spends: &[([u8; 16], Option<i64>, i64, Option<i64>)],
    ) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "e2fix_serve_{}_{}.db",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_file(&path);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE ext_slipstream_v_recovery_balance (account_uuid BLOB, balance_zat INTEGER);
             CREATE TABLE v_transactions (account_uuid BLOB, mined_height INTEGER, spent_note_count INTEGER, expired_unmined INTEGER);",
        )
        .unwrap();
        for (u, bal) in recovery {
            conn.execute(
                "INSERT INTO ext_slipstream_v_recovery_balance (account_uuid, balance_zat) VALUES (?1, ?2)",
                rusqlite::params![u.to_vec(), bal],
            )
            .unwrap();
        }
        for (u, mined, spent, expired) in spends {
            conn.execute(
                "INSERT INTO v_transactions (account_uuid, mined_height, spent_note_count, expired_unmined) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![u.to_vec(), mined, spent, expired],
            )
            .unwrap();
        }
        drop(conn);
        path
    }

    /// (uuid, orchard spendable) for each account slot of the served summary.
    fn balances_of(ptr: *mut WalletSummary) -> Vec<([u8; 16], i64)> {
        // SAFETY: `ptr` was just built by the serve path; borrowed only for this read.
        let summary = unsafe { &mut *ptr };
        summary
            .account_balances_mut()
            .iter()
            .map(|b| (*b.uuid_bytes(), b.orchard_balance.spendable_value))
            .collect()
    }

    /// A distinctive SENTINEL upstream `Some` (account 0xEE, orchard 999) — served only when the
    /// decision is `Upstream`/`RecoveringOverride`, so tests can tell it from a synthesized hold.
    fn sentinel_upstream() -> anyhow::Result<*mut WalletSummary> {
        Ok(WalletSummary::recovery_hold(
            vec![AccountBalance::recovery_only(acct(0xEE), 999, false)],
            100,
            90,
        ))
    }
    fn empty_upstream() -> anyhow::Result<*mut WalletSummary> {
        Ok(WalletSummary::none())
    }

    /// C1 (wiring): the flip tick with a STALE cached `Some` serves the SYNTHESIZED recovery
    /// balances from the fixture DB — NOT the stale upstream — and does NOT release the latch.
    #[test]
    fn serve_flip_tick_with_stale_some_holds_recovery() {
        let db = temp_wallet_db(&[(acct(1), 5000)], &[]);
        let cache =
            std::sync::Mutex::new(Some(std::collections::HashMap::from([(acct(1), 5000i64)])));
        let base = Instant::now();
        let kind = classify_upstream(true, true);
        assert_eq!(kind, UpstreamKind::StaleSome);
        let (latch, ptr) = serve_wallet_summary(
            false,
            false,
            kind,
            Some((100, 90)),
            Some(true),
            HoldLatch::Idle,
            base,
            POST_FLIP_HOLD_CAP,
            &db,
            &cache,
            sentinel_upstream,
        )
        .unwrap();
        assert!(
            matches!(latch, HoldLatch::Engaged { .. }),
            "a stale Some at the flip must engage the hold, not release"
        );
        assert_eq!(
            balances_of(ptr),
            vec![(acct(1), 5000)],
            "must serve synthesized recovery balances, not the stale upstream sentinel"
        );
        unsafe { zcashlc_free_wallet_summary(ptr) };
        let _ = std::fs::remove_file(&db);
    }

    /// C1 (wiring): once engaged, a later `None` tick keeps serving the synthesized hold.
    #[test]
    fn serve_engaged_none_tick_keeps_holding() {
        let db = temp_wallet_db(&[(acct(1), 7000)], &[]);
        let cache = std::sync::Mutex::new(None);
        let base = Instant::now();
        let (latch, ptr) = serve_wallet_summary(
            false,
            false,
            UpstreamKind::None,
            Some((100, 90)),
            Some(false),
            HoldLatch::Engaged { flip_at: base },
            base + Duration::from_secs(20),
            POST_FLIP_HOLD_CAP,
            &db,
            &cache,
            empty_upstream,
        )
        .unwrap();
        assert!(matches!(latch, HoldLatch::Engaged { .. }));
        assert_eq!(balances_of(ptr), vec![(acct(1), 7000)]);
        unsafe { zcashlc_free_wallet_summary(ptr) };
        let _ = std::fs::remove_file(&db);
    }

    /// A FRESH post-flip `Some` releases the latch and serves the upstream (sentinel) balances.
    #[test]
    fn serve_fresh_some_releases_and_serves_upstream() {
        let db = temp_wallet_db(&[(acct(1), 5000)], &[]);
        let cache = std::sync::Mutex::new(None);
        let base = Instant::now();
        let (latch, ptr) = serve_wallet_summary(
            false,
            false,
            UpstreamKind::FreshSome,
            Some((100, 90)),
            Some(false),
            HoldLatch::Engaged { flip_at: base },
            base + Duration::from_secs(5),
            POST_FLIP_HOLD_CAP,
            &db,
            &cache,
            sentinel_upstream,
        )
        .unwrap();
        assert_eq!(latch, HoldLatch::Released);
        assert_eq!(
            balances_of(ptr),
            vec![(acct(0xEE), 999)],
            "a fresh Some serves the upstream, not the hold"
        );
        unsafe { zcashlc_free_wallet_summary(ptr) };
        let _ = std::fs::remove_file(&db);
    }

    /// The safety gate at the wiring level: an unmined, unexpired spend (read from the real
    /// `v_transactions` fixture) releases the latch and serves empty.
    #[test]
    fn serve_unmined_spend_releases_and_serves_empty() {
        let db = temp_wallet_db(&[(acct(1), 5000)], &[(acct(1), None, 1, Some(0))]);
        let cache = std::sync::Mutex::new(None);
        let base = Instant::now();
        let (latch, ptr) = serve_wallet_summary(
            false,
            false,
            UpstreamKind::None,
            Some((100, 90)),
            Some(false),
            HoldLatch::Engaged { flip_at: base },
            base + Duration::from_secs(10),
            POST_FLIP_HOLD_CAP,
            &db,
            &cache,
            empty_upstream,
        )
        .unwrap();
        assert_eq!(latch, HoldLatch::Released);
        assert!(
            balances_of(ptr).is_empty(),
            "a pending spend must serve empty"
        );
        unsafe { zcashlc_free_wallet_summary(ptr) };
        let _ = std::fs::remove_file(&db);
    }

    /// The recovering path reads the DB nets and overrides every slot with them.
    #[test]
    fn serve_recovering_overrides_with_db_nets() {
        let db = temp_wallet_db(&[(acct(1), 5000)], &[]);
        let cache = std::sync::Mutex::new(None);
        let base = Instant::now();
        let (latch, ptr) = serve_wallet_summary(
            true,
            false,
            UpstreamKind::StaleSome,
            Some((100, 90)),
            Some(true),
            HoldLatch::Idle,
            base,
            POST_FLIP_HOLD_CAP,
            &db,
            &cache,
            || {
                Ok(WalletSummary::recovery_hold(
                    vec![AccountBalance::recovery_only(acct(1), 111, false)],
                    100,
                    90,
                ))
            },
        )
        .unwrap();
        assert_eq!(
            latch,
            HoldLatch::Idle,
            "recovering must not engage the hold latch"
        );
        assert_eq!(
            balances_of(ptr),
            vec![(acct(1), 5000)],
            "recovering overrides slots with DB nets"
        );
        unsafe { zcashlc_free_wallet_summary(ptr) };
        let _ = std::fs::remove_file(&db);
    }

    /// I1: an ordinary `None`-serving tick with an IDLE latch (never flipped) must not touch the
    /// DB — proven by pointing the serve path at a non-existent DB and still getting a clean empty.
    #[test]
    fn serve_idle_none_tick_never_touches_db() {
        let cache = std::sync::Mutex::new(None);
        let base = Instant::now();
        let bogus = std::path::Path::new("/nonexistent/e2fix/does_not_exist.db");
        let (latch, ptr) = serve_wallet_summary(
            false,
            false,
            UpstreamKind::None,
            None,
            Some(false),
            HoldLatch::Idle,
            base,
            POST_FLIP_HOLD_CAP,
            bogus,
            &cache,
            empty_upstream,
        )
        .unwrap();
        assert_eq!(latch, HoldLatch::Idle);
        assert!(balances_of(ptr).is_empty());
        unsafe { zcashlc_free_wallet_summary(ptr) };
    }
}
