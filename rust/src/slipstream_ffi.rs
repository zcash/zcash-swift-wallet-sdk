//! ZODL Slipstream (AGPL-3.0-only) FFI surface.
//!
//! This module holds the `zcashlc_slipstream_*` C ABI exposed to the SlipstreamSynchronizer
//! host, wrapping the `slipstream-core` (published as `zodl-slipstream`) sync engine. It is
//! compiled ONLY with the `slipstream` cargo feature (or `gpu`, which implies it) — the default
//! (MIT-clean) `libzcashlc` build carries none of this AGPL surface. See the `slipstream-core`
//! dependency comment in `Cargo.toml` for the licensing rationale.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::slice;

use anyhow::anyhow;
use ffi_helpers::panic::catch_panic;
use prost::Message;
use zcash_client_backend::data_api::WalletRead;
use zcash_client_backend::keys::UnifiedFullViewingKey;
use zcash_client_sqlite::AccountUuid;
use zcash_protocol::consensus::{
    BlockHeight,
    Network::{MainNetwork, TestNetwork},
    NetworkUpgrade, Parameters,
};

use crate::ffi;
use zcash_client_backend::data_api::wallet;
use crate::{
    NetworkParams, anchor_retention_interval, free_ptr_from_vec, ptr_from_vec, unwrap_exc_or,
    unwrap_exc_or_null, wallet_db,
};

// ── Slipstream FFI surface ────────────────────────────────────────────────────
//
// These functions are ADDITIVE — they do not modify any existing item above.
// Pattern mirrors `zcashlc_create_tor_runtime` / `zcashlc_free_tor_runtime`
// (lib.rs:3157-3195): Box::into_raw / Box::from_raw, catch_panic, unwrap_exc_or_null.
// D7 deviation: the tokio runtime is created at `open` and lives for the full
// handle lifetime (dropped at `free`), not created per-start. This mirrors the
// TorRuntime precedent where the runtime is owned by the handle.
//
// cbindgen note (C4/C12): cbindgen only parses the root crate. `FfiSlipstreamSnapshot`
// and `FfiSlipstreamEvent` are therefore defined directly here so they appear in the
// generated `zcashlc.h`.
//
// `SlipstreamHandle` MUST also be defined here (not imported from the dep crate) so
// cbindgen emits `typedef struct SlipstreamHandle SlipstreamHandle;` in the header.
// Without it the ObjC module fails to compile with "unknown type name 'SlipstreamHandle'".
// This is the TorRuntime pattern: `TorRuntime` is defined in rust/src/tor.rs (crate-local)
// so cbindgen can see and emit its opaque typedef. We wrap the core handle in a thin
// crate-local newtype here — the wrapper owns the core handle via `inner`.

use slipstream_core::ffi_handle::SyncState;

/// Opaque handle to a Slipstream engine instance.
///
/// Wraps [`slipstream_core::ffi_handle::SlipstreamHandle`] as a crate-local newtype so
/// that cbindgen (which only parses the root crate) emits the required opaque typedef
/// `typedef struct SlipstreamHandle SlipstreamHandle;` in the generated `zcashlc.h`.
///
/// All state is stored in `inner`; the six `zcashlc_slipstream_*` functions delegate
/// directly to it.
pub struct SlipstreamHandle {
    inner: slipstream_core::ffi_handle::SlipstreamHandle,
    /// [API v2.1 E-1] Upstream-summary cache: the expensive `get_wallet_summary` walk is
    /// rationed HERE (engine-side), so hosts may call the unified summary whenever they
    /// like. Arc'd because the background refresh thread outlives the FFI call.
    summary_cache: std::sync::Arc<std::sync::Mutex<Option<SummaryCacheEntry>>>,
    /// [API v2.1 E-1] One background refresh in flight at a time.
    summary_refresh_inflight: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// [#1806] Last successfully-read recovery-balance nets (account-uuid bytes → reconciled
    /// net zatoshi), used ONLY as a fallback when the bounded (250 ms) read of
    /// `slipstream_v_recovery_balance` is contended — so a momentarily-locked view never
    /// nulls the whole summary. `None` until the first successful read; see
    /// [`zcashlc_slipstream_wallet_summary`].
    recovery_nets_cache: std::sync::Mutex<Option<std::collections::HashMap<[u8; 16], i64>>>,
    /// [API v2.1 E-2] Tip-freshness for the [#1591] stale-tip spendable mask — the engine
    /// owns the FACT (it is the thing refreshing the tip); hosts apply the mask transform.
    /// `shouldMarkChainTipUpdated` semantics at the source: fresh once THIS run has
    /// persisted a freshly-fetched server tip (`Progress::tip_refreshes` advanced past the
    /// baseline captured at `start()` — the engine bumps it only after `update_chain_tip`
    /// succeeds), or when a pass reaches Done. Counter-based (not tip-value-based) so the
    /// E-3 DB-seeded tip can neither fake freshness nor suppress a genuine refresh that
    /// happens to fetch the same height.
    tip_refreshes_at_run_start: std::sync::atomic::AtomicU64,
    tip_fresh: std::sync::atomic::AtomicBool,
    /// [API v2.1 E-2] `stop()` timestamp: freshness survives a stop→start hop shorter than
    /// 120 s (the SDK's `SDKFlags.sdkStarted` quick-background parity).
    last_stop_at: std::sync::Mutex<Option<std::time::Instant>>,
    /// [v0.7 P1b] Alternate lightwalletd servers for probe-then-commit + wire
    /// failover. Set via [`zcashlc_slipstream_set_alternate_servers`]; each
    /// `start()` merges them into the pass config, deduped against the
    /// handle's primary (hosts pass their FULL server list — the selected
    /// server is usually in it). Empty = pre-v0.7 single-server behavior.
    alternate_servers: std::sync::Mutex<Vec<slipstream_core::config::Endpoint>>,
    /// [#1806] Post-restore balance-hold state (latch + last-observed recovery flag + last real
    /// heights). See [`PostFlipHold`] and [`zcashlc_slipstream_wallet_summary`].
    post_flip_hold: std::sync::Mutex<PostFlipHold>,
}

/// [API v2.1 E-1] One cached upstream wallet summary + the engine facts it was captured
/// under. Refresh triggers: the pass crossed a range boundary (`ranges_completed` moved),
/// the engine state changed (e.g. Syncing → Done), or — outside a scan — the idle TTL
/// elapsed. While Syncing between boundaries the cache is served as-is: this is the T5.5
/// no-walk-while-scanning invariant, now engine-owned.
struct SummaryCacheEntry {
    captured_at: std::time::Instant,
    ranges_completed: u64,
    state: u8,
    /// [#1806] `None` = a walked "no balance data yet" result, cached like any other so a
    /// fresh / just-imported wallet does not re-walk synchronously on every poll tick.
    summary: Option<zcash_client_backend::data_api::WalletSummary<AccountUuid>>,
    /// [#1806] The `is_recovering` flag captured when THIS entry's walk STARTED. A `Some`
    /// walked while recovering predates the `is_recovering 1→0` flip, so it is a STALE pre-flip
    /// summary (see [`classify_upstream`] / C1): the post-restore hold must not release on it or
    /// serve it raw. `false` for a walk that ran outside recovery (post-flip → fresh).
    walked_while_recovering: bool,
}

/// [API v2.1 E-1] Idle refresh TTL — matches the SDK's historical idle/error refetch cadence.
const SUMMARY_IDLE_TTL: std::time::Duration = std::time::Duration::from_secs(2);
/// [API v2.1 E-2] Freshness survives stop→start hops shorter than this (SDKFlags parity).
const TIP_FRESH_STOP_WINDOW: std::time::Duration = std::time::Duration::from_secs(120);

/// C-compatible snapshot of Slipstream engine progress. Returned by
/// [`zcashlc_slipstream_snapshot`] (by value — no heap allocation).
///
/// Sync state codes: 0 = idle, 1 = syncing, 2 = error, 3 = done.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct FfiSlipstreamSnapshot {
    /// Current chain tip height as reported by the server (0 = not yet fetched).
    pub chain_tip: u64,
    /// Number of compact blocks fetched in the current/last sync pass.
    pub fetched_blocks: u64,
    /// Number of compact blocks scanned in the current/last sync pass.
    pub scanned_blocks: u64,
    /// Number of transactions enhanced in the current/last sync pass.
    pub enhanced_txs: u64,
    /// End height of the block range currently being processed.
    pub current_range_end: u64,
    /// Sync state: 0 = idle, 1 = syncing, 2 = error, 3 = done.
    pub state: u8,
    // ── T5.5 counter-based progress fields (appended at END for padding stability) ──
    /// Total blocks in the current pass. Set (not accumulated) by the scheduler each time
    /// suggest_scan_ranges returns: value = scanned_so_far + sum(all returned ranges).
    /// Denominator for counter-based progress: scanned_blocks / pass_total_blocks.
    pub pass_total_blocks: u64,
    /// Spendable hint: 0 = not yet spendable; 1 = a ChainTip-priority range has completed
    /// scanning (≈ SBS funds-spendable semantics). Latches to 1; never resets within a pass.
    pub spendable_hint: u8,
    // ── T5.6 range-boundary signals (appended at END for padding stability) ──
    /// Number of suggested ranges whose scan+enhancement has completed in the current pass.
    /// Swift observes this counter and triggers ONE balance-summary fetch per boundary.
    pub ranges_completed: u64,
    // ── API v2 fields (appended at END for padding stability) ──
    /// 1 while the wallet is inside its recovery (restore backfill) window; engine-computed
    /// with the fail-safe latch built in (terminal Done/Error force 0).
    pub is_recovering: u8,
    /// Blessed progress, 0..=1000, session-monotonic (never regresses while the handle
    /// lives; Done forces 1000). Replaces host-side progress math.
    pub progress_permille: u16,
    /// Seconds since last forward progress while syncing; 0 otherwise.
    pub stalled_seconds: u32,
    // ── API v2.1 fields (appended at END for padding stability) ──
    /// [E-2] 1 once the CURRENT run has refreshed the wallet-DB chain tip (the [#1591]
    /// stale-tip fact, engine-owned): the engine's tip-refresh counter advanced past its
    /// `start()` baseline (bumped only after `update_chain_tip` succeeds), or a pass
    /// reached Done. Survives stop→start hops shorter than 120 s. While 0, hosts must
    /// mask spendable balances (the mask transform stays host-side because the C
    /// `AccountBalance` cannot express the awaiting-resolution shift).
    pub tip_fresh: u8,
    /// [E-4] Monotonic version of the wallet's stored transaction set: bumps exactly when
    /// enhancement stores/updates a tx, the mempool monitor stores a 0-conf hit, a range
    /// boundary detects a reconcile-linkage transition, or the host pokes
    /// [`zcashlc_slipstream_notify_tx_change`] after a submit. Host rule (one line):
    /// version moved since the last poll → re-fetch transactions + publish
    /// `foundTransactions`. Never reset while the handle lives.
    pub tx_set_version: u64,
}

/// [API v2.1 E-6] C-compatible wallet-provisioning anchor. Returned by
/// [`zcashlc_slipstream_restore_anchor`]; free with
/// [`zcashlc_slipstream_free_restore_anchor`].
///
/// RESTORE intent: `height` = the recover_until height (always valid by policy — live tip
/// or the offline `max(checkpoint, birthday+1)` fallback); `treestate` null.
/// NEW intent: `height` + serialized `TreeState` protobuf bytes = the reorg-safe recent
/// tree state; `height` 0 + null `treestate` when offline (host keeps its checkpoint).
#[repr(C)]
pub struct FfiRestoreAnchor {
    /// See the type docs — recover_until (restore) or the anchor height (new).
    pub height: u64,
    /// Serialized `TreeState` protobuf bytes, or null (see the type docs).
    pub treestate: *mut u8,
    /// Length of `treestate` (0 when null).
    pub treestate_len: usize,
}

/// C-compatible Slipstream engine event record. Returned by
/// [`zcashlc_slipstream_drain_events`] in a caller-allocated buffer.
///
/// Event tags: 1 = SyncStarted, 2 = SyncProgress, 3 = SyncDone,
/// 4 = SyncError, 5 = FoundTransactions.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FfiSlipstreamEvent {
    /// Event tag (see type documentation for values).
    pub tag: u8,
    /// For SyncDone: transactions stored. For SyncError: error code. Others: 0.
    pub value: u64,
}

/// Installs (once per process) a chaining panic hook that reports every Rust panic
/// through `tracing::error!` before delegating to the previously-installed hook.
///
/// `zcashlc_init_on_load` installs `log_panics`,
/// which reports panics via the `log` facade — that reaches os_log only through the
/// `tracing-log` bridge AND only when the app initialized logging at a level that
/// admits it. This hook reports directly through `tracing` so device logs always
/// carry the panic message and backtrace location, no matter how the `log` facade
/// is configured. Chaining preserves `log_panics` (and any test-harness hook).
static SLIPSTREAM_PANIC_HOOK: std::sync::Once = std::sync::Once::new();

fn install_slipstream_panic_hook() {
    SLIPSTREAM_PANIC_HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            tracing::error!(panic = %info, "rust panic");
            previous(info);
        }));
    });
}

/// Opens a Slipstream engine handle.
///
/// - `db_data`/`db_data_len`: path to the wallet data.db (UTF-8 bytes, no NUL terminator).
/// - `server_host`/`server_host_len`: lightwalletd hostname (UTF-8 bytes).
/// - `server_port`: lightwalletd port.
/// - `use_tls`: `true` for TLS (mainnet), `false` for plaintext.
/// - `network_id`: `1` for mainnet, `0` for testnet.
/// - `total_memory_bytes`: host physical memory in bytes (Swift passes
///   `ProcessInfo.processInfo.physicalMemory`); `0` = unknown. Drives device-memory
///   budget derating at start for <3 GiB devices (T8.4); `0`/big devices keep defaults.
///
/// Returns an opaque handle pointer, or null on failure.
/// Free with [`zcashlc_slipstream_free`] when done.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, with
///   alignment of `1`. Its contents must be a valid system path in the OS's preferred
///   representation.
/// - `server_host` must be non-null and valid for reads for `server_host_len` bytes,
///   with alignment of `1`. Its contents must be valid UTF-8.
/// - Neither pointer's memory must be mutated for the duration of the call.
/// - `db_data_len` and `server_host_len` must each be no larger than `isize::MAX`.
/// - Call [`zcashlc_slipstream_free`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_open(
    db_data: *const u8,
    db_data_len: usize,
    server_host: *const u8,
    server_host_len: usize,
    server_port: u16,
    use_tls: bool,
    network_id: u32,
    total_memory_bytes: u64,
) -> *mut SlipstreamHandle {
    let res = catch_panic(|| {
        // B1 : make sure every panic is visible in device logs (os_log via
        // the tracing layers) — see install_slipstream_panic_hook.
        install_slipstream_panic_hook();

        let db_path = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(db_data, db_data_len)
        }));
        let host =
            std::str::from_utf8(unsafe { slice::from_raw_parts(server_host, server_host_len) })
                .map_err(|e| anyhow!("server_host UTF-8: {e}"))?;
        let network = if network_id == 1 {
            MainNetwork
        } else {
            TestNetwork
        };

        // [B6, second half] Persist the anchor-retention marks the engine's in-memory trees
        // draw but its flush never writes: the open-time deep-history heal spares only ids
        // present in the SQLITE store's retained set, so reconcile the marks BEFORE any
        // engine session (and with it the heal) exists — including the E-3 snapshot seed's
        // own `WalletSession::open` a few lines below, which already runs that heal on
        // every open. Non-fatal by design — a wallet that cannot be marked must still open
        // and sync.
        let network_params = NetworkParams::Standard(network);
        match unsafe { wallet_db(db_data, db_data_len, network_params) }.and_then(|mut wallet| {
            crate::retained_marks::reconcile_retained_anchor_marks(&mut wallet, &network_params)
        }) {
            Ok(0) => {}
            Ok(n) => {
                tracing::info!(
                    marks = n,
                    "retained anchor marks reconciled into the wallet store"
                )
            }
            Err(e) => {
                tracing::warn!(%e, "retained anchor-mark reconcile failed (non-fatal) — continuing")
            }
        }

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .map_err(|e| anyhow!("tokio runtime: {e}"))?;

        let inner = slipstream_core::ffi_handle::SlipstreamHandle {
            runtime,
            progress: std::sync::Arc::new(slipstream_core::events::Progress::default()),
            state: std::sync::Arc::new(std::sync::Mutex::new(SyncState::Idle)),
            events: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            task: None,
            pass_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            endpoint: slipstream_core::config::Endpoint {
                host: host.to_string(),
                port: server_port,
                tls: use_tls,
            },
            wallet_db_path: db_path.to_path_buf(),
            network,
            total_memory_bytes,
        };

        // [API v2.1 E-3] Truthful-from-open snapshot: seed the progress atomics from the
        // persisted wallet DB (the same inputs the first suggest round would use), so a
        // pre-pass snapshot never lies — `is_recovering` is correct on a mid-restore
        // relaunch, the permille floor holds a 99%-synced wallet's real position, and
        // `chain_tip` reports the last persisted tip. Hosts must NOT compensate.
        // Failures degrade to the zero snapshot (truthful for a fresh wallet) — the seed
        // is presentation state and must never fail `open()`. NOTE: the Swift host always
        // runs `Initializer.initialize` (DB create + migrations) before `open()`, so this
        // does not race wallet creation.
        match slipstream_core::wallet_session::WalletSession::open(network, db_path) {
            Ok(session) => {
                if let Err(e) =
                    slipstream_core::scheduler::seed_progress_from_wallet(&inner.progress, &session)
                {
                    tracing::warn!(error = %e, "E-3 open-time snapshot seed failed — snapshot starts cold");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "E-3 seed skipped (wallet not openable) — snapshot starts cold");
            }
        }
        tracing::info!(total_memory_bytes, "slipstream handle opened");

        Ok(Box::into_raw(Box::new(SlipstreamHandle {
            inner,
            summary_cache: std::sync::Arc::new(std::sync::Mutex::new(None)),
            summary_refresh_inflight: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                false,
            )),
            // [#1806] Empty until the first successful recovery-balance read fills it.
            recovery_nets_cache: std::sync::Mutex::new(None),
            // Freshness baseline = the refresh COUNTER (0 on a fresh handle; the E-3 seed
            // above never bumps it) — a DB-seeded tip is persisted state, not freshness.
            tip_refreshes_at_run_start: std::sync::atomic::AtomicU64::new(0),
            tip_fresh: std::sync::atomic::AtomicBool::new(false),
            last_stop_at: std::sync::Mutex::new(None),
            alternate_servers: std::sync::Mutex::new(Vec::new()),
            post_flip_hold: std::sync::Mutex::new(PostFlipHold::default()),
        })))
    });
    unwrap_exc_or_null(res)
}

/// [v0.7 P1b] Sets the alternate lightwalletd servers for wire resilience.
///
/// - `handle`: non-null pointer returned by [`zcashlc_slipstream_open`].
/// - `uris`/`uris_len`: newline-separated `http(s)://host:port` list (UTF-8
///   bytes, no NUL terminator). Blank lines are ignored. Pass null/0 to clear.
///
/// The list is stored on the handle and merged into the engine config by every
/// subsequent [`zcashlc_slipstream_start`] (deduped against the primary — hosts
/// pass their FULL server list, selected server included). With a non-empty
/// list a pass opens with the ~1 s parallel probe (commit to the healthiest
/// server) and arms mid-pass wire-collapse failover. Tor passes ignore the list
/// inside the engine: probe and failover dial direct, which would bypass the
/// circuit. All-or-nothing: on any parse failure the stored list is unchanged
/// and `false` is returned (check [`zcashlc_get_last_error_message`]).
///
/// # Safety
///
/// - `handle` must be a non-null pointer returned by [`zcashlc_slipstream_open`] that
///   has not previously been freed.
/// - `handle` must not be passed to two FFI calls at the same time.
/// - If `uris` is non-null, it must be valid for reads for `uris_len` bytes (UTF-8,
///   alignment `1`), and its memory must not be mutated for the duration of the call.
/// - `uris_len` must be no larger than `isize::MAX`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_set_alternate_servers(
    handle: *mut SlipstreamHandle,
    uris: *const u8,
    uris_len: usize,
) -> bool {
    let handle = AssertUnwindSafe(handle);
    let res = catch_panic(|| {
        let handle = unsafe { handle.as_mut() }.ok_or_else(|| anyhow!("null handle"))?;
        let parsed: Vec<slipstream_core::config::Endpoint> = if uris.is_null() || uris_len == 0 {
            Vec::new()
        } else {
            std::str::from_utf8(unsafe { slice::from_raw_parts(uris, uris_len) })
                .map_err(|e| anyhow!("alternate servers UTF-8: {e}"))?
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(|l| {
                    slipstream_core::config::Endpoint::parse_uri(l).map_err(|e| anyhow!("{e}"))
                })
                .collect::<Result<_, _>>()?
        };
        tracing::info!(count = parsed.len(), "v0.7 P1b alternate servers set");
        *handle
            .alternate_servers
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = parsed;
        Ok(true)
    });
    unwrap_exc_or(res, false)
}

/// [B6] The anchor-retention floor for the slipstream engine: the NU6.3 activation
/// height, exactly the floor upstream's own `WalletDb::put_blocks` caller passes
/// (`zcash_client_sqlite`), so checkpoints on the 144-block anchor grid from
/// activation onward survive the engine's checkpoint downgrade/dooming/pruning.
/// The pool-migration engine pre-signs every transfer against a drawn boundary
/// anchor on that grid and proves it hours later — without this floor the
/// engine's persist path retains nothing (`EngineConfig.anchor_retention_height`
/// defaults to `None`) and the boundary checkpoint is pruned ~100 blocks behind
/// the tip, leaving `prove_transfer` in a permanent transient `AnchorNotFound`
/// retry and the scheduled migration stalled until expiry.
///
/// `None` (a network without NU6.3, e.g. a custom regtest without the upgrade)
/// keeps retention off — there are no boundary anchors to retain for. Generic
/// over [`Parameters`] (the slipstream handle stores the plain [`Network`]).
pub(crate) fn slipstream_anchor_retention_floor<P: Parameters>(network: &P) -> Option<u32> {
    network
        .activation_height(NetworkUpgrade::Nu6_3)
        .map(u32::from)
}

/// Starts a Slipstream sync pass.
///
/// - `handle`: non-null pointer returned by [`zcashlc_slipstream_open`].
/// - `ufvk`/`ufvk_len`: UFVK string (UTF-8 bytes), or null/0 for a keyless update
///   (birthday is ignored when ufvk is null — account must already be imported).
/// - `birthday_height`: wallet birthday height (ignored when ufvk is null).
/// - `tor_dir`/`tor_dir_len`: dedicated Tor state directory (UTF-8 bytes) for the engine's
///   isolated circuits. Pass null/0 to sync directly (Tor off). When non-empty, the engine
///   bootstraps an arti client from it — a subdir SEPARATE from the old SDK's `TorClient`
///   directory (arti holds a state lock). Metadata calls then use isolated Tor circuits;
///   bulk block fetch stays direct (mirrors the old SDK's per-call Tor policy).
///
/// Can be called after [`zcashlc_slipstream_stop`] to restart. Cancels any in-flight
/// sync before spawning the new one.
/// Returns `true` on success, `false` on error
/// (check [`zcashlc_get_last_error_message`] for the error text).
///
/// # Safety
///
/// - `handle` must be a non-null pointer returned by [`zcashlc_slipstream_open`] that
///   has not previously been freed.
/// - `handle` must not be passed to two FFI calls at the same time.
/// - If `ufvk` is non-null, it must be valid for reads for `ufvk_len` bytes (UTF-8,
///   alignment `1`), and its memory must not be mutated for the duration of the call.
/// - If `tor_dir` is non-null, it must be valid for reads for `tor_dir_len` bytes (UTF-8,
///   alignment `1`), and its memory must not be mutated for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_start(
    handle: *mut SlipstreamHandle,
    ufvk: *const u8,
    ufvk_len: usize,
    birthday_height: u64,
    tor_dir: *const u8,
    tor_dir_len: usize,
) -> bool {
    // SAFETY: callers must respect mutability rules on the Swift side so that observing
    // a panic from another thread does not leave the handle in an inconsistent state.
    let handle = AssertUnwindSafe(handle);
    let res = catch_panic(|| {
        let handle = unsafe { handle.as_mut() }.ok_or_else(|| anyhow!("null handle"))?;

        // [API v2.1 E-2] Tip-freshness bookkeeping (shouldMarkChainTipUpdated parity):
        // capture the refresh-counter baseline BEFORE the pass starts — a later advance
        // proves THIS run persisted a freshly-fetched tip (even when the fetched height
        // equals the E-3 DB-seeded one). Freshness survives a stop→start hop < 120 s
        // (quick background hop); a longer gap re-masks until the new pass proves the tip.
        let refreshes_now = handle.inner.progress.tip_refreshes();
        handle
            .tip_refreshes_at_run_start
            .store(refreshes_now, std::sync::atomic::Ordering::Relaxed);
        let stale_stop = handle
            .last_stop_at
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .map(|t| t.elapsed() >= TIP_FRESH_STOP_WINDOW)
            .unwrap_or(false);
        if stale_stop {
            handle
                .tip_fresh
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }

        let h = &mut handle.inner;

        // Cancel any in-flight task before spawning a new one.
        if let Some(task) = h.task.take() {
            task.abort();
            join_aborted_slipstream_task(&task);
        }
        // [B4-16 drain] The aborted pass's write-behind commit may still be running
        // (`spawn_blocking` — uncancellable); wait it out BEFORE spawning the new
        // session, so the new pass's first writes never collide with an orphan
        // ("database is locked" at pass start) and no orphan Scanned-mark can land
        // after this point. Kills the B4-12 orphan-overlap class at the root.
        drain_slipstream_wallet_writers(&h.progress);
        *h.state.lock().unwrap_or_else(|p| p.into_inner()) = SyncState::Syncing;

        let ufvk_str: Option<String> = if ufvk.is_null() || ufvk_len == 0 {
            None
        } else {
            Some(
                std::str::from_utf8(unsafe { slice::from_raw_parts(ufvk, ufvk_len) })
                    .map_err(|e| anyhow!("ufvk UTF-8: {e}"))?
                    .to_string(),
            )
        };

        // ── T-Tor.3: engine-owned Tor (mirrors the old SDK's per-call Tor setup) ──
        // Swift passes a non-empty `tor_dir` — a DEDICATED slipstream Tor state subdir,
        // separate from the old SDK's TorRuntime dir to avoid an arti state-lock clash —
        // ONLY when Tor is enabled at start() time; empty/null = Tor off (direct).
        let tor_dir_opt: Option<std::path::PathBuf> = if tor_dir.is_null() || tor_dir_len == 0 {
            None
        } else {
            Some(
                Path::new(OsStr::from_bytes(unsafe {
                    slice::from_raw_parts(tor_dir, tor_dir_len)
                }))
                .to_path_buf(),
            )
        };

        #[allow(unused_mut)] // `mut` is only used under the `gpu` feature below.
        let mut cfg = slipstream_core::config::EngineConfig::new(
            h.network,
            h.wallet_db_path.clone(),
            h.endpoint.clone(),
        )
        // T8.4: derate fetch/split budgets on <3 GiB devices from the open-time
        // physical-memory hint (0 = unknown → defaults). Explicit field overrides win.
        .scaled_for_device_memory(h.total_memory_bytes);

        // [B6] Anchor-retention policy — see `slipstream_anchor_retention_floor`:
        // without it the engine retains no anchor checkpoints and every scheduled
        // migration transfer's drawn boundary is pruned before proving time.
        //
        // The grid is the one this crate configures on the wallet itself (see
        // `anchor_retention_interval`), NOT a value chosen here. The engine runs its
        // own tree-update path rather than calling `ll::wallet::put_blocks`, so it
        // does not see the wallet's setting: passing the same interval is what keeps
        // the two from retaining different grids, which on a test network would
        // otherwise leave every transfer anchored to a boundary the engine drops.
        cfg.anchor_retention = slipstream_anchor_retention_floor(&h.network).map(|floor| {
            slipstream_core::AnchorRetention::new(
                BlockHeight::from(floor),
                anchor_retention_interval(NetworkParams::Standard(h.network)),
            )
        });

        // v0.3 : GPU Orchard subtree offload. Compiled only with `--features gpu`;
        // opt in at runtime via the ZCASH_GPU_SUBTREE env var (the dev A/B for the device
        // matrix — set it in the Xcode scheme for v0.3, unset for v0.2). The capability
        // auto-gate (calibration probe) supersedes this once tuned. No-op without the
        // feature (build_orchard_subtrees falls back to CPU regardless).
        #[cfg(feature = "gpu")]
        {
            cfg.gpu_subtree = std::env::var("ZCASH_GPU_SUBTREE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            tracing::info!(
                gpu_subtree = cfg.gpu_subtree,
                "v0.3 GPU offload config (feature=gpu)"
            );
        }

        // v0.4 : Plan A graft + Plan B batch — DEFAULT ON since 2026-07-05
        // (P3 gates passed 100%). The env toggles are now KILL SWITCHES
        // (`=0` disables) and the dev A/B lever. Mirrors ZCASH_GPU_SUBTREE.
        cfg.graft_subtree = std::env::var("ZCASH_GRAFT_SUBTREE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(cfg.graft_subtree);
        cfg.batch_combine = std::env::var("ZCASH_BATCH_COMBINE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(cfg.batch_combine);
        // [#1806] ZCASH_BATCH_DECRYPT / ZCASH_ENDO_MUL removed: the zodl-inc/slipstream
        // repoint dropped `EngineConfig::batch_decrypt`/`endo_mul` — upstream adopted
        // batched-trial-decryption GLV unconditionally and retired the vendored orchard
        // fork these knobs configured. No replacement field exists; the env vars are now
        // inert (left unhandled intentionally rather than silently repurposed).
        // v0.5 scan-pacer lever : local chunk-boundary treestates
        // (one seed fetch per range instead of one RPC per boundary).
        // Default OFF until the A/B + audit gates.
        cfg.local_treestate = std::env::var("ZCASH_LOCAL_TREESTATE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(cfg.local_treestate);
        tracing::info!(
            graft_subtree = cfg.graft_subtree,
            batch_combine = cfg.batch_combine,
            local_treestate = cfg.local_treestate,
            "v0.4/v0.5 lever config"
        );

        // v0.7 P1b : alternate servers → probe-then-commit + wire failover.
        // Deduped against the CURRENT primary (hosts pass their full server list;
        // the selected server is usually in it — after a switchTo the filter
        // re-derives against the new primary automatically). Tor passes ignore
        // these inside the engine: probe/failover dial direct, which would
        // bypass the circuit.
        {
            let alternates = handle
                .alternate_servers
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            cfg.alternate_endpoints = alternates
                .into_iter()
                .filter(|e| *e != cfg.endpoint)
                .collect();
            tracing::info!(
                alternates = cfg.alternate_endpoints.len(),
                wire_failover = cfg.wire_failover,
                "v0.7 wire config"
            );
        }

        // ── Build the session config + reporting sink, then spawn the engine session ──────
        // The orchestration (resilient Tor bootstrap + initial pass + tip-following + mempool)
        // now lives in slipstream_core::session::run_session. This FFI only marshals C args,
        // builds the config + the reporting sink (the handle's existing progress/state/event
        // Arcs), and spawns the engine's session on the handle runtime.
        // [#1806] `SessionConfig.account` was retyped to `accounts: Vec<(UnifiedFullViewingKey,
        // BlockHeight)>` (typed multi-account sync_once) by the zodl-inc/slipstream repoint.
        // This FFI still exposes single-account semantics: parse the raw ufvk/birthday into
        // the typed pair and wrap it in a one-element Vec (empty = keyless follow-up call,
        // ufvk was null) — no multi-account surface added upward.
        let accounts: Vec<(UnifiedFullViewingKey, BlockHeight)> = match ufvk_str {
            Some(ufvk_str) => {
                let ufvk = UnifiedFullViewingKey::decode(&h.network, &ufvk_str).map_err(|e| {
                    anyhow!(
                        "Value \"{}\" did not decode as a valid UFVK: {}",
                        ufvk_str,
                        e
                    )
                })?;
                let birthday = BlockHeight::try_from(birthday_height)
                    .map_err(|e| anyhow!("invalid birthday_height {}: {}", birthday_height, e))?;
                vec![(ufvk, birthday)]
            }
            None => Vec::new(),
        };
        // iOS sandboxes the app dir so fs-mistrust can trust it (mirrors the old SDK's
        // zcashlc_create_tor_runtime); elsewhere let Tor manage permissions. The engine stays
        // host-agnostic — a future Android FFI sets this field too.
        let tor = tor_dir_opt.map(|dir| slipstream_core::session::TorSessionConfig {
            dir,
            dangerously_trust_everyone: cfg!(target_os = "ios"),
        });
        let session_config = slipstream_core::session::SessionConfig {
            engine: cfg,
            accounts,
            tor,
        };
        let reporter = slipstream_core::session::SessionReporter {
            progress: std::sync::Arc::clone(&h.progress),
            state: std::sync::Arc::clone(&h.state),
            events: std::sync::Arc::clone(&h.events),
        };

        // B1 : spawn SUPERVISED — a panic in the session body becomes SyncState::Error(2)
        // + a tag=4/value=2 event instead of a silent death stuck at "Syncing" forever.
        let sup_state = std::sync::Arc::clone(&h.state);
        let sup_events = std::sync::Arc::clone(&h.events);
        h.task = Some(slipstream_core::ffi_handle::spawn_supervised(
            &h.runtime,
            slipstream_core::session::run_session(
                session_config,
                reporter,
                std::sync::Arc::clone(&h.pass_lock),
            ),
            sup_state,
            sup_events,
        ));
        Ok(true)
    });
    unwrap_exc_or(res, false)
}

/// Stops any in-flight Slipstream sync (non-blocking — task abort is async).
///
/// Returns `true` immediately. The handle remains live; poll
/// [`zcashlc_slipstream_snapshot`] to confirm state transitions to idle.
///
/// # Safety
///
/// - `handle` must be a non-null pointer returned by [`zcashlc_slipstream_open`] that
///   has not previously been freed.
/// - `handle` must not be passed to two FFI calls at the same time.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_stop(handle: *mut SlipstreamHandle) -> bool {
    let handle = AssertUnwindSafe(handle);
    let res = catch_panic(|| {
        let handle = unsafe { handle.as_mut() }.ok_or_else(|| anyhow!("null handle"))?;
        // [API v2.1 E-2] Stamp the stop: a start() within 120 s keeps tip freshness
        // (quick background hop, SDKFlags parity); a longer gap re-masks.
        *handle
            .last_stop_at
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(std::time::Instant::now());
        let h = &mut handle.inner;
        if let Some(task) = h.task.take() {
            task.abort();
            join_aborted_slipstream_task(&task);
        }
        // [B4-16 drain] abort() cannot cancel an in-flight write-behind commit
        // (`spawn_blocking`) — drain it so a returned stop means the wallet file is
        // QUIESCENT: the host's next write (deleteAccount / importAccount / rewind
        // truncate) can no longer interleave with an orphan commit. Swift hops this
        // call off the cooperative pool (the drain is a real, bounded wait).
        drain_slipstream_wallet_writers(&h.progress);
        *h.state.lock().unwrap_or_else(|p| p.into_inner()) = SyncState::Idle;
        Ok(true)
    });
    unwrap_exc_or(res, false)
}

/// [B4-16 drain] Bounded wait for the engine's in-flight wallet-file writer — the
/// write-behind lane's deferred commit, a `spawn_blocking` closure `task.abort()` cannot
/// cancel. Field evidence (2026-07-04): an orphan commit outlived an `importAccount`
/// restart, collided with the new pass's first writes ("database is locked" →
/// non-transient failure, absorbed by the revival loop) and — worse — landed its
/// Scanned-mark AFTER the import's force-rescan re-queue, silently shrinking the new
/// account's scan scope. Called by stop() and start() right after aborting the task.
/// 10 s cap ≫ the worst observed device commit (a few seconds, A10); on timeout we
/// proceed with a warning — the busy_timeouts remain the backstop.
/// [B4-16 drain] `abort()` is ASYNCHRONOUS — the task keeps running until its next await
/// point, so a synchronous in-flight wallet write (an enhance `decrypt_and_store`, a
/// chain-tip or subtree-roots update — field evidence: a `deleteAccount` landing in that
/// window failed its read→write lock upgrade, "error + try again") can land AFTER
/// `abort()` returns. Wait (bounded) for the task to finish unwinding. Combined with
/// `drain_slipstream_wallet_writers` (the persist lane's `spawn_blocking` commit — the
/// engine's ONLY detached writer), a completed stop/start-abort means the wallet file is
/// FULLY quiescent.
fn join_aborted_slipstream_task(task: &tokio::task::AbortHandle) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !task.is_finished() {
        if std::time::Instant::now() >= deadline {
            tracing::warn!(
                "slipstream stop/start: aborted pass still unwinding after 10 s — proceeding"
            );
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn drain_slipstream_wallet_writers(progress: &slipstream_core::ProgressArc) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut waited = false;
    while progress.wallet_writers() > 0 {
        if std::time::Instant::now() >= deadline {
            tracing::warn!(
                "slipstream stop/start: in-flight wallet commit still running after 10 s — proceeding (busy_timeouts remain the backstop)"
            );
            return;
        }
        waited = true;
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if waited {
        tracing::info!("slipstream stop/start: drained in-flight wallet commit");
    }
}

/// Reads a snapshot of current Slipstream progress atomics (non-blocking, poll-based — D8).
///
/// Returns a zero-filled struct on null handle.
///
/// # Safety
///
/// - `handle` must be a non-null pointer returned by [`zcashlc_slipstream_open`] that
///   has not previously been freed, or null (in which case a zeroed struct is returned).
/// - `handle` must not be passed to two FFI calls at the same time.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_snapshot(
    handle: *const SlipstreamHandle,
) -> FfiSlipstreamSnapshot {
    let handle = AssertUnwindSafe(handle);
    let res = catch_panic(|| {
        let handle = unsafe { handle.as_ref() }.ok_or_else(|| anyhow!("null handle"))?;
        // Delegate to the inner handle's snapshot() and copy fields into the
        // cbindgen-visible FfiSlipstreamSnapshot defined in this file.
        let s = handle.inner.snapshot();
        Ok(FfiSlipstreamSnapshot {
            chain_tip: s.chain_tip,
            fetched_blocks: s.fetched_blocks,
            scanned_blocks: s.scanned_blocks,
            enhanced_txs: s.enhanced_txs,
            current_range_end: s.current_range_end,
            state: s.state,
            pass_total_blocks: s.pass_total_blocks,
            spendable_hint: s.spendable_hint,
            ranges_completed: s.ranges_completed,
            is_recovering: s.is_recovering,
            progress_permille: s.progress_permille,
            stalled_seconds: s.stalled_seconds,
            tip_fresh: if handle.tip_fresh_now(s.state) { 1 } else { 0 },
            tx_set_version: s.tx_set_version,
        })
    });
    unwrap_exc_or(res, FfiSlipstreamSnapshot::default())
}

impl SlipstreamHandle {
    /// [API v2.1 E-2] Lazily evaluates + latches tip freshness — the exact
    /// `shouldMarkChainTipUpdated` semantics the SDK derived host-side:
    /// - already fresh → stays fresh (until a >120 s stop→start gap re-masks in `start()`);
    /// - the refresh counter advanced past its `start()` baseline → the engine bumps it
    ///   only AFTER `session.update_chain_tip` succeeds, so an advance proves THIS run
    ///   refreshed the wallet-DB tip (counter-based so the E-3 DB-seeded tip can neither
    ///   fake freshness nor mask a refresh that fetched the same height);
    /// - otherwise → trust only a pass that reached Done (state 3): `sync_once` cannot
    ///   complete without `update_chain_tip` having succeeded.
    fn tip_fresh_now(&self, state: u8) -> bool {
        use std::sync::atomic::Ordering;
        if self.tip_fresh.load(Ordering::Relaxed) {
            return true;
        }
        let advanced = self.inner.progress.tip_refreshes()
            > self.tip_refreshes_at_run_start.load(Ordering::Relaxed);
        if advanced || state == 3 {
            self.tip_fresh.store(true, Ordering::Relaxed);
            return true;
        }
        false
    }
}

/// [API v2 §4.5] Notifies the engine that the HOST changed the wallet's transaction set
/// outside a sync pass — e.g. it stored a just-broadcast transaction. The engine responds by
/// emitting a FoundTransactions event (tag 5) through its normal event channel, so every
/// host's single event loop sees the pending transaction immediately and uniformly instead of
/// waiting for the next mempool/scan round. Returns `true` on success, `false` on a null
/// handle or internal panic.
///
/// # Safety
///
/// - `handle` must be a non-null pointer returned by [`zcashlc_slipstream_open`] that
///   has not previously been freed.
/// - `handle` must not be passed to two FFI calls at the same time.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_notify_tx_change(
    handle: *mut SlipstreamHandle,
) -> bool {
    let handle = AssertUnwindSafe(handle);
    let res = catch_panic(|| {
        let handle = unsafe { handle.as_ref() }.ok_or_else(|| anyhow!("null handle"))?;
        // [E-4] The version counter is the primary signal (snapshot-carried, loss-proof);
        // the tag-5 event stays for hosts that consume the ring.
        handle.inner.progress.bump_tx_set_version();
        handle
            .inner
            .push_event(slipstream_core::ffi_handle::FfiSlipstreamEvent { tag: 5, value: 0 });
        Ok(true)
    });
    unwrap_exc_or(res, false)
}

/// [API v2.1 E-6] The engine-owned wallet-provisioning anchor (policy in slipstream-core
/// `anchor.rs`): the chain facts a host needs BEFORE creating/restoring a wallet, with the
/// offline fallback policy INSIDE — no host re-implements provisioning math.
///
/// - `intent` = 1 (RESTORE, with `birthday`): `height` = the live chain tip to provision as
///   `recover_until`; offline ⇒ `max(fallback_checkpoint_height, birthday + 1)` (a restore
///   must NEVER get a NULL recover_until — the syncLogsMac9 rule). `treestate` is null (the
///   host keeps its birthday checkpoint).
/// - `intent` = 0 (NEW wallet): `height` + serialized `TreeState` protobuf = the reorg-safe
///   recent tree state (`tip − 100`, floored at Sapling activation); offline ⇒ `height` 0 +
///   null `treestate` (the host keeps its bundled checkpoint defaults).
///
/// Handle-less by design: provisioning happens BEFORE [`zcashlc_slipstream_open`] in the
/// host init flow, and `importAccount` must not serialize against the live handle. Creates
/// a short-lived runtime and blocks until resolved (typically one round-trip; the direct
/// path is a SINGLE attempt — the offline fallback IS the retry policy). When `tor_dir` is
/// non-empty the identifying fetches ride an isolated Tor circuit; a requested-but-failed
/// Tor bootstrap resolves OFFLINE — never a de-anonymising direct retry.
///
/// Returns null only on invalid arguments or an internal panic. Free with
/// [`zcashlc_slipstream_free_restore_anchor`].
///
/// # Safety
///
/// - `server_host` must be non-null and valid for reads for `server_host_len` bytes (UTF-8).
/// - If `tor_dir` is non-null, it must be valid for reads for `tor_dir_len` bytes (UTF-8).
/// - Neither buffer may be mutated for the duration of the call.
/// - Call [`zcashlc_slipstream_free_restore_anchor`] to free the returned pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_restore_anchor(
    server_host: *const u8,
    server_host_len: usize,
    server_port: u16,
    use_tls: bool,
    network_id: u32,
    intent: u8,
    birthday: u64,
    fallback_checkpoint_height: u64,
    tor_dir: *const u8,
    tor_dir_len: usize,
) -> *mut FfiRestoreAnchor {
    let res = catch_panic(|| {
        let host =
            std::str::from_utf8(unsafe { slice::from_raw_parts(server_host, server_host_len) })
                .map_err(|e| anyhow!("server_host UTF-8: {e}"))?;
        let network = if network_id == 1 {
            MainNetwork
        } else {
            TestNetwork
        };
        let endpoint = slipstream_core::config::Endpoint {
            host: host.to_string(),
            port: server_port,
            tls: use_tls,
        };
        let tor_dir_opt: Option<std::path::PathBuf> = if tor_dir.is_null() || tor_dir_len == 0 {
            None
        } else {
            Some(
                Path::new(OsStr::from_bytes(unsafe {
                    slice::from_raw_parts(tor_dir, tor_dir_len)
                }))
                .to_path_buf(),
            )
        };
        let intent = if intent == 1 {
            slipstream_core::anchor::AnchorIntent::Restore {
                birthday,
                fallback_checkpoint: fallback_checkpoint_height,
            }
        } else {
            slipstream_core::anchor::AnchorIntent::New
        };

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| anyhow!("tokio runtime: {e}"))?;
        let anchor = runtime.block_on(async {
            let tor_conn = match &tor_dir_opt {
                Some(dir) => {
                    match slipstream_core::connector::TorConn::bootstrap(dir, false).await {
                        Ok(t) => Some(t),
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "anchor: Tor bootstrap failed — resolving OFFLINE (no direct fallback)"
                            );
                            return slipstream_core::anchor::offline_anchor(intent);
                        }
                    }
                }
                None => None,
            };
            slipstream_core::anchor::restore_anchor(&endpoint, network.into(), intent, tor_conn.as_ref())
                .await
        });

        let (ts_ptr, ts_len) = match anchor.treestate {
            Some(ts) => ptr_from_vec(ts.encode_to_vec()),
            None => (std::ptr::null_mut(), 0),
        };
        Ok(Box::into_raw(Box::new(FfiRestoreAnchor {
            height: anchor.height,
            treestate: ts_ptr,
            treestate_len: ts_len,
        })))
    });
    unwrap_exc_or_null(res)
}

/// Frees an [`FfiRestoreAnchor`] returned by [`zcashlc_slipstream_restore_anchor`].
///
/// # Safety
///
/// - If `ptr` is non-null, it must be a pointer returned by
///   [`zcashlc_slipstream_restore_anchor`] that has not previously been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_free_restore_anchor(ptr: *mut FfiRestoreAnchor) {
    if !ptr.is_null() {
        let anchor = unsafe { Box::from_raw(ptr) };
        free_ptr_from_vec(anchor.treestate, anchor.treestate_len);
        drop(anchor);
    }
}

/// [#1806] Upper bound on the post-restore balance hold (see [`PostFlipHold`] and
/// [`zcashlc_slipstream_wallet_summary`]). Generous relative to the observed ~30 s
/// summary-availability gap after a restore completes, but bounded so a wedged engine can never
/// hold a stale balance indefinitely.
pub(crate) const POST_FLIP_HOLD_CAP: std::time::Duration = std::time::Duration::from_secs(120);

/// [#1806] The post-restore balance-hold latch. Right after a restore finishes, the engine flips
/// `is_recovering` 1→0 while the upstream `get_wallet_summary` still returns `None` for ~30 s
/// (scan-progress for the just-finalized range is not yet computable). Without intervention the
/// FFI serves EMPTY balances for that window and the just-restored funds visibly vanish
/// (MOB-1513 E2-FIX). This latch lets the summary path keep serving the engine-owned recovery
/// view across that gap, under strict safety gates. One-shot: `Idle → Engaged → Released`, and
/// `Released` is terminal for the handle's life (a second restore in the same session does not
/// re-arm it).
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub(crate) enum HoldLatch {
    /// No qualifying `is_recovering 1→0` flip has engaged the hold yet.
    #[default]
    Idle,
    /// A flip whose recovery override was serving a non-zero value engaged the hold at `flip_at`.
    Engaged { flip_at: std::time::Instant },
    /// The hold is permanently consumed: either the first upstream `Some` after the flip won
    /// (upstream truth thereafter), or an unmined outgoing spend was detected. Never re-engages.
    Released,
}

/// [#1806] Per-handle post-restore hold state: the latch, the last-observed recovery flag (for
/// 1→0 edge detection), and the heights of the most recent non-`None` upstream summary (reused
/// when the hold synthesizes its balance-only summary, since the Swift bridge drops any summary
/// with `fully_scanned_height < 0`). Guarded by the handle's `post_flip_hold` mutex — the same
/// synchronization the sibling caches use. See [`zcashlc_slipstream_wallet_summary`] for the full
/// policy and its bounds.
///
/// Cold-start edge (ACCEPTED, documented here per the E2-FIX spec): if the PROCESS restarts
/// during the ~30 s post-flip window, no `1→0` flip is observed on the fresh handle, so the latch
/// never engages and the pre-hold behavior (serve the transient empty summary until upstream
/// returns `Some`) applies. That is the same brief exposure a host tolerated before this fix, and
/// far rarer than the steady-state flip the hold covers. The durable fix is slipstream-core
/// finalizing the restore handoff before it flips `is_recovering` (MOB-1513 E2-FIX spec).
#[derive(Debug, Default)]
struct PostFlipHold {
    /// Last observed `is_recovering` flag, for 1→0 edge detection. `None` until the first
    /// summary call on this handle observes a snapshot.
    last_is_recovering: Option<bool>,
    /// The hold latch.
    latch: HoldLatch,
    /// `(chain_tip_height, fully_scanned_height)` from the most recent non-`None` upstream
    /// summary. `None` until the first `Some` upstream summary resolves.
    last_heights: Option<(i32, i32)>,
}

/// [#1806] Per-account unmined-outgoing-spend status for the post-restore hold's safety gate.
/// The recovery view counts only MINED reconciled deltas, so it does not subtract a pending
/// (unmined) outgoing spend — holding across one would over-show a stale-high balance. `Unknown`
/// (the spend query failed / was contended) is treated as "cannot verify": the hold is suspended
/// for this tick WITHOUT releasing the latch, so a later successful check can resume it.
#[derive(Debug, Clone, Copy, PartialEq)]
enum UnminedSpendStatus {
    Absent,
    Present,
    Unknown,
}

/// [#1806] What the summary path serves for this tick, decided by [`decide_summary_serving`].
#[derive(Debug, Clone, Copy, PartialEq)]
enum SummaryServe {
    /// Serve the resolved upstream summary unchanged (a real `Some` → real balances; a `None`
    /// → the empty `none()` sentinel). No recovery override — the pre-hold behavior.
    Upstream,
    /// Recovering (`is_recovering == 1`): replace every account balance with the recovery-view
    /// net (the pre-existing unconditional override).
    RecoveringOverride,
    /// Post-restore hold: the upstream summary is transiently `None` but the latch is engaged,
    /// within the cap, and no unmined outgoing spend is pending — synthesize a balance-only
    /// summary from the recovery-view nets so the restored funds do not vanish.
    HoldOverride,
}

/// [#1806] Freshness-tagged classification of the resolved upstream summary. The summary served
/// to hosts comes from a RATIONED cache, so a `Some` observed at a given tick may be STALE — its
/// walk started before the `is_recovering 1→0` flip and therefore predates the restored notes.
/// Releasing the hold on such a stale `Some` (or serving it raw) would re-expose the very ~30 s
/// empty/regressed window the hold exists to cover (MOB-1513 E2-FIX / C1). The latch may be
/// released only by a `Some` KNOWN to be post-flip (`FreshSome`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum UpstreamKind {
    /// The cache walked to `None` (no balance data) — regardless of when the walk ran.
    None,
    /// A `Some` whose walk STARTED while the engine was still recovering (pre-flip). Not yet
    /// trustworthy: treated exactly like `None` by the hold (do not serve it, do not release).
    StaleSome,
    /// A `Some` whose walk started while NOT recovering (post-flip) — real, current balances.
    FreshSome,
}

/// [#1806] Classify the resolved upstream summary by presence + the recovery state its walk ran
/// under. `walked_while_recovering` is the `is_recovering` flag captured when the cache entry's
/// walk started; a `Some` produced during recovery is `StaleSome` (pre-flip), otherwise
/// `FreshSome`.
pub(crate) fn classify_upstream(summary_is_some: bool, walked_while_recovering: bool) -> UpstreamKind {
    if !summary_is_some {
        UpstreamKind::None
    } else if walked_while_recovering {
        UpstreamKind::StaleSome
    } else {
        UpstreamKind::FreshSome
    }
}

/// [#1806] Pure post-restore-hold state-machine step for the unified wallet summary. Factored out
/// of [`zcashlc_slipstream_wallet_summary`] so the whole serving policy — engage-on-flip,
/// first-`Some`-wins, cap expiry, and the unmined-spend safety gate — is exhaustively unit
/// testable with no engine, DB, or clock. Returns the next latch and the serve decision.
///
/// Inputs (this tick's observed facts):
/// - `is_recovering`: the engine snapshot's recovery flag.
/// - `last_is_recovering`: the previous tick's flag (for 1→0 edge detection); `None` on the
///   first observation on this handle.
/// - `upstream`: freshness-tagged classification of the resolved summary (see [`UpstreamKind`]);
///   only a `FreshSome` (post-flip) releases the latch.
/// - `prior_recovery_nonzero`: whether the recovery override had been serving a non-zero value
///   just before the flip (only consulted AT the flip; guards case (f) — nothing to hold).
/// - `spend`: per-account unmined-outgoing-spend status (only consulted while holding).
/// - `latch`: the current latch.
/// - `now`: the current instant (engages the latch at `flip_at = now`, and measures the cap).
/// - `cap`: the hold's upper time bound.
fn decide_summary_serving(
    is_recovering: bool,
    last_is_recovering: Option<bool>,
    upstream: UpstreamKind,
    prior_recovery_nonzero: bool,
    spend: UnminedSpendStatus,
    latch: HoldLatch,
    now: std::time::Instant,
    cap: std::time::Duration,
) -> (HoldLatch, SummaryServe) {
    // Recovering: the pre-existing unconditional override. The latch only ever engages at the
    // 1→0 edge below, so while recovering it passes through untouched.
    if is_recovering {
        return (latch, SummaryServe::RecoveringOverride);
    }

    // Not recovering.
    // (1) Engage on a 1→0 edge whose recovery override had been serving a non-zero value. One-
    //     shot: only `Idle` can engage, so a second restore in the same session never re-arms it,
    //     and case (f) (prior override was zero → nothing worth holding) is filtered out here.
    let mut latch = latch;
    let flipped = last_is_recovering == Some(true);
    if flipped && latch == HoldLatch::Idle && prior_recovery_nonzero {
        latch = HoldLatch::Engaged { flip_at: now };
    }

    // (2) Only a FRESH post-flip `Some` releases the latch: upstream truth wins thereafter, even if
    //     lower than the recovery view. A STALE cached `Some` (its walk started pre-flip, so it
    //     predates the restored notes — C1) is NOT trustworthy yet: treat it exactly like `None`
    //     below and keep holding, covering the window where the rationed cache still serves the
    //     pre-flip `Some`.
    if matches!(upstream, UpstreamKind::FreshSome) {
        if matches!(latch, HoldLatch::Engaged { .. }) {
            latch = HoldLatch::Released;
        }
        return (latch, SummaryServe::Upstream);
    }

    // (3) Upstream is `None` or `StaleSome` — evaluate the hold.
    match latch {
        HoldLatch::Engaged { flip_at } => {
            if now.saturating_duration_since(flip_at) > cap {
                // Cap expired: suspend the hold, serve empty (pre-hold behavior). The latch stays
                // Engaged-but-inert — `flip_at` is fixed so it never serves again and, being
                // non-`Idle`, never re-engages.
                (latch, SummaryServe::Upstream)
            } else {
                match spend {
                    // No pending spend: safe to surface the recovery-view balances.
                    UnminedSpendStatus::Absent => (latch, SummaryServe::HoldOverride),
                    // A pending unmined outgoing spend would make the mined-only recovery view
                    // over-show. End the hold PERMANENTLY (do not re-engage) and serve empty.
                    UnminedSpendStatus::Present => (HoldLatch::Released, SummaryServe::Upstream),
                    // Could not verify: suspend this tick but keep the latch, so a later
                    // successful check resumes — never hold on an unverified spend state.
                    UnminedSpendStatus::Unknown => (latch, SummaryServe::Upstream),
                }
            }
        }
        // Never engaged (cold start / case (e)) or already released: pre-hold behavior.
        HoldLatch::Idle | HoldLatch::Released => (latch, SummaryServe::Upstream),
    }
}

/// [#1806] The `v_transactions` query behind [`read_unmined_spend_accounts`], split out so it can
/// be unit-tested against an in-memory `v_transactions`-shaped table. Returns the set of accounts
/// with an UNMINED, UNEXPIRED, outgoing (note-spending) transaction — the post-restore hold's
/// safety gate. Derived from `v_transactions` (the same view family the recovery balance reads):
/// an outgoing spend is `spent_note_count > 0` (mirrors librustzcash's spent-notes clause),
/// unmined is `mined_height IS NULL`, and the view's own `expired_unmined` flag supplies
/// tx-expiry (mirrors `tx_unexpired_condition`). The returned UUIDs match the account keys of
/// `slipstream_v_recovery_balance`.
fn read_unmined_spend_accounts_conn(
    conn: &rusqlite::Connection,
) -> anyhow::Result<std::collections::HashSet<[u8; 16]>> {
    let mut accounts = std::collections::HashSet::new();
    let mut stmt = conn
        .prepare(
            // `COALESCE(expired_unmined, 0) = 0`, NOT `expired_unmined = 0`: `expired_unmined` is
            // NULL when the tx's `expiry_height` is unknown (e.g. an un-enhanced pending tx), and a
            // bare `= 0` silently drops NULL rows — letting such a hazard slip the gate (M1). NULL
            // ⇒ treat as not-yet-expired ⇒ a hazard the hold must respect.
            "SELECT DISTINCT account_uuid FROM v_transactions \
             WHERE mined_height IS NULL AND spent_note_count > 0 \
             AND COALESCE(expired_unmined, 0) = 0",
        )
        .map_err(|e| anyhow!("unmined-spend prepare: {}", e))?;
    let mut rows = stmt
        .query([])
        .map_err(|e| anyhow!("unmined-spend query: {}", e))?;
    while let Some(row) = rows
        .next()
        .map_err(|e| anyhow!("unmined-spend row: {}", e))?
    {
        let uuid: Vec<u8> = row
            .get(0)
            .map_err(|e| anyhow!("unmined-spend uuid: {}", e))?;
        if let Ok(uuid16) = <[u8; 16]>::try_from(uuid.as_slice()) {
            accounts.insert(uuid16);
        }
    }
    Ok(accounts)
}

/// [#1806] Open `db_path` with the same 250 ms busy timeout as the recovery-balance read and run
/// [`read_unmined_spend_accounts_conn`]. Errors (including busy contention) propagate so the
/// caller can treat them as [`UnminedSpendStatus::Unknown`] — never as "no spend".
fn read_unmined_spend_accounts(
    db_path: &std::path::Path,
) -> anyhow::Result<std::collections::HashSet<[u8; 16]>> {
    let conn =
        rusqlite::Connection::open(db_path).map_err(|e| anyhow!("unmined-spend open: {}", e))?;
    conn.busy_timeout(std::time::Duration::from_millis(250))
        .map_err(|e| anyhow!("unmined-spend busy_timeout: {}", e))?;
    read_unmined_spend_accounts_conn(&conn)
}

/// [#1806] The testable core of [`zcashlc_slipstream_wallet_summary`]'s serve path: given this
/// tick's classified upstream, the hold state, and DB access, it runs the I1 gates and the
/// [`decide_summary_serving`] state machine, then builds the summary to serve. Extracted so the
/// WIRING (classify → gate → decide → build) can be driven in tests with a fabricated cache
/// classification + a real fixture DB — the seam the pure-function tests alone cannot cover (C1).
///
/// `build_upstream` marshals the resolved upstream summary (a real `Some`, or the empty `none()`
/// sentinel) and is invoked ONLY for the `Upstream`/`RecoveringOverride` decisions — never for a
/// synthesized hold. The DB reads (recovery-view nets, unmined-spend gate) run against `db_path`.
///
/// `ironwood_active` says whether NU6.3 is active at the chain tip; it selects which pool carries
/// the collapsed recovery net (see [`ffi::AccountBalance::override_with_recovery_net`]).
///
/// I1: the unmined-spend query and the `prior_recovery_nonzero` scan run ONLY when the hold could
/// actually serve this tick (engaged-or-engaging, within cap, upstream not `FreshSome`) — never on
/// an ordinary `None`-serving tick with an idle/released latch — so there is no per-tick DB hit or
/// warn spam on a wallet that is merely between balances, and the warn is bounded by the 120 s cap.
#[allow(clippy::too_many_arguments)]
pub(crate) fn serve_wallet_summary(
    is_recovering: bool,
    ironwood_active: bool,
    upstream: UpstreamKind,
    hold_heights: Option<(i32, i32)>,
    last_is_recovering: Option<bool>,
    latch_in: HoldLatch,
    now: std::time::Instant,
    cap: std::time::Duration,
    db_path: &std::path::Path,
    recovery_nets_cache: &std::sync::Mutex<Option<std::collections::HashMap<[u8; 16], i64>>>,
    build_upstream: impl FnOnce() -> anyhow::Result<*mut ffi::WalletSummary>,
) -> anyhow::Result<(HoldLatch, *mut ffi::WalletSummary)> {
    // `prior_recovery_nonzero` is consulted only at the flip (Idle + flipped), so gate the
    // in-memory scan there — it must not run on every tick (I1).
    let flipped = !is_recovering && last_is_recovering == Some(true);
    let prior_recovery_nonzero = if flipped && latch_in == HoldLatch::Idle {
        recovery_nets_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|m| m.values().any(|&v| v > 0))
            .unwrap_or(false)
    } else {
        false
    };

    // Whether the hold could serve `HoldOverride` this tick — this gates the unmined-spend DB read
    // (I1). `FreshSome` is excluded: it releases rather than holds, so its gate never runs.
    let engaging = flipped && latch_in == HoldLatch::Idle && prior_recovery_nonzero;
    let engaged_now = matches!(latch_in, HoldLatch::Engaged { .. }) || engaging;
    let within_cap = match latch_in {
        HoldLatch::Engaged { flip_at } => now.saturating_duration_since(flip_at) <= cap,
        _ => true,
    };
    let hold_window =
        !is_recovering && engaged_now && within_cap && !matches!(upstream, UpstreamKind::FreshSome);
    let spend_status = if hold_window {
        match read_unmined_spend_accounts(db_path) {
            Ok(set) if set.is_empty() => UnminedSpendStatus::Absent,
            Ok(_) => UnminedSpendStatus::Present,
            Err(e) => {
                tracing::warn!(error = %e, "unmined-spend gate read failed; suspending hold this tick");
                UnminedSpendStatus::Unknown
            }
        }
    } else {
        UnminedSpendStatus::Absent
    };

    let (latch_after, decision) = decide_summary_serving(
        is_recovering,
        last_is_recovering,
        upstream,
        prior_recovery_nonzero,
        spend_status,
        latch_in,
        now,
        cap,
    );

    // The bounded recovery-balance read + last-good fallback, shared by the recovering override and
    // the hold synthesis. 250 ms busy timeout (NOT the 5 s used elsewhere): under mid-restore write
    // contention a longer wait would pin the Swift engine actor. On ANY failure, fall back to the
    // last successfully-read nets (or an empty map, which zeroes every balance — safe).
    let resolve_recovery_nets = || -> std::collections::HashMap<[u8; 16], i64> {
        let read = || -> anyhow::Result<std::collections::HashMap<[u8; 16], i64>> {
            let conn = rusqlite::Connection::open(db_path)
                .map_err(|e| anyhow!("recovery balance open: {}", e))?;
            conn.busy_timeout(std::time::Duration::from_millis(250))
                .map_err(|e| anyhow!("recovery balance busy_timeout: {}", e))?;
            let mut nets: std::collections::HashMap<[u8; 16], i64> =
                std::collections::HashMap::new();
            let mut stmt = conn
                .prepare("SELECT account_uuid, balance_zat FROM ext_slipstream_v_recovery_balance")
                .map_err(|e| anyhow!("recovery balance prepare: {}", e))?;
            let mut rows = stmt
                .query([])
                .map_err(|e| anyhow!("recovery balance query: {}", e))?;
            while let Some(row) = rows
                .next()
                .map_err(|e| anyhow!("recovery balance row: {}", e))?
            {
                let uuid: Vec<u8> = row
                    .get(0)
                    .map_err(|e| anyhow!("recovery balance uuid: {}", e))?;
                let net: i64 = row
                    .get(1)
                    .map_err(|e| anyhow!("recovery balance net: {}", e))?;
                if let Ok(uuid16) = <[u8; 16]>::try_from(uuid.as_slice()) {
                    nets.insert(uuid16, net);
                }
            }
            Ok(nets)
        };
        match read() {
            Ok(fresh) => {
                *recovery_nets_cache
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = Some(fresh.clone());
                fresh
            }
            Err(e) => {
                tracing::warn!(error = %e, "recovery balance read failed; using cached/zero fallback");
                recovery_nets_cache
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone()
                    .unwrap_or_default()
            }
        }
    };

    let summary_ptr = match decision {
        // Serve the resolved upstream summary unchanged (real `Some` balances, or the empty
        // `none()` sentinel). A `StaleSome` reaches here only in a non-hold latch state, where
        // serving today's cache is correct.
        SummaryServe::Upstream => build_upstream()?,
        // Recovering: marshal upstream, then REPLACE every slot with the recovery-view net.
        SummaryServe::RecoveringOverride => {
            let ptr = build_upstream()?;
            let nets = resolve_recovery_nets();
            let summary_mut = unsafe { &mut *ptr };
            for balance in summary_mut.account_balances_mut() {
                let net = nets.get(balance.uuid_bytes()).copied().unwrap_or(0);
                balance.override_with_recovery_net(net, ironwood_active);
            }
            ptr
        }
        // Post-restore hold: synthesize a balance-only summary from the FRESH recovery-view nets.
        // Needs real heights (Swift drops `fully_scanned_height < 0`); lacking them, serve the
        // empty sentinel — never the stale raw upstream, and never fabricate a height.
        // (M2) The synthesis carries one slot per recovery-view row, so an account with no recovery
        // row is present-as-ABSENT during the hold (reads 0 via the SDK's `?? .zero`), not
        // present-as-zero. Benign for the host's migration read (it only asks whether Orchard > 0
        // — which the collapsed net deliberately does not answer post-activation), so the hold
        // does not re-plumb full account enumeration.
        SummaryServe::HoldOverride => match hold_heights {
            Some((chain_tip_h, fully_scanned_h)) => {
                let nets = resolve_recovery_nets();
                let entries: Vec<ffi::AccountBalance> = nets
                    .iter()
                    .map(|(uuid, net)| {
                        ffi::AccountBalance::recovery_only(*uuid, *net, ironwood_active)
                    })
                    .collect();
                ffi::WalletSummary::recovery_hold(entries, chain_tip_h, fully_scanned_h)
            }
            None => ffi::WalletSummary::none(),
        },
    };
    Ok((latch_after, summary_ptr))
}

/// [API v2 §0-5] The unified, PHASE-RESOLVING wallet summary for Slipstream hosts: one call
/// that is correct at every phase, so no host ever re-implements restore balance math.
///
/// - **Not recovering** → the upstream wallet summary, unchanged (identical to
///   [`zcashlc_get_wallet_summary`]).
/// - **Recovering** (the recent-first restore backfill; `snapshot.is_recovering == 1`) →
///   the upstream summary's per-account balances are REPLACED, because upstream balances
///   "may overestimate" mid-restore by documented design (a receipt is counted before its
///   spend is scanned). The replacement is the engine-owned `slipstream_v_recovery_balance`
///   (Σ of FINAL, reconciled tx deltas — never over-shows, converges to the true total),
///   surfaced per the SDK's field-validated Direction-B mapping: the whole clamped net as
///   orchard spendable, everything else zero. Progress/heights fields pass through.
///
/// Returns null on error; a summary with `fully_scanned_height == -1` when the wallet has
/// no balance data yet.
///
/// # Safety
///
/// - `handle` must be a non-null pointer returned by [`zcashlc_slipstream_open`] that
///   has not previously been freed, and must not be passed to two FFI calls at once.
/// - Call [`zcashlc_free_wallet_summary`] to free the memory associated with the returned
///   pointer when done using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_wallet_summary(
    handle: *const SlipstreamHandle,
    confirmations_policy: ffi::ConfirmationsPolicy,
) -> *mut ffi::WalletSummary {
    let handle = AssertUnwindSafe(handle);
    let res = catch_panic(|| {
        let handle = unsafe { handle.as_ref() }.ok_or_else(|| anyhow!("null handle"))?;
        let network = handle.inner.network;
        let db_path = handle.inner.wallet_db_path.clone();
        let snap = handle.inner.snapshot();

        // ── [API v2.1 E-1] Serve-cached + refresh policy — the walk is rationed HERE, so
        // hosts may call this whenever they like (per poll tick included):
        //   • no cache yet → ONE synchronous walk (in practice: the host's prepare/open-time
        //     call, when the engine is quiet);
        //   • cache exists → serve it immediately, and — when the pass crossed a range
        //     boundary, the state changed, or (outside a scan) the idle TTL elapsed — spawn
        //     ONE background walk (plain thread; owns only clones + Arcs, so it is safe
        //     against `free()` racing it) that swaps the cache for later calls.
        // Between boundaries while Syncing, NO walk ever runs: the T5.5
        // no-summary-while-scanning invariant, now engine-owned. The recovery-balance
        // REPLACEMENT below still re-reads the cheap view on every call, so a recovering
        // host sees the per-tick climb; [#1806] only bounds that read and adds a
        // contended-read fallback cache — it is not a serve-cached policy.
        let cached: Option<SummaryCacheEntry> = {
            let guard = handle
                .summary_cache
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            guard.as_ref().map(|e| SummaryCacheEntry {
                captured_at: e.captured_at,
                ranges_completed: e.ranges_completed,
                state: e.state,
                summary: e.summary.clone(),
                walked_while_recovering: e.walked_while_recovering,
            })
        };

        // [#1806 / C1] Resolve the served summary AND the recovery state its walk ran under, so a
        // stale (pre-flip) cached `Some` can be told from a fresh (post-flip) one below.
        let (resolved, walked_while_recovering): (
            Option<zcash_client_backend::data_api::WalletSummary<AccountUuid>>,
            bool,
        ) = match cached {
            None => {
                // First call on this handle: walk synchronously and prime the cache with the
                // walked Option in BOTH arms. [#1806] A None walk ("no balance data yet" on a
                // fresh / just-imported wallet) is cached too, so later poll ticks serve that
                // cached None instead of repeating this synchronous walk; the boundary/TTL
                // refresh below then replaces it once the first scan commits real balances.
                let path_bytes = db_path.as_os_str().as_bytes();
                let db_data = unsafe {
                    wallet_db(
                        path_bytes.as_ptr(),
                        path_bytes.len(),
                        NetworkParams::Standard(network),
                    )?
                };
                let policy = wallet::ConfirmationsPolicy::try_from(confirmations_policy)?;
                let walked = db_data
                    .get_wallet_summary(policy)
                    .map_err(|e| anyhow!("Error while fetching wallet summary: {}", e))?;
                let recovering_at = snap.is_recovering == 1;
                *handle
                    .summary_cache
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = Some(SummaryCacheEntry {
                    captured_at: std::time::Instant::now(),
                    ranges_completed: snap.ranges_completed,
                    state: snap.state,
                    summary: walked.clone(),
                    walked_while_recovering: recovering_at,
                });
                (walked, recovering_at)
            }
            Some(entry) => {
                let boundary_crossed =
                    snap.ranges_completed != entry.ranges_completed || snap.state != entry.state;
                let idle_ttl_due =
                    snap.state != 1 && entry.captured_at.elapsed() >= SUMMARY_IDLE_TTL;
                if (boundary_crossed || idle_ttl_due)
                    && !handle
                        .summary_refresh_inflight
                        .swap(true, std::sync::atomic::Ordering::SeqCst)
                {
                    let cache = std::sync::Arc::clone(&handle.summary_cache);
                    let inflight = std::sync::Arc::clone(&handle.summary_refresh_inflight);
                    let thread_db_path = db_path.clone();
                    let thread_policy = confirmations_policy;
                    let (ranges_at, state_at, recovering_at) =
                        (snap.ranges_completed, snap.state, snap.is_recovering == 1);
                    std::thread::spawn(move || {
                        let walk = || -> anyhow::Result<
                            Option<zcash_client_backend::data_api::WalletSummary<AccountUuid>>,
                        > {
                            let path_bytes = thread_db_path.as_os_str().as_bytes();
                            let db_data = unsafe {
                                wallet_db(
                                    path_bytes.as_ptr(),
                                    path_bytes.len(),
                                    NetworkParams::Standard(network),
                                )?
                            };
                            let policy =
                                wallet::ConfirmationsPolicy::try_from(thread_policy)?;
                            db_data
                                .get_wallet_summary(policy)
                                .map_err(|e| anyhow!("summary refresh: {}", e))
                        };
                        // [#1806] Store the whole walked Option: a refresh that walks to None
                        // caches None (later ticks then serve that cached None). Only an Err
                        // leaves the cache untouched — a contended refresh must not clobber a
                        // good entry with nothing.
                        if let Ok(walked) = walk() {
                            *cache.lock().unwrap_or_else(|p| p.into_inner()) =
                                Some(SummaryCacheEntry {
                                    captured_at: std::time::Instant::now(),
                                    ranges_completed: ranges_at,
                                    state: state_at,
                                    summary: walked,
                                    walked_while_recovering: recovering_at,
                                });
                        }
                        // Always clears — on the stored, walked-None, and Err paths alike.
                        inflight.store(false, std::sync::atomic::Ordering::SeqCst);
                    });
                }
                (entry.summary, entry.walked_while_recovering)
            }
        };

        // [#1806 / C1] Classify the resolved summary by presence + the recovery state its walk ran
        // under, then serve via the extracted, unit-tested [`serve_wallet_summary`]. A `Some` whose
        // walk started pre-flip is `StaleSome` — the hold must not release on it or serve it raw
        // (the cache lags the flip, so the first post-flip tick still holds the pre-flip `Some`).
        let upstream_kind = classify_upstream(resolved.is_some(), walked_while_recovering);
        // Heights of a real (Some) upstream summary — the hold reuses them so its synthesized
        // summary carries a real, ≥0 scanned height (the Swift bridge drops `< 0` as "no data").
        let resolved_heights: Option<(i32, i32)> = resolved.as_ref().map(|s| {
            (
                u32::from(s.chain_tip_height()) as i32,
                u32::from(s.fully_scanned_height()) as i32,
            )
        });
        let is_recovering = snap.is_recovering == 1;

        let (latch_before, last_is_recovering, last_heights) = {
            let g = handle
                .post_flip_hold
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            (g.latch, g.last_is_recovering, g.last_heights)
        };
        // Synthesize from this tick's real heights when present, else the last-known ones.
        let hold_heights = resolved_heights.or(last_heights);
        let now = std::time::Instant::now();

        // NU6.3 active at the tip decides which pool the collapsed recovery net lands in.
        let ironwood_active = network
            .activation_height(NetworkUpgrade::Nu6_3)
            .is_some_and(|h| snap.chain_tip >= u64::from(u32::from(h)));

        let (latch_after, summary_ptr) = serve_wallet_summary(
            is_recovering,
            ironwood_active,
            upstream_kind,
            hold_heights,
            last_is_recovering,
            latch_before,
            now,
            POST_FLIP_HOLD_CAP,
            &db_path,
            &handle.recovery_nets_cache,
            || match resolved {
                Some(s) => ffi::WalletSummary::some(s),
                None => Ok(ffi::WalletSummary::none()),
            },
        )?;

        // Persist the latch, the observed recovery flag, and (from a real summary) the heights.
        {
            let mut g = handle
                .post_flip_hold
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            g.latch = latch_after;
            g.last_is_recovering = Some(is_recovering);
            if let Some(h) = resolved_heights {
                g.last_heights = Some(h);
            }
        }

        Ok(summary_ptr)
    });
    unwrap_exc_or_null(res)
}

/// Drains all queued Slipstream events into a caller-allocated buffer.
///
/// - `handle`: non-null pointer returned by [`zcashlc_slipstream_open`].
/// - `buf`: caller-allocated array of [`FfiSlipstreamEvent`]; must be valid for writes
///   for `buf_len` elements.
/// - `buf_len`: length of `buf` (maximum events to drain in this call).
///
/// Returns the number of events written (≤ `buf_len`). Events are drained atomically
/// — after this call returns, the drained events are removed from the internal ring.
///
/// # Safety
///
/// - `handle` must be a non-null pointer returned by [`zcashlc_slipstream_open`] that
///   has not previously been freed.
/// - `handle` must not be passed to two FFI calls at the same time.
/// - `buf` must be non-null and valid for writes for `buf_len` elements of
///   [`FfiSlipstreamEvent`], with alignment of `1`.
/// - `buf_len` must be no larger than `isize::MAX`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_drain_events(
    handle: *mut SlipstreamHandle,
    buf: *mut FfiSlipstreamEvent,
    buf_len: usize,
) -> usize {
    let handle = AssertUnwindSafe(handle);
    let buf = AssertUnwindSafe(buf);
    let res = catch_panic(|| {
        let handle = unsafe { handle.as_mut() }.ok_or_else(|| anyhow!("null handle"))?;
        let mut ring = handle
            .inner
            .events
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let to_copy = ring.len().min(buf_len);
        // Convert from the ffi_handle event type to the cbindgen-visible
        // FfiSlipstreamEvent (defined in this file). Both are repr(C); copy fields.
        let drained: Vec<FfiSlipstreamEvent> = ring
            .drain(..to_copy)
            .map(|e| FfiSlipstreamEvent {
                tag: e.tag,
                value: e.value,
            })
            .collect();
        // SAFETY: buf is valid for writes for buf_len elements (caller contract above).
        unsafe { std::ptr::copy_nonoverlapping(drained.as_ptr(), *buf, to_copy) };
        Ok(to_copy)
    });
    unwrap_exc_or(res, 0)
}

/// Frees a Slipstream handle.
///
/// Cancels any in-flight sync and drops the tokio runtime. After this call, `handle`
/// must not be used.
///
/// # Safety
///
/// - If `handle` is non-null, it must be a pointer returned by [`zcashlc_slipstream_open`]
///   that has not previously been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_slipstream_free(handle: *mut SlipstreamHandle) {
    if !handle.is_null() {
        // SAFETY: handle is non-null and was returned by zcashlc_slipstream_open (caller
        // contract). We take ownership here and drop it at end of scope.
        let mut h: Box<SlipstreamHandle> = unsafe { Box::from_raw(handle) };
        // Abort the in-flight task before dropping the runtime; dropping a Runtime with
        // live tasks causes a panic on some platforms.
        if let Some(task) = h.inner.task.take() {
            task.abort();
        }
        drop(h);
    }
}

#[cfg(test)]
mod post_flip_hold_tests {
    use super::{
        HoldLatch, POST_FLIP_HOLD_CAP, SummaryServe, UnminedSpendStatus, UpstreamKind,
        classify_upstream, decide_summary_serving, read_unmined_spend_accounts_conn,
    };
    use std::time::{Duration, Instant};

    /// `base + secs` — build a later instant without `Instant` subtraction (panic-free).
    fn at(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    // ── classify_upstream ──────────────────────────────────────────────────────────────────

    #[test]
    fn classify_none_is_none() {
        assert_eq!(classify_upstream(false, false), UpstreamKind::None);
        assert_eq!(classify_upstream(false, true), UpstreamKind::None);
    }

    #[test]
    fn classify_some_walked_recovering_is_stale() {
        assert_eq!(classify_upstream(true, true), UpstreamKind::StaleSome);
    }

    #[test]
    fn classify_some_walked_not_recovering_is_fresh() {
        assert_eq!(classify_upstream(true, false), UpstreamKind::FreshSome);
    }

    // ── decide_summary_serving: the post-restore hold state machine ────────────────────────

    #[test]
    fn recovering_always_overrides_and_leaves_latch_untouched() {
        let now = Instant::now();
        let (latch, serve) = decide_summary_serving(
            true,
            Some(true),
            UpstreamKind::FreshSome,
            true,
            UnminedSpendStatus::Absent,
            HoldLatch::Idle,
            now,
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::RecoveringOverride);
        assert_eq!(latch, HoldLatch::Idle);
    }

    /// (a) None + engaged hold + gates pass → recovery values served, and it keeps holding
    /// across later ticks still inside the cap.
    #[test]
    fn none_with_engaged_hold_and_no_spend_serves_recovery() {
        let base = Instant::now();
        // Flip tick: recovering last tick, not now; prior override non-zero; upstream None.
        let (latch, serve) = decide_summary_serving(
            false,
            Some(true),
            UpstreamKind::None,
            true,
            UnminedSpendStatus::Absent,
            HoldLatch::Idle,
            base,
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::HoldOverride);
        assert!(matches!(latch, HoldLatch::Engaged { .. }));

        // A later tick, still within the cap, keeps holding with the same flip_at.
        let (latch2, serve2) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::None,
            false,
            UnminedSpendStatus::Absent,
            latch,
            at(base, 30),
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve2, SummaryServe::HoldOverride);
        assert_eq!(latch2, latch);
    }

    /// C1 (pure): a STALE cached `Some` at the flip tick engages the hold and serves recovery —
    /// it must NOT be treated as the first post-flip truth (which would release + serve stale).
    #[test]
    fn stale_some_at_flip_engages_and_holds() {
        let base = Instant::now();
        let (latch, serve) = decide_summary_serving(
            false,
            Some(true),
            UpstreamKind::StaleSome,
            true,
            UnminedSpendStatus::Absent,
            HoldLatch::Idle,
            base,
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::HoldOverride);
        assert!(matches!(latch, HoldLatch::Engaged { .. }));
    }

    /// C1 (pure): while engaged, a still-stale cached `Some` keeps holding and never releases.
    #[test]
    fn stale_some_while_engaged_keeps_holding() {
        let base = Instant::now();
        let engaged = HoldLatch::Engaged { flip_at: base };
        let (latch, serve) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::StaleSome,
            false,
            UnminedSpendStatus::Absent,
            engaged,
            at(base, 30),
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::HoldOverride);
        assert_eq!(latch, engaged);
    }

    /// A stale `Some` in a NON-hold latch state (never engaged) serves today's cache unchanged —
    /// the fix must not disturb non-hold serving paths.
    #[test]
    fn stale_some_in_idle_serves_upstream_unchanged() {
        let now = Instant::now();
        let (latch, serve) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::StaleSome,
            false,
            UnminedSpendStatus::Absent,
            HoldLatch::Idle,
            now,
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::Upstream);
        assert_eq!(latch, HoldLatch::Idle);
    }

    /// (b) None + unmined outgoing spend → empty, and the latch is permanently released (no
    /// re-engage even once the spend later reads as absent within the cap).
    #[test]
    fn none_with_unmined_spend_serves_empty_and_releases_permanently() {
        let base = Instant::now();
        let engaged = HoldLatch::Engaged { flip_at: base };
        let (latch, serve) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::None,
            false,
            UnminedSpendStatus::Present,
            engaged,
            at(base, 10),
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::Upstream);
        assert_eq!(latch, HoldLatch::Released);

        let (latch2, serve2) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::None,
            false,
            UnminedSpendStatus::Absent,
            latch,
            at(base, 20),
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve2, SummaryServe::Upstream);
        assert_eq!(latch2, HoldLatch::Released);
    }

    /// (c) The first FRESH post-flip `Some` releases the latch permanently: upstream truth wins
    /// thereafter, even a subsequent `None` within the cap does not resurrect the hold.
    #[test]
    fn fresh_upstream_some_releases_latch_permanently() {
        let base = Instant::now();
        let engaged = HoldLatch::Engaged { flip_at: base };
        let (latch, serve) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::FreshSome,
            false,
            UnminedSpendStatus::Absent,
            engaged,
            at(base, 5),
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::Upstream);
        assert_eq!(latch, HoldLatch::Released);

        let (latch2, serve2) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::None,
            false,
            UnminedSpendStatus::Absent,
            latch,
            at(base, 6),
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve2, SummaryServe::Upstream);
        assert_eq!(latch2, HoldLatch::Released);
    }

    /// (d) Cap expired → empty.
    #[test]
    fn cap_expiry_serves_empty() {
        let base = Instant::now();
        let engaged = HoldLatch::Engaged { flip_at: base };
        let (_latch, serve) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::None,
            false,
            UnminedSpendStatus::Absent,
            engaged,
            at(base, 121),
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::Upstream);
    }

    /// (e) None with NO prior flip (cold start) → empty; the hold never engages without the
    /// 1→0 flip precondition (neither a first-observation `None` nor a not-recovering last tick).
    #[test]
    fn cold_start_none_never_engages() {
        let now = Instant::now();
        let (latch, serve) = decide_summary_serving(
            false,
            None,
            UpstreamKind::None,
            true,
            UnminedSpendStatus::Absent,
            HoldLatch::Idle,
            now,
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::Upstream);
        assert_eq!(latch, HoldLatch::Idle);

        let (latch2, serve2) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::None,
            true,
            UnminedSpendStatus::Absent,
            HoldLatch::Idle,
            now,
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve2, SummaryServe::Upstream);
        assert_eq!(latch2, HoldLatch::Idle);
    }

    /// (f) Flip observed but the recovery override was serving zero → the hold never engages.
    #[test]
    fn flip_with_zero_prior_override_never_engages() {
        let now = Instant::now();
        let (latch, serve) = decide_summary_serving(
            false,
            Some(true),
            UpstreamKind::None,
            false,
            UnminedSpendStatus::Absent,
            HoldLatch::Idle,
            now,
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::Upstream);
        assert_eq!(latch, HoldLatch::Idle);
    }

    /// An `Unknown` spend status (contended/failed query) suspends the hold for the tick WITHOUT
    /// releasing the latch, so a later successful `Absent` check resumes holding.
    #[test]
    fn unknown_spend_suspends_without_release_then_resumes() {
        let base = Instant::now();
        let engaged = HoldLatch::Engaged { flip_at: base };
        let (latch, serve) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::None,
            false,
            UnminedSpendStatus::Unknown,
            engaged,
            at(base, 10),
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve, SummaryServe::Upstream);
        assert_eq!(latch, engaged);

        let (latch2, serve2) = decide_summary_serving(
            false,
            Some(false),
            UpstreamKind::None,
            false,
            UnminedSpendStatus::Absent,
            latch,
            at(base, 12),
            POST_FLIP_HOLD_CAP,
        );
        assert_eq!(serve2, SummaryServe::HoldOverride);
        assert!(matches!(latch2, HoldLatch::Engaged { .. }));
    }

    // ── read_unmined_spend_accounts_conn: the v_transactions safety-gate query ──────────────

    fn setup_v_transactions(conn: &rusqlite::Connection) {
        conn.execute_batch(
            "CREATE TABLE v_transactions (
                account_uuid BLOB,
                mined_height INTEGER,
                spent_note_count INTEGER,
                expired_unmined INTEGER
            );",
        )
        .unwrap();
    }

    fn uuid(n: u8) -> [u8; 16] {
        [n; 16]
    }

    fn insert_tx(
        conn: &rusqlite::Connection,
        acct: [u8; 16],
        mined: Option<i64>,
        spent: i64,
        expired: Option<i64>,
    ) {
        conn.execute(
            "INSERT INTO v_transactions (account_uuid, mined_height, spent_note_count, expired_unmined) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![acct.to_vec(), mined, spent, expired],
        )
        .unwrap();
    }

    #[test]
    fn unmined_unexpired_spend_is_detected() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        setup_v_transactions(&conn);
        insert_tx(&conn, uuid(1), None, 1, Some(0));
        let set = read_unmined_spend_accounts_conn(&conn).unwrap();
        assert_eq!(set, std::collections::HashSet::from([uuid(1)]));
    }

    #[test]
    fn mined_spend_is_ignored() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        setup_v_transactions(&conn);
        insert_tx(&conn, uuid(1), Some(100), 1, Some(0));
        let set = read_unmined_spend_accounts_conn(&conn).unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn unmined_receive_only_is_ignored() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        setup_v_transactions(&conn);
        insert_tx(&conn, uuid(1), None, 0, Some(0));
        let set = read_unmined_spend_accounts_conn(&conn).unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn expired_unmined_spend_is_ignored() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        setup_v_transactions(&conn);
        insert_tx(&conn, uuid(1), None, 1, Some(1));
        let set = read_unmined_spend_accounts_conn(&conn).unwrap();
        assert!(set.is_empty());
    }

    /// M1: a pending unmined spend whose tx has UNKNOWN expiry (`expired_unmined IS NULL`, e.g. an
    /// un-enhanced tx) is a hazard and must be detected — the `= 0` comparison silently dropped
    /// NULL rows, letting such a spend slip the gate.
    #[test]
    fn null_expiry_unmined_spend_is_detected() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        setup_v_transactions(&conn);
        insert_tx(&conn, uuid(1), None, 1, None);
        let set = read_unmined_spend_accounts_conn(&conn).unwrap();
        assert_eq!(set, std::collections::HashSet::from([uuid(1)]));
    }

    #[test]
    fn per_account_only_hazardous_accounts_returned() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        setup_v_transactions(&conn);
        insert_tx(&conn, uuid(1), None, 1, Some(0)); // acct1: unmined spend, unexpired → hazardous
        insert_tx(&conn, uuid(2), Some(50), 1, Some(0)); // acct2: mined → safe
        insert_tx(&conn, uuid(3), None, 0, Some(0)); // acct3: pure receive → safe
        let set = read_unmined_spend_accounts_conn(&conn).unwrap();
        assert_eq!(set, std::collections::HashSet::from([uuid(1)]));
    }
}

#[cfg(test)]
mod slipstream_anchor_retention_tests {
    use super::slipstream_anchor_retention_floor;
    use zcash_protocol::consensus::{Network, NetworkUpgrade, Parameters};
    use zcash_protocol::local_consensus::LocalNetwork;

    /// [B6] The slipstream engine's anchor-retention floor is the NU6.3 activation
    /// height — the exact floor upstream's own `put_blocks` caller passes — so every
    /// drawn boundary anchor a migration pre-signed against stays witnessable. The
    /// handle stores the plain [`Network`], so the floor is exercised on it directly.
    #[test]
    fn floor_is_nu63_activation_on_standard_networks() {
        for network in [Network::MainNetwork, Network::TestNetwork] {
            let expected = network
                .activation_height(NetworkUpgrade::Nu6_3)
                .map(u32::from);
            assert_eq!(slipstream_anchor_retention_floor(&network), expected);
            // The pin must define NU6.3 on both standard networks — a `None` here
            // would silently disable anchor retention and stall scheduled transfers.
            assert!(
                slipstream_anchor_retention_floor(&network).is_some(),
                "NU6.3 activation must be defined for {network:?}"
            );
        }
    }

    /// A network without NU6.3 has nothing to retain for: floor off (`None`),
    /// matching the engine's documented pre-B6 default behavior.
    #[test]
    fn floor_is_none_without_nu63() {
        let no_nu63 = LocalNetwork {
            overwinter: None,
            sapling: None,
            blossom: None,
            heartwood: None,
            canopy: None,
            nu5: None,
            nu6: None,
            nu6_1: None,
            nu6_2: None,
            nu6_3: None,
        };
        assert_eq!(slipstream_anchor_retention_floor(&no_nu63), None);
    }
}

/// Guards the engine-owned view names this crate and the Swift layer hard-code.
///
/// Both read paths fail SILENTLY by design — the recovery-balance read falls back to an empty
/// map ("zeroes every balance — safe") and Swift's reconcile read swallows a missing view as the
/// legitimate non-engine case. So a view rename in the engine surfaces as zeroed balances and
/// phantom transactions rather than an error, which is how the pre-`ext_` names survived once
/// the engine's `ExtSchemaInit` migration renamed them. These turn the next rename into a
/// failing test naming the file to fix.
#[cfg(test)]
mod engine_schema_names_tests {
    /// The view `TransactionSQLDAO.unreconciledTxids()` reads from Swift. The engine exports
    /// this name, so bind to it rather than trusting our copy of the string.
    #[test]
    fn reconcile_view_name_matches_the_swift_query() {
        assert_eq!(
            slipstream_core::reconcile::RECONCILE_VIEW_NAME,
            "ext_slipstream_v_tx_reconciled",
            "the engine renamed the reconciliation view; update the query in \
             Sources/ZcashLightClientKit/DAO/TransactionDao.swift to match"
        );
    }

    /// The view `serve_wallet_summary` reads for recovery nets. The engine exports no name
    /// constant for it, so assert against the DDL it does export.
    #[test]
    fn recovery_balance_view_name_matches_our_query() {
        assert!(
            slipstream_core::reconcile::RECOVERY_BALANCE_VIEW_SQL
                .contains("ext_slipstream_v_recovery_balance"),
            "the engine renamed the recovery-balance view; update the query in \
             resolve_recovery_nets to match. Engine DDL: {}",
            slipstream_core::reconcile::RECOVERY_BALANCE_VIEW_SQL
        );
    }
}
