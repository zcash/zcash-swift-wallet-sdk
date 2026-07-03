//
//  SlipstreamFFI.swift
//  ZcashLightClientKit
//
//  Created for Slipstream task [#1755].
//
//  Swift-side wrappers for the C types generated in `zcashlc.h` by cbindgen.
//  These are plain value types — no FFI pointers; callers never reach into the C layer directly.
//

import Foundation
import libzcashlc

/// Swift-friendly wrapper around `FfiSlipstreamSnapshot` from the C header.
/// The C struct is returned BY VALUE from `zcashlc_slipstream_snapshot`; Swift receives it as a
/// value type automatically (cbindgen `#[repr(C)]` struct bridged as Swift struct).
public struct SlipstreamSnapshot {
    /// Current chain tip height as reported by the server (0 = not yet fetched).
    public let chainTip: UInt64
    /// Number of compact blocks fetched in the current/last sync pass.
    public let fetchedBlocks: UInt64
    /// Number of compact blocks scanned in the current/last sync pass.
    public let scannedBlocks: UInt64
    /// Number of transactions enhanced in the current/last sync pass.
    public let enhancedTxs: UInt64
    /// End height of the block range currently being processed.
    public let currentRangeEnd: UInt64
    /// Sync state: 0 = idle, 1 = syncing, 2 = error, 3 = done.
    public let state: UInt8
    /// Total blocks in the current pass (denominator for counter-based progress).
    /// Set (not accumulated) by the scheduler each time suggest_scan_ranges returns:
    /// value = scanned_so_far + sum(all returned ranges). F1 fix: whole-pass denominator
    /// is complete from the first suggestion — no 0→100→60% snap-back.
    public let passTotalBlocks: UInt64
    /// Spendable hint: 0 = not yet spendable; 1 = a ChainTip-priority range completed
    /// scanning (≈ SBS funds-spendable semantics). Latches to 1; never resets within a pass.
    public let spendableHint: UInt8
    /// Number of suggested ranges whose scan+enhancement has completed in the current pass.
    /// Monotonically increases. Swift observes changes to trigger ONE balance-summary fetch
    /// per range boundary while Syncing (F2 — boundary balance refresh).
    public let rangesCompleted: UInt64
    // ── Engine API v2 fields (ENGINE_API_V2.md §4.4) ──
    /// 1 while the wallet is inside its recovery (restore backfill) window. Engine-computed,
    /// fail-safe latch built in: terminal Done/Error force 0.
    public let isRecovering: UInt8
    /// Blessed progress, 0...1000, session-monotonic (never regresses while the handle lives;
    /// Done forces 1000). Replaces host-side progress math.
    public let progressPermille: UInt16
    /// Seconds since last forward progress while syncing; 0 otherwise.
    public let stalledSeconds: UInt32
    // ── Engine API v2.1 fields ──
    /// [E-2] 1 once the CURRENT run has refreshed the wallet-DB chain tip (the [#1591]
    /// stale-tip fact, engine-owned; survives stop→start hops under 120 s). While 0, the
    /// host masks spendable balances (`WalletSummary.withSpendableMasked()`).
    public let tipFresh: UInt8
    /// [E-4] Monotonic version of the wallet's stored transaction set (enhancement writes,
    /// mempool hits, boundary reconcile-linkage transitions, submit pokes). Host rule:
    /// version moved since the last poll → re-fetch transactions + publish.
    public let txSetVersion: UInt64

    init(_ cSnapshot: FfiSlipstreamSnapshot) {
        chainTip = cSnapshot.chain_tip
        fetchedBlocks = cSnapshot.fetched_blocks
        scannedBlocks = cSnapshot.scanned_blocks
        enhancedTxs = cSnapshot.enhanced_txs
        currentRangeEnd = cSnapshot.current_range_end
        state = cSnapshot.state
        passTotalBlocks = cSnapshot.pass_total_blocks
        spendableHint = cSnapshot.spendable_hint
        rangesCompleted = cSnapshot.ranges_completed
        isRecovering = cSnapshot.is_recovering
        progressPermille = cSnapshot.progress_permille
        stalledSeconds = cSnapshot.stalled_seconds
        tipFresh = cSnapshot.tip_fresh
        txSetVersion = cSnapshot.tx_set_version
    }

    /// Memberwise initializer for tests (avoids a direct dependency on `FfiSlipstreamSnapshot` / libzcashlc in test targets).
    init(
        chainTip: UInt64,
        fetchedBlocks: UInt64,
        scannedBlocks: UInt64,
        enhancedTxs: UInt64,
        currentRangeEnd: UInt64,
        state: UInt8,
        passTotalBlocks: UInt64 = 0,
        spendableHint: UInt8 = 0,
        rangesCompleted: UInt64 = 0,
        isRecovering: UInt8 = 0,
        progressPermille: UInt16 = 0,
        stalledSeconds: UInt32 = 0,
        tipFresh: UInt8 = 0,
        txSetVersion: UInt64 = 0
    ) {
        self.chainTip = chainTip
        self.fetchedBlocks = fetchedBlocks
        self.scannedBlocks = scannedBlocks
        self.enhancedTxs = enhancedTxs
        self.currentRangeEnd = currentRangeEnd
        self.state = state
        self.passTotalBlocks = passTotalBlocks
        self.spendableHint = spendableHint
        self.rangesCompleted = rangesCompleted
        self.isRecovering = isRecovering
        self.progressPermille = progressPermille
        self.stalledSeconds = stalledSeconds
        self.tipFresh = tipFresh
        self.txSetVersion = txSetVersion
    }
}

/// Swift-friendly wrapper around `FfiSlipstreamEvent`.
/// Event tags: 1 = SyncStarted, 2 = SyncProgress, 3 = SyncDone, 4 = SyncError, 5 = FoundTransactions.
public struct SlipstreamEngineEvent {
    /// Event tag (see type documentation for values).
    public let tag: UInt8
    /// For SyncDone: transactions stored. For SyncError: error code. Others: 0.
    public let value: UInt64
}
