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

    init(_ cSnapshot: FfiSlipstreamSnapshot) {
        chainTip = cSnapshot.chain_tip
        fetchedBlocks = cSnapshot.fetched_blocks
        scannedBlocks = cSnapshot.scanned_blocks
        enhancedTxs = cSnapshot.enhanced_txs
        currentRangeEnd = cSnapshot.current_range_end
        state = cSnapshot.state
    }

    /// Memberwise initializer for tests (avoids a direct dependency on `FfiSlipstreamSnapshot` / libzcashlc in test targets).
    init(
        chainTip: UInt64,
        fetchedBlocks: UInt64,
        scannedBlocks: UInt64,
        enhancedTxs: UInt64,
        currentRangeEnd: UInt64,
        state: UInt8
    ) {
        self.chainTip = chainTip
        self.fetchedBlocks = fetchedBlocks
        self.scannedBlocks = scannedBlocks
        self.enhancedTxs = enhancedTxs
        self.currentRangeEnd = currentRangeEnd
        self.state = state
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
