//
//  SlipstreamSynchronizer+PureHelpers.swift
//  ZcashLightClientKit
//
//  Created for Slipstream task [#1755].
//
//  Pure static helpers for `SlipstreamSynchronizer` — no instance state, no side effects.
//  Extracted so the decision logic stays unit-testable in OfflineTests without an engine.
//

import Foundation

extension SlipstreamSynchronizer {
    /// Counter-based sync progress — derived purely from engine atomics, no DB call.
    ///
    /// Formula: `Float(scanned) / Float(max(total, 1))`, clamped to [0.0, 1.0].
    ///   - `total == 0` (no ranges taken yet) → 0.0 (prevents division by zero).
    ///   - Result > 1.0 (defensive) → clamped to 1.0.
    ///
    /// This is the primary progress source while `state == 1` (Syncing). It eliminates
    /// the `getWalletSummary` call that caused ~20–35% per-output CPU overhead on iPad A10
    /// (T5.5 — A10 log evidence: summary-parasite root cause confirmed).
    ///
    /// - Parameters:
    ///   - scanned: `snap.scannedBlocks` from the FFI snapshot.
    ///   - total:   `snap.passTotalBlocks` from the FFI snapshot.
    /// - Returns: progress fraction ∈ [0.0, 1.0].
    static func counterProgress(scanned: UInt64, total: UInt64) -> Float {
        let denominator = max(total, 1)
        return min(Float(scanned) / Float(denominator), 1.0)
    }

    /// Pure progress composition — mirrors the old SDK's ScanAction formula verbatim.
    ///
    /// Formula source: `ScanAction.swift` lines ~81-99.
    /// ```
    ///   composedNumerator   = scanProgress.numerator   + (recoveryProgress?.numerator   ?? 0)
    ///   composedDenominator = scanProgress.denominator + (recoveryProgress?.denominator ?? 0)
    ///   denominator == 0    → 1.0
    ///   progress > 1.0      → clamp to 1.0 (old SDK threw; we log-warn, then clamp)
    ///   areFundsSpendable   = scanProgress.isComplete  (ScanAction.swift:99)
    /// ```
    ///
    /// - Parameters:
    ///   - scanProgress:     `(numerator, denominator, isComplete)` from `WalletSummary.scanProgress`,
    ///                       or `nil` when the summary is unavailable (fresh db).
    ///   - recoveryProgress: `(numerator, denominator)` from `WalletSummary.recoveryProgress`,
    ///                       or `nil` when no recovery range exists.
    /// - Returns: `(progress, spendable)` where `progress` ∈ [0.0, 1.0].
    static func composeProgress(
        scanProgress: (numerator: UInt64, denominator: UInt64, isComplete: Bool)?,
        recoveryProgress: (numerator: UInt64, denominator: UInt64)?
    ) -> (progress: Float, spendable: Bool) {
        guard let scan = scanProgress else {
            return (0.0, false)
        }

        let composedNumerator = Float(scan.numerator) + Float(recoveryProgress?.numerator ?? 0)
        let composedDenominator = Float(scan.denominator) + Float(recoveryProgress?.denominator ?? 0)

        let progress: Float
        if composedDenominator == 0 {
            progress = 1.0
        } else {
            let raw = composedNumerator / composedDenominator
            if raw > 1.0 {
                // Defensive clamp — should not happen, but protect the UI from an out-of-range
                // fraction; the old SDK threw ZcashError.rustScanProgressOutOfRange here.
                // We clamp and let the caller emit a warning (single emission point in tickPoll).
                progress = 1.0
            } else {
                progress = raw
            }
        }

        return (progress, scan.isComplete)
    }

    /// Pure decision: should this poll tick mark `SDKFlags.chainTipUpdated`?
    ///
    /// Semantics mirror `UpdateChainTipAction.swift:49` — the flag is marked exactly when
    /// the wallet DB chain tip is known to have been refreshed by the CURRENT run:
    ///
    ///   - `alreadyMarked` — marked once per run; later ticks are no-ops.
    ///   - `snapshotTip == 0` — the engine has not advertised any tip yet; never mark.
    ///   - `snapshotTip != tipAtRunStart` — the engine's `sync_once` stores the snapshot
    ///     tip ONLY AFTER `session.update_chain_tip(tip)` succeeds (engine.rs:111 → :116),
    ///     so a changed tip proves the DB tip was refreshed by this run.
    ///   - same tip value — trust it only when the pass reached Done (`state == 3`):
    ///     `sync_once` cannot complete without `update_chain_tip` having succeeded.
    ///     (While still Syncing, an unchanged nonzero tip may be residue from a PREVIOUS
    ///     pass on the same handle — e.g. stop()/start() after a long background period —
    ///     and marking on it would defeat the [#1591] stale-tip protection.)
    ///
    /// - Parameters:
    ///   - snapshotTip:   `snap.chainTip` from the FFI snapshot.
    ///   - tipAtRunStart: snapshot tip captured in `start()` before the pass began.
    ///   - state:         `snap.state` (0=idle, 1=syncing, 2=error, 3=done).
    ///   - alreadyMarked: whether this run already marked the flag.
    /// - Returns: true when the flag should be marked now.
    static func shouldMarkChainTipUpdated(
        snapshotTip: UInt64,
        tipAtRunStart: UInt64,
        state: UInt8,
        alreadyMarked: Bool
    ) -> Bool {
        guard !alreadyMarked else { return false }
        guard snapshotTip != 0 else { return false }
        if snapshotTip != tipAtRunStart { return true }
        return state == 3
    }

    // ── B4 (#1755 failure-path hardening): stall watchdog ─────────────────────

    /// Signature of every engine progress counter the poll loop can observe.
    /// Two consecutive snapshots with EQUAL signatures mean the engine made zero
    /// observable progress between the ticks.
    /// (Named "signature" — the natural alternative collides with the
    /// `print_function_usage` lint regex.)
    struct ProgressSignature: Equatable {
        let fetched: UInt64
        let scanned: UInt64
        let enhanced: UInt64
        let rangesCompleted: UInt64
        let chainTip: UInt64
    }

    /// Extracts the stall-watchdog progress signature from an engine snapshot.
    static func watchdogSignature(_ snap: SlipstreamSnapshot) -> ProgressSignature {
        ProgressSignature(
            fetched: snap.fetchedBlocks,
            scanned: snap.scannedBlocks,
            enhanced: snap.enhancedTxs,
            rangesCompleted: snap.rangesCompleted,
            chainTip: snap.chainTip
        )
    }

    /// Pure staleness predicate: the engine claims to be Syncing (`state == 1`) but
    /// NO progress counter has changed for at least `threshold` seconds.
    ///
    /// Field failure 2 (2026-06-12): the UI froze at one chunk with the state stuck
    /// "Syncing" — no logs, no error, forever. This predicate makes such silent
    /// stalls VISIBLE (a loud `Logger.error` in `tickPoll`); it deliberately does
    /// NOT auto-restart anything — recovery policy stays with the app.
    ///
    /// - Parameters:
    ///   - state: `snap.state` (0=idle, 1=syncing, 2=error, 3=done). Only Syncing
    ///     can stall silently; Done/Error/Idle are legitimate steady states.
    ///   - secondsSinceLastCounterChange: elapsed wall time since the watchdog
    ///     progress signature last changed.
    ///   - threshold: the stall window (`stallWatchdogThresholdSeconds`, 120 s — far
    ///     above any legitimate counter gap: the slowest observed device chunk is
    ///     ~36 s on iPad A10, and treestate/scan boundaries bump counters within it).
    /// - Returns: true when the stall warning should fire.
    static func isSyncStalled(
        state: UInt8,
        secondsSinceLastCounterChange: TimeInterval,
        threshold: TimeInterval
    ) -> Bool {
        state == 1 && secondsSinceLastCounterChange >= threshold
    }
}

// MARK: - withTaskTimeout helper (F1)

/// Races `operation` against a nanosecond timer.  Returns the operation's value if it
/// completes first; throws `_SummaryTimeoutError` when the timer wins.
///
/// Uses `Task.sleep(nanoseconds:)` for iOS 13+/macOS 12+ compatibility (the newer
/// `Task.sleep(for: Duration)` requires iOS 16+/macOS 13+).
///
/// Both the operation task and the timer task are cancelled when the other wins
/// (structured cancellation via `withThrowingTaskGroup`).  Structured concurrency
/// means this returns only once both child tasks have acknowledged cancellation.
///
/// `internal` (not `private`) so `@testable` test targets can exercise the timeout
/// behaviour directly without requiring a full `SlipstreamSynchronizer` instance.
/// (Moved here from SlipstreamSynchronizer.swift for file_length — B4 hardening.)
struct _SummaryTimeoutError: Error {}

func withTaskTimeout<T: Sendable>(
    _ nanoseconds: UInt64,
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(nanoseconds: nanoseconds)
            throw _SummaryTimeoutError()
        }
        defer { group.cancelAll() }
        guard let result = try await group.next() else {
            throw _SummaryTimeoutError()
        }
        return result
    }
}
