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

    /// T8.3.5: the wallet's GLOBAL scan progress from a persisted `WalletSummary`
    /// (the engine's scanned-vs-total-needed fraction), or `(0.0, false)` when no
    /// summary exists yet (a genuinely fresh wallet). Wraps `composeProgress` with the
    /// summary's `scanProgress`/`recoveryProgress`. Used to (a) warm the cold-launch
    /// emissions (`prepare`/`start`) so balance + progress show real values immediately,
    /// and (b) hold the pre-first-suggest ticks (before the engine seeds its global floor).
    static func summaryProgress(_ summary: WalletSummary?) -> (progress: Float, spendable: Bool) {
        guard let summary else { return (0.0, false) }
        return composeProgress(
            scanProgress: summary.scanProgress.map { ($0.numerator, $0.denominator, $0.isComplete) },
            recoveryProgress: summary.recoveryProgress.map { ($0.numerator, $0.denominator) }
        )
    }

    /// [#1755] Deep-recovery (restore / new-account backfill) detector. True while the wallet
    /// backend's `recovery_progress` exists and is incomplete — the window in which a note can
    /// appear unspent before the block that spends it has been scanned, transiently inflating both
    /// balance and Activity. The SDK reports 0 balance / empty Activity while this is true. A nil or
    /// complete recovery (light catch-ups, fully synced) ⇒ false.
    static func isRecovering(_ summary: WalletSummary?) -> Bool {
        guard let recovery = summary?.recoveryProgress else { return false }
        return !recovery.isComplete
    }

    /// [#1755] Wrap a per-account net recovery balance (Σ of FINAL transaction deltas — see
    /// `TransactionRepository.recoveryBalances()`) in an `AccountBalance` for the state stream during a
    /// restore. The whole net (clamped ≥ 0) is surfaced as orchard `spendableValue` so every consumer reads
    /// it correctly: `total()` == net (Zodl home `totalBalance`), available shielded == net (SmartBanner /
    /// WalletBalances). The per-pool breakdown is intentionally collapsed to Orchard for the duration of
    /// recovery — headline correctness over breakdown fidelity mid-restore (the "Restoring" banner is the
    /// progress affordance). Transparent is already folded into the delta sum, so `unshielded` stays zero
    /// here to avoid double-counting. Pure; net ≤ 0 yields a zero balance.
    static func recoveryAccountBalance(net: Zatoshi) -> AccountBalance {
        let clamped = Zatoshi(Swift.max(0, net.amount))
        return AccountBalance(
            saplingBalance: .zero,
            orchardBalance: PoolBalance(spendableValue: clamped, changePendingConfirmation: .zero, valuePendingSpendability: .zero),
            unshielded: .zero,
            awaitingResolution: .zero
        )
    }

    /// T8.3.5: the `SynchronizerState` that `prepare()` emits right after opening the
    /// engine. WARM (from the persisted summary) when a summary exists — the real balance
    /// + a truthful near-100% progress, so a cold launch of a synced wallet never flashes
    /// `[:]`/0%. COLD (`.disconnected`, no balances) when there is no summary yet (a
    /// genuinely fresh wallet about to restore — 0 balance / "connecting" is correct).
    static func initialState(from summary: WalletSummary?, syncSessionID: UUID) -> SynchronizerState {
        guard let summary else {
            return SynchronizerState(
                syncSessionID: syncSessionID,
                accountsBalances: [:],
                internalSyncStatus: .disconnected,
                latestBlockHeight: .zero
            )
        }
        let (progress, spendable) = summaryProgress(summary)
        let recovering = isRecovering(summary)
        return SynchronizerState(
            syncSessionID: syncSessionID,
            accountsBalances: recovering ? [:] : summary.accountBalances,
            internalSyncStatus: .syncing(progress, spendable),
            latestBlockHeight: summary.chainTipHeight,
            fullyScannedHeight: summary.fullyScannedHeight,
            isRecovering: recovering
        )
    }

    /// T8.3.6 (UX): return `raw` with each transaction's `state` populated from
    /// `currentHeight` (via `Overview.getState`). Pure — the height resolution stays in the
    /// synchronizer (it needs `latestState`/the backend). Without populating `state`, Zashi
    /// maps an INCOMING tx via `transaction.state == .pending` → `nil == .pending` → false →
    /// ".received", so a 0-conf mempool tx wrongly shows "received" instead of "receiving".
    static func transactionsWithState(
        _ raw: [ZcashTransaction.Overview],
        currentHeight: BlockHeight
    ) -> [ZcashTransaction.Overview] {
        raw.map { tx in
            var copy = tx
            copy.state = tx.getState(for: currentHeight)
            return copy
        }
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
    ///   - secondsSinceLastCounterChange: elapsed wall time since any engine counter
    ///     last moved (the engine-stamped `snap.stalledSeconds`, Phase D).
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
