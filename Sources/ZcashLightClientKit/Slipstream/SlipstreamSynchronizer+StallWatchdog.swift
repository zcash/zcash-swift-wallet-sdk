//
//  SlipstreamSynchronizer+StallWatchdog.swift
//  ZcashLightClientKit
//
//  Created for Slipstream task [#1755] — B4 failure-path hardening.
//
//  Detects the silent-freeze failure mode (field report 2026-06-12): the engine
//  state stuck at Syncing while NO progress counter moves — the Rust sync task
//  hung (transport stall) or died (panic; the Rust-side B1 supervisor now also
//  surfaces panics as Error state). The watchdog only LOGS — one loud
//  `Logger.error` per stall episode, carrying the full last snapshot. It never
//  restarts anything: recovery policy stays with the app.
//
//  The pure decision predicate (`isSyncStalled`) lives in
//  SlipstreamSynchronizer+PureHelpers.swift and is unit-tested in OfflineTests.
//

import Foundation

extension SlipstreamSynchronizer {
    /// B4 (#1755): stall-watchdog tick. Tracks the engine's progress-counter
    /// signature across poll ticks; when the state claims Syncing but NO counter
    /// has moved for `stallWatchdogThresholdSeconds`, logs ONE loud error per
    /// stall episode (the episode flag re-arms as soon as any counter moves
    /// again). Never restarts anything — visibility only.
    func checkStallWatchdog(_ snap: SlipstreamSnapshot) {
        // [Engine API v2 §4.4 / Phase D] The stall FACT is engine-owned now: `snap.stalledSeconds`
        // is stamped by the engine's own counters (0 unless state == Syncing). The watchdog keeps
        // only the POLICY — the once-per-episode loud log — re-armed whenever progress resumes.
        let elapsed = TimeInterval(snap.stalledSeconds)
        if elapsed < Self.stallWatchdogThresholdSeconds {
            watchdogStallLogged = false
            return
        }
        guard
            Self.isSyncStalled(
                state: snap.state,
                secondsSinceLastCounterChange: elapsed,
                threshold: Self.stallWatchdogThresholdSeconds
            ),
            !watchdogStallLogged
        else { return }

        watchdogStallLogged = true
        watchdogLogger.error(
            """
            Slipstream stall watchdog: state==Syncing but NO progress counter changed for \(Int(elapsed))s. \
            Last snapshot: chainTip=\(snap.chainTip) fetched=\(snap.fetchedBlocks) scanned=\(snap.scannedBlocks) \
            enhanced=\(snap.enhancedTxs) rangesCompleted=\(snap.rangesCompleted) passTotal=\(snap.passTotalBlocks) \
            rangeEnd=\(snap.currentRangeEnd). The engine sync task appears hung (transport stall) or dead (panic). \
            No auto-restart — recovery policy stays with the app.
            """,
            file: #file,
            function: #function,
            line: #line
        )
    }

    /// B4: re-arms the stall watchdog for a new run/handle (start, switchTo, wipe).
    /// (The stall clock itself is engine-owned and resets with the pass; only the
    /// once-per-episode log flag lives in Swift.)
    func resetStallWatchdog() {
        watchdogStallLogged = false
    }
}
