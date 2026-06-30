//
//  Action.swift
//
//
//  Created by Michal Fousek on 05.05.2023.
//

import Foundation

protocol ActionContext {
    var state: CBPState { get async }
    var prevState: CBPState? { get async }
    var syncControlData: SyncControlData { get async }
    var requestedRewindHeight: BlockHeight? { get async }
    var processedHeight: BlockHeight { get async }
    var lastChainTipUpdateTime: TimeInterval { get async }
    var lastScannedHeight: BlockHeight? { get async }
    var lastEnhancedHeight: BlockHeight? { get async }

    func update(state: CBPState) async
    func update(syncControlData: SyncControlData) async
    func update(processedHeight: BlockHeight) async
    func update(lastChainTipUpdateTime: TimeInterval) async
    func update(lastScannedHeight: BlockHeight) async
    func update(lastDownloadedHeight: BlockHeight) async
    func update(lastEnhancedHeight: BlockHeight?) async
    func update(requestedRewindHeight: BlockHeight) async
}

actor ActionContextImpl: ActionContext {
    var state: CBPState
    var prevState: CBPState?
    var syncControlData: SyncControlData
    var requestedRewindHeight: BlockHeight?
    /// Amount of blocks that have been processed so far
    var processedHeight: BlockHeight = 0
    /// Update chain tip must be called repeatadly, this value stores the previous update and help to decide when to call it again
    var lastChainTipUpdateTime: TimeInterval = 0.0
    var lastScannedHeight: BlockHeight?
    var lastDownloadedHeight: BlockHeight?
    var lastEnhancedHeight: BlockHeight?

    init(state: CBPState) {
        self.state = state
        syncControlData = SyncControlData.empty
    }

    func update(state: CBPState) async {
        prevState = self.state
        self.state = state
    }
    func update(syncControlData: SyncControlData) async { self.syncControlData = syncControlData }
    func update(processedHeight: BlockHeight) async { self.processedHeight = processedHeight }
    func update(lastChainTipUpdateTime: TimeInterval) async { self.lastChainTipUpdateTime = lastChainTipUpdateTime }
    func update(lastScannedHeight: BlockHeight) async { self.lastScannedHeight = lastScannedHeight }
    func update(lastDownloadedHeight: BlockHeight) async { self.lastDownloadedHeight = lastDownloadedHeight }
    func update(lastEnhancedHeight: BlockHeight?) async { self.lastEnhancedHeight = lastEnhancedHeight }
    func update(requestedRewindHeight: BlockHeight) async { self.requestedRewindHeight = requestedRewindHeight }
}

enum CBPState: CaseIterable {
    case idle
    case migrateLegacyCacheDB
    case validateServer
    case updateSubtreeRoots
    case updateChainTip
    case processSuggestedScanRanges
    case rewind
    case download
    case scan
    case clearAlreadyScannedBlocks
    case enhance
    case fetchUTXO
    case handleSaplingParams
    case clearCache
    case txResubmission
    case finished
    case failed
    case stopped
}

protocol Action {
    /// If this is true and action fails with error then blocks cache is cleared.
    var removeBlocksCacheWhenFailed: Bool { get }

    // When any action is created it can get `DIContainer` and resolve any depedencies it requires.
    // Every action uses `context` to get some informartion like download range.
    //
    // `didUpdate` is closure that action use to tell CBP that some part of the work is done. For example if download action would like to
    // update progress on every block downloaded it can use this closure. Also if action doesn't need to update progress on partial work it doesn't
    // need to use this closure at all.
    //
    // Each action updates context accordingly. It should at least set new state. Reason for this is that action can return different states for
    // different conditions. And action is the thing that knows these conditions.
    func run(with context: ActionContext, didUpdate: @escaping (CompactBlockProcessor.Event) async -> Void) async throws -> ActionContext

    // Should be called on each existing action when processor wants to stop. Some actions may do it's own background work.
    func stop() async
}
