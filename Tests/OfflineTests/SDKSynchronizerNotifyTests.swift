//
//  SDKSynchronizerNotifyTests.swift
//
//
//  Created by Michal Fousek on 28.07.2026.
//

import XCTest
@testable import ZcashLightClientKit

/// `InternalSyncStatus.==` deliberately treats any two `.error` values as equal. If the
/// synchronizer coalesced status notifications on that equality, `latestState` (chain tip,
/// balances) and the state stream would freeze at the snapshot taken for the FIRST failure
/// while the compact block processor keeps retrying — the app would keep rendering a stale
/// chain tip and a stale error indefinitely. Failures must therefore always be (re)published.
final class SDKSynchronizerNotifyTests: XCTestCase {
    func testRepeatedIdenticalErrorIsPublished() {
        XCTAssertTrue(
            SDKSynchronizer.shouldNotify(
                oldStatus: .error(ZcashError.synchronizerNotPrepared),
                newStatus: .error(ZcashError.synchronizerNotPrepared)
            )
        )
    }

    func testRepeatedDifferentErrorIsPublished() {
        XCTAssertTrue(
            SDKSynchronizer.shouldNotify(
                oldStatus: .error(ZcashError.synchronizerNotPrepared),
                newStatus: .error(ZcashError.synchronizerDisconnected)
            )
        )
    }

    func testFirstErrorIsPublished() {
        XCTAssertTrue(
            SDKSynchronizer.shouldNotify(
                oldStatus: .synced,
                newStatus: .error(ZcashError.synchronizerNotPrepared)
            )
        )
    }

    func testUnchangedNonErrorStatusIsCoalesced() {
        XCTAssertFalse(
            SDKSynchronizer.shouldNotify(
                oldStatus: .synced,
                newStatus: .synced
            )
        )

        XCTAssertFalse(
            SDKSynchronizer.shouldNotify(
                oldStatus: .syncing(0.5, false),
                newStatus: .syncing(0.5, false)
            )
        )
    }

    func testChangedStatusIsPublished() {
        XCTAssertTrue(
            SDKSynchronizer.shouldNotify(
                oldStatus: .syncing(0.5, false),
                newStatus: .syncing(0.75, false)
            )
        )

        XCTAssertTrue(
            SDKSynchronizer.shouldNotify(
                oldStatus: .error(ZcashError.synchronizerNotPrepared),
                newStatus: .syncing(0.1, false)
            )
        )
    }
}
