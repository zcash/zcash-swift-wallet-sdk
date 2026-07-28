//
//  ZcashTransactionStateTests.swift
//  
//
//  Created by Francisco Gindre on 5/3/23.
//

import XCTest
import TestUtils
@testable import ZcashLightClientKit

final class ZcashTransactionStateTests: XCTestCase {
    func testExpiredUnminedState() throws {
        let currentHeight = 1010

        XCTAssertEqual(
            ZcashTransaction.Overview.State(
                currentHeight: currentHeight,
                minedHeight: nil,
                expiredUnmined: true
            ),
            .expired
        )
    }

    func testConfirmationsBelowStaleConstantIsPending() {
        let currentHeight = 1010

        XCTAssertEqual(
            ZcashTransaction.Overview.State(
                currentHeight: currentHeight,
                minedHeight: currentHeight,
                expiredUnmined: false
            ),
            .pending
        )

        XCTAssertEqual(
            ZcashTransaction.Overview.State(
                currentHeight: currentHeight,
                minedHeight: currentHeight - ZcashSDK.defaultStaleTolerance + 1,
                expiredUnmined: false
            ),
            .pending
        )

        XCTAssertNotEqual(
            ZcashTransaction.Overview.State(
                currentHeight: currentHeight,
                minedHeight: currentHeight - ZcashSDK.defaultStaleTolerance,
                expiredUnmined: false
            ),
            .pending
        )
    }

    /// `expired_unmined` is NULL in `v_transactions` whenever the transaction is unmined and its
    /// expiry cannot be evaluated (unknown expiry height, or no scanned blocks yet — e.g. right
    /// after a rewind). NULL means "unknown", never "expired": the state must be derived from the
    /// mined-height evidence instead of short-circuiting to `.expired`.
    func testNilExpiredUnminedDerivesStateFromMinedHeight() {
        let currentHeight = 1_500_000

        // Mined with enough confirmations -> confirmed.
        XCTAssertEqual(
            ZcashTransaction.Overview.State(
                currentHeight: currentHeight,
                minedHeight: currentHeight - ZcashSDK.defaultStaleTolerance,
                expiredUnmined: nil
            ),
            .confirmed
        )

        // Freshly mined -> pending.
        XCTAssertEqual(
            ZcashTransaction.Overview.State(
                currentHeight: currentHeight,
                minedHeight: currentHeight,
                expiredUnmined: nil
            ),
            .pending
        )

        // Unmined -> pending.
        XCTAssertEqual(
            ZcashTransaction.Overview.State(
                currentHeight: currentHeight,
                minedHeight: nil,
                expiredUnmined: nil
            ),
            .pending
        )
    }

    func testMinedHeightAboveOrEqualToStaleConstantIsConfirmed() {
        let currentHeight = 1010

        XCTAssertEqual(
            ZcashTransaction.Overview.State(
                currentHeight: currentHeight,
                minedHeight: currentHeight - ZcashSDK.defaultStaleTolerance,
                expiredUnmined: false
            ),
            .confirmed
        )

        XCTAssertEqual(
            ZcashTransaction.Overview.State(
                currentHeight: currentHeight,
                minedHeight: currentHeight - ZcashSDK.defaultStaleTolerance - 1,
                expiredUnmined: false
            ),
            .confirmed
        )

        XCTAssertNotEqual(
            ZcashTransaction.Overview.State(
                currentHeight: currentHeight,
                minedHeight: currentHeight - ZcashSDK.defaultStaleTolerance + 1,
                expiredUnmined: false
            ),
            .confirmed
        )
    }
}
