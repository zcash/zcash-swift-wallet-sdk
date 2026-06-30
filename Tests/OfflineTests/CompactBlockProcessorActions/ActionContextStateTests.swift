//
//  ActionContextStateTests.swift
//
//
//  Created by Lukáš Korba on 15.06.2023.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class ActionContextStateTests: ZcashTestCase {
    func testPreviousState() async throws {
        let syncContext = ActionContextImpl(state: .idle)

        await syncContext.update(state: .clearCache)

        let currentState = await syncContext.state
        let prevState = await syncContext.prevState

        XCTAssertTrue(
            currentState == .clearCache,
            "syncContext.state after update is expected to be .clearCache but received \(currentState)"
        )

        if let prevState {
            XCTAssertTrue(
                prevState == .idle,
                "syncContext.prevState after update is expected to be .idle but received \(prevState)"
            )
        } else {
            XCTFail("syncContext.prevState is not expected to be nil.")
        }
    }

    func testActionContextReset_DefaultBehaviour() async throws {
        let testCoordinator: TestCoordinator! = try await TestCoordinator(
            alias: .default,
            container: mockContainer,
            walletBirthday: 10,
            network: ZcashTestnet(),
            callPrepareInConstructor: false
        )

        await testCoordinator.synchronizer.blockProcessor.context.update(lastEnhancedHeight: 1_500_000)

        let contextLastEnhancedHeight = await testCoordinator.synchronizer.blockProcessor.context.lastEnhancedHeight

        XCTAssertEqual(contextLastEnhancedHeight, 1_500_000)

        await testCoordinator.synchronizer.blockProcessor.resetContext()

        let contextLastEnhancedHeightAfterReset = await testCoordinator.synchronizer.blockProcessor.context.lastEnhancedHeight

        XCTAssertEqual(
            contextLastEnhancedHeightAfterReset,
            1_500_000,
            """
            testActionContextReset_DefaultBehaviour: The context after reset should restore the last enhanced height,
            received \(String(describing: contextLastEnhancedHeightAfterReset)) instead
            """
        )
    }

    func testActionContextReset_LastEnhancedHeightReset() async throws {
        let testCoordinator: TestCoordinator! = try await TestCoordinator(
            alias: .default,
            container: mockContainer,
            walletBirthday: 10,
            network: ZcashTestnet(),
            callPrepareInConstructor: false
        )

        await testCoordinator.synchronizer.blockProcessor.context.update(lastEnhancedHeight: 1_500_000)

        let contextLastEnhancedHeight = await testCoordinator.synchronizer.blockProcessor.context.lastEnhancedHeight

        XCTAssertEqual(contextLastEnhancedHeight, 1_500_000)

        await testCoordinator.synchronizer.blockProcessor.resetContext(restoreLastEnhancedHeight: false)

        let contextLastEnhancedHeightAfterReset = await testCoordinator.synchronizer.blockProcessor.context.lastEnhancedHeight

        XCTAssertNil(
            contextLastEnhancedHeightAfterReset,
            """
            testActionContextReset_LastEnhancedHeightReset: The context after reset should be nil when forced,
            received \(String(describing: contextLastEnhancedHeightAfterReset)) instead
            """
        )
    }
}
