//
//  ClearAlreadyScannedBlocksActionTests.swift
//
//
//  Created by Lukáš Korba on 22.05.2023.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class ClearAlreadyScannedBlocksActionTests: ZcashTestCase {
    func testClearAlreadyScannedBlocksAction_NextAction() async throws {
        let compactBlockRepositoryMock = CompactBlockRepositoryMock()

        let clearAlreadyScannedBlocksAction = setupAction(compactBlockRepositoryMock)

        do {
            let context = ActionContextMock.default()
            context.lastScannedHeight = -1

            let nextContext = try await clearAlreadyScannedBlocksAction.run(with: context) { _ in }

            XCTAssertTrue(compactBlockRepositoryMock.clearUpToCalled, "storage.clear(upTo:) is expected to be called.")

            let acResult = nextContext.checkStateIs(.enhance)
            XCTAssertTrue(acResult == .true, "Check of state failed with '\(acResult)'")
        } catch {
            XCTFail("testClearAlreadyScannedBlocksAction_NextAction is not expected to fail. \(error)")
        }
    }

    func testClearAlreadyScannedBlocksAction_LastScanHeightZcashError() async throws {
        let clearAlreadyScannedBlocksAction = setupAction()

        do {
            let context = ActionContextMock()

            _ = try await clearAlreadyScannedBlocksAction.run(with: context) { _ in }

            XCTFail("testClearAlreadyScannedBlocksAction_LastScanHeightZcashError should throw an error so fail here is unexpected.")
        } catch ZcashError.compactBlockProcessorLastScannedHeight {
            // it's expected to end up here because we test that error is a specific one and Swift automatically catched it up for us
        } catch {
            XCTFail(
                """
                testClearAlreadyScannedBlocksAction_NextAction is expected to fail
                with ZcashError.compactBlockProcessorLastScannedHeight but received \(error)
                """
            )
        }
    }

    private func setupAction(
        _ compactBlockRepositoryMock: CompactBlockRepositoryMock = CompactBlockRepositoryMock()
    ) -> ClearAlreadyScannedBlocksAction {
        let transactionRepositoryMock = TransactionRepositoryMock()

        compactBlockRepositoryMock.clearUpToClosure = { _ in }

        mockContainer.mock(type: CompactBlockRepository.self, isSingleton: true) { _ in compactBlockRepositoryMock }
        mockContainer.mock(type: TransactionRepository.self, isSingleton: true) { _ in transactionRepositoryMock }

        return ClearAlreadyScannedBlocksAction(
            container: mockContainer
        )
    }
}
