//
//  ClearCacheActionTests.swift
//
//
//  Created by Lukáš Korba on 22.05.2023.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class ClearCacheActionTests: ZcashTestCase {
    func testClearCacheAction_MigrationLegacyCacheDB() async throws {
        let compactBlockRepositoryMock = CompactBlockRepositoryMock()

        let clearCacheAction = setupAction(compactBlockRepositoryMock)

        do {
            let context = ActionContextMock.default()
            context.prevState = .idle

            let nextContext = try await clearCacheAction.run(with: context) { _ in }

            XCTAssertTrue(compactBlockRepositoryMock.clearCalled, "storage.clear() is expected to be called.")

            let acResult = nextContext.checkStateIs(.processSuggestedScanRanges)
            XCTAssertTrue(acResult == .true, "Check of state failed with '\(acResult)'")
        } catch {
            XCTFail("testClearCacheAction_MigrationLegacyCacheDB is not expected to fail. \(error)")
        }
    }

    private func setupAction(
        _ compactBlockRepositoryMock: CompactBlockRepositoryMock = CompactBlockRepositoryMock()
    ) -> ClearCacheAction {
        compactBlockRepositoryMock.clearClosure = { }

        mockContainer.mock(type: CompactBlockRepository.self, isSingleton: true) { _ in compactBlockRepositoryMock }

        return ClearCacheAction(
            container: mockContainer
        )
    }
}
