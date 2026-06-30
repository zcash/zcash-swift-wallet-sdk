//
//  SaplingParamsActionTests.swift
//
//
//  Created by Lukáš Korba on 18.05.2023.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class SaplingParamsActionTests: ZcashTestCase {
    func testSaplingParamsAction_NextAction_SpendBeforeSync() async throws {
        let loggerMock = LoggerMock()
        let saplingParametersHandlerMock = SaplingParametersHandlerMock()

        let saplingParamsActionAction = setupAction(saplingParametersHandlerMock, loggerMock)

        do {
            let context = ActionContextMock.default()

            let nextContext = try await saplingParamsActionAction.run(with: context) { _ in }

            XCTAssertTrue(loggerMock.debugFileFunctionLineCalled, "logger.debug(...) is expected to be called.")
            XCTAssertTrue(saplingParametersHandlerMock.handleIfNeededCalled, "saplingParametersHandler.handleIfNeeded() is expected to be called.")

            let acResult = nextContext.checkStateIs(.updateSubtreeRoots)
            XCTAssertTrue(acResult == .true, "Check of state failed with '\(acResult)'")
        } catch {
            XCTFail("testSaplingParamsAction_NextAction is not expected to fail. \(error)")
        }
    }

    private func setupAction(
        _ saplingParametersHandlerMock: SaplingParametersHandlerMock = SaplingParametersHandlerMock(),
        _ loggerMock: LoggerMock = LoggerMock()
    ) -> SaplingParamsAction {
        loggerMock.debugFileFunctionLineClosure = { _, _, _, _ in }
        saplingParametersHandlerMock.handleIfNeededClosure = { }

        mockContainer.mock(type: Logger.self, isSingleton: true) { _ in loggerMock }
        mockContainer.mock(type: SaplingParametersHandler.self, isSingleton: true) { _ in saplingParametersHandlerMock }

        return SaplingParamsAction(
            container: mockContainer
        )
    }
}
