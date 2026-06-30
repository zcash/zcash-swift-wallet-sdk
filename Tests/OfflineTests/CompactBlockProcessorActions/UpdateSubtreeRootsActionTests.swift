//
//  UpdateSubtreeRootsActionTests.swift
//
//
//  Created by Lukáš Korba on 25.08.2023.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class UpdateSubtreeRootsActionTests: ZcashTestCase {
    var underlyingChainName = ""
    var underlyingNetworkType = NetworkType.testnet
    var underlyingSaplingActivationHeight: BlockHeight?
    var underlyingConsensusBranchID = ""

    override func setUp() {
        super.setUp()

        underlyingChainName = "test"
        underlyingNetworkType = .testnet
        underlyingSaplingActivationHeight = nil
        underlyingConsensusBranchID = "c2d6d0b4"
    }

    func testUpdateSubtreeRootsAction_getSubtreeRootsTimeout() async throws {
        let loggerMock = LoggerMock()

        loggerMock.debugFileFunctionLineClosure = { _, _, _, _ in }

        let tupple = setupAction(loggerMock)
        let updateSubtreeRootsActionAction = tupple.action
        tupple.serviceMock.getSubtreeRootsModeClosure = { _, _ in
            AsyncThrowingStream { continuation in continuation.finish(
                throwing: ZcashError.serviceSubtreeRootsStreamFailed(LightWalletServiceError.timeOut)
            )
            }
        }

        do {
            let context = ActionContextMock.default()

            _ = try await updateSubtreeRootsActionAction.run(with: context) { _ in }
            XCTFail("The test is expected to fail but continued.")
        } catch ZcashError.serviceSubtreeRootsStreamFailed(LightWalletServiceError.timeOut) {
            // this is expected, the action must be terminated as there is no connectivity
        } catch {
            XCTFail(
                """
                testUpdateSubtreeRootsAction_getSubtreeRootsTimeout is expected to fail with
                ZcashError.serviceSubtreeRootsStreamFailed(LightWalletServiceError.timeOut)
                but received \(error)".
                """
            )
        }
    }

    func testUpdateSubtreeRootsAction_RootsAvailablePutRootsSuccess() async throws {
        let loggerMock = LoggerMock()

        loggerMock.debugFileFunctionLineClosure = { _, _, _, _ in }

        let tupple = setupAction(loggerMock)
        let updateSubtreeRootsActionAction = tupple.action
        tupple.serviceMock.getSubtreeRootsModeClosure = { _, _ in
            AsyncThrowingStream { continuation in
                continuation.yield(SubtreeRoot())
                continuation.finish()
            }
        }

        tupple.rustBackendMock.putSaplingSubtreeRootsStartIndexRootsClosure = { _, _ in }
        tupple.rustBackendMock.putOrchardSubtreeRootsStartIndexRootsClosure = { _, _ in }

        do {
            let context = ActionContextMock.default()

            let nextContext = try await updateSubtreeRootsActionAction.run(with: context) { _ in }

            let acResult = nextContext.checkStateIs(.updateChainTip)
            XCTAssertTrue(acResult == .called(2), "Check of state failed with '\(acResult)'")
        } catch {
            XCTFail("testUpdateSubtreeRootsAction_RootsAvailablePutRootsSuccess is not expected to fail. \(error)")
        }
    }

    func testUpdateSubtreeRootsAction_RootsAvailablePutSaplingRootsFailure() async throws {
        let loggerMock = LoggerMock()

        loggerMock.infoFileFunctionLineClosure = { _, _, _, _ in }
        loggerMock.debugFileFunctionLineClosure = { _, _, _, _ in }

        let tupple = setupAction(loggerMock)
        let updateSubtreeRootsActionAction = tupple.action
        tupple.serviceMock.getSubtreeRootsModeClosure = { _, _ in
            AsyncThrowingStream { continuation in
                continuation.yield(SubtreeRoot())
                continuation.finish()
            }
        }

        tupple.rustBackendMock.putSaplingSubtreeRootsStartIndexRootsThrowableError = "putSaplingFailed"
        tupple.rustBackendMock.putOrchardSubtreeRootsStartIndexRootsClosure = { _, _ in }

        do {
            let context = ActionContextMock.default()

            _ = try await updateSubtreeRootsActionAction.run(with: context) { _ in }

            XCTFail("updateSubtreeRootsActionAction.run(with:) is excpected to fail but didn't.")
        } catch ZcashError.compactBlockProcessorPutSaplingSubtreeRoots {
            // this is expected result of this test
        } catch {
            XCTFail("testUpdateSubtreeRootsAction_RootsAvailablePutRootsFailure is not expected to fail. \(error)")
        }
    }

    func testUpdateSubtreeRootsAction_RootsAvailablePutOrchardRootsFailure() async throws {
        let loggerMock = LoggerMock()

        loggerMock.infoFileFunctionLineClosure = { _, _, _, _ in }
        loggerMock.debugFileFunctionLineClosure = { _, _, _, _ in }

        let tupple = setupAction(loggerMock)
        let updateSubtreeRootsActionAction = tupple.action
        tupple.serviceMock.getSubtreeRootsModeClosure = { _, _ in
            AsyncThrowingStream { continuation in
                continuation.yield(SubtreeRoot())
                continuation.finish()
            }
        }

        tupple.rustBackendMock.putSaplingSubtreeRootsStartIndexRootsClosure = { _, _ in }
        tupple.rustBackendMock.putOrchardSubtreeRootsStartIndexRootsThrowableError = "putOrchardFailed"

        do {
            let context = ActionContextMock.default()

            _ = try await updateSubtreeRootsActionAction.run(with: context) { _ in }

            XCTFail("updateSubtreeRootsActionAction.run(with:) is excpected to fail but didn't.")
        } catch ZcashError.compactBlockProcessorPutOrchardSubtreeRoots {
            // this is expected result of this test
        } catch {
            XCTFail("testUpdateSubtreeRootsAction_RootsAvailablePutRootsFailure is not expected to fail. \(error)")
        }
    }

    // swiftlint:disable large_tuple
    private func setupAction(
        _ loggerMock: LoggerMock = LoggerMock()
    ) -> (
        action: UpdateSubtreeRootsAction,
        serviceMock: LightWalletServiceMock,
        rustBackendMock: ZcashRustBackendWeldingMock
    ) {
        let config: CompactBlockProcessor.Configuration = .standard(
            for: ZcashNetworkBuilder.network(for: underlyingNetworkType), walletBirthday: 0
        )

        let rustBackendMock = ZcashRustBackendWeldingMock()
        rustBackendMock.consensusBranchIdForHeightClosure = { height in
            XCTAssertEqual(height, 2, "")
            return -1026109260
        }

        let lightWalletdInfoMock = LightWalletdInfoMock()
        lightWalletdInfoMock.underlyingConsensusBranchID = underlyingConsensusBranchID
        lightWalletdInfoMock.underlyingSaplingActivationHeight = UInt64(underlyingSaplingActivationHeight ?? config.saplingActivation)
        lightWalletdInfoMock.underlyingBlockHeight = 2
        lightWalletdInfoMock.underlyingChainName = underlyingChainName

        let serviceMock = LightWalletServiceMock()
        serviceMock.getInfoModeReturnValue = lightWalletdInfoMock

        mockContainer.mock(type: ZcashRustBackendWelding.self, isSingleton: true) { _ in rustBackendMock }
        mockContainer.mock(type: LightWalletService.self, isSingleton: true) { _ in serviceMock }
        mockContainer.mock(type: Logger.self, isSingleton: true) { _ in loggerMock }

        return (
            action:
                UpdateSubtreeRootsAction(
                    container: mockContainer,
                    configProvider: CompactBlockProcessor.ConfigProvider(config: config)
                ),
            serviceMock: serviceMock,
            rustBackendMock: rustBackendMock
        )
    }
}
