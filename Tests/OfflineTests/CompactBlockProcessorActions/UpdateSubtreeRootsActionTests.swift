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

    private enum TestError: Error {
        case ironwoodUnsupported
    }

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
        tupple.rustBackendMock.putIronwoodSubtreeRootsStartIndexRootsClosure = { _, _ in }

        do {
            let context = ActionContextMock.default()

            let nextContext = try await updateSubtreeRootsActionAction.run(with: context) { _ in }

            // Sapling + Orchard + Ironwood roots all stored -> three chain-tip state updates.
            let acResult = nextContext.checkStateIs(.updateChainTip)
            XCTAssertTrue(acResult == .called(3), "Check of state failed with '\(acResult)'")
        } catch {
            XCTFail("testUpdateSubtreeRootsAction_RootsAvailablePutRootsSuccess is not expected to fail. \(error)")
        }
    }

    func testUpdateSubtreeRootsAction_IronwoodFetchFailureIsGraceful() async throws {
        let loggerMock = LoggerMock()

        loggerMock.debugFileFunctionLineClosure = { _, _, _, _ in }

        let tupple = setupAction(loggerMock)
        let updateSubtreeRootsActionAction = tupple.action

        // The server serves Sapling/Orchard roots but errors on the Ironwood protocol (no current
        // lightwalletd supports it). The action must skip Ironwood gracefully and still succeed.
        tupple.serviceMock.getSubtreeRootsModeClosure = { request, _ in
            if request.shieldedProtocol == .ironwood {
                return AsyncThrowingStream { $0.finish(throwing: TestError.ironwoodUnsupported) }
            }
            return AsyncThrowingStream { continuation in
                continuation.yield(SubtreeRoot())
                continuation.finish()
            }
        }

        tupple.rustBackendMock.putSaplingSubtreeRootsStartIndexRootsClosure = { _, _ in }
        tupple.rustBackendMock.putOrchardSubtreeRootsStartIndexRootsClosure = { _, _ in }

        do {
            let context = ActionContextMock.default()

            let nextContext = try await updateSubtreeRootsActionAction.run(with: context) { _ in }

            XCTAssertFalse(
                tupple.rustBackendMock.putIronwoodSubtreeRootsStartIndexRootsCalled,
                "putIronwoodSubtreeRoots must not be called when the Ironwood fetch fails"
            )
            // Only Sapling + Orchard updated the chain-tip state; Ironwood was skipped.
            let acResult = nextContext.checkStateIs(.updateChainTip)
            XCTAssertTrue(acResult == .called(2), "Check of state failed with '\(acResult)'")
        } catch {
            XCTFail("A failed Ironwood fetch must not break sync. \(error)")
        }
    }

    func testUpdateSubtreeRootsAction_FetchesIronwoodWhenSaplingHasNoCompletedSubtrees() async throws {
        let loggerMock = LoggerMock()
        loggerMock.debugFileFunctionLineClosure = { _, _, _, _ in }

        let tupple = setupAction(loggerMock)
        var orchardRequested = false
        var ironwoodRequested = false
        tupple.serviceMock.getSubtreeRootsModeClosure = { request, _ in
            switch request.shieldedProtocol {
            case .sapling:
                return AsyncThrowingStream { $0.finish() }
            case .orchard:
                orchardRequested = true
                return AsyncThrowingStream { $0.finish() }
            case .ironwood:
                ironwoodRequested = true
                return AsyncThrowingStream { continuation in
                    continuation.yield(SubtreeRoot())
                    continuation.finish()
                }
            case .UNRECOGNIZED(_):
                return AsyncThrowingStream { $0.finish() }
            }
        }
        tupple.rustBackendMock.putSaplingSubtreeRootsStartIndexRootsClosure = { _, _ in }
        tupple.rustBackendMock.putIronwoodSubtreeRootsStartIndexRootsClosure = { _, _ in }

        let context = ActionContextMock.default()
        _ = try await tupple.action.run(with: context) { _ in }

        XCTAssertFalse(orchardRequested, "the legacy Orchard probe remains gated on Sapling support")
        XCTAssertTrue(ironwoodRequested, "Ironwood must be queried independently of Sapling roots")
        XCTAssertTrue(tupple.rustBackendMock.putIronwoodSubtreeRootsStartIndexRootsCalled)
    }

    func testUpdateSubtreeRootsAction_RootsAvailablePutIronwoodRootsFailure() async throws {
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
        tupple.rustBackendMock.putOrchardSubtreeRootsStartIndexRootsClosure = { _, _ in }
        tupple.rustBackendMock.putIronwoodSubtreeRootsStartIndexRootsThrowableError = "putIronwoodFailed"

        do {
            let context = ActionContextMock.default()

            _ = try await updateSubtreeRootsActionAction.run(with: context) { _ in }

            XCTFail("updateSubtreeRootsActionAction.run(with:) is expected to fail but didn't.")
        } catch ZcashError.compactBlockProcessorPutIronwoodSubtreeRoots {
            // expected: a genuine Ironwood store failure (on roots we did receive) is surfaced.
        } catch {
            XCTFail("Expected compactBlockProcessorPutIronwoodSubtreeRoots. \(error)")
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
