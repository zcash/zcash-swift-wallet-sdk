//
//  ProcessSuggestedScanRangesActionTests.swift
//
//
//  Created by Lukáš Korba on 25.08.2023.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class ProcessSuggestedScanRangesActionTests: ZcashTestCase {
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

    func testProcessSuggestedScanRangesAction_EmptyScanRanges() async throws {
        let loggerMock = LoggerMock()

        loggerMock.debugFileFunctionLineClosure = { _, _, _, _ in }
        loggerMock.syncFileFunctionLineClosure = { _, _, _, _ in }

        let tupple = setupAction(loggerMock)
        tupple.rustBackendMock.suggestScanRangesClosure = { [] }

        let processSuggestedScanRangesActionAction = tupple.action

        do {
            let context = ActionContextMock.default()

            let nextContext = try await processSuggestedScanRangesActionAction.run(with: context) { _ in }

            let acResult = nextContext.checkStateIs(.txResubmission)
            XCTAssertTrue(acResult == .true, "Check of state failed with '\(acResult)'")
        } catch {
            XCTFail("testProcessSuggestedScanRangesAction_EmptyScanRanges is not expected to fail. \(error)")
        }
    }

    func testProcessSuggestedScanRangesAction_ChainTipScanRange() async throws {
        let loggerMock = LoggerMock()

        loggerMock.infoFileFunctionLineClosure = { _, _, _, _ in }
        loggerMock.debugFileFunctionLineClosure = { _, _, _, _ in }
        loggerMock.syncFileFunctionLineClosure = { _, _, _, _ in }

        let sdkMetricsMock = SDKMetricsMock()

        sdkMetricsMock.actionDetailForClosure = { _, _ in }

        let tupple = setupAction(loggerMock, sdkMetricsMock)
        tupple.rustBackendMock.suggestScanRangesClosure = {
            [ScanRange(range: 0..<10, priority: .chainTip)]
        }

        let processSuggestedScanRangesActionAction = tupple.action

        do {
            let context = ActionContextMock.default()
            context.updateLastEnhancedHeightClosure = { _ in }
            context.updateLastScannedHeightClosure = { _ in }
            context.updateLastDownloadedHeightClosure = { _ in }
            context.updateSyncControlDataClosure = { _ in }
            context.updateRequestedRewindHeightClosure = { _ in }

            let nextContext = try await processSuggestedScanRangesActionAction.run(with: context) { _ in }

            if let nextContextMock = nextContext as? ActionContextMock {
                XCTAssertFalse(
                    nextContextMock.updateRequestedRewindHeightCalled,
                    "context.update(requestedRewindHeight:) is not expected to be called"
                )

                let enhancedValue = nextContextMock.updateLastEnhancedHeightReceivedLastEnhancedHeight
                let value = String(describing: enhancedValue)
                XCTAssertNil(
                    enhancedValue,
                    "context.update(updateLastEnhancedHeight:) is expected to reset the value to nil but received \(value)"
                )
            } else {
                XCTFail("`nextContext` is not the ActionContextMock")
            }

            XCTAssertTrue(
                loggerMock.debugFileFunctionLineCalled,
                "logger.debug() is not expected to be called."
            )

            if let syncArguments = loggerMock.syncFileFunctionLineReceivedArguments {
                XCTAssertFalse(syncArguments.message.contains("Setting the total range for Spend before Sync to"))
            } else {
                XCTFail("`syncArguments` unavailable.")
            }

            let acResult = nextContext.checkStateIs(.download)
            XCTAssertTrue(acResult == .true, "Check of state failed with '\(acResult)'")
        } catch {
            XCTFail("testProcessSuggestedScanRangesAction_ChainTipScanRange is not expected to fail. \(error)")
        }
    }

    // swiftlint:disable large_tuple
    private func setupAction(
        _ loggerMock: LoggerMock = LoggerMock(),
        _ sdkMetricsMock: SDKMetricsMock = SDKMetricsMock()
    ) -> (
        action: ProcessSuggestedScanRangesAction,
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
        mockContainer.mock(type: SDKMetrics.self, isSingleton: true) { _ in sdkMetricsMock }

        return (
            action: ProcessSuggestedScanRangesAction(container: mockContainer),
            serviceMock: serviceMock,
            rustBackendMock: rustBackendMock
        )
    }

    func testScanRangePriorities() {
        XCTAssertEqual(ScanRange.Priority(0), .ignored)
        XCTAssertEqual(ScanRange.Priority(10), .scanned)
        XCTAssertEqual(ScanRange.Priority(20), .historic)
        XCTAssertEqual(ScanRange.Priority(30), .openAdjacent)
        XCTAssertEqual(ScanRange.Priority(40), .foundNote)
        XCTAssertEqual(ScanRange.Priority(50), .chainTip)
        XCTAssertEqual(ScanRange.Priority(60), .verify)
    }
}
