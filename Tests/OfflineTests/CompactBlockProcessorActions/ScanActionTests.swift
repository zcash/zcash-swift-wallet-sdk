//
//  ScanActionTests.swift
//
//
//  Created by Lukáš Korba on 18.05.2023.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class ScanActionTests: ZcashTestCase {
    func testScanAction_NextAction() async throws {
        let blockScannerMock = BlockScannerMock()
        let loggerMock = LoggerMock()

        loggerMock.debugFileFunctionLineClosure = { _, _, _, _ in }
        loggerMock.syncFileFunctionLineClosure = { _, _, _, _ in }

        let scanAction = setupAction(blockScannerMock, loggerMock)

        let syncContext = ActionContextMock.default()
        syncContext.lastScannedHeight = 1500
        syncContext.underlyingSyncControlData = SyncControlData(
            latestBlockHeight: 2000,
            latestScannedHeight: 1000,
            firstUnenhancedHeight: nil
        )
        blockScannerMock.scanBlocksAtDidScanReturnValue = 1

        do {
            let nextContext = try await scanAction.run(with: syncContext) { event in
                guard case .syncProgress = event else {
                    XCTFail("event is expected to be .syncProgress() but received \(event)")
                    return
                }
            }
            XCTAssertTrue(loggerMock.debugFileFunctionLineCalled, "logger.debug(...) is expected to be called.")

            let acResult = nextContext.checkStateIs(.clearAlreadyScannedBlocks)
            XCTAssertTrue(acResult == .true, "Check of state failed with '\(acResult)'")
        } catch {
            XCTFail("testScanAction_NextAction is not expected to fail. \(error)")
        }
    }

    func testScanAction_EarlyOutForNoDownloadAndScanRangeSet() async throws {
        let blockScannerMock = BlockScannerMock()
        let loggerMock = LoggerMock()

        let scanAction = setupAction(blockScannerMock, loggerMock)
        let syncContext = ActionContextMock.default()

        do {
            _ = try await scanAction.run(with: syncContext) { _ in }
            XCTAssertFalse(loggerMock.debugFileFunctionLineCalled, "logger.debug(...) is not expected to be called.")
        } catch {
            XCTFail("testScanAction_EarlyOutForNoDownloadAndScanRangeSet is not expected to fail. \(error)")
        }
    }

    func testScanAction_StartRangeHigherThanEndRange() async throws {
        let blockScannerMock = BlockScannerMock()
        let loggerMock = LoggerMock()

        let scanAction = setupAction(blockScannerMock, loggerMock)
        let syncContext = ActionContextMock.default()
        syncContext.lastScannedHeight = 2001
        syncContext.underlyingSyncControlData = SyncControlData(
            latestBlockHeight: 2000,
            latestScannedHeight: 1000,
            firstUnenhancedHeight: nil
        )
        blockScannerMock.scanBlocksAtDidScanReturnValue = 1

        do {
            _ = try await scanAction.run(with: syncContext) { _ in }
            XCTAssertFalse(loggerMock.debugFileFunctionLineCalled, "logger.debug(...) is not expected to be called.")
        } catch {
            XCTFail("testScanAction_StartRangeHigherThanEndRange is not expected to fail. \(error)")
        }
    }

    func testScanAction_EndRangeProperlySetLowerThanBatchSize() async throws {
        let blockScannerMock = BlockScannerMock()
        let loggerMock = LoggerMock()

        loggerMock.debugFileFunctionLineClosure = { _, _, _, _ in }
        loggerMock.syncFileFunctionLineClosure = { _, _, _, _ in }

        let scanAction = setupAction(blockScannerMock, loggerMock)
        let syncContext = ActionContextMock.default()
        syncContext.lastScannedHeight = 1001
        syncContext.underlyingSyncControlData = SyncControlData(
            latestBlockHeight: 1078,
            latestScannedHeight: 1000,
            firstUnenhancedHeight: nil
        )
        blockScannerMock.scanBlocksAtDidScanReturnValue = 1

        do {
            _ = try await scanAction.run(with: syncContext) { _ in }
            XCTAssertTrue(loggerMock.debugFileFunctionLineCalled, "logger.debug(...) is expected to be called.")
        } catch {
            XCTFail("testScanAction_EndRangeProperlySetLowerThanBatchSize is not expected to fail. \(error)")
        }
    }

    func testScanAction_EndRangeProperlySetBatchSize() async throws {
        let blockScannerMock = BlockScannerMock()
        let loggerMock = LoggerMock()

        loggerMock.debugFileFunctionLineClosure = { _, _, _, _ in }
        loggerMock.syncFileFunctionLineClosure = { _, _, _, _ in }

        let scanAction = setupAction(blockScannerMock, loggerMock)
        let syncContext = ActionContextMock.default()
        syncContext.lastScannedHeight = 1001
        syncContext.underlyingSyncControlData = SyncControlData(
            latestBlockHeight: 1978,
            latestScannedHeight: 1000,
            firstUnenhancedHeight: nil
        )
        blockScannerMock.scanBlocksAtDidScanReturnValue = 1

        do {
            _ = try await scanAction.run(with: syncContext) { _ in }
            XCTAssertTrue(loggerMock.debugFileFunctionLineCalled, "logger.debug(...) is expected to be called.")
        } catch {
            XCTFail("testScanAction_EndRangeProperlySetBatchSize is not expected to fail. \(error)")
        }
    }

    private func setupAction(
        _ blockScannerMock: BlockScannerMock,
        _ loggerMock: LoggerMock,
        _ latestBlocksDataProvider: LatestBlocksDataProvider = LatestBlocksDataProviderMock()
    ) -> ScanAction {
        let rustBackendMock = ZcashRustBackendWeldingMock()

        rustBackendMock.consensusBranchIdForHeightClosure = { height in
            XCTAssertEqual(height, 2, "")
            return -1026109260
        }

        mockContainer.mock(type: ZcashRustBackendWelding.self, isSingleton: true) { _ in rustBackendMock }
        mockContainer.mock(type: BlockScanner.self, isSingleton: true) { _ in blockScannerMock }
        mockContainer.mock(type: Logger.self, isSingleton: true) { _ in loggerMock }
        mockContainer.mock(type: LatestBlocksDataProvider.self, isSingleton: true) { _ in latestBlocksDataProvider }

        let config: CompactBlockProcessor.Configuration = .standard(
            for: ZcashNetworkBuilder.network(for: .testnet), walletBirthday: 0
        )

        return ScanAction(
            container: mockContainer,
            configProvider: CompactBlockProcessor.ConfigProvider(config: config)
        )
    }
}
