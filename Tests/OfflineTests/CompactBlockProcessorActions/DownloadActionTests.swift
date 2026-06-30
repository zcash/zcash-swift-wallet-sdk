//
//  DownloadActionTests.swift
//
//
//  Created by Lukáš Korba on 21.05.2023.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class DownloadActionTests: ZcashTestCase {
    var underlyingDownloadRange: CompactBlockRange?
    var underlyingScanRange: CompactBlockRange?

    func testDownloadAction_FullPass() async throws {
        let blockDownloaderMock = BlockDownloaderMock()
        let transactionRepositoryMock = TransactionRepositoryMock()

        blockDownloaderMock.setSyncRangeBatchSizeClosure = { _, _ in }
        blockDownloaderMock.setDownloadLimitClosure = { _ in }
        blockDownloaderMock.startDownloadMaxBlockBufferSizeClosure = { _ in }
        blockDownloaderMock.waitUntilRequestedBlocksAreDownloadedInClosure = { _ in }
        blockDownloaderMock.updateLatestDownloadedBlockHeightForceClosure = { _, _ in }

        let downloadAction = setupAction(
            blockDownloaderMock,
            transactionRepositoryMock
        )

        underlyingDownloadRange = CompactBlockRange(uncheckedBounds: (1000, 2000))
        underlyingScanRange = CompactBlockRange(uncheckedBounds: (1000, 2000))

        let syncContext = ActionContextMock.default()
        syncContext.lastScannedHeight = 1000
        syncContext.underlyingSyncControlData = SyncControlData(
            latestBlockHeight: 2000,
            latestScannedHeight: underlyingScanRange?.lowerBound,
            firstUnenhancedHeight: nil
        )

        do {
            let nextContext = try await downloadAction.run(with: syncContext) { _ in }

            XCTAssertTrue(
                blockDownloaderMock.setSyncRangeBatchSizeCallsCount == 1,
                "downloader.setSyncRange() is expected to be called exatcly once."
            )
            XCTAssertTrue(blockDownloaderMock.setDownloadLimitCallsCount == 1, "downloader.setDownloadLimit() is expected to be called exatcly once.")
            XCTAssertTrue(
                blockDownloaderMock.startDownloadMaxBlockBufferSizeCallsCount == 1,
                "downloader.startDownload() is expected to be called exatcly once."
            )
            XCTAssertTrue(
                blockDownloaderMock.updateLatestDownloadedBlockHeightForceCallsCount == 1,
                "downloader.update(latestDownloadedBlockHeight:) expected to be called exactly once."
            )
            XCTAssertTrue(
                blockDownloaderMock.waitUntilRequestedBlocksAreDownloadedInCallsCount == 1,
                "downloader.waitUntilRequestedBlocksAreDownloaded() is expected to be called exatcly once."
            )

            let acResult = nextContext.checkStateIs(.scan)
            XCTAssertTrue(acResult == .true, "Check of state failed with '\(acResult)'")
        } catch {
            XCTFail("testDownloadAction_NextAction is not expected to fail. \(error)")
        }
    }

    func testDownloadAction_LastScanHeightNil() async throws {
        let blockDownloaderMock = BlockDownloaderMock()

        let downloadAction = setupAction(blockDownloaderMock)

        let syncContext = ActionContextMock.default()

        do {
            let nextContext = try await downloadAction.run(with: syncContext) { _ in }

            XCTAssertTrue(blockDownloaderMock.setSyncRangeBatchSizeCallsCount == 0, "downloader.setSyncRange() is not expected to be called.")
            XCTAssertTrue(blockDownloaderMock.setDownloadLimitCallsCount == 0, "downloader.setDownloadLimit() is not expected to be called.")
            XCTAssertTrue(
                blockDownloaderMock.startDownloadMaxBlockBufferSizeCallsCount == 0,
                "downloader.startDownload() is not expected to be called."
            )
            XCTAssertTrue(
                blockDownloaderMock.updateLatestDownloadedBlockHeightForceCallsCount == 0,
                "downloader.update(latestDownloadedBlockHeight:) is not expected to be called."
            )
            XCTAssertTrue(
                blockDownloaderMock.waitUntilRequestedBlocksAreDownloadedInCallsCount == 0,
                "downloader.waitUntilRequestedBlocksAreDownloaded() is not expected to be called."
            )

            let acResult = nextContext.checkStateIs(.scan)
            XCTAssertTrue(acResult == .true, "Check of state failed with '\(acResult)'")
        } catch {
            XCTFail("testDownloadAction_NextAction is not expected to fail. \(error)")
        }
    }

    func testDownloadAction_NoDownloadAndScanRange() async throws {
        let blockDownloaderMock = BlockDownloaderMock()
        let transactionRepositoryMock = TransactionRepositoryMock()

        let downloadAction = setupAction(
            blockDownloaderMock,
            transactionRepositoryMock
        )

        let syncContext = ActionContextMock.default()
        syncContext.lastScannedHeight = 1000
        syncContext.underlyingSyncControlData = SyncControlData(
            latestBlockHeight: 999,
            latestScannedHeight: underlyingScanRange?.lowerBound,
            firstUnenhancedHeight: nil
        )

        do {
            let nextContext = try await downloadAction.run(with: syncContext) { _ in }

            XCTAssertFalse(blockDownloaderMock.setSyncRangeBatchSizeCalled, "downloader.setSyncRange() is not expected to be called.")
            XCTAssertFalse(blockDownloaderMock.setDownloadLimitCalled, "downloader.setDownloadLimit() is not expected to be called.")
            XCTAssertFalse(blockDownloaderMock.startDownloadMaxBlockBufferSizeCalled, "downloader.startDownload() is not expected to be called.")
            XCTAssertFalse(
                blockDownloaderMock.waitUntilRequestedBlocksAreDownloadedInCalled,
                "downloader.waitUntilRequestedBlocksAreDownloaded() is not expected to be called."
            )

            let acResult = nextContext.checkStateIs(.scan)
            XCTAssertTrue(acResult == .true, "Check of state failed with '\(acResult)'")
        } catch {
            XCTFail("testDownloadAction_NoDownloadAndScanRange is not expected to fail. \(error)")
        }
    }

    func testDownloadAction_DownloadStops() async throws {
        let blockDownloaderMock = BlockDownloaderMock()

        blockDownloaderMock.stopDownloadClosure = { }

        let downloadAction = setupAction(
            blockDownloaderMock
        )

        await downloadAction.stop()

        XCTAssertTrue(blockDownloaderMock.stopDownloadCalled, "downloader.stopDownload() is expected to be called.")
    }

    private func setupAction(
        _ blockDownloaderMock: BlockDownloaderMock = BlockDownloaderMock(),
        _ transactionRepositoryMock: TransactionRepositoryMock = TransactionRepositoryMock(),
        _ loggerMock: LoggerMock = LoggerMock()
    ) -> DownloadAction {
        mockContainer.mock(type: BlockDownloader.self, isSingleton: true) { _ in blockDownloaderMock }
        mockContainer.mock(type: TransactionRepository.self, isSingleton: true) { _ in transactionRepositoryMock }
        mockContainer.mock(type: Logger.self, isSingleton: true) { _ in loggerMock }

        loggerMock.debugFileFunctionLineClosure = { _, _, _, _ in }

        let config: CompactBlockProcessor.Configuration = .standard(
            for: ZcashNetworkBuilder.network(for: .testnet), walletBirthday: 0
        )

        return DownloadAction(
            container: mockContainer,
            configProvider: CompactBlockProcessor.ConfigProvider(config: config)
        )
    }
}
