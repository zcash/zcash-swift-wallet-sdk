//
//  RewindActionTests.swift
//
//
//  Created by Lukáš Korba on 25.08.2023.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class RewindActionTests: ZcashTestCase {
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

    func testRewindAction_requestedRewindHeightNil() async throws {
        let blockDownloaderMock = BlockDownloaderMock()

        let rewindActionAction = await setupAction(blockDownloaderMock)

        do {
            let context = ActionContextMock.default()

            let nextContext = try await rewindActionAction.run(with: context) { _ in }

            XCTAssertFalse(
                blockDownloaderMock.rewindLatestDownloadedBlockHeightCalled,
                "downloader.rewind(latestDownloadedBlockHeight:) is not expected to be called."
            )

            let acResult = nextContext.checkStateIs(.processSuggestedScanRanges)
            XCTAssertTrue(acResult == .true, "Check of state failed with '\(acResult)'")
        } catch {
            XCTFail("testRewindAction_requestedRewindHeightNil is not expected to fail. \(error)")
        }
    }

    func testRewindAction_FullPass() async throws {
        let blockDownloaderMock = BlockDownloaderMock()
        let loggerMock = LoggerMock()
        let blockDownloaderServiceMock = BlockDownloaderServiceMock()

        loggerMock.debugFileFunctionLineClosure = { _, _, _, _ in }
        blockDownloaderMock.rewindLatestDownloadedBlockHeightClosure = { _ in }
        blockDownloaderServiceMock.rewindToClosure = { _ in }

        let rewindActionAction = await setupAction(
            blockDownloaderMock,
            loggerMock,
            blockDownloaderServiceMock
        )

        do {
            let context = ActionContextMock.default()
            context.requestedRewindHeight = 1

            let nextContext = try await rewindActionAction.run(with: context) { _ in }

            XCTAssertTrue(
                blockDownloaderMock.rewindLatestDownloadedBlockHeightCallsCount == 1,
                "downloader.rewind(latestDownloadedBlockHeight:) is expected to be called."
            )
            XCTAssertTrue(
                loggerMock.debugFileFunctionLineCallsCount == 1,
                "logger.debug() is expected to be called."
            )
            XCTAssertTrue(
                blockDownloaderServiceMock.rewindToCallsCount == 1,
                "downloaderService.rewind(to:) is expected to be called."
            )

            let acResult = nextContext.checkStateIs(.processSuggestedScanRanges)
            XCTAssertTrue(acResult == .true, "Check of state failed with '\(acResult)'")
        } catch {
            XCTFail("testRewindAction_FullPass is not expected to fail. \(error)")
        }
    }

    private func setupAction(
        _ blockDownloaderMock: BlockDownloaderMock = BlockDownloaderMock(),
        _ loggerMock: LoggerMock = LoggerMock(),
        _ blockDownloaderServiceMock: BlockDownloaderServiceMock = BlockDownloaderServiceMock()
    ) async -> RewindAction {
        let rustBackendMock = ZcashRustBackendWeldingMock()

        rustBackendMock.consensusBranchIdForHeightClosure = { height in
            XCTAssertEqual(height, 2, "")
            return -1026109260
        }

        rustBackendMock.rewindToHeightHeightClosure = { height in
            return RewindResult.success(height)
        }

        mockContainer.mock(type: ZcashRustBackendWelding.self, isSingleton: true) { _ in rustBackendMock }
        mockContainer.mock(type: BlockDownloaderService.self, isSingleton: true) { _ in blockDownloaderServiceMock }
        mockContainer.mock(type: BlockDownloader.self, isSingleton: true) { _ in blockDownloaderMock }
        mockContainer.mock(type: Logger.self, isSingleton: true) { _ in loggerMock }

        return RewindAction(container: mockContainer)
    }
}
