//
//  ReOrgTests.swift
//  ZcashLightClientKit-Unit-Tests
//
//  Created by Francisco Gindre on 3/23/20.
//

import Combine
import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

/**
basic reorg test.  Scan, get a reorg and then reach latest height.

* connect to dLWD
* request latest height -> receive 663250
* download and sync blocks from 663150 to 663250
* trigger reorg by calling API (no need to pass params)**
* request latest height -> receive 663251!
* download that block
* observe that the prev hash of that block does not match the hash that we have for 663250
* rewind 10 blocks and request blocks 663241 to 663251
*/
class ReOrgTests: ZcashTestCase {
    let sendAmount: Int64 = 1000
    let defaultLatestHeight: BlockHeight = 663175
    let network = DarksideWalletDNetwork()
    let branchID = "2bb40e60"
    let chainName = "main"
    let mockLatestHeight = BlockHeight(663250)
    let targetLatestHeight = BlockHeight(663251)
    let walletBirthday = BlockHeight(663150)

    var birthday: BlockHeight = 663150
    var reorgExpectation = XCTestExpectation(description: "reorg")
    var coordinator: TestCoordinator!
    var syncedExpectation = XCTestExpectation(description: "synced")
    var sentTransactionExpectation = XCTestExpectation(description: "sent")
    var expectedReorgHeight: BlockHeight = 665188
    var expectedRewindHeight: BlockHeight = 665188
    var cancellables: [AnyCancellable] = []

    override func setUp() async throws {
        try await super.setUp()

        mockContainer.mock(type: CheckpointSource.self, isSingleton: true) { _ in
            return DarksideMainnetCheckpointSource()
        }

        self.coordinator = try await TestCoordinator(
            container: mockContainer,
            walletBirthday: self.birthday,
            network: self.network
        )

        try await coordinator.reset(
            saplingActivation: self.birthday,
            startSaplingTreeSize: 128607,
            startOrchardTreeSize: 0,
            branchID: self.branchID,
            chainName: self.chainName
        )

        try self.coordinator.resetBlocks(dataset: .default)

        let eventClosure: CompactBlockProcessor.EventClosure = { [weak self] event in
            switch event {
            case .handledReorg: self?.handleReOrgNotification(event: event)
            default: break
            }
        }

        await self.coordinator.synchronizer.blockProcessor.updateEventClosure(identifier: "tests", closure: eventClosure)
    }

    override func tearDown() async throws {
        try await super.tearDown()
        let coordinator = self.coordinator!
        self.coordinator = nil
        cancellables = []

        try await coordinator.stop()
        try? FileManager.default.removeItem(at: coordinator.databases.fsCacheDbRoot)
        try? FileManager.default.removeItem(at: coordinator.databases.dataDB)
    }

    func handleReOrgNotification(event: CompactBlockProcessor.Event) {
        reorgExpectation.fulfill()

        guard case let .handledReorg(reorgHeight, rewindHeight) = event else { return XCTFail("malformed reorg userInfo") }

        print("reorgHeight: \(reorgHeight)")
        print("rewindHeight: \(rewindHeight)")

        XCTAssertTrue(reorgHeight > 0)
        XCTAssertNoThrow(rewindHeight > 0)
    }

    func testBasicReOrg() async throws {
        let mockLatestHeight = BlockHeight(663200)
        let targetLatestHeight = BlockHeight(663202)
        let reOrgHeight = BlockHeight(663195)
        let checkpointSource = CheckpointSourceFactory.fromBundle(for: network.networkType)
        let walletBirthday = checkpointSource.birthday(for: 663150).height

        try await basicReOrgTest(
            baseDataset: .beforeReOrg,
            reorgDataset: .afterSmallReorg,
            firstLatestHeight: mockLatestHeight,
            reorgHeight: reOrgHeight,
            walletBirthday: walletBirthday,
            targetHeight: targetLatestHeight
        )
    }

    func testTenPlusBlockReOrg() async throws {
        let mockLatestHeight = BlockHeight(663200)
        let targetLatestHeight = BlockHeight(663250)
        let reOrgHeight = BlockHeight(663180)
        let checkpointSource = CheckpointSourceFactory.fromBundle(for: network.networkType)
        let walletBirthday = checkpointSource.birthday(for: 663150).height

        try await basicReOrgTest(
            baseDataset: .beforeReOrg,
            reorgDataset: .afterLargeReorg,
            firstLatestHeight: mockLatestHeight,
            reorgHeight: reOrgHeight,
            walletBirthday: walletBirthday,
            targetHeight: targetLatestHeight
        )
    }

    func basicReOrgTest(
        baseDataset: DarksideDataset,
        reorgDataset: DarksideDataset,
        firstLatestHeight: BlockHeight,
        reorgHeight: BlockHeight,
        walletBirthday: BlockHeight,
        targetHeight: BlockHeight
    ) async throws {
        do {
            try await coordinator.reset(
                saplingActivation: birthday,
                startSaplingTreeSize: 128607,
                startOrchardTreeSize: 0,
                branchID: branchID,
                chainName: chainName
            )

            try coordinator.resetBlocks(dataset: .predefined(dataset: .beforeReOrg))
            try coordinator.applyStaged(blockheight: firstLatestHeight)
            sleep(1)
        } catch {
            XCTFail("Error: \(error)")
            return
        }

        let firstSyncExpectation = XCTestExpectation(description: "firstSyncExpectation")

        /**
        download and sync blocks from walletBirthday to firstLatestHeight
        */
        var synchronizer: SDKSynchronizer?
        try await coordinator.sync(
            completion: { synchro in
                synchronizer = synchro
                firstSyncExpectation.fulfill()
            },
            error: self.handleError
        )

        await fulfillment(of: [firstSyncExpectation], timeout: 5)

        guard let syncedSynchronizer = synchronizer else {
            XCTFail("nil synchronizer")
            return
        }

        /**
        verify that mock height has been reached
        */
        var latestDownloadedHeight = BlockHeight(0)
        do {
            latestDownloadedHeight = try await syncedSynchronizer.initializer.blockDownloaderService.latestBlockHeight(mode: .direct)
            XCTAssertTrue(latestDownloadedHeight > 0)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        /**
        trigger reorg!
        */
        try coordinator.resetBlocks(dataset: .predefined(dataset: reorgDataset))
        try coordinator.applyStaged(blockheight: targetHeight)

        /**
        request latest height -> receive targetHeight!
        download that block
        observe that the prev hash of that block does not match the hash that we have for firstLatestHeight
        rewind 10 blocks and request blocks targetHeight-10 to targetHeight
        */
        let secondSyncExpectation = XCTestExpectation(description: "second sync")

        sleep(2)
        try await coordinator.sync(
            completion: { _ in
                secondSyncExpectation.fulfill()
            },
            error: self.handleError
        )

        // now reorg should happen and reorg notifications and idle notification should be triggered

        await fulfillment(of: [reorgExpectation, secondSyncExpectation], timeout: 5)

        // now everything should be fine. latest block should be targetHeight

        do {
            latestDownloadedHeight = try await syncedSynchronizer.initializer.blockDownloaderService.latestBlockHeight(mode: .direct)
            XCTAssertEqual(latestDownloadedHeight, targetHeight)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func handleError(_ error: Error?) {
        guard let testError = error else {
            XCTFail("failed with nil error")
            return
        }
        XCTFail("Failed with error: \(testError)")
    }
}
