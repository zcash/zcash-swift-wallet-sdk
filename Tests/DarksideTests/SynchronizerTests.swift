//
//  SynchronizerTests.swift
//  DarksideTests
//
//  Created by Francisco Gindre on 9/16/22.
//

import Combine
import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class SynchronizerTests: ZcashTestCase {
    let sendAmount = Zatoshi(1000)
    var birthday: BlockHeight = 663150
    let defaultLatestHeight: BlockHeight = 663175
    var coordinator: TestCoordinator!
    var expectedReorgHeight: BlockHeight = 665188
    var expectedRewindHeight: BlockHeight = 665188
    var reorgExpectation = XCTestExpectation(description: "reorg")
    let branchID = "2bb40e60"
    let chainName = "main"
    let network = DarksideWalletDNetwork()
    var cancellables: [AnyCancellable] = []
    var sdkSynchronizerInternalSyncStatusHandler: SDKSynchronizerInternalSyncStatusHandler! = SDKSynchronizerInternalSyncStatusHandler()

    override func setUp() async throws {
        try await super.setUp()

        mockContainer.mock(type: CheckpointSource.self, isSingleton: true) { _ in
            return DarksideMainnetCheckpointSource()
        }

        // don't use an exact birthday, users never do.
        self.coordinator = try await TestCoordinator(
            container: mockContainer,
            walletBirthday: birthday + 50,
            network: network
        )

        try await coordinator.reset(
            saplingActivation: 663150,
            startSaplingTreeSize: 128607,
            startOrchardTreeSize: 0,
            branchID: self.branchID,
            chainName: self.chainName
        )

        let eventClosure: CompactBlockProcessor.EventClosure = { [weak self] event in
            switch event {
            case .handledReorg: self?.handleReorg(event: event)
            default: break
            }
        }

        await self.coordinator.synchronizer.blockProcessor.updateEventClosure(identifier: "tests", closure: eventClosure)
    }

    override func tearDown() async throws {
        try await super.tearDown()
        let coordinator = self.coordinator!
        self.coordinator = nil
        sdkSynchronizerInternalSyncStatusHandler = nil
        cancellables = []

        try await coordinator.stop()
        try? FileManager.default.removeItem(at: coordinator.databases.fsCacheDbRoot)
        try? FileManager.default.removeItem(at: coordinator.databases.dataDB)
    }

    func handleReorg(event: CompactBlockProcessor.Event) {
        guard case let .handledReorg(reorgHeight, rewindHeight) = event else { return XCTFail("empty reorg notification") }

        logger.debug("--- REORG DETECTED \(reorgHeight)--- RewindHeight: \(rewindHeight)", file: #file, function: #function, line: #line)

        XCTAssertEqual(reorgHeight, expectedReorgHeight)
        reorgExpectation.fulfill()
    }

    func testSynchronizerStops() async throws {
        /*
        1. create fake chain
        */
        let fullSyncLength = 100_000

        try FakeChainBuilder.buildChain(darksideWallet: coordinator.service, branchID: branchID, chainName: chainName, length: fullSyncLength)

        try coordinator.applyStaged(blockheight: birthday + fullSyncLength)

        sleep(10)

        let syncStoppedExpectation = XCTestExpectation(description: "SynchronizerStopped Expectation")
        sdkSynchronizerInternalSyncStatusHandler.subscribe(
            to: coordinator.synchronizer.stateStream,
            expectations: [.stopped: syncStoppedExpectation]
        )

        /*
        sync to latest height
        */
        try await coordinator.sync(
            completion: { _ in
                XCTFail("Sync should have stopped")
            },
            error: self.handleError
        )

        try await Task.sleep(nanoseconds: 5_000_000_000)
        self.coordinator.synchronizer.stop()

        await fulfillment(of: [syncStoppedExpectation], timeout: 6)

        let status = await coordinator.synchronizer.status
        XCTAssertEqual(status, .stopped)
    }

    // MARK: Wipe tests

    func testWipeCalledWhichSyncDoesntRun() async throws {
        /*
         create fake chain
         */
        let fullSyncLength = 1000

        try FakeChainBuilder.buildChain(darksideWallet: coordinator.service, branchID: branchID, chainName: chainName, length: fullSyncLength)

        try coordinator.applyStaged(blockheight: birthday + fullSyncLength)

        sleep(2)

        let syncFinished = XCTestExpectation(description: "SynchronizerSyncFinished Expectation")

        /*
         sync to latest height
         */
        try await coordinator.sync(
            completion: { _ in
                syncFinished.fulfill()
            },
            error: handleError
        )

        await fulfillment(of: [syncFinished], timeout: 3)

        let wipeFinished = XCTestExpectation(description: "SynchronizerWipeFinished Expectation")

        /*
         Call wipe
         */
        coordinator.synchronizer.wipe()
            .sink(
                receiveCompletion: { completion in
                    switch completion {
                    case .finished:
                        wipeFinished.fulfill()

                    case .failure(let error):
                        XCTFail("Wipe should finish successfully. \(error)")
                    }
                },
                receiveValue: {
                    XCTFail("No no value should be received from wipe.")
                }
            )
            .store(in: &cancellables)

        await fulfillment(of: [wipeFinished], timeout: 1)

        /*
         Check that wipe cleared everything that is expected
         */
        try await checkThatWipeWorked()
    }

    func testWipeCalledWhileSyncRuns() async throws {
        /*
         1. create fake chain
         */
        let fullSyncLength = 50_000

        try FakeChainBuilder.buildChain(darksideWallet: coordinator.service, branchID: branchID, chainName: chainName, length: fullSyncLength)

        try coordinator.applyStaged(blockheight: birthday + fullSyncLength)

        sleep(5)

        /*
         Start sync
         */
        try await coordinator.sync(
            completion: { _ in
                XCTFail("Sync should have stopped")
            },
            error: self.handleError
        )

        try await Task.sleep(nanoseconds: 2_000_000_000)

        // Just to be sure that blockProcessor is still syncing and that this test does what it should.
        let synchronizerState = coordinator.synchronizer.latestState.syncStatus
        switch synchronizerState {
        case .syncing:
            break
        default:
            XCTFail("Synchornizer should be in syncing state.")
        }

        let wipeFinished = XCTestExpectation(description: "SynchronizerWipeFinished Expectation")
        /*
         Call wipe
         */
        coordinator.synchronizer.wipe()
            .sink(
                receiveCompletion: { completion in
                    switch completion {
                    case .finished:
                        wipeFinished.fulfill()

                    case .failure(let error):
                        XCTFail("Wipe should finish successfully. \(error)")
                    }
                },
                receiveValue: {
                    XCTFail("No no value should be received from wipe.")
                }
            )
            .store(in: &cancellables)

        await fulfillment(of: [wipeFinished], timeout: 6)

        /*
         Check that wipe cleared everything that is expected
         */
        try await checkThatWipeWorked()
    }

    private func checkThatWipeWorked() async throws {
        let storage = await self.coordinator.synchronizer.blockProcessor.storage as! FSCompactBlockRepository
        let fm = FileManager.default

        XCTAssertFalse(fm.fileExists(atPath: coordinator.synchronizer.initializer.dataDbURL.path), "Data DB should be deleted.")
        XCTAssertTrue(fm.fileExists(atPath: storage.blocksDirectory.path), "FS Cache directory should exist")
        XCTAssertEqual(try fm.contentsOfDirectory(atPath: storage.blocksDirectory.path), [], "FS Cache directory should be empty")

        let status = await coordinator.synchronizer.status
        XCTAssertEqual(status, .unprepared, "SDKSynchronizer state should be unprepared")
    }

    func handleError(_ error: Error?) async {
        _ = try? await coordinator.stop()
        guard let testError = error else {
            XCTFail("failed with nil error")
            return
        }
        XCTFail("Failed with error: \(testError)")
    }

    // MARK: Rewind tests

    func testRewindCalledWhileSyncRuns() async throws {
        // 1 sync and get spendable funds
        try FakeChainBuilder.buildChain(darksideWallet: coordinator.service, branchID: branchID, chainName: chainName)

        try coordinator.applyStaged(blockheight: 663200)
        let accountUUID = TestsData.mockedAccountUUID
        let spendableValue = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.saplingBalance.spendableValue
        let initialVerifiedBalance: Zatoshi = spendableValue ?? .zero
        let initialTotalBalance: Zatoshi = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.saplingBalance.total() ?? .zero
        sleep(1)
        let firstSyncExpectation = XCTestExpectation(description: "first sync expectation")

        do {
            try await coordinator.sync(
                completion: { _ in
                    firstSyncExpectation.fulfill()
                },
                error: self.handleError
            )
        } catch {
            await handleError(error)
        }

        await fulfillment(of: [firstSyncExpectation], timeout: 12)

        let verifiedBalance: Zatoshi = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.saplingBalance.spendableValue ?? .zero
        let totalBalance: Zatoshi = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.saplingBalance.total() ?? .zero
        // 2 check that there are no unconfirmed funds
        XCTAssertTrue(verifiedBalance > network.constants.defaultFee())
        XCTAssertEqual(verifiedBalance, totalBalance)

        // Add more blocks to the chain so the long sync can start.
        try FakeChainBuilder.buildChain(darksideWallet: coordinator.service, branchID: branchID, chainName: chainName, length: 10000)
        try coordinator.applyStaged(blockheight: birthday + 10000)

        sleep(2)

        do {
            // Start the long sync.
            try await coordinator.sync(
                completion: { _ in },
                error: self.handleError
            )
        } catch {
            await handleError(error)
        }

        // Wait 0.5 second and then start rewind while sync is in progress.
        let waitExpectation = XCTestExpectation()
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.5) {
            waitExpectation.fulfill()
        }

        await fulfillment(of: [waitExpectation], timeout: 1)

        let rewindExpectation = XCTestExpectation(description: "RewindExpectation")

        // rewind to birthday
        coordinator.synchronizer.rewind(.birthday)
            .sink(
                receiveCompletion: { result in
                    switch result {
                    case .finished:
                        break
                    case let .failure(error):
                        XCTFail("Rewind failed with error: \(error)")
                    }
                    rewindExpectation.fulfill()
                },
                receiveValue: { _ in  rewindExpectation.fulfill() }
            )
            .store(in: &cancellables)

        await fulfillment(of: [rewindExpectation], timeout: 5)

        // assert that after the new height is
        // TODO: [#1247] needs to review this to properly solve, https://github.com/zcash/ZcashLightClientKit/issues/1247
//        let lastScannedHeight = try await coordinator.synchronizer.initializer.transactionRepository.lastScannedHeight()
//        XCTAssertEqual(lastScannedHeight, self.birthday)

        // check that the balance is cleared
        let expectedVerifiedBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.saplingBalance.spendableValue ?? .zero
        let expectedBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.saplingBalance.total() ?? .zero
        XCTAssertEqual(initialVerifiedBalance, expectedVerifiedBalance)
        XCTAssertEqual(initialTotalBalance, expectedBalance)
    }
}
