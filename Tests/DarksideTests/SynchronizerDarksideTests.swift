//
//  SychronizerDarksideTests.swift
//  ZcashLightClientKit-Unit-Tests
//
//  Created by Francisco Gindre on 10/20/20.
//

import XCTest
import Combine
@testable import TestUtils
@testable import ZcashLightClientKit

class SynchronizerDarksideTests: ZcashTestCase {
    let sendAmount: Int64 = 1000
    let defaultLatestHeight: BlockHeight = 663175
    let branchID = "2bb40e60"
    let chainName = "main"
    let network = DarksideWalletDNetwork()

    var birthday: BlockHeight = 663150
    var coordinator: TestCoordinator!
    var syncedExpectation = XCTestExpectation(description: "synced")
    var sentTransactionExpectation = XCTestExpectation(description: "sent")
    var expectedReorgHeight: BlockHeight = 665188
    var expectedRewindHeight: BlockHeight = 665188
    var reorgExpectation = XCTestExpectation(description: "reorg")
    var foundTransactions: [ZcashTransaction.Overview] = []
    var cancellables: [AnyCancellable] = []
    var idGenerator: MockSyncSessionIDGenerator!

    override func setUp() async throws {
        try await super.setUp()

        mockContainer.mock(type: CheckpointSource.self, isSingleton: true) { _ in
            return DarksideMainnetCheckpointSource()
        }

        let idGenerator = MockSyncSessionIDGenerator(ids: [.deadbeef])
        mockContainer.mock(type: SyncSessionIDGenerator.self, isSingleton: false) { _ in idGenerator }
        self.idGenerator = idGenerator

        self.coordinator = try await TestCoordinator(
            container: mockContainer,
            walletBirthday: birthday,
            network: network
        )

        try await coordinator.reset(
            saplingActivation: 663150,
            startSaplingTreeSize: 128607,
            startOrchardTreeSize: 0,
            branchID: "e9ff75a6",
            chainName: "main"
        )
    }

    override func tearDown() async throws {
        try await super.tearDown()
        let coordinator = self.coordinator!
        self.coordinator = nil
        foundTransactions = []
        cancellables = []

        try await coordinator.stop()
        try? FileManager.default.removeItem(at: coordinator.databases.fsCacheDbRoot)
        try? FileManager.default.removeItem(at: coordinator.databases.dataDB)
    }

    func testFoundTransactions() async throws {
        coordinator.synchronizer.eventStream
            .map { event in
                guard case let .foundTransactions(transactions, _) = event else { return nil }
                return transactions
            }
            .compactMap { $0 }
            .sink(receiveValue: { [weak self] transactions in self?.handleFoundTransactions(transactions: transactions) })
            .store(in: &cancellables)

        try FakeChainBuilder.buildChain(darksideWallet: self.coordinator.service, branchID: branchID, chainName: chainName)
        let receivedTxHeight: BlockHeight = 663188

        try coordinator.applyStaged(blockheight: receivedTxHeight + 1)

        sleep(2)
        let preTxExpectation = XCTestExpectation(description: "pre receive")

        try await coordinator.sync(
            completion: { _ in
                preTxExpectation.fulfill()
            },
            error: self.handleError
        )

        await fulfillment(of: [preTxExpectation], timeout: 5)

        XCTAssertEqual(self.foundTransactions.count, 2)
    }

    func testFoundManyTransactions() async throws {
        self.idGenerator.ids = [.deadbeef, .beefbeef, .beefdead]
        coordinator.synchronizer.eventStream
            .map { event in
                guard case let .foundTransactions(transactions, _) = event else { return nil }
                return transactions
            }
            .compactMap { $0 }
            .sink(receiveValue: { [weak self] transactions in self?.handleFoundTransactions(transactions: transactions) })
            .store(in: &cancellables)

        try FakeChainBuilder.buildChain(darksideWallet: self.coordinator.service, branchID: branchID, chainName: chainName, length: 1000)
        let receivedTxHeight: BlockHeight = 663229

        try coordinator.applyStaged(blockheight: receivedTxHeight + 1)

        sleep(2)
        let firsTxExpectation = XCTestExpectation(description: "first sync")

        try await coordinator.sync(
            completion: { _ in
                firsTxExpectation.fulfill()
            },
            error: self.handleError
        )

        await fulfillment(of: [firsTxExpectation], timeout: 10)

        XCTAssertEqual(self.foundTransactions.count, 5)

        self.foundTransactions.removeAll()

        try coordinator.applyStaged(blockheight: 663900)
        sleep(2)

        let preTxExpectation = XCTestExpectation(description: "intermediate sync")

        try await coordinator.sync(
            completion: { _ in
                preTxExpectation.fulfill()
            },
            error: self.handleError
        )

        await fulfillment(of: [preTxExpectation], timeout: 10)

        XCTAssertTrue(self.foundTransactions.isEmpty)

        let findManyTxExpectation = XCTestExpectation(description: "final sync")

        try coordinator.applyStaged(blockheight: 664010)
        sleep(2)

        try await coordinator.sync(
            completion: { _ in
                findManyTxExpectation.fulfill()
            },
            error: self.handleError
        )

        await fulfillment(of: [findManyTxExpectation], timeout: 10)

        XCTAssertEqual(self.foundTransactions.count, 2)
    }

    func testLastStates() async throws {
        self.idGenerator.ids = [.deadbeef, .beefbeef, .beefdead]
        let uuids = self.idGenerator.ids

        var cancellables: [AnyCancellable] = []

        var states: [SynchronizerState] = []

        try FakeChainBuilder.buildChain(darksideWallet: self.coordinator.service, branchID: branchID, chainName: chainName)
        let receivedTxHeight: BlockHeight = 663188

        try coordinator.applyStaged(blockheight: receivedTxHeight + 1)

        sleep(2)
        let preTxExpectation = XCTestExpectation(description: "pre receive")

        coordinator.synchronizer.stateStream
            .sink { state in
                states.append(state)
            }
            .store(in: &cancellables)

        try await coordinator.sync(
            completion: { _ in
                preTxExpectation.fulfill()
            },
            error: self.handleError
        )

        await fulfillment(of: [preTxExpectation], timeout: 5)

        let expectedStates: [SynchronizerState] = [
            SynchronizerState(
                syncSessionID: .nullID,
                accountsBalances: [:],
                internalSyncStatus: .unprepared,
                latestBlockHeight: 0
            ),
            SynchronizerState(
                syncSessionID: uuids[0],
                accountsBalances: [:],
                internalSyncStatus: .syncing(0, false),
                latestBlockHeight: 0
            ),
            SynchronizerState(
                syncSessionID: uuids[0],
                accountsBalances: [:],
                internalSyncStatus: .syncing(0.9, false),
                latestBlockHeight: 663189
            ),
            SynchronizerState(
                syncSessionID: uuids[0],
                accountsBalances: [:],
                internalSyncStatus: .syncing(1.0, false),
                latestBlockHeight: 663189
            ),
            SynchronizerState(
                syncSessionID: uuids[0],
                accountsBalances: [:],
                internalSyncStatus: .synced,
                latestBlockHeight: 663189
            )
        ]

        XCTAssertEqual(states.count, expectedStates.count)

        for (index, state) in states.enumerated() {
            var expectedState = expectedStates[index]
            // `fullyScannedHeight` is not what this test exercises — it's checking the
            // sequence of (syncSessionID, internalSyncStatus, latestBlockHeight) tuples
            // emitted on `stateStream`. Scan-progress wiring is covered separately by
            // `SynchronizerOfflineTests.testSynchronizerStateEquatableDistinguishesFullyScannedHeight`
            // and the offline `SynchronizerState.zero` / init tests. Mask the field so
            // the structural comparison below stays focused on the transitions under test.
            expectedState.fullyScannedHeight = state.fullyScannedHeight
            XCTAssertEqual(state, expectedState, "Failed state comparison at index \(index).")
        }
    }

    func testSyncSessionUpdates() async throws {
        var cancellables: [AnyCancellable] = []

        self.idGenerator.ids = [.deadbeef, .beefbeef, .beefdead]
        let uuids = idGenerator.ids

        var states: [SynchronizerState] = []

        try FakeChainBuilder.buildChain(darksideWallet: self.coordinator.service, branchID: branchID, chainName: chainName)
        let receivedTxHeight: BlockHeight = 663188

        try coordinator.applyStaged(blockheight: receivedTxHeight + 1)

        sleep(2)
        let preTxExpectation = XCTestExpectation(description: "pre receive")

        coordinator.synchronizer.stateStream
            .sink { state in
                states.append(state)
            }
            .store(in: &cancellables)

        try await coordinator.sync(
            completion: { _ in
                preTxExpectation.fulfill()
            },
            error: self.handleError
        )

        await fulfillment(of: [preTxExpectation], timeout: 5)

        let expectedStates: [SynchronizerState] = [
            SynchronizerState(
                syncSessionID: .nullID,
                accountsBalances: [:],
                internalSyncStatus: .unprepared,
                latestBlockHeight: 0
            ),
            SynchronizerState(
                syncSessionID: uuids[0],
                accountsBalances: [:],
                internalSyncStatus: .syncing(0, false),
                latestBlockHeight: 0
            ),
            SynchronizerState(
                syncSessionID: uuids[0],
                accountsBalances: [:],
                internalSyncStatus: .syncing(0.9, false),
                latestBlockHeight: 663189
            ),
            SynchronizerState(
                syncSessionID: uuids[0],
                accountsBalances: [:],
                internalSyncStatus: .syncing(1.0, false),
                latestBlockHeight: 663189
            ),
            SynchronizerState(
                syncSessionID: uuids[0],
                accountsBalances: [:],
                internalSyncStatus: .synced,
                latestBlockHeight: 663189
            )
        ]

        XCTAssertEqual(states.count, expectedStates.count)

        for (index, state) in states.enumerated() {
            var expectedState = expectedStates[index]
            // See note in `testLastStates`: this test exercises sync-session + status
            // transitions, not scan-progress wiring; mask `fullyScannedHeight` to keep
            // the comparison focused.
            expectedState.fullyScannedHeight = state.fullyScannedHeight
            XCTAssertEqual(state, expectedState, "Failed state comparison at index \(index).")
        }

        try coordinator.service.applyStaged(nextLatestHeight: 663_200)

        sleep(2)

        states.removeAll()

        let secondSyncExpectation = XCTestExpectation(description: "second sync")

        try await coordinator.sync(
            completion: { _ in
                secondSyncExpectation.fulfill()
            },
            error: self.handleError
        )

        await fulfillment(of: [secondSyncExpectation], timeout: 5)

        let secondBatchOfExpectedStates: [SynchronizerState] = [
            SynchronizerState(
                syncSessionID: uuids[1],
                accountsBalances: [:],
                internalSyncStatus: .syncing(0, false),
                latestBlockHeight: 663189
            ),
            SynchronizerState(
                syncSessionID: uuids[1],
                accountsBalances: [:],
                internalSyncStatus: .syncing(0.9, false),
                latestBlockHeight: 663200
            ),
            SynchronizerState(
                syncSessionID: uuids[1],
                accountsBalances: [:],
                internalSyncStatus: .syncing(1.0, false),
                latestBlockHeight: 663200
            ),
            SynchronizerState(
                syncSessionID: uuids[1],
                accountsBalances: [:],
                internalSyncStatus: .synced,
                latestBlockHeight: 663200
            )
        ]

        XCTAssertEqual(states.count, secondBatchOfExpectedStates.count)

        for (index, state) in states.enumerated() {
            var expectedState = secondBatchOfExpectedStates[index]
            // See note above; `fullyScannedHeight` is intentionally out of scope for this test.
            expectedState.fullyScannedHeight = state.fullyScannedHeight
            XCTAssertEqual(state, expectedState, "Failed state comparison at index \(index).")
        }
    }

    func testSyncAfterWipeWorks() async throws {
        idGenerator.ids = [.deadbeef, .beefbeef, .beefdead]
        try FakeChainBuilder.buildChain(darksideWallet: self.coordinator.service, branchID: branchID, chainName: chainName)
        let receivedTxHeight: BlockHeight = 663188

        try coordinator.applyStaged(blockheight: receivedTxHeight + 1)

        sleep(2)

        let firsSyncExpectation = XCTestExpectation(description: "first sync")

        try await coordinator.sync(
            completion: { _ in
                firsSyncExpectation.fulfill()
            },
            error: self.handleError
        )

        await fulfillment(of: [firsSyncExpectation], timeout: 10)

        let wipeFinished = XCTestExpectation(description: "SynchronizerWipeFinished Expectation")

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

        _ = try await coordinator.prepare(seed: Environment.seedBytes)

        let secondSyncExpectation = XCTestExpectation(description: "second sync")

        try await coordinator.sync(
            completion: { _ in
                secondSyncExpectation.fulfill()
            },
            error: self.handleError
        )

        await fulfillment(of: [secondSyncExpectation], timeout: 10)
    }

    func handleFoundTransactions(transactions: [ZcashTransaction.Overview]) {
        self.foundTransactions.append(contentsOf: transactions)
    }

    func handleError(_ error: Error?) async {
        _ = try? await coordinator.stop()
        guard let testError = error else {
            XCTFail("failed with nil error")
            return
        }
        XCTFail("Failed with error: \(testError)")
    }
}

extension UUID {
    static let deadbeef = UUID(uuidString: "DEADBEEF-BEEF-FAFA-BEEF-FAFAFAFAFAFA")!
    static let beefbeef = UUID(uuidString: "BEEFBEEF-BEEF-DEAD-BEEF-BEEFEBEEFEBE")!
    static let beefdead = UUID(uuidString: "BEEFDEAD-BEEF-FAFA-DEAD-EAEAEAEAEAEA")!
}
