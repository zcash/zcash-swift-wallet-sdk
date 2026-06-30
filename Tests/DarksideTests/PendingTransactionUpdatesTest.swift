//
//  PendingTransactionUpdatesTest.swift
//  ZcashLightClientKit-Unit-Tests
//
//  Created by Francisco Gindre on 7/17/20.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

class PendingTransactionUpdatesTest: ZcashTestCase {
    let sendAmount: Int64 = 1000
    var birthday: BlockHeight = 663150
    let defaultLatestHeight: BlockHeight = 663175
    var coordinator: TestCoordinator!
    var syncedExpectation = XCTestExpectation(description: "synced")
    var sentTransactionExpectation = XCTestExpectation(description: "sent")
    var expectedReorgHeight: BlockHeight = 665188
    var expectedRewindHeight: BlockHeight = 665188
    let branchID = "2bb40e60"
    let chainName = "main"
    let network = DarksideWalletDNetwork()

    override func setUp() async throws {
        try await super.setUp()

        mockContainer.mock(type: CheckpointSource.self, isSingleton: true) { _ in
            return DarksideMainnetCheckpointSource()
        }

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

        try await coordinator.stop()
        try? FileManager.default.removeItem(at: coordinator.databases.fsCacheDbRoot)
        try? FileManager.default.removeItem(at: coordinator.databases.dataDB)
    }

    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testPendingTransactionMinedHeightUpdated() async throws {
        /*
        1. create fake chain
        */
        LoggerProxy.info("1. create fake chain")

        try FakeChainBuilder.buildChain(darksideWallet: coordinator.service, branchID: branchID, chainName: chainName)

        try coordinator.applyStaged(blockheight: 663188)
        sleep(2)

        let firstSyncExpectation = XCTestExpectation(description: "first sync")

        /*
        1a. sync to latest height
        */
        LoggerProxy.info("1a. sync to latest height")
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
        await fulfillment(of: [firstSyncExpectation], timeout: 5)

        sleep(1)

        let sendExpectation = XCTestExpectation(description: "send expectation")
        var pendingEntity: ZcashTransaction.Overview?

        /*
        2. send transaction to recipient address
        */
        LoggerProxy.info("2. send transaction to recipient address")
        do {
//            let pendingTx = try await coordinator.synchronizer.sendToAddress(
//                spendingKey: self.coordinator.spendingKey,
//                zatoshi: Zatoshi(20000),
//                toAddress: try Recipient(Environment.testRecipientAddress, network: self.network.networkType),
//                memo: try Memo(string: "this is a test")
//            )
//            pendingEntity = pendingTx
            sendExpectation.fulfill()
        } catch {
            await self.handleError(error)
        }

        await fulfillment(of: [sendExpectation], timeout: 11)

        guard let pendingUnconfirmedTx = pendingEntity else {
            XCTFail("no pending transaction after sending")
            try await coordinator.stop()
            return
        }

        XCTAssertTrue(
            pendingUnconfirmedTx.isPending(currentHeight: 633188),
            "pending transaction evaluated as confirmed when it shouldn't"
        )
        XCTAssertNil(
            pendingUnconfirmedTx.minedHeight,
            "pending transaction evaluated as mined when it shouldn't"
        )

        XCTAssertTrue(
            pendingUnconfirmedTx.isPending(currentHeight: 663188),
            "pending transaction evaluated as not pending when it should be"
        )

        /**
        3. getIncomingTransaction
        */
        LoggerProxy.info("3. getIncomingTransaction")
        guard let incomingTx = try coordinator.getIncomingTransactions()?.first else {
            XCTFail("no incoming transaction")
            try await coordinator.stop()
            return
        }

        let sentTxHeight: BlockHeight = 663189

        /*
        4. stage transaction at sentTxHeight
        */
        LoggerProxy.info("4. stage transaction at \(sentTxHeight)")
        try coordinator.stageBlockCreate(height: sentTxHeight)

        try coordinator.stageTransaction(incomingTx, at: sentTxHeight)

        /*
        5. applyHeight(sentTxHeight)
        */
        LoggerProxy.info("5. applyHeight(\(sentTxHeight))")
        try coordinator.applyStaged(blockheight: sentTxHeight)

        sleep(2)

        /*
        6. sync to latest height
        */
        LoggerProxy.info("6. sync to latest height")
        let secondSyncExpectation = XCTestExpectation(description: "after send expectation")

        do {
            try await coordinator.sync(
                completion: { _ in
                    secondSyncExpectation.fulfill()
                },
                error: self.handleError
            )
        } catch {
            await handleError(error)
        }

        await fulfillment(of: [secondSyncExpectation], timeout: 5)

        // TODO: [#1247] needs to review this to properly solve, https://github.com/zcash/ZcashLightClientKit/issues/1247
//        let pendingTransactionsCount = await coordinator.synchronizer.pendingTransactions.count
//        XCTAssertEqual(pendingTransactionsCount, 1)
//        guard let afterStagePendingTx = await coordinator.synchronizer.pendingTransactions.first else {
//            return
//        }
//
//        /*
//        6a. verify that there's a pending transaction with a mined height of sentTxHeight
//        */
//        LoggerProxy.info("6a. verify that there's a pending transaction with a mined height of \(sentTxHeight)")
//        XCTAssertEqual(afterStagePendingTx.minedHeight, sentTxHeight)
//        XCTAssertNotNil(afterStagePendingTx.minedHeight, "pending transaction shown as unmined when it has been mined")
//        XCTAssertTrue(afterStagePendingTx.isPending(currentHeight: sentTxHeight))

        /*
        7. stage 15  blocks from sentTxHeight
        */
        LoggerProxy.info("7. stage 15  blocks from \(sentTxHeight)")
        try coordinator.stageBlockCreate(height: sentTxHeight + 1, count: 15)
        sleep(2)
        let lastStageHeight = sentTxHeight + 14
        LoggerProxy.info("applyStaged(\(lastStageHeight))")
        try coordinator.applyStaged(blockheight: lastStageHeight)

        sleep(2)
        let syncToConfirmExpectation = XCTestExpectation(description: "sync to confirm expectation")

        /*
        8. last sync to latest height
        */
        LoggerProxy.info("last sync to latest height: \(lastStageHeight)")

        do {
            try await coordinator.sync(
                completion: { _ in
                    syncToConfirmExpectation.fulfill()
                },
                error: self.handleError
            )
        } catch {
            await handleError(error)
        }

        // TODO: [#1247] needs to review this to properly solve, https://github.com/zcash/ZcashLightClientKit/issues/1247
//        await fulfillment(of: [syncToConfirmExpectation], timeout: 6)
//        let supposedlyPendingUnexistingTransaction = try await coordinator.synchronizer.allPendingTransactions().first
//
//        let clearedTransactions = await coordinator.synchronizer
//            .transactions
//
//        let clearedTransaction = clearedTransactions.first(where: { $0.rawID == afterStagePendingTx.rawID })
//
//        XCTAssertEqual(clearedTransaction!.value.amount, afterStagePendingTx.value.amount)
//        XCTAssertNil(supposedlyPendingUnexistingTransaction)
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
