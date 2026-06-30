//
//  XCTRewindRescanTests.swift
//  ZcashLightClientKit-Unit-Tests
//
//  Created by Francisco Gindre on 3/25/21.
//

import Combine
import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

// FIXME: [#586] disabled until this is resolved https://github.com/zcash/ZcashLightClientKit/issues/586
class RewindRescanTests: ZcashTestCase {
    let sendAmount: Int64 = 1000
    let defaultLatestHeight: BlockHeight = 663175
    let branchID = "2bb40e60"
    let chainName = "main"

    var cancellables: [AnyCancellable] = []
    var birthday: BlockHeight = 663150
    var coordinator: TestCoordinator!
    var syncedExpectation = XCTestExpectation(description: "synced")
    var sentTransactionExpectation = XCTestExpectation(description: "sent")
    var expectedReorgHeight: BlockHeight = 665188
    var expectedRewindHeight: BlockHeight = 665188
    var reorgExpectation = XCTestExpectation(description: "reorg")
    var network = ZcashNetworkBuilder.network(for: .mainnet)

    override func setUp() async throws {
        try await super.setUp()

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
        cancellables = []

        try await coordinator.stop()
        try? FileManager.default.removeItem(at: coordinator.databases.fsCacheDbRoot)
        try? FileManager.default.removeItem(at: coordinator.databases.dataDB)
    }

    func handleError(_ error: Error?) {
        guard let testError = error else {
            XCTFail("failed with nil error")
            return
        }

        XCTFail("Failed with error: \(testError)")
    }

    func testBirthdayRescan() async throws {
        // 1 sync and get spendable funds
        try FakeChainBuilder.buildChain(darksideWallet: coordinator.service, branchID: branchID, chainName: chainName)

        let accountUUID = TestsData.mockedAccountUUID
        try coordinator.applyStaged(blockheight: defaultLatestHeight + 50)
        var accountBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]
        let initialVerifiedBalance: Zatoshi = accountBalance?.saplingBalance.spendableValue ?? .zero
        let initialTotalBalance: Zatoshi = accountBalance?.saplingBalance.total() ?? .zero
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
            handleError(error)
        }

        await fulfillment(of: [firstSyncExpectation], timeout: 12)
        accountBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]
        let verifiedBalance: Zatoshi = accountBalance?.saplingBalance.spendableValue ?? .zero
        let totalBalance: Zatoshi = accountBalance?.saplingBalance.total() ?? .zero
        // 2 check that there are no unconfirmed funds
        XCTAssertTrue(verifiedBalance > network.constants.defaultFee())
        XCTAssertEqual(verifiedBalance, totalBalance)

        let rewindExpectation = XCTestExpectation(description: "RewindExpectation")

        try await withCheckedThrowingContinuation { continuation in
            // rewind to birthday
            coordinator.synchronizer.rewind(.birthday)
                .sink(
                    receiveCompletion: { result in
                        rewindExpectation.fulfill()
                        switch result {
                        case .finished:
                            continuation.resume()

                        case let .failure(error):
                            XCTFail("Rewind failed with error: \(error)")
                            continuation.resume(with: .failure(error))
                        }
                    },
                    receiveValue: { _ in }
                )
                .store(in: &cancellables)
        }

        await fulfillment(of: [rewindExpectation], timeout: 2)

        // assert that after the new height is
        // TODO: [#1247] needs to review this to properly solve, https://github.com/zcash/ZcashLightClientKit/issues/1247
//        let lastScannedHeight = try await coordinator.synchronizer.initializer.transactionRepository.lastScannedHeight()
//        XCTAssertEqual(lastScannedHeight, self.birthday)

        // check that the balance is cleared
        accountBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]
        var expectedVerifiedBalance = accountBalance?.saplingBalance.spendableValue ?? .zero
        var expectedBalance = accountBalance?.saplingBalance.total() ?? .zero
        XCTAssertEqual(initialVerifiedBalance, expectedVerifiedBalance)
        XCTAssertEqual(initialTotalBalance, expectedBalance)
        let secondScanExpectation = XCTestExpectation(description: "rescan")

        do {
            try await coordinator.sync(
                completion: { _ in
                    secondScanExpectation.fulfill()
                },
                error: self.handleError
            )
        } catch {
            handleError(error)
        }

        await fulfillment(of: [secondScanExpectation], timeout: 12)

        // verify that the balance still adds up
        accountBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]
        expectedVerifiedBalance = accountBalance?.saplingBalance.spendableValue ?? .zero
        expectedBalance = accountBalance?.saplingBalance.total() ?? .zero
        XCTAssertEqual(verifiedBalance, expectedVerifiedBalance)
        XCTAssertEqual(totalBalance, expectedBalance)
    }

    // FIXME [#789]: Fix test
    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testRescanToHeight() async throws {
        // 1 sync and get spendable funds
        try FakeChainBuilder.buildChainWithTxsFarFromEachOther(
            darksideWallet: coordinator.service,
            branchID: branchID,
            chainName: chainName,
            length: 10000
        )

        let accountUUID = TestsData.mockedAccountUUID
        let newChaintTip = defaultLatestHeight + 10000
        try coordinator.applyStaged(blockheight: newChaintTip)
        sleep(3)
        let spendableValue = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.saplingBalance.spendableValue
        let initialVerifiedBalance: Zatoshi = spendableValue ?? .zero
        let firstSyncExpectation = XCTestExpectation(description: "first sync expectation")

        do {
            try await coordinator.sync(
                completion: { _ in
                    firstSyncExpectation.fulfill()
                },
                error: self.handleError
            )
        } catch {
            handleError(error)
        }

        await fulfillment(of: [firstSyncExpectation], timeout: 20)
        var accountBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]
        let verifiedBalance: Zatoshi = accountBalance?.saplingBalance.spendableValue ?? .zero
        let totalBalance: Zatoshi = accountBalance?.saplingBalance.total() ?? .zero
        // 2 check that there are no unconfirmed funds
        XCTAssertTrue(verifiedBalance > network.constants.defaultFee())
        XCTAssertEqual(verifiedBalance, totalBalance)

        // rewind to birthday
        let targetHeight: BlockHeight = newChaintTip - 8000

        let rewindExpectation = XCTestExpectation(description: "RewindExpectation")

        try await withCheckedThrowingContinuation { continuation in
            coordinator.synchronizer.rewind(.height(blockheight: targetHeight))
                .sink(
                    receiveCompletion: { result in
                        rewindExpectation.fulfill()
                        switch result {
                        case .finished:
                            continuation.resume()

                        case let .failure(error):
                            XCTFail("Rewind failed with error: \(error)")
                            continuation.resume(with: .failure(error))
                        }
                    },
                    receiveValue: { _ in }
                )
                .store(in: &cancellables)
        }

        await fulfillment(of: [rewindExpectation], timeout: 2)

        // check that the balance is cleared
        var expectedVerifiedBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.saplingBalance.spendableValue ?? .zero
        XCTAssertEqual(initialVerifiedBalance, expectedVerifiedBalance)

        let secondScanExpectation = XCTestExpectation(description: "rescan")

        do {
            try await coordinator.sync(
                completion: { _ in
                    secondScanExpectation.fulfill()
                },
                error: self.handleError
            )
        } catch {
            handleError(error)
        }

        await fulfillment(of: [secondScanExpectation], timeout: 20)

        // verify that the balance still adds up
        accountBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]
        expectedVerifiedBalance = accountBalance?.saplingBalance.spendableValue ?? .zero
        let expectedBalance = accountBalance?.saplingBalance.total() ?? .zero
        XCTAssertEqual(verifiedBalance, expectedVerifiedBalance)
        XCTAssertEqual(totalBalance, expectedBalance)

        // try to spend the funds
        let sendExpectation = XCTestExpectation(description: "after rewind expectation")
        do {
//            let pendingTx = try await coordinator.synchronizer.sendToAddress(
//                spendingKey: coordinator.spendingKey,
//                zatoshi: Zatoshi(1000),
//                toAddress: try! Recipient(Environment.testRecipientAddress, network: .mainnet),
//                memo: .empty
//            )
//            XCTAssertEqual(Zatoshi(1000), pendingTx.value)
            sendExpectation.fulfill()
        } catch {
            XCTFail("sending fail: \(error)")
        }
        await fulfillment(of: [sendExpectation], timeout: 15)
    }

    func testRescanToTransaction() async throws {
        // 1 sync and get spendable funds
        try FakeChainBuilder.buildChain(darksideWallet: coordinator.service, branchID: branchID, chainName: chainName)

        try coordinator.applyStaged(blockheight: defaultLatestHeight + 50)

        sleep(1)
        let firstSyncExpectation = XCTestExpectation(description: "first sync expectation")

        try await coordinator.sync(
            completion: { _ in
                firstSyncExpectation.fulfill()
            },
            error: handleError
        )

        await fulfillment(of: [firstSyncExpectation], timeout: 12)
        let accountUUID = TestsData.mockedAccountUUID
        var accountBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]
        let verifiedBalance: Zatoshi = accountBalance?.saplingBalance.spendableValue ?? .zero
        let totalBalance: Zatoshi = accountBalance?.saplingBalance.total() ?? .zero
        // 2 check that there are no unconfirmed funds
        XCTAssertTrue(verifiedBalance > network.constants.defaultFee())
        XCTAssertEqual(verifiedBalance, totalBalance)

        // rewind to transaction
        guard let transaction = try await coordinator.synchronizer.allTransactions().first else {
            XCTFail("failed to get a transaction to rewind to")
            return
        }

        let rewindExpectation = XCTestExpectation(description: "RewindExpectation")

        try await withCheckedThrowingContinuation { continuation in
            coordinator.synchronizer.rewind(.transaction(transaction))
                .sink(
                    receiveCompletion: { result in
                        rewindExpectation.fulfill()
                        switch result {
                        case .finished:
                            continuation.resume()

                        case let .failure(error):
                            XCTFail("Rewind failed with error: \(error)")
                            continuation.resume(with: .failure(error))
                        }
                    },
                    receiveValue: { _ in }
                )
                .store(in: &cancellables)
        }

        await fulfillment(of: [rewindExpectation], timeout: 2)

        // assert that after the new height is lower or same as transaction, rewind doesn't have to be make exactly to transaction height, it can
        // be done to nearest height provided by rust
        // TODO: [#1247] needs to review this to properly solve, https://github.com/zcash/ZcashLightClientKit/issues/1247
//        let lastScannedHeight = try await coordinator.synchronizer.initializer.transactionRepository.lastScannedHeight()
//        XCTAssertLessThanOrEqual(lastScannedHeight, transaction.anchor(network: network) ?? -1)

        let secondScanExpectation = XCTestExpectation(description: "rescan")

        try await coordinator.sync(
            completion: { _ in
                secondScanExpectation.fulfill()
            },
            error: handleError
        )

        await fulfillment(of: [secondScanExpectation], timeout: 12)

        // verify that the balance still adds up
        accountBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]
        let expectedVerifiedBalance = accountBalance?.saplingBalance.spendableValue ?? .zero
        let expectedBalance = accountBalance?.saplingBalance.total() ?? .zero
        XCTAssertEqual(verifiedBalance, expectedVerifiedBalance)
        XCTAssertEqual(totalBalance, expectedBalance)
    }

    // FIXME [#791]: Fix test
    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testRewindAfterSendingTransaction() async throws {
        let notificationHandler = SDKSynchonizerListener()
        let foundTransactionsExpectation = XCTestExpectation(description: "found transactions expectation")
        let transactionMinedExpectation = XCTestExpectation(description: "transaction mined expectation")

        // 0 subscribe to updated transactions events
        notificationHandler.subscribeToSynchronizer(coordinator.synchronizer)
        // 1 sync and get spendable funds
        try FakeChainBuilder.buildChain(darksideWallet: coordinator.service, branchID: branchID, chainName: chainName)

        try coordinator.applyStaged(blockheight: defaultLatestHeight + 10)

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
            handleError(error)
        }

        await fulfillment(of: [firstSyncExpectation], timeout: 12)
        // 2 check that there are no unconfirmed funds

        let accountUUID = TestsData.mockedAccountUUID
        var accountBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]
        let verifiedBalance: Zatoshi = accountBalance?.saplingBalance.spendableValue ?? .zero
        let totalBalance: Zatoshi = accountBalance?.saplingBalance.total() ?? .zero
        XCTAssertTrue(verifiedBalance > network.constants.defaultFee())
        XCTAssertEqual(verifiedBalance, totalBalance)

        let maxBalance = verifiedBalance - Zatoshi(10000)

        // 3 create a transaction for the max amount possible
        // 4 send the transaction
        let spendingKey = coordinator.spendingKey
        var pendingTx: ZcashTransaction.Overview?
        do {
//            let transaction = try await coordinator.synchronizer.sendToAddress(
//                spendingKey: spendingKey,
//                zatoshi: maxBalance,
//                toAddress: try! Recipient(Environment.testRecipientAddress, network: .mainnet),
//                memo: try Memo(string: "test send \(self.description) \(Date().description)")
//            )
//            pendingTx = transaction
            self.sentTransactionExpectation.fulfill()
        } catch {
            XCTFail("sendToAddress failed: \(error)")
        }
        await fulfillment(of: [sentTransactionExpectation], timeout: 20)
        guard let pendingTx else {
            XCTFail("transaction creation failed")
            return
        }

        notificationHandler.synchronizerMinedTransaction = { transaction in
            XCTAssertNotNil(transaction.rawID)
            XCTAssertNotNil(pendingTx.rawID)
            XCTAssertEqual(transaction.rawID, pendingTx.rawID)
            transactionMinedExpectation.fulfill()
        }

        // 5 apply to height
        // 6 mine the block
        guard let rawTx = try coordinator.getIncomingTransactions()?.first else {
            XCTFail("no incoming transaction after")
            return
        }

        let latestHeight = try await coordinator.latestHeight(mode: .direct)
        let sentTxHeight = latestHeight + 1

        notificationHandler.transactionsFound = { txs in
            let foundTx = txs.first(where: { $0.rawID == pendingTx.rawID })
            XCTAssertNotNil(foundTx)
            XCTAssertEqual(foundTx?.minedHeight, sentTxHeight)

            foundTransactionsExpectation.fulfill()
        }
        try coordinator.stageBlockCreate(height: sentTxHeight, count: 100)
        sleep(1)
        try coordinator.stageTransaction(rawTx, at: sentTxHeight)
        try coordinator.applyStaged(blockheight: sentTxHeight)
        sleep(2)

        // TODO: [#1247] needs to review this to properly solve, https://github.com/zcash/ZcashLightClientKit/issues/1247
//        let mineExpectation = XCTestExpectation(description: "mineTxExpectation")

//        do {
//            try await coordinator.sync(
//                completion: { synchronizer in
//                    let pendingTransaction = try await synchronizer.allPendingTransactions()
//                        .first(where: { $0.rawID == pendingTx.rawID })
//                    XCTAssertNotNil(pendingTransaction, "pending transaction should have been mined by now")
//                    XCTAssertNotNil(pendingTransaction?.minedHeight)
//                    XCTAssertEqual(pendingTransaction?.minedHeight, sentTxHeight)
//                    mineExpectation.fulfill()
//                }, error: self.handleError
//            )
//        } catch {
//            handleError(error)
//        }
//
//        await fulfillment(of: [mineExpectation, transactionMinedExpectation, foundTransactionsExpectation], timeout: 5)

        // 7 advance to confirmation
        let advanceToConfirmationHeight = sentTxHeight + 10

        try coordinator.applyStaged(blockheight: advanceToConfirmationHeight)

        sleep(2)

        let rewindExpectation = XCTestExpectation(description: "RewindExpectation")

        let rewindHeight = sentTxHeight - 5
        try await withCheckedThrowingContinuation { continuation in
            // rewind 5 blocks prior to sending
            coordinator.synchronizer.rewind(.height(blockheight: rewindHeight))
                .sink(
                    receiveCompletion: { result in
                        rewindExpectation.fulfill()
                        switch result {
                        case .finished:
                            continuation.resume()

                        case let .failure(error):
                            XCTFail("Rewind failed with error: \(error)")
                            continuation.resume(with: .failure(error))
                        }
                    },
                    receiveValue: { _ in }
                )
                .store(in: &cancellables)
        }

        await fulfillment(of: [rewindExpectation], timeout: 2)

        // TODO: [#1247] needs to review this to properly solve, https://github.com/zcash/ZcashLightClientKit/issues/1247
//        guard
//            let pendingEntity = try await coordinator.synchronizer.allPendingTransactions()
//                .first(where: { $0.rawID == pendingTx.rawID })
//        else {
//            XCTFail("sent pending transaction not found after rewind")
//            return
//        }
//
//        XCTAssertNil(pendingEntity.minedHeight)

        let confirmExpectation = XCTestExpectation(description: "confirm expectation")
        notificationHandler.transactionsFound = { txs in
            XCTAssertEqual(txs.count, 1)
            guard let transaction = txs.first else {
                XCTFail("should have found sent transaction but didn't")
                return
            }
            XCTAssertEqual(transaction.rawID, pendingTx.rawID, "should have mined sent transaction but didn't")
        }

        notificationHandler.synchronizerMinedTransaction = { transaction in
            XCTAssertEqual(transaction.rawID, pendingTx.rawID)
        }

        do {
            try await coordinator.sync(
                completion: { _ in
                    confirmExpectation.fulfill()
                },
                error: self.handleError
            )
        } catch {
            handleError(error)
        }

        await fulfillment(of: [confirmExpectation], timeout: 10)

        // TODO: [#1247] needs to review this to properly solve, https://github.com/zcash/ZcashLightClientKit/issues/1247
//        let confirmedPending = try await coordinator.synchronizer.allPendingTransactions()
//            .first(where: { $0.rawID == pendingTx.rawID })
//
//        XCTAssertNil(confirmedPending, "pending, now confirmed transaction found")

        accountBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]
        let expectedVerifiedbalance = accountBalance?.saplingBalance.spendableValue ?? .zero
        let expectedBalance = accountBalance?.saplingBalance.total() ?? .zero
        XCTAssertEqual(expectedBalance, .zero)
        XCTAssertEqual(expectedVerifiedbalance, .zero)
    }
}
