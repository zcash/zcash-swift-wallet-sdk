//
//  BalanceTests.swift
//  ZcashLightClientKit-Unit-Tests
//
//  Created by Francisco Gindre on 4/28/20.
//

import Combine
import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

class BalanceTests: ZcashTestCase {
    let sendAmount = Zatoshi(1000)
    let defaultLatestHeight: BlockHeight = 663188
    let branchID = "2bb40e60"
    let chainName = "main"
    let network: ZcashNetwork = DarksideWalletDNetwork()

    var birthday: BlockHeight = 663150
    var sentTransactionExpectation = XCTestExpectation(description: "sent")
    var syncedExpectation = XCTestExpectation(description: "synced")
    var coordinator: TestCoordinator!
    var cancellables: [AnyCancellable] = []

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
        cancellables = []

        try await coordinator.stop()
        try? FileManager.default.removeItem(at: coordinator.databases.fsCacheDbRoot)
        try? FileManager.default.removeItem(at: coordinator.databases.dataDB)
    }

    /**
    verify that when sending the maximum amount, the transactions are broadcasted properly
    */
    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testMaxAmountSendBroadcast() async throws {
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
//                toAddress: try Recipient(Environment.testRecipientAddress, network: self.network.networkType),
//                memo: try Memo(string: "this is a test")
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
        sleep(2) // add enhance breakpoint here

        // TODO: [#1247] needs to review this to properly solve, https://github.com/zcash/ZcashLightClientKit/issues/1247
//        let mineExpectation = XCTestExpectation(description: "mineTxExpectation")

//        do {
//            try await coordinator.sync(
//                completion: { synchronizer in
//                    let pendingEntity = try await synchronizer.allPendingTransactions().first(where: { $0.rawID == pendingTx.rawID })
//                    XCTAssertNotNil(pendingEntity, "pending transaction should have been mined by now")
//                    XCTAssertNotNil(pendingEntity?.minedHeight)
//                    XCTAssertEqual(pendingEntity?.minedHeight, sentTxHeight)
//                    mineExpectation.fulfill()
//                },
//                error: self.handleError
//            )
//        } catch {
//            handleError(error)
//        }
//
//        await fulfillment(of: [mineExpectation, transactionMinedExpectation, foundTransactionsExpectation], timeout: 5)
//
        // 7 advance to confirmation

        try coordinator.applyStaged(blockheight: sentTxHeight + 10)

        sleep(2)

        let confirmExpectation = XCTestExpectation(description: "confirm expectation")
        notificationHandler.transactionsFound = { txs in
            XCTFail("We shouldn't find any transactions at this point but found \(txs)")
        }
        notificationHandler.synchronizerMinedTransaction = { transaction in
            XCTFail("We shouldn't find any mined transactions at this point but found \(transaction)")
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

        await fulfillment(of: [confirmExpectation], timeout: 5)

        // TODO: [#1247] needs to review this to properly solve, https://github.com/zcash/ZcashLightClientKit/issues/1247
//        let confirmedPending = try await coordinator.synchronizer.allPendingTransactions()
//            .first(where: { $0.rawID == pendingTx.rawID })
//
//        XCTAssertNil(confirmedPending, "pending, now confirmed transaction found")

        accountBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]
        let expectedVerifiedBalance = accountBalance?.saplingBalance.spendableValue ?? .zero
        let expectedBalance = accountBalance?.saplingBalance.total() ?? .zero
        XCTAssertEqual(expectedBalance, .zero)
        XCTAssertEqual(expectedVerifiedBalance, .zero)
    }

    /**
    verify that when sending the maximum amount of zatoshi, the transactions are broadcasted properly
    */
    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testMaxAmountSend() async throws {
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

        let maxBalanceMinusOne = verifiedBalance - Zatoshi(10000)

        // 3 create a transaction for the max amount possible
        // 4 send the transaction
        let spendingKey = coordinator.spendingKey
        var pendingTx: ZcashTransaction.Overview?
        do {
//            let transaction = try await coordinator.synchronizer.sendToAddress(
//                spendingKey: spendingKey,
//                zatoshi: maxBalanceMinusOne,
//                toAddress: try Recipient(Environment.testRecipientAddress, network: self.network.networkType),
//                memo: try Memo(string: "\(self.description) \(Date().description)")
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
        sleep(2) // add enhance breakpoint here

        // TODO: [#1247] needs to review this to properly solve, https://github.com/zcash/ZcashLightClientKit/issues/1247
//        let mineExpectation = XCTestExpectation(description: "mineTxExpectation")

//        do {
//            try await coordinator.sync(
//                completion: { synchronizer in
//                    let pendingEntity = try await synchronizer.allPendingTransactions().first(where: { $0.rawID == pendingTx.rawID })
//                    XCTAssertNotNil(pendingEntity, "pending transaction should have been mined by now")
//                    XCTAssertNotNil(pendingEntity?.minedHeight)
//                    XCTAssertEqual(pendingEntity?.minedHeight, sentTxHeight)
//                    mineExpectation.fulfill()
//                },
//                error: self.handleError
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

        let confirmExpectation = XCTestExpectation(description: "confirm expectation")
        notificationHandler.transactionsFound = { txs in
            XCTFail("We shouldn't find any transactions at this point but found \(txs)")
        }
        notificationHandler.synchronizerMinedTransaction = { transaction in
            XCTFail("We shouldn't find any mined transactions at this point but found \(transaction)")
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

        await fulfillment(of: [confirmExpectation], timeout: 5)

        // TODO: [#1247] needs to review this to properly solve, https://github.com/zcash/ZcashLightClientKit/issues/1247
//        let confirmedPending = try await coordinator.synchronizer
//            .allPendingTransactions()
//            .first(where: { $0.rawID == pendingTx.rawID })
//
//        XCTAssertNil(confirmedPending, "pending, now confirmed transaction found")

        accountBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]
        let expectedVerifiedBalance = accountBalance?.saplingBalance.spendableValue ?? .zero
        let expectedBalance = accountBalance?.saplingBalance.total() ?? .zero
        XCTAssertEqual(expectedBalance, .zero)
        XCTAssertEqual(expectedVerifiedBalance, .zero)
    }

    /**
    verify that when sending the maximum amount minus one zatoshi, the transactions are broadcasted properly
    */
    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testMaxAmountMinusOneSendFails() async throws {
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
        let accountBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]
        let verifiedBalance: Zatoshi = accountBalance?.saplingBalance.spendableValue ?? .zero
        let totalBalance: Zatoshi = accountBalance?.saplingBalance.total() ?? .zero
        XCTAssertTrue(verifiedBalance > network.constants.defaultFee())
        XCTAssertEqual(verifiedBalance, totalBalance)

        let maxBalanceMinusOne = verifiedBalance - Zatoshi(10000) - Zatoshi(1)

        // 3 create a transaction for the max amount possible
        // 4 send the transaction
        let spendingKey = coordinator.spendingKey

        do {
//            _ = try await coordinator.synchronizer.sendToAddress(
//                spendingKey: spendingKey,
//                zatoshi: maxBalanceMinusOne,
//                toAddress: try Recipient(Environment.testRecipientAddress, network: self.network.networkType),
//                memo: try Memo(string: "\(self.description) \(Date().description)")
//            )
        } catch {
            guard
                let zcashError = error as? ZcashError,
                case let ZcashError.rustCreateToAddress(message) = zcashError
            else {
                XCTFail("Expected ZcashError and found \(error)")
                return
            }

            XCTAssertEqual(message, "Error while sending funds: Insufficient balance (have 200000, need 200999 including fee)")
            return
        }
        XCTFail("This should have failed with Insufficient funds error")
    }

    /**
    verify that when sending the a no change transaction, the transactions are broadcasted properly
    */
    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testSingleNoteNoChangeTransaction() async throws {
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

        let maxBalanceMinusFee = Zatoshi(100000) - Zatoshi(10000)

        // 3 create a transaction for the max amount possible
        // 4 send the transaction
        let spendingKey = coordinator.spendingKey
        var pendingTx: ZcashTransaction.Overview?
        do {
//            let transaction = try await coordinator.synchronizer.sendToAddress(
//                spendingKey: spendingKey,
//                zatoshi: maxBalanceMinusFee,
//                toAddress: try Recipient(Environment.testRecipientAddress, network: self.network.networkType),
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
        sleep(2) // add enhance breakpoint here

        // TODO: [#1247] needs to review this to properly solve, https://github.com/zcash/ZcashLightClientKit/issues/1247
//        let mineExpectation = XCTestExpectation(description: "mineTxExpectation")

//        do {
//            try await coordinator.sync(
//                completion: { synchronizer in
//                    let pendingEntity = try await synchronizer.allPendingTransactions().first(where: { $0.rawID == pendingTx.rawID })
//                    XCTAssertNotNil(pendingEntity, "pending transaction should have been mined by now")
//                    XCTAssertTrue(pendingEntity?.minedHeight != nil)
//                    XCTAssertEqual(pendingEntity?.minedHeight, sentTxHeight)
//                    mineExpectation.fulfill()
//                },
//                error: self.handleError
//            )
//        } catch {
//            handleError(error)
//        }
//
//        await fulfillment(of: [mineExpectation, transactionMinedExpectation, foundTransactionsExpectation], timeout: 5)

        // 7 advance to confirmation
        let advanceToConfirmation = sentTxHeight + 10

        try coordinator.applyStaged(blockheight: advanceToConfirmation)

        sleep(2)

        let confirmExpectation = XCTestExpectation(description: "confirm expectation")
        notificationHandler.transactionsFound = { txs in
            XCTFail("We shouldn't find any transactions at this point but found \(txs)")
        }
        notificationHandler.synchronizerMinedTransaction = { transaction in
            XCTFail("We shouldn't find any mined transactions at this point but found \(transaction)")
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

        await fulfillment(of: [confirmExpectation], timeout: 5)

        // TODO: [#1247] needs to review this to properly solve, https://github.com/zcash/ZcashLightClientKit/issues/1247
//        let confirmedPending = try await coordinator.synchronizer
//            .allPendingTransactions()
//            .first(where: { $0.rawID == pendingTx.rawID })
//
//        XCTAssertNil(confirmedPending, "pending, now confirmed transaction found")

        accountBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]
        let expectedVerifiedBalance = accountBalance?.saplingBalance.spendableValue ?? .zero
        let expectedBalance = accountBalance?.saplingBalance.total() ?? .zero
        XCTAssertEqual(expectedBalance, Zatoshi(100000))
        XCTAssertEqual(expectedVerifiedBalance, Zatoshi(100000))
    }

    /**
    Verify available balance is correct in all wallet states during a send

    This can be either a Wallet test or a Synchronizer test. The latter is supposed to be simpler because it involves no UI testing whatsoever.

    Precondition:
    Account has spendable funds
    Librustzcash is ‘synced’ up to ‘current tip’

    Action:
    Send Amount(*) to zAddr

    Success per state:
    Sent:  (previous available funds - spent note + change) equals to (previous available funds - sent amount)
    Error:  previous available funds  equals to current funds
    */
    // FIXME [#782]: Fix tests
    func disabled_testVerifyAvailableBalanceDuringSend() async throws {
        try FakeChainBuilder.buildChain(darksideWallet: coordinator.service, branchID: branchID, chainName: chainName)

        try coordinator.applyStaged(blockheight: defaultLatestHeight)

        sleep(1)

        do {
            try await coordinator.sync(
                completion: { _ in
                    self.syncedExpectation.fulfill()
                },
                error: self.handleError
            )
        } catch {
            handleError(error)
        }

        await fulfillment(of: [syncedExpectation], timeout: 60)

        let spendingKey = coordinator.spendingKey

        let accountUUID = TestsData.mockedAccountUUID
        let spendableValue = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.saplingBalance.spendableValue
        let presendVerifiedBalance: Zatoshi = spendableValue ?? .zero

        /*
        there's more zatoshi to send than network fee
        */
        XCTAssertTrue(presendVerifiedBalance >= network.constants.defaultFee() + sendAmount)

        var pendingTx: ZcashTransaction.Overview?

//        let transaction = try await coordinator.synchronizer.sendToAddress(
//            spendingKey: spendingKey,
//            zatoshi: sendAmount,
//            toAddress: try Recipient(Environment.testRecipientAddress, network: self.network.networkType),
//            memo: try Memo(string: "this is a test")
//        )
//        pendingTx = transaction
        self.sentTransactionExpectation.fulfill()

        var expectedVerifiedBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.saplingBalance.spendableValue ?? .zero
        XCTAssertTrue(expectedVerifiedBalance > .zero)
        await fulfillment(of: [sentTransactionExpectation], timeout: 12)

        // sync and mine

        guard let rawTx = try coordinator.getIncomingTransactions()?.first else {
            XCTFail("no incoming transaction after")
            return
        }

        let latestHeight = try await coordinator.latestHeight(mode: .direct)
        let sentTxHeight = latestHeight + 1
        try coordinator.stageBlockCreate(height: sentTxHeight)

        try coordinator.stageTransaction(rawTx, at: sentTxHeight)
        try coordinator.applyStaged(blockheight: sentTxHeight)
        sleep(1)
        let mineExpectation = XCTestExpectation(description: "mineTxExpectation")

        do {
            try await coordinator.sync(
                completion: { _ in
                    mineExpectation.fulfill()
                },
                error: self.handleError
            )
        } catch {
            handleError(error)
        }

        await fulfillment(of: [mineExpectation], timeout: 5)

        let accountBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]
        expectedVerifiedBalance = accountBalance?.saplingBalance.spendableValue ?? .zero
        let expectedBalance = accountBalance?.saplingBalance.total() ?? .zero

        XCTAssertEqual(
            presendVerifiedBalance - self.sendAmount - network.constants.defaultFee(),
            expectedBalance
        )

        XCTAssertEqual(
            presendVerifiedBalance - self.sendAmount - network.constants.defaultFee(),
            expectedVerifiedBalance
        )

        guard let transaction = pendingTx else {
            XCTFail("pending transaction nil")
            return
        }

        /*
        basic health check
        */
        XCTAssertEqual(transaction.value, self.sendAmount)

        let outputs = await coordinator.synchronizer.getTransactionOutputs(for: transaction)

        guard outputs.count == 2 else {
            XCTFail("Expected sent transaction to have 2 outputs")
            return
        }

        guard outputs.first(where: { $0.isChange }) != nil else {
            XCTFail("Sent transaction has no change")
            return
        }

        guard let sentOutput = outputs.first(where: { !$0.isChange }) else {
            XCTFail("sent transaction does not have a 'sent' output")
            return
        }

        guard let fee = transaction.fee else {
            XCTFail("sent transaction has no fee")
            return
        }
        //  (previous available funds - spent note + change) equals to (previous available funds - sent amount)
        self.verifiedBalanceValidation(
            previousBalance: presendVerifiedBalance,
            spentValue: sentOutput.value,
            fee: fee,
            sentAmount: self.sendAmount,
            currentVerifiedBalance: try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.saplingBalance.spendableValue ?? .zero
        )
    }

    /**
    Verify total balance in all wallet states during a send
    This can be either a Wallet test or a Synchronizer test. The latter is supposed to be simpler because it involves no UI testing whatsoever.

    Precondition:
    Account has spendable funds
    Librustzcash is ‘synced’ up to ‘current tip’

    Action:
    Send Amount to zAddr

    Success per state:
    Sent:  (total balance funds - sentAmount) equals to (previous available funds - sent amount)
    Error:  previous total balance  funds  equals to current total balance

    */
    // FIXME [#787]: Fix test
    func disabled_testVerifyTotalBalanceDuringSend() async throws {
        try FakeChainBuilder.buildChain(darksideWallet: coordinator.service, branchID: branchID, chainName: chainName)

        try coordinator.applyStaged(blockheight: defaultLatestHeight)

        sleep(2)
        do {
            try await coordinator.sync(
                completion: { _ in
                    self.syncedExpectation.fulfill()
                },
                error: self.handleError
            )
        } catch {
            handleError(error)
        }

        await fulfillment(of: [syncedExpectation], timeout: 5)

        let spendingKey = coordinator.spendingKey

        let accountUUID = TestsData.mockedAccountUUID
        let presendBalance: Zatoshi = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.saplingBalance.total() ?? .zero

        // there's more zatoshi to send than network fee
        XCTAssertTrue(presendBalance >= network.constants.defaultFee() + sendAmount)
        var pendingTx: ZcashTransaction.Overview?

        var testError: Error?
        do {
//            let transaction = try await coordinator.synchronizer.sendToAddress(
//                spendingKey: spendingKey,
//                zatoshi: sendAmount,
//                toAddress: try Recipient(Environment.testRecipientAddress, network: self.network.networkType),
//                memo: try Memo(string: "test send \(self.description) \(Date().description)")
//            )
//            pendingTx = transaction
            self.sentTransactionExpectation.fulfill()
        } catch {
            // balance should be the same as before sending if transaction failed
            testError = error
            XCTFail("sendToAddress failed: \(error)")
        }

        let accountBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]
        var expectedVerifiedBalance = accountBalance?.saplingBalance.spendableValue ?? .zero
        XCTAssertTrue(expectedVerifiedBalance > .zero)
        await fulfillment(of: [sentTransactionExpectation], timeout: 12)

        expectedVerifiedBalance = accountBalance?.saplingBalance.spendableValue ?? .zero
        if let testError {
            XCTAssertEqual(expectedVerifiedBalance, presendBalance)
            XCTFail("error: \(testError)")
            return
        }
        guard let transaction = pendingTx else {
            XCTFail("pending transaction nil after send")
            return
        }

        XCTAssertEqual(transaction.value, self.sendAmount)

        var expectedBalance = accountBalance?.saplingBalance.total() ?? .zero
        XCTAssertEqual(
            expectedBalance,
            presendBalance - self.sendAmount - network.constants.defaultFee()
        )

        let latestHeight = try await coordinator.latestHeight(mode: .direct)
        let sentTxHeight = latestHeight + 1
        try coordinator.stageBlockCreate(height: sentTxHeight)
        guard let rawTx = try coordinator.getIncomingTransactions()?.first else {
            XCTFail("no incoming transaction after send")
            return
        }

        try coordinator.stageTransaction(rawTx, at: latestHeight + 1)
        try coordinator.applyStaged(blockheight: latestHeight + 1)
        sleep(2)
        let mineExpectation = XCTestExpectation(description: "mineTxExpectation")

        do {
            try await coordinator.sync(
                completion: { _ in
                    mineExpectation.fulfill()
                },
                error: self.handleError
            )
        } catch {
            handleError(error)
        }

        await fulfillment(of: [mineExpectation], timeout: 5)

        expectedBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.saplingBalance.total() ?? .zero
        XCTAssertEqual(
            presendBalance - self.sendAmount - network.constants.defaultFee(),
            expectedBalance
        )
    }

    /**
    Verify incoming transactions
    This can be either a Wallet test or a Synchronizer test. The latter is supposed to be simpler because it involves no UI testing whatsoever.

    Precondition:
    Librustzcash is ‘synced’ up to ‘current tip’
    Known list of expected transactions on the block range to sync the wallet up to.
    Known expected balance on the block range to sync the wallet up to.
    Action:
    sync to latest height
    Success criteria:
    The transaction list matches the expected one
    Balance matches expected balance

    */
    func testVerifyIncomingTransaction() async throws {
        try FakeChainBuilder.buildChain(darksideWallet: coordinator.service, branchID: branchID, chainName: chainName)
        try coordinator.applyStaged(blockheight: defaultLatestHeight)
        sleep(1)

        try await coordinator.sync(
            completion: { _ in
                self.syncedExpectation.fulfill()
            },
            error: self.handleError
        )

        await fulfillment(of: [syncedExpectation], timeout: 5)

        let accountUUID = TestsData.mockedAccountUUID
        let clearedTransactions = await coordinator.synchronizer.transactions
        let expectedBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.saplingBalance.total() ?? .zero
        XCTAssertEqual(clearedTransactions.count, 2)
        XCTAssertEqual(expectedBalance, Zatoshi(200000))
    }

    /**
    Verify change transactions

    This can be either a Wallet test or a Synchronizer test. The latter is supposed to be simpler because it involves no UI testing whatsoever.

    Precondition
    Librustzcash is ‘synced’ up to ‘current tip’
    Known list of expected transactions on the block range to sync the wallet up to.
    Known expected balance on the block range to sync the wallet up to.
    There’s a spendable note with value > send amount that generates change

    Action:
    Send amount to zAddr
    sync to minedHeight + 1

    Success Criteria:
    There’s a sent transaction matching the amount sent to the given zAddr
    minedHeight is not -1
    Balance meets verified Balance and total balance criteria
    There’s a change note of value (previous note value - sent amount)

    */

    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testVerifyChangeTransaction() async throws {
        try FakeChainBuilder.buildSingleNoteChain(darksideWallet: coordinator.service, branchID: branchID, chainName: chainName)

        try coordinator.applyStaged(blockheight: defaultLatestHeight)
        sleep(1)
        let sendExpectation = XCTestExpectation(description: "send expectation")

        try coordinator.setLatestHeight(height: defaultLatestHeight)

        /*
        sync to current tip
        */
        do {
            try await coordinator.sync(
                completion: { _ in
                    self.syncedExpectation.fulfill()
                },
                error: self.handleError
            )
        } catch {
            handleError(error)
        }

        await fulfillment(of: [syncedExpectation], timeout: 6)

        let accountUUID = TestsData.mockedAccountUUID
        let accountBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]
        let previousVerifiedBalance: Zatoshi = accountBalance?.saplingBalance.spendableValue ?? .zero
        let previousTotalBalance: Zatoshi = accountBalance?.saplingBalance.total() ?? .zero

        let spendingKey = coordinator.spendingKey

        /*
        Send
        */
        let memo = try Memo(string: "shielding is fun!")
        var pendingTx: ZcashTransaction.Overview?

//        let transaction = try await coordinator.synchronizer.sendToAddress(
//            spendingKey: spendingKey,
//            zatoshi: sendAmount,
//            toAddress: try Recipient(Environment.testRecipientAddress, network: self.network.networkType),
//            memo: memo
//        )
//        pendingTx = transaction
        sendExpectation.fulfill()

        await fulfillment(of: [sendExpectation], timeout: 30)

        let syncToMinedheightExpectation = XCTestExpectation(description: "sync to mined height + 1")

        /*
        include sent transaction in block
        */
        guard let rawTx = try coordinator.getIncomingTransactions()?.first else {
            XCTFail("pending transaction nil after send")
            return
        }

        let latestHeight = try await coordinator.latestHeight(mode: .direct)
        let sentTxHeight = latestHeight + 1
        try coordinator.stageBlockCreate(height: sentTxHeight, count: 12)
        try coordinator.stageTransaction(rawTx, at: sentTxHeight)
        try coordinator.applyStaged(blockheight: sentTxHeight + 11  )
        sleep(2)

        /*
        Sync to that block
        */
        do {
            try await coordinator.sync(
                completion: { synchronizer in
                    let confirmedTx: ZcashTransaction.Overview!
                    do {
                        confirmedTx = try await synchronizer.allTransactions().first(where: { confirmed -> Bool in
                            confirmed.rawID == pendingTx?.rawID
                        })
                    } catch {
                        XCTFail("Error  retrieving cleared transactions")
                        return
                    }

                    /*
                    There’s a sent transaction matching the amount sent to the given zAddr
                    */
                    XCTAssertEqual(
                        -confirmedTx.value.amount,
                        (self.sendAmount + (confirmedTx.fee ?? Zatoshi(0))).amount
                    )
                    // TODO [#683]: Add API to SDK to fetch memos.
                    let confirmedMemo = try await self.coordinator.synchronizer.getMemos(for: confirmedTx).first

                    XCTAssertEqual(confirmedMemo, memo)

                    /*
                    Find out what note was used
                    */

                    let outputs = await self.coordinator.synchronizer.getTransactionOutputs(for: confirmedTx)

                    guard outputs.count == 2 else {
                        XCTFail("Expected sent transaction to have 2 outputs")
                        return
                    }

                    guard let changeOutput = outputs.first(where: { $0.isChange }) else {
                        XCTFail("Sent transaction has no change")
                        return
                    }

                    guard let sentOutput = outputs.first(where: { !$0.isChange }) else {
                        XCTFail("sent transaction does not have a 'sent' output")
                        return
                    }

                    /*
                    There’s a change note of value (previous note value - sent amount)
                    */
                    XCTAssertEqual(
                        previousVerifiedBalance - self.sendAmount - Zatoshi(10000),
                        changeOutput.value
                    )

//                    guard let fee = transaction.fee else {
//                        XCTFail("sent transaction has no fee")
//                        return
//                    }
//                    /*
//                    Balance meets verified Balance and total balance criteria
//                    */
//                    self.verifiedBalanceValidation(
//                        previousBalance: previousVerifiedBalance,
//                        spentValue: sentOutput.value,
//                        fee: fee,
//                        sentAmount: self.sendAmount,
//                        currentVerifiedBalance: try await synchronizer.getAccountsBalances()[accountUUID]?.saplingBalance.spendableValue ?? .zero
//                    )
//
//                    self.totalBalanceValidation(
//                        totalBalance: try await synchronizer.getAccountsBalances()[accountUUID]?.saplingBalance.total() ?? .zero,
//                        previousTotalbalance: previousTotalBalance,
//                        sentAmount: self.sendAmount
//                    )

                    syncToMinedheightExpectation.fulfill()
                },
                error: self.handleError
            )
        } catch {
            handleError(error)
        }

        await fulfillment(of: [syncToMinedheightExpectation], timeout: 5)
    }

    /**
    Verify transactions that expire are reflected accurately in balance
    This test requires the transaction to expire.

    How can we mock or cause this? Would createToAddress and faking a network submission through lightwalletService and syncing 10 more blocks work?

    Precondition:
    Account has spendable funds
    Librustzcash is ‘synced’ up to ‘current tip’ †
    Current tip can be scanned 10 blocks past the generated to be expired transaction

    Action:
    Sync to current tip
    Create transaction to zAddr
    Mock send success
    Sync 10 blocks more

    Success Criteria:
    There’s a pending transaction that has expired
    Total Balance is equal to total balance previously shown before sending the expired transaction
    Verified Balance is equal to verified balance previously shown before sending the expired transaction
    */
    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testVerifyBalanceAfterExpiredTransaction() async throws {
        try FakeChainBuilder.buildChain(darksideWallet: coordinator.service, branchID: branchID, chainName: chainName)

        try coordinator.applyStaged(blockheight: self.defaultLatestHeight + 10)
        sleep(2)

        do {
            try await coordinator.sync(
                completion: { _ in
                    self.syncedExpectation.fulfill()
                },
                error: self.handleError
            )
        } catch {
            handleError(error)
        }

        await fulfillment(of: [syncedExpectation], timeout: 5)

        let spendingKey = coordinator.spendingKey

        let accountUUID = TestsData.mockedAccountUUID
        var accountBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]
        let previousVerifiedBalance: Zatoshi = accountBalance?.saplingBalance.spendableValue ?? .zero
        let previousTotalBalance: Zatoshi = accountBalance?.saplingBalance.total() ?? .zero
        let sendExpectation = XCTestExpectation(description: "send expectation")
        var pendingTx: ZcashTransaction.Overview?
        do {
//            let pending = try await coordinator.synchronizer.sendToAddress(
//                spendingKey: spendingKey,
//                zatoshi: sendAmount,
//                toAddress: try Recipient(Environment.testRecipientAddress, network: self.network.networkType),
//                memo: try Memo(string: "test send \(self.description)")
//            )
//            pendingTx = pending
            sendExpectation.fulfill()
        } catch {
            // balance should be the same as before sending if transaction failed
            let accountBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]
            let expectedVerifiedBalance = accountBalance?.saplingBalance.spendableValue ?? .zero
            let expectedBalance = accountBalance?.saplingBalance.total() ?? .zero
            XCTAssertEqual(expectedVerifiedBalance, previousVerifiedBalance)
            XCTAssertEqual(expectedBalance, previousTotalBalance)
            XCTFail("sendToAddress failed: \(error)")
        }

        await fulfillment(of: [sendExpectation], timeout: 12)

        guard let pendingTransaction = pendingTx, let expiryHeight = pendingTransaction.expiryHeight, expiryHeight > defaultLatestHeight else {
            XCTFail("No pending transaction")
            return
        }

        let expirationSyncExpectation = XCTestExpectation(description: "expiration sync expectation")

        try coordinator.applyStaged(blockheight: expiryHeight + 1)

        sleep(2)

        do {
            try await coordinator.sync(
                completion: { _ in
                    expirationSyncExpectation.fulfill()
                },
                error: self.handleError
            )
        } catch {
            handleError(error)
        }

        await fulfillment(of: [expirationSyncExpectation], timeout: 5)

        accountBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]
        let expectedVerifiedBalance = accountBalance?.saplingBalance.spendableValue ?? .zero
        let expectedBalance = accountBalance?.saplingBalance.total() ?? .zero
        /*
        Verified Balance is equal to verified balance previously shown before sending the expired transaction
        */
        XCTAssertEqual(expectedVerifiedBalance, previousVerifiedBalance)

        /*
        Total Balance is equal to total balance previously shown before sending the expired transaction
        */
        XCTAssertEqual(expectedBalance, previousTotalBalance)

        let transactionRepo = TransactionSQLDAO(
            dbProvider: SimpleConnectionProvider(
                path: coordinator.synchronizer.initializer.dataDbURL.absoluteString
            )
        )

        let expiredPending = try await transactionRepo.find(rawID: pendingTransaction.rawID)

        /*
        there no sent transaction displayed
        */

        let sentTransactions = try await coordinator.synchronizer.allSentTransactions()
        XCTAssertNil(sentTransactions.first(where: { $0.rawID == pendingTransaction.rawID }))
        /*
        There’s a pending transaction that has expired
        */
        XCTAssertNil(expiredPending.minedHeight)
    }

    func handleError(_ error: Error?) {
        guard let testError = error else {
            XCTFail("failed with nil error")
            return
        }
        XCTFail("Failed with error: \(testError)")
    }

    /**
    check if (previous available funds - spent note + change) equals to (previous available funds - sent amount)
    */
    func verifiedBalanceValidation(
        previousBalance: Zatoshi,
        spentValue: Zatoshi,
        fee: Zatoshi,
        sentAmount: Zatoshi,
        currentVerifiedBalance: Zatoshi
    ) {
        XCTAssertEqual(previousBalance - spentValue - fee, currentVerifiedBalance)
    }

    func totalBalanceValidation(
        totalBalance: Zatoshi,
        previousTotalbalance: Zatoshi,
        sentAmount: Zatoshi
    ) {
        XCTAssertEqual(totalBalance, previousTotalbalance - sentAmount - Zatoshi(10000))
    }
}

class SDKSynchonizerListener {
    var transactionsFound: (([ZcashTransaction.Overview]) -> Void)?
    var synchronizerMinedTransaction: ((ZcashTransaction.Overview) -> Void)?
    var cancellables: [AnyCancellable] = []

    func subscribeToSynchronizer(_ synchronizer: SDKSynchronizer) {
        synchronizer.eventStream
            .sink(
                receiveValue: { [weak self] event in
                    switch event {
                    case let .minedTransaction(transaction):
                        self?.txMined(transaction)

                    case let .foundTransactions(transactions, _):
                        self?.txFound(transactions)

                    case .storedUTXOs, .connectionStateChanged:
                        break
                    }
                }
            )
            .store(in: &cancellables)
    }

    func unsubscribe() {
        cancellables = []
    }

    func txFound(_ txs: [ZcashTransaction.Overview]) {
        DispatchQueue.main.async { [weak self] in
            self?.transactionsFound?(txs)
        }
    }

    func txMined(_ transaction: ZcashTransaction.Overview) {
        DispatchQueue.main.async { [weak self] in
            self?.synchronizerMinedTransaction?(transaction)
        }
    }
}
