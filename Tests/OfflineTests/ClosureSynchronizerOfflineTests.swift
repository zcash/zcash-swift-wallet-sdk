//
//  ClosureSynchronizerOfflineTests.swift
//
//
//  Created by Michal Fousek on 20.03.2023.
//

import Combine
import Foundation
@testable import TestUtils
import XCTest
@testable import ZcashLightClientKit

class ClosureSynchronizerOfflineTests: XCTestCase {
    var data: TestsData!

    var cancellables: [AnyCancellable] = []
    var synchronizerMock: SynchronizerMock!
    var synchronizer: ClosureSDKSynchronizer!

    override func setUpWithError() throws {
        try super.setUpWithError()
        data = TestsData(networkType: .testnet)
        synchronizerMock = SynchronizerMock()
        synchronizer = ClosureSDKSynchronizer(synchronizer: synchronizerMock)
        cancellables = []
    }

    override func tearDown() {
        super.tearDown()
        data = nil
    }

    func testAliasIsAsExpected() {
        synchronizerMock.underlyingAlias = .custom("some_alias")
        XCTAssertEqual(synchronizer.alias, .custom("some_alias"))
    }

    func testStateStreamEmitsAsExpected() {
        let state = SynchronizerState.mock
        synchronizerMock.underlyingStateStream = Just(state).eraseToAnyPublisher()

        let expectation = XCTestExpectation()

        synchronizer.stateStream
            .sink(
                receiveCompletion: { completion in
                    switch completion {
                    case .finished:
                        expectation.fulfill()
                    case let .failure(error):
                        XCTFail("Unexpected failure with error: \(error)")
                    }
                },
                receiveValue: { receivedState in
                    XCTAssertEqual(receivedState, state)
                }
            )
            .store(in: &cancellables)

        wait(for: [expectation], timeout: 0.5)
    }

    func testLatestStateIsAsExpected() {
        let state = SynchronizerState.mock
        synchronizerMock.underlyingLatestState = state

        XCTAssertEqual(synchronizer.latestState, state)
    }

    func testEventStreamEmitsAsExpected() {
        synchronizerMock.underlyingEventStream = Just(.connectionStateChanged(.connecting)).eraseToAnyPublisher()

        let expectation = XCTestExpectation()

        synchronizer.eventStream
            .sink(
                receiveCompletion: { completion in
                    switch completion {
                    case .finished:
                        expectation.fulfill()
                    case let .failure(error):
                        XCTFail("Unexpected failure with error: \(error)")
                    }
                },
                receiveValue: { event in
                    if case .connectionStateChanged = event {
                    } else {
                        XCTFail("Unexpected event: \(event)")
                    }
                }
            )
            .store(in: &cancellables)

        wait(for: [expectation], timeout: 0.5)
    }

    func testConnectionStateAsExpected() {
        synchronizerMock.underlyingConnectionState = .reconnecting
        XCTAssertEqual(synchronizer.connectionState, .reconnecting)
    }

    func testPrepareSucceed() throws {
        synchronizerMock.prepareWithWalletBirthdayNameKeySourceClosure = { receivedSeed, receivedWalletBirthday, _, _ in
            XCTAssertEqual(receivedSeed, self.data.seed)
            XCTAssertEqual(receivedWalletBirthday, self.data.birthday)
            return .success
        }

        let expectation = XCTestExpectation()

        synchronizer.prepare(with: data.seed, walletBirthday: data.birthday, name: "", keySource: nil) { result in
            switch result {
            case let .success(status):
                XCTAssertEqual(status, .success)
                expectation.fulfill()
            case let .failure(error):
                XCTFail("Unpected failure with error: \(error)")
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testPrepareThrowsError() throws {
        synchronizerMock.prepareWithWalletBirthdayNameKeySourceClosure = { _, _, _, _ in
            throw "Some error"
        }

        let expectation = XCTestExpectation()

        synchronizer.prepare(with: data.seed, walletBirthday: data.birthday, name: "", keySource: nil) { result in
            switch result {
            case .success:
                XCTFail("Error should be thrown.")
                expectation.fulfill()
            case .failure:
                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testStartSucceeds() {
        synchronizerMock.startRetryClosure = { retry in
            XCTAssertTrue(retry)
            return
        }

        let expectation = XCTestExpectation()

        synchronizer.start(retry: true) { error in
            XCTAssertNil(error)
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testStartThrowsError() {
        synchronizerMock.startRetryClosure = { _ in
            throw "Some error"
        }

        let expectation = XCTestExpectation()

        synchronizer.start(retry: true) { error in
            XCTAssertNotNil(error)
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testStopSucceed() {
        var stopCalled = false
        synchronizerMock.stopClosure = {
            stopCalled = true
        }

        synchronizer.stop()
        XCTAssertTrue(stopCalled)
    }

    func testGetSaplingAddressSucceed() {
        synchronizerMock.getSaplingAddressAccountUUIDClosure = { accountUUID in
            XCTAssertEqual(accountUUID, TestsData.mockedAccountUUID)
            return self.data.saplingAddress
        }

        let expectation = XCTestExpectation()

        synchronizer.getSaplingAddress(accountUUID: TestsData.mockedAccountUUID) { result in
            switch result {
            case let .success(address):
                XCTAssertEqual(address, self.data.saplingAddress)
                expectation.fulfill()
            case let .failure(error):
                XCTFail("getSaplingAddress failed with error: \(error)")
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testGetSaplingAddressThrowsError() {
        synchronizerMock.getSaplingAddressAccountUUIDClosure = { _ in
            throw "Some error"
        }

        let expectation = XCTestExpectation()

        synchronizer.getSaplingAddress(accountUUID: TestsData.mockedAccountUUID) { result in
            switch result {
            case .success:
                XCTFail("Error should be thrown.")
            case .failure:
                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testGetUnifiedAddressSucceed() {
        synchronizerMock.getUnifiedAddressAccountUUIDClosure = { accountUUID in
            XCTAssertEqual(accountUUID, TestsData.mockedAccountUUID)
            return self.data.unifiedAddress
        }

        let expectation = XCTestExpectation()

        synchronizer.getUnifiedAddress(accountUUID: TestsData.mockedAccountUUID) { result in
            switch result {
            case let .success(address):
                XCTAssertEqual(address, self.data.unifiedAddress)
                expectation.fulfill()
            case let .failure(error):
                XCTFail("getSaplingAddress failed with error: \(error)")
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testGetUnifiedAddressThrowsError() {
        synchronizerMock.getUnifiedAddressAccountUUIDClosure = { _ in
            throw "Some error"
        }

        let expectation = XCTestExpectation()

        synchronizer.getUnifiedAddress(accountUUID: TestsData.mockedAccountUUID) { result in
            switch result {
            case .success:
                XCTFail("Error should be thrown.")
            case .failure:
                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testGetTransparentAddressSucceed() {
        synchronizerMock.getTransparentAddressAccountUUIDClosure = { accountUUID in
            XCTAssertEqual(accountUUID, TestsData.mockedAccountUUID)
            return self.data.transparentAddress
        }

        let expectation = XCTestExpectation()

        synchronizer.getTransparentAddress(accountUUID: TestsData.mockedAccountUUID) { result in
            switch result {
            case let .success(address):
                XCTAssertEqual(address, self.data.transparentAddress)
                expectation.fulfill()
            case let .failure(error):
                XCTFail("getSaplingAddress failed with error: \(error)")
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testGetTransparentAddressThrowsError() {
        synchronizerMock.getTransparentAddressAccountUUIDClosure = { _ in
            throw "Some error"
        }

        let expectation = XCTestExpectation()

        synchronizer.getTransparentAddress(accountUUID: TestsData.mockedAccountUUID) { result in
            switch result {
            case .success:
                XCTFail("Error should be thrown.")
            case .failure:
                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testClearedTransactionsSucceed() {
        synchronizerMock.underlyingTransactions = [data.clearedTransaction]

        let expectation = XCTestExpectation()

        synchronizer.clearedTransactions() { transactions in
            XCTAssertEqual(transactions.count, 1)
            XCTAssertEqual(transactions[0].rawID, self.data.clearedTransaction.rawID)
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testSentTransactionsSucceed() {
        synchronizerMock.underlyingSentTransactions = [data.sentTransaction]

        let expectation = XCTestExpectation()

        synchronizer.sentTranscations() { transactions in
            XCTAssertEqual(transactions.count, 1)
            XCTAssertEqual(transactions[0].rawID, self.data.sentTransaction.rawID)
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testReceivedTransactionsSucceed() {
        synchronizerMock.underlyingReceivedTransactions = [data.receivedTransaction]

        let expectation = XCTestExpectation()

        synchronizer.receivedTransactions() { transactions in
            XCTAssertEqual(transactions.count, 1)
            XCTAssertEqual(transactions[0].rawID, self.data.receivedTransaction.rawID)
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testGetMemosForClearedTransactionSucceed() throws {
        let memo: Memo = .text(try MemoText("Some message"))

        synchronizerMock.getMemosForClearedTransactionClosure = { receivedTransaction in
            XCTAssertEqual(receivedTransaction.rawID, self.data.clearedTransaction.rawID)
            return [memo]
        }

        let expectation = XCTestExpectation()

        synchronizer.getMemos(for: data.clearedTransaction) { result in
            switch result {
            case let .success(memos):
                XCTAssertEqual(memos.count, 1)
                XCTAssertEqual(memos[0], memo)
                expectation.fulfill()
            case let .failure(error):
                XCTFail("Unpected failure with error: \(error)")
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testGetMemosForClearedTransactionThrowsError() {
        synchronizerMock.getMemosForClearedTransactionClosure = { _ in
            throw "Some error"
        }

        let expectation = XCTestExpectation()

        synchronizer.getMemos(for: data.clearedTransaction) { result in
            switch result {
            case .success:
                XCTFail("Error should be thrown.")
            case .failure:
                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testGetRecipientsForClearedTransaction() {
        let expectedRecipient: TransactionRecipient = .address(.transparent(data.transparentAddress))

        synchronizerMock.getRecipientsForClearedTransactionClosure = { receivedTransaction in
            XCTAssertEqual(receivedTransaction.rawID, self.data.clearedTransaction.rawID)
            return [expectedRecipient]
        }

        let expectation = XCTestExpectation()

        synchronizer.getRecipients(for: data.clearedTransaction) { recipients in
            XCTAssertEqual(recipients.count, 1)
            XCTAssertEqual(recipients[0], expectedRecipient)
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testAllConfirmedTransactionsSucceed() throws {
        synchronizerMock.allTransactionsFromLimitClosure = { receivedTransaction, limit in
            XCTAssertEqual(receivedTransaction.rawID, self.data.clearedTransaction.rawID)
            XCTAssertEqual(limit, 3)
            return [self.data.clearedTransaction]
        }

        let expectation = XCTestExpectation()

        synchronizer.allConfirmedTransactions(from: data.clearedTransaction, limit: 3) { result in
            switch result {
            case let .success(transactions):
                XCTAssertEqual(transactions.count, 1)
                XCTAssertEqual(transactions[0].rawID, self.data.clearedTransaction.rawID)
                expectation.fulfill()
            case let .failure(error):
                XCTFail("Unpected failure with error: \(error)")
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testAllConfirmedTransactionsThrowsError() throws {
        synchronizerMock.allTransactionsFromLimitClosure = { _, _ in
            throw "Some error"
        }

        let expectation = XCTestExpectation()

        synchronizer.allConfirmedTransactions(from: data.clearedTransaction, limit: 3) { result in
            switch result {
            case .success:
                XCTFail("Error should be thrown.")
            case .failure:
                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testLatestHeightSucceed() {
        synchronizerMock.latestHeightClosure = { 123000 }

        let expectation = XCTestExpectation()

        synchronizer.latestHeight() { result in
            switch result {
            case let .success(receivedHeight):
                XCTAssertEqual(receivedHeight, 123000)
                expectation.fulfill()
            case let .failure(error):
                XCTFail("Unpected failure with error: \(error)")
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testLatestHeightThrowsError() {
        synchronizerMock.latestHeightClosure = {
            throw "Some error"
        }

        let expectation = XCTestExpectation()

        synchronizer.latestHeight() { result in
            switch result {
            case .success:
                XCTFail("Error should be thrown.")
            case .failure:
                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testRefreshUTXOsSucceed() {
        let insertedEntity = UnspentTransactionOutputEntityMock(address: "addr", txid: Data(), index: 0, script: Data(), valueZat: 1, height: 2)
        let skippedEntity = UnspentTransactionOutputEntityMock(address: "addr2", txid: Data(), index: 1, script: Data(), valueZat: 2, height: 3)
        let refreshedUTXO = (inserted: [insertedEntity], skipped: [skippedEntity])

        synchronizerMock.refreshUTXOsAddressFromClosure = { receivedAddress, receivedFromHeight in
            XCTAssertEqual(receivedAddress, self.data.transparentAddress)
            XCTAssertEqual(receivedFromHeight, 121000)
            return refreshedUTXO
        }

        let expectation = XCTestExpectation()

        synchronizer.refreshUTXOs(address: data.transparentAddress, from: 121000) { result in
            switch result {
            case let .success(utxos):
                XCTAssertEqual(utxos.inserted as! [UnspentTransactionOutputEntityMock], [insertedEntity])
                XCTAssertEqual(utxos.skipped as! [UnspentTransactionOutputEntityMock], [skippedEntity])
                expectation.fulfill()
            case let .failure(error):
                XCTFail("Unpected failure with error: \(error)")
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testRefreshUTXOsThrowsError() {
        synchronizerMock.refreshUTXOsAddressFromClosure = { _, _ in
            throw "Some error"
        }

        let expectation = XCTestExpectation()

        synchronizer.refreshUTXOs(address: data.transparentAddress, from: 121000) { result in
            switch result {
            case .success:
                XCTFail("Error should be thrown.")
            case .failure:
                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testGetTransparentBalanceSucceed() {
        let accountUUID = TestsData.mockedAccountUUID

        let expectedBalance = [accountUUID: AccountBalance(saplingBalance: .zero, orchardBalance: .zero, unshielded: Zatoshi(200))]

        synchronizerMock.getAccountsBalancesClosure = {
            return expectedBalance
        }

        let expectation = XCTestExpectation()

        synchronizer.getAccountsBalances() { result in
            switch result {
            case let .success(receivedBalance):
                XCTAssertEqual(receivedBalance, expectedBalance)
                expectation.fulfill()
            case let .failure(error):
                XCTFail("Unpected failure with error: \(error)")
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testGetTransparentBalanceThrowsError() {
        synchronizerMock.getAccountsBalancesClosure = {
            throw "Some error"
        }

        let expectation = XCTestExpectation()

        synchronizer.getAccountsBalances() { result in
            switch result {
            case .success:
                XCTFail("Error should be thrown.")
            case .failure:
                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testGetShieldedBalanceSucceed() {
        let accountUUID = TestsData.mockedAccountUUID

        let expectedBalance = [
            accountUUID: AccountBalance(
                saplingBalance:
                    PoolBalance(
                        spendableValue: Zatoshi(333),
                        changePendingConfirmation: .zero,
                        valuePendingSpendability: .zero
                    ),
                orchardBalance:
                    PoolBalance(
                        spendableValue: Zatoshi(333),
                        changePendingConfirmation: .zero,
                        valuePendingSpendability: .zero
                    ),
                unshielded: .zero
            )
        ]

        synchronizerMock.getAccountsBalancesClosure = {
            return expectedBalance
        }

        let expectation = XCTestExpectation()

        synchronizer.getAccountsBalances() { result in
            switch result {
            case let .success(receivedBalance):
                XCTAssertEqual(receivedBalance, expectedBalance)
                expectation.fulfill()
            case let .failure(error):
                XCTFail("Unpected failure with error: \(error)")
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testGetShieldedBalanceThrowsError() {
        synchronizerMock.getAccountsBalancesClosure = {
            throw "Some error"
        }

        let expectation = XCTestExpectation()

        synchronizer.getAccountsBalances() { result in
            switch result {
            case .success:
                XCTFail("Error should be thrown.")
            case .failure:
                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testGetShieldedVerifiedBalanceSucceed() {
        let expectedBalance = [
            TestsData.mockedAccountUUID: AccountBalance(
                saplingBalance:
                    PoolBalance(
                        spendableValue: .zero,
                        changePendingConfirmation: Zatoshi(333),
                        valuePendingSpendability: .zero
                    ),
                orchardBalance:
                    PoolBalance(
                        spendableValue: .zero,
                        changePendingConfirmation: Zatoshi(333),
                        valuePendingSpendability: .zero
                    ),
                unshielded: .zero
            )
        ]

        synchronizerMock.getAccountsBalancesClosure = {
            return expectedBalance
        }

        let expectation = XCTestExpectation()

        synchronizer.getAccountsBalances() { result in
            switch result {
            case let .success(receivedBalance):
                XCTAssertEqual(receivedBalance, expectedBalance)
                expectation.fulfill()
            case let .failure(error):
                XCTFail("Unpected failure with error: \(error)")
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testGetShieldedVerifiedBalanceThrowsError() {
        synchronizerMock.getAccountsBalancesClosure = {
            throw "Some error"
        }

        let expectation = XCTestExpectation()

        synchronizer.getAccountsBalances() { result in
            switch result {
            case .success:
                XCTFail("Error should be thrown.")
            case .failure:
                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: 0.5)
    }

    func testRewindSucceed() {
        synchronizerMock.rewindClosure = { receivedPolicy in
            if case .quick = receivedPolicy {
            } else {
                XCTFail("Unexpected policy \(receivedPolicy)")
            }

            return Empty().eraseToAnyPublisher()
        }

        let expectation = XCTestExpectation()

        synchronizer.rewind(.quick)
            .sink(
                receiveCompletion: { result in
                    switch result {
                    case .finished:
                        expectation.fulfill()
                    case let .failure(error):
                        XCTFail("Unexpected failure \(error)")
                    }
                },
                receiveValue: { _ in }
            )
            .store(in: &cancellables)

        wait(for: [expectation], timeout: 0.5)
    }

    func testRewindThrowsError() {
        synchronizerMock.rewindClosure = { _ in
            return Fail(error: "some error").eraseToAnyPublisher()
        }

        let expectation = XCTestExpectation()

        synchronizer.rewind(.quick)
            .sink(
                receiveCompletion: { result in
                    switch result {
                    case .finished:
                        XCTFail("Failure is expected")
                    case .failure:
                        expectation.fulfill()
                    }
                },
                receiveValue: { _ in }
            )
            .store(in: &cancellables)

        wait(for: [expectation], timeout: 0.5)
    }

    func testWipeSucceed() {
        synchronizerMock.wipeClosure = {
            return Empty().eraseToAnyPublisher()
        }

        let expectation = XCTestExpectation()

        synchronizer.wipe()
            .sink(
                receiveCompletion: { result in
                    switch result {
                    case .finished:
                        expectation.fulfill()
                    case let .failure(error):
                        XCTFail("Unexpected failure \(error)")
                    }
                },
                receiveValue: { _ in }
            )
            .store(in: &cancellables)

        wait(for: [expectation], timeout: 0.5)
    }

    func testWipeThrowsError() {
        synchronizerMock.wipeClosure = {
            return Fail(error: "some error").eraseToAnyPublisher()
        }

        let expectation = XCTestExpectation()

        synchronizer.wipe()
            .sink(
                receiveCompletion: { result in
                    switch result {
                    case .finished:
                        XCTFail("Failure is expected")
                    case .failure:
                        expectation.fulfill()
                    }
                },
                receiveValue: { _ in }
            )
            .store(in: &cancellables)

        wait(for: [expectation], timeout: 0.5)
    }
}
