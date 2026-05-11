//
//  AutomaticTxResubmissionGuardTests.swift
//  ZcashLightClientKitTests
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class AutomaticTxResubmissionGuardTests: ZcashTestCase {
    func testPersistsExcludedTransactions() async throws {
        let excludedTransaction = makeTransaction(rawID: Data(repeating: 0xAB, count: 32))
        let resubmittableTransaction = makeTransaction(rawID: Data(repeating: 0xCD, count: 32))
        let guardStorage = testGeneralStorageDirectory.appendingPathComponent("persisted")
        let resubmissionGuard = AutomaticTxResubmissionGuard(storageURL: guardStorage, logger: NullLogger())

        await resubmissionGuard.excludeFromAutomaticResubmission([excludedTransaction])

        let reloadedGuard = AutomaticTxResubmissionGuard(storageURL: guardStorage, logger: NullLogger())
        let transactions = await reloadedGuard.filterAutomaticallyResubmittable([
            excludedTransaction,
            resubmittableTransaction
        ])

        XCTAssertEqual(transactions.map(\.rawID), [resubmittableTransaction.rawID])
    }

    func testPrunesExcludedTransactionsThatAreNoLongerCandidates() async throws {
        let retainedTransaction = makeTransaction(rawID: Data(repeating: 0xAB, count: 32))
        let prunedTransaction = makeTransaction(rawID: Data(repeating: 0xCD, count: 32))
        let guardStorage = testGeneralStorageDirectory.appendingPathComponent("pruned")
        let resubmissionGuard = AutomaticTxResubmissionGuard(storageURL: guardStorage, logger: NullLogger())

        await resubmissionGuard.excludeFromAutomaticResubmission([retainedTransaction, prunedTransaction])
        _ = await resubmissionGuard.filterAutomaticallyResubmittable([retainedTransaction])

        let reloadedGuard = AutomaticTxResubmissionGuard(storageURL: guardStorage, logger: NullLogger())
        let transactions = await reloadedGuard.filterAutomaticallyResubmittable([
            retainedTransaction,
            prunedTransaction
        ])

        XCTAssertEqual(transactions.map(\.rawID), [prunedTransaction.rawID])
    }

    func testTxResubmissionActionSkipsExcludedTransactions() async throws {
        let excludedTransaction = makeTransaction(rawID: Data(repeating: 0xAB, count: 32))
        let resubmittableTransaction = makeTransaction(rawID: Data(repeating: 0xCD, count: 32))
        let transactionRepository = TransactionRepositoryMock()
        let transactionEncoder = RecordingTransactionEncoder()
        let resubmissionGuard = AutomaticTxResubmissionGuard(
            storageURL: testGeneralStorageDirectory,
            logger: NullLogger()
        )

        transactionRepository.findForResubmissionUpToReturnValue = [
            excludedTransaction,
            resubmittableTransaction
        ]

        mockContainer.mock(type: TransactionRepository.self, isSingleton: true) { _ in transactionRepository }
        mockContainer.mock(type: TransactionEncoder.self, isSingleton: true) { _ in transactionEncoder }
        mockContainer.mock(type: Logger.self, isSingleton: true) { _ in NullLogger() }
        mockContainer.mock(type: AutomaticTxResubmissionGuard.self, isSingleton: true) { _ in resubmissionGuard }

        await resubmissionGuard.excludeFromAutomaticResubmission([excludedTransaction])

        let context = ActionContextMock.default()
        context.underlyingSyncControlData = SyncControlData(
            latestBlockHeight: 1000,
            latestScannedHeight: nil,
            firstUnenhancedHeight: nil
        )

        let action = TxResubmissionAction(container: mockContainer)
        action.latestResolvedTime = 0

        _ = try await action.run(with: context) { _ in }

        XCTAssertEqual(
            transactionEncoder.submittedTransactions.map(\.transactionId),
            [resubmittableTransaction.rawID]
        )
    }

    private func makeTransaction(rawID: Data) -> ZcashTransaction.Overview {
        ZcashTransaction.Overview(
            accountUUID: TestsData.mockedAccountUUID,
            blockTime: nil,
            expiryHeight: 123_456,
            fee: Zatoshi(10_000),
            index: 0,
            isShielding: false,
            hasChange: false,
            memoCount: 0,
            minedHeight: nil,
            raw: Data([0x01]),
            rawID: rawID,
            receivedNoteCount: 0,
            sentNoteCount: 1,
            value: Zatoshi(-1_000),
            isExpiredUmined: false,
            totalSpent: nil,
            totalReceived: nil
        )
    }
}

private final class RecordingTransactionEncoder: TransactionEncoder {
    private(set) var submittedTransactions: [EncodedTransaction] = []

    func proposeTransfer(
        accountUUID: AccountUUID,
        recipient: String,
        amount: Zatoshi,
        memoBytes: MemoBytes?
    ) async throws -> Proposal {
        fatalError("Unused in test")
    }

    func proposeShielding(
        accountUUID: AccountUUID,
        shieldingThreshold: Zatoshi,
        memoBytes: MemoBytes?,
        transparentReceiver: String?
    ) async throws -> Proposal? {
        fatalError("Unused in test")
    }

    func createProposedTransactions(
        proposal: Proposal,
        spendingKey: UnifiedSpendingKey
    ) async throws -> [ZcashTransaction.Overview] {
        fatalError("Unused in test")
    }

    func proposeFulfillingPaymentFromURI(
        _ uri: String,
        accountUUID: AccountUUID
    ) async throws -> Proposal {
        fatalError("Unused in test")
    }

    func submit(transaction: EncodedTransaction) async throws {
        submittedTransactions.append(transaction)
    }

    func fetchTransactionsForTxIds(_ txIds: [Data]) async throws -> [ZcashTransaction.Overview] {
        fatalError("Unused in test")
    }

    func closeDBConnection() { }
}
