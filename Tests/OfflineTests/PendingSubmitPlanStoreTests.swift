//
//  PendingSubmitPlanStoreTests.swift
//  ZcashLightClientKitTests
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class PendingSubmitPlanStoreTests: ZcashTestCase {
    func testCreatedTransactionsWaitForSubmitPlan() async throws {
        let transaction = makeTransaction(rawID: Data(repeating: 0xAB, count: 32))
        let store = PendingSubmitPlanStore(logger: NullLogger())

        await store.markAwaitingSubmitPlan([transaction])

        switch await store.getSubmitPlan(for: transaction.rawID) {
        case .awaitingPlan:
            break
        default:
            XCTFail("Expected transaction to wait for a submit plan.")
        }
    }

    func testPersistsSubmitPlans() async throws {
        let persistence = InMemorySubmitPlanPersistence()
        let transaction = makeTransaction(rawID: Data(repeating: 0xAB, count: 32))
        let endpoint = LightWalletEndpointBuilder.default
        let firstStore = PendingSubmitPlanStore(persistence: persistence, logger: NullLogger())

        await firstStore.markAwaitingSubmitPlan([transaction])
        await firstStore.addSubmitEndpoint(transaction: transaction, endpoint: endpoint)

        let secondStore = PendingSubmitPlanStore(persistence: persistence, logger: NullLogger())
        switch await secondStore.getSubmitPlan(for: transaction.rawID) {
        case .ready(let plan):
            XCTAssertEqual(plan.endpoints.count, 1)
            assertEndpoint(plan.endpoints[0], equals: endpoint)
        default:
            XCTFail("Expected persisted submit plan.")
        }
    }

    func testAddsSubmittedEndpointsToExistingPlan() async throws {
        let transaction = makeTransaction(rawID: Data(repeating: 0xAB, count: 32))
        let firstEndpoint = LightWalletEndpoint(address: "a.z.cash", port: 443, secure: true)
        let secondEndpoint = LightWalletEndpoint(address: "b.z.cash", port: 443, secure: true)
        let store = PendingSubmitPlanStore(logger: NullLogger())

        await store.markAwaitingSubmitPlan([transaction])
        await store.addSubmitEndpoint(transaction: transaction, endpoint: firstEndpoint)
        await store.addSubmitEndpoint(transaction: transaction, endpoint: secondEndpoint)

        switch await store.getSubmitPlan(for: transaction.rawID) {
        case .ready(let plan):
            XCTAssertEqual(plan.endpoints.count, 2)
            assertEndpoint(plan.endpoints[0], equals: firstEndpoint)
            assertEndpoint(plan.endpoints[1], equals: secondEndpoint)
        default:
            XCTFail("Expected submit plan with both endpoints.")
        }
    }

    func testPrunesPlansThatAreNoLongerResubmissionCandidates() async throws {
        let persistence = InMemorySubmitPlanPersistence()
        let retainedTransaction = makeTransaction(rawID: Data(repeating: 0xAB, count: 32))
        let prunedTransaction = makeTransaction(rawID: Data(repeating: 0xCD, count: 32))
        let store = PendingSubmitPlanStore(persistence: persistence, logger: NullLogger())

        await store.markAwaitingSubmitPlan([retainedTransaction, prunedTransaction])
        await store.addSubmitEndpoint(transaction: retainedTransaction, endpoint: LightWalletEndpointBuilder.default)
        await store.addSubmitEndpoint(transaction: prunedTransaction, endpoint: LightWalletEndpointBuilder.eccTestnet)
        await store.retainPlans(for: [retainedTransaction.rawID])

        let reloadedStore = PendingSubmitPlanStore(persistence: persistence, logger: NullLogger())
        let retainedPlan = await reloadedStore.getSubmitPlan(for: retainedTransaction.rawID)
        let prunedPlan = await reloadedStore.getSubmitPlan(for: prunedTransaction.rawID)
        XCTAssertNotNil(retainedPlan)
        XCTAssertNil(prunedPlan)
    }

    func testTxResubmissionSkipsTransactionsAwaitingSubmitPlan() async throws {
        let awaitingTransaction = makeTransaction(rawID: Data(repeating: 0xAB, count: 32))
        let legacyTransaction = makeTransaction(rawID: Data(repeating: 0xCD, count: 32))
        let transactionRepository = TransactionRepositoryMock()
        let transactionEncoder = RecordingTransactionEncoder()
        let store = PendingSubmitPlanStore(logger: NullLogger())
        let submitter = RecordingTransactionSubmitter()

        transactionRepository.findForResubmissionUpToReturnValue = [
            awaitingTransaction,
            legacyTransaction
        ]

        mockContainer.mock(type: TransactionRepository.self, isSingleton: true) { _ in transactionRepository }
        mockContainer.mock(type: TransactionEncoder.self, isSingleton: true) { _ in transactionEncoder }
        mockContainer.mock(type: PendingSubmitPlanStore.self, isSingleton: true) { _ in store }
        mockContainer.mock(type: SubmitPlanExecutor.self, isSingleton: true) { _ in
            SubmitPlanExecutor(transactionSubmitter: submitter)
        }
        mockContainer.mock(type: Logger.self, isSingleton: true) { _ in NullLogger() }

        await store.markAwaitingSubmitPlan([awaitingTransaction])

        let action = TxResubmissionAction(container: mockContainer)
        action.latestResolvedTime = 0
        _ = try await action.run(with: resubmissionContext()) { _ in }

        XCTAssertEqual(transactionEncoder.submittedTransactions.map(\.transactionId), [legacyTransaction.rawID])
        XCTAssertTrue(submitter.submissions.isEmpty)
    }

    func testTxResubmissionUsesRegisteredSubmitPlan() async throws {
        let transaction = makeTransaction(rawID: Data(repeating: 0xAB, count: 32))
        let endpoint = LightWalletEndpoint(address: "submit.z.cash", port: 443, secure: true)
        let transactionRepository = TransactionRepositoryMock()
        let transactionEncoder = RecordingTransactionEncoder()
        let store = PendingSubmitPlanStore(logger: NullLogger())
        let submitter = RecordingTransactionSubmitter()

        transactionRepository.findForResubmissionUpToReturnValue = [transaction]

        mockContainer.mock(type: TransactionRepository.self, isSingleton: true) { _ in transactionRepository }
        mockContainer.mock(type: TransactionEncoder.self, isSingleton: true) { _ in transactionEncoder }
        mockContainer.mock(type: PendingSubmitPlanStore.self, isSingleton: true) { _ in store }
        mockContainer.mock(type: SubmitPlanExecutor.self, isSingleton: true) { _ in
            SubmitPlanExecutor(transactionSubmitter: submitter)
        }
        mockContainer.mock(type: Logger.self, isSingleton: true) { _ in NullLogger() }

        await store.markAwaitingSubmitPlan([transaction])
        await store.addSubmitEndpoint(transaction: transaction, endpoint: endpoint)

        let action = TxResubmissionAction(container: mockContainer)
        action.latestResolvedTime = 0
        _ = try await action.run(with: resubmissionContext()) { _ in }

        XCTAssertTrue(transactionEncoder.submittedTransactions.isEmpty)
        XCTAssertEqual(submitter.submissions.map(\.transaction.transactionId), [transaction.rawID])
        assertEndpoint(try XCTUnwrap(submitter.submissions.first?.endpoint), equals: endpoint)
    }

    private func resubmissionContext() -> ActionContextMock {
        let context = ActionContextMock.default()
        context.underlyingSyncControlData = SyncControlData(
            latestBlockHeight: 1000,
            latestScannedHeight: nil,
            firstUnenhancedHeight: nil
        )
        return context
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
            raw: Data([0x01, 0x02]),
            rawID: rawID,
            receivedNoteCount: 0,
            sentNoteCount: 1,
            value: Zatoshi(-1_000),
            isExpiredUmined: false,
            totalSpent: nil,
            totalReceived: nil
        )
    }

    private func assertEndpoint(
        _ actual: LightWalletEndpoint,
        equals expected: LightWalletEndpoint,
        file: StaticString = #file,
        line: UInt = #line
    ) {
        XCTAssertEqual(actual.host, expected.host, file: file, line: line)
        XCTAssertEqual(actual.port, expected.port, file: file, line: line)
        XCTAssertEqual(actual.secure, expected.secure, file: file, line: line)
        XCTAssertEqual(
            actual.singleCallTimeoutInMillis,
            expected.singleCallTimeoutInMillis,
            file: file,
            line: line
        )
        XCTAssertEqual(
            actual.streamingCallTimeoutInMillis,
            expected.streamingCallTimeoutInMillis,
            file: file,
            line: line
        )
    }
}

private final class InMemorySubmitPlanPersistence: PendingSubmitPlanPersistence {
    var data: Data?

    func load() throws -> Data? {
        data
    }

    func save(_ data: Data) throws {
        self.data = data
    }

    func clear() throws {
        data = nil
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

private final class RecordingTransactionSubmitter: TransactionSubmitter {
    struct Submission {
        let transaction: EncodedTransaction
        let endpoint: LightWalletEndpoint
    }

    private(set) var submissions: [Submission] = []

    func submit(
        rawTransaction: Data,
        to endpoint: LightWalletEndpoint
    ) async throws {
        fatalError("Unused in test")
    }

    func submit(
        transaction: EncodedTransaction,
        to endpoint: LightWalletEndpoint
    ) async throws {
        submissions.append(Submission(transaction: transaction, endpoint: endpoint))
    }
}
