//
//  BroadcasterTests.swift
//  ZcashLightClientKitTests
//

import Combine
import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class BroadcasterTests: ZcashTestCase {
    private var cancellables: [AnyCancellable] = []

    override func setUp() async throws {
        try await super.setUp()
        cancellables = []
    }

    override func tearDown() async throws {
        cancellables = []
        try await super.tearDown()
    }

    // MARK: - Create

    func testCreateProposedTransactionsReturnsCreatedTransactionsAndEmitsEvent() async throws {
        let rawTransaction = Data([0x01, 0x02, 0x03, 0x04])
        let rawID = Data(repeating: 0xAB, count: 32)
        let overviews = [makeTransaction(raw: rawTransaction, rawID: rawID)]
        let transactionEncoder = StubTransactionEncoder(createdTransactions: overviews)
        let synchronizer = try makeSynchronizer(transactionEncoder: transactionEncoder)

        let foundTransactionsExpectation = XCTestExpectation(description: "found transactions event")
        synchronizer.eventStream
            .sink { event in
                guard case let .foundTransactions(transactions, range) = event else { return }
                XCTAssertNil(range)
                XCTAssertEqual(transactions.map(\.rawID), [rawID])
                foundTransactionsExpectation.fulfill()
            }
            .store(in: &cancellables)

        await synchronizer.updateStatus(.stopped)

        let proposal = Proposal.testOnlyFakeProposal(totalFee: 10)
        let spendingKey = TestsData(networkType: .testnet).spendingKey

        let transactions = try await synchronizer.broadcaster.createProposedTransactions(
            proposal: proposal,
            spendingKey: spendingKey
        )

        XCTAssertEqual(transactions.map(\.txId), [rawID])
        XCTAssertEqual(transactions.map(\.raw), [rawTransaction])
        await fulfillment(of: [foundTransactionsExpectation], timeout: 1.0)
    }

    func testCreateProposedTransactionsContinuesWhenHistoryViewDoesNotContainCreatedTransaction() async throws {
        let rawTransaction = Data([0x01, 0x02, 0x03, 0x04])
        let rawID = Data(repeating: 0xAB, count: 32)
        let overviews = [makeTransaction(raw: rawTransaction, rawID: rawID)]
        let transactionEncoder = StubTransactionEncoder(
            createdTransactions: overviews,
            fetchError: ZcashError.transactionRepositoryEntityNotFound
        )
        let synchronizer = try makeSynchronizer(transactionEncoder: transactionEncoder)
        await synchronizer.updateStatus(.stopped)

        let transactions = try await synchronizer.broadcaster.createProposedTransactions(
            proposal: Proposal.testOnlyFakeProposal(totalFee: 10),
            spendingKey: TestsData(networkType: .testnet).spendingKey
        )

        XCTAssertEqual(transactions.map(\.txId), [rawID])
        XCTAssertEqual(transactions.map(\.raw), [rawTransaction])

        let store = mockContainer.resolve(SubmitPlanStoring.self)
        let plan = await store.plan(for: rawID)
        XCTAssertEqual(plan, StoredSubmitPlan.awaiting)
    }

    func testCreateProposedTransactionsContinuesWhenHistoryEnrichmentThrowsAnotherError() async throws {
        struct TransientHistoryError: Error {}
        let rawTransaction = Data([0x01, 0x02, 0x03, 0x04])
        let rawID = Data(repeating: 0xAC, count: 32)
        let transactionEncoder = StubTransactionEncoder(
            createdTransactions: [makeTransaction(raw: rawTransaction, rawID: rawID)],
            fetchError: TransientHistoryError()
        )
        let synchronizer = try makeSynchronizer(transactionEncoder: transactionEncoder)
        await synchronizer.updateStatus(.stopped)

        let transactions = try await synchronizer.broadcaster.createProposedTransactions(
            proposal: Proposal.testOnlyFakeProposal(totalFee: 10),
            spendingKey: TestsData(networkType: .testnet).spendingKey
        )

        XCTAssertEqual(transactions, [CreatedTransaction(txId: rawID, raw: rawTransaction, expiryHeight: 123_456)])
        let plan = await mockContainer.resolve(SubmitPlanStoring.self).plan(for: rawID)
        XCTAssertEqual(plan, StoredSubmitPlan.awaiting)
    }

    func testCreateProposedTransactionsEmitsAvailableHistoryWhenOnlyOneOverviewIsMissing() async throws {
        let foundRawID = Data(repeating: 0xAB, count: 32)
        let missingRawID = Data(repeating: 0xCD, count: 32)
        let overviews = [
            makeTransaction(raw: Data([0x01]), rawID: foundRawID),
            makeTransaction(raw: Data([0x02]), rawID: missingRawID)
        ]
        let transactionEncoder = StubTransactionEncoder(
            createdTransactions: overviews,
            missingHistoryTxIds: [missingRawID]
        )
        let synchronizer = try makeSynchronizer(transactionEncoder: transactionEncoder)
        let foundTransactionsExpectation = XCTestExpectation(description: "available history event")
        synchronizer.eventStream
            .sink { event in
                guard case let .foundTransactions(transactions, range) = event else { return }
                XCTAssertNil(range)
                XCTAssertEqual(transactions.map(\.rawID), [foundRawID])
                foundTransactionsExpectation.fulfill()
            }
            .store(in: &cancellables)
        await synchronizer.updateStatus(.stopped)

        let transactions = try await synchronizer.broadcaster.createProposedTransactions(
            proposal: Proposal.testOnlyFakeProposal(totalFee: 10),
            spendingKey: TestsData(networkType: .testnet).spendingKey
        )

        XCTAssertEqual(transactions.map(\.txId), [foundRawID, missingRawID])
        await fulfillment(of: [foundTransactionsExpectation], timeout: 1.0)
    }

    func testCreateMarksTransactionsAwaitingSubmission() async throws {
        let rawID = Data(repeating: 0xAB, count: 32)
        let overviews = [makeTransaction(raw: Data([0x01]), rawID: rawID)]
        let transactionEncoder = StubTransactionEncoder(createdTransactions: overviews)
        let synchronizer = try makeSynchronizer(transactionEncoder: transactionEncoder)
        await synchronizer.updateStatus(.stopped)

        _ = try await synchronizer.broadcaster.createProposedTransactions(
            proposal: Proposal.testOnlyFakeProposal(totalFee: 10),
            spendingKey: TestsData(networkType: .testnet).spendingKey
        )

        let store = mockContainer.resolve(SubmitPlanStoring.self)
        let plan = await store.plan(for: rawID)
        XCTAssertEqual(plan, StoredSubmitPlan.awaiting)
    }

    func testWalletTransactionEncoderReadsCreatedTransactionThroughGeneralFFI() async throws {
        let rawID = Data(repeating: 0xBC, count: 32)
        let transactionData = TransactionData(
            txId: rawID,
            raw: Data([0x01, 0x02, 0x03]),
            expiryHeight: 123_456
        )
        let rustBackend = ZcashRustBackendWeldingMock()
        rustBackend.createProposedTransactionsProposalUskReturnValue = [rawID]
        rustBackend.getTransactionTxIdReturnValue = transactionData
        let encoder = WalletTransactionEncoder(
            rustBackend: rustBackend,
            dataDb: try __dataDbURL(),
            fsBlockDbRoot: testTempDirectory,
            service: LightWalletServiceMock(),
            repository: TransactionRepositoryMock(),
            outputParams: try __outputParamsURL(),
            spendParams: try __spendParamsURL(),
            networkType: .testnet,
            logger: submissionLifecycleLogger(),
            sdkFlags: SDKFlags(torEnabled: false, exchangeRateEnabled: false)
        )

        let transactions = try await encoder.createProposedTransactions(
            proposal: Proposal.testOnlyFakeProposal(totalFee: 10),
            spendingKey: TestsData(networkType: .testnet).spendingKey
        )

        XCTAssertEqual(transactions, [CreatedTransaction(transactionData: transactionData)])
        XCTAssertEqual(rustBackend.getTransactionTxIdReceivedTxId, rawID)
    }

    func testWalletTransactionEncoderReportsFailedAndAlreadyReadTransactionIds() async throws {
        let firstTxId = Data(repeating: 0xBC, count: 32)
        let missingTxId = Data(repeating: 0xBD, count: 32)
        let rustBackend = ZcashRustBackendWeldingMock()
        rustBackend.createProposedTransactionsProposalUskReturnValue = [firstTxId, missingTxId]
        rustBackend.getTransactionTxIdClosure = { txId in
            guard txId == firstTxId else { return nil }
            return TransactionData(txId: firstTxId, raw: Data([0x01]), expiryHeight: 123_456)
        }
        let encoder = WalletTransactionEncoder(
            rustBackend: rustBackend,
            dataDb: try __dataDbURL(),
            fsBlockDbRoot: testTempDirectory,
            service: LightWalletServiceMock(),
            repository: TransactionRepositoryMock(),
            outputParams: try __outputParamsURL(),
            spendParams: try __spendParamsURL(),
            networkType: .testnet,
            logger: submissionLifecycleLogger(),
            sdkFlags: SDKFlags(torEnabled: false, exchangeRateEnabled: false)
        )

        do {
            _ = try await encoder.createProposedTransactions(
                proposal: Proposal.testOnlyFakeProposal(totalFee: 10),
                spendingKey: TestsData(networkType: .testnet).spendingKey
            )
            XCTFail("Expected wallet-store readback to fail")
        } catch ZcashError.rustGetTransaction(let message) {
            XCTAssertTrue(message.contains(missingTxId.toHexStringTxId()))
            XCTAssertTrue(message.contains(firstTxId.toHexStringTxId()))
        } catch {
            XCTFail("Expected rustGetTransaction but got \(error.localizedDescription)")
        }
    }

    func testCreateTransactionFromPCZTMarksAwaitingAndEmitsEvent() async throws {
        let rawID = Data(repeating: 0xCD, count: 32)
        let overviews = [makeTransaction(raw: Data([0x05, 0x06]), rawID: rawID)]
        let transactionEncoder = StubTransactionEncoder(createdTransactions: overviews)
        let rustBackend = ZcashRustBackendWeldingMock()
        rustBackend.extractAndStoreTxFromPCZTPcztWithProofsPcztWithSigsReturnValue = rawID
        let synchronizer = try makeSynchronizer(transactionEncoder: transactionEncoder, rustBackend: rustBackend)
        await synchronizer.updateStatus(.stopped)

        let transactions = try await synchronizer.broadcaster.createTransactionFromPCZT(
            pcztWithProofs: Pczt([0x10, 0x11]),
            pcztWithSigs: Pczt([0x12, 0x13])
        )

        XCTAssertEqual(transactions.map(\.txId), [rawID])
        let store = mockContainer.resolve(SubmitPlanStoring.self)
        let plan = await store.plan(for: rawID)
        XCTAssertEqual(plan, StoredSubmitPlan.awaiting)
    }

    func testCreateTransactionFromPCZTContinuesWhenHistoryViewDoesNotContainCreatedTransaction() async throws {
        let rawID = Data(repeating: 0xCD, count: 32)
        let rawTransaction = Data([0x05, 0x06])
        let overviews = [makeTransaction(raw: rawTransaction, rawID: rawID)]
        let transactionEncoder = StubTransactionEncoder(
            createdTransactions: overviews,
            fetchError: ZcashError.transactionRepositoryEntityNotFound
        )
        let rustBackend = ZcashRustBackendWeldingMock()
        rustBackend.extractAndStoreTxFromPCZTPcztWithProofsPcztWithSigsReturnValue = rawID
        let synchronizer = try makeSynchronizer(transactionEncoder: transactionEncoder, rustBackend: rustBackend)
        await synchronizer.updateStatus(.stopped)

        let transactions = try await synchronizer.broadcaster.createTransactionFromPCZT(
            pcztWithProofs: Pczt([0x10, 0x11]),
            pcztWithSigs: Pczt([0x12, 0x13])
        )

        XCTAssertEqual(transactions, [CreatedTransaction(txId: rawID, raw: rawTransaction, expiryHeight: 123_456)])
    }

    func testBroadcasterThrowsWhenNotPrepared() async throws {
        let transactionEncoder = StubTransactionEncoder(createdTransactions: [])
        let synchronizer = try makeSynchronizer(transactionEncoder: transactionEncoder)

        do {
            _ = try await synchronizer.broadcaster.createProposedTransactions(
                proposal: Proposal.testOnlyFakeProposal(totalFee: 10),
                spendingKey: TestsData(networkType: .testnet).spendingKey
            )
            XCTFail("Should throw when synchronizer is not prepared")
        } catch {
            XCTAssertTrue(error is ZcashError, "Expected ZcashError but got \(error)")
        }
    }

    func testBroadcasterThrowsWhenSynchronizerIsReleased() async throws {
        let transactionEncoder = StubTransactionEncoder(createdTransactions: [])
        var synchronizer: SDKSynchronizer? = try makeSynchronizer(transactionEncoder: transactionEncoder)
        await synchronizer?.updateStatus(.stopped)

        let broadcaster = try XCTUnwrap(synchronizer?.broadcaster)
        synchronizer = nil
        await Task.yield()

        do {
            _ = try await broadcaster.createProposedTransactions(
                proposal: Proposal.testOnlyFakeProposal(totalFee: 10),
                spendingKey: TestsData(networkType: .testnet).spendingKey
            )
            XCTFail("Should throw when the owning synchronizer has been released")
        } catch ZcashError.synchronizerNotPrepared {
            // expected
        } catch {
            XCTFail("Expected synchronizerNotPrepared but got \(error)")
        }
    }

    // MARK: - Submit (single, via real local gRPC servers)

    func testSubmitRecordsPlanAndDeliversToEndpoint() async throws {
        let acceptingService = try RecordingCompactTxStreamerService(sendResponse: makeSendResponse(errorCode: 0, errorMessage: ""))
        defer { try? acceptingService.stop() }
        let synchronizer = try makeSynchronizer(transactionEncoder: StubTransactionEncoder(createdTransactions: []))
        let transaction = makeCreatedTransaction()

        let outcome = await synchronizer.broadcaster.submit(
            transaction: transaction,
            to: [acceptingService.endpoint]
        )

        XCTAssertEqual(outcome, TransactionSubmissionOutcome.accepted(by: acceptingService.endpoint))
        XCTAssertEqual(acceptingService.recordedTransactions(), [transaction.raw])

        let store = mockContainer.resolve(SubmitPlanStoring.self)
        let plan = await store.plan(for: transaction.txId)
        XCTAssertEqual(plan, StoredSubmitPlan.ready([acceptingService.endpoint]))
    }

    func testSubmitToRejectingEndpointIsRejected() async throws {
        let rejectingService = try RecordingCompactTxStreamerService(sendResponse: makeSendResponse(errorCode: -25, errorMessage: "rejected"))
        defer { try? rejectingService.stop() }
        let synchronizer = try makeSynchronizer(transactionEncoder: StubTransactionEncoder(createdTransactions: []))

        let outcome = await synchronizer.broadcaster.submit(
            transaction: makeCreatedTransaction(),
            to: [rejectingService.endpoint]
        )

        XCTAssertEqual(outcome, TransactionSubmissionOutcome.rejected(code: -25, message: "rejected"))
    }

    func testSubmitFirstAcceptanceWinsAcrossEndpoints() async throws {
        let acceptingService = try RecordingCompactTxStreamerService(sendResponse: makeSendResponse(errorCode: 0, errorMessage: ""))
        defer { try? acceptingService.stop() }
        let rejectingService = try RecordingCompactTxStreamerService(sendResponse: makeSendResponse(errorCode: -25, errorMessage: "rejected"))
        defer { try? rejectingService.stop() }
        let synchronizer = try makeSynchronizer(transactionEncoder: StubTransactionEncoder(createdTransactions: []))
        let transaction = makeCreatedTransaction()

        let outcome = await synchronizer.broadcaster.submit(
            transaction: transaction,
            to: [rejectingService.endpoint, acceptingService.endpoint],
            timing: SubmissionTiming(responseTimeout: 5, postAcceptanceGraceDelay: 0.2)
        )

        XCTAssertEqual(outcome, TransactionSubmissionOutcome.accepted(by: acceptingService.endpoint))

        let store = mockContainer.resolve(SubmitPlanStoring.self)
        let plan = await store.plan(for: transaction.txId)
        XCTAssertEqual(plan, StoredSubmitPlan.ready([rejectingService.endpoint, acceptingService.endpoint]))
    }

    func testSubmitWithEmptyEndpointsIsUnreachableAndRecordsNoPlan() async throws {
        let synchronizer = try makeSynchronizer(transactionEncoder: StubTransactionEncoder(createdTransactions: []))
        let transaction = makeCreatedTransaction()

        let outcome = await synchronizer.broadcaster.submit(transaction: transaction, to: [])

        XCTAssertEqual(outcome, TransactionSubmissionOutcome.unreachable)
        let store = mockContainer.resolve(SubmitPlanStoring.self)
        let plan = await store.plan(for: transaction.txId)
        XCTAssertNil(plan)
    }

    // MARK: - Submit (batch)

    func testBatchSubmitStopsAfterFirstFailureAndMarksRestNotAttempted() async throws {
        let rejectingService = try RecordingCompactTxStreamerService(sendResponse: makeSendResponse(errorCode: -25, errorMessage: "rejected"))
        defer { try? rejectingService.stop() }
        let synchronizer = try makeSynchronizer(transactionEncoder: StubTransactionEncoder(createdTransactions: []))
        let first = makeCreatedTransaction(seed: 0x01)
        let second = makeCreatedTransaction(seed: 0x02)

        let reports = await synchronizer.broadcaster.submit(
            transactions: [first, second],
            to: [rejectingService.endpoint]
        )

        XCTAssertEqual(reports.count, 2)
        XCTAssertEqual(reports[0].txId, first.txId)
        XCTAssertEqual(reports[0].outcome, TransactionSubmissionOutcome.rejected(code: -25, message: "rejected"))
        XCTAssertEqual(reports[1].txId, second.txId)
        XCTAssertEqual(reports[1].outcome, TransactionSubmissionOutcome.notAttempted)

        // The second transaction was never released — its plan must not exist.
        let store = mockContainer.resolve(SubmitPlanStoring.self)
        let secondPlan = await store.plan(for: second.txId)
        XCTAssertNil(secondPlan)
    }

    func testBatchSubmitAllAccepted() async throws {
        let acceptingService = try RecordingCompactTxStreamerService(sendResponse: makeSendResponse(errorCode: 0, errorMessage: ""))
        defer { try? acceptingService.stop() }
        let synchronizer = try makeSynchronizer(transactionEncoder: StubTransactionEncoder(createdTransactions: []))
        let first = makeCreatedTransaction(seed: 0x03)
        let second = makeCreatedTransaction(seed: 0x04)

        let reports = await synchronizer.broadcaster.submit(
            transactions: [first, second],
            to: [acceptingService.endpoint]
        )

        XCTAssertEqual(reports.map(\.outcome), [
            TransactionSubmissionOutcome.accepted(by: acceptingService.endpoint),
            TransactionSubmissionOutcome.accepted(by: acceptingService.endpoint)
        ])
        XCTAssertEqual(acceptingService.recordedTransactions(), [first.raw, second.raw])
    }

    // MARK: - Legacy Synchronizer APIs (behavior unchanged, no plan rows)

    func testLegacyCreateProposedTransactionsSubmitsOnceAndRecordsNoPlan() async throws {
        let rawID = Data(repeating: 0xAB, count: 32)
        let rawTransaction = Data([0x01, 0x02, 0x03, 0x04])
        let overviews = [makeTransaction(raw: rawTransaction, rawID: rawID)]
        let transactionEncoder = StubTransactionEncoder(createdTransactions: overviews)
        let synchronizer = try makeSynchronizer(transactionEncoder: transactionEncoder)
        await synchronizer.updateStatus(.stopped)

        let stream = try await synchronizer.createProposedTransactions(
            proposal: Proposal.testOnlyFakeProposal(totalFee: 10),
            spendingKey: TestsData(networkType: .testnet).spendingKey
        )
        var iterator = stream.makeAsyncIterator()

        let maybeSubmitResult = try await iterator.next()
        let submitResult = try XCTUnwrap(maybeSubmitResult)
        XCTAssertEqual(submitResult, TransactionSubmitResult.success(txId: rawID))
        let nextSubmitResult = try await iterator.next()
        XCTAssertNil(nextSubmitResult)
        XCTAssertEqual(
            transactionEncoder.submittedTransactions,
            [EncodedTransaction(transactionId: rawID, raw: rawTransaction)]
        )

        let store = mockContainer.resolve(SubmitPlanStoring.self)
        let plan = await store.plan(for: rawID)
        XCTAssertNil(plan, "Legacy path must not register submit plans")
    }

    func testLegacyCreateTransactionFromPCZTSubmitsOnceAndRecordsNoPlan() async throws {
        let rawID = Data(repeating: 0xCD, count: 32)
        let rawTransaction = Data([0x05, 0x06, 0x07, 0x08])
        let overviews = [makeTransaction(raw: rawTransaction, rawID: rawID)]
        let transactionEncoder = StubTransactionEncoder(createdTransactions: overviews)
        let rustBackend = ZcashRustBackendWeldingMock()
        rustBackend.extractAndStoreTxFromPCZTPcztWithProofsPcztWithSigsReturnValue = rawID
        let synchronizer = try makeSynchronizer(transactionEncoder: transactionEncoder, rustBackend: rustBackend)
        await synchronizer.updateStatus(.stopped)

        let stream = try await synchronizer.createTransactionFromPCZT(
            pcztWithProofs: Pczt([0x10, 0x11]),
            pcztWithSigs: Pczt([0x12, 0x13])
        )
        var iterator = stream.makeAsyncIterator()

        let maybeSubmitResult = try await iterator.next()
        let submitResult = try XCTUnwrap(maybeSubmitResult)
        XCTAssertEqual(submitResult, TransactionSubmitResult.success(txId: rawID))

        let store = mockContainer.resolve(SubmitPlanStoring.self)
        let plan = await store.plan(for: rawID)
        XCTAssertNil(plan, "Legacy path must not register submit plans")
    }

    // MARK: - Helpers

    private func makeSynchronizer(
        transactionEncoder: TransactionEncoder,
        rustBackend: ZcashRustBackendWelding? = nil
    ) throws -> SDKSynchronizer {
        let serviceMock = LightWalletServiceMock()
        let transactionRepository = TransactionRepositoryMock()

        if let rustBackend {
            mockContainer.mock(type: ZcashRustBackendWelding.self, isSingleton: true) { _ in rustBackend }
        }
        mockContainer.mock(type: LightWalletService.self, isSingleton: true) { _ in serviceMock }
        mockContainer.mock(type: TransactionRepository.self, isSingleton: true) { _ in transactionRepository }
        mockContainer.mock(type: Logger.self, isSingleton: true) { _ in submissionLifecycleLogger() }

        let initializer = Initializer(
            container: mockContainer,
            cacheDbURL: nil,
            fsBlockDbRoot: testTempDirectory,
            generalStorageURL: testGeneralStorageDirectory,
            dataDbURL: try __dataDbURL(),
            torDirURL: try __torDirURL(),
            endpoint: LightWalletEndpointBuilder.default,
            network: ZcashNetworkBuilder.network(for: .testnet),
            spendParamsURL: try __spendParamsURL(),
            outputParamsURL: try __outputParamsURL(),
            saplingParamsSourceURL: SaplingParamsSourceURL.tests,
            isTorEnabled: false,
            isExchangeRateEnabled: false
        )

        let blockProcessor = CompactBlockProcessor(
            initializer: initializer,
            walletBirthdayProvider: { initializer.walletBirthday }
        )

        return SDKSynchronizer(
            status: .unprepared,
            initializer: initializer,
            transactionEncoder: transactionEncoder,
            transactionRepository: transactionRepository,
            blockProcessor: blockProcessor,
            syncSessionTicker: .live
        )
    }

    private func makeTransaction(raw: Data?, rawID: Data) -> ZcashTransaction.Overview {
        CreatedTransactionTests.makeTransaction(raw: raw, rawID: rawID)
    }

    private func makeCreatedTransaction(seed: UInt8 = 0xAB) -> CreatedTransaction {
        CreatedTransaction(
            txId: Data(repeating: seed, count: 32),
            raw: Data([seed, 0x02, 0x03, 0x04]),
            expiryHeight: 123_456
        )
    }

    private func makeSendResponse(errorCode: Int32, errorMessage: String) -> SendResponse {
        var response = SendResponse()
        response.errorCode = errorCode
        response.errorMessage = errorMessage
        return response
    }
}

// MARK: - Test Doubles

private final class StubTransactionEncoder: TransactionEncoder {
    private let createdTransactions: [CreatedTransaction]
    private let overviews: [ZcashTransaction.Overview]
    private let fetchError: Error?
    private let missingHistoryTxIds: Set<Data>
    private(set) var receivedCreateArguments: (proposal: Proposal, spendingKey: UnifiedSpendingKey)?
    private(set) var receivedFetchTxIds: [Data]?
    private(set) var submittedTransactions: [EncodedTransaction] = []

    init(
        createdTransactions overviews: [ZcashTransaction.Overview],
        fetchError: Error? = nil,
        missingHistoryTxIds: Set<Data> = []
    ) {
        self.overviews = overviews
        self.createdTransactions = overviews.map { overview in
            guard let raw = overview.raw else {
                XCTFail("StubTransactionEncoder requires raw transaction bytes")
                return CreatedTransaction(txId: overview.rawID, raw: Data(), expiryHeight: overview.expiryHeight)
            }
            return CreatedTransaction(txId: overview.rawID, raw: raw, expiryHeight: overview.expiryHeight)
        }
        self.fetchError = fetchError
        self.missingHistoryTxIds = missingHistoryTxIds
    }

    func proposeTransfer(
        accountUUID: AccountUUID,
        recipient: String,
        amount: Zatoshi,
        memoBytes: MemoBytes?
    ) async throws -> Proposal {
        fatalError("Unused in test")
    }

    func proposeSendMax(
        accountUUID: AccountUUID,
        recipient: String,
        memo: MemoBytes?,
        mode: MaxSpendMode
    ) async throws -> Proposal {
        fatalError("Unused in test")
    }

    func proposeOrchardToIronwoodMigration(accountUUID: AccountUUID) async throws -> Proposal {
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
    ) async throws -> [CreatedTransaction] {
        receivedCreateArguments = (proposal, spendingKey)
        return createdTransactions
    }

    func createdTransactions(forTxIds txIds: [Data]) async throws -> [CreatedTransaction] {
        txIds.compactMap { txId in
            createdTransactions.first { $0.txId == txId }
        }
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

    func isTransactionKnownToServer(txId: Data) async -> Bool {
        false
    }

    func fetchTransactionsForTxIds(_ txIds: [Data]) async throws -> [ZcashTransaction.Overview] {
        receivedFetchTxIds = txIds
        if let fetchError {
            throw fetchError
        }
        if txIds.contains(where: missingHistoryTxIds.contains) {
            throw ZcashError.transactionRepositoryEntityNotFound
        }
        return txIds.compactMap { txId in
            overviews.first { $0.rawID == txId }
        }
    }

    func closeDBConnection() { }
}
