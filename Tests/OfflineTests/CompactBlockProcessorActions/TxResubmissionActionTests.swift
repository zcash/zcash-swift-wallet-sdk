//
//  TxResubmissionActionTests.swift
//  ZcashLightClientKitTests
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class TxResubmissionActionTests: ZcashTestCase {
    private var transactionRepository: TransactionRepositoryMock!
    private var transactionEncoder: StubTransactionEncoder!
    private var submitPlanStore: SubmitPlanStoringMock!
    private var endpointSubmitter: EndpointSubmitterMock!
    private var rustBackend: ZcashRustBackendWeldingMock!

    private let latestBlockHeight = BlockHeight(2_000_000)

    private var endpointA: LightWalletEndpoint {
        LightWalletEndpoint(address: "a.example.com", port: 443, secure: true)
    }

    private func makeOverview(
        rawID: Data,
        minedHeight: BlockHeight? = nil,
        expiryHeight: BlockHeight? = 3_000_000
    ) -> ZcashTransaction.Overview {
        ZcashTransaction.Overview(
            accountUUID: TestsData.mockedAccountUUID,
            blockTime: nil,
            expiryHeight: expiryHeight,
            fee: Zatoshi(10_000),
            index: 0,
            isShielding: false,
            hasChange: false,
            memoCount: 0,
            minedHeight: minedHeight,
            raw: Data([0x01, 0x02, 0x03]),
            rawID: rawID,
            receivedNoteCount: 0,
            sentNoteCount: 1,
            value: Zatoshi(-1_000),
            isExpiredUmined: false,
            totalSpent: nil,
            totalReceived: nil,
            spentNoteCount: 0,
            poolCrossingValue: nil,
            isTrusted: false,
            zip318Kind: .notClassified
        )
    }

    private func setupAction(
        candidates: [ZcashTransaction.Overview],
        encoderTransactions: [ZcashTransaction.Overview] = []
    ) -> TxResubmissionAction {
        transactionRepository = TransactionRepositoryMock()
        transactionRepository.findForResubmissionUpToClosure = { _ in candidates }
        transactionEncoder = StubTransactionEncoder(createdTransactions: encoderTransactions)
        submitPlanStore = SubmitPlanStoringMock()
        endpointSubmitter = EndpointSubmitterMock()
        // Unconfigured, `getTransaction` returns nil, i.e. "the wallet store does not hold this
        // transaction". Tests that need it to hold one set `getTransactionTxIdClosure`.
        rustBackend = ZcashRustBackendWeldingMock()

        mockContainer.mock(type: ZcashRustBackendWelding.self, isSingleton: true) { _ in self.rustBackend }
        mockContainer.mock(type: TransactionRepository.self, isSingleton: true) { _ in self.transactionRepository }
        mockContainer.mock(type: TransactionEncoder.self, isSingleton: true) { _ in self.transactionEncoder }
        mockContainer.mock(type: SubmitPlanStoring.self, isSingleton: true) { _ in self.submitPlanStore }
        mockContainer.mock(type: Logger.self, isSingleton: true) { _ in submissionLifecycleLogger() }
        mockContainer.mock(type: SubmitPlanExecutor.self, isSingleton: true) { _ in
            SubmitPlanExecutor(endpointSubmitter: self.endpointSubmitter, logger: submissionLifecycleLogger())
        }

        let action = TxResubmissionAction(container: mockContainer)
        // Push the throttle back so tests exercise the resubmit branch.
        // The first-invocation throttle is covered by its own test.
        action.latestResolvedTime = 0
        return action
    }

    private func makeContext() -> ActionContextMock {
        let context = ActionContextMock.default()
        context.prevState = .enhance
        context.underlyingSyncControlData = SyncControlData(
            latestBlockHeight: latestBlockHeight,
            latestScannedHeight: nil,
            firstUnenhancedHeight: nil
        )
        return context
    }

    func testAwaitingTransactionIsSkipped() async throws {
        let rawID = Data(repeating: 0x01, count: 32)
        let candidate = makeOverview(rawID: rawID)
        let action = setupAction(candidates: [candidate])
        await submitPlanStore.markAwaitingSubmission(txIds: [rawID])
        // Make the repository confirm the candidate is alive so pruning keeps it.
        transactionRepository.findRawIDClosure = { _ in candidate }

        _ = try await action.run(with: makeContext()) { _ in }

        XCTAssertTrue(transactionEncoder.submittedTransactions.isEmpty, "Awaiting transactions must not be submitted")
        XCTAssertTrue(endpointSubmitter.recordedSubmissions().isEmpty)
        let plan = await submitPlanStore.plan(for: rawID)
        XCTAssertEqual(plan, StoredSubmitPlan.awaiting, "Awaiting plan must survive")
    }

    func testReadyTransactionIsResubmittedThroughPlanEndpoints() async throws {
        let rawID = Data(repeating: 0x02, count: 32)
        let candidate = makeOverview(rawID: rawID)
        let action = setupAction(candidates: [candidate])
        await submitPlanStore.recordPlan(txId: rawID, endpoints: [endpointA])
        transactionRepository.findRawIDClosure = { _ in candidate }

        _ = try await action.run(with: makeContext()) { _ in }

        XCTAssertEqual(endpointSubmitter.recordedSubmissions().map(\.host), ["a.example.com"])
        XCTAssertTrue(transactionEncoder.submittedTransactions.isEmpty, "Plan transactions must not use the default endpoint")
    }

    func testLegacyTransactionUsesDefaultEncoderSubmit() async throws {
        let rawID = Data(repeating: 0x03, count: 32)
        let candidate = makeOverview(rawID: rawID)
        let action = setupAction(candidates: [candidate])

        _ = try await action.run(with: makeContext()) { _ in }

        XCTAssertEqual(transactionEncoder.submittedTransactions.count, 1)
        XCTAssertEqual(transactionEncoder.submittedTransactions.first?.transactionId, rawID)
        XCTAssertTrue(endpointSubmitter.recordedSubmissions().isEmpty)
    }

    func testPruningRemovesExpiredMissingAndNilExpiryPlansButKeepsMinedUntilExpiry() async throws {
        let minedUnexpiredTxId = Data(repeating: 0x04, count: 32)
        let expiredTxId = Data(repeating: 0x05, count: 32)
        let minedExpiredTxId = Data(repeating: 0x0B, count: 32)
        let missingTxId = Data(repeating: 0x06, count: 32)
        let nilExpiryTxId = Data(repeating: 0x08, count: 32)
        let aliveTxId = Data(repeating: 0x07, count: 32)

        let action = setupAction(candidates: [])
        await submitPlanStore.recordPlan(txId: minedUnexpiredTxId, endpoints: [endpointA])
        await submitPlanStore.recordPlan(txId: expiredTxId, endpoints: [endpointA])
        await submitPlanStore.recordPlan(txId: minedExpiredTxId, endpoints: [endpointA])
        await submitPlanStore.recordPlan(txId: missingTxId, endpoints: [endpointA])
        await submitPlanStore.recordPlan(txId: nilExpiryTxId, endpoints: [endpointA])
        await submitPlanStore.recordPlan(txId: aliveTxId, endpoints: [endpointA])

        transactionRepository.findRawIDClosure = { rawID in
            if rawID == minedUnexpiredTxId {
                return self.makeOverview(rawID: rawID, minedHeight: 1_999_000)
            }
            if rawID == expiredTxId {
                return self.makeOverview(rawID: rawID, expiryHeight: 1_999_999)
            }
            if rawID == minedExpiredTxId {
                return self.makeOverview(rawID: rawID, minedHeight: 1_999_000, expiryHeight: 1_999_999)
            }
            if rawID == missingTxId {
                throw ZcashError.transactionRepositoryEntityNotFound
            }
            if rawID == nilExpiryTxId {
                return self.makeOverview(rawID: rawID, expiryHeight: nil)
            }
            return self.makeOverview(rawID: rawID)
        }

        _ = try await action.run(with: makeContext()) { _ in }

        let remaining = await submitPlanStore.allPlannedTransactionIds()
        // The mined-but-unexpired plan survives: a reorg could un-mine the
        // transaction, and its retries must still use the recorded endpoints.
        XCTAssertEqual(Set(remaining), Set([aliveTxId, minedUnexpiredTxId]))
    }

    /// A transaction the history view does not project, but which the wallet store holds and which
    /// has not expired, must keep its submit plan.
    ///
    /// `v_transactions` omits a stored transaction whenever none of its inputs was recorded and it
    /// has no wallet-internal output, which is the shape of a shielding or cross-pay send. Reading
    /// that omission as "the transaction is gone" destroys the endpoints the user chose for
    /// multi-endpoint submission, and it does so for precisely the transactions that most need a
    /// retry, since they are also the ones `findForResubmission` cannot see.
    func testPlanSurvivesWhenTheTransactionIsMissingFromHistoryButHeldByTheWalletStore() async throws {
        let hiddenTxId = Data(repeating: 0x0E, count: 32)

        let action = setupAction(candidates: [])
        await submitPlanStore.recordPlan(txId: hiddenTxId, endpoints: [endpointA])

        transactionRepository.findRawIDClosure = { _ in
            throw ZcashError.transactionRepositoryEntityNotFound
        }
        rustBackend.getTransactionTxIdClosure = { txId in
            guard txId == hiddenTxId else { return nil }
            return TransactionData(
                txId: hiddenTxId,
                raw: Data([0x01, 0x02, 0x03]),
                expiryHeight: 3_000_000
            )
        }

        _ = try await action.run(with: makeContext()) { _ in }

        let remaining = await submitPlanStore.allPlannedTransactionIds()
        XCTAssertEqual(
            Set(remaining),
            Set([hiddenTxId]),
            "absence from the history projection is not evidence that the transaction is gone"
        )
    }

    /// The counterpart: when the wallet store does not hold the transaction either, the plan is
    /// genuinely orphaned and is still pruned. Without this, the fix above would simply leak plans.
    func testPlanIsPrunedWhenNeitherHistoryNorTheWalletStoreHoldsTheTransaction() async throws {
        let goneTxId = Data(repeating: 0x0F, count: 32)

        let action = setupAction(candidates: [])
        await submitPlanStore.recordPlan(txId: goneTxId, endpoints: [endpointA])

        transactionRepository.findRawIDClosure = { _ in
            throw ZcashError.transactionRepositoryEntityNotFound
        }
        rustBackend.getTransactionTxIdClosure = { _ in nil }

        _ = try await action.run(with: makeContext()) { _ in }

        let remaining = await submitPlanStore.allPlannedTransactionIds()
        XCTAssertTrue(remaining.isEmpty, "a plan for a transaction no store holds is orphaned")
    }

    /// A failed wallet-store read must not be read as absence either: the plan is kept and the
    /// check retried on the next pass, matching how an unknown repository error is handled.
    func testPlanSurvivesWhenTheWalletStoreLookupFails() async throws {
        let txId = Data(repeating: 0x10, count: 32)

        let action = setupAction(candidates: [])
        await submitPlanStore.recordPlan(txId: txId, endpoints: [endpointA])

        transactionRepository.findRawIDClosure = { _ in
            throw ZcashError.transactionRepositoryEntityNotFound
        }
        rustBackend.getTransactionTxIdClosure = { _ in
            throw ZcashError.rustGetTransaction("boom")
        }

        _ = try await action.run(with: makeContext()) { _ in }

        let remaining = await submitPlanStore.allPlannedTransactionIds()
        XCTAssertEqual(Set(remaining), Set([txId]), "an errored lookup is not evidence of absence")
    }

    func testStoreUnavailableSkipsResubmission() async throws {
        let rawID = Data(repeating: 0x0C, count: 32)
        let candidate = makeOverview(rawID: rawID)
        let action = setupAction(candidates: [candidate])
        submitPlanStore.storeUnavailable = true
        transactionRepository.findRawIDClosure = { _ in candidate }

        _ = try await action.run(with: makeContext()) { _ in }

        XCTAssertTrue(
            transactionEncoder.submittedTransactions.isEmpty,
            "An unreadable plan store must not fall back to the default-endpoint submit"
        )
        XCTAssertTrue(endpointSubmitter.recordedSubmissions().isEmpty)
    }

    func testOneFailingPlanDoesNotStarveOtherCandidates() async throws {
        let planTxId = Data(repeating: 0x0D, count: 32)
        let legacyTxId = Data(repeating: 0x0E, count: 32)
        let planCandidate = makeOverview(rawID: planTxId)
        let legacyCandidate = makeOverview(rawID: legacyTxId)
        let action = setupAction(candidates: [planCandidate, legacyCandidate])
        await submitPlanStore.recordPlan(txId: planTxId, endpoints: [endpointA])
        endpointSubmitter.set(behavior: .failTransport, for: endpointA)
        transactionRepository.findRawIDClosure = { rawID in
            rawID == planTxId ? planCandidate : legacyCandidate
        }

        _ = try await action.run(with: makeContext()) { _ in }

        XCTAssertEqual(
            transactionEncoder.submittedTransactions.map(\.transactionId),
            [legacyTxId],
            "A failing plan retry must not abort resubmission of the remaining candidates"
        )
    }

    func testNoCandidatesStillPrunes() async throws {
        let staleTxId = Data(repeating: 0x09, count: 32)
        let action = setupAction(candidates: [])
        await submitPlanStore.recordPlan(txId: staleTxId, endpoints: [endpointA])
        transactionRepository.findRawIDClosure = { _ in
            throw ZcashError.transactionRepositoryEntityNotFound
        }

        _ = try await action.run(with: makeContext()) { _ in }

        let remaining = await submitPlanStore.allPlannedTransactionIds()
        XCTAssertTrue(remaining.isEmpty)
    }

    func testFreshActionThrottlesFirstInvocation() async throws {
        let rawID = Data(repeating: 0x0F, count: 32)
        let candidate = makeOverview(rawID: rawID)
        let action = setupAction(candidates: [candidate])
        // Undo the test-only push: a freshly constructed action should not
        // resubmit on its first invocation, even when candidates are present.
        action.latestResolvedTime = Date().timeIntervalSince1970
        transactionRepository.findRawIDClosure = { _ in candidate }

        _ = try await action.run(with: makeContext()) { _ in }

        XCTAssertTrue(
            transactionEncoder.submittedTransactions.isEmpty,
            "Fresh action must not resubmit before the throttle window elapses"
        )
        XCTAssertTrue(endpointSubmitter.recordedSubmissions().isEmpty)
    }

    func testUnknownRepositoryErrorKeepsPlanDuringPruning() async throws {
        struct TransientDatabaseError: Error {}
        let txId = Data(repeating: 0x0A, count: 32)
        let action = setupAction(candidates: [])
        await submitPlanStore.recordPlan(txId: txId, endpoints: [endpointA])
        transactionRepository.findRawIDClosure = { _ in
            throw TransientDatabaseError()
        }

        _ = try await action.run(with: makeContext()) { _ in }

        let remaining = await submitPlanStore.allPlannedTransactionIds()
        XCTAssertEqual(remaining, [txId], "A transient repository error must not prune a live retry plan")
    }
}
