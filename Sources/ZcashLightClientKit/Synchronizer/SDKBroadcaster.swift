//
//  SDKBroadcaster.swift
//  ZcashLightClientKit
//

import Combine
import Foundation

final class SDKBroadcaster: Broadcaster {
    private let transactionEncoder: TransactionEncoder
    private let initializer: Initializer
    private let logger: Logger
    private let eventSubject: PassthroughSubject<SynchronizerEvent, Never>
    private let submitPlanStore: SubmitPlanStoring
    private let multiEndpointSubmitter: MultiEndpointSubmitter
    private let statusCheck: () throws -> Void

    init(
        transactionEncoder: TransactionEncoder,
        initializer: Initializer,
        logger: Logger,
        eventSubject: PassthroughSubject<SynchronizerEvent, Never>,
        submitPlanStore: SubmitPlanStoring,
        multiEndpointSubmitter: MultiEndpointSubmitter,
        statusCheck: @escaping () throws -> Void
    ) {
        self.transactionEncoder = transactionEncoder
        self.initializer = initializer
        self.logger = logger
        self.eventSubject = eventSubject
        self.submitPlanStore = submitPlanStore
        self.multiEndpointSubmitter = multiEndpointSubmitter
        self.statusCheck = statusCheck
    }

    // MARK: - Broadcaster conformance

    func createProposedTransactions(
        proposal: Proposal,
        spendingKey: UnifiedSpendingKey
    ) async throws -> [CreatedTransaction] {
        try await createProposedTransactions(proposal: proposal, spendingKey: spendingKey, recordingPlans: true)
    }

    func createTransactionFromPCZT(
        pcztWithProofs: Pczt,
        pcztWithSigs: Pczt
    ) async throws -> [CreatedTransaction] {
        try await createTransactionFromPCZT(pcztWithProofs: pcztWithProofs, pcztWithSigs: pcztWithSigs, recordingPlans: true)
    }

    func submit(
        transaction: CreatedTransaction,
        to endpoints: [LightWalletEndpoint],
        timing: SubmissionTiming
    ) async -> TransactionSubmissionOutcome {
        let txId = transaction.txId.toHexStringTxId()

        guard !endpoints.isEmpty else {
            logger.debug("Transaction \(txId) submit requested with no endpoints; nothing sent, transaction stays awaiting.")
            return .unreachable
        }

        let endpointList = endpoints.map { "\($0.host):\($0.port)" }.joined(separator: ", ")
        logger.debug("Transaction \(txId) submitting to \(endpoints.count) endpoint(s): \(endpointList).")

        // Record before any network attempt so a cancelled or timed-out race
        // still leaves the intended retry plan behind.
        await submitPlanStore.recordPlan(txId: transaction.txId, endpoints: endpoints)

        let outcome = await multiEndpointSubmitter.submit(transaction: transaction, to: endpoints, timing: timing)
        logger.debug("Transaction \(txId) submission \(outcome.logDescription).")
        return outcome
    }

    func submit(
        transactions: [CreatedTransaction],
        to endpoints: [LightWalletEndpoint],
        timing: SubmissionTiming
    ) async -> [TransactionSubmissionReport] {
        logger.debug("Batch submitting \(transactions.count) transaction(s).")
        var reports: [TransactionSubmissionReport] = []
        var stopped = false

        for transaction in transactions {
            let txId = transaction.txId.toHexStringTxId()
            if stopped {
                logger.debug("Transaction \(txId) not attempted; an earlier transaction in the batch was not accepted.")
                reports.append(TransactionSubmissionReport(txId: transaction.txId, outcome: .notAttempted))
                continue
            }

            let outcome = await submit(transaction: transaction, to: endpoints, timing: timing)
            reports.append(TransactionSubmissionReport(txId: transaction.txId, outcome: outcome))

            if case .accepted = outcome {
                continue
            }
            logger.debug("Batch stopping after \(txId) was \(outcome.logDescription); remaining marked not attempted.")
            stopped = true
        }

        return reports
    }

    // MARK: - Internal create paths (legacy callers pass recordingPlans: false)

    func createProposedTransactions(
        proposal: Proposal,
        spendingKey: UnifiedSpendingKey,
        recordingPlans: Bool
    ) async throws -> [CreatedTransaction] {
        try statusCheck()
        try await downloadSaplingParamsIfNeeded()

        let overviews = try await transactionEncoder.createProposedTransactions(
            proposal: proposal,
            spendingKey: spendingKey
        )

        return try await finishCreation(overviews: overviews, recordingPlans: recordingPlans)
    }

    func createTransactionFromPCZT(
        pcztWithProofs: Pczt,
        pcztWithSigs: Pczt,
        recordingPlans: Bool
    ) async throws -> [CreatedTransaction] {
        try statusCheck()
        try await downloadSaplingParamsIfNeeded()

        let txId = try await initializer.rustBackend.extractAndStoreTxFromPCZT(
            pcztWithProofs: pcztWithProofs,
            pcztWithSigs: pcztWithSigs
        )

        let overviews = try await transactionEncoder.fetchTransactionsForTxIds([txId])

        return try await finishCreation(overviews: overviews, recordingPlans: recordingPlans)
    }

    // MARK: - Private

    private func downloadSaplingParamsIfNeeded() async throws {
        try await SaplingParameterDownloader.downloadParamsIfnotPresent(
            spendURL: initializer.spendParamsURL,
            spendSourceURL: initializer.saplingParamsSourceURL.spendParamFileURL,
            outputURL: initializer.outputParamsURL,
            outputSourceURL: initializer.saplingParamsSourceURL.outputParamFileURL,
            logger: logger
        )
    }

    private func finishCreation(
        overviews: [ZcashTransaction.Overview],
        recordingPlans: Bool
    ) async throws -> [CreatedTransaction] {
        let createdTransactions = try overviews.map { try CreatedTransaction(overview: $0) }

        let txIdList = createdTransactions.map { $0.txId.toHexStringTxId() }.joined(separator: ", ")
        if recordingPlans {
            logger.debug("Created \(createdTransactions.count) transaction(s) awaiting submission by the app: \(txIdList).")
            await submitPlanStore.markAwaitingSubmission(txIds: createdTransactions.map(\.txId))
        } else {
            logger.debug("Created \(createdTransactions.count) transaction(s) for immediate submission: \(txIdList).")
        }

        if !overviews.isEmpty {
            eventSubject.send(.foundTransactions(overviews, nil))
        }

        return createdTransactions
    }
}
