//
//  SDKBroadcaster.swift
//  ZcashLightClientKit
//
//  Created by Adam Tucker on 2026-04-15.
//

import Combine
import Foundation

class SDKBroadcaster: Broadcaster {
    private let transactionEncoder: TransactionEncoder
    private let initializer: Initializer
    private let logger: Logger
    private let eventSubject: PassthroughSubject<SynchronizerEvent, Never>
    private let statusCheck: () throws -> Void
    private let pendingSubmitPlanStore: PendingSubmitPlanStore
    private let transactionSubmitter: TransactionSubmitter
    private let rawTransactionLookup: RawTransactionLookup?

    init(
        transactionEncoder: TransactionEncoder,
        initializer: Initializer,
        logger: Logger,
        eventSubject: PassthroughSubject<SynchronizerEvent, Never>,
        pendingSubmitPlanStore: PendingSubmitPlanStore,
        transactionSubmitter: TransactionSubmitter,
        rawTransactionLookup: RawTransactionLookup?,
        statusCheck: @escaping () throws -> Void
    ) {
        self.transactionEncoder = transactionEncoder
        self.initializer = initializer
        self.logger = logger
        self.eventSubject = eventSubject
        self.pendingSubmitPlanStore = pendingSubmitPlanStore
        self.transactionSubmitter = transactionSubmitter
        self.rawTransactionLookup = rawTransactionLookup
        self.statusCheck = statusCheck
    }

    func createProposedTransactions(
        proposal: Proposal,
        spendingKey: UnifiedSpendingKey
    ) async throws -> [ZcashTransaction.Overview] {
        try statusCheck()

        try await SaplingParameterDownloader.downloadParamsIfnotPresent(
            spendURL: initializer.spendParamsURL,
            spendSourceURL: initializer.saplingParamsSourceURL.spendParamFileURL,
            outputURL: initializer.outputParamsURL,
            outputSourceURL: initializer.saplingParamsSourceURL.outputParamFileURL,
            logger: logger
        )

        let transactions = try await transactionEncoder.createProposedTransactions(
            proposal: proposal,
            spendingKey: spendingKey
        )

        await pendingSubmitPlanStore.markAwaitingSubmitPlan(transactions)
        sendFoundTransactionsEvent(transactions)

        return transactions
    }

    func createProposedTransactionsForLegacySubmit(
        proposal: Proposal,
        spendingKey: UnifiedSpendingKey
    ) async throws -> [ZcashTransaction.Overview] {
        let transactions = try await createProposedTransactionsWithoutRegisteringSubmitPlan(
            proposal: proposal,
            spendingKey: spendingKey
        )
        sendFoundTransactionsEvent(transactions)
        return transactions
    }

    func createTransactionFromPCZT(
        pcztWithProofs: Pczt,
        pcztWithSigs: Pczt
    ) async throws -> [ZcashTransaction.Overview] {
        try statusCheck()

        try await SaplingParameterDownloader.downloadParamsIfnotPresent(
            spendURL: initializer.spendParamsURL,
            spendSourceURL: initializer.saplingParamsSourceURL.spendParamFileURL,
            outputURL: initializer.outputParamsURL,
            outputSourceURL: initializer.saplingParamsSourceURL.outputParamFileURL,
            logger: logger
        )

        let txId = try await initializer.rustBackend.extractAndStoreTxFromPCZT(
            pcztWithProofs: pcztWithProofs,
            pcztWithSigs: pcztWithSigs
        )

        let transactions = try await transactionEncoder.fetchTransactionsForTxIds([txId])
        await pendingSubmitPlanStore.markAwaitingSubmitPlan(transactions)
        sendFoundTransactionsEvent(transactions)

        return transactions
    }

    func createTransactionFromPCZTForLegacySubmit(
        pcztWithProofs: Pczt,
        pcztWithSigs: Pczt
    ) async throws -> [ZcashTransaction.Overview] {
        let transactions = try await createTransactionFromPCZTWithoutRegisteringSubmitPlan(
            pcztWithProofs: pcztWithProofs,
            pcztWithSigs: pcztWithSigs
        )
        sendFoundTransactionsEvent(transactions)
        return transactions
    }

    func submit(
        _ rawTransaction: Data,
        to endpoint: LightWalletEndpoint
    ) async throws {
        if let transaction = try? await rawTransactionLookup?.find(rawTransaction: rawTransaction) {
            await pendingSubmitPlanStore.addSubmitEndpoint(transaction: transaction, endpoint: endpoint)
            try await transactionSubmitter.submit(
                transaction: EncodedTransaction(transactionId: transaction.rawID, raw: rawTransaction),
                to: endpoint
            )
        } else {
            await pendingSubmitPlanStore.addSubmitEndpoint(rawTransaction: rawTransaction, endpoint: endpoint)
            try await transactionSubmitter.submit(rawTransaction: rawTransaction, to: endpoint)
        }
    }

    private func createProposedTransactionsWithoutRegisteringSubmitPlan(
        proposal: Proposal,
        spendingKey: UnifiedSpendingKey
    ) async throws -> [ZcashTransaction.Overview] {
        try statusCheck()

        try await SaplingParameterDownloader.downloadParamsIfnotPresent(
            spendURL: initializer.spendParamsURL,
            spendSourceURL: initializer.saplingParamsSourceURL.spendParamFileURL,
            outputURL: initializer.outputParamsURL,
            outputSourceURL: initializer.saplingParamsSourceURL.outputParamFileURL,
            logger: logger
        )

        return try await transactionEncoder.createProposedTransactions(
            proposal: proposal,
            spendingKey: spendingKey
        )
    }

    private func createTransactionFromPCZTWithoutRegisteringSubmitPlan(
        pcztWithProofs: Pczt,
        pcztWithSigs: Pczt
    ) async throws -> [ZcashTransaction.Overview] {
        try statusCheck()

        try await SaplingParameterDownloader.downloadParamsIfnotPresent(
            spendURL: initializer.spendParamsURL,
            spendSourceURL: initializer.saplingParamsSourceURL.spendParamFileURL,
            outputURL: initializer.outputParamsURL,
            outputSourceURL: initializer.saplingParamsSourceURL.outputParamFileURL,
            logger: logger
        )

        let txId = try await initializer.rustBackend.extractAndStoreTxFromPCZT(
            pcztWithProofs: pcztWithProofs,
            pcztWithSigs: pcztWithSigs
        )

        return try await transactionEncoder.fetchTransactionsForTxIds([txId])
    }

    private func sendFoundTransactionsEvent(_ transactions: [ZcashTransaction.Overview]) {
        if !transactions.isEmpty {
            eventSubject.send(.foundTransactions(transactions, nil))
        }
    }
}
