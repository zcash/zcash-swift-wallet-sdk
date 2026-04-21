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
    private let sdkFlags: SDKFlags
    private let logger: Logger
    private let eventSubject: PassthroughSubject<SynchronizerEvent, Never>
    private let statusCheck: () throws -> Void

    init(
        transactionEncoder: TransactionEncoder,
        initializer: Initializer,
        sdkFlags: SDKFlags,
        logger: Logger,
        eventSubject: PassthroughSubject<SynchronizerEvent, Never>,
        statusCheck: @escaping () throws -> Void
    ) {
        self.transactionEncoder = transactionEncoder
        self.initializer = initializer
        self.sdkFlags = sdkFlags
        self.logger = logger
        self.eventSubject = eventSubject
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

        if !transactions.isEmpty {
            eventSubject.send(.foundTransactions(transactions, nil))
        }

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

        if !transactions.isEmpty {
            eventSubject.send(.foundTransactions(transactions, nil))
        }

        return transactions
    }

    func submit(
        _ rawTransaction: Data,
        to endpoint: LightWalletEndpoint
    ) async throws {
        try statusCheck()

        let torClient = initializer.container.resolve(TorClient.self)
        let service = LightWalletGRPCServiceOverTor(endpoint: endpoint, tor: torClient)
        defer { Task { await service.closeConnections() } }

        let mode: ServiceMode = await sdkFlags.torEnabled ? .uniqueTor : .direct
        let response = try await service.submit(spendTransaction: rawTransaction, mode: mode)

        guard response.errorCode >= 0 else {
            throw TransactionEncoderError.submitError(
                code: Int(response.errorCode),
                message: response.errorMessage
            )
        }
    }
}
