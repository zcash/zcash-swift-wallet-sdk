//
//  SubmitPlanExecutor.swift
//  ZcashLightClientKit
//
//  Created by Adam Tucker on 2026-05-12.
//

import Foundation

protocol TransactionSubmitter {
    func submit(
        rawTransaction: Data,
        to endpoint: LightWalletEndpoint
    ) async throws

    func submit(
        transaction: EncodedTransaction,
        to endpoint: LightWalletEndpoint
    ) async throws
}

final class EndpointTransactionSubmitter: TransactionSubmitter {
    private let torClient: TorClient
    private let sdkFlags: SDKFlags

    init(
        torClient: TorClient,
        sdkFlags: SDKFlags
    ) {
        self.torClient = torClient
        self.sdkFlags = sdkFlags
    }

    func submit(
        rawTransaction: Data,
        to endpoint: LightWalletEndpoint
    ) async throws {
        try await submit(
            rawTransaction: rawTransaction,
            to: endpoint,
            mode: await sdkFlags.torEnabled ? .uniqueTor : .direct
        )
    }

    func submit(
        transaction: EncodedTransaction,
        to endpoint: LightWalletEndpoint
    ) async throws {
        let mode: ServiceMode
        if await sdkFlags.torEnabled {
            mode = ServiceMode.txIdGroup(prefix: "submit", txId: transaction.transactionId)
        } else {
            mode = .direct
        }

        try await submit(
            rawTransaction: transaction.raw,
            to: endpoint,
            mode: mode
        )
    }

    private func submit(
        rawTransaction: Data,
        to endpoint: LightWalletEndpoint,
        mode: ServiceMode
    ) async throws {
        let service = LightWalletGRPCServiceOverTor(endpoint: endpoint, tor: torClient)
        let response: any LightWalletServiceResponse
        do {
            response = try await service.submit(spendTransaction: rawTransaction, mode: mode)
        } catch {
            await service.closeConnections()
            throw error
        }

        await service.closeConnections()

        guard response.errorCode >= 0 else {
            throw TransactionEncoderError.submitError(
                code: Int(response.errorCode),
                message: response.errorMessage
            )
        }
    }
}

final class SubmitPlanExecutor {
    private let transactionSubmitter: TransactionSubmitter

    init(transactionSubmitter: TransactionSubmitter) {
        self.transactionSubmitter = transactionSubmitter
    }

    func submit(
        transaction: EncodedTransaction,
        submitPlan: TransactionSubmitPlan
    ) async throws {
        var lastError: Error?

        for endpoint in submitPlan.endpoints {
            do {
                try await transactionSubmitter.submit(transaction: transaction, to: endpoint)
                return
            } catch {
                lastError = error
            }
        }

        if let lastError {
            throw lastError
        }
    }
}
