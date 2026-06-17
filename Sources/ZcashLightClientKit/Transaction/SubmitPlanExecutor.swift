//
//  SubmitPlanExecutor.swift
//  ZcashLightClientKit
//

import Foundation

/// Background-retry executor: tries the recorded plan endpoints sequentially
/// until one accepts. Background retry stays gentle — no fan-out.
/// An empty endpoint list returns without submitting.
final class SubmitPlanExecutor {
    private let endpointSubmitter: EndpointSubmitter
    private let logger: Logger

    init(endpointSubmitter: EndpointSubmitter, logger: Logger) {
        self.endpointSubmitter = endpointSubmitter
        self.logger = logger
    }

    func submit(transaction: CreatedTransaction, endpoints: [LightWalletEndpoint]) async throws {
        let txId = transaction.txId.toHexStringTxId()
        logger.debug("Transaction \(txId) background retry across \(endpoints.count) recorded endpoint(s).")
        var lastError: Error?

        for endpoint in endpoints {
            try Task.checkCancellation()
            do {
                try await endpointSubmitter.submit(transaction: transaction, to: endpoint)
                logger.debug("Transaction \(txId) background retry accepted by \(endpoint.host):\(endpoint.port).")
                return
            } catch {
                logger.warn("Transaction \(txId) background retry to \(endpoint.host):\(endpoint.port) failed: \(error)")
                lastError = error
            }
        }

        if let lastError {
            logger.warn("Transaction \(txId) background retry exhausted all \(endpoints.count) recorded endpoint(s).")
            throw lastError
        }
    }
}
