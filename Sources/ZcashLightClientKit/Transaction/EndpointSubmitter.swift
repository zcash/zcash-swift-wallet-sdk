//
//  EndpointSubmitter.swift
//  ZcashLightClientKit
//

import Foundation

/// Submits one transaction to one endpoint. The mock seam for offline tests.
protocol EndpointSubmitter {
    /// - Throws: `TransactionEncoderError.submitError` when the server rejects
    ///   the transaction; any other error indicates a transport-level failure.
    func submit(transaction: CreatedTransaction, to endpoint: LightWalletEndpoint) async throws
}

/// Submits over an ephemeral gRPC connection, respecting the Tor configuration.
final class GRPCEndpointSubmitter: EndpointSubmitter {
    private let torClient: TorClient
    private let sdkFlags: SDKFlags
    private let logger: Logger

    init(torClient: TorClient, sdkFlags: SDKFlags, logger: Logger) {
        self.torClient = torClient
        self.sdkFlags = sdkFlags
        self.logger = logger
    }

    func submit(transaction: CreatedTransaction, to endpoint: LightWalletEndpoint) async throws {
        let mode: ServiceMode
        let serviceTorClient: TorClient
        let transport: String
        if await sdkFlags.torEnabled {
            // One isolated Tor client per submission attempt: connecting
            // through the shared TorClient serializes every endpoint behind
            // one blocking FFI call on its actor, so a single stalled endpoint
            // would starve the whole multi-endpoint race.
            serviceTorClient = try await torClient.isolatedClient()
            mode = ServiceMode.txIdGroup(prefix: "submit", txId: transaction.txId)
            transport = "an isolated Tor circuit"
        } else {
            serviceTorClient = torClient
            mode = ServiceMode.direct
            transport = "a direct connection"
        }

        logger.debug(
            "Transaction \(transaction.txId.toHexStringTxId()) submitting to \(endpoint.host):\(endpoint.port) over \(transport)."
        )

        let service = LightWalletGRPCServiceOverTor(endpoint: endpoint, tor: serviceTorClient)

        let response: LightWalletServiceResponse
        do {
            response = try await service.submit(spendTransaction: transaction.raw, mode: mode)
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
