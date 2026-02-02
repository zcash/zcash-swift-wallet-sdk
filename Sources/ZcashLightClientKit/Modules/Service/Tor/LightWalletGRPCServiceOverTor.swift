//
//  LightWalletGRPCServiceOverTor.swift
//  ZcashLightClientKit
//
//  Created by Lukáš Korba on 2025-04-08.
//

import Foundation

actor ServiceConnections {
    var tor: TorClient
    var endpointString: String?
    var groups: [String: TorLwdConn] = [:]
    var defaultTorLwdConn: TorLwdConn?
    
    init(endpoint: LightWalletEndpoint, tor: TorClient) {
        self.tor = tor
        endpointString = String(format: "%@://%@:%d", endpoint.secure ? "https" : "http", endpoint.host, endpoint.port)
    }
    
    func connectToLightwalletd(_ mode: ServiceMode) async throws -> TorLwdConn {
        guard let endpointString else {
            throw ZcashError.torServiceMissingEndpoint
        }

        // uniqueTor
        if mode == .uniqueTor {
            return try await tor.connectToLightwalletd(endpoint: endpointString)
        } else if mode == .defaultTor {
            // defaultTor
            let connection: TorLwdConn
            
            if let defaultTorLwdConn {
                connection = defaultTorLwdConn
            } else {
                connection = try await tor.connectToLightwalletd(endpoint: endpointString)
                defaultTorLwdConn = connection
            }
            
            return connection
        } else if case let .torInGroup(groupName) = mode {
            // torInGroup
            guard let torInGroup = groups[groupName] else {
                let torInGroupNamed = try await tor.connectToLightwalletd(endpoint: endpointString)
                
                groups[groupName] = torInGroupNamed
                
                return torInGroupNamed
            }
            
            return torInGroup
        } else {
            throw ZcashError.torServiceUnresolvedMode
        }
    }
    
    func responseToTorFailure(_ mode: ServiceMode) async {
        if mode == .defaultTor {
            defaultTorLwdConn = nil
        } else if case let .torInGroup(groupName) = mode {
            groups.removeValue(forKey: groupName)
        }
    }
    
    func closeConnections() {
        groups.removeAll()
        defaultTorLwdConn = nil
    }
}

class LightWalletGRPCServiceOverTor: LightWalletGRPCService {
    var tor: TorClient
    let serviceConnections: ServiceConnections

    convenience init(endpoint: LightWalletEndpoint, tor: TorClient) {
        self.init(
            endpoint: endpoint,
            singleCallTimeout: endpoint.singleCallTimeoutInMillis,
            streamingCallTimeout: endpoint.streamingCallTimeoutInMillis,
            tor: tor
        )
    }
    
    convenience init(endpoint: LightWalletEndpoint, tor: TorClient, singleCallTimeout: Int64) {
        self.init(
            endpoint: endpoint,
            singleCallTimeout: singleCallTimeout,
            streamingCallTimeout: endpoint.streamingCallTimeoutInMillis,
            tor: tor
        )
    }
    
    init(
        endpoint: LightWalletEndpoint,
        singleCallTimeout: Int64,
        streamingCallTimeout: Int64,
        tor: TorClient
    ) {
        self.tor = tor
        serviceConnections = ServiceConnections(endpoint: endpoint, tor: tor)

        super.init(
            host: endpoint.host,
            port: endpoint.port,
            secure: endpoint.secure,
            singleCallTimeout: singleCallTimeout,
            streamingCallTimeout: streamingCallTimeout
        )
    }

    override func getInfo(mode: ServiceMode) async throws -> LightWalletdInfo {
        guard mode != .direct else {
            return try await super.getInfo(mode: mode)
        }
        
        do {
            return try await serviceConnections.connectToLightwalletd(mode).getInfo()
        } catch {
            await serviceConnections.responseToTorFailure(mode)
            throw error
        }
    }

    override func latestBlockHeight(mode: ServiceMode) async throws -> BlockHeight {
        guard mode != .direct else {
            return try await super.latestBlockHeight(mode: mode)
        }

        return BlockHeight(try await latestBlock(mode: mode).height)
    }

    override func latestBlock(mode: ServiceMode) async throws -> BlockID {
        guard mode != .direct else {
            return try await super.latestBlock(mode: mode)
        }

        do {
            return try await serviceConnections.connectToLightwalletd(mode).latestBlock()
        } catch {
            await serviceConnections.responseToTorFailure(mode)
            throw error
        }
    }
    
    override func submit(spendTransaction: Data, mode: ServiceMode) async throws -> LightWalletServiceResponse {
        guard mode != .direct else {
            return try await super.submit(spendTransaction: spendTransaction, mode: mode)
        }

        do {
            return try await serviceConnections.connectToLightwalletd(mode).submit(spendTransaction: spendTransaction)
        } catch {
            await serviceConnections.responseToTorFailure(mode)
            throw ZcashError.serviceSubmitFailed(LightWalletServiceError.genericError(error: error))
        }
    }
    
    override func fetchTransaction(txId: Data, mode: ServiceMode) async throws -> (tx: ZcashTransaction.Fetched?, status: TransactionStatus) {
        guard mode != .direct else {
            return try await super.fetchTransaction(txId: txId, mode: mode)
        }

        do {
            return try await serviceConnections.connectToLightwalletd(mode).fetchTransaction(txId: txId)
        } catch {
            await serviceConnections.responseToTorFailure(mode)
            throw error
        }
    }
    
    override func getTreeState(_ id: BlockID, mode: ServiceMode) async throws -> TreeState {
        guard mode != .direct else {
            return try await super.getTreeState(id, mode: mode)
        }

        do {
            return try await serviceConnections.connectToLightwalletd(mode).getTreeState(height: BlockHeight(id.height))
        } catch {
            await serviceConnections.responseToTorFailure(mode)
            throw error
        }
    }
    
    override func checkSingleUseTransparentAddresses(
        dbData: (String, UInt),
        networkType: NetworkType,
        accountUUID: AccountUUID,
        mode: ServiceMode
    ) async throws -> TransparentAddressCheckResult {
        guard mode != .direct else {
            return try await super.checkSingleUseTransparentAddresses(dbData: dbData, networkType: networkType, accountUUID: accountUUID, mode: mode)
        }

        do {
            return try await serviceConnections.connectToLightwalletd(mode).checkSingleUseTransparentAddresses(
                dbData: dbData,
                networkType: networkType,
                accountUUID: accountUUID
            )
        } catch {
            await serviceConnections.responseToTorFailure(mode)
            throw error
        }
    }
    
    override func updateTransparentAddressTransactions(
        address: String,
        start: BlockHeight,
        end: BlockHeight,
        dbData: (String, UInt),
        networkType: NetworkType,
        mode: ServiceMode
    ) async throws -> TransparentAddressCheckResult {
        guard mode != .direct else {
            return try await super.updateTransparentAddressTransactions(
                address: address,
                start: start,
                end: end,
                dbData: dbData,
                networkType: networkType,
                mode: mode
            )
        }

        do {
            return try await serviceConnections.connectToLightwalletd(mode).updateTransparentAddressTransactions(
                address: address,
                start: start,
                end: end,
                dbData: dbData,
                networkType: networkType
            )
        } catch {
            await serviceConnections.responseToTorFailure(mode)
            throw error
        }
    }
    
    override func fetchUTXOsByAddress(
        address: String,
        dbData: (String, UInt),
        networkType: NetworkType,
        accountUUID: AccountUUID,
        mode: ServiceMode
    ) async throws -> TransparentAddressCheckResult {
        guard mode != .direct else {
            return try await super.fetchUTXOsByAddress(
                address: address,
                dbData: dbData,
                networkType: networkType,
                accountUUID: accountUUID,
                mode: mode
            )
        }

        do {
            return try await serviceConnections.connectToLightwalletd(mode).fetchUTXOsByAddress(
                address: address,
                dbData: dbData,
                networkType: networkType,
                accountUUID: accountUUID
            )
        } catch {
            await serviceConnections.responseToTorFailure(mode)
            throw error
        }
    }
    
    override func closeConnections() async {
        await super.closeConnections()
        await serviceConnections.closeConnections()
    }
}
