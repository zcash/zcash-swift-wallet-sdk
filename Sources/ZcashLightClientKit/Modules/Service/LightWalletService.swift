//
//  LightWalletService.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 12/09/2019.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import Foundation

/**
Wrapper for errors received from a Lightwalletd endpoint
*/
public enum LightWalletServiceError: Error {
    case generalError(message: String)
    case failed(statusCode: Int, message: String)
    case invalidBlock
    case sentFailed(error: Error)
    case genericError(error: Error)
    case timeOut
    case criticalError
    case userCancelled
    case unknown
}

extension LightWalletServiceError: Equatable {
    // swiftlint:disable:next cyclomatic_complexity
    public static func == (lhs: Self, rhs: Self) -> Bool {
        switch lhs {
        case .generalError(let message):
            switch rhs {
            case .generalError(let msg):
                return message == msg
            default:
                return false
            }
        case .failed(let statusCode, _):
            switch rhs {
            case .failed(let anotherStatus, _):
                return statusCode == anotherStatus
            default:
                return false
            }
            
        case .invalidBlock:
            switch rhs {
            case .invalidBlock:
                return true
            default:
                return false
            }
        case .sentFailed:
            switch rhs {
            case .sentFailed:
                return true
            default:
                return false
            }
        case .genericError:
            return false
        
        case .timeOut:
            switch rhs {
            case .timeOut:
                return true
            default:
                return false
            }
        case .criticalError:
            switch rhs {
            case .criticalError:
                return true
            default:
                return false
            }
        case .userCancelled:
            switch rhs {
            case .userCancelled:
                return true
            default:
                return false
            }
        case .unknown:
            switch rhs {
            case .unknown:
                return true
            default:
                return false
            }
        }
    }
}

protocol LightWalletdInfo {
    var version: String { get }

    var vendor: String { get }

    /// true
    var taddrSupport: Bool { get }

    /// either "main" or "test"
    var chainName: String { get }

    /// depends on mainnet or testnet
    var saplingActivationHeight: UInt64 { get }

    /// protocol identifier, see consensus/upgrades.cpp
    var consensusBranchID: String { get }

    /// latest block on the best chain
    var blockHeight: UInt64 { get }

    var gitCommit: String { get }

    var branch: String { get }

    var buildDate: String { get }

    var buildUser: String { get }

    /// less than tip height if zcashd is syncing
    var estimatedHeight: UInt64 { get }

    /// example: "v4.1.1-877212414"
    var zcashdBuild: String { get }

    /// example: "/MagicBean:4.1.1/"
    var zcashdSubversion: String { get }
}

protocol LightWalletServiceResponse {
    var errorCode: Int32 { get }
    var errorMessage: String { get }
}

struct LightWalletServiceFactory {
    let endpoint: LightWalletEndpoint

    func make() -> LightWalletService {
        return LightWalletGRPCService(endpoint: endpoint)
    }
}

/// Mode that determines which connection is used for the lightwalletd networking calls.
enum ServiceMode: Equatable {
    /// Default Tor connection is used, lives for the lifetime of the Synchronizer.
    case defaultTor
    /// GRPC connection is used, no Tor involved.
    case direct
    /// Tor connection is used tagged by a given group name (String). Tags are held in memory for the lifetime of the Synchronizer.
    case torInGroup(String)
    /// Tor connection is used, each time a new one, not held in memory, used only once.
    case uniqueTor

    /// Helper method that generates a tagged group for a given transaction ID with a prefix. 
    static func txIdGroup(prefix: String, txId: Data) -> ServiceMode {
        torInGroup("\(prefix)-\(txId.hexEncodedString())")
    }
}

protocol LightWalletService: AnyObject {
    /// Closure which is called when connection state changes.
    var connectionStateChange: ((_ from: ConnectionState, _ to: ConnectionState) -> Void)? { get set }

    /// Returns the info for this lightwalletd server
    /// - Throws: `serviceGetInfoFailed` when GRPC call fails.
    func getInfo(mode: ServiceMode) async throws -> LightWalletdInfo

    /// - Throws: `serviceLatestBlockHeightFailed` when GRPC call fails.
    func latestBlock(mode: ServiceMode) async throws -> BlockID

    /// Return the latest block height known to the service.
    /// - Throws: `serviceLatestBlockFailed` when GRPC call fails.
    func latestBlockHeight(mode: ServiceMode) async throws -> BlockHeight

    /// Return the given range of blocks.
    /// - Parameter range: the inclusive range to fetch.
    ///     For instance if 1..5 is given, then every block in that will be fetched, including 1 and 5.
    /// - Throws: `serviceBlockRangeFailed` when GRPC call fails.
    func blockRange(_ range: CompactBlockRange, mode: ServiceMode) throws -> AsyncThrowingStream<ZcashCompactBlock, Error>
    
    /// Submits a raw transaction over lightwalletd.
    /// - Parameter spendTransaction: data representing the transaction to be sent
    /// - Throws: `serviceSubmitFailed` when GRPC call fails.
    func submit(spendTransaction: Data, mode: ServiceMode) async throws -> LightWalletServiceResponse

    /// Gets a transaction by id
    /// - Parameter txId: data representing the transaction ID
    /// - Throws: LightWalletServiceError
    /// - Returns: LightWalletServiceResponse
    /// - Throws: `serviceFetchTransactionFailed` when GRPC call fails.
    func fetchTransaction(txId: Data, mode: ServiceMode) async throws -> (tx: ZcashTransaction.Fetched?, status: TransactionStatus)

    /// - Throws: `serviceFetchUTXOsFailed` when GRPC call fails.
    // sourcery: mockedName="fetchUTXOsSingle"
    func fetchUTXOs(for tAddress: String, height: BlockHeight, mode: ServiceMode) throws -> AsyncThrowingStream<UnspentTransactionOutputEntity, Error>

    /// - Throws: `serviceFetchUTXOsFailed` when GRPC call fails.
    func fetchUTXOs(for tAddresses: [String], height: BlockHeight, mode: ServiceMode) throws -> AsyncThrowingStream<UnspentTransactionOutputEntity, Error>

    /// - Throws: `serviceBlockStreamFailed` when GRPC call fails.
    func blockStream(
        startHeight: BlockHeight,
        endHeight: BlockHeight,
        mode: ServiceMode
    ) throws -> AsyncThrowingStream<ZcashCompactBlock, Error>

    /// Used for potential closure of channels or connections.
    /// Example:` LightWalletGRPCServiceOverTor` inherits `LightWalletService` and closes Tor connections.
    func closeConnections() async
    
    /// Returns a stream of information about roots of subtrees of the Sapling and Orchard
    /// note commitment trees.
    ///
    /// - Parameters:
    ///   - request: Request to send to GetSubtreeRoots.
    func getSubtreeRoots(_ request: GetSubtreeRootsArg, mode: ServiceMode) throws -> AsyncThrowingStream<SubtreeRoot, Error>

    func getTreeState(_ id: BlockID, mode: ServiceMode) async throws -> TreeState

    func getTaddressTxids(_ request: TransparentAddressBlockFilter, mode: ServiceMode) throws -> AsyncThrowingStream<RawTransaction, Error>
    
    func getMempoolStream() throws -> AsyncThrowingStream<RawTransaction, Error>
    
    func checkSingleUseTransparentAddresses(
        dbHandle: OpaquePointer,
        accountUUID: AccountUUID,
        mode: ServiceMode
    ) async throws -> TransparentAddressCheckResult

    func updateTransparentAddressTransactions(
        address: String,
        start: BlockHeight,
        end: BlockHeight,
        dbHandle: OpaquePointer,
        mode: ServiceMode
    ) async throws -> TransparentAddressCheckResult

    func fetchUTXOsByAddress(
        address: String,
        dbHandle: OpaquePointer,
        accountUUID: AccountUUID,
        mode: ServiceMode
    ) async throws -> TransparentAddressCheckResult
}
