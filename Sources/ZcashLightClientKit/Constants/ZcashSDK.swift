//
//  ZcashSDK.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 7/22/21.
//

import Foundation
public protocol ZcashNetwork {
    var networkType: NetworkType { get }
    var constants: NetworkConstants.Type { get }
}

public enum NetworkType: Equatable, Codable, Hashable {
    case mainnet
    case testnet

    var networkId: UInt32 {
        switch self {
        case .mainnet:  return 1
        case .testnet:  return 0
        }
    }
}

extension NetworkType {
    static func forChainName(_ chainame: String) -> NetworkType? {
        switch chainame {
        case "test":    return .testnet
        case "main":    return .mainnet
        default:        return nil
        }
    }

    static func forNetworkId(_ id: UInt32) -> NetworkType? {
        switch id {
        case 1: return .mainnet
        case 0: return .testnet
        default: return nil
        }
    }
}

extension NetworkType {
    public var chainName: String {
        switch self {
        case .mainnet:
            return "main"
        case .testnet:
            return "test"
        }
    }
}

public enum ZcashNetworkBuilder {
    public static func network(for networkType: NetworkType) -> ZcashNetwork {
        switch networkType {
        case .mainnet:  return ZcashMainnet()
        case .testnet:  return ZcashTestnet()
        }
    }
}

class ZcashTestnet: ZcashNetwork {
    let networkType: NetworkType = .testnet
    let constants: NetworkConstants.Type = ZcashSDKTestnetConstants.self
}

class ZcashMainnet: ZcashNetwork {
    let networkType: NetworkType = .mainnet
    let constants: NetworkConstants.Type = ZcashSDKMainnetConstants.self
}

/**
Constants of ZcashLightClientKit. this constants don't
*/
public enum ZcashSDK {
    /// The number of zatoshi that equal 1 ZEC.
    public static let zatoshiPerZEC: BlockHeight = 100_000_000

    /// The theoretical maximum number of blocks in a reorg, due to other bottlenecks in the protocol design.
    public static let maxReorgSize = 100

    /// The amount of blocks ahead of the current height where new transactions are set to expire. This value is controlled
    /// by the rust backend but it is helpful to know what it is set to and should be kept in sync.
    public static let expiryOffset = 20

    // MARK: Defaults

    /// Default size of batches of blocks to request from the compact block service. Which was used both for scanning and downloading.
    public static let DefaultBatchSize = 100

    /// Default batch size for enhancing transactions for the compact block processor
    public static let DefaultEnhanceBatch = 1000

    /// Default amount of time, in in seconds, to poll for new blocks. Typically, this should be about half the average
    /// block time.
    public static let defaultPollInterval: TimeInterval = 20

    /// Default attempts at retrying.
    // This has been tweaked in https://github.com/zcash/ZcashLightClientKit/issues/1303
    // There are many places that rely on hasRetryAttempt() that reads and compares this value.
    // Better solution is to think about retry logic and potentially either remove completely
    // or implement more sophisticated solutuion. Until that time, Int.max solves our UX issues
    // TODO: [#1304] smart retry logic, https://github.com/zcash/ZcashLightClientKit/issues/1304
    public static let defaultRetries = Int.max

    /// The communication errors are usually false positive and another try will continue the work,
    /// in case the service is trully down we cap the amount of retries by this value.
    public static let serviceFailureRetries = 3

    /// The default maximum amount of time to wait during retry backoff intervals. Failed loops will never wait longer than
    /// this before retrying.
    public static let defaultMaxBackOffInterval: TimeInterval = 600

    /// Default number of blocks to rewind when a chain reorg is detected. This should be large enough to recover from the
    /// reorg but smaller than the theoretical max reorg size of 100.
    public static let defaultRewindDistance: Int = 10

    /// The number of blocks to allow before considering our data to be stale. This usually helps with what to do when
    /// returning from the background and is exposed via the Synchronizer's isStale function.
    public static let defaultStaleTolerance: Int = 10

    /// Default Name for LibRustZcash data.db
    public static let defaultDataDbName = "data.db"

    /// Default Name for Tor data directory
    public static let defaultTorDirName = "tor"

    /// Default Name for Compact Block file system based db
    public static let defaultFsCacheName = "fs_cache"

    /// Default Name for Compact Block caches db
    public static let defaultCacheDbName = "caches.db"

    /// The Url that is used by default in zcashd.
    /// We'll want to make this externally configurable, rather than baking it into the SDK but
    /// this will do for now, since we're using a cloudfront URL that already redirects.
    public static let cloudParameterURL = "https://download.z.cash/downloads/"

    /// File name for the sapling spend params
    public static let spendParamFilename = "sapling-spend.params"
    // swiftlint:disable:next force_unwrapping
    public static let spendParamFileURL = URL(string: cloudParameterURL)!.appendingPathComponent(spendParamFilename)

    /// File name for the sapling output params
    public static let outputParamFilename = "sapling-output.params"
    // swiftlint:disable:next force_unwrapping
    public static let outputParamFileURL = URL(string: cloudParameterURL)!.appendingPathComponent(outputParamFilename)

    /// A constant that helps determine if a server’s chain tip is so far away from the estimated height that we consider the server out of sync
    public static let syncedThresholdBlocks = UInt64(288)
}

public protocol NetworkConstants {
    /// The height of the first sapling block. When it comes to shielded transactions, we do not need to consider any blocks
    /// prior to this height, at all.
    static var saplingActivationHeight: BlockHeight { get }

    /// Default Name for LibRustZcash data.db
    static var defaultDataDbName: String { get }

    /// Default Name for Tor data directory
    static var defaultTorDirName: String { get }

    static var defaultFsBlockDbRootName: String { get }

    /// Default Name for Compact Block caches db
    @available(*, deprecated, message: "use this name to clean up the sqlite compact block database")
    static var defaultCacheDbName: String { get }

    /// Default prefix for db filenames
    static var defaultDbNamePrefix: String { get }

    /// Returns the default fee, hardcoded 10k Zatoshi is the minimum ZIP 317 fee
    static func defaultFee() -> Zatoshi
}

public extension NetworkConstants {
    static func defaultFee() -> Zatoshi {
        Zatoshi(10_000)
    }
}

public enum ZcashSDKMainnetConstants: NetworkConstants {
    /// The height of the first sapling block. When it comes to shielded transactions, we do not need to consider any blocks
    /// prior to this height, at all.
    public static let saplingActivationHeight: BlockHeight = 419_200

    /// Default Name for LibRustZcash data.db
    public static let defaultDataDbName = "data.db"

    /// Default Name for Tor data directory
    public static let defaultTorDirName = "tor"

    public static let defaultFsBlockDbRootName = "fs_cache"

    /// Default Name for Compact Block caches db
    public static let defaultCacheDbName = "caches.db"

    public static let defaultDbNamePrefix = "ZcashSdk_mainnet_"
}

public enum ZcashSDKTestnetConstants: NetworkConstants {
    /// The height of the first sapling block. When it comes to shielded transactions, we do not need to consider any blocks
    /// prior to this height, at all.
    public static let saplingActivationHeight: BlockHeight = 280_000

    /// Default Name for LibRustZcash data.db
    public static let defaultDataDbName = "data.db"

    /// Default Name for Tor data directory
    public static let defaultTorDirName = "tor"

    /// Default Name for Compact Block caches db
    public static let defaultCacheDbName = "caches.db"

    public static let defaultFsBlockDbRootName = "fs_cache"

    public static let defaultDbNamePrefix = "ZcashSdk_testnet_"
}

/// Used when importing an account `importAccount(..., purpose: AccountPurpose)`
public enum AccountPurpose: UInt32, Equatable {
    case spending = 0
    case viewOnly
}
