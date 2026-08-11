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

    /// The Sapling activation height for this network. Defaults to ``constants``'s
    /// `saplingActivationHeight`; a regtest network returns its configured height.
    var saplingActivationHeight: BlockHeight { get }

    /// The full set of custom NU activation heights when this is a custom (regtest-slot) network,
    /// otherwise `nil`. Consumed by the Rust backend to switch the core onto a custom-parameter network.
    var customActivationHeights: NetworkActivationHeights? { get }

    /// For a custom network (``customActivationHeights`` non-nil), the base identity registered with the
    /// Rust core: address encoding and `chainName` follow this, while the activation heights are custom
    /// (e.g. a modified-mainnet Ironwood backend uses base `.mainnet`). `nil` for standard networks.
    var customNetworkBase: NetworkType? { get }
}

public extension ZcashNetwork {
    var saplingActivationHeight: BlockHeight { constants.saplingActivationHeight }
    var customActivationHeights: NetworkActivationHeights? { nil }
    var customNetworkBase: NetworkType? { nil }
}

public enum NetworkType: Equatable, Codable, Hashable {
    case mainnet
    case testnet
    /// A custom-parameter (regtest) network with configurable NU activation heights. Select it via
    /// ``ZcashNetworkBuilder/regtest(activationHeights:)`` rather than constructing it directly.
    case regtest

    var networkId: UInt32 {
        switch self {
        case .mainnet:  return 1
        case .testnet:  return 0
        case .regtest:  return 2
        }
    }
}

extension NetworkType {
    static func forChainName(_ chainame: String) -> NetworkType? {
        switch chainame {
        case "test":    return .testnet
        case "main":    return .mainnet
        case "regtest": return .regtest
        default:        return nil
        }
    }

    static func forNetworkId(_ id: UInt32) -> NetworkType? {
        switch id {
        case 1: return .mainnet
        case 0: return .testnet
        case 2: return .regtest
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
        case .regtest:
            return "regtest"
        }
    }
}

public enum ZcashNetworkBuilder {
    public static func network(for networkType: NetworkType) -> ZcashNetwork {
        switch networkType {
        case .mainnet:  return ZcashMainnet()
        case .testnet:  return ZcashTestnet()
        case .regtest:  return ZcashRegtest(base: .regtest, activationHeights: NetworkActivationHeights.allActiveFromGenesis)
        }
    }

    /// Builds a custom **regtest** network with the given NU activation heights, for connecting the SDK
    /// to a custom-parameter `lightwalletd`. Addresses and chain identity are regtest-encoded, and the
    /// on-disk databases use a `regtest`-specific name prefix. See `MIGRATING.md`.
    public static func regtest(activationHeights: NetworkActivationHeights) -> ZcashNetwork {
        ZcashRegtest(base: .regtest, activationHeights: activationHeights)
    }

    /// Builds a **custom network**: a chosen `base` identity (which determines address encoding and the
    /// expected `chainName`) combined with custom per-NU activation heights. For example a
    /// modified-mainnet Ironwood testing backend uses `base: .mainnet` with NU6.3 at a custom height —
    /// the Rust core then derives **mainnet-encoded** addresses and runs mainnet consensus at the custom
    /// heights. On-disk the network still uses the `regtest`-slot name prefix, so it never collides with
    /// a real mainnet wallet. See `MIGRATING.md`.
    public static func custom(base: NetworkType, activationHeights: NetworkActivationHeights) -> ZcashNetwork {
        ZcashRegtest(base: base, activationHeights: activationHeights)
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

class ZcashRegtest: ZcashNetwork {
    let networkType: NetworkType = .regtest
    let constants: NetworkConstants.Type = ZcashSDKRegtestConstants.self
    /// The base identity registered with the Rust core (address encoding / `chainName`). `.regtest` for
    /// a plain regtest network; `.mainnet` for a modified-mainnet custom network (e.g. Ironwood).
    let base: NetworkType
    let activationHeights: NetworkActivationHeights

    init(base: NetworkType, activationHeights: NetworkActivationHeights) {
        self.base = base
        self.activationHeights = activationHeights
    }

    var saplingActivationHeight: BlockHeight { activationHeights.sapling ?? 1 }
    var customActivationHeights: NetworkActivationHeights? { activationHeights }
    var customNetworkBase: NetworkType? { base }
}

/**
Constants of ZcashLightClientKit. this constants don't
*/
public enum ZcashSDK {
    /// The consensus branch ID of NU6.3 ("Ironwood").
    ///
    /// Published so hosts that must name the active consensus era read it from
    /// the SDK instead of hardcoding the literal. The voting stack is the case
    /// that forced this: `zcash_voting` rejects a delegation built for any other
    /// branch, so a stale hardcoded era does not degrade — every delegation fails
    /// at construction. A constant that moves with the SDK cannot go stale
    /// silently at the next network upgrade the way a copied literal does.
    public static let nu63ConsensusBranchID: ConsensusBranchID = 0x37a5_165b

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

public enum ZcashSDKRegtestConstants: NetworkConstants {
    /// Fallback only. The Sapling activation height of a regtest network is supplied per-instance via
    /// ``ZcashNetworkBuilder/regtest(activationHeights:)`` and read from the ``ZcashNetwork`` instance,
    /// not from this static value.
    public static let saplingActivationHeight: BlockHeight = 1

    /// Default Name for LibRustZcash data.db
    public static let defaultDataDbName = "data.db"

    /// Default Name for Tor data directory
    public static let defaultTorDirName = "tor"

    /// Default Name for Compact Block caches db
    public static let defaultCacheDbName = "caches.db"

    public static let defaultFsBlockDbRootName = "fs_cache"

    /// A regtest-specific prefix keeps regtest wallet databases from colliding with mainnet/testnet data.
    public static let defaultDbNamePrefix = "ZcashSdk_regtest_"
}

/// Used when importing an account `importAccount(..., purpose: AccountPurpose)`
public enum AccountPurpose: UInt32, Equatable {
    case spending = 0
    case viewOnly
}
