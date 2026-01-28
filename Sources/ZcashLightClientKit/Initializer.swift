//
//  Initializer.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 13/09/2019.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import Foundation

/**
Represents a lightwallet instance endpoint to connect to
*/
public struct LightWalletEndpoint {
    public let host: String
    public let port: Int
    public let secure: Bool
    public let singleCallTimeoutInMillis: Int64
    public let streamingCallTimeoutInMillis: Int64
    
    /**
    initializes a LightWalletEndpoint
    - Parameters:
        - address: a String containing the host address
        - port: string with the port of the host address
        - secure: true if connecting through TLS. Default value is true
        - singleCallTimeoutInMillis: timeout for single calls in Milliseconds. Default 30 seconds
        - streamingCallTimeoutInMillis: timeout for streaming calls in Milliseconds. Default 100 seconds
    */
    public init(
        address: String,
        port: Int,
        secure: Bool = true,
        singleCallTimeoutInMillis: Int64 = 30000,
        streamingCallTimeoutInMillis: Int64 = 100000
    ) {
        self.host = address
        self.port = port
        self.secure = secure
        self.singleCallTimeoutInMillis = singleCallTimeoutInMillis
        self.streamingCallTimeoutInMillis = streamingCallTimeoutInMillis
    }

    var urlString: String {
        String(format: "%@://%@:%d", secure ? "https" : "http", host, port)
    }
}

/// This contains URLs from which can the SDK fetch files that contain sapling parameters.
/// Use `SaplingParamsSourceURL.default` when initilizing the SDK.
public struct SaplingParamsSourceURL {
    public let spendParamFileURL: URL
    public let outputParamFileURL: URL

    public static var `default`: SaplingParamsSourceURL {
        SaplingParamsSourceURL(spendParamFileURL: ZcashSDK.spendParamFileURL, outputParamFileURL: ZcashSDK.outputParamFileURL)
    }
}

/// This identifies different instances of the synchronizer. It is usefull when the client app wants to support multiple wallets (with different
/// seeds) in one app. If the client app support only one wallet then it doesn't have to care about alias atall.
///
/// When custom alias is used to create instance of the synchronizer then paths to all resources (databases, storages...) are updated accordingly to
/// be sure that each instance is using unique paths to resources.
///
/// Custom alias identifiers shouldn't contain any confidential information because it may be logged. It also should have a reasonable length and
/// form. It will be part of the paths to the files (databases, storage...)
///
/// IMPORTANT: Always use `default` alias for one of the instances of the synchronizer.
public enum ZcashSynchronizerAlias: Hashable {
    case `default`
    case custom(String)
}

extension ZcashSynchronizerAlias: CustomStringConvertible {
    public var description: String {
        switch self {
        case .`default`:
            return "default"
        case let .custom(alias):
            return "c_\(alias)"
        }
    }
}

/**
Wrapper for all the Rust backend functionality that does not involve processing blocks. This
class initializes the Rust backend and the supporting data required to exercise those abilities.
The [cash.z.wallet.sdk.block.CompactBlockProcessor] handles all the remaining Rust backend
functionality, related to processing blocks.
*/
// swiftlint:disable:next type_body_length
public class Initializer {
    struct URLs {
        let fsBlockDbRoot: URL
        let dataDbURL: URL
        let torDirURL: URL
        let generalStorageURL: URL
        let spendParamsURL: URL
        let outputParamsURL: URL
    }

    public enum InitializationResult {
        case success
        case seedRequired
    }
    
    public enum LoggingPolicy {
        case `default`(OSLogger.LogLevel)
        case custom(Logger)
        case noLogging
    }

    // This is used to uniquely identify instance of the SDKSynchronizer. It's used when checking if the Alias is already used or not.
    let id = UUID()

    let container: DIContainer
    let alias: ZcashSynchronizerAlias
    var endpoint: LightWalletEndpoint
    let fsBlockDbRoot: URL
    let generalStorageURL: URL
    let dataDbURL: URL
    let torDirURL: URL
    let spendParamsURL: URL
    let outputParamsURL: URL
    let saplingParamsSourceURL: SaplingParamsSourceURL
    var lightWalletService: LightWalletService
    let transactionRepository: TransactionRepository
    let storage: CompactBlockRepository
    var blockDownloaderService: BlockDownloaderService
    let network: ZcashNetwork
    let logger: Logger
    let rustBackend: ZcashRustBackendWelding

    /// The effective birthday of the wallet based on the height provided when initializing and the checkpoints available on this SDK.
    ///
    /// This contains valid value only after `initialize` function is called.
    public private(set) var walletBirthday: BlockHeight

    /// The purpose of this to migrate from cacheDb to fsBlockDb
    private let cacheDbURL: URL?

    /// Error that can be created when updating URLs according to alias. If this error is created then it is thrown from `SDKSynchronizer.prepare()`
    /// or `SDKSynchronizer.wipe()`.
    var urlsParsingError: ZcashError?

    /// Constructs the Initializer and migrates an old cacheDb to the new file system block cache if a `cacheDbURL` is provided.
    /// - Parameters:
    ///  - cacheDbURL: previous location of the cacheDb. If you don't know what a cacheDb is and you are adopting this SDK for the first time then
    ///                just pass `nil` here.
    ///  - fsBlockDbRoot: location of the compact blocks cache
    ///  - generalStorageURL: Location of the directory where the SDK can store any information it needs. A directory doesn't have to exist. But the
    ///                       SDK must be able to write to this location after it creates this directory. It is suggested that this directory is
    ///                       a subdirectory of the `Documents` directory. If this information is stored in `Documents` then the system itself won't
    ///                       remove these data.
    ///  - dataDbURL: Location of the data db
    ///  - endpoint: the endpoint representing the lightwalletd instance you want to point to
    ///  - spendParamsURL: location of the spend parameters
    ///  - outputParamsURL: location of the output parameters
    ///  - loggingPolicy: the `LoggingPolicy` for the logger
    ///  - enableBackendTracing: this enables tracing for super detailed debugging. it will slow down everything 10 or 100x.
    convenience public init(
        cacheDbURL: URL?,
        fsBlockDbRoot: URL,
        generalStorageURL: URL,
        dataDbURL: URL,
        torDirURL: URL,
        endpoint: LightWalletEndpoint,
        network: ZcashNetwork,
        spendParamsURL: URL,
        outputParamsURL: URL,
        saplingParamsSourceURL: SaplingParamsSourceURL,
        alias: ZcashSynchronizerAlias = .default,
        loggingPolicy: LoggingPolicy = .default(.debug),
        isTorEnabled: Bool,
        isExchangeRateEnabled: Bool
    ) {
        let container = DIContainer()
        
        // It's not possible to fail from constructor. Technically it's possible but it can be pain for the client apps to handle errors thrown
        // from constructor. So `parsingError` is just stored in initializer and `SDKSynchronizer.prepare()` throw this error if it exists.
        let (updatedURLs, parsingError) = Self.setup(
            container: container,
            cacheDbURL: cacheDbURL,
            fsBlockDbRoot: fsBlockDbRoot,
            generalStorageURL: generalStorageURL,
            dataDbURL: dataDbURL,
            torDirURL: torDirURL,
            endpoint: endpoint,
            network: network,
            spendParamsURL: spendParamsURL,
            outputParamsURL: outputParamsURL,
            saplingParamsSourceURL: saplingParamsSourceURL,
            alias: alias,
            loggingPolicy: loggingPolicy,
            isTorEnabled: isTorEnabled,
            isExchangeRateEnabled: isExchangeRateEnabled
        )
        
        self.init(
            container: container,
            cacheDbURL: cacheDbURL,
            urls: updatedURLs,
            endpoint: endpoint,
            network: network,
            saplingParamsSourceURL: saplingParamsSourceURL,
            alias: alias,
            urlsParsingError: parsingError,
            loggingPolicy: loggingPolicy,
            isTorEnabled: isTorEnabled,
            isExchangeRateEnabled: isExchangeRateEnabled
        )
    }

    /// Internal for dependency injection purposes.
    convenience init(
        container: DIContainer,
        cacheDbURL: URL?,
        fsBlockDbRoot: URL,
        generalStorageURL: URL,
        dataDbURL: URL,
        torDirURL: URL,
        endpoint: LightWalletEndpoint,
        network: ZcashNetwork,
        spendParamsURL: URL,
        outputParamsURL: URL,
        saplingParamsSourceURL: SaplingParamsSourceURL,
        alias: ZcashSynchronizerAlias = .default,
        loggingPolicy: LoggingPolicy = .default(.debug),
        isTorEnabled: Bool,
        isExchangeRateEnabled: Bool
    ) {
        // It's not possible to fail from constructor. Technically it's possible but it can be pain for the client apps to handle errors thrown
        // from constructor. So `parsingError` is just stored in initializer and `SDKSynchronizer.prepare()` throw this error if it exists.
        let (updatedURLs, parsingError) = Self.setup(
            container: container,
            cacheDbURL: cacheDbURL,
            fsBlockDbRoot: fsBlockDbRoot,
            generalStorageURL: generalStorageURL,
            dataDbURL: dataDbURL,
            torDirURL: torDirURL,
            endpoint: endpoint,
            network: network,
            spendParamsURL: spendParamsURL,
            outputParamsURL: outputParamsURL,
            saplingParamsSourceURL: saplingParamsSourceURL,
            alias: alias,
            loggingPolicy: loggingPolicy,
            isTorEnabled: isTorEnabled,
            isExchangeRateEnabled: isExchangeRateEnabled
        )

        self.init(
            container: container,
            cacheDbURL: cacheDbURL,
            urls: updatedURLs,
            endpoint: endpoint,
            network: network,
            saplingParamsSourceURL: saplingParamsSourceURL,
            alias: alias,
            urlsParsingError: parsingError,
            loggingPolicy: loggingPolicy,
            isTorEnabled: isTorEnabled,
            isExchangeRateEnabled: isExchangeRateEnabled
        )
    }
    
    private init(
        container: DIContainer,
        cacheDbURL: URL?,
        urls: URLs,
        endpoint: LightWalletEndpoint,
        network: ZcashNetwork,
        saplingParamsSourceURL: SaplingParamsSourceURL,
        alias: ZcashSynchronizerAlias,
        urlsParsingError: ZcashError?,
        loggingPolicy: LoggingPolicy = .default(.debug),
        isTorEnabled: Bool,
        isExchangeRateEnabled: Bool
    ) {
        self.container = container
        self.cacheDbURL = cacheDbURL
        self.rustBackend = container.resolve(ZcashRustBackendWelding.self)
        self.fsBlockDbRoot = urls.fsBlockDbRoot
        self.generalStorageURL = urls.generalStorageURL
        self.dataDbURL = urls.dataDbURL
        self.torDirURL = urls.torDirURL
        self.endpoint = endpoint
        self.spendParamsURL = urls.spendParamsURL
        self.outputParamsURL = urls.outputParamsURL
        self.saplingParamsSourceURL = saplingParamsSourceURL
        self.alias = alias
        self.lightWalletService = container.resolve(LightWalletService.self)
        self.transactionRepository = container.resolve(TransactionRepository.self)
        self.storage = container.resolve(CompactBlockRepository.self)
        self.blockDownloaderService = container.resolve(BlockDownloaderService.self)
        self.network = network
        self.walletBirthday = container.resolve(CheckpointSource.self).saplingActivation.height
        self.urlsParsingError = urlsParsingError
        self.logger = container.resolve(Logger.self)
    }
    
    // swiftlint:disable:next function_parameter_count
    private static func setup(
        container: DIContainer,
        cacheDbURL: URL?,
        fsBlockDbRoot: URL,
        generalStorageURL: URL,
        dataDbURL: URL,
        torDirURL: URL,
        endpoint: LightWalletEndpoint,
        network: ZcashNetwork,
        spendParamsURL: URL,
        outputParamsURL: URL,
        saplingParamsSourceURL: SaplingParamsSourceURL,
        alias: ZcashSynchronizerAlias,
        loggingPolicy: LoggingPolicy = .default(.debug),
        isTorEnabled: Bool,
        isExchangeRateEnabled: Bool
    ) -> (URLs, ZcashError?) {
        let urls = URLs(
            fsBlockDbRoot: fsBlockDbRoot,
            dataDbURL: dataDbURL,
            torDirURL: torDirURL,
            generalStorageURL: generalStorageURL,
            spendParamsURL: spendParamsURL,
            outputParamsURL: outputParamsURL
        )
        
        // It's not possible to fail from constructor. Technically it's possible but it can be pain for the client apps to handle errors thrown
        // from constructor. So `parsingError` is just stored in initializer and `SDKSynchronizer.prepare()` throw this error if it exists.
        let (updatedURLs, parsingError) = Self.tryToUpdateURLs(with: alias, urls: urls)
        
        Dependencies.setup(
            in: container,
            urls: updatedURLs,
            alias: alias,
            networkType: network.networkType,
            endpoint: endpoint,
            loggingPolicy: loggingPolicy,
            isTorEnabled: isTorEnabled,
            isExchangeRateEnabled: isExchangeRateEnabled
        )
        
        return (updatedURLs, parsingError)
    }

    /// Try to update URLs with `alias`.
    ///
    /// If the `default` alias is used then the URLs are changed at all.
    /// If the `custom("anotherInstance")` is used then last path component or the URL is updated like this:
    /// - /some/path/to.file -> /some/path/c_anotherInstance_to.file
    /// - /some/path/to/directory -> /some/path/to/c_anotherInstance_directory
    ///
    /// If any of the URLs can't be parsed then returned error isn't nil.
    static func tryToUpdateURLs(
        with alias: ZcashSynchronizerAlias,
        urls: URLs
    ) -> (URLs, ZcashError?) {
        let updatedURLsResult = Self.updateURLs(with: alias, urls: urls)

        let parsingError: ZcashError?
        let updatedURLs: URLs
        switch updatedURLsResult {
        case let .success(updated):
            parsingError = nil
            updatedURLs = updated
        case let .failure(error):
            parsingError = error
            // When failure happens just use original URLs because something must be used. But this shouldn't be a problem because
            // `SDKSynchronizer.prepare()` handles this error. And the SDK won't work if it isn't switched from `unprepared` state.
            updatedURLs = urls
        }

        return (updatedURLs, parsingError)
    }

    private static func updateURLs(
        with alias: ZcashSynchronizerAlias,
        urls: URLs
    ) -> Result<URLs, ZcashError> {
        guard let updatedFsBlockDbRoot = urls.fsBlockDbRoot.updateLastPathComponent(with: alias) else {
            return .failure(.initializerCantUpdateURLWithAlias(urls.fsBlockDbRoot))
        }

        guard let updatedDataDbURL = urls.dataDbURL.updateLastPathComponent(with: alias) else {
            return .failure(.initializerCantUpdateURLWithAlias(urls.dataDbURL))
        }

        guard let updatedTorDirURL = urls.torDirURL.updateLastPathComponent(with: alias) else {
            return .failure(.initializerCantUpdateURLWithAlias(urls.torDirURL))
        }

        guard let updatedSpendParamsURL = urls.spendParamsURL.updateLastPathComponent(with: alias) else {
            return .failure(.initializerCantUpdateURLWithAlias(urls.spendParamsURL))
        }

        guard let updateOutputParamsURL = urls.outputParamsURL.updateLastPathComponent(with: alias) else {
            return .failure(.initializerCantUpdateURLWithAlias(urls.outputParamsURL))
        }

        guard let updatedGeneralStorageURL = urls.generalStorageURL.updateLastPathComponent(with: alias) else {
            return .failure(.initializerCantUpdateURLWithAlias(urls.generalStorageURL))
        }

        return .success(
            URLs(
                fsBlockDbRoot: updatedFsBlockDbRoot,
                dataDbURL: updatedDataDbURL,
                torDirURL: updatedTorDirURL,
                generalStorageURL: updatedGeneralStorageURL,
                spendParamsURL: updatedSpendParamsURL,
                outputParamsURL: updateOutputParamsURL
            )
        )
    }

    /// Initialize the wallet. The ZIP-32 seed bytes can optionally be passed to perform
    /// database migrations. most of the times the seed won't be needed. If they do and are
    /// not provided this will fail with `InitializationResult.seedRequired`. It could
    /// be the case that this method is invoked by a wallet that does not contain the seed phrase
    /// and is view-only, or by a wallet that does have the seed but the process does not have the
    /// consent of the OS to fetch the keys from the secure storage, like on background tasks.
    ///
    /// 'cache.db' and 'data.db' files are created by this function (if they
    /// do not already exist). These files can be given a prefix for scenarios where multiple wallets
    ///
    /// - Parameter seed: ZIP-32 Seed bytes for the wallet that will be initialized
    /// - Throws: `InitializerError.dataDbInitFailed` if the creation of the dataDb fails
    /// `InitializerError.accountInitFailed` if the account table can't be initialized. 
    func initialize(
        with seed: [UInt8]?,
        walletBirthday: BlockHeight,
        for walletMode: WalletInitMode,
        name: String,
        keySource: String? = nil
    ) async throws -> InitializationResult {
        try await storage.create()

        try await rustBackend.openDb()

        if case .seedRequired = try await rustBackend.initDataDb(seed: seed) {
            return .seedRequired
        }

        let checkpointSource = container.resolve(CheckpointSource.self)

        let checkpoint = checkpointSource.birthday(for: walletBirthday)

        self.walletBirthday = checkpoint.height

        // If there are no accounts it must be created, the default amount of accounts is 1
        if let seed, try await rustBackend.listAccounts().isEmpty {
            var chainTip: UInt32?
            
            let sdkFlags = container.resolve(SDKFlags.self)
            
            // called when client starts and restore of the wallet is in progress
            if walletMode == .restoreWallet {
                if let latestBlockHeight = try? await lightWalletService.latestBlockHeight(mode: await sdkFlags.ifTor(.uniqueTor)) {
                    chainTip = UInt32(latestBlockHeight)
                }
            }
            
            _ = try await rustBackend.createAccount(
                seed: seed,
                treeState: checkpoint.treeState(),
                recoverUntil: chainTip,
                name: name,
                keySource: keySource
            )
        }

        return .success
    }
    
    /**
    checks if the provided address is a valid sapling address
    */
    public func isValidSaplingAddress(_ address: String) -> Bool {
        DerivationTool(networkType: network.networkType).isValidSaplingAddress(address)
    }

    /**
    checks if the provided address is a transparent zAddress
    */
    public func isValidTransparentAddress(_ address: String) -> Bool {
        DerivationTool(networkType: network.networkType).isValidTransparentAddress(address)
    }
}
