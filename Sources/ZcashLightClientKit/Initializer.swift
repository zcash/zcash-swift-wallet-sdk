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

// Sendable: a pure value type (String/Int/Bool fields). [v0.7 P1b] Alternate-endpoint
// lists cross the SlipstreamSynchronizer actor boundary, which makes hosts building
// under strict concurrency need this conformance spelled out.
extension LightWalletEndpoint: Equatable, Sendable {}

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
        case seedNotRelevant
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

    /// [v2.1 E-6] Engine-owned wallet-provisioning anchor source. `SlipstreamSynchronizer`
    /// sets this before `prepare()` runs `initialize`, routing the restore/new chain-fact
    /// fetch (recover_until tip; reorg-safe new-wallet tree state) through the engine's
    /// `restore_anchor` primitive — offline fallback policy and Tor privacy included.
    /// `nil` (the legacy `SDKSynchronizer` path) keeps the host-side fetch below,
    /// byte-for-byte (the old sync path is frozen).
    /// Signature: (isRestore, birthday, latest bundled checkpoint height) → anchor.
    var slipstreamAnchorSource: ((Bool, BlockHeight, BlockHeight) async -> SlipstreamRestoreAnchor?)?

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

        // A custom network carries a base identity + custom NU activation heights; register them with
        // the Rust core before any FFI call resolves the custom (regtest-slot) network id.
        // Process-global (see MIGRATING.md).
        if let activationHeights = network.customActivationHeights {
            let cleanRegistration = ZcashRustBackend.setCustomNetwork(
                base: network.customNetworkBase ?? network.networkType,
                activationHeights
            )
            if !cleanRegistration {
                // A different custom network was already registered in this process. The new values
                // are applied (last writer wins), but per-instance state of any earlier Initializer
                // (e.g. its checkpoint source) no longer matches the process-global parameters —
                // a host configuration bug worth failing fast on during development.
                assertionFailure(
                    "Conflicting custom-network registration: a different custom network was already registered in this process."
                )
            }
        }

        Dependencies.setup(
            in: container,
            urls: updatedURLs,
            alias: alias,
            networkType: network.networkType,
            endpoint: endpoint,
            loggingPolicy: loggingPolicy,
            isTorEnabled: isTorEnabled,
            isExchangeRateEnabled: isExchangeRateEnabled,
            regtestActivationHeights: network.customActivationHeights
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
    /// `InitializationResult.seedNotRelevant` is returned when the provided seed does not match the accounts
    /// already present in the wallet database. The rust layer currently reports this during seed-requiring
    /// migrations; callers must treat it as "this database belongs to a different wallet" rather than proceed
    /// as if initialization succeeded.
    ///
    /// 'cache.db' and 'data.db' files are created by this function (if they
    /// do not already exist). These files can be given a prefix for scenarios where multiple wallets
    ///
    /// - Parameter seed: ZIP-32 Seed bytes for the wallet that will be initialized
    /// - Throws: `InitializerError.dataDbInitFailed` if the creation of the dataDb fails
    /// `InitializerError.accountInitFailed` if the account table can't be initialized.
    func initialize(
        with seed: [UInt8]?,
        walletBirthday: BlockHeight?,
        name: String,
        keySource: String? = nil
    ) async throws -> InitializationResult {
        try await storage.create()

        switch try await rustBackend.initDataDb(seed: seed) {
        case .seedRequired:
            return .seedRequired
        case .seedNotRelevant:
            return .seedNotRelevant
        case .success:
            break
        }

        let checkpointSource = container.resolve(CheckpointSource.self)

        // A restore honors the caller's (past) birthday; a new wallet (nil birthday) starts from the
        // latest checkpoint, refined below to a reorg-safe server tree state.
        let checkpoint = checkpointSource.birthday(for: walletBirthday ?? BlockHeight.max)

        self.walletBirthday = checkpoint.height

        // If there are no accounts it must be created (the default amount of accounts is 1). The init
        // "mode" is DERIVED here — clients no longer pass `WalletInitMode`:
        //   • an account already exists  → existing wallet → we never enter this block, just open it.
        //   • no account + a birthday    → RESTORE: recover_until = current tip, so the
        //     [birthday … tip] backfill is tracked as recovery (SynchronizerState.isRecovering).
        //   • no account + nil birthday  → NEW: start at a reorg-safe recent height, no recovery phase
        //     (recover_until = nil).
        // (A deliberate re-scan/resync is a separate, explicit action — `rewind(_:)` — not an init mode.)
        let existingAccounts = try await rustBackend.listAccounts()
        try await validateSeedAgainstExistingAccounts(seed, existingAccounts: existingAccounts)
        if let seed, existingAccounts.isEmpty {
            var chainTip: UInt32?
            var accountTreeState = checkpoint.treeState()

            if let anchorSource = slipstreamAnchorSource {
                // [v2.1 E-6] SLIPSTREAM: the provisioning chain facts come from the engine's
                // `restore_anchor` primitive — one policy for every host (offline fallback +
                // Tor privacy inside; see slipstream-core anchor.rs). Keys never cross: the
                // `createAccount(seed:…)` call below stays host-side.
                let resolved = await resolveSlipstreamAnchor(
                    anchorSource,
                    checkpointSource: checkpointSource,
                    isRestore: walletBirthday != nil
                )
                chainTip = resolved.chainTip
                if let serverTreeState = resolved.treeState {
                    accountTreeState = serverTreeState
                    self.walletBirthday = BlockHeight(serverTreeState.height)
                }
            } else {
                // LEGACY (`SDKSynchronizer`) — host-side fetch policy, frozen verbatim.
                let sdkFlags = container.resolve(SDKFlags.self)

                if walletBirthday != nil {
                    // RESTORE — recover_until = current chain tip.
                    if let latestBlockHeight = try? await lightWalletService.latestBlockHeight(mode: await sdkFlags.ifTor(.uniqueTor)) {
                        chainTip = UInt32(latestBlockHeight)
                    } else {
                        // [#1755] Server unreachable at restore time: recover_until MUST still be a valid recent
                        // height. A NULL recover_until makes the restore look like a NEW wallet — recovery_progress
                        // reads complete ⇒ isRecovering=false ⇒ NO "Restoring" UI, the recovery gate never engages,
                        // and the raw (transiently over-counted) balance is shown (syncLogsMac9: recover_until=unknown,
                        // wallet showed 0 then a fluttering 8/5 with no banner). Fall back to the latest bundled
                        // checkpoint — the best offline estimate of "now"; the [checkpoint..tip] gap is caught up as a
                        // normal scan once the server is reachable, and recovery [birthday..checkpoint] keeps the
                        // restore identity. max(.., birthday+1) guarantees a non-empty recovery even for a wallet
                        // whose birthday is newer than the bundled checkpoints.
                        let latestCheckpointHeight = checkpointSource.birthday(for: BlockHeight.max).height
                        chainTip = UInt32(max(latestCheckpointHeight, self.walletBirthday + 1))
                    }
                } else {
                    // NEW — no prior history. Fetch a recent tree state below the reorg horizon so funds
                    // intended for the wallet can't be missed if the current chain tip is reorganized; leave
                    // recover_until nil (no recovery phase).
                    if let latestBlockHeight = try? await lightWalletService.latestBlockHeight(mode: await sdkFlags.ifTor(.uniqueTor)) {
                        let birthdayTreeStateHeight = max(
                            latestBlockHeight - ZcashSDK.maxReorgSize,
                            network.saplingActivationHeight
                        )
                        let blockID = BlockID(height: UInt64(birthdayTreeStateHeight))
                        if let serverTreeState = try? await lightWalletService.getTreeState(blockID, mode: await sdkFlags.ifTor(.uniqueTor)) {
                            accountTreeState = serverTreeState
                            // Not using birthdayTreeStateHeight directly just in case that something is wrong and server returns different height for
                            // tree state. At 99.9999999% of cases `birthdayTreeStateHeight` and `serverTreeState.height` will be the same. In those
                            // other cases this makes sure that there is no inconsistency between rust and `self.walletBirthday`.
                            self.walletBirthday = BlockHeight(serverTreeState.height)
                        }
                    }
                }
            }

            // [#1755] Surface the DERIVED init flow (clients no longer pass it) so a device log shows
            // exactly which path each launch took — the first thing to check when validating a restore.
            let recoverUntil = chainTip.map { "tip \($0)" } ?? "unknown"
            logger.info(
                walletBirthday != nil
                    ? "[slipstream] init flow: RESTORE — birthday \(self.walletBirthday), recover_until=\(recoverUntil)"
                    : "[slipstream] init flow: NEW — start height \(self.walletBirthday), recover_until=nil",
                file: #file,
                function: #function,
                line: #line
            )

            _ = try await rustBackend.createAccount(
                seed: seed,
                treeState: accountTreeState,
                recoverUntil: chainTip,
                name: name,
                keySource: keySource
            )
        } else {
            logger.info(
                existingAccounts.isEmpty
                    ? "[slipstream] init flow: OPEN — no seed supplied, not creating an account"
                    : "[slipstream] init flow: EXISTING — \(existingAccounts.count) account(s) present, opening (no create)",
                file: #file,
                function: #function,
                line: #line
            )
        }

        return .success
    }

    /// Seed↔account integrity guard: `initialize` is idempotent for an existing wallet, so
    /// restoring a DIFFERENT seed over existing accounts previously no-op'd silently — the
    /// keychain held seed B while data.db kept seed A's account, the app showed A's balance AND
    /// receive address (funds receivable but unspendable), and sends failed ZRUST0002. Validate
    /// the caller's seed against the stored derived account(s) before opening.
    ///
    /// The relevance check is delegated to the Rust core, which reports the seed relevant when it
    /// derives an existing account, when there are no accounts, or when there is no seed-derived
    /// account to validate against — so imported-only wallets (hardware-wallet UFVKs) are exempt.
    /// Only a genuine mismatch against existing seed-derived accounts throws. This must not use a
    /// Swift-side heuristic on `seedFingerprint`/`hdAccountIndex`, since those are also populated
    /// for imported-spending accounts and would falsely brick hardware-wallet-only wallets.
    private func validateSeedAgainstExistingAccounts(_ seed: [UInt8]?, existingAccounts: [Account]) async throws {
        guard let seed, !existingAccounts.isEmpty else { return }
        let seedIsRelevant = try await rustBackend.isSeedRelevantToAnyDerivedAccount(seed: seed)
        guard seedIsRelevant else { throw ZcashError.initializerSeedMismatch }
    }

    /// [v2.1 E-6] Resolve the slipstream provisioning anchor. RESTORE ⇒ `chainTip` = the
    /// recover_until height (always present by the engine's policy: live tip, or offline
    /// max(bundled checkpoint, birthday+1) — never NULL, the syncLogsMac9 rule). NEW ⇒
    /// `treeState` = the reorg-safe recent server tree state, or nil offline (the caller
    /// keeps the bundled checkpoint defaults).
    private func resolveSlipstreamAnchor(
        _ anchorSource: (Bool, BlockHeight, BlockHeight) async -> SlipstreamRestoreAnchor?,
        checkpointSource: CheckpointSource,
        isRestore: Bool
    ) async -> (chainTip: UInt32?, treeState: TreeState?) {
        let latestCheckpointHeight = checkpointSource.birthday(for: BlockHeight.max).height
        if isRestore {
            guard let anchor = await anchorSource(true, walletBirthday, latestCheckpointHeight) else {
                return (nil, nil)
            }
            return (UInt32(anchor.height), nil)
        } else {
            guard let anchor = await anchorSource(false, 0, latestCheckpointHeight) else {
                return (nil, nil)
            }
            return (nil, anchor.treeState)
        }
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

extension Initializer.LoggingPolicy {
    /// Builds the `Logger` this policy specifies.
    ///
    /// Extracted from what were two independently maintained copies of this exact mapping
    /// (`Synchronizer/Dependencies.swift`'s DI registration, `OrchardMigration`'s standalone
    /// backend setup) so there is one implementation to keep in sync with `LoggingPolicy`'s cases.
    ///
    /// - Parameters:
    ///   - category: the OSLog category for the `.default` case's `OSLogger`. Defaults to
    ///     `OSLogger`'s own default (`"sdkLogs"`).
    ///   - alias: the synchronizer alias folded into the `.default` case's `OSLogger` category
    ///     suffix, mirroring the DI-registered per-synchronizer-instance logger. Pass `nil` when the
    ///     logger is not scoped to a synchronizer instance (e.g. `OrchardMigration`, which predates
    ///     any `Synchronizer`).
    func makeLogger(category: String = "sdkLogs", alias: ZcashSynchronizerAlias? = nil) -> Logger {
        switch self {
        case let .default(logLevel):
            return OSLogger(logLevel: logLevel, category: category, alias: alias)
        case let .custom(customLogger):
            return customLogger
        case .noLogging:
            return NullLogger()
        }
    }

    /// Maps this policy to the Rust FFI's log-level enum: `.default` translates its `OSLogger.LogLevel`
    /// directly, `.custom` reads the supplied logger's own `maxLogLevel()` (`nil` -> `.off`), and
    /// `.noLogging` is always `.off`. Extracted alongside `makeLogger(category:alias:)` -- see its
    /// doc for the two call sites this used to be duplicated across.
    func makeRustLogging() -> RustLogging {
        switch self {
        case .default(let logLevel):
            return Self.rustLogging(for: logLevel)
        case .custom(let customLogger):
            guard let logLevel = customLogger.maxLogLevel() else {
                return RustLogging.off
            }
            return Self.rustLogging(for: logLevel)
        case .noLogging:
            return RustLogging.off
        }
    }

    private static func rustLogging(for logLevel: OSLogger.LogLevel) -> RustLogging {
        switch logLevel {
        case .debug:
            return RustLogging.debug
        case .info, .event:
            return RustLogging.info
        case .warning:
            return RustLogging.warn
        case .error:
            return RustLogging.error
        }
    }
}
