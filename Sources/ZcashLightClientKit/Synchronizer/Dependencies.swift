//
//  Dependencies.swift
//
//
//  Created by Michal Fousek on 01.05.2023.
//

import Foundation

enum Dependencies {
    /// Phase 1: Register synchronous dependencies that don't require the rust backend.
    /// This is called from the Initializer constructor.
    // swiftlint:disable:next cyclomatic_complexity function_parameter_count
    static func setup(
        in container: DIContainer,
        urls: Initializer.URLs,
        alias: ZcashSynchronizerAlias,
        networkType: NetworkType,
        endpoint: LightWalletEndpoint,
        loggingPolicy: Initializer.LoggingPolicy = .default(.debug),
        isTorEnabled: Bool,
        isExchangeRateEnabled: Bool
    ) {
        container.register(type: SDKFlags.self, isSingleton: true) { _ in
            SDKFlags(
                torEnabled: isTorEnabled,
                exchangeRateEnabled: isExchangeRateEnabled
            )
        }

        container.register(type: CheckpointSource.self, isSingleton: true) { _ in
            CheckpointSourceFactory.fromBundle(for: networkType)
        }

        container.register(type: Logger.self, isSingleton: true) { _ in
            let logger: Logger
            switch loggingPolicy {
            case let .default(logLevel):
                logger = OSLogger(logLevel: logLevel, alias: alias)
            case let .custom(customLogger):
                logger = customLogger
            case .noLogging:
                logger = NullLogger()
            }

            return logger
        }

        container.register(type: TorClient.self, isSingleton: true) { _ in
            TorClient(torDir: urls.torDirURL)
        }

        container.register(type: LightWalletService.self, isSingleton: true) { di in
            let torClient = di.resolve(TorClient.self)

            return LightWalletGRPCServiceOverTor(endpoint: endpoint, tor: torClient)
        }

        container.register(type: TransactionRepository.self, isSingleton: true) { _ in
            /// The direct queries to the database in the SDK should be scarse. Better approach is to use FFI/rust instead.
            /// However direct connection is not blocked or denied but a hard requirement is to have such connection in a read-only mode.
            /// Never update this dependency to `readonly: false`.
            TransactionSQLDAO(dbProvider: SimpleConnectionProvider(path: urls.dataDbURL.path, readonly: true))
        }

        container.register(type: SDKMetrics.self, isSingleton: true) { _ in
            SDKMetricsImpl()
        }

        container.register(type: SyncSessionIDGenerator.self, isSingleton: false) { _ in
            UniqueSyncSessionIDGenerator()
        }

        container.register(type: ZcashFileManager.self, isSingleton: true) { _ in
            FileManager.default
        }

        // Register placeholder dependencies that will be replaced during initialize().
        // These allow the SDK to be constructed before prepare() is called.
        Self.registerPlaceholderDependencies(in: container, urls: urls, logger: container.resolve(Logger.self))
    }

    /// Register placeholder dependencies that will be replaced with real implementations during initialize().
    /// These placeholders allow tests and other code to construct SDK components before prepare() is called.
    private static func registerPlaceholderDependencies(in container: DIContainer, urls: Initializer.URLs, logger: Logger) {
        // Placeholder backend - methods will throw errors if called before prepare()
        container.register(type: ZcashRustBackendWelding.self, isSingleton: true) { _ in
            PlaceholderRustBackend()
        }

        container.register(type: CompactBlockRepository.self, isSingleton: true) { _ in
            FSCompactBlockRepository(
                fsBlockDbRoot: urls.fsBlockDbRoot,
                metadataStore: FSMetadataStore(
                    saveBlocksMeta: { _ in },
                    rewindToHeight: { _ in },
                    initFsBlockDbRoot: { },
                    latestHeight: { .empty() },
                    reopenBlockDb: { }
                ),
                blockDescriptor: .live,
                contentProvider: DirectoryListingProviders.defaultSorted,
                logger: logger
            )
        }

        container.register(type: BlockDownloaderService.self, isSingleton: true) { di in
            let service = di.resolve(LightWalletService.self)
            let storage = di.resolve(CompactBlockRepository.self)
            return BlockDownloaderServiceImpl(service: service, storage: storage)
        }

        container.register(type: LatestBlocksDataProvider.self, isSingleton: true) { _ in
            LatestBlocksDataProviderImpl.placeholder()
        }

        container.register(type: TransactionEncoder.self, isSingleton: true) { _ in
            PlaceholderTransactionEncoder()
        }
    }

    /// Phase 2: Create and register the opened rust backend.
    /// This must be called after Phase 1 and requires the directory structure to exist.
    /// Called from `Initializer.initialize()`.
    @DBActor
    static func setupRustBackend(
        in container: DIContainer,
        urls: Initializer.URLs,
        networkType: NetworkType,
        loggingPolicy: Initializer.LoggingPolicy
    ) async throws {
        let rustLogging = Self.rustLogging(from: loggingPolicy)
        let sdkFlags = container.resolve(SDKFlags.self)

        let backend = try await ZcashRustBackend.open(
            dbData: urls.dataDbURL,
            fsBlockDbRoot: urls.fsBlockDbRoot,
            spendParamsPath: urls.spendParamsURL,
            outputParamsPath: urls.outputParamsURL,
            networkType: networkType,
            logLevel: rustLogging,
            sdkFlags: sdkFlags
        )

        container.register(type: ZcashRustBackendWelding.self, isSingleton: true) { _ in
            backend
        }
    }

    /// Phase 3: Register dependencies that require the rust backend.
    /// This must be called after Phase 2.
    /// Called from `Initializer.initialize()`.
    static func setupBackendDependencies(
        in container: DIContainer,
        urls: Initializer.URLs,
        networkType: NetworkType
    ) {
        let logger = container.resolve(Logger.self)
        let rustBackend = container.resolve(ZcashRustBackendWelding.self)

        container.register(type: CompactBlockRepository.self, isSingleton: true) { _ in
            FSCompactBlockRepository(
                fsBlockDbRoot: urls.fsBlockDbRoot,
                metadataStore: .live(
                    fsBlockDbRoot: urls.fsBlockDbRoot,
                    rustBackend: rustBackend,
                    logger: logger
                ),
                blockDescriptor: .live,
                contentProvider: DirectoryListingProviders.defaultSorted,
                logger: logger
            )
        }

        container.register(type: BlockDownloaderService.self, isSingleton: true) { di in
            let service = di.resolve(LightWalletService.self)
            let storage = di.resolve(CompactBlockRepository.self)

            return BlockDownloaderServiceImpl(service: service, storage: storage)
        }

        container.register(type: LatestBlocksDataProvider.self, isSingleton: true) { di in
            let service = di.resolve(LightWalletService.self)
            let sdkFlags = di.resolve(SDKFlags.self)

            return LatestBlocksDataProviderImpl(service: service, rustBackend: rustBackend, sdkFlags: sdkFlags)
        }

        container.register(type: TransactionEncoder.self, isSingleton: true) { di in
            let service = di.resolve(LightWalletService.self)
            let transactionRepository = di.resolve(TransactionRepository.self)
            let sdkFlags = di.resolve(SDKFlags.self)

            return WalletTransactionEncoder(
                rustBackend: rustBackend,
                dataDb: urls.dataDbURL,
                fsBlockDbRoot: urls.fsBlockDbRoot,
                service: service,
                repository: transactionRepository,
                outputParams: urls.outputParamsURL,
                spendParams: urls.spendParamsURL,
                networkType: networkType,
                logger: logger,
                sdkFlags: sdkFlags
            )
        }
    }

    /// Convert logging policy to RustLogging level.
    private static func rustLogging(from loggingPolicy: Initializer.LoggingPolicy) -> RustLogging {
        switch loggingPolicy {
        case .default(let logLevel):
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
        case .custom(let logger):
            switch logger.maxLogLevel() {
            case .debug:
                return RustLogging.debug
            case .info, .event:
                return RustLogging.info
            case .warning:
                return RustLogging.warn
            case .error:
                return RustLogging.error
            case .none:
                return RustLogging.off
            }
        case .noLogging:
            return RustLogging.off
        }
    }
    
    static func setupCompactBlockProcessor(
        in container: DIContainer,
        config: CompactBlockProcessor.Configuration
    ) {
        container.register(type: BlockDownloader.self, isSingleton: true) { di in
            let service = di.resolve(LightWalletService.self)
            let blockDownloaderService = di.resolve(BlockDownloaderService.self)
            let storage = di.resolve(CompactBlockRepository.self)
            let metrics = di.resolve(SDKMetrics.self)
            let logger = di.resolve(Logger.self)

            return BlockDownloaderImpl(
                service: service,
                downloaderService: blockDownloaderService,
                storage: storage,
                metrics: metrics,
                logger: logger
            )
        }

        container.register(type: BlockScanner.self, isSingleton: true) { di in
            let service = di.resolve(LightWalletService.self)
            let rustBackend = di.resolve(ZcashRustBackendWelding.self)
            let transactionRepository = di.resolve(TransactionRepository.self)
            let metrics = di.resolve(SDKMetrics.self)
            let logger = di.resolve(Logger.self)

            let blockScannerConfig = BlockScannerConfig(
                networkType: config.network.networkType,
                scanningBatchSize: config.batchSize
            )

            return BlockScannerImpl(
                config: blockScannerConfig,
                rustBackend: rustBackend,
                service: service,
                transactionRepository: transactionRepository,
                metrics: metrics,
                logger: logger
            )
        }
        
        container.register(type: BlockEnhancer.self, isSingleton: true) { di in
            let blockDownloaderService = di.resolve(BlockDownloaderService.self)
            let rustBackend = di.resolve(ZcashRustBackendWelding.self)
            let transactionRepository = di.resolve(TransactionRepository.self)
            let metrics = di.resolve(SDKMetrics.self)
            let service = di.resolve(LightWalletService.self)
            let logger = di.resolve(Logger.self)
            let sdkFlags = di.resolve(SDKFlags.self)

            return BlockEnhancerImpl(
                blockDownloaderService: blockDownloaderService,
                rustBackend: rustBackend,
                transactionRepository: transactionRepository,
                metrics: metrics,
                service: service,
                logger: logger,
                sdkFlags: sdkFlags
            )
        }
        
        container.register(type: UTXOFetcher.self, isSingleton: true) { di in
            let blockDownloaderService = di.resolve(BlockDownloaderService.self)
            let utxoFetcherConfig = UTXOFetcherConfig(walletBirthdayProvider: config.walletBirthdayProvider)
            let rustBackend = di.resolve(ZcashRustBackendWelding.self)
            let metrics = di.resolve(SDKMetrics.self)
            let logger = di.resolve(Logger.self)
            
            return UTXOFetcherImpl(
                blockDownloaderService: blockDownloaderService,
                config: utxoFetcherConfig,
                rustBackend: rustBackend,
                metrics: metrics,
                logger: logger
            )
        }
        
        container.register(type: SaplingParametersHandler.self, isSingleton: true) { di in
            let rustBackend = di.resolve(ZcashRustBackendWelding.self)
            let logger = di.resolve(Logger.self)

            let saplingParametersHandlerConfig = SaplingParametersHandlerConfig(
                outputParamsURL: config.outputParamsURL,
                spendParamsURL: config.spendParamsURL,
                saplingParamsSourceURL: config.saplingParamsSourceURL
            )
            
            return SaplingParametersHandlerImpl(
                config: saplingParametersHandlerConfig,
                rustBackend: rustBackend,
                logger: logger
            )
        }
    }
}
