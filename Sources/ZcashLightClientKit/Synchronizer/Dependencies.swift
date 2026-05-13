//
//  Dependencies.swift
//  
//
//  Created by Michal Fousek on 01.05.2023.
//

import Foundation

enum Dependencies {
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

        let rustLogging: RustLogging
        switch loggingPolicy {
        case .default(let logLevel):
            switch logLevel {
            case .debug:
                rustLogging = RustLogging.debug
            case .info, .event:
                rustLogging = RustLogging.info
            case .warning:
                rustLogging = RustLogging.warn
            case .error:
                rustLogging = RustLogging.error
            }
        case .custom(let logger):
            switch logger.maxLogLevel() {
            case .debug:
                rustLogging = RustLogging.debug
            case .info, .event:
                rustLogging = RustLogging.info
            case .warning:
                rustLogging = RustLogging.warn
            case .error:
                rustLogging = RustLogging.error
            case .none:
                rustLogging = RustLogging.off
            }
        case .noLogging:
            rustLogging = RustLogging.off
        }

        container.register(type: ZcashRustBackendWelding.self, isSingleton: true) { di in
            let sdkFlags = di.resolve(SDKFlags.self)

            return ZcashRustBackend(
                dbData: urls.dataDbURL,
                fsBlockDbRoot: urls.fsBlockDbRoot,
                spendParamsPath: urls.spendParamsURL,
                outputParamsPath: urls.outputParamsURL,
                networkType: networkType,
                logLevel: rustLogging,
                sdkFlags: sdkFlags
            )
        }

        container.register(type: TorClient.self, isSingleton: true) { _ in
            TorClient(torDir: urls.torDirURL)
        }

        container.register(type: PendingSubmitPlanStore.self, isSingleton: true) { di in
            let logger = di.resolve(Logger.self)
            return PendingSubmitPlanStore(
                persistence: KeychainSubmitPlanPersistence(
                    alias: alias,
                    networkType: networkType
                ),
                logger: logger
            )
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

        container.register(type: CompactBlockRepository.self, isSingleton: true) { di in
            let logger = di.resolve(Logger.self)
            let rustBackend = di.resolve(ZcashRustBackendWelding.self)

            return FSCompactBlockRepository(
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

        container.register(type: SDKMetrics.self, isSingleton: true) { _ in
            SDKMetricsImpl()
        }

        container.register(type: LatestBlocksDataProvider.self, isSingleton: true) { di in
            let service = di.resolve(LightWalletService.self)
            let rustBackend = di.resolve(ZcashRustBackendWelding.self)
            let sdkFlags = di.resolve(SDKFlags.self)

            return LatestBlocksDataProviderImpl(service: service, rustBackend: rustBackend, sdkFlags: sdkFlags)
        }

        container.register(type: SyncSessionIDGenerator.self, isSingleton: false) { _ in
            UniqueSyncSessionIDGenerator()
        }
        
        container.register(type: ZcashFileManager.self, isSingleton: true) { _ in
            FileManager.default
        }

        container.register(type: TransactionSubmitter.self, isSingleton: true) { di in
            EndpointTransactionSubmitter(
                torClient: di.resolve(TorClient.self),
                sdkFlags: di.resolve(SDKFlags.self)
            )
        }

        container.register(type: SubmitPlanExecutor.self, isSingleton: true) { di in
            SubmitPlanExecutor(transactionSubmitter: di.resolve(TransactionSubmitter.self))
        }
        
        container.register(type: TransactionEncoder.self, isSingleton: true) { di in
            let service = di.resolve(LightWalletService.self)
            let logger = di.resolve(Logger.self)
            let transactionRepository = di.resolve(TransactionRepository.self)
            let rustBackend = di.resolve(ZcashRustBackendWelding.self)
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
