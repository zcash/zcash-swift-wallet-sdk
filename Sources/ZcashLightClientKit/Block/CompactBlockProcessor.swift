//
//  CompactBlockProcessor.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 18/09/2019.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import Foundation
import Combine

public typealias RefreshedUTXOs = (inserted: [UnspentTransactionOutputEntity], skipped: [UnspentTransactionOutputEntity])

/// The compact block processor is in charge of orchestrating the download and caching of compact blocks from a LightWalletEndpoint
/// when started the processor downloads does a download - validate - scan cycle until it reaches latest height on the blockchain.
actor CompactBlockProcessor {
    // It would be better to use Combine here but Combine doesn't work great with async. When this runs regularly only one closure is stored here
    // and that is one provided by `SDKSynchronizer`. But while running tests more "subscribers" is required here. Therefore it's required to handle
    // more closures here.
    private var eventClosures: [String: EventClosure] = [:]

    private var syncTask: Task<Void, Error>?
    private var mempoolDetectionTask: Task<Void, Error>?

    private let actions: [CBPState: Action]
    var context: ActionContext

    private(set) var config: Configuration
    private let configProvider: ConfigProvider
    private var afterSyncHooksManager = AfterSyncHooksManager()

    var blockDownloaderService: BlockDownloaderService
    private var latestBlocksDataProvider: LatestBlocksDataProvider
    private let logger: Logger
    private let metrics: SDKMetrics
    private let rustBackend: ZcashRustBackendWelding
    var service: LightWalletService
    let storage: CompactBlockRepository
    private let transactionRepository: TransactionRepository
    private let fileManager: ZcashFileManager

    private var retryAttempts: Int = 0
    private var serviceFailureRetryAttempts: Int = 0
    private var backoffTimer: Timer?
    private var consecutiveChainValidationErrors: Int = 0
    
    private var compactBlockProgress: CompactBlockProgress = .zero
    
    /// Compact Block Processor configuration
    ///
    /// - parameter fsBlockCacheRoot: absolute root path where the filesystem block cache will be stored.
    /// - parameter dataDb: absolute file path of the DB where all information derived from the cache DB is stored.
    /// - parameter spendParamsURL: absolute file path of the sapling-spend.params file
    /// - parameter outputParamsURL: absolute file path of the sapling-output.params file
    struct Configuration {
        let alias: ZcashSynchronizerAlias
        let saplingParamsSourceURL: SaplingParamsSourceURL
        let fsBlockCacheRoot: URL
        let dataDb: URL
        let torDir: URL
        let spendParamsURL: URL
        let outputParamsURL: URL
        let enhanceBatchSize: Int
        let batchSize: Int
        let retries: Int
        let maxBackoffInterval: TimeInterval
        let maxReorgSize = ZcashSDK.maxReorgSize
        let rewindDistance: Int
        let walletBirthdayProvider: () -> BlockHeight
        var walletBirthday: BlockHeight { walletBirthdayProvider() }
        let downloadBufferSize: Int = 100
        let network: ZcashNetwork
        let saplingActivation: BlockHeight
        let cacheDbURL: URL?
        var blockPollInterval: TimeInterval {
            TimeInterval.random(in: ZcashSDK.defaultPollInterval / 2 ... ZcashSDK.defaultPollInterval * 1.5)
        }

        init(
            alias: ZcashSynchronizerAlias,
            cacheDbURL: URL? = nil,
            fsBlockCacheRoot: URL,
            dataDb: URL,
            torDir: URL,
            spendParamsURL: URL,
            outputParamsURL: URL,
            saplingParamsSourceURL: SaplingParamsSourceURL,
            enhanceBatchSize: Int = ZcashSDK.DefaultEnhanceBatch,
            batchSize: Int = ZcashSDK.DefaultBatchSize,
            retries: Int = ZcashSDK.defaultRetries,
            maxBackoffInterval: TimeInterval = ZcashSDK.defaultMaxBackOffInterval,
            rewindDistance: Int = ZcashSDK.defaultRewindDistance,
            walletBirthdayProvider: @escaping () -> BlockHeight,
            saplingActivation: BlockHeight,
            network: ZcashNetwork
        ) {
            self.alias = alias
            self.fsBlockCacheRoot = fsBlockCacheRoot
            self.dataDb = dataDb
            self.torDir = torDir
            self.spendParamsURL = spendParamsURL
            self.outputParamsURL = outputParamsURL
            self.saplingParamsSourceURL = saplingParamsSourceURL
            self.network = network
            self.enhanceBatchSize = enhanceBatchSize
            self.batchSize = batchSize
            self.retries = retries
            self.maxBackoffInterval = maxBackoffInterval
            self.rewindDistance = rewindDistance
            self.walletBirthdayProvider = walletBirthdayProvider
            self.saplingActivation = saplingActivation
            self.cacheDbURL = cacheDbURL
        }

        init(
            alias: ZcashSynchronizerAlias,
            fsBlockCacheRoot: URL,
            dataDb: URL,
            torDir: URL,
            spendParamsURL: URL,
            outputParamsURL: URL,
            saplingParamsSourceURL: SaplingParamsSourceURL,
            enhanceBatchSize: Int = ZcashSDK.DefaultEnhanceBatch,
            batchSize: Int = ZcashSDK.DefaultBatchSize,
            retries: Int = ZcashSDK.defaultRetries,
            maxBackoffInterval: TimeInterval = ZcashSDK.defaultMaxBackOffInterval,
            rewindDistance: Int = ZcashSDK.defaultRewindDistance,
            walletBirthdayProvider: @escaping () -> BlockHeight,
            network: ZcashNetwork
        ) {
            self.alias = alias
            self.fsBlockCacheRoot = fsBlockCacheRoot
            self.dataDb = dataDb
            self.torDir = torDir
            self.spendParamsURL = spendParamsURL
            self.outputParamsURL = outputParamsURL
            self.saplingParamsSourceURL = saplingParamsSourceURL
            self.walletBirthdayProvider = walletBirthdayProvider
            self.saplingActivation = network.constants.saplingActivationHeight
            self.network = network
            self.cacheDbURL = nil
            self.enhanceBatchSize = enhanceBatchSize
            self.batchSize = batchSize
            self.retries = retries
            self.maxBackoffInterval = maxBackoffInterval
            self.rewindDistance = rewindDistance
        }
    }

    /// Initializes a CompactBlockProcessor instance from an Initialized object
    /// - Parameters:
    ///     - initializer: an instance that complies to CompactBlockDownloading protocol
    init(initializer: Initializer, walletBirthdayProvider: @escaping () -> BlockHeight) {
        self.init(
            container: initializer.container,
            config: Configuration(
                alias: initializer.alias,
                fsBlockCacheRoot: initializer.fsBlockDbRoot,
                dataDb: initializer.dataDbURL,
                torDir: initializer.torDirURL,
                spendParamsURL: initializer.spendParamsURL,
                outputParamsURL: initializer.outputParamsURL,
                saplingParamsSourceURL: initializer.saplingParamsSourceURL,
                walletBirthdayProvider: walletBirthdayProvider,
                network: initializer.network
            )
        )
    }

    /// Initializes a CompactBlockProcessor instance
    /// - Parameters:
    ///  - service: concrete implementation of `LightWalletService` protocol
    ///  - storage: concrete implementation of `CompactBlockRepository` protocol
    ///  - backend: a class that complies to `ZcashRustBackendWelding`
    ///  - config: `Configuration` struct for this processor
    init(
        container: DIContainer,
        config: Configuration
    ) {
        Dependencies.setupCompactBlockProcessor(
            in: container,
            config: config
        )

        let configProvider = ConfigProvider(config: config)
        context = ActionContextImpl(state: .idle)
        actions = Self.makeActions(container: container, configProvider: configProvider)

        self.metrics = container.resolve(SDKMetrics.self)
        self.logger = container.resolve(Logger.self)
        self.latestBlocksDataProvider = container.resolve(LatestBlocksDataProvider.self)
        self.blockDownloaderService = container.resolve(BlockDownloaderService.self)
        self.service = container.resolve(LightWalletService.self)
        self.rustBackend = container.resolve(ZcashRustBackendWelding.self)
        self.storage = container.resolve(CompactBlockRepository.self)
        self.config = config
        self.transactionRepository = container.resolve(TransactionRepository.self)
        self.fileManager = container.resolve(ZcashFileManager.self)
        self.configProvider = configProvider
    }

    deinit {
        syncTask?.cancel()
        syncTask = nil
        mempoolDetectionTask?.cancel()
        mempoolDetectionTask = nil
    }

    // swiftlint:disable:next cyclomatic_complexity
    private static func makeActions(container: DIContainer, configProvider: ConfigProvider) -> [CBPState: Action] {
        let actionsDefinition = CBPState.allCases.compactMap { state -> (CBPState, Action)? in
            let action: Action
            switch state {
            case .migrateLegacyCacheDB:
                action = MigrateLegacyCacheDBAction(container: container, configProvider: configProvider)
            case .validateServer:
                action = ValidateServerAction(container: container, configProvider: configProvider)
            case .updateSubtreeRoots:
                action = UpdateSubtreeRootsAction(container: container, configProvider: configProvider)
            case .updateChainTip:
                action = UpdateChainTipAction(container: container)
            case .processSuggestedScanRanges:
                action = ProcessSuggestedScanRangesAction(container: container)
            case .rewind:
                action = RewindAction(container: container)
            case .download:
                action = DownloadAction(container: container, configProvider: configProvider)
            case .scan:
                action = ScanAction(container: container, configProvider: configProvider)
            case .clearAlreadyScannedBlocks:
                action = ClearAlreadyScannedBlocksAction(container: container)
            case .enhance:
                action = EnhanceAction(container: container, configProvider: configProvider)
            case .fetchUTXO:
                action = FetchUTXOsAction(container: container)
            case .handleSaplingParams:
                action = SaplingParamsAction(container: container)
            case .clearCache:
                action = ClearCacheAction(container: container)
            case .txResubmission:
                action = TxResubmissionAction(container: container)
            case .finished, .failed, .stopped, .idle:
                return nil
            }

            return (state, action)
        }

        return Dictionary(uniqueKeysWithValues: actionsDefinition)
    }

    // This is currently used only in tests. And it should be used only in tests.
    func update(config: Configuration) async {
        self.config = config
        await configProvider.update(config: config)
    }
}

// MARK: - "Public" API

extension CompactBlockProcessor {
    func start(retry: Bool = false) async {
        if retry {
            self.retryAttempts = 0
            self.serviceFailureRetryAttempts = 0
            self.backoffTimer?.invalidate()
            self.backoffTimer = nil
        }

        guard await canStartSync() else {
            if await isIdle() {
                logger.warn("max retry attempts reached on \(await context.state) state")
                await send(event: .failed(ZcashError.compactBlockProcessorMaxAttemptsReached(config.retries)))
            } else {
                logger.debug("Warning: compact block processor was started while busy!!!!")
                afterSyncHooksManager.insert(hook: .anotherSync)
            }
            return
        }

        syncTask = Task(priority: .userInitiated) {
            await run()
        }
        
        mempoolDetectionTask = Task {
            await watchMempool()
        }
    }

    func stop() async {
        syncTask?.cancel()
        mempoolDetectionTask?.cancel()
        self.backoffTimer?.invalidate()
        self.backoffTimer = nil
        await stopAllActions()
        retryAttempts = 0
        serviceFailureRetryAttempts = 0
    }

    func latestHeight(mode: ServiceMode) async throws -> BlockHeight {
        try await blockDownloaderService.latestBlockHeight(mode: mode)
    }
    
    func consensusBranchIdFor(_ height: Int32) -> Int32? {
        try? rustBackend.consensusBranchIdFor(height: height)
    }
}

// MARK: - Rewind

extension CompactBlockProcessor {
    /// Rewinds to provided height.
    /// - Parameter height: height to rewind to. If nil is provided, it will rescan to nearest height (quick rescan)
    ///
    /// - Note: If this is called while sync is in progress then the sync process is stopped first and then rewind is executed.
    func rewind(context: AfterSyncHooksManager.RewindContext) async throws {
        logger.debug("Starting rewind")
        if await isIdle() {
            logger.debug("Sync doesn't run. Executing rewind.")
            try await doRewind(context: context)
        } else {
            logger.debug("Stopping sync because of rewind")
            afterSyncHooksManager.insert(hook: .rewind(context))
            await stop()
        }
    }

    private func doRewind(context: AfterSyncHooksManager.RewindContext) async throws {
        logger.debug("Executing rewind.")
        let lastDownloaded = await latestBlocksDataProvider.maxScannedHeight
        var rewindHeight = BlockHeight(Int32(context.height ?? lastDownloaded) - 10)
        do {
            let rewindResult = try await rustBackend.rewindToHeight(height: rewindHeight)
            switch rewindResult {
            case let .success(height):
                rewindHeight = height
            case let .requestedHeightTooLow(safeHeight):
                let retryResult = try await rustBackend.rewindToHeight(height: safeHeight)
                switch retryResult {
                case let .success(height):
                    rewindHeight = height
                default:
                    throw ZcashError.rustRewindToHeight(Int32(safeHeight), lastErrorMessage(fallback: "`rewindToHeight` unable to rewind"))
                }
            }
            try await rewindDownloadBlockAction(to: rewindHeight)
        } catch {
            await failure(error)
            return await context.completion(.failure(error))
        }

        // clear cache
        let rewindBlockHeight = BlockHeight(rewindHeight)
        do {
            try await blockDownloaderService.rewind(to: rewindBlockHeight)
        } catch {
            return await context.completion(.failure(error))
        }
        
        await resetContext(restoreLastEnhancedHeight: false)

        await context.completion(.success(rewindBlockHeight))
    }
}

// MARK: - Actions

private extension CompactBlockProcessor {
    func rewindDownloadBlockAction(to rewindHeight: BlockHeight?) async throws {
        if let downloadAction = actions[.download] as? DownloadAction {
            await downloadAction.downloader.rewind(latestDownloadedBlockHeight: rewindHeight)
        } else {
            throw ZcashError.compactBlockProcessorDownloadBlockActionRewind
        }
    }
}

// MARK: - Mempool Detection

extension CompactBlockProcessor {
    func watchMempool() async {
        while !Task.isCancelled {
            do {
                try await consumeMempoolStream()
                
                try await Task.sleep(nanoseconds: 500_000_000)
            } catch {
                // Connection hammering prevention, wait 30s in case stream failed
                try? await Task.sleep(nanoseconds: 30_000_000_000)
            }
        }
    }
    
    func consumeMempoolStream() async throws {
        let stream = try service.getMempoolStream()
        
        do {
            for try await rawTransaction in stream {
                let mempoolTransactions = try await resolveMempools(rawTransaction: rawTransaction)
                
                if !mempoolTransactions.isEmpty {
                    let height = BlockHeight(rawTransaction.height)
                    await send(event: .foundTransactions(mempoolTransactions, .init(uncheckedBounds: (lower: height, upper: height))))
                }
            }
        } catch { }
    }
    
    @DBActor
    func resolveMempools(rawTransaction: RawTransaction) async throws -> [ZcashTransaction.Overview] {
        let minedHeight = (rawTransaction.height == 0 || rawTransaction.height > UInt32.max)
        ? nil : UInt32(rawTransaction.height)
        
        let txIdData = try await rustBackend.decryptAndStoreTransaction(
            txBytes: rawTransaction.data.bytes,
            minedHeight: minedHeight
        )

        if let transaction = try? await transactionRepository.find(rawID: txIdData) {
            return [transaction]
        }
        
        return []
    }
}

// MARK: - Wipe

extension CompactBlockProcessor {
    func wipe(context: AfterSyncHooksManager.WipeContext) async throws {
        logger.debug("Starting wipe")
        if await isIdle() {
            logger.debug("Sync doesn't run. Executing wipe.")
            self.backoffTimer?.invalidate()
            self.backoffTimer = nil
            try await doWipe(context: context)
        } else {
            logger.debug("Stopping sync because of wipe")
            afterSyncHooksManager.insert(hook: .wipe(context))
            await stop()
        }
    }

    private func doWipe(context: AfterSyncHooksManager.WipeContext) async throws {
        logger.debug("Executing wipe.")
        context.prewipe()

        do {
            try self.storage.wipe()

            wipeLegacyCacheDbIfNeeded()

            let fileManager = FileManager.default
            if fileManager.fileExists(atPath: config.dataDb.path) {
                try fileManager.removeItem(at: config.dataDb)
            }

            try await rewindDownloadBlockAction(to: nil)

            await latestBlocksDataProvider.reset()
            
            await context.completion(nil)
        } catch {
            await context.completion(error)
        }
    }

    private func wipeLegacyCacheDbIfNeeded() {
        guard let cacheDbURL = config.cacheDbURL else { return }
        guard fileManager.isDeletableFile(atPath: cacheDbURL.pathExtension) else { return }
        try? fileManager.removeItem(at: cacheDbURL)
    }
}

// MARK: - Switch server

extension CompactBlockProcessor {
    func updateService(_ container: DIContainer) {
        // LightWalletGRPCService
        let updatedLWDService = container.resolve(LightWalletService.self)
        
        (actions[.processSuggestedScanRanges] as? ProcessSuggestedScanRangesAction)?.service = updatedLWDService
        (actions[.updateChainTip] as? UpdateChainTipAction)?.service = updatedLWDService
        (actions[.updateSubtreeRoots] as? UpdateSubtreeRootsAction)?.service = updatedLWDService
        (actions[.validateServer] as? ValidateServerAction)?.service = updatedLWDService
        self.service = updatedLWDService
        
        // BlockDownloaderService
        let updatedDownloaderService = container.resolve(BlockDownloaderService.self)

        (actions[.rewind] as? RewindAction)?.downloaderService = updatedDownloaderService
        self.blockDownloaderService = updatedDownloaderService
        
        // LatestBlocksDataProvider
        let updatedLBDProvider = container.resolve(LatestBlocksDataProvider.self)

        (actions[.scan] as? ScanAction)?.latestBlocksDataProvider = updatedLBDProvider
        (actions[.updateChainTip] as? UpdateChainTipAction)?.latestBlocksDataProvider = updatedLBDProvider
        self.latestBlocksDataProvider = updatedLBDProvider
        
        // BlockDownloader
        let updatedBlockDownloader = container.resolve(BlockDownloader.self)

        (actions[.download] as? DownloadAction)?.downloader = updatedBlockDownloader
        (actions[.updateChainTip] as? UpdateChainTipAction)?.downloader = updatedBlockDownloader
        (actions[.rewind] as? RewindAction)?.downloader = updatedBlockDownloader
        self.blockDownloaderService = updatedDownloaderService
        
        // BlockEnhancer
        let updatedEnhancer = container.resolve(BlockEnhancer.self)

        (actions[.enhance] as? EnhanceAction)?.blockEnhancer = updatedEnhancer

        // UTXOFetcher
        let updatedUTXOFetcher = container.resolve(UTXOFetcher.self)

        (actions[.fetchUTXO] as? FetchUTXOsAction)?.utxoFetcher = updatedUTXOFetcher
    }
}

// MARK: - Events

extension CompactBlockProcessor {
    typealias EventClosure = (Event) async -> Void

    enum Event {
        /// Event sent when the CompactBlockProcessor presented an error.
        case failed(Error)

        /// Event sent when the CompactBlockProcessor has finished syncing the blockchain to latest height
        case finished(_ lastScannedHeight: BlockHeight)

        /// Event sent when the CompactBlockProcessor found a newly mined transaction
        case minedTransaction(ZcashTransaction.Overview)

        /// Event sent when the CompactBlockProcessor enhanced a bunch of transactions in some range.
        case foundTransactions([ZcashTransaction.Overview], CompactBlockRange)

        /// Event sent when the CompactBlockProcessor handled a ReOrg.
        /// `reorgHeight` is the height on which the reorg was detected.
        /// `rewindHeight` is the height that the processor backed to in order to solve the Reorg.
        case handledReorg(_ reorgHeight: BlockHeight, _ rewindHeight: BlockHeight)

        /// Event sent when progress of some specific action happened.
        case syncProgress(Float, Bool)

        /// Event sent when progress of the sync process changes.
        case progressUpdated(Float, Bool)

        /// Event sent when the CompactBlockProcessor fetched utxos from lightwalletd attempted to store them.
        case storedUTXOs((inserted: [UnspentTransactionOutputEntity], skipped: [UnspentTransactionOutputEntity]))

        /// Event sent when the CompactBlockProcessor starts enhancing of the transactions.
        case startedEnhancing

        /// Event sent when the CompactBlockProcessor starts fetching of the UTXOs.
        case startedFetching

        /// Event sent when the CompactBlockProcessor starts syncing.
        case startedSyncing

        /// Event sent when the CompactBlockProcessor stops syncing.
        case stopped
    }

    func updateEventClosure(identifier: String, closure: @escaping (Event) async -> Void) async {
        eventClosures[identifier] = closure
    }

    private func send(event: Event) async {
        for item in eventClosures {
            await item.value(event)
        }
    }
}

// MARK: - Main loop

extension CompactBlockProcessor {
    // This is main loop of the sync process. It simply takes state and try to find action which handles it. If action is found it executes the
    // action. If action is not found then loop finishes. Thanks to this it's super easy to identify start point of sync process and end points
    // of sync process without any side effects.
    //
    // Check `docs/cbp_state_machine.puml` file and `docs/images/cbp_state_machine.png` file to see all the state tree. Also when you update state
    // tree in the code update this documentation. Image is generated by plantuml tool.
    //
    // swiftlint:disable:next cyclomatic_complexity
    private func run() async {
        logger.debug("Starting run")
        metrics.cbpStart()
        await resetContext()

        while true {
            // Sync is starting when the state is `idle`.
            if await context.state == .idle {
                // Side effect of calling stop is to delete last used download stream. To be sure that it doesn't keep any data in memory.
                await stopAllActions()
                // Update state to the first state in state machine that can be handled by action.
                await context.update(state: .migrateLegacyCacheDB)
                await syncStarted()

                if backoffTimer == nil {
                    await setTimer()
                }
            }

            let state = await context.state
            logger.debug("Handling state: \(state)")

            // Try to find action for state.
            guard let action = actions[state] else {
                // Side effect of calling stop is to delete last used download stream. To be sure that it doesn't keep any data in memory.
                await stopAllActions()
                if await syncFinished() {
                    await resetContext()
                    continue
                } else {
                    break
                }
            }

            do {
                try Task.checkCancellation()

                // Execute action.
                metrics.actionStart(state)
                context = try await action.run(with: context) { [weak self] event in
                    await self?.send(event: event)
                    if let progressChanged = await self?.compactBlockProgress.hasProgressUpdated(event), progressChanged {
                        if let progress = await self?.compactBlockProgress.progress {
                            await self?.send(
                                event: .progressUpdated(progress, self?.compactBlockProgress.areFundsSpendable ?? false)
                            )
                        }
                    }
                }

                await didFinishAction()
            } catch {
                // Side effect of calling stop is to delete last used download stream. To be sure that it doesn't keep any data in memory.
                await stopAllActions()
                logger.error("Sync failed with error: \(error)")

                // catching the service errors
                let serviceError: Bool
                switch error {
                case ZcashError.serviceGetInfoFailed, ZcashError.serviceLatestBlockFailed,
                    ZcashError.serviceLatestBlockHeightFailed, ZcashError.serviceBlockRangeFailed,
                    ZcashError.serviceSubmitFailed, ZcashError.serviceFetchTransactionFailed,
                    ZcashError.serviceFetchUTXOsFailed, ZcashError.serviceBlockStreamFailed,
                    ZcashError.serviceSubtreeRootsStreamFailed: serviceError = true
                default: serviceError = false
                }

                if serviceError && self.serviceFailureRetryAttempts < ZcashSDK.serviceFailureRetries {
                    // This may be false positive communication error that is usually resolved by retry.
                    // We will try to reset the sync and continue but this will we done at most `ZcashSDK.serviceFailureRetries` times.
                    logger.error("ServiceError: \(error), retry is available, starting the sync all over again.")

                    self.serviceFailureRetryAttempts += 1
                    
                    // Start sync all over again
                    await resetContext()
                } else if Task.isCancelled {
                    logger.info("Processing cancelled.")
                    do {
                        if try await syncTaskWasCancelled() {
                            // Start sync all over again
                            await resetContext()
                        } else {
                            // end the sync loop
                            break
                        }
                    } catch {
                        await failure(error)
                        break
                    }
                } else {
                    await handleSyncFailure(action: action, error: error)
                    break
                }
            }
        }

        logger.debug("Run ended")
        syncTask = nil
    }

    private func syncTaskWasCancelled() async throws -> Bool {
        logger.info("Sync cancelled.")
        await context.update(state: .stopped)
        await send(event: .stopped)
        return try await handleAfterSyncHooks()
    }

    private func handleSyncFailure(action: Action, error: Error) async {
        if action.removeBlocksCacheWhenFailed {
            await ifTaskIsNotCanceledClearCompactBlockCache()
        }

        logger.error("Sync failed with error: \(error)")
        await failure(error)
    }

    // swiftlint:disable:next cyclomatic_complexity
    private func didFinishAction() async {
        // This is evalution of the state setup by previous action.
        switch await context.state {
        case .idle:
            break
        case .migrateLegacyCacheDB:
            break
        case .validateServer:
            break
        case .updateSubtreeRoots:
            break
        case .updateChainTip:
            break
        case .processSuggestedScanRanges:
            break
        case .rewind:
            break
        case .download:
            break
        case .scan:
            break
        case .clearAlreadyScannedBlocks:
            break
        case .enhance:
            await send(event: .startedEnhancing)
        case .fetchUTXO:
            await send(event: .startedFetching)
        case .handleSaplingParams:
            break
        case .clearCache:
            break
        case .finished:
            break
        case .failed:
            break
        case .stopped:
            break
        case .txResubmission:
            break
        }
    }

    func resetContext(restoreLastEnhancedHeight: Bool = true) async {
        let lastEnhancedHeight = await context.lastEnhancedHeight
        context = ActionContextImpl(state: .idle)
        if restoreLastEnhancedHeight {
            await context.update(lastEnhancedHeight: lastEnhancedHeight)
        }
    }

    private func syncStarted() async {
        logger.debug("Sync started")
        // handle start of the sync process
        await send(event: .startedSyncing)
    }

    private func syncFinished() async -> Bool {
        logger.debug("Sync finished")
        let latestBlockHeightWhenSyncing = await context.syncControlData.latestBlockHeight
        let latestBlockHeight = await latestBlocksDataProvider.latestBlockHeight
        // If `latestBlockHeightWhenSyncing` is 0 then it means that there was nothing to sync in last sync process.
        let newerBlocksWereMinedDuringSync =
            latestBlockHeightWhenSyncing > 0 && latestBlockHeightWhenSyncing < latestBlockHeight

        retryAttempts = 0
        serviceFailureRetryAttempts = 0
        consecutiveChainValidationErrors = 0

        let lastScannedHeight = await latestBlocksDataProvider.maxScannedHeight
        // Some actions may not run. For example there are no transactions to enhance and therefore there is no enhance progress. And in
        // cases like this computation of final progress won't work properly. So let's fake 100% progress at the end of the sync process.
        await send(event: .progressUpdated(1, false))
        await send(event: .finished(lastScannedHeight))
        await context.update(state: .finished)

        let walletSummary = try? await rustBackend.getWalletSummary()
        await metrics.logCBPOverviewReport(logger, walletSummary: walletSummary)

        // If new blocks were mined during previous sync run the sync process again
        if newerBlocksWereMinedDuringSync {
            return true
        } else {
            await setTimer()
            return false
        }
    }

    private func failure(_ error: Error) async {
        await context.update(state: .failed)

        logger.error("Fail with error: \(error)")

        self.retryAttempts += 1
        await send(event: .failed(error))

        // don't set a new timer if there are no more attempts.
        if hasRetryAttempt() {
            await self.setTimer()
        }
    }

    private func handleAfterSyncHooks() async throws -> Bool {
        let afterSyncHooksManager = self.afterSyncHooksManager
        self.afterSyncHooksManager = AfterSyncHooksManager()

        if let wipeContext = afterSyncHooksManager.shouldExecuteWipeHook() {
            try await doWipe(context: wipeContext)
            return false
        } else if let rewindContext = afterSyncHooksManager.shouldExecuteRewindHook() {
            try await doRewind(context: rewindContext)
            return false
        } else if afterSyncHooksManager.shouldExecuteAnotherSyncHook() {
            logger.debug("Starting new sync.")
            return true
        } else {
            return false
        }
    }
}

// MARK: - Utils

extension CompactBlockProcessor {
    private func setTimer() async {
        let interval = config.blockPollInterval
        self.backoffTimer?.invalidate()
        let timer = Timer(
            timeInterval: interval,
            repeats: true,
            block: { [weak self] _ in
                Task { [weak self] in
                    guard let self else { return }
                    if await self.isIdle() {
                        if await self.canStartSync() {
                            await self.logger.debug(
                                """
                                Timer triggered: Starting compact Block processor!.
                                Processor State: \(await self.context.state)
                                attempts: \(await self.retryAttempts)
                                """
                            )
                            await self.start()
                        } else if await self.hasRetryAttempt() {
                            await self.failure(ZcashError.compactBlockProcessorMaxAttemptsReached(self.config.retries))
                        }
                    } else {
                        await self.latestBlocksDataProvider.updateBlockData()
                    }
                }
            }
        )
        RunLoop.main.add(timer, forMode: .default)
        self.backoffTimer = timer
    }

    private func isIdle() async -> Bool {
        return syncTask == nil
    }

    private func canStartSync() async -> Bool {
        return await isIdle() && hasRetryAttempt()
    }

    private func hasRetryAttempt() -> Bool {
        retryAttempts < config.retries
    }

    func determineLowerBound(errorHeight: Int, consecutiveErrors: Int, walletBirthday: BlockHeight) -> BlockHeight {
        let offset = min(ZcashSDK.maxReorgSize, ZcashSDK.defaultRewindDistance * (consecutiveErrors + 1))
        return max(errorHeight - offset, walletBirthday - ZcashSDK.maxReorgSize)
    }

    private func stopAllActions() async {
        for action in actions.values {
            await action.stop()
        }
    }

    private func ifTaskIsNotCanceledClearCompactBlockCache() async {
        guard !Task.isCancelled else { return }
        do {
            try await clearCompactBlockCache()
        } catch {
            logger.error("`clearCompactBlockCache` failed after error: \(error)")
        }
    }

    private func clearCompactBlockCache() async throws {
        await stopAllActions()
        try await storage.clear()
        logger.info("Cache removed")
    }
}

extension CompactBlockProcessor {
    func getUnifiedAddress(accountUUID: AccountUUID) async throws -> UnifiedAddress {
        try await rustBackend.getCurrentAddress(accountUUID: accountUUID)
    }
    
    func getSaplingAddress(accountUUID: AccountUUID) async throws -> SaplingAddress {
        try await getUnifiedAddress(accountUUID: accountUUID).saplingReceiver()
    }
    
    func getTransparentAddress(accountUUID: AccountUUID) async throws -> TransparentAddress {
        try await getUnifiedAddress(accountUUID: accountUUID).transparentReceiver()
    }

    func getCustomUnifiedAddress(accountUUID: AccountUUID, receivers: Set<ReceiverType>) async throws -> UnifiedAddress {
        try await rustBackend.getNextAvailableAddress(accountUUID: accountUUID, receiverFlags: receivers.toFlags())
    }
}

extension CompactBlockProcessor {
    func refreshUTXOs(tAddress: TransparentAddress, startHeight: BlockHeight) async throws -> RefreshedUTXOs {
        let dataDb = self.config.dataDb
        
        // ServiceMode to resolve
        let stream: AsyncThrowingStream<UnspentTransactionOutputEntity, Error> = try blockDownloaderService.fetchUnspentTransactionOutputs(
            tAddress: tAddress.stringEncoded,
            startHeight: startHeight,
            mode: .direct
        )
        var utxos: [UnspentTransactionOutputEntity] = []
        
        do {
            for try await utxo in stream {
                utxos.append(utxo)
            }
            return await storeUTXOs(utxos, in: dataDb)
        } catch {
            throw error
        }
    }
    
    private func storeUTXOs(_ utxos: [UnspentTransactionOutputEntity], in dataDb: URL) async -> RefreshedUTXOs {
        var refreshed: [UnspentTransactionOutputEntity] = []
        var skipped: [UnspentTransactionOutputEntity] = []
        for utxo in utxos {
            do {
                try await rustBackend.putUnspentTransparentOutput(
                    txid: utxo.txid.bytes,
                    index: utxo.index,
                    script: utxo.script.bytes,
                    value: Int64(utxo.valueZat),
                    height: utxo.height
                )

                refreshed.append(utxo)
            } catch {
                logger.info("failed to put utxo - error: \(error)")
                skipped.append(utxo)
            }
        }
        return (inserted: refreshed, skipped: skipped)
    }
}

// MARK: - Config provider

extension CompactBlockProcessor {
    actor ConfigProvider {
        var config: Configuration
        init(config: Configuration) {
            self.config = config
        }

        func update(config: Configuration) async {
            self.config = config
        }
    }
}
