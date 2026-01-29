//
//  SDKSynchronizer.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 11/6/19.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import Foundation
import Combine

/// Synchronizer implementation for UIKit and iOS 13+
// swiftlint:disable type_body_length file_length
public class SDKSynchronizer: Synchronizer {
    private enum Constants {
        static let fixWitnessesLastVersionCall = "ud_fixWitnessesLastVersionCall"
    }
    
    public var alias: ZcashSynchronizerAlias { initializer.alias }

    private lazy var streamsUpdateQueue = { DispatchQueue(label: "streamsUpdateQueue_\(initializer.alias.description)") }()
    private let stateSubject = CurrentValueSubject<SynchronizerState, Never>(.zero)
    public var stateStream: AnyPublisher<SynchronizerState, Never> { stateSubject.eraseToAnyPublisher() }
    public private(set) var latestState: SynchronizerState = .zero

    private let eventSubject = PassthroughSubject<SynchronizerEvent, Never>()
    public var eventStream: AnyPublisher<SynchronizerEvent, Never> { eventSubject.eraseToAnyPublisher() }

    private let exchangeRateUSDSubject = CurrentValueSubject<FiatCurrencyResult?, Never>(nil)
    public var exchangeRateUSDStream: AnyPublisher<FiatCurrencyResult?, Never> { exchangeRateUSDSubject.eraseToAnyPublisher() }
    
    let metrics: SDKMetrics
    public let logger: Logger
    var exchangeRateTor: TorClient?
    var httpTor: TorClient?
    let sdkFlags: SDKFlags

    // Don't read this variable directly. Use `status` instead. And don't update this variable directly use `updateStatus()` methods instead.
    private var underlyingStatus: GenericActor<InternalSyncStatus>
    var status: InternalSyncStatus {
        get async { await underlyingStatus.value }
    }

    let blockProcessor: CompactBlockProcessor
    lazy var blockProcessorEventProcessingQueue = { DispatchQueue(label: "blockProcessorEventProcessingQueue_\(initializer.alias.description)") }()

    public let initializer: Initializer
    public var connectionState: ConnectionState
    public let network: ZcashNetwork
    private let transactionEncoder: TransactionEncoder
    private let transactionRepository: TransactionRepository

    private let syncSessionIDGenerator: SyncSessionIDGenerator
    private let syncSession: SyncSession
    private let syncSessionTicker: SessionTicker
    var latestBlocksDataProvider: LatestBlocksDataProvider

    /// Creates an SDKSynchronizer instance
    /// - Parameter initializer: a wallet Initializer object
    public convenience init(initializer: Initializer) {
        self.init(
            status: .unprepared,
            initializer: initializer,
            transactionEncoder: WalletTransactionEncoder(initializer: initializer),
            transactionRepository: initializer.transactionRepository,
            blockProcessor: CompactBlockProcessor(
                initializer: initializer,
                walletBirthdayProvider: { initializer.walletBirthday }
            ),
            syncSessionTicker: .live
        )
    }

    init(
        status: InternalSyncStatus,
        initializer: Initializer,
        transactionEncoder: TransactionEncoder,
        transactionRepository: TransactionRepository,
        blockProcessor: CompactBlockProcessor,
        syncSessionTicker: SessionTicker
    ) {
        self.connectionState = .idle
        self.underlyingStatus = GenericActor(status)
        self.initializer = initializer
        self.transactionEncoder = transactionEncoder
        self.transactionRepository = transactionRepository
        self.blockProcessor = blockProcessor
        self.network = initializer.network
        self.metrics = initializer.container.resolve(SDKMetrics.self)
        self.logger = initializer.logger
        self.syncSessionIDGenerator = initializer.container.resolve(SyncSessionIDGenerator.self)
        self.syncSession = SyncSession(.nullID)
        self.syncSessionTicker = syncSessionTicker
        self.latestBlocksDataProvider = initializer.container.resolve(LatestBlocksDataProvider.self)
        self.sdkFlags = initializer.container.resolve(SDKFlags.self)

        initializer.lightWalletService.connectionStateChange = { [weak self] oldState, newState in
            self?.connectivityStateChanged(oldState: oldState, newState: newState)
        }

        Task(priority: .high) { [weak self] in
            await self?.subscribeToProcessorEvents(blockProcessor)
        }
    }

    deinit {
        Task { [blockProcessor] in
            await blockProcessor.stop()
        }
    }

    func updateStatus(_ newValue: InternalSyncStatus, updateExternalStatus: Bool = true) async {
        let oldValue = await underlyingStatus.update(newValue)
        logger.info("Synchronizer's status updated from \(oldValue) to \(newValue)")
        await notify(oldStatus: oldValue, newStatus: newValue, updateExternalStatus: updateExternalStatus)
    }

    func throwIfUnprepared() throws {
        if !latestState.internalSyncStatus.isPrepared {
            throw ZcashError.synchronizerNotPrepared
        }
    }

    func checkIfCanContinueInitialisation() -> ZcashError? {
        if let initialisationError = initializer.urlsParsingError {
            return initialisationError
        }

        return nil
    }

    public func prepare(
        with seed: [UInt8]?,
        walletBirthday: BlockHeight,
        for walletMode: WalletInitMode,
        name: String,
        keySource: String?
    ) async throws -> Initializer.InitializationResult {
        guard await status == .unprepared else { return .success }

        if let error = checkIfCanContinueInitialisation() {
            throw error
        }

        if case .seedRequired = try await self.initializer.initialize(
            with: seed,
            walletBirthday: walletBirthday,
            for: walletMode,
            name: name,
            keySource: keySource
        ) {
            return .seedRequired
        }

        await latestBlocksDataProvider.updateWalletBirthday(initializer.walletBirthday)
        await latestBlocksDataProvider.updateScannedData()

        await updateStatus(.disconnected, updateExternalStatus: false)

        await resolveWitnessesFix()

        return .success
    }

    /// Starts the synchronizer
    /// - Throws: ZcashError when failures occur
    public func start(retry: Bool = false) async throws {
        switch await status {
        case .unprepared:
            throw ZcashError.synchronizerNotPrepared

        case .syncing:
            logger.warn("warning: Synchronizer started when already running. Next sync process will be started when the current one stops.")
            await exchangeRateTor?.wake()
            await httpTor?.wake()
            await sdkFlags.sdkStarted()
            /// This may look strange but `CompactBlockProcessor` has mechanisms which can handle this situation. So we are fine with calling
            /// it's start here.
            await blockProcessor.start(retry: retry)

        case .stopped, .synced, .disconnected, .error:
            await sdkFlags.sdkStarted()
            let walletSummary = try? await initializer.rustBackend.getWalletSummary()
            let recoveryProgress = walletSummary?.recoveryProgress
            
            var syncProgress: Float = 0.0
            var areFundsSpendable = false
            
            if let scanProgress = walletSummary?.scanProgress {
                let composedNumerator = Float(scanProgress.numerator) + Float(recoveryProgress?.numerator ?? 0)
                let composedDenominator = Float(scanProgress.denominator) + Float(recoveryProgress?.denominator ?? 0)
                
                let progress: Float
                if composedDenominator == 0 {
                    progress = 1.0
                } else {
                    progress = composedNumerator / composedDenominator
                }
                
                // this shouldn't happen but if it does, we need to get notified by clients and work on a fix
                if progress > 1.0 {
                    throw ZcashError.rustScanProgressOutOfRange("\(progress)")
                }

                areFundsSpendable = scanProgress.isComplete

                syncProgress = progress
            }
            await updateStatus(.syncing(syncProgress, areFundsSpendable))
            await exchangeRateTor?.wake()
            await httpTor?.wake()
            await blockProcessor.start(retry: retry)
        }
    }

    /// Stops the synchronizer
    public func stop() {
        // Calling `await blockProcessor.stop()` make take some time. If the downloading of blocks is in progress then this method inside waits until
        // downloading is really done. Which could block execution of the code on the client side. So it's better strategy to spin up new task and
        // exit fast on client side.
        Task(priority: .high) {
            await sdkFlags.sdkStopped()
            
            let status = await self.status
            guard status != .stopped, status != .disconnected else {
                logger.info("attempted to stop when status was: \(status)")
                return
            }

            await blockProcessor.stop()
            await exchangeRateTor?.sleep()
            await httpTor?.sleep()
        }
    }

    // MARK: Witnesses Fix
    
    private func resolveWitnessesFix() async {
        let appVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? ""
        let lastVersionCall = UserDefaults.standard.string(forKey: Constants.fixWitnessesLastVersionCall)
        
        guard lastVersionCall == nil || lastVersionCall! < appVersion else { return }
        
        UserDefaults.standard.set(appVersion, forKey: Constants.fixWitnessesLastVersionCall)
        try? await initializer.rustBackend.fixWitnesses()
    }

    // MARK: Connectivity State

    func connectivityStateChanged(oldState: ConnectionState, newState: ConnectionState) {
        connectionState = newState
        streamsUpdateQueue.async { [weak self] in
            self?.eventSubject.send(.connectionStateChanged(newState))
        }
    }

    // MARK: Handle CompactBlockProcessor.Flow

    private func subscribeToProcessorEvents(_ processor: CompactBlockProcessor) async {
        let eventClosure: CompactBlockProcessor.EventClosure = { [weak self] event in
            switch event {
            case let .failed(error):
                await self?.failed(error: error)

            case let .finished(height):
                await self?.finished(lastScannedHeight: height)

            case let .foundTransactions(transactions, range):
                self?.foundTransactions(transactions: transactions, in: range)

            case let .handledReorg(reorgHeight, rewindHeight):
                // log reorg information
                self?.logger.info("handling reorg at: \(reorgHeight) with rewind height: \(rewindHeight)")

            case let .progressUpdated(syncProgress, areFundsSpendable):
                await self?.progressUpdated(syncProgress, areFundsSpendable)

            case .syncProgress:
                break
                
            case let .storedUTXOs(utxos):
                self?.storedUTXOs(utxos: utxos)

            case .startedEnhancing, .startedFetching, .startedSyncing:
                break

            case .stopped:
                await self?.updateStatus(.stopped)

            case .minedTransaction(let transaction):
                self?.notifyMinedTransaction(transaction)
            }
        }

        await processor.updateEventClosure(identifier: "SDKSynchronizer", closure: eventClosure)
    }

    private func failed(error: Error) async {
        await updateStatus(.error(error))
    }

    private func finished(lastScannedHeight: BlockHeight) async {
        await latestBlocksDataProvider.updateScannedData()

        await updateStatus(.synced)
    }

    private func foundTransactions(transactions: [ZcashTransaction.Overview], in range: CompactBlockRange) {
        guard !transactions.isEmpty else { return }
        
        streamsUpdateQueue.async { [weak self] in
            self?.eventSubject.send(.foundTransactions(transactions, range))
        }
    }

    private func progressUpdated(_ syncProgress: Float, _ areFundsSpendable: Bool) async {
        let newStatus = InternalSyncStatus(syncProgress, areFundsSpendable)
        await updateStatus(newStatus)
    }

    private func storedUTXOs(utxos: (inserted: [UnspentTransactionOutputEntity], skipped: [UnspentTransactionOutputEntity])) {
        streamsUpdateQueue.async { [weak self] in
            self?.eventSubject.send(.storedUTXOs(utxos.inserted, utxos.skipped))
        }
    }

    // MARK: Synchronizer methods

    public func listAccounts() async throws -> [Account] {
        try await initializer.rustBackend.listAccounts()
    }
    
    // swiftlint:disable:next function_parameter_count
    public func importAccount(
        ufvk: String,
        seedFingerprint: [UInt8]?,
        zip32AccountIndex: Zip32AccountIndex?,
        purpose: AccountPurpose,
        name: String,
        keySource: String?
    ) async throws -> AccountUUID {
        // called when a new account is imported
        let chainTip = try? await UInt32(
            initializer.lightWalletService.latestBlockHeight(
                mode: await sdkFlags.ifTor(.uniqueTor)
            )
        )

        let checkpointSource = initializer.container.resolve(CheckpointSource.self)

        guard let chainTip else {
            throw ZcashError.synchronizerNotPrepared
        }
        
        let checkpoint = checkpointSource.birthday(for: BlockHeight(chainTip))
            
        return try await initializer.rustBackend.importAccount(
            ufvk: ufvk,
            seedFingerprint: seedFingerprint,
            zip32AccountIndex: zip32AccountIndex,
            treeState: checkpoint.treeState(),
            recoverUntil: chainTip,
            purpose: purpose,
            name: name,
            keySource: keySource
        )
    }

    public func proposeTransfer(accountUUID: AccountUUID, recipient: Recipient, amount: Zatoshi, memo: Memo?) async throws -> Proposal {
        try throwIfUnprepared()

        if case Recipient.transparent = recipient, memo != nil {
            throw ZcashError.synchronizerSendMemoToTransparentAddress
        }

        let proposal = try await transactionEncoder.proposeTransfer(
            accountUUID: accountUUID,
            recipient: recipient.stringEncoded,
            amount: amount,
            memoBytes: memo?.asMemoBytes()
        )

        return proposal
    }

    public func proposeShielding(
        accountUUID: AccountUUID,
        shieldingThreshold: Zatoshi,
        memo: Memo,
        transparentReceiver: TransparentAddress? = nil
    ) async throws -> Proposal? {
        try throwIfUnprepared()

        return try await transactionEncoder.proposeShielding(
            accountUUID: accountUUID,
            shieldingThreshold: shieldingThreshold,
            memoBytes: memo.asMemoBytes(),
            transparentReceiver: transparentReceiver?.stringEncoded
        )
    }

    public func proposefulfillingPaymentURI(
        _ uri: String,
        accountUUID: AccountUUID
    ) async throws -> Proposal {
        do {
            try throwIfUnprepared()
            return try await transactionEncoder.proposeFulfillingPaymentFromURI(
                uri,
                accountUUID: accountUUID
            )
        } catch ZcashError.rustCreateToAddress(let error) {
            throw ZcashError.rustProposeTransferFromURI(error)
        } catch {
            throw error
        }
    }

    public func createProposedTransactions(
        proposal: Proposal,
        spendingKey: UnifiedSpendingKey
    ) async throws -> AsyncThrowingStream<TransactionSubmitResult, Error> {
        try throwIfUnprepared()

        try await SaplingParameterDownloader.downloadParamsIfnotPresent(
            spendURL: initializer.spendParamsURL,
            spendSourceURL: initializer.saplingParamsSourceURL.spendParamFileURL,
            outputURL: initializer.outputParamsURL,
            outputSourceURL: initializer.saplingParamsSourceURL.outputParamFileURL,
            logger: logger
        )

        let transactions = try await transactionEncoder.createProposedTransactions(
            proposal: proposal,
            spendingKey: spendingKey
        )
        
        return submitTransactions(transactions)
    }
    
    func submitTransactions(_ transactions: [ZcashTransaction.Overview]) -> AsyncThrowingStream<TransactionSubmitResult, Error> {
        var iterator = transactions.makeIterator()
        var submitFailed = false

        // let clients know the transaction repository changed
        if !transactions.isEmpty {
            eventSubject.send(.foundTransactions(transactions, nil))
        }
        
        return AsyncThrowingStream() {
            guard let transaction = iterator.next() else { return nil }

            if submitFailed {
                return .notAttempted(txId: transaction.rawID)
            } else {
                let encodedTransaction = try transaction.encodedTransaction()

                do {
                    try await self.transactionEncoder.submit(transaction: encodedTransaction)
                    return TransactionSubmitResult.success(txId: transaction.rawID)
                } catch ZcashError.serviceSubmitFailed(let error) {
                    submitFailed = true
                    return TransactionSubmitResult.grpcFailure(txId: transaction.rawID, error: error)
                } catch TransactionEncoderError.submitError(let code, let message) {
                    submitFailed = true
                    return TransactionSubmitResult.submitFailure(txId: transaction.rawID, code: code, description: message)
                }
            }
        }
    }
    
    public func createPCZTFromProposal(accountUUID: AccountUUID, proposal: Proposal) async throws -> Pczt {
        try await initializer.rustBackend.createPCZTFromProposal(
            accountUUID: accountUUID,
            proposal: proposal.inner
        )
    }

    public func redactPCZTForSigner(pczt: Pczt) async throws -> Pczt {
        try await initializer.rustBackend.redactPCZTForSigner(
            pczt: pczt
        )
    }

    public func PCZTRequiresSaplingProofs(pczt: Pczt) async -> Bool {
        await initializer.rustBackend.PCZTRequiresSaplingProofs(
            pczt: pczt
        )
    }

    public func addProofsToPCZT(pczt: Pczt) async throws -> Pczt {
        // TODO [#1724]: zcash_client_backend: Make Sapling parameters optional for extract_and_store_transaction
        // TODO [#1724]: https://github.com/zcash/librustzcash/issues/1724
//        if await initializer.rustBackend.PCZTRequiresSaplingProofs(pczt: pczt) {
        try await SaplingParameterDownloader.downloadParamsIfnotPresent(
            spendURL: initializer.spendParamsURL,
            spendSourceURL: initializer.saplingParamsSourceURL.spendParamFileURL,
            outputURL: initializer.outputParamsURL,
            outputSourceURL: initializer.saplingParamsSourceURL.outputParamFileURL,
            logger: logger
        )
//        }

        return try await initializer.rustBackend.addProofsToPCZT(
            pczt: pczt
        )
    }
    
    public func createTransactionFromPCZT(pcztWithProofs: Pczt, pcztWithSigs: Pczt) async throws -> AsyncThrowingStream<TransactionSubmitResult, Error> {
        try throwIfUnprepared()

        try await SaplingParameterDownloader.downloadParamsIfnotPresent(
            spendURL: initializer.spendParamsURL,
            spendSourceURL: initializer.saplingParamsSourceURL.spendParamFileURL,
            outputURL: initializer.outputParamsURL,
            outputSourceURL: initializer.saplingParamsSourceURL.outputParamFileURL,
            logger: logger
        )

        let txId = try await initializer.rustBackend.extractAndStoreTxFromPCZT(
            pcztWithProofs: pcztWithProofs,
            pcztWithSigs: pcztWithSigs
        )

        let transactions = try await transactionEncoder.fetchTransactionsForTxIds([txId])
        
        return submitTransactions(transactions)
    }

    public func fetchTxidsWithMemoContaining(searchTerm: String) async throws -> [Data] {
        try await transactionRepository.fetchTxidsWithMemoContaining(searchTerm: searchTerm)
    }
    
    public func allReceivedTransactions() async throws -> [ZcashTransaction.Overview] {
        try await enhanceRawTransactionsWithState(
            rawTransactions: try await transactionRepository.findReceived(offset: 0, limit: Int.max)
        )
    }

    public func allTransactions() async throws -> [ZcashTransaction.Overview] {
        try await enhanceRawTransactionsWithState(
            rawTransactions: try await transactionRepository.find(offset: 0, limit: Int.max, kind: .all)
        )
    }

    public func allSentTransactions() async throws -> [ZcashTransaction.Overview] {
        try await enhanceRawTransactionsWithState(
            rawTransactions: try await transactionRepository.findSent(offset: 0, limit: Int.max)
        )
    }

    public func allTransactions(from transaction: ZcashTransaction.Overview, limit: Int) async throws -> [ZcashTransaction.Overview] {
        try await enhanceRawTransactionsWithState(
            rawTransactions: try await transactionRepository.find(from: transaction, limit: limit, kind: .all)
        )
    }
    
    private func enhanceRawTransactionsWithState(rawTransactions: [ZcashTransaction.Overview]) async throws -> [ZcashTransaction.Overview] {
        var latestKnownBlockHeight = await latestBlocksDataProvider.latestBlockHeight
        if latestKnownBlockHeight == 0 {
            latestKnownBlockHeight = try await initializer.rustBackend.maxScannedHeight() ?? .zero
        }
        
        return rawTransactions.map { rawTransaction in
            var copyOfRawTransaction = rawTransaction
            
            copyOfRawTransaction.state = rawTransaction.getState(for: latestKnownBlockHeight)
            
            return copyOfRawTransaction
        }
    }

    public func paginatedTransactions(of kind: TransactionKind = .all) -> PaginatedTransactionRepository {
        PagedTransactionRepositoryBuilder.build(initializer: initializer, kind: .all)
    }

    public func getMemos(for rawID: Data) async throws -> [Memo] {
        return try await transactionRepository.findMemos(for: rawID)
    }

    public func getMemos(for transaction: ZcashTransaction.Overview) async throws -> [Memo] {
        return try await transactionRepository.findMemos(for: transaction.rawID)
    }

    public func getRecipients(for transaction: ZcashTransaction.Overview) async -> [TransactionRecipient] {
        return (try? await transactionRepository.getRecipients(for: transaction.rawID)) ?? []
    }

    public func getTransactionOutputs(for transaction: ZcashTransaction.Overview) async -> [ZcashTransaction.Output] {
        return (try? await transactionRepository.getTransactionOutputs(for: transaction.rawID)) ?? []
    }

    public func latestHeight() async throws -> BlockHeight {
        try await blockProcessor.latestHeight(mode: await sdkFlags.ifTor(.torInGroup("SDKSynchronizer.latestHeight")))
    }

    public func refreshUTXOs(address: TransparentAddress, from height: BlockHeight) async throws -> RefreshedUTXOs {
        try throwIfUnprepared()
        return try await blockProcessor.refreshUTXOs(tAddress: address, startHeight: height)
    }

    public func getAccountsBalances() async throws -> [AccountUUID: AccountBalance] {
        try await initializer.rustBackend.getWalletSummary()?.accountBalances ?? [:]
    }

    /// Fetches the latest ZEC-USD exchange rate.
    public func refreshExchangeRateUSD() {
        Task {
            // ignore when Tor is not enabled
            guard await sdkFlags.exchangeRateEnabled else {
                return
            }
            
            // ignore refresh request when one is already in flight
            if let latestState = await exchangeRateTor?.cachedFiatCurrencyResult?.state, latestState == .fetching {
                return
            }
            
            // broadcast cached value but update the state
            if let cachedFiatCurrencyResult = await exchangeRateTor?.cachedFiatCurrencyResult {
                var fetchingState = cachedFiatCurrencyResult
                fetchingState.state = .fetching
                await exchangeRateTor?.updateCachedFiatCurrencyResult(fetchingState)
                
                exchangeRateUSDSubject.send(fetchingState)
            }
            
            do {
                if exchangeRateTor == nil {
                    logger.info("Bootstrapping Tor client for fetching exchange rates")
                    let torClient = initializer.container.resolve(TorClient.self)
                    exchangeRateTor = try await torClient.isolatedClient()
                }
                // broadcast new value in case of success
                exchangeRateUSDSubject.send(try await exchangeRateTor?.getExchangeRateUSD())
            } catch {
                // broadcast cached value but update the state
                var errorState = await exchangeRateTor?.cachedFiatCurrencyResult
                errorState?.state = .error
                await exchangeRateTor?.updateCachedFiatCurrencyResult(errorState)
                
                exchangeRateUSDSubject.send(errorState)
            }
        }
    }

    public func getUnifiedAddress(accountUUID: AccountUUID) async throws -> UnifiedAddress {
        try await blockProcessor.getUnifiedAddress(accountUUID: accountUUID)
    }

    public func getSaplingAddress(accountUUID: AccountUUID) async throws -> SaplingAddress {
        try await blockProcessor.getSaplingAddress(accountUUID: accountUUID)
    }

    public func getTransparentAddress(accountUUID: AccountUUID) async throws -> TransparentAddress {
        try await blockProcessor.getTransparentAddress(accountUUID: accountUUID)
    }

    public func getCustomUnifiedAddress(accountUUID: AccountUUID, receivers: Set<ReceiverType>) async throws -> UnifiedAddress {
        try await blockProcessor.getCustomUnifiedAddress(accountUUID: accountUUID, receivers: receivers)
    }

    // MARK: Rewind

    public func rewind(_ policy: RewindPolicy) -> AnyPublisher<Void, Error> {
        let subject = PassthroughSubject<Void, Error>()
        Task(priority: .high) {
            if !latestState.internalSyncStatus.isPrepared {
                subject.send(completion: .failure(ZcashError.synchronizerNotPrepared))
                return
            }

            let height: BlockHeight?

            switch policy {
            case .quick:
                height = nil

            case .birthday:
                let birthday = await self.blockProcessor.config.walletBirthday
                height = birthday

            case .height(let rewindHeight):
                height = rewindHeight

            case .transaction(let transaction):
                guard let txHeight = transaction.anchor(network: self.network) else {
                    throw ZcashError.synchronizerRewindUnknownArchorHeight
                }
                height = txHeight
            }

            let context = AfterSyncHooksManager.RewindContext(
                height: height,
                completion: { result in
                    switch result {
                    case .success:
                        subject.send(completion: .finished)

                    case let .failure(error):
                        subject.send(completion: .failure(error))
                    }
                }
            )

            do {
                try await blockProcessor.rewind(context: context)
            } catch {
                subject.send(completion: .failure(error))
            }
        }
        return subject.eraseToAnyPublisher()
    }

    // MARK: Wipe

    public func wipe() -> AnyPublisher<Void, Error> {
        let subject = PassthroughSubject<Void, Error>()
        Task(priority: .high) {
            if let error = checkIfCanContinueInitialisation() {
                subject.send(completion: .failure(error))
                return
            }

            let context = AfterSyncHooksManager.WipeContext(
                prewipe: { [weak self] in
                    self?.transactionEncoder.closeDBConnection()
                    self?.transactionRepository.closeDBConnection()
                },
                completion: { [weak self] possibleError in
                    await self?.updateStatus(.unprepared)
                    if let error = possibleError {
                        subject.send(completion: .failure(error))
                    } else {
                        subject.send(completion: .finished)
                    }
                }
            )

            do {
                try await blockProcessor.wipe(context: context)
            } catch {
                subject.send(completion: .failure(error))
            }
        }

        return subject.eraseToAnyPublisher()
    }

    public func isSeedRelevantToAnyDerivedAccount(seed: [UInt8]) async throws -> Bool {
        try await initializer.rustBackend.isSeedRelevantToAnyDerivedAccount(seed: seed)
    }

    /// Takes the list of endpoints and runs it through a series of checks to evaluate its performance.
    /// - Parameters:
    ///    - endpoints: Array of endpoints to evaluate.
    ///    - latencyThresholdMillis: The mean latency of `getInfo` and `getTheLatestHeight` calls must be below this threshold. The default is 300 ms.
    ///    - fetchThresholdSeconds: The time to download `nBlocksToFetch` blocks from the stream must be below this threshold. The default is 60 seconds.
    ///    - nBlocksToFetch: The number of blocks expected to be downloaded from the stream, with the time compared to `fetchThresholdSeconds`. The default is 100.
    ///    - kServers: The expected number of endpoints in the output. The default is 3.
    ///    - network: Mainnet or testnet. The default is mainnet.
    // swiftlint:disable:next cyclomatic_complexity
    public func evaluateBestOf(
        endpoints: [LightWalletEndpoint],
        fetchThresholdSeconds: Double = 60.0,
        nBlocksToFetch: UInt64 = 100,
        kServers: Int = 3,
        network: NetworkType = .mainnet
    ) async -> [LightWalletEndpoint] {
        struct Service {
            let originalEndpoint: LightWalletEndpoint
            let service: LightWalletGRPCService
            let url: String
        }
        
        struct CheckResult {
            let id: String
            let info: LightWalletdInfo?
            let getInfoTime: TimeInterval
            let latestBlockHeight: BlockHeight?
            let latestBlockHeightTime: TimeInterval
            let mean: TimeInterval
            let service: Service
            var blockTime: TimeInterval
        }
        
        let torClient = initializer.container.resolve(TorClient.self)
        
        // Initialize services for the endpoints
        let services = endpoints.map {
            Service(
                originalEndpoint: $0,
                service: LightWalletGRPCServiceOverTor(endpoint: $0, tor: torClient),
                url: "\($0.host):\($0.port)"
            )
        }

        // Parallel part
        var checkResults: [String: CheckResult] = [:]
        let sdkFlagsRef = sdkFlags
        
        await withTaskGroup(of: CheckResult.self) { group in
            for service in services {
                group.addTask {
                    let startTime = Date().timeIntervalSince1970

                    // called when performance of servers is evaluated
                    let mode = await sdkFlagsRef.ifTor(ServiceMode.torInGroup("SDKSynchronizer.evaluateBestOf(\(service.originalEndpoint))"))

                    let info = try? await service.service.getInfo(mode: mode)
                    let markTime = Date().timeIntervalSince1970
                    // called when performance of servers is evaluated
                    let latestBlockHeight = try? await service.service.latestBlockHeight(mode: mode)
                    let endTime = Date().timeIntervalSince1970

                    let getInfoTime = markTime - startTime
                    let latestBlockHeightTime = endTime - markTime
                    let mean = (getInfoTime + latestBlockHeightTime) / 2

                    return CheckResult(
                        id: service.url,
                        info: info,
                        getInfoTime: getInfoTime,
                        latestBlockHeight: latestBlockHeight,
                        latestBlockHeightTime: latestBlockHeightTime,
                        mean: mean,
                        service: service,
                        blockTime: 0
                    )
                }
            }
            
            var tmpResults: [String: CheckResult] = [:]
            
            for await result in group {
                // rule out results where calls failed
                guard let info = result.info, result.latestBlockHeight != nil else {
                    continue
                }
                
                // rule out if mismatch of networks
                guard (info.chainName == "main" && network == .mainnet)
                    || (info.chainName == "test" && network == .testnet) else {
                    continue
                }
                
                // rule out mismatch of consensus branch IDs
                guard let localBranchID = await blockProcessor.consensusBranchIdFor(Int32(info.blockHeight)) else {
                    continue
                }

                guard let remoteBranchID = ConsensusBranchID.fromString(info.consensusBranchID) else {
                    continue
                }
                
                guard remoteBranchID == localBranchID else {
                    continue
                }

                // Rule out servers that are syncing, stuck, or probably on the wrong fork.
                // To avoid falsely ruling out all servers this can only be a very loose check
                // (i.e. `ZcashSDK.syncedThresholdBlocks` should not be too small),
                // because `info.estimatedHeight` may be quite inaccurate.
                guard info.blockHeight + ZcashSDK.syncedThresholdBlocks >= info.estimatedHeight else {
                    continue
                }
                
                tmpResults[result.id] = result
            }

            // sort the server responses by mean
            let sortedCheckResults = tmpResults.sorted {
                $0.value.mean < $1.value.mean
            }

            // retain k servers
            let sortedKOnly = sortedCheckResults.prefix(kServers)

            sortedKOnly.forEach {
                checkResults[$0.key] = $0.value
            }
        }

        // Sequential part
        var blockResults: [String: CheckResult] = [:]

        for serviceDict in checkResults {
            guard let info = serviceDict.value.info else {
                continue
            }
            
            let service = serviceDict.value.service
            
            guard info.blockHeight >= nBlocksToFetch else {
                continue
            }

            do {
                // Fetched the same way as in `BlockDownloader`.
                let stream = try service.service.blockStream(
                    startHeight: BlockHeight(info.blockHeight - nBlocksToFetch),
                    endHeight: BlockHeight(info.blockHeight),
                    mode: .direct
                )

                let startTime = Date().timeIntervalSince1970
                var endTime = startTime
                for try await _ in stream {
                    endTime = Date().timeIntervalSince1970
                    if endTime - startTime >= fetchThresholdSeconds {
                        break
                    }
                }

                let blockTime = endTime - startTime

                // rule out servers that can't fetch `nBlocksToFetch` blocks under fetchThresholdSeconds
                if blockTime < fetchThresholdSeconds {
                    var value = serviceDict.value
                    value.blockTime = blockTime
                    
                    blockResults[serviceDict.key] = value
                }
            } catch {
                continue
            }
        }
        
        // return what's left
        let sortedServers = blockResults.sorted {
            $0.value.blockTime < $1.value.blockTime
        }

        let finalResult = sortedServers.map {
            $0.value.service.originalEndpoint
        }

        return finalResult
    }
    
    public func estimateBirthdayHeight(for date: Date) -> BlockHeight {
        initializer.container.resolve(CheckpointSource.self).estimateBirthdayHeight(for: date)
    }
    
    public func estimateTimestamp(for height: BlockHeight) -> TimeInterval? {
        initializer.container.resolve(CheckpointSource.self).estimateTimestamp(for: height)
    }

    public func tor(enabled: Bool) async throws {
        let isExchangeRateEnabled = await sdkFlags.exchangeRateEnabled

        // turn Tor on
        if enabled && !isExchangeRateEnabled {
            try await enableAndStartupTorClient()
        }

        // turn Tor off
        if !enabled && !isExchangeRateEnabled {
            try await disableAndCleanupTorClients()
        }

        await sdkFlags.torFlagUpdate(enabled)
    }

    public func exchangeRateOverTor(enabled: Bool) async throws {
        let isTorEnabled = await sdkFlags.torEnabled

        // turn Tor on
        if enabled && !isTorEnabled {
            try await enableAndStartupTorClient()
        }

        // turn Tor off
        if !enabled && !isTorEnabled {
            try await disableAndCleanupTorClients()
        }

        await sdkFlags.exchangeRateFlagUpdate(enabled)
    }
    
    private func enableAndStartupTorClient() async throws {
        let torClient = initializer.container.resolve(TorClient.self)
        try await torClient.prepare()
    }
    
    private func disableAndCleanupTorClients() async throws {
        await sdkFlags.torClientInitializationSuccessfullyDoneFlagUpdate(nil)

        // case when previous was enabled and newly is required to be stopped
        let torClient = initializer.container.resolve(TorClient.self)
        // close of the initial TorClient, it's used for creation of isolated clients
        try await torClient.close()
        // deinit of isolated TorClient used for fetching exchange rates
        exchangeRateTor = nil
        // deinit of isolated TorClient used for http requests
        httpTor = nil
        // close all connections
        let lwdService = initializer.container.resolve(LightWalletService.self)
        await lwdService.closeConnections()
    }
    
    public func isTorSuccessfullyInitialized() async -> Bool? {
        await sdkFlags.torClientInitializationSuccessfullyDone
    }

    public func httpRequestOverTor(for request: URLRequest, retryLimit: UInt8 = 3) async throws -> (data: Data, response: HTTPURLResponse) {
        let torEnabled = await sdkFlags.torEnabled
        let exchangeRateEnabled = await sdkFlags.exchangeRateEnabled
        
        guard torEnabled || exchangeRateEnabled else {
            throw ZcashError.torNotEnabled
        }
        
        if httpTor == nil {
            logger.info("Bootstrapping Tor client for making http requests")
            if let torService = initializer.container.resolve(LightWalletService.self) as? LightWalletGRPCServiceOverTor {
                httpTor = try await torService.tor.isolatedClient()
            }
        }
        
        guard let httpTor else {
            throw ZcashError.torClientUnavailable
        }
        
        return try await httpTor.isolatedClient().httpRequest(for: request, retryLimit: retryLimit)
    }
    
    public func debugDatabase(sql: String) -> String {
        transactionRepository.debugDatabase(sql: sql)
    }
    
    public func getSingleUseTransparentAddress(accountUUID: AccountUUID) async throws -> SingleUseTransparentAddress {
        try await initializer.rustBackend.getSingleUseTransparentAddress(accountUUID: accountUUID)
    }

    public func checkSingleUseTransparentAddresses(accountUUID: AccountUUID) async throws -> TransparentAddressCheckResult {
        let dbHandle = try await initializer.rustBackend.resolveDbHandle()

        return try await initializer.lightWalletService.checkSingleUseTransparentAddresses(
            dbHandle: dbHandle,
            accountUUID: accountUUID,
            mode: await sdkFlags.ifTor(.uniqueTor)
        )
    }

    public func updateTransparentAddressTransactions(address: String) async throws -> TransparentAddressCheckResult {
        let dbHandle = try await initializer.rustBackend.resolveDbHandle()

        return try await initializer.lightWalletService.updateTransparentAddressTransactions(
            address: address,
            start: 0,
            end: -1,
            dbHandle: dbHandle,
            mode: await sdkFlags.ifTor(.uniqueTor)
        )
    }

    public func fetchUTXOsBy(address: String, accountUUID: AccountUUID) async throws -> TransparentAddressCheckResult {
        let dbHandle = try await initializer.rustBackend.resolveDbHandle()

        return try await initializer.lightWalletService.fetchUTXOsByAddress(
            address: address,
            dbHandle: dbHandle,
            accountUUID: accountUUID,
            mode: await sdkFlags.ifTor(.uniqueTor)
        )
    }

    public func enhanceTransactionBy(txId: TxId) async throws -> Void {
        let txIdData = txId.id.data

        let response = try await initializer.blockDownloaderService.fetchTransaction(
            txId: txIdData,
            mode: await sdkFlags.ifTor(ServiceMode.txIdGroup(prefix: "fetch", txId: txIdData))
        )

        if response.status == .txidNotRecognized {
            try await initializer.rustBackend.setTransactionStatus(txId: txIdData, status: .txidNotRecognized)
        } else if let fetchedTransaction = response.tx {
            _ = try await initializer.rustBackend.decryptAndStoreTransaction(
                txBytes: fetchedTransaction.raw.bytes,
                minedHeight: fetchedTransaction.minedHeight
            )
        }
    }
    
    public func deleteAccount(_ accountUUID: AccountUUID) async throws {
        try await initializer.rustBackend.deleteAccount(accountUUID)
    }

    // MARK: Server switch

    public func switchTo(endpoint: LightWalletEndpoint) async throws {
        // Stop synchronization
        let status = await self.status
        if status != .stopped && status != .disconnected {
            await blockProcessor.stop()
        }

        let torClient = initializer.container.resolve(TorClient.self)
        
        // Validation of the server is first because any custom endpoint can be passed here
        // Extra instance of the service is created with lower timeout for a single call
        initializer.container.register(type: LightWalletService.self, isSingleton: true) { _ in
            LightWalletGRPCServiceOverTor(endpoint: endpoint, tor: torClient, singleCallTimeout: 5000)
        }

        let validateSever = ValidateServerAction(
            container: initializer.container,
            configProvider: CompactBlockProcessor.ConfigProvider(config: await blockProcessor.config)
        )
 
        do {
            _ = try await validateSever.run(with: ActionContextImpl(state: .idle)) { _ in }
        } catch {
            throw ZcashError.synchronizerServerSwitch
        }
        
        // The `ValidateServerAction` confirmed the server is ok and we can continue
        // final instance of the service will be instantiated and propagated to the all parties

        // SWITCH TO NEW ENDPOINT
        
        // LightWalletService dependency update
        initializer.container.register(type: LightWalletService.self, isSingleton: true) { _ in
            LightWalletGRPCServiceOverTor(endpoint: endpoint, tor: torClient)
        }

        // DEPENDENCIES

        // BlockDownloaderService dependency update
        initializer.container.register(type: BlockDownloaderService.self, isSingleton: true) { di in
            let service = di.resolve(LightWalletService.self)
            let storage = di.resolve(CompactBlockRepository.self)

            return BlockDownloaderServiceImpl(service: service, storage: storage)
        }

        // LatestBlocksDataProvider dependency update
        initializer.container.register(type: LatestBlocksDataProvider.self, isSingleton: true) { di in
            let service = di.resolve(LightWalletService.self)
            let rustBackend = di.resolve(ZcashRustBackendWelding.self)
            let sdkFlags = di.resolve(SDKFlags.self)

            return LatestBlocksDataProviderImpl(service: service, rustBackend: rustBackend, sdkFlags: sdkFlags)
        }
        
        // CompactBlockProcessor dependency update
        Dependencies.setupCompactBlockProcessor(
            in: initializer.container,
            config: await blockProcessor.config
        )
        
        // INITIALIZER - update endpoint (lightWalletService and blockDownloaderService
        // are computed properties that auto-resolve from the container)
        initializer.endpoint = endpoint

        // SELF
        self.latestBlocksDataProvider = initializer.container.resolve(LatestBlocksDataProvider.self)
        
        // COMPACT BLOCK PROCESSOR
        await blockProcessor.updateService(initializer.container)
        
        // Start synchronization
        if status != .unprepared {
            try await start(retry: true)
        }
    }

    // MARK: notify state

    private func snapshotState(status: InternalSyncStatus) async -> SynchronizerState {
        await SynchronizerState(
            syncSessionID: syncSession.value,
            accountsBalances: (try? await getAccountsBalances()) ?? [:],
            internalSyncStatus: status,
            latestBlockHeight: latestBlocksDataProvider.latestBlockHeight
        )
    }

    private func notify(oldStatus: InternalSyncStatus, newStatus: InternalSyncStatus, updateExternalStatus: Bool = true) async {
        guard oldStatus != newStatus else { return }

        let newState: SynchronizerState

        // When the wipe happens status is switched to `unprepared`. And we expect that everything is deleted. All the databases including data DB.
        // When new snapshot is created balance is checked. And when balance is checked and data DB doesn't exist then rust initialise new database.
        // So it's necessary to not create new snapshot after status is switched to `unprepared` otherwise data DB exists after wipe
        if newStatus == .unprepared {
            var nextState = SynchronizerState.zero

            let nextSessionID = await self.syncSession.update(.nullID)

            nextState.syncSessionID = nextSessionID
            newState = nextState
        } else {
            if SessionTicker.live.isNewSyncSession(oldStatus, newStatus) {
                await self.syncSession.newSession(with: self.syncSessionIDGenerator)
            }
            newState = await snapshotState(status: newStatus)
        }

        latestState = newState

        if updateExternalStatus {
            updateStateStream(with: latestState)
        }
    }

    private func updateStateStream(with newState: SynchronizerState) {
        streamsUpdateQueue.async { [weak self] in
            self?.stateSubject.send(newState)
        }
    }

    private func notifyMinedTransaction(_ transaction: ZcashTransaction.Overview) {
        streamsUpdateQueue.async { [weak self] in
            self?.eventSubject.send(.minedTransaction(transaction))
        }
    }
}

extension SDKSynchronizer {
    public var transactions: [ZcashTransaction.Overview] {
        get async {
            (try? await self.allTransactions()) ?? []
        }
    }

    public var sentTransactions: [ZcashTransaction.Overview] {
        get async {
            (try? await allSentTransactions()) ?? []
        }
    }

    public var receivedTransactions: [ZcashTransaction.Overview] {
        get async {
            (try? await allReceivedTransactions()) ?? []
        }
    }
}

extension InternalSyncStatus {
    func isDifferent(from otherStatus: InternalSyncStatus) -> Bool {
        switch (self, otherStatus) {
        case (.unprepared, .unprepared): return false
        case (.syncing, .syncing): return false
        case (.synced, .synced): return false
        case (.stopped, .stopped): return false
        case (.disconnected, .disconnected): return false
        case (.error, .error): return false
        default: return true
        }
    }
}

struct SessionTicker {
    /// Helper function to determine whether we are in front of a SyncSession change for a given syncStatus
    /// transition we consider that every sync attempt is a new sync session and should have it's unique UUID reported.
    var isNewSyncSession: (InternalSyncStatus, InternalSyncStatus) -> Bool
}

extension SessionTicker {
    static let live = SessionTicker { oldStatus, newStatus in
        // if the state hasn't changed to a different syncStatus member
        guard oldStatus.isDifferent(from: newStatus) else { return false }

        switch (oldStatus, newStatus) {
        case (.unprepared, .syncing):
            return true
        case (.error, .syncing),
            (.disconnected, .syncing),
            (.stopped, .syncing),
            (.synced, .syncing):
            return true
        default:
            return false
        }
    }
}
