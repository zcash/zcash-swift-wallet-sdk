//
//  SlipstreamSynchronizer.swift
//  ZcashLightClientKit
//
//  Created for Slipstream task [#1755].
//
//  Implements the `Synchronizer` protocol using:
//    - Sync members  → `SlipstreamEngine` (open / start / stop / snapshot / drainEvents)
//    - Data members  → `TransactionRepository` + `ZcashRustBackendWelding`
//                      resolved from the SAME `DIContainer` as `SDKSynchronizer`
//    - State stream  → `CurrentValueSubject<SynchronizerState, Never>` updated by a 2-second
//                      polling `Task` that calls `engine.snapshot()` and `engine.drainEvents()`
//    - Event stream  → `PassthroughSubject<SynchronizerEvent, Never>` emits `foundTransactions`
//                      from the polling tick when the engine reports SyncDone with txs
//
//  Delegation notes (T4.3):
//    Sync-side:      prepare / start / stop / stateStream / eventStream / rescanFrom /
//                    rewind / wipe / switchTo / latestHeight (9 members on engine + light service)
//    Delegated:      ~40 data-model members delegated to transactionRepository / rustBackend /
//                    transactionEncoder / broadcaster / checkpointSource / torClient
//    Honest-unsupported (throw or log): wipe, switchTo
//

import Combine
import Foundation

// swiftlint:disable type_body_length

/// `Synchronizer` implementation that uses the Slipstream Rust engine for sync
/// while delegating all data-model operations to the existing SDK components.
/// This allows the two synchronizer implementations to share the same `data.db`.
public final class SlipstreamSynchronizer: Synchronizer {
    // ── Alias ──────────────────────────────────────────────────────────────────
    public var alias: ZcashSynchronizerAlias { initializer.alias }

    // ── Sync engine ────────────────────────────────────────────────────────────
    private let engine: SlipstreamEngine

    // ── Shared infrastructure ──────────────────────────────────────────────────
    // swiftlint:disable:next strict_fileprivate
    fileprivate let initializer: Initializer
    private let transactionRepository: TransactionRepository
    private let transactionEncoder: TransactionEncoder
    private let broadcasterStorage: Broadcaster

    // ── State subjects (mirrors SDKSynchronizer) ───────────────────────────────
    private let stateSubject = CurrentValueSubject<SynchronizerState, Never>(.zero)
    private let eventSubject = PassthroughSubject<SynchronizerEvent, Never>()
    private let exchangeRateSubject = CurrentValueSubject<FiatCurrencyResult?, Never>(nil)

    // ── Public read-only state ─────────────────────────────────────────────────
    public var latestState: SynchronizerState { stateSubject.value }
    public var connectionState: ConnectionState = .idle
    public var stateStream: AnyPublisher<SynchronizerState, Never> { stateSubject.eraseToAnyPublisher() }
    public var eventStream: AnyPublisher<SynchronizerEvent, Never> { eventSubject.eraseToAnyPublisher() }
    public var exchangeRateUSDStream: AnyPublisher<FiatCurrencyResult?, Never> { exchangeRateSubject.eraseToAnyPublisher() }

    // ── Broadcaster (Synchronizer protocol requirement) ────────────────────────
    public var broadcaster: Broadcaster { broadcasterStorage }

    // ── Polling task ───────────────────────────────────────────────────────────
    private var pollTask: Task<Void, Never>?

    // ── Init ───────────────────────────────────────────────────────────────────

    /// Creates a `SlipstreamSynchronizer` instance.
    /// - Parameters:
    ///   - initializer: the same `Initializer` used for `SDKSynchronizer`; the
    ///     `SlipstreamSynchronizer` writes to the same `data.db` and uses the same
    ///     `ZcashRustBackend` for all data-model queries.
    public init(initializer: Initializer) {
        self.initializer = initializer
        self.transactionRepository = initializer.transactionRepository
        self.transactionEncoder = WalletTransactionEncoder(initializer: initializer)
        let eventSubjectRef = eventSubject

        let sdkFlags = initializer.container.resolve(SDKFlags.self)
        let logger = initializer.logger
        let transactionEncoderRef = WalletTransactionEncoder(initializer: initializer)
        self.broadcasterStorage = SDKBroadcaster(
            transactionEncoder: transactionEncoderRef,
            initializer: initializer,
            sdkFlags: sdkFlags,
            logger: logger,
            eventSubject: eventSubjectRef,
            statusCheck: {}
        )
        self.engine = SlipstreamEngine(
            dbURL: initializer.dataDbURL,
            server: initializer.endpoint
        )
    }

    // ── prepare ────────────────────────────────────────────────────────────────

    /// Initialises the wallet database (same as `SDKSynchronizer.prepare`) and opens the
    /// engine handle.  Handles `SeedRequired` migrations identically to `SDKSynchronizer`.
    public func prepare(
        with seed: [UInt8]?,
        walletBirthday: BlockHeight,
        for walletMode: WalletInitMode,
        name: String,
        keySource: String?
    ) async throws -> Initializer.InitializationResult {
        if case .seedRequired = try await initializer.initialize(
            with: seed,
            walletBirthday: walletBirthday,
            for: walletMode,
            name: name,
            keySource: keySource
        ) {
            return .seedRequired
        }
        try await engine.open(network: initializer.network)
        stateSubject.send(SynchronizerState(
            syncSessionID: UUID(),
            accountsBalances: [:],
            internalSyncStatus: .disconnected,
            latestBlockHeight: .zero
        ))
        return .success
    }

    // ── start ──────────────────────────────────────────────────────────────────

    /// Starts a Slipstream sync pass.
    /// The account is already imported in `data.db` from `prepare`, so UFVK is passed as `nil`
    /// (keyless update — engine calls `ensure_account` only when `ufvk=Some`).
    public func start(retry: Bool = false) async throws {
        let birthday = BlockHeight(initializer.walletBirthday)
        // TODO: [#1755] Consider passing ufvk=Some after T4.4 integration tests confirm
        //   idempotency. Current strategy: ufvk=nil (keyless) since prepare() already
        //   imported the account and stored its birthday treestate.
        try await engine.start(ufvk: nil, birthday: birthday)
        startPolling()
        stateSubject.send(SynchronizerState(
            syncSessionID: UUID(),
            accountsBalances: latestState.accountsBalances,
            internalSyncStatus: .syncing(0, false),
            latestBlockHeight: latestState.latestBlockHeight
        ))
    }

    // ── stop ───────────────────────────────────────────────────────────────────

    /// Stops the in-flight sync.
    /// Per plan binding note C8: engine.stop() is an actor method; the synchronous
    /// protocol method wraps it in `Task {}`.
    public func stop() {
        Task { await engine.stop() }
        stopPolling()
        stateSubject.send(SynchronizerState(
            syncSessionID: latestState.syncSessionID,
            accountsBalances: latestState.accountsBalances,
            internalSyncStatus: .stopped,
            latestBlockHeight: latestState.latestBlockHeight
        ))
    }

    // ── Polling (D8) ──────────────────────────────────────────────────────────

    private func startPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.tickPoll()
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    private func stopPolling() {
        pollTask?.cancel()
        pollTask = nil
    }

    private func tickPoll() async {
        guard let snap = await engine.snapshot() else { return }
        let events = await engine.drainEvents()

        // Map snapshot state integer to InternalSyncStatus.
        let progress = snap.chainTip > 0
            ? Float(snap.scannedBlocks) / Float(snap.chainTip)
            : Float(0)

        let newStatus: InternalSyncStatus = {
            switch snap.state {
            case 0: return .disconnected
            case 1: return .syncing(min(progress, 1.0), false)
            case 2: return .error(ZcashError.rustSlipstreamSyncFailed(snap.chainTip))
            case 3: return .synced
            default: return .disconnected
            }
        }()

        // Fetch balances and fullyScannedHeight from rust (shared data.db).
        let balances = (try? await initializer.rustBackend.getWalletSummary()?.accountBalances) ?? [:]
        let fullyScannedHeight = (try? await initializer.rustBackend.fullyScannedHeight()) ?? .zero

        stateSubject.send(SynchronizerState(
            syncSessionID: latestState.syncSessionID,
            accountsBalances: balances,
            internalSyncStatus: newStatus,
            latestBlockHeight: BlockHeight(snap.chainTip),
            fullyScannedHeight: fullyScannedHeight
        ))

        // Map SyncDone event (tag==3) with value>0 → foundTransactions event.
        for event in events where event.tag == 3 && event.value > 0 {
            let txs = (try? await transactionRepository.find(offset: 0, limit: Int.max, kind: .all)) ?? []
            if !txs.isEmpty {
                eventSubject.send(.foundTransactions(txs, nil))
            }
        }
    }

    // ── Accounts / Balances ────────────────────────────────────────────────────

    public func getAccountsBalances() async throws -> [AccountUUID: AccountBalance] {
        try await initializer.rustBackend.getWalletSummary()?.accountBalances ?? [:]
    }

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
        keySource: String?,
        birthday: BlockHeight? = nil
    ) async throws -> AccountUUID {
        let checkpointSource = initializer.container.resolve(CheckpointSource.self)
        // Use chain tip if available, fallback to provided birthday.
        let chainTipHeight = try? await UInt32(
            initializer.lightWalletService.latestBlockHeight(mode: .direct)
        )
        let effectiveBirthday = birthday ?? BlockHeight(chainTipHeight ?? UInt32(initializer.walletBirthday))
        let checkpoint = checkpointSource.birthday(for: effectiveBirthday)

        return try await initializer.rustBackend.importAccount(
            ufvk: ufvk,
            seedFingerprint: seedFingerprint,
            zip32AccountIndex: zip32AccountIndex,
            treeState: checkpoint.treeState(),
            recoverUntil: chainTipHeight,
            purpose: purpose,
            name: name,
            keySource: keySource
        )
    }

    public func deleteAccount(_ accountUUID: AccountUUID) async throws {
        try await initializer.rustBackend.deleteAccount(accountUUID)
    }

    // ── Addresses ─────────────────────────────────────────────────────────────

    public func getUnifiedAddress(accountUUID: AccountUUID) async throws -> UnifiedAddress {
        try await initializer.rustBackend.getCurrentAddress(accountUUID: accountUUID)
    }

    public func getSaplingAddress(accountUUID: AccountUUID) async throws -> SaplingAddress {
        try await getUnifiedAddress(accountUUID: accountUUID).saplingReceiver()
    }

    public func getTransparentAddress(accountUUID: AccountUUID) async throws -> TransparentAddress {
        try await getUnifiedAddress(accountUUID: accountUUID).transparentReceiver()
    }

    public func getCustomUnifiedAddress(accountUUID: AccountUUID, receivers: Set<ReceiverType>) async throws -> UnifiedAddress {
        try await initializer.rustBackend.getNextAvailableAddress(accountUUID: accountUUID, receiverFlags: receivers.toFlags())
    }

    public func getSingleUseTransparentAddress(accountUUID: AccountUUID) async throws -> SingleUseTransparentAddress {
        try await initializer.rustBackend.getSingleUseTransparentAddress(accountUUID: accountUUID)
    }

    // ── Proposals / Spending ──────────────────────────────────────────────────

    public func proposeTransfer(
        accountUUID: AccountUUID,
        recipient: Recipient,
        amount: Zatoshi,
        memo: Memo?
    ) async throws -> Proposal {
        if case Recipient.transparent = recipient, memo != nil {
            throw ZcashError.synchronizerSendMemoToTransparentAddress
        }
        return try await transactionEncoder.proposeTransfer(
            accountUUID: accountUUID,
            recipient: recipient.stringEncoded,
            amount: amount,
            memoBytes: memo?.asMemoBytes()
        )
    }

    public func proposeShielding(
        accountUUID: AccountUUID,
        shieldingThreshold: Zatoshi,
        memo: Memo,
        transparentReceiver: TransparentAddress? = nil
    ) async throws -> Proposal? {
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
        let transactions = try await broadcaster.createProposedTransactions(
            proposal: proposal,
            spendingKey: spendingKey
        )
        return submitTransactions(transactions)
    }

    // ── PCZT ──────────────────────────────────────────────────────────────────

    public func createPCZTFromProposal(accountUUID: AccountUUID, proposal: Proposal) async throws -> Pczt {
        try await initializer.rustBackend.createPCZTFromProposal(
            accountUUID: accountUUID,
            proposal: proposal.inner
        )
    }

    public func redactPCZTForSigner(pczt: Pczt) async throws -> Pczt {
        try await initializer.rustBackend.redactPCZTForSigner(pczt: pczt)
    }

    public func PCZTRequiresSaplingProofs(pczt: Pczt) async -> Bool {
        await initializer.rustBackend.PCZTRequiresSaplingProofs(pczt: pczt)
    }

    public func addProofsToPCZT(pczt: Pczt) async throws -> Pczt {
        try await SaplingParameterDownloader.downloadParamsIfnotPresent(
            spendURL: initializer.spendParamsURL,
            spendSourceURL: initializer.saplingParamsSourceURL.spendParamFileURL,
            outputURL: initializer.outputParamsURL,
            outputSourceURL: initializer.saplingParamsSourceURL.outputParamFileURL,
            logger: initializer.logger
        )
        return try await initializer.rustBackend.addProofsToPCZT(pczt: pczt)
    }

    public func createTransactionFromPCZT(pcztWithProofs: Pczt, pcztWithSigs: Pczt) async throws -> AsyncThrowingStream<TransactionSubmitResult, Error> {
        let transactions = try await broadcaster.createTransactionFromPCZT(
            pcztWithProofs: pcztWithProofs,
            pcztWithSigs: pcztWithSigs
        )
        return submitTransactions(transactions)
    }

    // ── Transactions ──────────────────────────────────────────────────────────

    public var transactions: [ZcashTransaction.Overview] {
        get async { (try? await allTransactions()) ?? [] }
    }

    public var sentTransactions: [ZcashTransaction.Overview] {
        get async { (try? await allSentTransactions()) ?? [] }
    }

    public var receivedTransactions: [ZcashTransaction.Overview] {
        get async { (try? await allReceivedTransactions()) ?? [] }
    }

    public func paginatedTransactions(of kind: TransactionKind = .all) -> PaginatedTransactionRepository {
        PagedTransactionRepositoryBuilder.build(initializer: initializer, kind: kind)
    }

    public func allTransactions(from transaction: ZcashTransaction.Overview, limit: Int) async throws -> [ZcashTransaction.Overview] {
        try await transactionRepository.find(from: transaction, limit: limit, kind: .all)
    }

    public func getMemos(for rawID: Data) async throws -> [Memo] {
        try await transactionRepository.findMemos(for: rawID)
    }

    public func getMemos(for transaction: ZcashTransaction.Overview) async throws -> [Memo] {
        try await transactionRepository.findMemos(for: transaction.rawID)
    }

    public func getRecipients(for transaction: ZcashTransaction.Overview) async -> [TransactionRecipient] {
        (try? await transactionRepository.getRecipients(for: transaction.rawID)) ?? []
    }

    public func getTransactionOutputs(for transaction: ZcashTransaction.Overview) async -> [ZcashTransaction.Output] {
        (try? await transactionRepository.getTransactionOutputs(for: transaction.rawID)) ?? []
    }

    public func fetchTxidsWithMemoContaining(searchTerm: String) async throws -> [Data] {
        try await transactionRepository.fetchTxidsWithMemoContaining(searchTerm: searchTerm)
    }

    public func enhanceTransactionBy(txId: TxId) async throws {
        let txIdData = txId.id.data
        let response = try await initializer.blockDownloaderService.fetchTransaction(
            txId: txIdData,
            mode: .direct
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

    // ── Height queries ────────────────────────────────────────────────────────

    public func latestHeight() async throws -> BlockHeight {
        try await initializer.lightWalletService.latestBlockHeight(mode: .direct)
    }

    // ── UTXO refresh ──────────────────────────────────────────────────────────

    public func refreshUTXOs(address: TransparentAddress, from height: BlockHeight) async throws -> RefreshedUTXOs {
        // Delegate via blockDownloaderService — same path as CompactBlockProcessor.refreshUTXOs.
        let stream = try initializer.blockDownloaderService.fetchUnspentTransactionOutputs(
            tAddress: address.stringEncoded,
            startHeight: height,
            mode: .direct
        )
        var utxos: [UnspentTransactionOutputEntity] = []
        for try await utxo in stream {
            utxos.append(utxo)
        }
        var inserted: [UnspentTransactionOutputEntity] = []
        var skipped: [UnspentTransactionOutputEntity] = []
        for utxo in utxos {
            do {
                try await initializer.rustBackend.putUnspentTransparentOutput(
                    txid: utxo.txid.bytes,
                    index: utxo.index,
                    script: utxo.script.bytes,
                    value: Int64(utxo.valueZat),
                    height: utxo.height
                )
                inserted.append(utxo)
            } catch {
                skipped.append(utxo)
            }
        }
        return RefreshedUTXOs(inserted: inserted, skipped: skipped)
    }

    // ── Exchange rate ─────────────────────────────────────────────────────────

    public func refreshExchangeRateUSD() {
        Task {
            let sdkFlags = initializer.container.resolve(SDKFlags.self)
            guard await sdkFlags.exchangeRateEnabled else { return }
            let torClient = initializer.container.resolve(TorClient.self)
            do {
                let isolatedClient = try await torClient.isolatedClient()
                exchangeRateSubject.send(try await isolatedClient.getExchangeRateUSD())
            } catch {
                // swallow exchange rate fetch errors (best-effort)
            }
        }
    }

    // ── Rescan / Rewind ───────────────────────────────────────────────────────

    public func rescanFrom(height: BlockHeight) async throws {
        let saplingActivationHeight = initializer.network.networkType == .mainnet
            ? ZcashMainnet().constants.saplingActivationHeight
            : ZcashTestnet().constants.saplingActivationHeight
        guard height >= saplingActivationHeight else {
            throw ZcashError.rescanFromHeightBellowSaplingActivation
        }
        let checkpointSource = initializer.container.resolve(CheckpointSource.self)
        let checkpoint = checkpointSource.birthday(for: height)
        try await initializer.rustBackend.truncateToChainState(chainState: checkpoint.treeState())
    }

    public func rewind(_ policy: RewindPolicy) -> AnyPublisher<Void, Error> {
        let subject = PassthroughSubject<Void, Error>()
        Task {
            let height: BlockHeight?
            switch policy {
            case .quick:
                height = nil
            case .birthday:
                height = initializer.walletBirthday
            case .height(let rewindHeight):
                height = rewindHeight
            case .transaction(let transaction):
                guard let txHeight = transaction.anchor(network: initializer.network) else {
                    subject.send(completion: .failure(ZcashError.synchronizerRewindUnknownArchorHeight))
                    return
                }
                height = txHeight
            }

            do {
                let checkpointSource = initializer.container.resolve(CheckpointSource.self)
                if let height {
                    let checkpoint = checkpointSource.birthday(for: height)
                    try await initializer.rustBackend.truncateToChainState(chainState: checkpoint.treeState())
                } else {
                    // Quick rewind: truncate to nearest checkpoint at the current latestBlockHeight.
                    let currentHeight = latestState.latestBlockHeight
                    let checkpoint = checkpointSource.birthday(for: currentHeight)
                    try await initializer.rustBackend.truncateToChainState(chainState: checkpoint.treeState())
                }
                subject.send(completion: .finished)
            } catch {
                subject.send(completion: .failure(error))
            }
        }
        return subject.eraseToAnyPublisher()
    }

    /// Wipe is not supported in `SlipstreamSynchronizer`.
    /// It requires coordinating engine handle teardown + database file deletion + state reset,
    /// which is not yet implemented.
    ///
    /// TODO: [#1755] Implement wipe — coordinate engine.stop() + file deletion + state reset.
    public func wipe() -> AnyPublisher<Void, Error> {
        Fail(error: ZcashError.rustSlipstreamUnsupported).eraseToAnyPublisher()
    }

    // ── Server switch ─────────────────────────────────────────────────────────

    /// Endpoint switching is not supported in `SlipstreamSynchronizer`.
    /// The engine handle is bound to a fixed endpoint at `open` time; switching requires
    /// re-opening the handle, which is not yet implemented.
    ///
    /// TODO: [#1755] Implement switchTo — re-open the engine handle with the new endpoint.
    public func switchTo(endpoint: LightWalletEndpoint) async throws {
        throw ZcashError.rustSlipstreamUnsupported
    }

    // ── Seed check ────────────────────────────────────────────────────────────

    public func isSeedRelevantToAnyDerivedAccount(seed: [UInt8]) async throws -> Bool {
        try await initializer.rustBackend.isSeedRelevantToAnyDerivedAccount(seed: seed)
    }

    // ── Server evaluation ─────────────────────────────────────────────────────

    public func evaluateBestOf(
        endpoints: [LightWalletEndpoint],
        fetchThresholdSeconds: Double = 60.0,
        nBlocksToFetch: UInt64 = 100,
        kServers: Int = 3,
        network: NetworkType = .mainnet
    ) async -> [LightWalletEndpoint] {
        // Delegate to ephemeral gRPC connections — same pattern as SDKSynchronizer.
        // TODO: [#1755] Hook into Tor when torEnabled; for now direct mode is used.
        var results: [(LightWalletEndpoint, TimeInterval)] = []
        await withTaskGroup(of: (LightWalletEndpoint, TimeInterval)?.self) { group in
            for endpoint in endpoints {
                group.addTask {
                    let service = LightWalletGRPCService(endpoint: endpoint)
                    let start = Date().timeIntervalSince1970
                    let info = try? await service.getInfo(mode: .direct)
                    let elapsed = Date().timeIntervalSince1970 - start
                    guard let info,
                        (info.chainName == "main" && network == .mainnet) ||
                        (info.chainName == "test" && network == .testnet) else {
                        return nil
                    }
                    return (endpoint, elapsed)
                }
            }
            for await result in group {
                if let result { results.append(result) }
            }
        }
        return results
            .sorted { $0.1 < $1.1 }
            .prefix(kServers)
            .map { $0.0 }
    }

    // ── Birthday / timestamp ──────────────────────────────────────────────────

    public func estimateBirthdayHeight(for date: Date) -> BlockHeight {
        initializer.container.resolve(CheckpointSource.self).estimateBirthdayHeight(for: date)
    }

    public func estimateTimestamp(for height: BlockHeight) -> TimeInterval? {
        initializer.container.resolve(CheckpointSource.self).estimateTimestamp(for: height)
    }

    // ── Tor ───────────────────────────────────────────────────────────────────

    public func tor(enabled: Bool) async throws {
        let sdkFlags = initializer.container.resolve(SDKFlags.self)
        let torClient = initializer.container.resolve(TorClient.self)
        if enabled {
            try await torClient.prepare()
        } else {
            try await torClient.close()
        }
        await sdkFlags.torFlagUpdate(enabled)
    }

    public func exchangeRateOverTor(enabled: Bool) async throws {
        let sdkFlags = initializer.container.resolve(SDKFlags.self)
        let torClient = initializer.container.resolve(TorClient.self)
        if enabled {
            try await torClient.prepare()
        } else {
            // Only close if plain Tor is also disabled.
            let torEnabled = await sdkFlags.torEnabled
            if !torEnabled {
                try await torClient.close()
            }
        }
        await sdkFlags.exchangeRateFlagUpdate(enabled)
    }

    public func isTorSuccessfullyInitialized() async -> Bool? {
        let sdkFlags = initializer.container.resolve(SDKFlags.self)
        return await sdkFlags.torClientInitializationSuccessfullyDone
    }

    public func httpRequestOverTor(for request: URLRequest, retryLimit: UInt8) async throws -> (data: Data, response: HTTPURLResponse) {
        let sdkFlags = initializer.container.resolve(SDKFlags.self)
        let torEnabled = await sdkFlags.torEnabled
        let exchangeRateEnabled = await sdkFlags.exchangeRateEnabled
        guard torEnabled || exchangeRateEnabled else {
            throw ZcashError.torNotEnabled
        }
        let torClient = initializer.container.resolve(TorClient.self)
        return try await torClient.isolatedClient().httpRequest(for: request, retryLimit: retryLimit)
    }

    // ── Transparent / UTXO helpers ────────────────────────────────────────────

    public func checkSingleUseTransparentAddresses(accountUUID: AccountUUID) async throws -> TransparentAddressCheckResult {
        let dbData = initializer.dataDbURL.osStr()
        return try await initializer.lightWalletService.checkSingleUseTransparentAddresses(
            dbData: dbData,
            networkType: initializer.network.networkType,
            accountUUID: accountUUID,
            mode: .direct
        )
    }

    public func updateTransparentAddressTransactions(address: String) async throws -> TransparentAddressCheckResult {
        let dbData = initializer.dataDbURL.osStr()
        return try await initializer.lightWalletService.updateTransparentAddressTransactions(
            address: address,
            start: 0,
            end: -1,
            dbData: dbData,
            networkType: initializer.network.networkType,
            mode: .direct
        )
    }

    public func fetchUTXOsBy(address: String, accountUUID: AccountUUID) async throws -> TransparentAddressCheckResult {
        let dbData = initializer.dataDbURL.osStr()
        return try await initializer.lightWalletService.fetchUTXOsByAddress(
            address: address,
            dbData: dbData,
            networkType: initializer.network.networkType,
            accountUUID: accountUUID,
            mode: .direct
        )
    }

    // ── Tree state ────────────────────────────────────────────────────────────

    public func getTreeState(height: UInt64) async throws -> Data {
        let treeState = try await initializer.lightWalletService.getTreeState(
            BlockID(height: height),
            mode: .direct
        )
        return try treeState.serializedData()
    }

    // ── Database debug ────────────────────────────────────────────────────────

    public func debugDatabase(sql: String) -> String {
        transactionRepository.debugDatabase(sql: sql)
    }
}

// MARK: - Private helpers

private extension SlipstreamSynchronizer {
    func allTransactions() async throws -> [ZcashTransaction.Overview] {
        try await transactionRepository.find(offset: 0, limit: Int.max, kind: .all)
    }

    func allSentTransactions() async throws -> [ZcashTransaction.Overview] {
        try await transactionRepository.findSent(offset: 0, limit: Int.max)
    }

    func allReceivedTransactions() async throws -> [ZcashTransaction.Overview] {
        try await transactionRepository.findReceived(offset: 0, limit: Int.max)
    }

    func submitTransactions(_ transactions: [ZcashTransaction.Overview]) -> AsyncThrowingStream<TransactionSubmitResult, Error> {
        var iterator = transactions.makeIterator()
        var submitFailed = false
        return AsyncThrowingStream {
            guard let transaction = iterator.next() else { return nil }
            if submitFailed {
                return .notAttempted(txId: transaction.rawID)
            }
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
