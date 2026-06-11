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
//  Delegation notes (T4.3 / T4.6):
//    Sync-side:      prepare / start / stop / stateStream / eventStream / rescanFrom /
//                    rewind / wipe / switchTo / latestHeight (9 members on engine + light service)
//    Delegated:      ~40 data-model members delegated to transactionRepository / rustBackend /
//                    transactionEncoder / broadcaster / checkpointSource / torClient
//    Honest-unsupported (throw or log): switchTo only (T4.6 ships real wipe)
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
    // TODO: [#1755] never updated (engine has no connection-state callback yet; P5).
    public var connectionState: ConnectionState = .idle
    public var stateStream: AnyPublisher<SynchronizerState, Never> { stateSubject.eraseToAnyPublisher() }
    public var eventStream: AnyPublisher<SynchronizerEvent, Never> { eventSubject.eraseToAnyPublisher() }
    public var exchangeRateUSDStream: AnyPublisher<FiatCurrencyResult?, Never> { exchangeRateSubject.eraseToAnyPublisher() }

    // ── Broadcaster (Synchronizer protocol requirement) ────────────────────────
    public var broadcaster: Broadcaster { broadcasterStorage }

    // ── Endpoint (mutable for switchTo) ───────────────────────────────────────
    // Tracks the endpoint currently in use.  `engine.reopen(server:network:)` uses
    // this value; `initializer.endpoint` is the initial value.
    private var currentEndpoint: LightWalletEndpoint

    // ── Running state (for switchTo restart decision) ──────────────────────────
    private var isRunning: Bool = false

    // ── Polling task ───────────────────────────────────────────────────────────
    private var pollTask: Task<Void, Never>?

    // ── foundTransactions emission tracking ────────────────────────────────────
    // Monotonically-increasing counter mirroring the Rust engine's `enhanced_txs`
    // field (which is per-handle, growing across multiple start/stop cycles until
    // the handle is closed).  Persists across start() calls — reset only when the
    // engine handle is closed (close() / wipe()).
    private var lastEnhancedCount: UInt64 = 0

    // ── Cached wallet-summary state (F1 — non-blocking progress) ──────────────
    // `getWalletSummary` can take tens of seconds mid-scan (complex shard-tree +
    // balance SQL queries) and is `@DBActor`-isolated, serialising all other DB
    // calls on the same global executor.  To prevent this from blocking the 2-second
    // poll tick — which must emit a state update EVERY tick — we maintain a cached
    // copy of the last completed summary and fetch updates in a background Task.
    //
    // Invariants:
    //   - Only ONE summary fetch is in flight at a time (`summaryTask != nil`).
    //   - A new fetch starts only when the previous one is done AND ≥ the state-dependent
    //     interval have elapsed since it completed (`lastSummaryFinishDate`).
    //   - The fetch is wrapped in a 3-second hard timeout; on expiry the cached value
    //     is left unchanged and the next tick will retry.
    //   - When state == 3 (Done), any in-flight task is cancelled and the tick emits
    //     `.synced` immediately without waiting.
    //   - THROTTLE: While state == Syncing (1), summary fetches are throttled to 8-second
    //     intervals (T5.3). The 2-second state ticks bridge from cachedSummary + cheap
    //     snapshot counters; this wider cadence prevents summary computation from stealing
    //     CPU from rayon trial-decryption on weak devices.
    private var cachedSummary: WalletSummary?
    private var summaryTask: Task<Void, Never>?
    private var lastSummaryFinishDate: Date?
    // Minimum interval (seconds) between summary fetches when NOT syncing (Disconnected, Done, Error).
    private static let summaryRefetchIntervalSeconds: TimeInterval = 2.0
    // Minimum interval (seconds) between summary fetches while Syncing (T5.3).
    // Summary computation steals CPU from rayon trial-decryption on-device; widen the
    // cadence while scan-bound. The 2s state ticks bridge from cachedSummary.
    private static let SUMMARY_SYNC_INTERVAL: TimeInterval = 8.0
    // Hard timeout (nanoseconds) for a single getWalletSummary call: 3 seconds.
    private static let summaryTimeoutNanoseconds: UInt64 = 3_000_000_000

    // ── Init ───────────────────────────────────────────────────────────────────

    /// Creates a `SlipstreamSynchronizer` instance.
    /// - Parameters:
    ///   - initializer: the same `Initializer` used for `SDKSynchronizer`; the
    ///     `SlipstreamSynchronizer` writes to the same `data.db` and uses the same
    ///     `ZcashRustBackend` for all data-model queries.
    public init(initializer: Initializer) {
        self.initializer = initializer
        self.currentEndpoint = initializer.endpoint
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
        isRunning = true
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
        isRunning = false
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
        // Cancel any in-flight summary fetch (F1): no point updating the cache when
        // the poll loop is stopped; the task would complete after stop and write to
        // stale state.  The cached value itself is preserved for the next start().
        summaryTask?.cancel()
        summaryTask = nil
    }

    private func tickPoll() async {
        guard let snap = await engine.snapshot() else { return }
        let events = await engine.drainEvents()

        // ── F1: Emit state immediately from cheap snapshot + cached summary ──────
        //
        // getWalletSummary() can take 10–30 s mid-scan (complex shard-tree + balance
        // SQL queries, all serialised on @DBActor).  Awaiting it here would block this
        // tick — and every subsequent tick — causing the UI to show long pauses with
        // no progress updates.
        //
        // Fix: use the CACHED summary from the last completed background fetch.
        // A background Task is kicked off to refresh the cache (one at a time, ≥2 s
        // apart, with a 3-second hard timeout) WITHOUT blocking this tick.
        //
        // Special-case: state == 3 (Done) → emit .synced IMMEDIATELY and cancel any
        // in-flight summary task; we do not need updated balances to report completion.

        // Cancel in-flight summary fetch and emit .synced right away on Done.
        if snap.state == 3 {
            summaryTask?.cancel()
            summaryTask = nil
            stateSubject.send(SynchronizerState(
                syncSessionID: latestState.syncSessionID,
                accountsBalances: cachedSummary?.accountBalances ?? latestState.accountsBalances,
                internalSyncStatus: .synced,
                latestBlockHeight: BlockHeight(snap.chainTip),
                fullyScannedHeight: cachedSummary?.fullyScannedHeight ?? latestState.fullyScannedHeight
            ))
            // Fall through to foundTransactions emission below (still needed on Done).
        } else {
            // Kick off a background summary refresh when the previous one has finished
            // and enough time has elapsed (prevents overlapping calls and queue build-up).
            // Pass the current snapshot state for state-dependent throttling (T5.3).
            kickSummaryFetchIfNeeded(state: snap.state)

            // Build progress from the cached summary (may be nil on the very first ticks).
            let summary = cachedSummary

            // Compose scan+recovery progress exactly as the old SDK's ScanAction does
            // (ScanAction.swift:81-99): numerators and denominators are summed; denominator==0
            // → 1.0; progress clamped to 1.0 (old SDK threw; we log-warn once and clamp).
            // areFundsSpendable = scanProgress.isComplete (ScanAction.swift:99).
            let (composedProgress, spendable) = SlipstreamSynchronizer.composeProgress(
                scanProgress: summary?.scanProgress.map { ($0.numerator, $0.denominator, $0.isComplete) },
                recoveryProgress: summary?.recoveryProgress.map { ($0.numerator, $0.denominator) }
            )

            // fullyScannedHeight comes from the wallet summary (avoids a redundant
            // fullyScannedHeight() Rust call — WalletSummary already carries this field).
            let fullyScannedHeight = summary?.fullyScannedHeight ?? latestState.fullyScannedHeight

            // Balances are already in the summary fetched above — reuse, no extra Rust call.
            let balances = summary?.accountBalances ?? latestState.accountsBalances

            // Fallback progress when the summary is nil (fresh db, first ticks before any
            // scan range is committed): keep a simple counter ratio but avoid the genesis-
            // relative distortion — use max(currentRangeEnd, 1) as the local baseline so
            // the fraction is honest within the current range rather than near-zero across
            // the entire chain.  This path is transient and only fires until the first
            // getWalletSummary() returns a non-nil scanProgress.
            let fallbackProgress: Float = {
                guard summary?.scanProgress == nil else { return composedProgress }
                let rangeEnd = max(snap.currentRangeEnd, UInt64(1))
                return snap.scannedBlocks > 0
                    ? min(Float(snap.scannedBlocks) / Float(rangeEnd), 1.0)
                    : Float(0)
            }()
            let effectiveProgress = summary?.scanProgress != nil ? composedProgress : fallbackProgress

            let newStatus: InternalSyncStatus = {
                switch snap.state {
                case 0: return .disconnected
                case 1: return .syncing(effectiveProgress, spendable)
                case 2: return .error(ZcashError.rustSlipstreamSyncFailed(snap.chainTip))
                default: return .disconnected
                }
            }()

            stateSubject.send(SynchronizerState(
                syncSessionID: latestState.syncSessionID,
                accountsBalances: balances,
                internalSyncStatus: newStatus,
                latestBlockHeight: BlockHeight(snap.chainTip),
                fullyScannedHeight: fullyScannedHeight
            ))
        }

        // ── Resilient foundTransactions emission ──────────────────────────────
        // Primary path: emit whenever the engine's enhanced_txs counter advances
        // beyond what we last saw.  This fires on every poll tick where new
        // transactions were enhanced, regardless of whether the event ring also
        // carries a SyncDone event (event-ring capacity is 64; the ring can lose
        // events under a sustained burst).
        //
        // Fallback path: if the counter did NOT move but the event ring contains
        // a SyncDone event (tag==3, value>0) AND there are stored transactions,
        // emit once.  This catches the edge case where enhancedTxs stalls at a
        // non-zero value (e.g. the engine re-uses a counter from a prior pass and
        // the primary path already fired) while we still know a pass completed.
        //
        // Single emission point: we never emit both paths in the same tick (the
        // primary path takes precedence; the fallback is an else-branch).
        let hasSyncDoneEvent = events.contains { $0.tag == 3 && $0.value > 0 }

        if snap.enhancedTxs > lastEnhancedCount {
            // Primary: new enhancements observed — fetch and emit.
            let txs = (try? await transactionRepository.find(offset: 0, limit: 50, kind: .all)) ?? []
            if !txs.isEmpty {
                eventSubject.send(.foundTransactions(txs, nil))
            }
            lastEnhancedCount = snap.enhancedTxs
        } else if hasSyncDoneEvent && snap.enhancedTxs > 0 {
            // Fallback: sync completed with stored transactions but the counter
            // did not advance this tick (already caught by an earlier tick or
            // count unchanged across this pass).  Emit so the UI sees them.
            let txs = (try? await transactionRepository.find(offset: 0, limit: 50, kind: .all)) ?? []
            if !txs.isEmpty {
                eventSubject.send(.foundTransactions(txs, nil))
            }
        }
    }

    /// Returns the minimum interval (seconds) between summary fetches based on the
    /// current sync state. While Syncing (state 1), uses the wider 8-second interval
    /// to avoid stealing CPU from rayon trial-decryption. All other states use 2 seconds.
    /// Internal for testability (pure function, no side effects).
    static func summaryFetchInterval(forState state: UInt8) -> TimeInterval {
        state == 1 ? SUMMARY_SYNC_INTERVAL : summaryRefetchIntervalSeconds
    }

    /// Starts a background summary fetch if no fetch is in-flight and the state-dependent
    /// minimum refetch interval has elapsed since the last one completed.
    ///
    /// The fetch is wrapped in a hard 3-second timeout.  On completion (success or
    /// timeout) the result is stored in `cachedSummary` and `lastSummaryFinishDate`
    /// is updated so the next tick can trigger another fetch after the interval.
    ///
    /// State-dependent throttling (T5.3): while syncing (state 1), the interval is 8 seconds
    /// instead of 2 seconds; the 2-second polling ticks bridge from the cached summary to
    /// prevent summary CPU theft during active scan.
    ///
    /// Invariant: only ONE summary fetch task is live at a time (`summaryTask != nil`
    /// while running).  This prevents DBActor queue build-up when the DB is slow.
    private func kickSummaryFetchIfNeeded(state: UInt8) {
        // If a fetch is already running, do not start another.
        guard summaryTask == nil else { return }

        // Enforce the state-dependent minimum interval between fetches.
        let interval = Self.summaryFetchInterval(forState: state)
        if let last = lastSummaryFinishDate {
            let elapsed = Date().timeIntervalSince(last)
            guard elapsed >= interval else { return }
        }

        let rustBackend = initializer.rustBackend
        summaryTask = Task { [weak self] in
            // Race the summary call against the hard timeout.
            let result = try? await withTaskTimeout(Self.summaryTimeoutNanoseconds) {
                try await rustBackend.getWalletSummary()
            }
            // Only update state if the task was not cancelled (e.g. by Done or wipe).
            guard !Task.isCancelled else { return }
            self?.cachedSummary = result ?? self?.cachedSummary
            self?.lastSummaryFinishDate = Date()
            self?.summaryTask = nil
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

    public func allTransactions() async throws -> [ZcashTransaction.Overview] {
        try await transactionRepository.find(offset: 0, limit: Int.max, kind: .all)
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

    /// Wipes all wallet data managed by this synchronizer.
    ///
    /// Mirrors `SDKSynchronizer.wipe()` + `CompactBlockProcessor.doWipe()`:
    /// 1. Stop the poll loop.
    /// 2. `engine.stop()` — cancel any in-flight sync task.
    /// 3. `engine.close()` — free the Rust handle so no Rust-side state survives file deletion.
    /// 4. Delete `data.db` + its WAL (`-wal`) and shared-memory (`-shm`) siblings.
    /// 5. Delete the `fsBlockDbRoot` directory (parity with old SDK's `storage.clear()` +
    ///    FS-cache directory removal; Slipstream does not use it but the app may have created it).
    /// 6. Reset the state subject to `.zero` (status `.unprepared`).
    /// 7. Complete the returned publisher — or fail it if any file-removal throws.
    ///
    /// The publisher uses a `PassthroughSubject` driven from a `Task(priority: .high)`,
    /// mirroring the `SDKSynchronizer.wipe()` idiom.
    public func wipe() -> AnyPublisher<Void, Error> {
        let subject = PassthroughSubject<Void, Error>()
        Task(priority: .high) { [weak self] in
            guard let self else {
                subject.send(completion: .finished)
                return
            }

            // 1. Stop polling.
            stopPolling()

            // 2. Stop the in-flight sync (non-blocking cancel in Rust).
            await engine.stop()

            // 3. Free the engine handle (exact-once — close() guards against double-free).
            await engine.close()

            // 3a. Reset the per-handle enhanced-tx counter: the engine handle is being
            //     destroyed, so the Rust-side monotonic counter resets on next open().
            lastEnhancedCount = 0

            // 3b-F1. Reset the cached wallet summary: the DB is being wiped, so the
            //        cached values would be stale for any subsequent prepare()/start().
            cachedSummary = nil
            lastSummaryFinishDate = nil

            // 3b. Close Swift-side DB connections before deleting files — mirrors
            //     SDKSynchronizer.wipe() prewipe closure (SDKSynchronizer.swift:759-760).
            transactionEncoder.closeDBConnection()
            transactionRepository.closeDBConnection()

            do {
                let fm = FileManager.default

                // 4. Remove data.db and its SQLite WAL/SHM siblings.
                // E.g. /path/data.db  → /path/data.db-wal, /path/data.db-shm.
                let dataDb = initializer.dataDbURL
                for suffix in ["", "-wal", "-shm"] {
                    let targetURL = suffix.isEmpty
                        ? dataDb
                        : URL(fileURLWithPath: dataDb.path + suffix)
                    if fm.fileExists(atPath: targetURL.path) {
                        try fm.removeItem(at: targetURL)
                    }
                }

                // 5. Remove the fsBlockDbRoot directory tree (parity with old SDK wipe).
                let fsRoot = initializer.fsBlockDbRoot
                if fm.fileExists(atPath: fsRoot.path) {
                    try fm.removeItem(at: fsRoot)
                }

                // 6. Reset state to unprepared/zero.
                stateSubject.send(.zero)

                // 7. Signal completion.
                subject.send(completion: .finished)
            } catch {
                subject.send(completion: .failure(error))
            }
        }
        return subject.eraseToAnyPublisher()
    }

    // ── Server switch ─────────────────────────────────────────────────────────

    /// Switches the synchronizer to `endpoint` by re-opening the engine handle.
    ///
    /// Sequence:
    /// 1. F2: No-op immediately if `endpoint` equals `currentEndpoint` (same host + port + secure).
    ///    Prevents AutoServerSelection from restarting a sync pass when the benchmark selects the
    ///    same server already in use.
    /// 2. Snapshot whether the sync was running (to decide whether to restart).
    /// 3. F3: If a sync is active, log a warning — the pass will restart from the current scan
    ///    queue position (no data loss, but a brief latency cost until the engine reconnects).
    /// 4. Stop polling + await `engine.stop()` — cancel any in-flight sync task.
    /// 5. `engine.reopen(server:network:)` — close old handle + open new one bound
    ///    to the new endpoint (frees Rust-side tokio runtime, then allocates a fresh one).
    /// 6. Store `endpoint` in `currentEndpoint`.
    /// 7. If the engine was running before the switch, restart via `start(retry: false)`.
    public func switchTo(endpoint: LightWalletEndpoint) async throws {
        // F2: No-op on identical endpoint — avoids an unnecessary restart.
        // Compare host, port and TLS flag (all three must match to be the same server).
        if endpoint.host == currentEndpoint.host
            && endpoint.port == currentEndpoint.port
            && endpoint.secure == currentEndpoint.secure {
            initializer.logger.debug(
                "switchTo: endpoint unchanged (\(endpoint.host):\(endpoint.port)) — no-op",
                file: #file, function: #function, line: #line
            )
            return
        }

        let wasRunning = isRunning

        // F3: Warn when a switch fires while sync is active — the pass will restart.
        // This is not an error: the scan queue is durable and resumes after reopen.
        // The warning surfaces in device logs so we can correlate slow-progress reports
        // with mid-sync server switches (H-B investigation).
        if wasRunning {
            initializer.logger.warn(
                "switchTo during active sync — pass will restart (old: \(currentEndpoint.host):\(currentEndpoint.port), new: \(endpoint.host):\(endpoint.port))",
                file: #file, function: #function, line: #line
            )
        }

        // Stop poll loop and cancel in-flight sync (also cancels in-flight summary task).
        stopPolling()
        isRunning = false
        await engine.stop()

        // Re-open the engine handle against the new endpoint.
        try await engine.reopen(server: endpoint, network: initializer.network)

        // Record the new endpoint.
        currentEndpoint = endpoint

        // Also reset the enhanced-tx counter: the new handle starts from zero.
        lastEnhancedCount = 0

        // Restart if the engine was previously running.
        if wasRunning {
            try await start(retry: false)
        }
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

// MARK: - Internal test-visible helpers

extension SlipstreamSynchronizer {
    /// Pure progress composition — mirrors the old SDK's ScanAction formula verbatim.
    ///
    /// Formula source: `ScanAction.swift` lines ~81-99.
    /// ```
    ///   composedNumerator   = scanProgress.numerator   + (recoveryProgress?.numerator   ?? 0)
    ///   composedDenominator = scanProgress.denominator + (recoveryProgress?.denominator ?? 0)
    ///   denominator == 0    → 1.0
    ///   progress > 1.0      → clamp to 1.0 (old SDK threw; we log-warn, then clamp)
    ///   areFundsSpendable   = scanProgress.isComplete  (ScanAction.swift:99)
    /// ```
    ///
    /// - Parameters:
    ///   - scanProgress:     `(numerator, denominator, isComplete)` from `WalletSummary.scanProgress`,
    ///                       or `nil` when the summary is unavailable (fresh db).
    ///   - recoveryProgress: `(numerator, denominator)` from `WalletSummary.recoveryProgress`,
    ///                       or `nil` when no recovery range exists.
    /// - Returns: `(progress, spendable)` where `progress` ∈ [0.0, 1.0].
    static func composeProgress(
        scanProgress: (numerator: UInt64, denominator: UInt64, isComplete: Bool)?,
        recoveryProgress: (numerator: UInt64, denominator: UInt64)?
    ) -> (progress: Float, spendable: Bool) {
        guard let scan = scanProgress else {
            return (0.0, false)
        }

        let composedNumerator = Float(scan.numerator) + Float(recoveryProgress?.numerator ?? 0)
        let composedDenominator = Float(scan.denominator) + Float(recoveryProgress?.denominator ?? 0)

        let progress: Float
        if composedDenominator == 0 {
            progress = 1.0
        } else {
            let raw = composedNumerator / composedDenominator
            if raw > 1.0 {
                // Defensive clamp — should not happen, but protect the UI from an out-of-range
                // fraction; the old SDK threw ZcashError.rustScanProgressOutOfRange here.
                // We clamp and let the caller emit a warning (single emission point in tickPoll).
                progress = 1.0
            } else {
                progress = raw
            }
        }

        return (progress, scan.isComplete)
    }
}

// MARK: - withTaskTimeout helper (F1)

/// Races `operation` against a nanosecond timer.  Returns the operation's value if it
/// completes first; throws `_SummaryTimeoutError` when the timer wins.
///
/// Uses `Task.sleep(nanoseconds:)` for iOS 13+/macOS 12+ compatibility (the newer
/// `Task.sleep(for: Duration)` requires iOS 16+/macOS 13+).
///
/// Both the operation task and the timer task are cancelled when the other wins
/// (structured cancellation via `withThrowingTaskGroup`).  Structured concurrency
/// means this returns only once both child tasks have acknowledged cancellation.
///
/// `internal` (not `private`) so `@testable` test targets can exercise the timeout
/// behaviour directly without requiring a full `SlipstreamSynchronizer` instance.
struct _SummaryTimeoutError: Error {}

func withTaskTimeout<T: Sendable>(
    _ nanoseconds: UInt64,
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(nanoseconds: nanoseconds)
            throw _SummaryTimeoutError()
        }
        defer { group.cancelAll() }
        guard let result = try await group.next() else {
            throw _SummaryTimeoutError()
        }
        return result
    }
}

// MARK: - Private helpers

private extension SlipstreamSynchronizer {
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
