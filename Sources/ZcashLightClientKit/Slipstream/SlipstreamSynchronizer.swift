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

    // ── F2: range-boundary balance tracking ────────────────────────────────────
    // Mirrors the Rust engine's `ranges_completed` counter.  When it advances while
    // state==1 (Syncing), we trigger ONE balance-summary fetch (the "boundary summary").
    // This is EXEMPT from the no-summary-while-syncing rule: the scheduler has paused
    // the scan while enhancement runs, so DB contention is low, and calling summary
    // at this moment gives the user balance + fullyScannedHeight updates mid-sync.
    // We use a separate task (`boundarySummaryTask`) with a 20-second timeout to avoid
    // abandoning the call on an iPad A10 where summary may take 5-15s.
    private var lastRangesCompleted: UInt64 = 0
    private var boundarySummaryTask: Task<Void, Never>?

    // ── Chain-tip-updated flag parity (field bug 2026-06-11) ───────────────────
    // `ZcashRustBackend.getWalletSummary()` masks `spendableValue` to zero (moving it
    // into `valuePendingSpendability`) while `SDKFlags.chainTipUpdated == false` — the
    // [#1591] stale-chain-tip protection. In the old SDK that flag is set by
    // `UpdateChainTipAction.swift:49` right after `rustBackend.updateChainTip` succeeds.
    // The Slipstream engine performs the equivalent DB update inside `sync_once`
    // (engine.rs:111 `session.update_chain_tip(tip)`) and only THEN advertises the tip
    // to the snapshot (engine.rs:116 `p.set_chain_tip(tip)`), so a snapshot tip that
    // differs from the value captured at start() — or any nonzero tip once the pass
    // reaches Done — proves the wallet DB chain tip was refreshed by THIS run.
    // Without this marking, every balance the Slipstream path emits has
    // spendableValue == 0 forever (field report: balance pending-spinner, cannot pay).
    private var chainTipMarkedThisRun = false
    private var chainTipAtRunStart: UInt64 = 0

    // ── B4 (#1755): stall watchdog ─────────────────────────────────────────────
    // Detects the silent-freeze failure mode (field, 2026-06-12): state stuck at
    // Syncing while NO engine counter moves — the sync task hung (transport stall)
    // or died (panic — now also surfaced by the Rust-side B1 supervisor). The
    // watchdog only LOGS (Logger.error, once per stall episode); it never restarts
    // anything. Methods live in SlipstreamSynchronizer+StallWatchdog.swift; pure
    // decision logic in +PureHelpers.swift (isSyncStalled / watchdogSignature).
    // State is `internal` (not private) so the extension file can reach it.
    var watchdogLastSignature: ProgressSignature?
    var watchdogLastChangeDate = Date()
    var watchdogStallLogged = false
    /// Logger accessor for same-class extensions in other files (`initializer` is
    /// fileprivate; the StallWatchdog extension needs the injected logger).
    var watchdogLogger: Logger { initializer.logger }
    /// Stall window before the watchdog fires: 120 s with zero counter movement
    /// while Syncing. The slowest legitimate counter gap observed in the field is
    /// ~36 s (iPad A10 worst chunk), so 120 s is comfortably out of reach for a
    /// healthy sync. `internal` so tests can reference the constant.
    static let stallWatchdogThresholdSeconds: TimeInterval = 120

    // Hard timeout (nanoseconds) for a boundary getWalletSummary call: 20 seconds.
    // Longer than the 3s idle timeout because this fires mid-sync when the DB is
    // quiet (scanner paused) — we can afford to wait for a fresh balance.
    // `internal` (not `private`) so @testable test targets can verify the constant.
    static let boundarySummaryTimeoutNanoseconds: UInt64 = 20_000_000_000

    // ── Cached wallet-summary state (F1 — non-blocking progress) ──────────────
    // `getWalletSummary` can take tens of seconds mid-scan (complex shard-tree +
    // balance SQL queries) and is `@DBActor`-isolated, serialising all other DB
    // calls on the same global executor.  To prevent this from blocking the 2-second
    // poll tick — which must emit a state update EVERY tick — we maintain a cached
    // copy of the last completed summary and fetch updates in a background Task.
    //
    // T5.5 iPad A10 log evidence (the "summary-parasite" root cause):
    //   Every 8s a summary computation (10–30s of shard walks) ran CONCURRENTLY with
    //   scanning on a 4-core A10 — CPU theft + SQLite contention → ~20–35% per-output
    //   slowdown across ALL chunks. THE FIX: during active sync (state==1), make ZERO
    //   getWalletSummary calls. Progress + spendability derive entirely from engine
    //   counters (scannedBlocks / passTotalBlocks, spendableHint). Summary fetches are
    //   reserved for idle/done/error states where the DB is quiet.
    //
    // Invariants:
    //   - Only ONE summary fetch is in flight at a time (`summaryTask != nil`).
    //   - A new fetch starts only when the previous one is done AND ≥ the state-dependent
    //     interval have elapsed since it completed (`lastSummaryFinishDate`).
    //   - The fetch is wrapped in a 3-second hard timeout; on expiry the cached value
    //     is left unchanged and the next tick will retry.
    //   - When state == 1 (Syncing): NO summary fetch is ever started (see above).
    //   - When state == 3 (Done), any in-flight task is cancelled and the tick emits
    //     `.synced` immediately without waiting. A single post-sync summary fetch fires
    //     AFTER emitting .synced (never delays the .synced emission).
    private var cachedSummary: WalletSummary?
    private var summaryTask: Task<Void, Never>?
    private var lastSummaryFinishDate: Date?
    // Minimum interval (seconds) between summary fetches when NOT syncing (Disconnected, Done, Error).
    private static let summaryRefetchIntervalSeconds: TimeInterval = 2.0
    // Hard timeout (nanoseconds) for a single getWalletSummary call: 3 seconds.
    // `internal` (not `private`) so @testable test targets can verify the constant.
    static let summaryTimeoutNanoseconds: UInt64 = 3_000_000_000

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
        // Parity with SDKSynchronizer.start (SDKSynchronizer.swift:198/204): re-enables
        // `SDKFlags.chainTipUpdated` when the SDK was stopped less than 120 s ago, so a
        // quick background/foreground hop does not re-mask spendable balances.
        let sdkFlags = initializer.container.resolve(SDKFlags.self)
        await sdkFlags.sdkStarted()
        // Capture the engine's snapshot tip BEFORE the new pass starts: any LATER tip
        // change (or a Done state) proves THIS pass refreshed the wallet DB chain tip
        // (engine.rs:111 → :116 ordering) — the condition for markChainTipAsUpdated().
        chainTipAtRunStart = await engine.snapshot()?.chainTip ?? 0
        chainTipMarkedThisRun = false
        // B4: a new run starts with a fresh stall-watchdog window.
        resetStallWatchdog()
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
        // Parity with SDKSynchronizer.stop (SDKSynchronizer.swift:244): reset
        // `SDKFlags.chainTipUpdated` so spendable balances are re-masked until the next
        // pass refreshes the wallet DB chain tip ([#1591] stale-tip protection).
        let sdkFlags = initializer.container.resolve(SDKFlags.self)
        Task {
            await sdkFlags.sdkStopped()
            await engine.stop()
        }
        chainTipMarkedThisRun = false
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
        // F2: Cancel any in-flight boundary summary fetch as well.
        boundarySummaryTask?.cancel()
        boundarySummaryTask = nil
    }

    private func tickPoll() async {
        guard let snap = await engine.snapshot() else { return }
        let events = await engine.drainEvents()

        // B4: surface silent stalls (state==Syncing, zero counter movement) loudly.
        checkStallWatchdog(snap)

        // Chain-tip flag marking (field bug 2026-06-11) — see markChainTipFlagIfNeeded.
        await markChainTipFlagIfNeeded(snap)

        // ── T5.5 state-dispatch: Syncing vs Done vs other ─────────────────────
        //
        // STATE 1 (Syncing): ZERO getWalletSummary calls. Progress and spendability
        // derive entirely from engine counters:
        //   progress  = counterProgress(scanned: snap.scannedBlocks, total: snap.passTotalBlocks)
        //   spendable = snap.spendableHint != 0
        // This eliminates the "summary-parasite" regression (iPad A10 log, T5.5):
        // every 8s a 10–30s shard walk ran concurrently with scanning, stealing 20–35%
        // of CPU from rayon trial-decryption on a 4-core device. By making ZERO summary
        // calls during scan, the device's full CPU budget is available for scanning.
        //
        // STATE 3 (Done): emit .synced IMMEDIATELY (never delayed), then start ONE
        // background summary fetch to refresh balances/fullyScannedHeight for the
        // post-sync idle state.
        //
        // STATES 0/2 (Disconnected/Error): summary fetches run at the 2s cadence so
        // the balance display stays fresh while the wallet is idle or recovering.

        if snap.state == 3 {
            // Done: cancel any in-flight summary task + emit .synced immediately.
            summaryTask?.cancel()
            summaryTask = nil
            stateSubject.send(SynchronizerState(
                syncSessionID: latestState.syncSessionID,
                accountsBalances: cachedSummary?.accountBalances ?? latestState.accountsBalances,
                internalSyncStatus: .synced,
                latestBlockHeight: BlockHeight(snap.chainTip),
                fullyScannedHeight: cachedSummary?.fullyScannedHeight ?? latestState.fullyScannedHeight
            ))
            // Kick a post-sync summary fetch for balance freshness in idle state.
            // The .synced emission already fired above — this never delays it.
            kickSummaryFetchIfNeeded(state: snap.state)
            // Fall through to foundTransactions emission below (still needed on Done).
        } else if snap.state == 1 {
            // Syncing: counter-based progress only — NO regular getWalletSummary.
            // (A10 log evidence: summary was ~20–35% CPU parasite; eliminated in T5.5.)
            let progress = SlipstreamSynchronizer.counterProgress(
                scanned: snap.scannedBlocks,
                total: snap.passTotalBlocks
            )
            let spendable = snap.spendableHint != 0

            stateSubject.send(SynchronizerState(
                syncSessionID: latestState.syncSessionID,
                accountsBalances: cachedSummary?.accountBalances ?? latestState.accountsBalances,
                internalSyncStatus: .syncing(progress, spendable),
                latestBlockHeight: BlockHeight(snap.chainTip),
                fullyScannedHeight: cachedSummary?.fullyScannedHeight ?? latestState.fullyScannedHeight
            ))

            // F2: Range-boundary balance refresh (exempt from no-summary-while-syncing rule).
            // When ranges_completed advances, the scheduler has just finished scanning+enhancing
            // one suggested range and is paused before re-suggest — DB contention is LOW.
            // We trigger ONE summary fetch per boundary (one-in-flight guard) with a 20s timeout.
            // The cachedSummary result feeds balances+fullyScannedHeight into subsequent ticks.
            // % progress is NOT changed (stays counter-based from scanned/passTotalBlocks).
            if snap.rangesCompleted > lastRangesCompleted {
                lastRangesCompleted = snap.rangesCompleted
                kickBoundarySummaryFetchIfNeeded()
            }
        } else {
            // Disconnected (0) or Error (2): summary fetches remain active for balance
            // freshness at the 2s cadence.
            kickSummaryFetchIfNeeded(state: snap.state)

            let summary = cachedSummary
            let fullyScannedHeight = summary?.fullyScannedHeight ?? latestState.fullyScannedHeight
            let balances = summary?.accountBalances ?? latestState.accountsBalances

            let newStatus: InternalSyncStatus = {
                switch snap.state {
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

    /// Marks `SDKFlags.chainTipUpdated` once per run when the engine has refreshed the
    /// wallet DB chain tip — the mirror of `UpdateChainTipAction.swift:49` for the
    /// Slipstream path (field bug 2026-06-11).
    ///
    /// `ZcashRustBackend.getWalletSummary()` masks `spendableValue` to zero while
    /// `SDKFlags.chainTipUpdated == false` ([#1591] stale-tip protection). Without this
    /// marking the Slipstream path never lifts that mask and the app shows all funds as
    /// pending/unspendable forever. The decision itself is the pure helper
    /// `shouldMarkChainTipUpdated` (see its doc for the engine-ordering argument).
    private func markChainTipFlagIfNeeded(_ snap: SlipstreamSnapshot) async {
        guard Self.shouldMarkChainTipUpdated(
            snapshotTip: snap.chainTip,
            tipAtRunStart: chainTipAtRunStart,
            state: snap.state,
            alreadyMarked: chainTipMarkedThisRun
        ) else { return }

        chainTipMarkedThisRun = true
        await initializer.container.resolve(SDKFlags.self).markChainTipAsUpdated()
        initializer.logger.debug(
            "chainTipUpdated marked (snapshot tip \(snap.chainTip), state \(snap.state))",
            file: #file,
            function: #function,
            line: #line
        )
    }

    /// Returns the minimum interval (seconds) between summary fetches based on the
    /// current sync state. State 1 (Syncing) never receives a summary fetch (T5.5 —
    /// summary calls are completely eliminated during active scan to avoid CPU parasitism
    /// on weak devices; A10 evidence: ~20–35% per-output slowdown). All other states use
    /// 2 seconds.
    /// Internal for testability (pure function, no side effects).
    static func summaryFetchInterval(forState state: UInt8) -> TimeInterval {
        // Note: state==1 (Syncing) is never passed here — kickSummaryFetchIfNeeded
        // returns early for state==1 before calling this function. The 8-second
        // SUMMARY_SYNC_INTERVAL branch from T5.3 is superseded by the T5.5 full
        // elimination: zero fetches while syncing is strictly better than 8s cadence.
        return summaryRefetchIntervalSeconds
    }

    /// Starts a background summary fetch if no fetch is in-flight and the state-dependent
    /// minimum refetch interval has elapsed since the last one completed.
    ///
    /// The fetch is wrapped in a hard 3-second timeout.  On completion (success or
    /// timeout) the result is stored in `cachedSummary` and `lastSummaryFinishDate`
    /// is updated so the next tick can trigger another fetch after the interval.
    ///
    /// T5.5: Returns immediately (no-op) when state == 1 (Syncing). Progress and
    /// spendability are derived from engine counters during sync; getWalletSummary
    /// is never called while the scan is active (eliminates the "summary-parasite"
    /// CPU theft observed on iPad A10 — 10–30s shard walks competing with rayon
    /// trial-decryption on 4 cores caused ~20–35% per-output slowdown).
    ///
    /// Invariant: only ONE summary fetch task is live at a time (`summaryTask != nil`
    /// while running).  This prevents DBActor queue build-up when the DB is slow.
    private func kickSummaryFetchIfNeeded(state: UInt8) {
        // T5.5: NO summary fetch while actively syncing — see function docs above.
        guard state != 1 else { return }

        // If a fetch is already running, do not start another.
        guard summaryTask == nil else { return }

        // Enforce the minimum interval between fetches.
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

    /// F2: Starts a boundary summary fetch (exempt from the no-summary-while-syncing rule).
    ///
    /// Called when `ranges_completed` advances while `state == 1` (Syncing).
    /// At this moment the scheduler is paused between scan+enhance and re-suggest,
    /// so DB contention is low and a summary call is acceptable.
    ///
    /// Uses a separate task (`boundarySummaryTask`) with a 20-second timeout so an
    /// iPad A10 (where summary may take 5–15s) has enough time to complete.
    /// One-in-flight guard: if a boundary fetch is already running, we skip (the
    /// in-progress fetch will update `cachedSummary` when it finishes).
    ///
    /// On completion, `cachedSummary` is updated so subsequent Syncing ticks emit
    /// fresh balances + `fullyScannedHeight` while keeping counter-based % intact.
    private func kickBoundarySummaryFetchIfNeeded() {
        // One-in-flight guard: skip if a boundary fetch is already running.
        guard boundarySummaryTask == nil else { return }

        let rustBackend = initializer.rustBackend
        boundarySummaryTask = Task { [weak self] in
            let result = try? await withTaskTimeout(Self.boundarySummaryTimeoutNanoseconds) {
                try await rustBackend.getWalletSummary()
            }
            guard !Task.isCancelled else { return }
            // Update the shared cache so the next tick emits fresh balances.
            self?.cachedSummary = result ?? self?.cachedSummary
            self?.lastSummaryFinishDate = Date()
            self?.boundarySummaryTask = nil
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

            // 3a-F2. Reset the ranges-completed counter: the engine handle is being destroyed.
            lastRangesCompleted = 0

            // 3a-chainTip. Reset the chain-tip marking state: the handle (and its
            // snapshot tip) is destroyed; the next start() re-evaluates from scratch.
            chainTipMarkedThisRun = false
            chainTipAtRunStart = 0

            // 3a-B4. Re-arm the stall watchdog: the handle is destroyed.
            resetStallWatchdog()

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
        // F2: reset range-boundary counter: new handle starts from zero.
        lastRangesCompleted = 0
        // Chain-tip marking: the new handle's snapshot tip starts at zero; start()
        // below re-captures the baseline. Reset here for the not-restarting case.
        chainTipMarkedThisRun = false
        chainTipAtRunStart = 0
        // B4: re-arm the stall watchdog for the new handle.
        resetStallWatchdog()

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
