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
///
/// [Phase E / audit SDK-2] An ACTOR: every mutable var (poll mirrors, the recovery gate, …)
/// is actor-isolated, retiring the class-era races between the poll task,
/// the summary-fetch tasks and the public API. The protocol's synchronous members are
/// `nonisolated` and touch only immutable lets (the thread-safe Combine subjects, the DI
/// handles) — except `stop()`, which registers its teardown in a lock-guarded slot so an
/// immediately-following `start()` can still await it (the SDK-1 ordering contract).
public actor SlipstreamSynchronizer: Synchronizer {
    // ── Alias ──────────────────────────────────────────────────────────────────
    public nonisolated var alias: ZcashSynchronizerAlias { initializer.alias }

    // ── Sync engine ────────────────────────────────────────────────────────────
    private let engine: SlipstreamEngine

    // ── Shared infrastructure ──────────────────────────────────────────────────
    // `private` reaches the same-file private extension (Swift 4+ file-scope rule).
    private let initializer: Initializer
    private let transactionRepository: TransactionRepository
    private let transactionEncoder: TransactionEncoder
    private let broadcasterStorage: Broadcaster

    /// The one migration host this synchronizer owns (see `OrchardMigrationHost`'s type doc: each
    /// synchronizer holds exactly one). Registered on `initializer.container` and resolved
    /// immediately in `init`, mirroring `SDKSynchronizer`'s exact idiom -- see that type's
    /// `migrationHost` property doc for the full registration-timing rationale. Two live
    /// synchronizers over one `Initializer` stay unsupported (round note N3): each synchronizer
    /// type registers its own host on its own initializer's container.
    private let migrationHost: OrchardMigrationHost

    // ── State subjects (mirrors SDKSynchronizer) ───────────────────────────────
    private let stateSubject = CurrentValueSubject<SynchronizerState, Never>(.zero)
    private let eventSubject = PassthroughSubject<SynchronizerEvent, Never>()
    private let exchangeRateSubject = CurrentValueSubject<FiatCurrencyResult?, Never>(nil)

    // ── Public read-only state (nonisolated: subjects are thread-safe lets) ────
    public nonisolated var latestState: SynchronizerState { stateSubject.value }
    // TODO: [#1755] never updated (engine has no connection-state callback yet; P5).
    public nonisolated var connectionState: ConnectionState { .idle }
    public nonisolated var stateStream: AnyPublisher<SynchronizerState, Never> { stateSubject.eraseToAnyPublisher() }
    public nonisolated var eventStream: AnyPublisher<SynchronizerEvent, Never> { eventSubject.eraseToAnyPublisher() }
    public nonisolated var exchangeRateUSDStream: AnyPublisher<FiatCurrencyResult?, Never> { exchangeRateSubject.eraseToAnyPublisher() }

    // ── Broadcaster (Synchronizer protocol requirement) ────────────────────────
    public nonisolated var broadcaster: Broadcaster { broadcasterStorage }

    // ── Endpoint (mutable for switchTo) ───────────────────────────────────────
    // Tracks the endpoint currently in use.  `engine.reopen(server:network:)` uses
    // this value; `initializer.endpoint` is the initial value.
    private var currentEndpoint: LightWalletEndpoint

    // ── Running state (for switchTo restart decision) ──────────────────────────
    private var isRunning: Bool = false

    // ── Polling task ───────────────────────────────────────────────────────────
    private var pollTask: Task<Void, Never>?

    // ── foundTransactions emission tracking (v2.1 E-4) ─────────────────────────
    // Last-seen `snap.txSetVersion` — the engine's monotonic tx-set version (per-handle,
    // survives start/stop cycles; reset only where the handle dies: wipe()/switchTo()).
    private var lastTxSetVersion: UInt64 = 0
    // The host reconcile FILTER's last-published scope (recovering on/off): the filter is
    // host policy (API v2 §0, applied in `droppingUnreconciled`), so its edge — which
    // changes the VISIBLE list with no engine write — is host-observed. Together with the
    // version compare this is the WHOLE emission rule.
    private var lastRevealRecovering = false

    // [v2.1 Phase 2] The F2 boundary-refresh mirror and the [#1591] chain-tip-flag parity
    // machinery are GONE: the engine refreshes the unified summary at its own boundaries
    // (E-1) and owns tip freshness as `snapshot.tipFresh` (E-2).

    // ── B4 (#1755): stall watchdog ─────────────────────────────────────────────
    // Detects the silent-freeze failure mode (field, 2026-06-12): state stuck at
    // Syncing while NO engine counter moves — the sync task hung (transport stall)
    // or died (panic — now also surfaced by the Rust-side B1 supervisor). The
    // watchdog only LOGS (Logger.error, once per stall episode); it never restarts
    // anything. The stall FACT is engine-owned (`snap.stalledSeconds`, Phase D) —
    // Swift keeps only the once-per-episode log policy. Methods live in
    // SlipstreamSynchronizer+StallWatchdog.swift; the pure predicate is
    // `isSyncStalled` (+PureHelpers.swift). State is `internal` (not private) so
    // the extension file can reach it.
    var watchdogStallLogged = false
    /// Logger accessor for same-type extensions in other files (`initializer` is
    /// private; the StallWatchdog extension needs the injected logger).
    var watchdogLogger: Logger { initializer.logger }
    /// Stall window before the watchdog fires: 120 s with zero counter movement
    /// while Syncing. The slowest legitimate counter gap observed in the field is
    /// ~36 s (iPad A10 worst chunk), so 120 s is comfortably out of reach for a
    /// healthy sync. `internal` so tests can reference the constant.
    static let stallWatchdogThresholdSeconds: TimeInterval = 120


    // [v2.1 E-3] The host-side summary cache is GONE: the engine caches the summary itself
    // (E-1) and the warm-start emissions it fed read the truthful-from-open snapshot instead.
    // [audit SDK-1 + SDK-2] The pending `stop()` teardown, registered SYNCHRONOUSLY from the
    // nonisolated `stop()` (an actor's nonisolated members can't write actor state) and awaited
    // at the top of `start()` so a rapid stop→start can't have the stop land after (and kill)
    // the new pass. A plain `let` of a Sendable lock-guarded slot — reachable from both worlds.
    private let pendingStop = PendingStopSlot()
    /// [#1755] Mirrors the wallet's deep-recovery state. Seeded from the persisted summary at
    /// prepare()/start(); ENGINE-OWNED during a run (tickPoll adopts `snap.isRecovering`, which embeds
    /// the terminal fail-safe latch — Done/Error force it 0). Drives the "Restoring"
    /// LABEL and the Activity gate: the Activity is gated PER-TRANSACTION by the `slipstream_v_tx_reconciled`
    /// view (not held wholesale), so reconciled txs surface immediately while only the provisional ones
    /// wait. (Balance is NOT special-cased — live is correct on a fresh restore; see tickPoll.) Tracks the
    /// LIVE signal, so it self-corrects across rewind / truncate / stop.
    private var currentlyRecovering = false {
        didSet {
            // [#1755] Log only true⇄false transitions (every write site funnels through here). One line
            // per restore proves the engine's recovery→catch-up flip and the "Restoring"→"Syncing" label.
            guard currentlyRecovering != oldValue else { return }
            initializer.logger.info(
                currentlyRecovering
                    ? "[slipstream] recovery ACTIVE — restore backfill in progress (isRecovering=true)"
                    : "[slipstream] recovery COMPLETE — switching to catch-up sync (isRecovering=false)",
                file: #file,
                function: #function,
                line: #line
            )
        }
    }

    // [v2.1 E-5] `forceCounterProgressUntilDone` is GONE: the ENGINE re-baselines its
    // session progress floor when the scan scope expands (an import with an older birthday,
    // a rewind), so the blessed `progressPermille` reads the re-scan as a genuine climb by
    // itself — no host-side floor bypass.

    // ── Init ───────────────────────────────────────────────────────────────────

    /// Creates a `SlipstreamSynchronizer` instance.
    /// - Parameters:
    ///   - initializer: the same `Initializer` used for `SDKSynchronizer`; the
    ///     `SlipstreamSynchronizer` writes to the same `data.db` and uses the same
    ///     `ZcashRustBackend` for all data-model queries.
    ///   - alternateEndpoints: [v0.7 P1b] the host's full known-server list (the
    ///     selected `initializer.endpoint` may be in it — the engine dedupes).
    ///     Non-empty ⇒ every sync pass opens with a ~1 s parallel health probe
    ///     (commit to the healthiest server for the pass) and arms mid-pass
    ///     wire-collapse failover. Empty (the default) ⇒ single-server behavior,
    ///     exactly as before. Ignored on Tor passes (probe/failover dial direct,
    ///     which would bypass the circuit).
    public init(initializer: Initializer, alternateEndpoints: [LightWalletEndpoint] = []) {
        self.initializer = initializer
        self.currentEndpoint = initializer.endpoint
        self.transactionRepository = initializer.transactionRepository
        self.transactionEncoder = WalletTransactionEncoder(initializer: initializer)
        let eventSubjectRef = eventSubject

        let logger = initializer.logger

        // `[weak initializer]` breaks the initializer -> container -> closure -> initializer cycle
        // (`initializer` owns `container`, and `container` would otherwise hold this closure -- and
        // therefore `initializer` -- for its own lifetime). The `nil` branch is unreachable: this
        // closure only ever runs synchronously from `resolve`, on the next line, while `initializer`
        // is still alive; by the time anything could resolve this singleton again, `resolve` has
        // already cached the instance and will not invoke the factory a second time. Mirrors
        // `SDKSynchronizer.init`'s registration exactly (a strong capture here is a known,
        // review-flagged retain cycle -- B-1 in the round's review).
        initializer.container.register(type: OrchardMigrationHost.self, isSingleton: true) { [weak initializer] _ in
            guard let initializer else {
                preconditionFailure("OrchardMigrationHost resolved after its Initializer was released")
            }
            return OrchardMigrationHost(initializer: initializer)
        }
        self.migrationHost = initializer.container.resolve(OrchardMigrationHost.self)

        let transactionEncoderRef = WalletTransactionEncoder(initializer: initializer)
        // [#1755] zcash #1757 (multiserver submission) reworked SDKBroadcaster's init: it now
        // takes submitPlanStore + multiEndpointSubmitter (resolved from the container, same as
        // SDKSynchronizer) and no longer takes sdkFlags. Mirror SDKSynchronizer exactly.
        self.broadcasterStorage = SDKBroadcaster(
            transactionEncoder: transactionEncoderRef,
            initializer: initializer,
            logger: logger,
            eventSubject: eventSubjectRef,
            submitPlanStore: initializer.container.resolve(SubmitPlanStoring.self),
            multiEndpointSubmitter: initializer.container.resolve(MultiEndpointSubmitter.self),
            statusCheck: {}
        )
        self.engine = SlipstreamEngine(
            dbURL: initializer.dataDbURL,
            server: initializer.endpoint,
            alternates: alternateEndpoints
        )
    }

    // ── prepare ────────────────────────────────────────────────────────────────

    /// Initialises the wallet database (same as `SDKSynchronizer.prepare`) and opens the
    /// engine handle.  Handles `SeedRequired` migrations identically to `SDKSynchronizer`.
    public func prepare(
        with seed: [UInt8]?,
        walletBirthday: BlockHeight?,
        name: String,
        keySource: String?
    ) async throws -> Initializer.InitializationResult {
        // [v2.1 E-6] Route init-time provisioning (restore recover_until / new-wallet tree
        // state) through the engine's `restore_anchor` primitive — the offline fallback
        // policy and Tor privacy live ENGINE-side, one implementation for every host. The
        // legacy `SDKSynchronizer` path never sets this and keeps its frozen inline fetch.
        let anchorServer = currentEndpoint
        let anchorNetwork = initializer.network
        let anchorTorDir = await slipstreamTorDirPath()
        initializer.slipstreamAnchorSource = { isRestore, birthday, fallbackCheckpoint in
            await SlipstreamEngine.restoreAnchor(
                isRestore: isRestore,
                birthday: birthday,
                fallbackCheckpointHeight: fallbackCheckpoint,
                server: anchorServer,
                network: anchorNetwork,
                torDirPath: anchorTorDir
            )
        }
        if case .seedRequired = try await initializer.initialize(
            with: seed,
            walletBirthday: walletBirthday,
            name: name,
            keySource: keySource
        ) {
            return .seedRequired
        }
        try await engine.open(network: initializer.network)
        // [v2.1 E-3] The snapshot is truthful FROM OPEN: the engine seeds `isRecovering`,
        // the permille floor, the persisted chain tip and spendability from the wallet DB
        // (the same inputs the first suggest round would use), so the cold-launch emission
        // is a trivial snapshot→state mapping — the summary-derived warm-start math this
        // block used to carry (summaryProgress/isRecovering(summary)) is deleted. Balances
        // still come from the unified summary (recovery-safe at every phase, D-1/E-1).
        let snap = await engine.snapshot()
        currentlyRecovering = snap?.isRecovering == 1
        let summary = await unifiedWalletSummary()
        stateSubject.send(SlipstreamSynchronizer.initialState(
            snapshot: snap,
            accountsBalances: summary?.accountBalances ?? [:],
            fullyScannedHeight: summary?.fullyScannedHeight,
            syncSessionID: UUID()
        ))
        return .success
    }

    // ── start ──────────────────────────────────────────────────────────────────

    /// Starts a Slipstream sync pass.
    /// The account is already imported in `data.db` from `prepare`, so UFVK is passed as `nil`
    /// (keyless update — engine calls `ensure_account` only when `ufvk=Some`).
    public func start(retry: Bool = false) async throws {
        // T8.3 (T5.5 wart fix): a start() before prepare() must throw
        // .synchronizerNotPrepared — parity with SDKSynchronizer.start
        // (SDKSynchronizer.swift:189-192). Without this guard, start() reached
        // engine.start() on a nil handle and surfaced the internal
        // .rustSlipstreamNotOpen the user saw at launch. This makes that internal
        // error unreachable via the public Synchronizer API (it is kept only for
        // direct SlipstreamEngine misuse, covered by its own test).
        guard latestState.internalSyncStatus.isPrepared else {
            throw ZcashError.synchronizerNotPrepared
        }
        // Migration privacy gate — parity with SDKSynchronizer.start's `.stopped, .synced,
        // .disconnected, .error` branch: a migration broadcast's post-broadcast privacy buffer must
        // not be immediately followed by a sync session. Only blocks a NEW start(); an already-running
        // engine is unaffected (this synchronizer has no separate "already syncing" branch to skip
        // into, unlike SDKSynchronizer's status switch), and stop() is untouched.
        if await migrationHost.isSyncBlocked() {
            throw ZcashError.migrationSyncBlocked
        }
        // [audit SDK-1] A `stop()` registers its (chained) teardown in `pendingStop`; let the
        // whole chain land BEFORE this run's `engine.start()` so the engine actor can't order
        // an old stop after the new start (which would abort the fresh pass).
        await pendingStop.take()?.value
        let birthday = BlockHeight(initializer.walletBirthday)
        // [v2.1 Phase 2] Tip freshness ([#1591]) is ENGINE-OWNED (snapshot.tipFresh, E-2):
        // the FFI start() captures the refresh baseline and keeps freshness across a <120 s
        // stop→start hop — the SDKFlags.sdkStarted()/chainTipAtRunStart parity machinery
        // this block used to carry is deleted.
        // B4: a new run starts with a fresh stall-watchdog window.
        resetStallWatchdog()
        // TODO: [#1755] Consider passing ufvk=Some after T4.4 integration tests confirm
        //   idempotency. Current strategy: ufvk=nil (keyless) since prepare() already
        //   imported the account and stored its birthday treestate.
        let slipstreamTorDir = await slipstreamTorDirPath()
        try await engine.start(ufvk: nil, birthday: birthday, torDir: slipstreamTorDir)
        isRunning = true
        startPolling()
        // [v2.1 E-3] Warm start emission straight off the truthful snapshot: the engine
        // seeded the permille floor / recovery flag / persisted tip at open(), so a
        // cold-launch catch-up reads its real near-100% position (never 0%) with no
        // summary math. Balances carry over from prepare()'s emission.
        let snap = await engine.snapshot()
        currentlyRecovering = snap?.isRecovering == 1
        stateSubject.send(SynchronizerState(
            syncSessionID: UUID(),
            accountsBalances: latestState.accountsBalances,
            internalSyncStatus: .syncing(
                Float(snap?.progressPermille ?? 0) / 1000,
                (snap?.spendableHint ?? 0) != 0
            ),
            latestBlockHeight: (snap?.chainTip).flatMap { $0 != 0 ? BlockHeight($0) : nil }
                ?? latestState.latestBlockHeight,
            isRecovering: currentlyRecovering
        ))
    }

    // ── stop ───────────────────────────────────────────────────────────────────

    /// Stops the in-flight sync.
    /// The protocol member is synchronous, so on the actor it is `nonisolated`: it registers
    /// the isolated teardown in `pendingStop` SYNCHRONOUSLY (chained after any prior pending
    /// stop) and returns. `start()` awaits the whole chain, preserving the [audit SDK-1]
    /// ordering contract — the engine can never order an old stop after a new pass's start.
    /// The observable state change (`.stopped` emission) lands moments later on the actor.
    public nonisolated func stop() {
        pendingStop.chain { previous in
            Task {
                await previous?.value
                await self.stopImpl()
            }
        }
    }

    /// The actor-isolated body of `stop()`.
    private func stopImpl() async {
        isRunning = false
        stopPolling()
        // T8.3 (T5.5 wart fix): only emit .stopped if we were prepared. stop() on an
        // unprepared synchronizer (Zodl calls it unconditionally on didEnterBackground,
        // RootInitialization.swift:75-76) must NOT forge isPrepared by moving
        // .unprepared → .stopped — that springs the start-before-prepare wart on the
        // next foreground start(). The sdkStopped()/engine.stop() side effects below
        // stay unconditional (engine.stop() on a nil handle is a no-op). Mirrors
        // SDKSynchronizer.stop ordering (SDKSynchronizer.swift:243-249).
        if latestState.internalSyncStatus.isPrepared {
            stateSubject.send(SynchronizerState(
                syncSessionID: latestState.syncSessionID,
                accountsBalances: latestState.accountsBalances,
                internalSyncStatus: .stopped,
                latestBlockHeight: latestState.latestBlockHeight
            ))
        }
        // [v2.1 Phase 2] Re-masking after a stop is ENGINE-OWNED: the FFI stop() stamps the
        // moment, and a start() more than 120 s later re-masks via snapshot.tipFresh (E-2).
        await engine.stop()
    }

    /// Test-only seam: overrides `latestState`'s `internalSyncStatus` directly, without touching the
    /// engine, the poll loop, or `pendingStop`. `internal` (not `private`) so `@testable` tests can
    /// drive the actor into a specific status (e.g. `.disconnected` to satisfy `start(retry:)`'s
    /// `isPrepared` guard, or `.syncing` to exercise `throwIfSyncingForMigrationBroadcast()`)
    /// deterministically and instantly. `SDKSynchronizer` has an analogous production-code seam
    /// (`updateStatus(_:updateExternalStatus:)`) that its own tests reuse; `SlipstreamSynchronizer` has
    /// no equivalent single choke point (state is written from several call sites directly), and the
    /// only other way to reach a non-`.unprepared` status is the real `prepare()`/`start()` pair --
    /// which opens a real engine handle and spawns the real poll loop, unsuitable for fast, isolated
    /// migration-group tests (see `SlipstreamSynchronizerMigrationTests`: driving `.syncing` through a
    /// real `start()` left a background poll task whose `tickPoll()` → `engine.walletSummary()` call
    /// can run long against an unreachable server -- documented as unsafe "mid-scan" on `walletSummary()`
    /// itself -- and that in turn blocked `engine.stop()` behind it, since both share the
    /// `SlipstreamEngine` actor; the resulting slow teardown bled into unrelated later tests).
    func setInternalSyncStatusForTesting(_ status: InternalSyncStatus) {
        stateSubject.send(SynchronizerState(
            syncSessionID: latestState.syncSessionID,
            accountsBalances: latestState.accountsBalances,
            internalSyncStatus: status,
            latestBlockHeight: latestState.latestBlockHeight
        ))
    }

    // ── Polling (D8) ──────────────────────────────────────────────────────────

    /// [T-Tor.3 / E-6] The engine's dedicated Tor state directory when Tor is enabled, else
    /// nil (direct). A subdir of the SDK's torDirURL, SEPARATE from the old SDK's TorClient
    /// dir (arti holds a state lock). Used by both `start()` (sync metadata circuits) and
    /// the provisioning-anchor calls (identifying fetches ride Tor with the same state).
    /// The engine syncs at full speed regardless — bulk block fetch stays direct.
    private func slipstreamTorDirPath() async -> String? {
        let sdkFlags = initializer.container.resolve(SDKFlags.self)
        guard await sdkFlags.torEnabled else { return nil }
        let dir = initializer.torDirURL.appendingPathComponent("slipstream", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.path
    }

    private func startPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                // End the loop when the synchronizer is gone — without this the orphaned
                // task would keep sleeping/looping forever after dealloc.
                guard let self else { return }
                await self.tickPoll()
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    private func stopPolling() {
        pollTask?.cancel()
        pollTask = nil
        // [v2.1 Phase 2] No host-side summary tasks to cancel — the engine owns the
        // refresh lifecycle (E-1); its background thread is handle-scoped and Arc-safe.
    }

    private func tickPoll() async {
        guard let snap = await engine.snapshot() else { return }
        // [E-4] Ring hygiene only: the tx signal is the snapshot-carried `txSetVersion`
        // (loss-proof — a cumulative counter can't be evicted the way ring events can);
        // the ring stays drained so overflow warnings never fire for an idle consumer.
        _ = await engine.drainEvents()

        // B4: surface silent stalls (state==Syncing, zero counter movement) loudly.
        checkStallWatchdog(snap)

        // [v2.1 Phase 2] ONE summary source, refreshed every tick: the engine rations the
        // walk internally (E-1), so this is a cached serve on non-boundary ticks and carries
        // phase-correct balances at every state — recovery-safe Σ-view values while
        // recovering (re-read per call ⇒ the mid-restore climb stays per-tick), upstream
        // passthrough otherwise, [#1591]-masked while snapshot.tipFresh == 0 (E-2).
        // [E-3] A plain local: the host-side summary CACHE is gone with the warm-start
        // machinery it fed (the engine serves its own cache; a nil here only means
        // "engine mid-close", and every consumer falls back to `latestState`).
        let summary = await unifiedWalletSummary()

        // ── State-dispatch: Syncing vs Done vs other ──────────────────────────
        // Progress + spendability come from the snapshot (blessed `progressPermille` +
        // `spendableHint`); balances/fullyScannedHeight from the unified summary above.
        // The T5.5 no-walk-while-scanning protection lives in the ENGINE'S summary
        // rationing (E-1) — the walk never competes with rayon trial-decryption on
        // low-core devices regardless of how often the host asks.

        // [#1755] Deep-recovery gate. While the restore backfill is incomplete, Activity rows are
        // provisional (device data: phantom at every recov<100%, gone at 100%), so the reconcile
        // filter holds unlinked txs until their delta is final — forced, not a flag clients must
        // honor. A live signal ⇒ robust across rewind/truncate/stop.
        //
        // [Engine API v2 / Phase D] The recovery gate is ENGINE-OWNED: `snap.isRecovering` carries
        // the scheduler-computed flag WITH the fail-safe latch built in (terminal Done/Error force
        // 0 — the engine-side successor of the Swift resolveRecoveryGate/releasedByError machinery,
        // deleted in Phase E).
        // [E-3] Adopted UNCONDITIONALLY: the snapshot is truthful from open() (the engine seeds
        // the flag from the persisted `recover_until_height` + scan queue), so the first-seconds
        // adopt-guard that closed the pre-first-suggest lying window is retired.
        currentlyRecovering = snap.isRecovering == 1
        let recovering = currentlyRecovering

        // [v2.1 Phase 2] Balances come straight from the per-tick unified summary above —
        // the separate recovery Σ-computation (Direction B host-side) is DELETED; the engine
        // resolves the phase inside the FFI (same view, same mapping, one definition).

        if snap.state == 3 {
            // Done: emit .synced immediately.
            stateSubject.send(SynchronizerState(
                syncSessionID: latestState.syncSessionID,
                accountsBalances: summary?.accountBalances ?? latestState.accountsBalances,
                internalSyncStatus: .synced,
                latestBlockHeight: BlockHeight(snap.chainTip),
                fullyScannedHeight: summary?.fullyScannedHeight ?? latestState.fullyScannedHeight,
                isRecovering: recovering
            ))
            // Fall through to foundTransactions emission below (still needed on Done).
        } else if snap.state == 1 {
            // Syncing. [Engine API v2 / Phase E + v2.1 E-3/E-5] `progressPermille` is the ONE
            // blessed progress source: the pass-counter ratio, Done→100%, the session-monotonic
            // floor (seeded truthful-from-open, E-3), AND the scope-expansion re-baseline (E-5 —
            // an import/rewind re-scan reads as a genuine climb with no host-side floor bypass).
            let surfacedProgress = Float(snap.progressPermille) / 1000
            let spendable = snap.spendableHint != 0

            stateSubject.send(SynchronizerState(
                syncSessionID: latestState.syncSessionID,
                accountsBalances: summary?.accountBalances ?? latestState.accountsBalances,
                internalSyncStatus: .syncing(surfacedProgress, spendable),
                latestBlockHeight: BlockHeight(snap.chainTip),
                fullyScannedHeight: summary?.fullyScannedHeight ?? latestState.fullyScannedHeight,
                isRecovering: recovering
            ))
            // [v2.1 Phase 2] The F2 boundary refresh lives in the ENGINE now: the unified
            // summary refreshes itself (in a background thread) when ranges_completed moves,
            // and the per-tick call above serves it — no host-side boundary tracking.
        } else {
            // Disconnected (0) or Error (2): the per-tick unified summary keeps balances
            // fresh (engine-side 2 s idle TTL — the old host cadence, now engine-owned).
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
                fullyScannedHeight: fullyScannedHeight,
                isRecovering: recovering
            ))
        }

        // ── foundTransactions: the E-4 one-line rule ──────────────────────────
        // The ENGINE versions the stored tx set (`snap.txSetVersion`: enhancement writes,
        // mempool hits, boundary reconcile-linkage transitions, post-submit pokes — a
        // cumulative counter carried in every snapshot, so nothing can be "lost" the way
        // ring events could). The HOST owns exactly one extra edge: its own reconcile
        // FILTER flipping scope (recovering on/off — visibility policy per API v2 §0,
        // applied in `droppingUnreconciled`), which changes the VISIBLE list with no
        // engine write. Version moved or filter flipped → re-fetch + publish. Replaces
        // the counter-watch + SyncDone-fallback + count-dedup strategy (R6).
        if snap.txSetVersion != lastTxSetVersion || recovering != lastRevealRecovering {
            lastTxSetVersion = snap.txSetVersion
            lastRevealRecovering = recovering
            let txs = await droppingUnreconciled(await enhanceWithState((try? await transactionRepository.find(offset: 0, limit: 50, kind: .all)) ?? []))
            eventSubject.send(.foundTransactions(txs, nil))
        }
    }

    /// [v2.1 Phase 2] THE summary source for the slipstream path: the engine's unified
    /// phase-resolving summary (`zcashlc_slipstream_wallet_summary`, ENGINE_API_V2.md §0.5) —
    /// correct at EVERY phase (recovering ⇒ per-account Σ-reconciled balances, never over-shows;
    /// else ⇒ upstream passthrough), and freely callable (per poll tick included): the engine
    /// rations the expensive walk internally (E-1 — serve-cached + background refresh at
    /// boundaries/idle-TTL; the recovery view is re-read every call, so the mid-restore climb
    /// stays per-tick).
    ///
    /// The [#1591] stale-tip spendable mask keys on the ENGINE-OWNED fact `snapshot.tipFresh`
    /// (E-2); only the 3-line transform stays host-side (the C `AccountBalance` cannot express
    /// the awaiting-resolution shift). Recovery balances are never masked — parity with the
    /// old path, where the recovery display bypassed the legacy summary's mask entirely.
    /// A nil snapshot (engine mid-close) masks conservatively: never over-show spendable.
    private func unifiedWalletSummary() async -> WalletSummary? {
        guard let summary = await engine.walletSummary() else { return nil }
        let snap = await engine.snapshot()
        if snap?.isRecovering != 1 && snap?.tipFresh != 1 {
            return summary.withSpendableMasked()
        }
        return summary
    }

    // ── Accounts / Balances ────────────────────────────────────────────────────

    public func getAccountsBalances() async throws -> [AccountUUID: AccountBalance] {
        // [v2.1 Phase 2] ONE call, correct at every phase: the engine resolves recovery
        // (Σ-reconciled view values) vs normal (upstream passthrough) inside the unified
        // summary FFI and rations the expensive walk itself — no host-side branching.
        let summary = await unifiedWalletSummary()
        return summary?.accountBalances ?? [:]
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
        // [v2.1 E-6] recover_until comes from the engine's `restore_anchor` primitive (live
        // tip; offline ⇒ the engine's max(checkpoint, birthday+1) fallback — an offline
        // import now keeps its recovery identity instead of provisioning recover_until=NULL).
        // Identifying fetches ride Tor when enabled (same engine state dir as start()).
        let anchor = await SlipstreamEngine.restoreAnchor(
            isRestore: true,
            birthday: birthday ?? 0,
            fallbackCheckpointHeight: checkpointSource.birthday(for: BlockHeight.max).height,
            server: currentEndpoint,
            network: initializer.network,
            torDirPath: await slipstreamTorDirPath()
        )
        let chainTipHeight = anchor.map { UInt32($0.height) }
        let effectiveBirthday = birthday ?? (chainTipHeight.map { BlockHeight($0) } ?? initializer.walletBirthday)
        let checkpoint = checkpointSource.birthday(for: effectiveBirthday)

        // [#1755 H2 / SCENARIO_MATRIX S22] Serialize with the engine BEFORE the wallet write.
        // The import force-re-queues [birthday, tip] as Historic (upstream `add_account`) so
        // already-scanned blocks get re-scanned with the new key — but with a pass still
        // running, an in-flight (uncancellable) write-behind commit could mark one of those
        // ranges Scanned AFTER the import's re-queue, and that range would never be re-scanned
        // with the new account's key: silently missing notes. Stopping first guarantees any
        // orphan commit lands BEFORE the import transaction (both serialize on the SQLite
        // write lock), so the force-re-queue is the last writer. The anchor fetch above
        // deliberately runs with the engine still live — it is network-only, no wallet write.
        let wasRunning = isRunning
        await engine.stop()

        let uuid: AccountUUID
        do {
            uuid = try await initializer.rustBackend.importAccount(
                ufvk: ufvk,
                seedFingerprint: seedFingerprint,
                zip32AccountIndex: zip32AccountIndex,
                treeState: checkpoint.treeState(),
                recoverUntil: chainTipHeight,
                purpose: purpose,
                name: name,
                keySource: keySource
            )
        } catch {
            // A failed import must not leave the engine dead.
            if wasRunning {
                try? await start()
            }
            throw error
        }

        // [#1755 → v2.1 E-5] Make the new account's re-scan VISIBLE + prompt. The re-scan's
        // progress needs NO host help anymore: the ENGINE detects the scope expansion (the
        // new account's older birthday drops the suggest-round seed far below the session
        // floor) and re-baselines the floor, so the blessed `progressPermille` reads the
        // re-scan as a genuine 0→100% climb (the `forceCounterProgressUntilDone` host bypass
        // is deleted). One host job remains: RESTART the pass — the follow loop only
        // re-syncs when the server tip advances (`session.rs` `should_resync`), so without a
        // restart the re-scan would wait for the next block (≤ ~75 s). `try?`: a restart
        // hiccup must never fail an otherwise-successful import.
        initializer.logger.debug(
            "[#1755] importAccount: wasRunning=\(wasRunning) "
            + (wasRunning ? "→ restarting sync pass now to surface the re-scan" : "→ next start() will re-scan")
        )
        if wasRunning {
            try? await start()
        }

        return uuid
    }

    public func deleteAccount(_ accountUUID: AccountUUID) async throws {
        // [#1755 B4-16] Serialize with the engine — a raw pass-through here killed the wallet:
        // an in-flight pass scans with a PER-RANGE snapshot of the UFVK map + nullifier views
        // (`WriteBehindFacade::seed`, whose documented invariant is "accounts mutate only via
        // import/create, which cannot run during a range"). Deleting mid-range made the next
        // `put_blocks` write notes for a vanished account → non-transient pass error. So:
        // stop the engine first, delete, then restart. The restarted pass re-seeds without
        // the deleted key, and `WalletSession::open` prunes the account's orphaned Historic
        // scan ranges — a deep-birthday import's restore does NOT grind on after its account
        // is gone. `wasRunning` mirrors importAccount's restart contract.
        let wasRunning = isRunning
        await engine.stop()
        try await initializer.rustBackend.deleteAccount(accountUUID)
        // `delete_account` removes the account's transactions — bump `tx_set_version`
        // (tag-5 poke) so hosts re-fetch and Activity drops the dead rows on the next tick.
        await engine.notifyTxChange()
        if wasRunning {
            try? await start()
        }
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

    public nonisolated func paginatedTransactions(of kind: TransactionKind = .all) -> PaginatedTransactionRepository {
        PagedTransactionRepositoryBuilder.build(initializer: initializer, kind: kind)
    }

    public func allTransactions() async throws -> [ZcashTransaction.Overview] {
        await droppingUnreconciled(try await enhanceWithState(transactionRepository.find(offset: 0, limit: Int.max, kind: .all)))
    }

    public func allTransactions(from transaction: ZcashTransaction.Overview, limit: Int) async throws -> [ZcashTransaction.Overview] {
        await droppingUnreconciled(try await enhanceWithState(transactionRepository.find(from: transaction, limit: limit, kind: .all)))
    }

    /// [#1755] During a recent-first RESTORE the scheduler scans a recent block that spends an older note
    /// before that note's origin block, so a self-send's change reads as a phantom "+receive" until the
    /// spend links. `slipstream_v_tx_reconciled` flags those still-provisional txs, and we hold them out of
    /// the Activity list until their delta is final (genuine receives + already-linked sends still surface
    /// as soon as they appear).
    ///
    /// GATED ON `currentlyRecovering`: outside an active recovery this is a hard no-op — and we skip the
    /// view query entirely (this is the Activity-fetch hot path). A mined tx on an up-to-date wallet is real
    /// and must never be hidden. In the field the view was seen flagging a fresh Keystone send whose
    /// just-spent note stayed unlinked even after full sync AND an app restart, dropping the confirmed tx
    /// from Activity indefinitely — the "vanishing transaction" bug. The earlier "empty set outside
    /// recovery" assumption did not hold, so the recovery scope is now explicit (the transient dangling this
    /// guards against is a property of recent-first recovery scanning, not of a synced wallet).
    private func droppingUnreconciled(_ txs: [ZcashTransaction.Overview]) async -> [ZcashTransaction.Overview] {
        let recovering = currentlyRecovering
        // Optimization + fix: outside recovery `reconciledVisible` returns `txs` unchanged, so skip the
        // view query rather than fetch-then-discard on every Activity refresh.
        guard recovering else { return txs }
        let unreconciled = (try? await transactionRepository.unreconciledTxids()) ?? []
        let kept = Self.reconciledVisible(txs, unreconciled: unreconciled, recovering: recovering)
        // [#1755] Fires only during recovery now — provisional txs are gated and released as their spends
        // link, not held wholesale.
        initializer.logger.debug(
            "[slipstream] reconcile: holding \(txs.count - kept.count) provisional tx(s), surfacing \(kept.count)/\(txs.count)",
            file: #file,
            function: #function,
            line: #line
        )
        return kept
    }

    /// Pure: which txs the Activity list shows. Outside recovery (or with nothing flagged) every tx passes;
    /// during recovery the unreconciled txids (a dangling shielded spend per `slipstream_v_tx_reconciled`)
    /// are held back until their delta is final. Static + pure so it is unit-testable.
    static func reconciledVisible(
        _ txs: [ZcashTransaction.Overview],
        unreconciled: Set<Data>,
        recovering: Bool
    ) -> [ZcashTransaction.Overview] {
        guard recovering, !unreconciled.isEmpty else { return txs }
        return txs.filter { !unreconciled.contains($0.rawID) }
    }

    /// T8.3.6 (UX): populate `ZcashTransaction.Overview.state` on fetched transactions (the
    /// Slipstream equivalent of `SDKSynchronizer.enhanceRawTransactionsWithState`). `find`
    /// leaves `state == nil`, so without this Zashi maps an INCOMING tx via
    /// `transaction.state == .pending` → `nil == .pending` → false → ".received" — a 0-conf
    /// mempool tx then wrongly shows "received" instead of "receiving". Pure mapping lives in
    /// `transactionsWithState`; here we just resolve the current chain height it needs.
    private func enhanceWithState(_ raw: [ZcashTransaction.Overview]) async -> [ZcashTransaction.Overview] {
        let tip = latestState.latestBlockHeight
        return Self.transactionsWithState(raw, currentHeight: tip != 0 ? tip : ((try? await initializer.rustBackend.maxScannedHeight()) ?? .zero))
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
        let sdkFlags = initializer.container.resolve(SDKFlags.self)
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

    // ── Height queries ────────────────────────────────────────────────────────

    public func latestHeight() async throws -> BlockHeight {
        let sdkFlags = initializer.container.resolve(SDKFlags.self)
        return try await initializer.lightWalletService.latestBlockHeight(mode: await sdkFlags.ifTor(.uniqueTor))
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

    public nonisolated func refreshExchangeRateUSD() {
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

    public nonisolated func rewind(_ policy: RewindPolicy) -> AnyPublisher<Void, Error> {
        let subject = PassthroughSubject<Void, Error>()
        Task {
            await self.rewindImpl(policy, subject)
        }
        return subject.eraseToAnyPublisher()
    }

    /// The actor-isolated body of `rewind(_:)`.
    private func rewindImpl(_ policy: RewindPolicy, _ subject: PassthroughSubject<Void, Error>) async {
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

        // [#1755 H1 / SCENARIO_MATRIX S15] Serialize with the engine — the same contract as
        // deleteAccount/importAccount: truncating while a pass is mid-write would let the
        // in-flight pass commit against the truncated chain state (the old SDK stopped the
        // processor inside `blockProcessor.rewind`; slipstream lost that parity). Stop →
        // truncate → restart. The restarted pass re-suggests from the truncated queue, and
        // the engine's scope-expansion re-baseline (E-5) makes the re-scan read as a genuine
        // climb. Restart on BOTH outcomes — a failed truncate must not leave the engine dead.
        let wasRunning = isRunning
        await engine.stop()

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
            // [audit SDK-5 → E-3] No host cache to reset after a truncate: the summary is
            // engine-served per call (E-1). Engine COUNTERS are NOT reset here on purpose:
            // the handle survives a rewind, so `enhancedTxs`/`rangesCompleted` stay monotonic
            // and the SDK mirrors keep tracking them (mirrors reset only where the handle
            // dies: `wipe()` / `switchTo()`).
            if wasRunning {
                try? await start()
            }
            subject.send(completion: .finished)
        } catch {
            if wasRunning {
                try? await start()
            }
            subject.send(completion: .failure(error))
        }
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
    public nonisolated func wipe() -> AnyPublisher<Void, Error> {
        let subject = PassthroughSubject<Void, Error>()
        Task(priority: .high) { [weak self] in
            guard let self else {
                subject.send(completion: .finished)
                return
            }
            await self.wipeImpl(subject)
        }
        return subject.eraseToAnyPublisher()
    }

    /// The actor-isolated body of `wipe()`.
    private func wipeImpl(_ subject: PassthroughSubject<Void, Error>) async {
        // 1. Stop polling.
        stopPolling()

        // 2. Stop the in-flight sync (non-blocking cancel in Rust).
        await engine.stop()

        // 3. Free the engine handle (exact-once — close() guards against double-free).
        await engine.close()

        // 3a. Reset the per-handle tx-set-version mirror: the engine handle is being
        //     destroyed, so the Rust-side monotonic counter restarts at 0 on next open().
        lastTxSetVersion = 0
        lastRevealRecovering = false

        // 3a-B4. Re-arm the stall watchdog: the handle is destroyed.
        resetStallWatchdog()

        // 3b. Close Swift-side DB connections before deleting files — mirrors
        //     SDKSynchronizer.wipe() prewipe closure (SDKSynchronizer.swift:759-760).
        transactionEncoder.closeDBConnection()
        transactionRepository.closeDBConnection()

        do {
            let fileManager = FileManager.default

            // 4. Remove data.db and its SQLite WAL/SHM siblings.
            // E.g. /path/data.db  → /path/data.db-wal, /path/data.db-shm.
            let dataDb = initializer.dataDbURL
            for suffix in ["", "-wal", "-shm"] {
                let targetURL = suffix.isEmpty
                    ? dataDb
                    : URL(fileURLWithPath: dataDb.path + suffix)
                if fileManager.fileExists(atPath: targetURL.path) {
                    try fileManager.removeItem(at: targetURL)
                }
            }

            // 5. Remove the fsBlockDbRoot directory tree (parity with old SDK wipe).
            let fsRoot = initializer.fsBlockDbRoot
            if fileManager.fileExists(atPath: fsRoot.path) {
                try fileManager.removeItem(at: fsRoot)
            }

            // 6. Reset state to unprepared/zero.
            stateSubject.send(.zero)

            // 7. Signal completion.
            subject.send(completion: .finished)
        } catch {
            subject.send(completion: .failure(error))
        }
    }

    // ── Migration (Orchard -> Ironwood) ────────────────────────────────────────
    //
    // Thin forwards to `migrationHost.migration(for:)`'s per-account `OrchardMigration` actor (or,
    // for the three wallet-scope gate members, to the host itself) -- mirrors `SDKSynchronizer`'s
    // "MARK: Migration" section exactly. The two members that can broadcast (`submitNoteSplit`,
    // `executeNextPendingMigrationTransfer`) are guarded here by `throwIfSyncingForMigrationBroadcast()`
    // -- an advisory point-in-time check, not a hard mutual-exclusion lock: sync and migration
    // broadcasts must never share a session, and hosts still sequence sessions themselves.

    public func migrationState(accountUUID: AccountUUID) async throws -> MigrationState {
        try await migrationHost.migration(for: accountUUID).migrationState()
    }

    public func migrationProgress(accountUUID: AccountUUID) async throws -> MigrationProgress? {
        try await migrationHost.migration(for: accountUUID).migrationProgress()
    }

    public func isNoteSplitNeeded(accountUUID: AccountUUID) async throws -> Bool {
        try await migrationHost.migration(for: accountUUID).isNoteSplitNeeded()
    }

    public func prepareNoteSplit(accountUUID: AccountUUID) async throws -> NoteSplitProposal {
        try await migrationHost.migration(for: accountUUID).prepareNoteSplit()
    }

    public func submitNoteSplit(
        accountUUID: AccountUUID,
        proposal: NoteSplitProposal,
        usk: UnifiedSpendingKey,
        options: MigrationNetworkPrivacyOptions
    ) async throws -> MigrationTransferResult {
        try throwIfSyncingForMigrationBroadcast()
        return try await migrationHost.migration(for: accountUUID).submitNoteSplit(proposal: proposal, usk: usk, options: options)
    }

    public func proposeMigrationTransfers(accountUUID: AccountUUID, includeResidual: Bool) async throws -> MigrationSchedule {
        try await migrationHost.migration(for: accountUUID).proposeMigrationTransfers(includeResidual: includeResidual)
    }

    public func proposeImmediateMigration(accountUUID: AccountUUID) async throws -> ImmediateMigrationProposal {
        try await migrationHost.migration(for: accountUUID).proposeImmediateMigration()
    }

    public func recordImmediateMigration(accountUUID: AccountUUID, txid: Data) async throws {
        try await migrationHost.migration(for: accountUUID).recordImmediateMigration(txid: txid)
    }

    public func residualAfterMigration(accountUUID: AccountUUID) async throws -> Zatoshi? {
        try await migrationHost.migration(for: accountUUID).residualAfterMigration()
    }

    public func lockMigrationResidual(accountUUID: AccountUUID) async throws -> Zatoshi {
        try await migrationHost.migration(for: accountUUID).lockMigrationResidual()
    }

    public func unlockMigrationResidual(accountUUID: AccountUUID) async throws -> Int {
        try await migrationHost.migration(for: accountUUID).unlockMigrationResidual()
    }

    public func estimateMigrationRuns(accountUUID: AccountUUID) async throws -> MigrationRunEstimate {
        try await migrationHost.migration(for: accountUUID).estimateMigrationRuns()
    }

    public func signAndStoreMigrationSchedule(accountUUID: AccountUUID, _ schedule: MigrationSchedule, usk: UnifiedSpendingKey) async throws {
        try await migrationHost.migration(for: accountUUID).signAndStoreMigrationSchedule(schedule, usk: usk)
    }

    public func isSyncRequiredBeforeNextMigrationTransfer(accountUUID: AccountUUID) async throws -> Bool {
        try await migrationHost.migration(for: accountUUID).isSyncRequiredBeforeNextTransfer()
    }

    public func executeNextPendingMigrationTransfer(
        accountUUID: AccountUUID,
        options: MigrationNetworkPrivacyOptions
    ) async throws -> MigrationTransferResult? {
        try throwIfSyncingForMigrationBroadcast()
        return try await migrationHost.migration(for: accountUUID).executeNextPendingTransfer(options: options)
    }

    public func isMigrationSyncBlocked() async -> Bool {
        await migrationHost.isSyncBlocked()
    }

    public nonisolated var migrationSyncBlockedStream: AnyPublisher<Bool, Never> {
        migrationHost.syncBlockedStream
    }

    public nonisolated var migrationPrivacySyncBufferDuration: TimeInterval {
        migrationHost.privacySyncBufferDuration
    }

    public func hasOverdueMigrationTransfers(accountUUID: AccountUUID) async throws -> Bool {
        try await migrationHost.migration(for: accountUUID).hasOverdueTransfers()
    }

    public func hasInvalidMigrationTransfers(accountUUID: AccountUUID) async throws -> Bool {
        try await migrationHost.migration(for: accountUUID).hasInvalidTransfers()
    }

    public func rescheduleOverdueMigrationTransfer(accountUUID: AccountUUID) async throws -> MigrationTransferProposal? {
        try await migrationHost.migration(for: accountUUID).rescheduleOverdueTransfer()
    }

    public func restartCurrentMigrationStep(accountUUID: AccountUUID, includeResidual: Bool) async throws -> MigrationSchedule {
        try await migrationHost.migration(for: accountUUID).restartCurrentMigrationStep(includeResidual: includeResidual)
    }

    public func refreshStaleMigrationTransfers(accountUUID: AccountUUID, usk: UnifiedSpendingKey, includeResidual: Bool) async throws -> UInt32 {
        try await migrationHost.migration(for: accountUUID).refreshStaleTransfers(usk: usk, includeResidual: includeResidual)
    }

    public func createUnsignedNoteSplitPCZTs(accountUUID: AccountUUID) async throws -> [MigrationUnsignedTransferPczt] {
        try await migrationHost.migration(for: accountUUID).createUnsignedNoteSplitPCZTs()
    }

    public func storeSignedNoteSplitPCZTs(accountUUID: AccountUUID, _ signed: [MigrationSignedTransferPczt]) async throws -> PreparedMigrationTransfer {
        try await migrationHost.migration(for: accountUUID).storeSignedNoteSplitPCZTs(signed)
    }

    public func createUnsignedMigrationTransferPCZTs(
        accountUUID: AccountUUID,
        for schedule: MigrationSchedule
    ) async throws -> [MigrationUnsignedTransferPczt] {
        try await migrationHost.migration(for: accountUUID).createUnsignedTransferPCZTs(for: schedule)
    }

    public func storeSignedMigrationSchedulePCZTs(accountUUID: AccountUUID, _ signed: [MigrationSignedTransferPczt]) async throws {
        try await migrationHost.migration(for: accountUUID).storeSignedSchedulePCZTs(signed)
    }

    /// Throws ``ZcashError/migrationBroadcastDuringSync`` when the synchronizer is actively syncing.
    ///
    /// Guards the two migration entry points that broadcast (``submitNoteSplit(accountUUID:proposal:usk:options:)``
    /// and ``executeNextPendingMigrationTransfer(accountUUID:options:)``): sync and migration
    /// broadcasts must never share a session. Reads `latestState.internalSyncStatus` -- the same
    /// nonisolated status surface `start(retry:)`'s unprepared guard reads -- so the guard triggers on
    /// the syncing case only; unprepared/stopped/synced/disconnected/error all proceed. Advisory,
    /// point-in-time enforcement, not a hard mutual-exclusion lock: hosts still sequence sync and
    /// migration-broadcast sessions themselves.
    private func throwIfSyncingForMigrationBroadcast() throws {
        if case .syncing = latestState.internalSyncStatus {
            throw ZcashError.migrationBroadcastDuringSync
        }
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

        // Also reset the tx-set-version mirror: the new handle's counter starts from zero.
        lastTxSetVersion = 0
        lastRevealRecovering = false
        // B4: re-arm the stall watchdog for the new handle.
        resetStallWatchdog()

        // Restart if the engine was previously running.
        if wasRunning {
            try await start(retry: false)
        }
    }

    /// [v0.7 P1b] Replaces the alternate-server list at runtime — the host calls this
    /// when the user's server-selection consent changes (e.g. Automatic ⇄ Manual).
    /// A non-empty list arms per-pass probe-then-commit + wire failover; an EMPTY list
    /// revokes it (probe skipped, failover disarmed — the configured endpoint is used
    /// exclusively, exact single-server behavior). Takes effect from the NEXT sync
    /// pass; an in-flight pass keeps the config it started with.
    public func setAlternateEndpoints(_ endpoints: [LightWalletEndpoint]) async {
        await engine.setAlternates(endpoints)
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

    public nonisolated func estimateBirthdayHeight(for date: Date) -> BlockHeight {
        initializer.container.resolve(CheckpointSource.self).estimateBirthdayHeight(for: date)
    }

    public nonisolated func estimateTimestamp(for height: BlockHeight) -> TimeInterval? {
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

    // [G1, docs/slipstream/2026-07-08-grpc-privacy-map.md] These helpers send
    // wallet-identifying data (transparent addresses, UTXO queries) — with Tor
    // enabled they MUST ride isolated circuits, exactly like the old
    // SDKSynchronizer. The thin-host port hardcoded `.direct` here; restored
    // to `ifTor(.uniqueTor)` old-SDK parity 2026-07-08.

    public func checkSingleUseTransparentAddresses(accountUUID: AccountUUID) async throws -> TransparentAddressCheckResult {
        let dbData = initializer.dataDbURL.osStr()
        let sdkFlags = initializer.container.resolve(SDKFlags.self)
        return try await initializer.lightWalletService.checkSingleUseTransparentAddresses(
            dbData: dbData,
            networkType: initializer.network.networkType,
            accountUUID: accountUUID,
            mode: await sdkFlags.ifTor(.uniqueTor)
        )
    }

    public func updateTransparentAddressTransactions(address: String) async throws -> TransparentAddressCheckResult {
        let dbData = initializer.dataDbURL.osStr()
        let sdkFlags = initializer.container.resolve(SDKFlags.self)
        return try await initializer.lightWalletService.updateTransparentAddressTransactions(
            address: address,
            start: 0,
            end: -1,
            dbData: dbData,
            networkType: initializer.network.networkType,
            mode: await sdkFlags.ifTor(.uniqueTor)
        )
    }

    public func fetchUTXOsBy(address: String, accountUUID: AccountUUID) async throws -> TransparentAddressCheckResult {
        let dbData = initializer.dataDbURL.osStr()
        let sdkFlags = initializer.container.resolve(SDKFlags.self)
        return try await initializer.lightWalletService.fetchUTXOsByAddress(
            address: address,
            dbData: dbData,
            networkType: initializer.network.networkType,
            accountUUID: accountUUID,
            mode: await sdkFlags.ifTor(.uniqueTor)
        )
    }

    // ── Tree state ────────────────────────────────────────────────────────────

    public func getTreeState(height: UInt64) async throws -> Data {
        let sdkFlags = initializer.container.resolve(SDKFlags.self)
        let treeState = try await initializer.lightWalletService.getTreeState(
            BlockID(height: height),
            mode: await sdkFlags.ifTor(.uniqueTor)
        )
        return try treeState.serializedData()
    }

    // ── Database debug ────────────────────────────────────────────────────────

    public nonisolated func debugDatabase(sql: String) -> String {
        transactionRepository.debugDatabase(sql: sql)
    }

}

// MARK: - Private helpers

private extension SlipstreamSynchronizer {
    func allSentTransactions() async throws -> [ZcashTransaction.Overview] {
        try await enhanceWithState(transactionRepository.findSent(offset: 0, limit: Int.max))
    }

    func allReceivedTransactions() async throws -> [ZcashTransaction.Overview] {
        try await enhanceWithState(transactionRepository.findReceived(offset: 0, limit: Int.max))
    }


    // [#1755] Mirrors SDKSynchronizer.submitTransactions after zcash #1757 (multiserver
    // submission): consumes [CreatedTransaction] (was [ZcashTransaction.Overview]) and adopts the
    // "trust the network over the submit-side error" recovery branch. Submission is shared SDK
    // logic — slipstream only owns the sync path — so this stays byte-for-byte the SDK behaviour.
    func submitTransactions(_ transactions: [CreatedTransaction]) -> AsyncThrowingStream<TransactionSubmitResult, Error> {
        var iterator = transactions.makeIterator()
        var submitFailed = false

        return AsyncThrowingStream(unfolding: {
            guard let transaction = iterator.next() else { return nil }

            if submitFailed {
                return .notAttempted(txId: transaction.txId)
            } else {
                do {
                    try await self.transactionEncoder.submit(transaction: transaction.encodedTransaction)
                    // [Engine API v2 §4.5 / E-4] Surface the just-broadcast tx: poke the engine
                    // (`notify_tx_change`), which bumps the snapshot's `txSetVersion` (+ a tag-5
                    // ring event for ring consumers) — the poll loop's version compare re-fetches
                    // and emits on the next tick (≤ the poll cadence). One path for every host.
                    // Fire-and-forget; never delays the submit stream.
                    Task { await self.engine.notifyTxChange() }
                    return TransactionSubmitResult.success(txId: transaction.txId)
                } catch ZcashError.serviceSubmitFailed(let error) {
                    submitFailed = true
                    return TransactionSubmitResult.grpcFailure(txId: transaction.txId, error: error)
                } catch TransactionEncoderError.submitError(let code, let message) {
                    // If the server already has this tx, the broadcast landed — treat as success.
                    if await self.transactionEncoder.isTransactionKnownToServer(txId: transaction.txId) {
                        return TransactionSubmitResult.success(txId: transaction.txId)
                    }
                    submitFailed = true
                    return TransactionSubmitResult.submitFailure(txId: transaction.txId, code: code, description: message)
                }
            }
        })
    }
}
