//
//  OrchardMigrationHost.swift
//  ZcashLightClientKit
//

import Combine
import Foundation

/// The per-synchronizer owner of all Orchard -> Ironwood migration machinery.
///
/// `SDKSynchronizer` (and, later, `SlipstreamSynchronizer`) each hold exactly one host. It owns the
/// lazily-created, per-account ``OrchardMigration`` actors, a single ``MigrationBroadcaster`` shared
/// across every account (so two accounts never race two independent Tor bootstraps against the shared
/// `migration_tor` directory), and the wallet-scope sync-blocked predicate/stream the synchronizer's
/// sync loop consults.
///
/// The per-account actors resolve everything from the wallet's paths and hold their own Rust backend
/// (see ``OrchardMigration``); the host itself borrows the synchronizer's welding
/// (`Initializer.rustBackend`) only for the WALLET-scope members — the sync-blocked predicate
/// (enumerating every account and reading each account's persisted gate file directly, so a
/// dormant account whose actor has never been created this launch still counts) and the
/// account-free chain-tip estimation pair (``estimatedChainTip()`` /
/// ``estimatedSecondsPerBlock()``, which read the shared blocks table).
package actor OrchardMigrationHost {
    private let welding: ZcashRustBackendWelding
    private let sharedBroadcaster: any MigrationBroadcasting
    private let generalStorageURL: URL
    private let now: @Sendable () -> Date
    private let logger: Logger

    /// Builds a per-account ``OrchardMigration`` bound to `accountUUID`, wired to the given shared
    /// broadcaster. Injected so tests can substitute mock-welded actors; production builds each from
    /// the initializer's config via ``OrchardMigration/init(config:sharedBroadcaster:)``.
    private let actorFactory: (AccountUUID, any MigrationBroadcasting) -> OrchardMigration

    /// The wallet-scope reactive stream machinery. A separate, self-synchronized object (like
    /// ``MigrationSyncGate``) so ``syncBlockedStream`` can be `nonisolated`.
    private let blockedPublisher: HostSyncBlockedPublisher

    /// The live per-account gate views the wallet-scope predicate consults ALONGSIDE the persisted
    /// gate files (A8): each actor ``migration(for:)`` creates registers its gate's in-memory
    /// inputs here, so a failed gate-file write (full disk, sandbox hiccup) cannot blind
    /// ``isSyncBlocked()`` to a mark this process just made — the predicate evaluates both views
    /// and lets blocked win. A separate lock-synchronized object (not actor state) because the
    /// predicate closure is built in `init`, before `self` exists, and runs off-actor.
    private let liveGateRegistry: MigrationLiveGateRegistry

    /// The lazily-created, cached per-account actors. Actor isolation is the synchronization: a given
    /// account resolves to the same instance for the host's lifetime.
    private var migrations: [AccountUUID: OrchardMigration] = [:]

    /// Production initializer: derives everything from the synchronizer's ``Initializer``.
    ///
    /// The shared ``MigrationBroadcaster`` is built here, once, from the initializer's Tor directory
    /// and logger. Per-account configs reuse the initializer's paths, network, and logger
    /// (`loggingPolicy: .custom(initializer.logger)`); the wallet-scope predicate borrows the
    /// initializer's `rustBackend` welding.
    package init(initializer: Initializer) {
        let dataDbURL = initializer.dataDbURL
        let fsBlockDbRoot = initializer.fsBlockDbRoot
        let spendParamsURL = initializer.spendParamsURL
        let outputParamsURL = initializer.outputParamsURL
        let network = initializer.network
        let torDirURL = initializer.torDirURL
        let generalStorageURL = initializer.generalStorageURL
        let logger = initializer.logger

        let factory: (AccountUUID, any MigrationBroadcasting) -> OrchardMigration = { accountUUID, broadcaster in
            OrchardMigration(
                config: OrchardMigration.Config(
                    dataDbURL: dataDbURL,
                    fsBlockDbRoot: fsBlockDbRoot,
                    spendParamsURL: spendParamsURL,
                    outputParamsURL: outputParamsURL,
                    network: network,
                    accountUUID: accountUUID,
                    torDirURL: torDirURL,
                    generalStorageURL: generalStorageURL,
                    loggingPolicy: Initializer.LoggingPolicy.custom(logger)
                ),
                sharedBroadcaster: broadcaster
            )
        }

        self.init(
            welding: initializer.rustBackend,
            sharedBroadcaster: MigrationBroadcaster(torDirURL: torDirURL, logger: logger),
            generalStorageURL: generalStorageURL,
            tickInterval: 15,
            now: { Date() },
            logger: logger,
            actorFactory: factory
        )
    }

    /// Injecting initializer for tests: supply the welding, the shared broadcaster, the storage
    /// directory the gate files live in, the ticker interval and clock, the logger, and the
    /// per-account actor factory directly — mirroring ``OrchardMigration``'s own injecting init.
    init(
        welding: ZcashRustBackendWelding,
        sharedBroadcaster: any MigrationBroadcasting,
        generalStorageURL: URL,
        tickInterval: TimeInterval,
        now: @escaping @Sendable () -> Date,
        logger: Logger,
        actorFactory: @escaping (AccountUUID, any MigrationBroadcasting) -> OrchardMigration
    ) {
        self.welding = welding
        self.sharedBroadcaster = sharedBroadcaster
        self.generalStorageURL = generalStorageURL
        self.now = now
        self.logger = logger
        self.actorFactory = actorFactory

        let liveGateRegistry = MigrationLiveGateRegistry()
        self.liveGateRegistry = liveGateRegistry

        let predicate: @Sendable () async -> Bool = {
            await OrchardMigrationHost.computeSyncBlocked(
                welding: welding,
                generalStorageURL: generalStorageURL,
                liveGateRegistry: liveGateRegistry,
                now: now,
                logger: logger
            )
        }
        self.blockedPublisher = HostSyncBlockedPublisher(
            initialBlocked: false,
            tickInterval: tickInterval,
            logger: logger,
            predicate: predicate
        )
    }

    /// The ``OrchardMigration`` bound to `accountUUID`, lazily created and cached on first request.
    ///
    /// The same account resolves to the same instance thereafter; distinct accounts get distinct
    /// actors, each sharing the host's single ``MigrationBroadcaster``. A newly created actor's
    /// per-account blocked stream is registered with ``syncBlockedStream`` so a broadcast on it
    /// re-evaluates the wallet-scope value immediately, and its live gate view is registered with
    /// the wallet-scope predicate so a failed gate-file write cannot hide its marks (A8).
    package func migration(for accountUUID: AccountUUID) -> OrchardMigration {
        if let existing = migrations[accountUUID] {
            return existing
        }

        let migration = actorFactory(accountUUID, sharedBroadcaster)
        migrations[accountUUID] = migration
        blockedPublisher.watchBroadcastSignal(migration.syncBlockedStream)
        liveGateRegistry.register(accountUUID) { migration.liveInFlightUntil() }
        return migration
    }

    /// Whether ordinary wallet sync should currently be paused for *any* migrating account.
    ///
    /// Enumerates every wallet account via the welding (not the lazy actor cache, so a dormant
    /// account whose gate file records a marker a crash left behind still counts after a fresh
    /// launch) and blocks if any account has a submission in flight. Non-throwing: an account
    /// enumeration failure logs and degrades to "unblocked" (sync allowed) — matching
    /// ``OrchardMigration/isSyncBlocked()``.
    package func isSyncBlocked() async -> Bool {
        await Self.computeSyncBlocked(
            welding: welding,
            generalStorageURL: generalStorageURL,
            liveGateRegistry: liveGateRegistry,
            now: now,
            logger: logger
        )
    }

    /// The wall-clock ESTIMATED chain tip: the ``ChainTipEstimator`` projection over the most
    /// recently scanned blocks' `(height, header time)` samples. WALLET-scoped (the samples come
    /// from the shared blocks table), hence hosted here rather than on a per-account actor. With
    /// no samples at all (a wallet whose `blocks` table is empty — e.g. one restored from a
    /// checkpoint that has not scanned since), this falls back to the wallet's max SCANNED height
    /// verbatim (the honest "no data to project from" answer: welding's `maxScannedHeight` is the
    /// only height the wallet knows without the network), and throws
    /// ``ZcashError/migrationChainTipUnavailable`` when even that is unknown because the wallet
    /// has never scanned.
    package func estimatedChainTip() async throws -> BlockHeight {
        let projection = try await MigrationTipEstimation.project(welding: welding, now: now())
        if let estimated = projection.estimatedTip {
            return estimated
        }
        guard let scannedTip = try await welding.maxScannedHeight() else {
            throw ZcashError.migrationChainTipUnavailable
        }
        return scannedTip
    }

    /// The measured seconds-per-block over the most recently scanned blocks (see
    /// ``ChainTipEstimator/secondsPerBlock()``): the mean of the last up-to-100 consecutive
    /// header-time deltas, clamped to [5, 150] s, falling back to 75 s (the target spacing) when
    /// fewer than two samples exist. WALLET-scoped like ``estimatedChainTip()``. A host uses it
    /// to convert wake-up heights into wall-clock OS timers.
    package func estimatedSecondsPerBlock() async throws -> Double {
        try await MigrationTipEstimation.project(welding: welding, now: now()).secondsPerBlock
    }

    /// A stream of ``isSyncBlocked()`` at wallet scope: emits the current value on subscribe,
    /// re-evaluates the wallet predicate on a subscription-gated ~15 s ticker and immediately after
    /// any hosted account's actor marks a broadcast, and collapses consecutive duplicates.
    ///
    /// `nonisolated` so the synchronizer's sync-gating can subscribe without awaiting the host; it is
    /// backed by the internally synchronized ``HostSyncBlockedPublisher`` (generation-ordered,
    /// latest-wins). Dormant accounts (no actor created this launch) are covered by the seed and the
    /// periodic ticker; active accounts additionally push an immediate re-evaluation through their
    /// per-account gate stream.
    ///
    /// - Important: The value delivered synchronously on subscribe is a conservative "unblocked"
    ///   seed (the wallet predicate needs the async welding enumeration, so it cannot be computed
    ///   synchronously — unlike ``MigrationSyncGate/blockedStream``'s per-account marker seed). It is
    ///   corrected by the first asynchronous re-evaluation (the ticker's immediate startup recompute,
    ///   or sooner if a broadcast happens first). A subscriber that must be correct from its very
    ///   first value should pair this stream with an initial ``isSyncBlocked()`` call.
    package nonisolated var syncBlockedStream: AnyPublisher<Bool, Never> {
        blockedPublisher.stream
    }

    // MARK: - Private

    /// The wallet-scope blocked predicate, factored out so both ``isSyncBlocked()`` and
    /// ``syncBlockedStream``'s recompute share one implementation and neither consults the lazy actor
    /// cache. Non-throwing; degrades open (to "unblocked") on any enumeration/db error.
    ///
    /// Per account, the gate state is evaluated over BOTH views and blocked wins (A8): the
    /// persisted gate file (covers dormant accounts from previous launches) and — when the
    /// account's actor exists this launch — its live in-memory marker from `liveGateRegistry`, so
    /// a failed gate-file write cannot hide a mark this process just made.
    ///
    /// There is nothing else to consult. No work-pending query gates sync (the forward-looking
    /// ready-broadcast predicate went on 2026-08-05, taking the estimate-aware second pass it
    /// needed with it), and no elapsed-time condition does either (the post-broadcast privacy
    /// buffer went on 2026-08-07) — see ``MigrationSyncGate``'s type doc.
    private static func computeSyncBlocked(
        welding: ZcashRustBackendWelding,
        generalStorageURL: URL,
        liveGateRegistry: MigrationLiveGateRegistry,
        now: @Sendable () -> Date,
        logger: Logger
    ) async -> Bool {
        let accounts: [Account]
        do {
            accounts = try await welding.listAccounts()
        } catch {
            logger.error("OrchardMigrationHost: failed to enumerate wallet accounts for the sync-blocked check; degrading to unblocked: \(error)")
            return false
        }

        let evaluatedAt = now()

        // Gate files + live gate views only — the in-flight broadcast marker is the single
        // condition left (see `MigrationSyncGate`'s type doc).
        for account in accounts {
            let fileBlocked = MigrationSyncGate.isBlocked(
                now: evaluatedAt,
                inFlightUntil: MigrationSyncGate.persistedInFlightUntil(
                    directory: generalStorageURL,
                    accountUUID: account.id,
                    logger: logger
                )
            )
            // A8: the live view exists only for accounts whose actor was created this launch;
            // evaluating it separately (rather than merging timestamps) keeps "blocked wins"
            // exact under the in-flight plausible-window rule.
            let liveBlocked = MigrationSyncGate.isBlocked(
                now: evaluatedAt,
                inFlightUntil: liveGateRegistry.inFlightUntil(for: account.id)
            )
            if fileBlocked || liveBlocked {
                return true
            }
        }
        return false
    }
}

/// The lock-synchronized registry of live per-account gate views behind
/// ``OrchardMigrationHost``'s A8 defense: `register(_:provider:)` is called from the host actor as
/// each per-account ``OrchardMigration`` is created, and `inFlightUntil(for:)` is read by the
/// wallet-scope predicate closure off-actor. The lock guards only the dictionary; a provider (a
/// tiny nonisolated read — `OrchardMigration.liveInFlightUntil()`, itself lock-guarded) is invoked
/// AFTER release, so the two locks never nest.
final class MigrationLiveGateRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private var providers: [AccountUUID: @Sendable () -> Date?] = [:]

    /// Registers (or replaces) `accountUUID`'s live gate view.
    func register(_ accountUUID: AccountUUID, provider: @escaping @Sendable () -> Date?) {
        lock.lock()
        providers[accountUUID] = provider
        lock.unlock()
    }

    /// The live in-flight marker expiry for `accountUUID`, or `nil` when it has none — which
    /// covers both a live gate with no marker set and a dormant account whose actor was never
    /// created this launch (that case is the persisted gate file's alone). The two collapse
    /// safely: neither blocks sync.
    func inFlightUntil(for accountUUID: AccountUUID) -> Date? {
        lock.lock()
        let provider = providers[accountUUID]
        lock.unlock()
        return provider?()
    }
}

/// The wallet-scope analog of ``MigrationSyncGate``'s reactive half: it publishes a `Bool` "sync
/// blocked" stream computed by an injected async `predicate`, on a subscription-gated ticker plus
/// on-demand ``triggerRecompute()`` pulses, with generation-ordered latest-wins emission.
///
/// It deliberately mirrors ``MigrationSyncGate``'s two-lock split rather than improvising a
/// single-lock version: `emissionLock` guards the generation counters and the `send`, `subscriptionLock`
/// guards the subscriber count, ticker task, and the registered per-account broadcast signals. The
/// split exists because Combine can invoke `receiveCancel` synchronously, on the calling thread, while
/// that thread is still inside `publish(_:generation:)`'s `emissionLock` critical section around
/// `send(_:)` (a subscriber cancelling from inside its own value handler). Subscription-side code
/// therefore only ever touches `subscriptionLock`, never `emissionLock`, so that re-entrant call never
/// deadlocks — see ``MigrationSyncGate`` for the full rationale.
private final class HostSyncBlockedPublisher: @unchecked Sendable {
    private let predicate: @Sendable () async -> Bool
    private let tickInterval: TimeInterval
    private let logger: Logger
    private let blockedSubject: CurrentValueSubject<Bool, Never>

    /// Guards the send-generation counters and serializes `blockedSubject.send(_:)`. See
    /// ``MigrationSyncGate``'s `emissionLock` for why `NSLock` here rather than `OSAllocatedUnfairLock`
    /// (the package deployment target predates the latter's availability floor).
    private let emissionLock = NSLock()
    private var nextGeneration: UInt64 = 0
    private var lastPublishedGeneration: UInt64 = 0

    /// Guards the subscriber count, ticker task, and the registered broadcast signals plus their live
    /// subscriptions. Kept strictly separate from `emissionLock`: subscription-side code must never
    /// acquire `emissionLock`, so a synchronous `receiveCancel` reached during `publish`'s `send`
    /// cannot deadlock.
    private let subscriptionLock = NSLock()
    private var subscriberCount = 0
    private var tickerTask: Task<Void, Never>?
    /// Every hosted account's per-account blocked stream, registered via ``watchBroadcastSignal(_:)``.
    private var broadcastSignals: [AnyPublisher<Bool, Never>] = []
    /// The live subscriptions to `broadcastSignals`, held only while this stream itself has a
    /// subscriber (so a hosted account's per-account ticker — finding 14 — does not run when nobody is
    /// watching the wallet-scope stream).
    private var broadcastSignalCancellables: [AnyCancellable] = []

    init(
        initialBlocked: Bool,
        tickInterval: TimeInterval,
        logger: Logger,
        predicate: @escaping @Sendable () async -> Bool
    ) {
        self.predicate = predicate
        self.tickInterval = tickInterval
        self.logger = logger
        self.blockedSubject = CurrentValueSubject(initialBlocked)
    }

    deinit {
        tickerTask?.cancel()
    }

    /// The public stream: seeds the current value on subscribe, gates the ticker and broadcast-signal
    /// subscriptions on having at least one subscriber, and collapses consecutive duplicates.
    var stream: AnyPublisher<Bool, Never> {
        blockedSubject
            .handleEvents(
                receiveSubscription: { [weak self] _ in self?.subscriberAttached() },
                receiveCancel: { [weak self] in self?.subscriberDetached() }
            )
            .removeDuplicates()
            .eraseToAnyPublisher()
    }

    /// Registers a hosted account's per-account blocked stream. While this stream has a subscriber, an
    /// emission on `signal` (in particular the account's own in-flight-marker arm/clear emission)
    /// triggers an immediate wallet-scope re-evaluation.
    func watchBroadcastSignal(_ signal: AnyPublisher<Bool, Never>) {
        subscriptionLock.lock()
        broadcastSignals.append(signal)
        if subscriberCount > 0 {
            broadcastSignalCancellables.append(subscribe(to: signal))
        }
        subscriptionLock.unlock()
    }

    /// Schedules a wallet-scope recompute + publish. Used by broadcast-signal emissions.
    func triggerRecompute() {
        recomputeAsync()
    }

    // MARK: - Subscription lifecycle (subscriptionLock only)

    private func subscriberAttached() {
        subscriptionLock.lock()
        subscriberCount += 1
        if subscriberCount == 1 {
            startTicking()
            broadcastSignalCancellables = broadcastSignals.map { subscribe(to: $0) }
        }
        subscriptionLock.unlock()
    }

    private func subscriberDetached() {
        subscriptionLock.lock()
        subscriberCount -= 1
        if subscriberCount == 0 {
            stopTicking()
            // Cancels each per-account subscription, which stops the corresponding per-account ticker.
            broadcastSignalCancellables.removeAll()
        }
        subscriptionLock.unlock()
    }

    /// Subscribes to a per-account signal; every emission pulses a wallet-scope recompute. Called only
    /// with `subscriptionLock` held — safe because the synchronous seed the subscribe delivers only
    /// spawns a detached recompute `Task` (via `triggerRecompute`), never re-entering this lock.
    private func subscribe(to signal: AnyPublisher<Bool, Never>) -> AnyCancellable {
        signal.sink { [weak self] _ in
            self?.triggerRecompute()
        }
    }

    private func startTicking() {
        tickerTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else {
                    return
                }
                await self.recompute()
                try? await Task.sleep(nanoseconds: UInt64(self.tickInterval * 1_000_000_000))
            }
        }
    }

    private func stopTicking() {
        tickerTask?.cancel()
        tickerTask = nil
    }

    // MARK: - Recompute / publish (emissionLock only)

    private func recomputeAsync() {
        Task { [weak self] in
            await self?.recompute()
        }
    }

    private func recompute() async {
        let generation = drawNextGeneration()
        let blocked = await predicate()
        publish(blocked, generation: generation)
    }

    /// Snapshots this recompute's generation under `emissionLock`, at the moment it starts (before the
    /// `predicate` suspension), so `publish(_:generation:)` can drop a later-published-but-earlier-started
    /// recompute — latest-wins.
    private func drawNextGeneration() -> UInt64 {
        emissionLock.lock()
        defer { emissionLock.unlock() }

        nextGeneration += 1
        return nextGeneration
    }

    /// The single funnel every `send` goes through: under `emissionLock`, drops stale generations and
    /// serializes the send. Holding `emissionLock` across `send(_:)` is safe with respect to
    /// `subscriptionLock` — the only re-entrant call a synchronous subscriber-cancel reaches is
    /// `subscriberDetached()`, which touches `subscriptionLock`, never this lock.
    private func publish(_ blocked: Bool, generation: UInt64) {
        emissionLock.lock()
        defer { emissionLock.unlock() }

        guard generation > lastPublishedGeneration else {
            return
        }
        lastPublishedGeneration = generation
        blockedSubject.send(blocked)
    }
}
