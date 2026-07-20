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
/// (`Initializer.rustBackend`) only for the wallet-scope predicate — enumerating every account and
/// reading each account's persisted gate file directly, so a dormant account (one whose actor has
/// never been created this launch) still counts.
actor OrchardMigrationHost {
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

    /// The lazily-created, cached per-account actors. Actor isolation is the synchronization: a given
    /// account resolves to the same instance for the host's lifetime.
    private var migrations: [AccountUUID: OrchardMigration] = [:]

    /// Production initializer: derives everything from the synchronizer's ``Initializer``.
    ///
    /// The shared ``MigrationBroadcaster`` is built here, once, from the initializer's Tor directory
    /// and logger. Per-account configs reuse the initializer's paths, network, and logger
    /// (`loggingPolicy: .custom(initializer.logger)`); the wallet-scope predicate borrows the
    /// initializer's `rustBackend` welding.
    init(initializer: Initializer) {
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

        let predicate: @Sendable () async -> Bool = {
            await OrchardMigrationHost.computeSyncBlocked(
                welding: welding,
                generalStorageURL: generalStorageURL,
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

    /// The post-broadcast privacy buffer duration, forwarding ``OrchardMigration/privacySyncBufferDuration``.
    nonisolated var privacySyncBufferDuration: TimeInterval {
        OrchardMigration.privacySyncBufferDuration
    }

    /// The ``OrchardMigration`` bound to `accountUUID`, lazily created and cached on first request.
    ///
    /// The same account resolves to the same instance thereafter; distinct accounts get distinct
    /// actors, each sharing the host's single ``MigrationBroadcaster``. A newly created actor's
    /// per-account blocked stream is registered with ``syncBlockedStream`` so a broadcast on it
    /// re-evaluates the wallet-scope value immediately.
    func migration(for accountUUID: AccountUUID) -> OrchardMigration {
        if let existing = migrations[accountUUID] {
            return existing
        }

        let migration = actorFactory(accountUUID, sharedBroadcaster)
        migrations[accountUUID] = migration
        blockedPublisher.watchBroadcastSignal(migration.syncBlockedStream)
        return migration
    }

    /// Whether ordinary wallet sync should currently be paused for *any* migrating account.
    ///
    /// Enumerates every wallet account via the welding (not the lazy actor cache, so a dormant
    /// account with a persisted gate file or overdue transfers still counts after a fresh launch)
    /// and blocks if any account is overdue or still inside its privacy buffer. Non-throwing: an
    /// account enumeration failure logs and degrades to "unblocked" (sync allowed), and a per-account
    /// overdue-query failure contributes "not overdue" — matching ``OrchardMigration/isSyncBlocked()``.
    func isSyncBlocked() async -> Bool {
        await Self.computeSyncBlocked(
            welding: welding,
            generalStorageURL: generalStorageURL,
            now: now,
            logger: logger
        )
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
    ///   synchronously — unlike ``MigrationSyncGate/blockedStream``'s per-account buffer seed). It is
    ///   corrected by the first asynchronous re-evaluation (the ticker's immediate startup recompute,
    ///   or sooner if a broadcast happens first). A subscriber that must be correct from its very
    ///   first value should pair this stream with an initial ``isSyncBlocked()`` call.
    nonisolated var syncBlockedStream: AnyPublisher<Bool, Never> {
        blockedPublisher.stream
    }

    // MARK: - Private

    /// The wallet-scope blocked predicate, factored out so both ``isSyncBlocked()`` and
    /// ``syncBlockedStream``'s recompute share one implementation and neither consults the lazy actor
    /// cache. Non-throwing; degrades open (to "unblocked") on any enumeration/db error.
    private static func computeSyncBlocked(
        welding: ZcashRustBackendWelding,
        generalStorageURL: URL,
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
        for account in accounts {
            // Degrade to "not overdue" on any engine error, exactly like OrchardMigration.isSyncBlocked().
            let hasOverdue = (try? await welding.migrationHasOverdueTransfers(for: account.id)) ?? false
            let resumeAt = MigrationSyncGate.persistedResumeAt(
                directory: generalStorageURL,
                accountUUID: account.id,
                logger: logger
            )
            if MigrationSyncGate.isBlocked(now: evaluatedAt, hasOverdue: hasOverdue, resumeAt: resumeAt) {
                return true
            }
        }
        return false
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
    /// emission on `signal` (in particular the account's own `markBroadcast()`-triggered emission)
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
