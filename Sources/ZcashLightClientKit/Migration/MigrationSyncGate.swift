//
//  MigrationSyncGate.swift
//  ZcashLightClientKit
//

import Combine
import Foundation

/// The persisted, per-account gate that decides whether ordinary wallet sync must pause for the
/// benefit of an in-flight migration.
///
/// Two independent reasons block sync:
/// 1. **Overdue transfers** — a scheduled transfer is past its send height but not yet broadcast.
///    This is engine-derived (`migrationHasOverdueTransfers`) and passed in as `hasOverdue`.
/// 2. **Privacy buffer** — for a fixed window after each broadcast, sync stays paused so the
///    broadcast is not correlated with a fresh sync. This is the `resumeAt` timestamp persisted here.
///
/// The gate owns only the privacy-buffer half; the overdue half is supplied by the caller (and, for
/// the reactive `blockedStream`, by an injected `overdueProvider`). State is durably persisted to an
/// atomically written JSON file, but every read in this process is served from an in-memory cache
/// (see `cachedResumeAt`) -- the file exists for durability across launches, not as the read path.
/// The other in-memory mutable state is the subscriber-gated ticker task (see `subscriberAttached()`,
/// guarded by `subscriptionLock`) and the send-generation counters (see `publish(_:generation:)`,
/// guarded by `emissionLock`); all of it is guarded by one lock or the other, so a `final class` is
/// `@unchecked Sendable` without needing an actor hop to read the reactive stream. A corrupt or
/// missing file reads as "no buffer".
final class MigrationSyncGate: @unchecked Sendable {
    /// The persisted envelope: a schema version plus the epoch-seconds instant at which the privacy
    /// buffer elapses.
    private struct GateState: Codable {
        let version: Int
        let resumeAtEpochSeconds: Double
    }

    private static let currentVersion = 1

    private let fileURL: URL
    private let bufferDuration: TimeInterval
    private let tickInterval: TimeInterval
    private let now: @Sendable () -> Date
    private let overdueProvider: @Sendable () async -> Bool
    private let logger: Logger
    private let blockedSubject: CurrentValueSubject<Bool, Never>

    /// Guards the send-generation counters (`nextGeneration`, `lastPublishedGeneration`) and the
    /// in-memory `resumeAt` cache (`cachedResumeAt`) -- the funnel that computes and emits values on
    /// `blockedSubject`. `publish(_:generation:)` holds this lock across the actual
    /// `blockedSubject.send(_:)` call (Combine requires sends on a subject to be serialized). Kept
    /// deliberately separate from `subscriptionLock` below -- see that property's doc for why.
    /// `NSLock` rather than `OSAllocatedUnfairLock` (the usual preference for new locking code): this
    /// package's deployment target (`Package.swift`: `.iOS(.v13)` / `.macOS(.v12)`) is below
    /// `OSAllocatedUnfairLock`'s iOS 16 / macOS 13 floor, so this matches the plain-`NSLock`
    /// convention already used elsewhere in this codebase (see `ZcashRustBackend.rustInitLock`).
    private let emissionLock = NSLock()
    /// The generation handed out to the most recently *started* `recompute()`, and the newest
    /// generation `publish(_:generation:)` has actually sent. Both guarded by `emissionLock`.
    private var nextGeneration: UInt64 = 0
    private var lastPublishedGeneration: UInt64 = 0

    /// The in-memory cache of the persisted privacy-buffer expiry, guarded by `emissionLock`. Loaded
    /// once from the gate file at init; `markBroadcast()` is the only writer thereafter (updates this
    /// cache first, then persists to the file for durability only -- see `markBroadcast()`). Every
    /// read in this process (`currentResumeAt()`, hence `currentlyBlocked(hasOverdue:)` and
    /// `recompute()`) serves this cache rather than re-reading the file.
    ///
    /// A plain lock-guarded value suffices here, unlike `publish(_:generation:)`'s generation
    /// ordering: `markBroadcast()` is this gate's only writer, under the standing single-writer
    /// assumption that there is one `MigrationSyncGate` instance per account per process, so there is
    /// never a fresher write for a slower one to clobber.
    private var cachedResumeAt: Date?

    /// Guards the subscriber count and the ticker task's start/stop state -- the bookkeeping for
    /// `blockedStream`'s subscription lifecycle. Deliberately a SEPARATE lock from `emissionLock`:
    /// Combine can invoke `receiveCancel` (-> `subscriberDetached()`) *synchronously, on the calling
    /// thread*, when a subscriber cancels from inside its own value-handling closure -- including a
    /// value just delivered by `publish(_:generation:)`, i.e. while that thread is still inside
    /// `publish`'s `emissionLock` critical section around `blockedSubject.send(_:)`. If subscription
    /// bookkeeping shared `emissionLock`, that re-entrant `lock()` would deadlock against itself
    /// (`NSLock` is non-recursive) and wedge the gate permanently -- every later
    /// `currentResumeAt()` / `currentlyBlocked()` / `markBroadcast()` / subscribe would then hang too,
    /// since the thread that deadlocked never releases the lock it holds.
    ///
    /// The ordering rule this buys is one-way, not "never both": `subscriberAttached()`,
    /// `subscriberDetached()`, `startTicking()`, and `stopTicking()` touch only `subscriptionLock`
    /// and must never acquire `emissionLock` -- that is the invariant that actually prevents the
    /// deadlock described above. The reverse nesting is deliberate and safe: `publish(_:generation:)`
    /// legitimately holds `emissionLock` across `blockedSubject.send(_:)`, and that send can
    /// synchronously re-enter this instance via a subscriber's synchronous cancel
    /// (-> `subscriberDetached()`, which acquires `subscriptionLock`) -- so `emissionLock` ->
    /// `subscriptionLock` is a real, one-way nesting this type relies on. What must never happen is
    /// the reverse acquisition order; keep it that way rather than letting subscription-side code
    /// reach back into `emissionLock`. See `publish(_:generation:)`'s doc for the different,
    /// currently-unreachable re-entrancy hazard this same nesting creates for `emissionLock` itself.
    private let subscriptionLock = NSLock()
    /// Live subscriber count of `blockedStream`, guarded by `subscriptionLock`. The ticker task runs
    /// only while this is > 0: `subscriberAttached()` starts it on the 0 -> 1 transition,
    /// `subscriberDetached()` cancels it on the 1 -> 0 transition. With zero subscribers the gate
    /// does zero periodic FFI/sqlite work (finding 14).
    private var subscriberCount = 0
    /// The ticker task itself, guarded by `subscriptionLock` alongside `subscriberCount` -- see
    /// `startTicking()` / `stopTicking()`.
    private var tickerTask: Task<Void, Never>?

    /// Creates a gate rooted at `directory`, scoped to `accountUUID` by file name.
    ///
    /// - Parameters:
    ///   - directory: the general-storage directory the gate file lives in; provisioned via
    ///     ``BackupExcludedStorage`` (created if missing, and excluded from backup either way --
    ///     schedule timing must never leave the device via an iCloud/iTunes backup).
    ///   - accountUUID: the account this gate governs; encoded into the file name.
    ///   - bufferDuration: how long the privacy buffer keeps sync blocked after each broadcast.
    ///   - tickInterval: how often the reactive stream re-evaluates (time passing alone can flip the
    ///     answer even with no data change). Injectable for tests.
    ///   - now: the clock. Injectable for tests.
    ///   - overdueProvider: supplies the engine's "has overdue transfers" answer for the reactive
    ///     stream; must degrade to `false` (never throw) on failure.
    ///   - logger: sink for the single warning emitted on a corrupt read or a failed write.
    init(
        directory: URL,
        accountUUID: AccountUUID,
        bufferDuration: TimeInterval,
        tickInterval: TimeInterval = 15,
        now: @escaping @Sendable () -> Date = { Date() },
        overdueProvider: @escaping @Sendable () async -> Bool,
        logger: Logger
    ) {
        let url = directory.appendingPathComponent(Self.fileName(accountUUID: accountUUID))
        self.fileURL = url
        self.bufferDuration = bufferDuration
        self.tickInterval = tickInterval
        self.now = now
        self.overdueProvider = overdueProvider
        self.logger = logger

        do {
            try BackupExcludedStorage.provision(directory: directory)
        } catch {
            logger.warn("MigrationSyncGate: failed to provision the storage directory (backup exclusion may be missing): \(error)")
        }

        // Load the in-memory `resumeAt` cache from the file exactly once, here -- every subsequent
        // read in this process serves this cache (see `cachedResumeAt`), never the file again, until
        // `markBroadcast()` updates it. Also seeds the synchronous subscribe-time value (buffer only
        // -- see `blockedStream`'s documented caveat: the first tick refines it with the real overdue
        // signal) so subscribers get an immediate value.
        let initialResumeAt = Self.readResumeAt(fileURL: url, logger: logger)
        self.cachedResumeAt = initialResumeAt
        let initialBlocked = Self.isBlocked(now: now(), hasOverdue: false, resumeAt: initialResumeAt)
        self.blockedSubject = CurrentValueSubject(initialBlocked)
        self.tickerTask = nil

        // No `startTicking()` here: the ticker is subscription-gated (finding 14) -- it starts on the
        // first `blockedStream` subscriber (`subscriberAttached()`), not at construction.
    }

    deinit {
        tickerTask?.cancel()
    }

    /// The account-scoped gate file name, e.g. `migration_sync_gate_<account-uuid-hex>.json`.
    static func fileName(accountUUID: AccountUUID) -> String {
        "migration_sync_gate_\(Data(accountUUID.id).hexEncodedString()).json"
    }

    /// The persisted privacy-buffer expiry for `accountUUID`, read directly from its gate file under
    /// `directory`, without constructing a gate instance. A corrupt or missing file reads as `nil`
    /// ("no buffer"), exactly like an instance's init-time load.
    ///
    /// The wallet-scope path a host uses to answer "is any account still inside its privacy buffer?"
    /// after a fresh launch, when the per-account gate for a dormant account has not been (and must
    /// not need to be) constructed. Reuses the same envelope-read path (`readResumeAt`) as the
    /// instance's own init so the on-disk format has a single reader.
    static func persistedResumeAt(directory: URL, accountUUID: AccountUUID, logger: Logger) -> Date? {
        let fileURL = directory.appendingPathComponent(fileName(accountUUID: accountUUID))
        return readResumeAt(fileURL: fileURL, logger: logger)
    }

    /// The gate's core predicate: sync is blocked when a transfer is overdue, or while the privacy
    /// buffer has not yet elapsed. Pure, so it is exhaustively table-testable.
    static func isBlocked(now: Date, hasOverdue: Bool, resumeAt: Date?) -> Bool {
        if hasOverdue {
            return true
        }
        guard let resumeAt else {
            return false
        }
        return now < resumeAt
    }

    /// Starts (or restarts) the privacy buffer: updates the in-memory `resumeAt` cache immediately,
    /// persists `resumeAt = now + bufferDuration` to the gate file for durability, and pushes a fresh
    /// value to the reactive stream. Call after every successful migration broadcast.
    func markBroadcast() {
        let resumeAt = now().addingTimeInterval(bufferDuration)

        emissionLock.lock()
        cachedResumeAt = resumeAt
        emissionLock.unlock()

        write(resumeAt: resumeAt)
        recomputeAsync()
    }

    /// The in-memory cached privacy-buffer expiry (see `cachedResumeAt`), or `nil` when no buffer is
    /// active. Reflects the gate file's contents as of the last init or `markBroadcast()` in THIS
    /// process, not a fresh file read.
    func currentResumeAt() -> Date? {
        emissionLock.lock()
        defer { emissionLock.unlock() }
        return cachedResumeAt
    }

    /// Whether sync is currently blocked, combining the supplied `hasOverdue` with the persisted
    /// privacy buffer. Never throws.
    func currentlyBlocked(hasOverdue: Bool) -> Bool {
        Self.isBlocked(now: now(), hasOverdue: hasOverdue, resumeAt: currentResumeAt())
    }

    /// A stream of the blocked flag: emits the current value on subscribe, re-evaluates every
    /// `tickInterval` and after every ``markBroadcast()``, and collapses consecutive duplicates.
    /// Internally synchronized: the ticker loop and every `markBroadcast()`-triggered recompute can
    /// be in flight concurrently (both suspend awaiting the injected `overdueProvider`), but every
    /// send is serialized and generation-ordered -- latest-wins, so a recompute that started earlier
    /// but finishes later after a fresher one already published is dropped rather than emitted as a
    /// stale overwrite. See `publish(_:generation:)`.
    ///
    /// - Important: The synchronous subscribe-time seed reflects only the persisted privacy buffer
    ///   (see the `hasOverdue: false` seed in `init`) -- overdue-transfer detection arrives with the
    ///   first asynchronous recompute. On relaunch with an overdue transfer and no active buffer, the
    ///   first emission can therefore briefly read `false` while a fresh `isBlocked`/`currentlyBlocked`
    ///   call (which always consults the overdue answer) already reads `true`.
    /// - Important: Subscription-gated (finding 14): the periodic ticker only runs while at least one
    ///   subscriber is attached (`subscriberAttached()`/`subscriberDetached()`, via `handleEvents`
    ///   below), so a `blockedStream` with no subscribers costs nothing beyond the seed already
    ///   computed at init. `markBroadcast()`-triggered recomputes are unaffected by subscriber count.
    var blockedStream: AnyPublisher<Bool, Never> {
        blockedSubject
            .handleEvents(
                receiveSubscription: { [weak self] _ in self?.subscriberAttached() },
                receiveCancel: { [weak self] in self?.subscriberDetached() }
            )
            .removeDuplicates()
            .eraseToAnyPublisher()
    }

    // MARK: - Private

    /// Called (via `handleEvents`) whenever a new `blockedStream` subscription is established. On the
    /// 0 -> 1 transition, starts the ticker task -- see `subscriberCount`.
    private func subscriberAttached() {
        subscriptionLock.lock()
        subscriberCount += 1
        if subscriberCount == 1 {
            startTicking()
        }
        subscriptionLock.unlock()
    }

    /// Called (via `handleEvents`) whenever a `blockedStream` subscription is cancelled. On the
    /// 1 -> 0 transition, cancels the ticker task -- see `subscriberCount`.
    private func subscriberDetached() {
        subscriptionLock.lock()
        subscriberCount -= 1
        if subscriberCount == 0 {
            stopTicking()
        }
        subscriptionLock.unlock()
    }

    /// Starts the ticker task. Only called with `subscriptionLock` held, on the 0 -> 1 subscriber
    /// transition (`subscriberAttached()`) -- creating the `Task` here is a cheap, non-suspending
    /// call, so doing it under the lock is safe. No risk of deadlock either way: the task's own body
    /// (`recompute()`) only ever acquires `emissionLock`, never `subscriptionLock`.
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

    /// Stops the ticker task. Only called with `subscriptionLock` held, on the 1 -> 0 subscriber
    /// transition (`subscriberDetached()`).
    private func stopTicking() {
        tickerTask?.cancel()
        tickerTask = nil
    }

    private func recomputeAsync() {
        Task { [weak self] in
            await self?.recompute()
        }
    }

    private func recompute() async {
        let generation = drawNextGeneration()

        let hasOverdue = await overdueProvider()
        let blocked = Self.isBlocked(now: now(), hasOverdue: hasOverdue, resumeAt: currentResumeAt())
        publish(blocked, generation: generation)
    }

    /// Snapshots this recompute's generation, under `emissionLock`, at the moment it *starts* --
    /// before the `overdueProvider` suspension point -- so `publish(_:generation:)` can later tell
    /// whether a later-started recompute has already published.
    private func drawNextGeneration() -> UInt64 {
        emissionLock.lock()
        defer { emissionLock.unlock() }

        nextGeneration += 1
        return nextGeneration
    }

    /// The single funnel every `blockedSubject.send` goes through. Atomically (under `emissionLock`)
    /// checks freshness and sends: `generation` was snapshotted when the calling `recompute()`
    /// started, so if a *later*-started recompute has already published (`lastPublishedGeneration` is
    /// newer), this send is stale and is silently dropped instead of overwriting the fresher value.
    /// Serializing the actual `.send()` call here also satisfies Combine's requirement that sends on
    /// a subject not race.
    ///
    /// Holding `emissionLock` across `send(_:)` is safe with respect to `subscriptionLock` even
    /// though `send(_:)` can synchronously re-enter this instance (a subscriber cancelling from
    /// inside its own value handler, see `subscriptionLock`'s doc): the only re-entrant call that path
    /// reaches is `subscriberDetached()`, which acquires `subscriptionLock`, never this lock.
    ///
    /// - Warning: That safety is specific to the cancel path. A subscriber's synchronous
    ///   value-handling callback must never call back into `currentResumeAt()`,
    ///   `currentlyBlocked(hasOverdue:)`, or `markBroadcast()` from inside its handler for this
    ///   emission: all three acquire `emissionLock`, which -- unlike `subscriptionLock` -- this
    ///   thread is already holding right here, and `NSLock` is non-recursive, so a same-thread
    ///   re-acquisition would deadlock. No shipped subscriber does this today (only cancellation
    ///   reaches back in, and only into `subscriptionLock`), so the hazard is currently unreachable,
    ///   not exercised.
    private func publish(_ blocked: Bool, generation: UInt64) {
        emissionLock.lock()
        defer { emissionLock.unlock() }

        guard generation > lastPublishedGeneration else {
            return
        }
        lastPublishedGeneration = generation
        blockedSubject.send(blocked)
    }

    private func write(resumeAt: Date) {
        do {
            let state = GateState(version: Self.currentVersion, resumeAtEpochSeconds: resumeAt.timeIntervalSince1970)
            let data = try JSONEncoder().encode(state)
            try data.write(to: fileURL, options: .atomic)
        } catch {
            logger.warn("MigrationSyncGate: failed to persist sync-gate state: \(error)")
        }
    }

    private static func readResumeAt(fileURL: URL, logger: Logger) -> Date? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return nil
        }

        do {
            let data = try Data(contentsOf: fileURL)
            let state = try JSONDecoder().decode(GateState.self, from: data)
            guard state.version == Self.currentVersion else {
                logger.warn("MigrationSyncGate: ignoring sync-gate file with unknown version \(state.version)")
                return nil
            }
            return Date(timeIntervalSince1970: state.resumeAtEpochSeconds)
        } catch {
            logger.warn("MigrationSyncGate: ignoring corrupt sync-gate file: \(error)")
            return nil
        }
    }
}
