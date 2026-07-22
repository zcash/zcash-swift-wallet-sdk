//
//  MigrationLogicTests.swift
//  ZcashLightClientKitTests
//

import Combine
import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

/// Pure-logic tests for the app-facing migration layer: sync-gate math and file round-trip,
/// endpoint resolution, broadcast-result mapping, and the reschedule accessor's delegation to the
/// migration welding. No network, no dataDb — every collaborator here is exercised in isolation.
final class MigrationLogicTests: ZcashTestCase {
    private let accountA = AccountUUID(id: [UInt8](repeating: 0x11, count: 16))
    private let referenceDate = Date(timeIntervalSince1970: 1_700_000_000)
    private let buffer: TimeInterval = 600
    private static let uaString = """
    u1l9f0l4348negsncgr9pxd9d3qaxagmqv3lnexcplmufpq7muffvfaue6ksevfvd7wrz7xrvn95rc5zjtn7ugkmgh5rnxswmcj30y0pw52pn0zjvy38rn2esfgve64rj5pcmazxgpyuj
    """

    // MARK: - Gate math

    func testGateBlockedImmediatelyAfterMark() {
        // The +600 s buffer starts at `now`, so `now` itself is inside the blocked window.
        let resumeAt = referenceDate.addingTimeInterval(buffer)
        XCTAssertTrue(MigrationSyncGate.isBlocked(now: referenceDate, hasOverdue: false, resumeAt: resumeAt))
    }

    func testGateUnblocksAtExactlyBufferBoundary() {
        // At exactly `resumeAt` the buffer has elapsed: `now < resumeAt` is false.
        let resumeAt = referenceDate.addingTimeInterval(buffer)
        XCTAssertFalse(MigrationSyncGate.isBlocked(now: resumeAt, hasOverdue: false, resumeAt: resumeAt))
    }

    func testGateOverdueForcesBlockedEvenAfterBufferElapsed() {
        let resumeAt = referenceDate.addingTimeInterval(buffer)
        let afterBuffer = resumeAt.addingTimeInterval(1)
        XCTAssertTrue(MigrationSyncGate.isBlocked(now: afterBuffer, hasOverdue: true, resumeAt: resumeAt))
    }

    func testGateOverdueForcesBlockedWithoutAnyBuffer() {
        XCTAssertTrue(MigrationSyncGate.isBlocked(now: referenceDate, hasOverdue: true, resumeAt: nil))
    }

    func testGateCorruptOrMissingFileUnblockedWhenNoOverdue() {
        // Corrupt/missing file resolves to `resumeAt == nil`, which is "no gate".
        XCTAssertFalse(MigrationSyncGate.isBlocked(now: referenceDate, hasOverdue: false, resumeAt: nil))
    }

    // MARK: - Gate file round-trip

    func testGateFileRoundTripPersistsResumeAt() {
        let clock = TestClock(referenceDate)
        let gate = makeGate(account: accountA, clock: clock)

        gate.markBroadcast()

        XCTAssertEqual(gate.currentResumeAt(), referenceDate.addingTimeInterval(buffer))
        XCTAssertTrue(gate.currentlyBlocked(hasOverdue: false))
    }

    func testGateUnblocksOnceRealTimePassesTheBuffer() {
        let clock = TestClock(referenceDate)
        let gate = makeGate(account: accountA, clock: clock)

        gate.markBroadcast()
        // Advance the injected clock past the buffer; the persisted resumeAt is unchanged.
        clock.now = referenceDate.addingTimeInterval(buffer + 1)

        XCTAssertFalse(gate.currentlyBlocked(hasOverdue: false))
        XCTAssertTrue(gate.currentlyBlocked(hasOverdue: true))
    }

    func testCorruptFileAtInitReadsAsNoGate() throws {
        // Written BEFORE construction: finding 14's in-memory `resumeAt` cache is loaded from the
        // file exactly once, at init, so this is the only point at which corrupt content is parsed.
        let fileURL = testGeneralStorageDirectory.appendingPathComponent(MigrationSyncGate.fileName(accountUUID: accountA))
        try Data("not json at all".utf8).write(to: fileURL)

        let gate = makeGate(account: accountA, clock: TestClock(referenceDate))

        XCTAssertNil(gate.currentResumeAt())
        XCTAssertFalse(gate.currentlyBlocked(hasOverdue: false))
    }

    /// Finding 14: `currentResumeAt()`/`currentlyBlocked` read the in-memory `resumeAt` cache, not a
    /// fresh file read every call -- a write to the gate file from something other than this gate
    /// instance must not change what THIS instance reports until its OWN `markBroadcast()` updates
    /// the cache. Stands the violation up with a second `MigrationSyncGate` over the SAME file
    /// (deliberately breaking the documented single-writer assumption) so the write is genuinely
    /// out-of-band and genuinely observable if reads went to disk: a "read fresh every call"
    /// implementation would pick it up, a cached one will not. Was
    /// `testGateCorruptFileReadsAsNoGate` pre-finding-14, when every read re-parsed the file fresh;
    /// the corrupt-JSON coverage that test used to provide now lives in
    /// `testCorruptFileAtInitReadsAsNoGate` above (corrupt content is only ever parsed at init).
    func testCurrentResumeAtIgnoresAnOutOfBandFileChangeAfterInit() throws {
        let gate = makeGate(account: accountA, clock: TestClock(referenceDate))
        XCTAssertNil(gate.currentResumeAt(), "precondition: no buffer yet")

        // A second gate instance over the same account/directory (hence the same file) marks a fresh
        // broadcast -- a valid, non-nil resumeAt written out-of-band from the first gate's viewpoint.
        let otherProcessGate = makeGate(account: accountA, clock: TestClock(referenceDate))
        otherProcessGate.markBroadcast()

        XCTAssertNil(gate.currentResumeAt(), "an out-of-band file write after init must not change the cached answer")
        XCTAssertFalse(gate.currentlyBlocked(hasOverdue: false))
    }

    /// Finding 14: the in-memory `resumeAt` cache is loaded from the gate file once, at init -- a
    /// value persisted by an earlier gate instance (standing in for a previous process launch) must
    /// be honored by a fresh instance over the same file, before that fresh instance's own
    /// `markBroadcast()` ever runs.
    func testMemoryCacheHonorsAPreExistingFileValueAtInit() throws {
        let clock = TestClock(referenceDate)
        let firstLaunchGate = makeGate(account: accountA, clock: clock)
        firstLaunchGate.markBroadcast()
        let persistedResumeAt = try XCTUnwrap(firstLaunchGate.currentResumeAt())

        let secondLaunchGate = makeGate(account: accountA, clock: clock)

        XCTAssertEqual(secondLaunchGate.currentResumeAt(), persistedResumeAt)
        XCTAssertTrue(secondLaunchGate.currentlyBlocked(hasOverdue: false))
    }

    // MARK: - Storage provisioning (backup exclusion)

    /// Finding 15: the gate's storage directory must be excluded from backup, mirroring
    /// `SubmitPlanStore.connection()`'s handling of the same general-storage directory (schedule
    /// timing/heights must never leave the device via an iCloud/iTunes backup). The directory is
    /// created fresh (but NOT yet excluded) by `ZcashTestCase.setUp()`, so this also exercises the
    /// "directory already exists" re-provisioning path, not just first creation.
    func testGateInitExcludesItsStorageDirectoryFromBackup() throws {
        let resourceValuesBefore = try testGeneralStorageDirectory.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertNotEqual(resourceValuesBefore.isExcludedFromBackup, true, "precondition: not yet excluded")

        _ = makeGate(account: accountA, clock: TestClock(referenceDate))

        let resourceValuesAfter = try testGeneralStorageDirectory.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(resourceValuesAfter.isExcludedFromBackup, true)
    }

    // MARK: - Ticker gated on subscribers

    /// Finding 14: the ticker must do zero periodic work with no subscriber attached, start
    /// evaluating on the first subscriber (0 -> 1), and stop again once the last one detaches (1 -> 0)
    /// -- the `overdueProvider` invocation count freezes rather than merely slowing down. A very
    /// short `tickInterval` keeps the "prove nothing fires" waits fast; unlike `now`, the ticker's
    /// inter-tick delay is real wall-clock sleep, not injected, so those two waits are real-time
    /// (mirrors the inverted-expectation style already used by
    /// `testStaleRecomputeIsDroppedInFavorOfAFresherPublishedValue` above).
    func testTickerTicksOnlyWhileSubscribed() async throws {
        let counter = CallCountingOverdueProvider()
        let tickedAtLeastTwice = expectation(description: "ticker evaluates at least twice while subscribed")
        let gate = MigrationSyncGate(
            directory: testGeneralStorageDirectory,
            accountUUID: accountA,
            bufferDuration: buffer,
            tickInterval: 0.02,
            overdueProvider: {
                let count = await counter.increment()
                if count == 2 { tickedAtLeastTwice.fulfill() }
                return false
            },
            logger: logger
        )

        // No subscriber yet: several tick intervals' worth of real time must produce zero calls.
        try await Task.sleep(nanoseconds: 200_000_000)
        let countBeforeSubscribing = await counter.count
        XCTAssertEqual(countBeforeSubscribing, 0, "the ticker must not run with no subscriber attached")

        // Attaching a subscriber starts evaluation.
        let cancellable = gate.blockedStream.sink { _ in }
        await fulfillment(of: [tickedAtLeastTwice], timeout: 2)

        // Detaching stops it: the invocation count must stop growing across a further quiet period.
        cancellable.cancel()
        // A tick may already be in flight at the moment of cancellation; let it settle before
        // snapshotting the count both sides of the quiet period.
        try await Task.sleep(nanoseconds: 50_000_000)
        let countAfterCancel = await counter.count
        try await Task.sleep(nanoseconds: 200_000_000)
        let countAfterQuietPeriod = await counter.count
        XCTAssertEqual(countAfterQuietPeriod, countAfterCancel, "the ticker must stop once the last subscriber detaches")
    }

    // MARK: - Blocked stream behavior (finding 13)

    /// Subscribe-time value, "unblocked" half: a fresh gate -- no gate file yet -- seeds `false` on
    /// the very first (synchronous, subscribe-time) emission. Complements
    /// `testBlockedStreamSubscribeTimeSeedIsTrueWhenAlreadyLiveInTheGateFileAtInit` below (the "blocked"
    /// half of the same behavior). Synchronous (not `async`): the assertion runs before the ticker
    /// (started by this very subscription) gets a chance to schedule its first recompute, so there is
    /// no race with the seed being the only value observed.
    func testBlockedStreamSubscribeTimeSeedIsFalseForAFreshGateWithNoBuffer() {
        let gate = makeGate(account: accountA, clock: TestClock(referenceDate))

        var received: [Bool] = []
        let cancellable = gate.blockedStream.sink { received.append($0) }
        defer { cancellable.cancel() }

        XCTAssertEqual(received, [false])
    }

    /// Subscribe-time value, "blocked" half: when the gate file already carries a live privacy buffer
    /// at init -- a second gate instance over a file a prior instance already wrote via
    /// `markBroadcast()`, standing in for a relaunch mid-buffer -- the very first (synchronous)
    /// emission is `true`, without waiting for any tick. Exercises `MigrationSyncGate`'s documented
    /// init-time seed (loads `cachedResumeAt` from the file once, then seeds `blockedSubject` from it)
    /// through the public `blockedStream`, complementing `testMemoryCacheHonorsAPreExistingFileValueAtInit`
    /// above (which checks the same init-time load via `currentResumeAt()`/`currentlyBlocked(hasOverdue:)`
    /// rather than the stream).
    func testBlockedStreamSubscribeTimeSeedIsTrueWhenAlreadyLiveInTheGateFileAtInit() {
        let clock = TestClock(referenceDate)
        let firstLaunchGate = makeGate(account: accountA, clock: clock)
        firstLaunchGate.markBroadcast()

        let secondLaunchGate = makeGate(account: accountA, clock: clock)
        var received: [Bool] = []
        let cancellable = secondLaunchGate.blockedStream.sink { received.append($0) }
        defer { cancellable.cancel() }

        XCTAssertEqual(received, [true])
    }

    /// Emission after `markBroadcast()`: a subscriber already attached before a broadcast must
    /// receive the fresh `true` value promptly, without waiting for the periodic ticker -- pinned by
    /// using a `tickInterval` far longer than the test's timeout, so only `markBroadcast()`'s own
    /// `recomputeAsync()` call (never a coincidental tick) can possibly deliver it.
    ///
    /// Canary (R3-D report): commenting out `recomputeAsync()` inside `markBroadcast()` makes this
    /// test time out and fail red, since with that line gone nothing would ever publish a fresh value
    /// before the next tick 3600 s away.
    func testBlockedStreamEmitsTrueAfterMarkBroadcastWithoutWaitingForATick() async throws {
        let clock = TestClock(referenceDate)
        let gate = MigrationSyncGate(
            directory: testGeneralStorageDirectory,
            accountUUID: accountA,
            bufferDuration: buffer,
            // Long enough that no real tick can plausibly fire during this test's timeout below.
            tickInterval: 3600,
            now: { clock.now },
            overdueProvider: { false },
            logger: logger
        )

        var received: [Bool] = []
        let trueReceivedWithNoTick = expectation(description: "true received promptly after markBroadcast, with no tick possible")
        let cancellable = gate.blockedStream.sink { value in
            received.append(value)
            if value { trueReceivedWithNoTick.fulfill() }
        }
        defer { cancellable.cancel() }
        XCTAssertEqual(received, [false], "precondition: fresh gate seeds false")

        gate.markBroadcast()

        await fulfillment(of: [trueReceivedWithNoTick], timeout: 5)
        XCTAssertEqual(received, [false, true])
    }

    /// Tick re-evaluation, "overdue flips on" half: the ticker's OWN periodic re-evaluation -- not a
    /// `markBroadcast()` -- must pick up an `overdueProvider` answer that flips from `false` to `true`
    /// between ticks. `GatedOverdueProvider` (already used by
    /// `testStaleRecomputeIsDroppedInFavorOfAFresherPublishedValue` above) pre-queues both ticks'
    /// answers so each `next()` call resolves immediately -- no suspension, no `Task.sleep` in this
    /// test -- while the real (short) `tickInterval` is what actually paces the two ticks.
    func testBlockedStreamTickEmitsTrueAfterOverdueProviderFlipsFromFalseToTrue() async throws {
        let provider = GatedOverdueProvider()
        await provider.queue(false) // generation 1 (the ticker's startup recompute): agrees with the seed
        await provider.queue(true) // generation 2 (the next tick): the flip
        let fixedNow = referenceDate
        let gate = MigrationSyncGate(
            directory: testGeneralStorageDirectory,
            accountUUID: accountA,
            bufferDuration: buffer,
            tickInterval: 0.02,
            now: { fixedNow },
            overdueProvider: { await provider.next() },
            logger: logger
        )

        var received: [Bool] = []
        let trueReceived = expectation(description: "a tick observed the overdueProvider flip to true")
        let cancellable = gate.blockedStream.sink { value in
            received.append(value)
            if value { trueReceived.fulfill() }
        }
        defer { cancellable.cancel() }

        await fulfillment(of: [trueReceived], timeout: 5)
        XCTAssertEqual(received, [false, true])
    }

    /// Tick re-evaluation, "buffer expires" half: with a live buffer already seeded at subscribe time
    /// (so the gate reads `true`) and nothing ever overdue, advancing the INJECTED clock past the
    /// persisted `resumeAt` must have the next tick re-evaluate to `false`. Uses a fresh gate over a
    /// file a prior instance already wrote via `markBroadcast()` (rather than calling
    /// `markBroadcast()` on the gate under test) precisely so the `true` -> `false` transition
    /// observed here is unambiguously a TICK's doing, not another `markBroadcast()`-triggered
    /// recompute -- that path is `testBlockedStreamEmitsTrueAfterMarkBroadcastWithoutWaitingForATick`
    /// above.
    func testBlockedStreamTickEmitsFalseOnceTheInjectedClockPassesBufferExpiry() async throws {
        let clock = TestClock(referenceDate)
        let firstLaunchGate = makeGate(account: accountA, clock: clock)
        firstLaunchGate.markBroadcast()

        let gate = MigrationSyncGate(
            directory: testGeneralStorageDirectory,
            accountUUID: accountA,
            bufferDuration: buffer,
            tickInterval: 0.02,
            now: { clock.now },
            overdueProvider: { false },
            logger: logger
        )

        var received: [Bool] = []
        let falseAfterExpiry = expectation(description: "a tick re-evaluates false once the buffer has expired")
        let cancellable = gate.blockedStream.sink { value in
            received.append(value)
            if value == false { falseAfterExpiry.fulfill() }
        }
        defer { cancellable.cancel() }
        XCTAssertEqual(received, [true], "precondition: the live buffer seeds true at subscribe time")

        // Advance the injected clock past the persisted resumeAt; nothing is overdue, so the next
        // tick must re-evaluate to false.
        clock.now = referenceDate.addingTimeInterval(buffer + 1)

        await fulfillment(of: [falseAfterExpiry], timeout: 5)
        XCTAssertEqual(received, [true, false])
    }

    /// Duplicate collapse: several ticks that all agree with the already-published value must not
    /// produce any additional emissions -- pins `.removeDuplicates()` in `blockedStream`'s pipeline.
    /// Reuses `CallCountingOverdueProvider` (already used by `testTickerTicksOnlyWhileSubscribed`
    /// above) to prove multiple recomputes actually ran, rather than merely that nothing arrived
    /// because nothing ticked.
    func testBlockedStreamCollapsesConsecutiveIdenticalTickEvaluationsIntoNoExtraEmissions() async throws {
        let counter = CallCountingOverdueProvider()
        let tickedAtLeastThreeTimes = expectation(description: "the ticker evaluates at least three times")
        let fixedNow = referenceDate
        let gate = MigrationSyncGate(
            directory: testGeneralStorageDirectory,
            accountUUID: accountA,
            bufferDuration: buffer,
            tickInterval: 0.02,
            now: { fixedNow },
            overdueProvider: {
                let count = await counter.increment()
                if count == 3 { tickedAtLeastThreeTimes.fulfill() }
                // No buffer, never overdue: every tick agrees with the fresh-gate seed.
                return false
            },
            logger: logger
        )

        var received: [Bool] = []
        let cancellable = gate.blockedStream.sink { received.append($0) }
        defer { cancellable.cancel() }
        XCTAssertEqual(received, [false], "precondition: fresh gate seeds false")

        await fulfillment(of: [tickedAtLeastThreeTimes], timeout: 5)

        XCTAssertEqual(received, [false], "three ticks agreeing with the seed must not add any emissions")
    }

    // MARK: - Concurrent send serialization

    /// Reproduces finding 7's race directly: the ticker's very first recompute -- generation 1,
    /// started by subscribing below (finding 14 gates the ticker on the first subscriber; it no
    /// longer starts at construction) -- is held suspended in `overdueProvider`, standing in for "a
    /// tick suspended when a broadcast lands", while a second, later-started `markBroadcast()`-
    /// triggered recompute resolves immediately and publishes a fresher value. Releasing the stale
    /// first recompute (with an answer engineered to compute a *different* `blocked` value, so
    /// `removeDuplicates()` can't accidentally be the thing hiding the bug) must not publish a third,
    /// stale emission: latest-wins, and a recompute that started earlier but finishes later is
    /// dropped.
    func testStaleRecomputeIsDroppedInFavorOfAFresherPublishedValue() async throws {
        let clock = TestClock(referenceDate)
        let provider = GatedOverdueProvider()
        let gate = MigrationSyncGate(
            directory: testGeneralStorageDirectory,
            accountUUID: accountA,
            bufferDuration: buffer,
            // Long enough that only the ticker's own startup recompute fires during this test.
            tickInterval: 3600,
            now: { clock.now },
            overdueProvider: { await provider.next() },
            logger: logger
        )

        var received: [Bool] = []
        let freshValuePublished = expectation(description: "fresher value published")
        let noStaleValuePublished = expectation(description: "a stale third value must not publish")
        noStaleValuePublished.isInverted = true
        // Subscribing is what starts the ticker (finding 14): this kicks off generation 1, which
        // immediately suspends in `overdueProvider` below.
        let cancellable = gate.blockedStream.sink { value in
            received.append(value)
            if received.count == 2 { freshValuePublished.fulfill() }
            if received.count >= 3 { noStaleValuePublished.fulfill() }
        }
        defer { cancellable.cancel() }

        // Generation 1 is now in flight (started by the subscription above): wait for it to be
        // suspended in `overdueProvider`, unresolved, until we explicitly release it below.
        await provider.waitUntilWaiting()

        // Generation 2: queued ahead of time, so `next()` returns immediately (no suspension) and
        // this recompute -- started AFTER generation 1 -- finishes and publishes FIRST.
        await provider.queue(true)
        gate.markBroadcast()

        await fulfillment(of: [freshValuePublished], timeout: 5)
        XCTAssertEqual(received, [false, true])

        // Advance the clock past the buffer `markBroadcast()` just started, so generation 1's
        // eventual answer (`hasOverdue: false`) computes to `false` -- different from generation 2's
        // published `true` -- rather than being incidentally deduplicated to the same value.
        clock.now = referenceDate.addingTimeInterval(buffer + 1)

        // Release the stale generation-1 call. Pre-fix this publishes a third, stale `false`;
        // post-fix it is dropped (generation 1 < the already-published generation 2).
        await provider.resolveOldestWaiting(false)

        await fulfillment(of: [noStaleValuePublished], timeout: 0.5)
        XCTAssertEqual(received, [false, true])
    }

    // MARK: - Lock split regression (deadlock on synchronous cancel during publish)

    /// Regression for the reviewer's Important finding on the sync-gate lock split: a `blockedStream`
    /// subscriber that cancels *synchronously*, from inside its own `receiveValue` handler, in
    /// response to a value delivered through `publish(_:generation:)` (a `markBroadcast()`-triggered
    /// emission -- NOT the synchronous subscribe-time seed, which bypasses `publish(_:generation:)`
    /// entirely) drives Combine's `receiveCancel` synchronously on the SAME thread, still inside
    /// `publish`'s lock critical section around `blockedSubject.send(_:)`. Before the lock split this
    /// was a single `sendLock`: `subscriberDetached()`'s re-entrant `lock()` on that same,
    /// already-held, non-recursive `NSLock` deadlocked the thread and left the lock forever held,
    /// wedging the whole gate -- every later `currentResumeAt()` / `currentlyBlocked()` /
    /// `markBroadcast()` / subscribe would hang too. After the split, `subscriberDetached()` only
    /// ever touches `subscriptionLock`, a separate, uncontended lock, so the re-entrant call during
    /// `send` no longer contends anything `publish()` holds.
    ///
    /// The risky calls run on a background `Task`, gated by expectations fulfilled from inside the
    /// relevant closures, with the outer `fulfillment` below as the single bound on the whole
    /// scenario: pre-fix, the synchronous `cancel()` deadlocks that Task's thread permanently, so
    /// nothing after it -- including the second `markBroadcast()`, which needs the very same
    /// still-held lock -- ever runs. The outer wait still times out cleanly rather than hanging the
    /// test itself, because it only watches an `XCTestExpectation` object, independent of whether the
    /// Task that would fulfill it is stuck. No wall sleeps anywhere.
    func testSubscriberCancellingSynchronouslyDuringAPublishDoesNotWedgeTheGate() async throws {
        let gate = makeGate(account: accountA, clock: TestClock(referenceDate))

        var cancellable: AnyCancellable?
        var received: [Bool] = []
        let publishedValueCancelledSynchronously = expectation(
            description: "the markBroadcast-triggered value was received and its synchronous cancel completed"
        )
        cancellable = gate.blockedStream.sink { value in
            received.append(value)
            // The seed (subscribe-time) value is delivered outside `publish(_:generation:)` and is
            // deterministically `false` here (fresh gate, no resumeAt yet) -- only a `true` value can
            // be the `markBroadcast()`-triggered publish this test targets.
            if value {
                cancellable?.cancel()
                publishedValueCancelledSynchronously.fulfill()
            }
        }
        XCTAssertEqual(received, [false], "precondition: the synchronous seed must be the unblocked value")

        let secondSubscriberReceivedAValue = expectation(description: "a new subscriber after the scenario still receives a value")
        let scenarioCompleted = expectation(description: "gate remains usable after the cancel-during-publish scenario")

        Task {
            // Triggers a recompute that publishes `true` (a live resumeAt now exists); the
            // synchronous cancel above fires from inside that publish's `send`.
            gate.markBroadcast()

            // Pre-fix this never fires: the sink's `receiveValue` is stuck inside
            // `cancellable?.cancel()` -> `subscriberDetached()` re-locking the same lock `publish()`
            // is still holding.
            await self.fulfillment(of: [publishedValueCancelledSynchronously], timeout: 5)
            XCTAssertEqual(received, [false, true])

            // The gate must not be wedged: a fresh `markBroadcast()` plus a brand-new subscriber must
            // still work. Pre-fix, the lock is left permanently held by the deadlocked cancel above,
            // so this direct, synchronous call would hang right here too.
            gate.markBroadcast()
            _ = gate.blockedStream.sink { _ in secondSubscriberReceivedAValue.fulfill() }
            await self.fulfillment(of: [secondSubscriberReceivedAValue], timeout: 5)

            scenarioCompleted.fulfill()
        }

        await fulfillment(of: [scenarioCompleted], timeout: 15)
    }

    // MARK: - Tor client bootstrap caching

    /// Reproduces finding 8 directly: two concurrent `useTor` bootstraps must await the SAME cached
    /// `Task` rather than each racing an independent `TorClient` construction against the shared
    /// `migration_tor` directory. A gated factory pins it deterministically: held suspended until
    /// both callers have reached `dedicatedTorClient()`, then released once -- if the cache were
    /// bypassed, the second caller would have driven a second, independent factory invocation
    /// before the first could even resolve. Drives the internal `dedicatedTorClient()` seam directly
    /// (rather than the full `broadcast()`) so this stays an offline test: once the factory resolves
    /// successfully, a real `TorClient` would need actual FFI/network I/O for anything beyond this
    /// bootstrap step.
    func testConcurrentTorBootstrapsShareASingleFactoryInvocation() async throws {
        let factory = GatedTorClientFactory()
        let broadcaster = MigrationBroadcaster(
            torDirURL: testGeneralStorageDirectory,
            logger: logger,
            torClientFactory: factory.make
        )

        let first = Task { try await broadcaster.dedicatedTorClient() }
        await factory.awaitCallsStarted(1)
        let second = Task { try await broadcaster.dedicatedTorClient() }
        // Scheduling aid only (correctness must not depend on it): give the second caller ample
        // opportunity to reach the actor while the first bootstrap is still in flight.
        for _ in 0..<50 {
            await Task.yield()
        }
        await factory.resolve()

        _ = try await first.value
        _ = try await second.value

        let callCount = await factory.callCount
        XCTAssertEqual(callCount, 1, "two concurrent useTor bootstraps must await the same cached Task")
    }

    /// The failure half: a bootstrap failure is observed by every concurrent caller of that SAME
    /// attempt -- both throw `migrationTorUnavailable`, driven through the public `broadcast` entry
    /// point so the fail-closed wrapping is exercised too -- but clears the cache so a LATER,
    /// non-concurrent broadcast retries with a fresh bootstrap instead of replaying the same cached
    /// failure forever.
    func testTorBootstrapFailureIsSharedByConcurrentCallersThenClearsForALaterRetry() async throws {
        let factory = GatedTorClientFactory()
        let broadcaster = MigrationBroadcaster(
            torDirURL: testGeneralStorageDirectory,
            logger: logger,
            torClientFactory: factory.make
        )
        let endpoint = LightWalletEndpoint(address: "default.example", port: 9067)

        let first = Task {
            try await broadcaster.broadcast(rawTransaction: Data([0x01]), to: endpoint, useTor: true)
        }
        await factory.awaitCallsStarted(1)
        let second = Task {
            try await broadcaster.broadcast(rawTransaction: Data([0x02]), to: endpoint, useTor: true)
        }
        for _ in 0..<50 {
            await Task.yield()
        }
        await factory.resolve(throwing: StubTorBootstrapError())

        await assertThrowsMigrationTorUnavailable(first)
        await assertThrowsMigrationTorUnavailable(second)

        let callCountAfterFailure = await factory.callCount
        XCTAssertEqual(callCountAfterFailure, 1, "the failing bootstrap must be shared by both concurrent callers")

        do {
            _ = try await broadcaster.broadcast(rawTransaction: Data([0x03]), to: endpoint, useTor: true)
            XCTFail("Expected migrationTorUnavailable to be thrown")
        } catch ZcashError.migrationTorUnavailable {
            // expected
        } catch {
            XCTFail("Expected migrationTorUnavailable but got \(error)")
        }

        let callCountAfterRetry = await factory.callCount
        XCTAssertEqual(callCountAfterRetry, 2, "a later broadcast must retry with a fresh bootstrap, not replay the cached failure")
    }

    private func assertThrowsMigrationTorUnavailable(_ task: Task<MigrationBroadcastOutcome, Error>) async {
        do {
            _ = try await task.value
            XCTFail("Expected migrationTorUnavailable to be thrown")
        } catch ZcashError.migrationTorUnavailable {
            // expected
        } catch {
            XCTFail("Expected migrationTorUnavailable but got \(error)")
        }
    }

    // MARK: - Result mapping table

    func testMapTransportErrorIsRetryableNetworkError() {
        XCTAssertEqual(
            MigrationBroadcaster.map(outcome: .transportError, successTxId: "unused"),
            MigrationTransferResult.networkError(retryable: true)
        )
    }

    func testMapGenericRejectionIsInvalidNote() {
        XCTAssertEqual(
            MigrationBroadcaster.map(outcome: .rejected(errorCode: -25, message: "missing inputs"), successTxId: "unused"),
            MigrationTransferResult.invalidNote
        )
    }

    func testMapExpiringSoonRejectionIsExpired() {
        XCTAssertEqual(
            MigrationBroadcaster.map(outcome: .rejected(errorCode: -26, message: "tx-expiring-soon"), successTxId: "unused"),
            MigrationTransferResult.expired
        )
    }

    func testMapExpiredRejectionIsCaseInsensitive() {
        XCTAssertEqual(
            MigrationBroadcaster.map(outcome: .rejected(errorCode: -1, message: "Transaction has EXPIRED"), successTxId: "unused"),
            MigrationTransferResult.expired
        )
    }

    func testMapSuccessCarriesProvidedTxId() {
        XCTAssertEqual(
            MigrationBroadcaster.map(outcome: .submitted, successTxId: "aabbccdd"),
            MigrationTransferResult.success(txId: "aabbccdd")
        )
    }

    // MARK: - Result mapping table: duplicate re-submissions

    /// A rejection carrying zcashd's "already known" RPC code means the transaction landed on a
    /// previous attempt: it must map to success (with the prepared transfer's txid), not to a dead-end
    /// `invalidNote`, regardless of the message text.
    func testMapDuplicateRejectionByErrorCodeIsSuccessWithTxId() {
        XCTAssertEqual(
            MigrationBroadcaster.map(
                outcome: .rejected(errorCode: -27, message: "transaction verification failed"),
                successTxId: "feedface"
            ),
            MigrationTransferResult.success(txId: "feedface")
        )
    }

    /// Every known duplicate-rejection message variant maps to success, independently of the error
    /// code (here a non-duplicate code, so only the message can classify).
    func testMapDuplicateRejectionByEachKnownMessageIsSuccessWithTxId() {
        let duplicateMessages = [
            "transaction already in block chain",
            "already in blockchain",
            "18: txn-already-in-mempool",
            "transaction is already in mempool",
            "257: txn-already-known"
        ]

        for message in duplicateMessages {
            XCTAssertEqual(
                MigrationBroadcaster.map(outcome: .rejected(errorCode: -26, message: message), successTxId: "aabbccdd"),
                MigrationTransferResult.success(txId: "aabbccdd"),
                "expected duplicate message \"\(message)\" to map to success"
            )
        }
    }

    func testMapDuplicateRejectionMessageMatchIsCaseInsensitive() {
        XCTAssertEqual(
            MigrationBroadcaster.map(
                outcome: .rejected(errorCode: -26, message: "Transaction ALREADY In Block Chain"),
                successTxId: "aabbccdd"
            ),
            MigrationTransferResult.success(txId: "aabbccdd")
        )
    }

    /// The duplicate check runs before the expiry sniffing: the "already known" RPC code identifies
    /// a duplicate even when the message alone would read as an expiry.
    func testMapDuplicateDetectionWinsOverExpirySniffing() {
        XCTAssertEqual(
            MigrationBroadcaster.map(
                outcome: .rejected(errorCode: -27, message: "transaction has expired"),
                successTxId: "aabbccdd"
            ),
            MigrationTransferResult.success(txId: "aabbccdd")
        )
    }

    /// Fragment specificity: a message merely containing "already" (an already-spent input) is not a
    /// duplicate re-submission and stays on the invalidNote path.
    func testMapNonDuplicateRejectionMentioningAlreadyStaysInvalidNote() {
        XCTAssertEqual(
            MigrationBroadcaster.map(
                outcome: .rejected(errorCode: -25, message: "input already spent"),
                successTxId: "unused"
            ),
            MigrationTransferResult.invalidNote
        )
    }

    // MARK: - Reschedule delegation

    /// `rescheduleOverdueTransfer()` is now a straight delegation to the engine-backed welding
    /// accessor: the proposal the welding returns is passed through untouched (no local
    /// time-shifting of `nextExecutableAfterHeight`), the bound account is forwarded, and a `nil`
    /// answer becomes `nil` out.
    func testRescheduleOverdueTransferReturnsWeldingProposalUntouched() async throws {
        let welding = ZcashRustBackendWeldingMock()
        let proposal = Self.makeSchedule(count: 3).transfers[1]
        welding.migrationPendingTransferProposalForReturnValue = proposal
        let migration = makeMigration(welding: welding, account: accountA)

        let rescheduled = try await migration.rescheduleOverdueTransfer()

        XCTAssertEqual(rescheduled, proposal)
        XCTAssertEqual(welding.migrationPendingTransferProposalForReceivedAccount, accountA)
    }

    func testRescheduleOverdueTransferReturnsNilWhenWeldingReturnsNil() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.migrationPendingTransferProposalForReturnValue = nil
        let migration = makeMigration(welding: welding, account: accountA)

        let rescheduled = try await migration.rescheduleOverdueTransfer()

        XCTAssertNil(rescheduled)
    }

    func testRescheduleOverdueTransferRethrowsWhenWeldingThrows() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.migrationPendingTransferProposalForThrowableError =
            ZcashError.rustMigrationPendingTransferProposal("boom")
        let migration = makeMigration(welding: welding, account: accountA)

        do {
            _ = try await migration.rescheduleOverdueTransfer()
            XCTFail("Expected rescheduleOverdueTransfer to rethrow the welding error")
        } catch ZcashError.rustMigrationPendingTransferProposal {
            // expected
        } catch {
            XCTFail("Expected rustMigrationPendingTransferProposal but got \(error)")
        }
    }

    // MARK: - Immediate migration (send-max lane, MOB-1513)

    /// `proposeImmediateMigration()` derives the account's own current address and proposes an
    /// Orchard-only send-max transfer to it: the immediate lane is a self-send that lands in the
    /// account's own Ironwood receiver (the UA's Orchard receiver doubles as the Ironwood receiver
    /// post-NU6.3), with no memo, and restricted to the Orchard pool (never draws on Sapling funds).
    func testProposeImmediateMigrationSendsMaxToOwnAddressOrchardOnly() async throws {
        let welding = ZcashRustBackendWeldingMock()
        let ownAddress = UnifiedAddress(validatedEncoding: Self.uaString, networkType: .testnet)
        welding.getCurrentAddressAccountUUIDReturnValue = ownAddress
        welding.proposeSendMaxTransferAccountUUIDRecipientMemoOrchardOnlyReturnValue = Self.makeSendMaxProposal(
            inputValues: [1_000_000],
            changeValues: [],
            fee: 10_000
        )
        let migration = makeMigration(welding: welding, account: accountA)

        _ = try await migration.proposeImmediateMigration()

        XCTAssertEqual(welding.getCurrentAddressAccountUUIDReceivedAccountUUID, accountA)
        let received = welding.proposeSendMaxTransferAccountUUIDRecipientMemoOrchardOnlyReceivedArguments
        XCTAssertEqual(received?.accountUUID, accountA)
        XCTAssertEqual(received?.recipient, ownAddress.stringEncoded)
        XCTAssertNil(received?.memo)
        XCTAssertEqual(received?.orchardOnly, true)
    }

    /// The core decode: `amount` is the net value that crosses into Ironwood (input total minus the
    /// fee), and `fee` is `Proposal.totalFeeRequired()` -- matching the documented "value that
    /// crosses the turnstile" contract the rust half applies on the privacy path, applied here to
    /// the immediate lane's ordinary proposal. A send-max proposal declares no change, so the net
    /// amount is just the swept input total minus the fee.
    func testProposeImmediateMigrationDecodesNetAmountAndFee() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.getCurrentAddressAccountUUIDReturnValue = UnifiedAddress(validatedEncoding: Self.uaString, networkType: .testnet)
        welding.proposeSendMaxTransferAccountUUIDRecipientMemoOrchardOnlyReturnValue = Self.makeSendMaxProposal(
            inputValues: [600_000, 400_000],
            changeValues: [],
            fee: 15_000
        )
        let migration = makeMigration(welding: welding, account: accountA)

        let proposal = try await migration.proposeImmediateMigration()

        XCTAssertEqual(proposal.fee, Zatoshi(15_000))
        XCTAssertEqual(proposal.amount, Zatoshi(600_000 + 400_000 - 15_000))
    }

    /// Defensive edge: a send-max proposal should never declare change (there is nothing left to
    /// return), but the decode subtracts any declared change anyway rather than assuming it is
    /// always empty, so `amount` always means "what left the wallet toward the payment" even if
    /// that assumption is ever violated.
    func testProposeImmediateMigrationSubtractsAnyDeclaredChangeFromTheAmount() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.getCurrentAddressAccountUUIDReturnValue = UnifiedAddress(validatedEncoding: Self.uaString, networkType: .testnet)
        welding.proposeSendMaxTransferAccountUUIDRecipientMemoOrchardOnlyReturnValue = Self.makeSendMaxProposal(
            inputValues: [1_000_000],
            changeValues: [50_000],
            fee: 10_000
        )
        let migration = makeMigration(welding: welding, account: accountA)

        let proposal = try await migration.proposeImmediateMigration()

        XCTAssertEqual(proposal.amount, Zatoshi(1_000_000 - 50_000 - 10_000))
    }

    func testProposeImmediateMigrationRethrowsWhenAddressDerivationFails() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.getCurrentAddressAccountUUIDThrowableError = ZcashError.rustGetCurrentAddress("boom")
        let migration = makeMigration(welding: welding, account: accountA)

        do {
            _ = try await migration.proposeImmediateMigration()
            XCTFail("Expected proposeImmediateMigration to rethrow the address-derivation error")
        } catch ZcashError.rustGetCurrentAddress {
            // expected
        } catch {
            XCTFail("Expected rustGetCurrentAddress but got \(error)")
        }
    }

    func testProposeImmediateMigrationRethrowsWhenSendMaxProposalFails() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.getCurrentAddressAccountUUIDReturnValue = UnifiedAddress(validatedEncoding: Self.uaString, networkType: .testnet)
        welding.proposeSendMaxTransferAccountUUIDRecipientMemoOrchardOnlyThrowableError = ZcashError.rustProposeSendMaxTransfer("boom")
        let migration = makeMigration(welding: welding, account: accountA)

        do {
            _ = try await migration.proposeImmediateMigration()
            XCTFail("Expected proposeImmediateMigration to rethrow the send-max proposal error")
        } catch ZcashError.rustProposeSendMaxTransfer {
            // expected
        } catch {
            XCTFail("Expected rustProposeSendMaxTransfer but got \(error)")
        }
    }

    /// `recordImmediateMigration` is a straight forward to the welding record call, bound to this
    /// actor's own account -- the SDK-store bookkeeping (state-machine derivation) all lives
    /// rust-side.
    func testRecordImmediateMigrationForwardsTxidAndAccount() async throws {
        let welding = ZcashRustBackendWeldingMock()
        var receivedTxid: Data?
        var receivedAccount: AccountUUID?
        welding.migrationRecordImmediateRunTxidForClosure = { txid, account in
            receivedTxid = txid
            receivedAccount = account
        }
        let migration = makeMigration(welding: welding, account: accountA)
        let txid = Data(repeating: 0xCD, count: 32)

        try await migration.recordImmediateMigration(txid: txid)

        XCTAssertEqual(receivedTxid, txid)
        XCTAssertEqual(receivedAccount, accountA)
    }

    // MARK: - Broadcast composition (I1 canary)

    /// Canary for the privacy-critical composition in `OrchardMigration.broadcastAndRecord`: a
    /// pre-broadcast Tor failure must fail closed — throw, record nothing, and never start the
    /// privacy buffer. Drives the real actor through the ``MigrationBroadcasting`` seam (a fake
    /// transport), a real ``MigrationSyncGate``, and a welding mock, so a future regression that
    /// reorders "record" before "broadcast", or adds a direct-transport fallback on Tor failure, would
    /// turn this test red.
    func testExecuteNextPendingTransferFailsClosedOnTorUnavailableWithoutRecordingOrGating() async throws {
        let prepared = PreparedMigrationTransfer(
            id: "transfer-0",
            txid: Data(repeating: 0xAB, count: 32),
            pczt: Data([0x01, 0x02])
        )
        let welding = ZcashRustBackendWeldingMock()
        welding.migrationNextDueTransferForReturnValue = prepared
        welding.migrationExtractBroadcastTxPcztForReturnValue = Data([0x03, 0x04])
        // A no-op closure: if the fail-closed guard regresses and this ends up called anyway, it
        // completes instead of crashing the process, so the call-count assertion below fails cleanly
        // rather than taking the whole test run down with it.
        welding.migrationRecordTransferResultTransferIdResultForClosure = { _, _, _ in }

        let fakeBroadcaster = ScriptedBroadcaster(script: .throwing(ZcashError.migrationTorUnavailable))
        let gate = makeGate(account: accountA, clock: TestClock(referenceDate))

        let migration = OrchardMigration(
            welding: welding,
            accountUUID: accountA,
            broadcaster: fakeBroadcaster,
            syncGate: gate,
            logger: logger
        )

        do {
            _ = try await migration.executeNextPendingTransfer(
                options: MigrationNetworkPrivacyOptions(
                    useTor: true,
                    submissionEndpoint: LightWalletEndpoint(address: "default.example", port: 9067)
                )
            )
            XCTFail("Expected migrationTorUnavailable to be thrown")
        } catch ZcashError.migrationTorUnavailable {
            // expected
        } catch {
            XCTFail("Expected migrationTorUnavailable but got \(error)")
        }

        XCTAssertEqual(fakeBroadcaster.receivedCalls.count, 1)
        XCTAssertFalse(welding.migrationRecordTransferResultTransferIdResultForCalled)
        XCTAssertNil(gate.currentResumeAt())
    }

    // MARK: - Helpers

    private func makeGate(account: AccountUUID, clock: TestClock) -> MigrationSyncGate {
        MigrationSyncGate(
            directory: testGeneralStorageDirectory,
            accountUUID: account,
            bufferDuration: buffer,
            // A long tick keeps the background re-evaluation out of these deterministic assertions.
            tickInterval: 3600,
            now: { clock.now },
            overdueProvider: { false },
            logger: logger
        )
    }

    /// Builds a real `OrchardMigration` around the given welding mock, wired with a real,
    /// temp-file-backed sync gate and a broadcaster that is never reached by the reschedule path.
    private func makeMigration(welding: ZcashRustBackendWeldingMock, account: AccountUUID) -> OrchardMigration {
        OrchardMigration(
            welding: welding,
            accountUUID: account,
            broadcaster: ScriptedBroadcaster(script: .throwing(ZcashError.migrationTorUnavailable)),
            syncGate: makeGate(account: account, clock: TestClock(referenceDate)),
            logger: logger
        )
    }

    static func makeSchedule(count: Int) -> MigrationSchedule {
        // An explicit accumulator rather than `(0..<count).map { ... }`: CI's Xcode 16.0 compiler
        // times out type-checking the closure-wrapped multi-argument literal expression ("unable to
        // type-check this expression in reasonable time"); newer local toolchains accept either form.
        var transfers: [MigrationTransferProposal] = []
        for index in 0..<count {
            let amount = Zatoshi(Int64((index + 1) * 100_000))
            let transfer = MigrationTransferProposal(
                id: "transfer-\(index)",
                amount: amount,
                anchorHeight: 2_000_000 + index,
                nextExecutableAfterHeight: 2_000_100 + index,
                expiryHeight: 2_010_000 + index
            )
            transfers.append(transfer)
        }
        return MigrationSchedule(transfers: transfers, estimatedDurationHours: count * 6)
    }

    /// Builds a single-step `FfiProposal` fixture shaped like a send-max proposal: one
    /// `receivedOutput` input per entry of `inputValues`, one `proposedChange` output per entry of
    /// `changeValues` (empty for a "true" send-max, non-empty to exercise the decode's defensive
    /// subtraction), and `fee` as the step's `feeRequired`.
    static func makeSendMaxProposal(inputValues: [UInt64], changeValues: [UInt64], fee: UInt64) -> FfiProposal {
        var inputs: [FfiProposedInput] = []
        for value in inputValues {
            var receivedOutput = FfiReceivedOutput()
            receivedOutput.value = value
            var input = FfiProposedInput()
            input.receivedOutput = receivedOutput
            inputs.append(input)
        }

        var changes: [FfiChangeValue] = []
        for value in changeValues {
            var change = FfiChangeValue()
            change.value = value
            changes.append(change)
        }

        var balance = FfiTransactionBalance()
        balance.feeRequired = fee
        balance.proposedChange = changes

        var step = FfiProposalStep()
        step.inputs = inputs
        step.balance = balance

        var proposal = FfiProposal()
        proposal.steps = [step]
        return proposal
    }
}

/// A controllable test double for `MigrationSyncGate`'s `overdueProvider` seam: each call to
/// `next()` either returns an already-queued answer immediately, or suspends until `resolveOldestWaiting`
/// releases the oldest still-waiting call. Lets a test pin the exact interleaving of two concurrent
/// recomputes deterministically -- no `Task.sleep`, no polling -- by controlling which of two
/// `overdueProvider` calls resolves first.
private actor GatedOverdueProvider {
    private var queuedAnswers: [Bool] = []
    private var waiters: [CheckedContinuation<Bool, Never>] = []
    private var suspensionSignals: [CheckedContinuation<Void, Never>] = []

    func next() async -> Bool {
        if !queuedAnswers.isEmpty {
            return queuedAnswers.removeFirst()
        }
        return await withCheckedContinuation { continuation in
            waiters.append(continuation)
            let signals = suspensionSignals
            suspensionSignals = []
            for signal in signals {
                signal.resume()
            }
        }
    }

    /// Queues `answer` for the next call to `next()` that is not already suspended, so that call
    /// returns immediately instead of waiting on `resolveOldestWaiting`.
    func queue(_ answer: Bool) {
        queuedAnswers.append(answer)
    }

    /// Resolves the oldest currently-suspended `next()` call with `answer`.
    func resolveOldestWaiting(_ answer: Bool) {
        guard !waiters.isEmpty else {
            XCTFail("GatedOverdueProvider: no suspended `next()` call to resolve")
            return
        }
        waiters.removeFirst().resume(returning: answer)
    }

    /// Suspends until at least one call to `next()` is itself suspended awaiting resolution.
    func waitUntilWaiting() async {
        if !waiters.isEmpty { return }
        await withCheckedContinuation { continuation in
            suspensionSignals.append(continuation)
        }
    }
}

/// A trivial, always-immediately-resolving `overdueProvider` double that just counts calls -- used
/// to pin finding 14's subscription-gated ticker (``MigrationLogicTests/testTickerTicksOnlyWhileSubscribed()``):
/// unlike `GatedOverdueProvider`, nothing here ever suspends, so the count only grows when the
/// ticker itself actually decides to tick.
private actor CallCountingOverdueProvider {
    private(set) var count = 0

    @discardableResult
    func increment() -> Int {
        count += 1
        return count
    }
}

// `GatedTorClientFactory` and `StubTorBootstrapError` were promoted to
// `Tests/TestUtils/MigrationTestDoubles.swift` so `OrchardMigrationHostTests` can reuse them for the
// shared-broadcaster single-bootstrap canary.
