//
//  MigrationLogicTests.swift
//  ZcashLightClientKitTests
//

import Combine
import XCTest
@testable import TestUtils
@_spi(Testing) @testable import ZcashLightClientKit

/// Pure-logic tests for the app-facing migration layer: sync-gate math and file round-trip,
/// endpoint resolution, broadcast-result mapping, and the reschedule accessor's delegation to the
/// migration welding. No network, no dataDb — every collaborator here is exercised in isolation.
final class MigrationLogicTests: ZcashTestCase {
    private let accountA = AccountUUID(id: [UInt8](repeating: 0x11, count: 16))
    private let referenceDate = Date(timeIntervalSince1970: 1_700_000_000)
    private let mappedTxId = TxId([UInt8](repeating: 0xAB, count: 32))
    private static let uaString = """
    u1l9f0l4348negsncgr9pxd9d3qaxagmqv3lnexcplmufpq7muffvfaue6ksevfvd7wrz7xrvn95rc5zjtn7ugkmgh5rnxswmcj30y0pw52pn0zjvy38rn2esfgve64rj5pcmazxgpyuj
    """

    // MARK: - Gate math

    /// The gate's whole predicate: with no in-flight marker there is nothing to block on, and a
    /// live one blocks. Nothing else is an input any more.
    func testGateBlocksOnlyWhileAMarkerIsLive() {
        XCTAssertFalse(MigrationSyncGate.isBlocked(now: referenceDate, inFlightUntil: nil))
        let inFlightUntil = referenceDate.addingTimeInterval(MigrationSyncGate.broadcastInFlightGuardDuration)
        XCTAssertTrue(MigrationSyncGate.isBlocked(now: referenceDate, inFlightUntil: inFlightUntil))
    }

    /// At exactly `inFlightUntil` the marker has elapsed: `now < inFlightUntil` is false.
    func testGateUnblocksAtExactlyInFlightMarkerBoundary() {
        let inFlightUntil = referenceDate.addingTimeInterval(MigrationSyncGate.broadcastInFlightGuardDuration)
        XCTAssertFalse(MigrationSyncGate.isBlocked(now: inFlightUntil, inFlightUntil: inFlightUntil))
    }

    /// D1 (2026-08-05): the forward-looking ready-broadcast clause is GONE — no
    /// pending work of any kind can block sync. This is the anti-regression pin for the clause's
    /// removal (it froze an awake session for 50+ min by blocking the very sync its pending
    /// broadcast needed — FIND-5).
    func testGateHasNoForwardLookingClause() {
        XCTAssertFalse(MigrationSyncGate.isBlocked(now: referenceDate, inFlightUntil: nil))
    }

    func testGateCorruptOrMissingFileIsUnblocked() {
        // Corrupt/missing file resolves to `inFlightUntil == nil`, which is "no gate".
        XCTAssertFalse(MigrationSyncGate.isBlocked(now: referenceDate, inFlightUntil: nil))
    }

    // MARK: - Gate math: no time component (the behavior-based gate)

    /// THE PIN FOR THE DELETED POST-BROADCAST BUFFER: a completed broadcast leaves NO timed hold.
    /// The moment the in-flight marker clears, the gate is open — a query at the very same instant
    /// as the broadcast reads unblocked. A fixed post-broadcast delay is an identifiable pattern,
    /// so time-based spacing is not the gate's mechanism at any duration; if a `resumeAt`-style
    /// condition ever comes back, this test goes red.
    func testGateIsOpenImmediatelyAfterABroadcastCompletes() {
        let clock = TestClock(referenceDate)
        let gate = makeGate(account: accountA, clock: clock)

        gate.markBroadcastInFlight()
        XCTAssertTrue(gate.currentlyBlocked(), "precondition: the submit is mid-flight")

        gate.clearBroadcastInFlight()

        // Not one second of the clock has moved since the broadcast.
        XCTAssertFalse(gate.currentlyBlocked(), "a recorded broadcast must leave no timed hold behind")
        XCTAssertEqual(clock.now, referenceDate, "precondition: the assertion above is at the broadcast instant")
    }

    /// The same pin at the persistence layer: the gate file a broadcast leaves behind carries no
    /// `resumeAt`-style field for anything to re-derive a timed hold from.
    func testPersistedGateFileCarriesNoResumeAtField() throws {
        let fileURL = testGeneralStorageDirectory.appendingPathComponent(MigrationSyncGate.fileName(accountUUID: accountA))
        let gate = makeGate(account: accountA, clock: TestClock(referenceDate))

        gate.markBroadcastInFlight()
        XCTAssertEqual(
            Set(try persistedGateKeys(at: fileURL)),
            ["version", "inFlightUntilEpochSeconds"],
            "the armed envelope carries the marker and nothing else"
        )

        gate.clearBroadcastInFlight()
        XCTAssertEqual(
            Set(try persistedGateKeys(at: fileURL)),
            ["version"],
            "a completed broadcast persists no instant at all — there is nothing timed to resume from"
        )
    }

    // MARK: - Gate math: broadcast in-flight marker

    /// `markBroadcastInFlight()` blocks sync immediately; `clearBroadcastInFlight()` releases it
    /// again. The seconds-scale submit-to-record window is the only wait the gate ever imposes.
    func testMarkBroadcastInFlightBlocksAndClearReleases() {
        let gate = makeGate(account: accountA, clock: TestClock(referenceDate))
        XCTAssertFalse(gate.currentlyBlocked(), "precondition: fresh gate is unblocked")

        gate.markBroadcastInFlight()

        XCTAssertTrue(gate.currentlyBlocked())
        XCTAssertNotNil(gate.currentInFlightUntil())

        gate.clearBroadcastInFlight()

        XCTAssertFalse(gate.currentlyBlocked())
        XCTAssertNil(gate.currentInFlightUntil())
    }

    /// The in-flight marker self-expires after `broadcastInFlightGuardDuration` even without an
    /// explicit `clearBroadcastInFlight()` -- the CRASH-RECOVERY liveness a crash between submit
    /// and record relies on (a ceiling on the wedge, not a privacy interval).
    func testInFlightMarkerSelfExpiresAfterGuardDuration() {
        let clock = TestClock(referenceDate)
        let gate = makeGate(account: accountA, clock: clock)

        gate.markBroadcastInFlight()
        XCTAssertTrue(gate.currentlyBlocked())

        clock.now = referenceDate.addingTimeInterval(MigrationSyncGate.broadcastInFlightGuardDuration + 1)

        XCTAssertFalse(gate.currentlyBlocked(), "an expired in-flight marker must stop blocking sync")
    }

    // MARK: - Gate math: in-flight marker backwards-clock-step guard (A13)

    /// An in-flight expiry MORE than the guard duration in the future is impossible under a
    /// monotone clock (the marker is armed at exactly `now + guard`) — it proves the clock
    /// stepped backwards after arming. On the stateless predicate (the wallet-scope reader's raw
    /// file input, with no cache to persist a clamp into) such a marker must fail OPEN, or every
    /// re-read would re-derive a fresh block until real time caught back up.
    func testIsBlockedIgnoresAnImplausiblyFarFutureInFlightMarker() {
        let farFuture = referenceDate.addingTimeInterval(MigrationSyncGate.broadcastInFlightGuardDuration + 3600)
        XCTAssertFalse(
            MigrationSyncGate.isBlocked(now: referenceDate, inFlightUntil: farFuture),
            "a clock-step artifact must not wedge sync"
        )
        // The boundary itself is plausible: a freshly armed marker sits at exactly now + guard.
        let freshlyArmed = referenceDate.addingTimeInterval(MigrationSyncGate.broadcastInFlightGuardDuration)
        XCTAssertTrue(
            MigrationSyncGate.isBlocked(now: referenceDate, inFlightUntil: freshlyArmed)
        )
    }

    /// The clamp helper itself: a far-future expiry clamps to `now + guard`, a plausible one and
    /// `nil` pass through untouched.
    func testClampedInFlightUntilClampsOnlyImplausibleValues() {
        let ceiling = referenceDate.addingTimeInterval(MigrationSyncGate.broadcastInFlightGuardDuration)
        let farFuture = referenceDate.addingTimeInterval(7200)
        XCTAssertEqual(MigrationSyncGate.clampedInFlightUntil(farFuture, now: referenceDate), ceiling)
        let plausible = referenceDate.addingTimeInterval(30)
        XCTAssertEqual(MigrationSyncGate.clampedInFlightUntil(plausible, now: referenceDate), plausible)
        XCTAssertNil(MigrationSyncGate.clampedInFlightUntil(nil, now: referenceDate))
    }

    /// The stateful half of A13: a far-future marker in the PERSISTED file (armed before a
    /// backwards clock step, standing in for a relaunch) is clamped at the fresh instance's load,
    /// so it blocks for at most the guard duration from launch and then self-expires — instead of
    /// wedging sync until real time re-passes the stale expiry.
    func testInitLoadClampsAFarFutureInFlightMarkerToTheGuardWindow() throws {
        let armClock = TestClock(referenceDate.addingTimeInterval(3600))
        let armingGate = makeGate(account: accountA, clock: armClock)
        armingGate.markBroadcastInFlight()

        // Relaunch with the clock stepped back an hour: the persisted expiry is now ~3720 s away.
        let steppedBackClock = TestClock(referenceDate)
        let relaunchedGate = makeGate(account: accountA, clock: steppedBackClock)

        let ceiling = referenceDate.addingTimeInterval(MigrationSyncGate.broadcastInFlightGuardDuration)
        XCTAssertEqual(relaunchedGate.currentInFlightUntil(), ceiling, "the load must clamp the marker into its plausible window")
        XCTAssertTrue(relaunchedGate.currentlyBlocked(), "the protective window survives the clamp")

        steppedBackClock.now = ceiling.addingTimeInterval(1)
        XCTAssertFalse(
            relaunchedGate.currentlyBlocked(),
            "the clamped marker must expire a guard-duration after the relaunch, not an hour later"
        )
    }

    /// The evaluation-side clamp: a marker that becomes implausible MID-RUN (the clock steps back
    /// after arming, no relaunch) is clamped — with cache write-back — at the next read, so it
    /// again blocks for at most the guard duration from that observation.
    func testCurrentInFlightUntilClampsAndPersistsAMidRunClockStepBack() {
        let clock = TestClock(referenceDate.addingTimeInterval(3600))
        let gate = makeGate(account: accountA, clock: clock)
        gate.markBroadcastInFlight()

        // The clock steps back an hour mid-run.
        clock.now = referenceDate

        let ceiling = referenceDate.addingTimeInterval(MigrationSyncGate.broadcastInFlightGuardDuration)
        XCTAssertEqual(gate.currentInFlightUntil(), ceiling, "the read must clamp the marker to now + guard")
        XCTAssertTrue(gate.currentlyBlocked())

        // The clamp persisted (write-back): advancing past the ceiling expires the marker even
        // though the ORIGINAL expiry is still far in this clock's future.
        clock.now = ceiling.addingTimeInterval(1)
        XCTAssertFalse(gate.currentlyBlocked())
    }

    // MARK: - Gate file round-trip

    func testCorruptFileAtInitReadsAsNoGate() throws {
        // Written BEFORE construction: finding 14's in-memory marker cache is loaded from the
        // file exactly once, at init, so this is the only point at which corrupt content is parsed.
        let fileURL = testGeneralStorageDirectory.appendingPathComponent(MigrationSyncGate.fileName(accountUUID: accountA))
        try Data("not json at all".utf8).write(to: fileURL)

        let gate = makeGate(account: accountA, clock: TestClock(referenceDate))

        XCTAssertNil(gate.currentInFlightUntil())
        XCTAssertFalse(gate.currentlyBlocked())
    }

    /// Finding 14: `currentInFlightUntil()`/`currentlyBlocked` read the in-memory cache, not a
    /// fresh file read every call -- a write to the gate file from something other than this gate
    /// instance must not change what THIS instance reports until its OWN marking call updates the
    /// cache. Stands the violation up with a second `MigrationSyncGate` over the SAME file
    /// (deliberately breaking the documented single-writer assumption) so the write is genuinely
    /// out-of-band and genuinely observable if reads went to disk: a "read fresh every call"
    /// implementation would pick it up, a cached one will not. Was
    /// `testGateCorruptFileReadsAsNoGate` pre-finding-14, when every read re-parsed the file fresh;
    /// the corrupt-JSON coverage that test used to provide now lives in
    /// `testCorruptFileAtInitReadsAsNoGate` above (corrupt content is only ever parsed at init).
    func testCurrentInFlightUntilIgnoresAnOutOfBandFileChangeAfterInit() throws {
        let gate = makeGate(account: accountA, clock: TestClock(referenceDate))
        XCTAssertNil(gate.currentInFlightUntil(), "precondition: nothing in flight yet")

        // A second gate instance over the same account/directory (hence the same file) arms a
        // marker -- a valid, non-nil expiry written out-of-band from the first gate's viewpoint.
        let otherProcessGate = makeGate(account: accountA, clock: TestClock(referenceDate))
        otherProcessGate.markBroadcastInFlight()

        XCTAssertNil(gate.currentInFlightUntil(), "an out-of-band file write after init must not change the cached answer")
        XCTAssertFalse(gate.currentlyBlocked())
    }

    /// Finding 14: the in-memory marker cache is loaded from the gate file once, at init -- a
    /// value persisted by an earlier gate instance (standing in for a previous process launch,
    /// i.e. a crash mid-broadcast) must be honored by a fresh instance over the same file, both
    /// through the instance API and through the file-only wallet-scope reader
    /// `persistedInFlightUntil`.
    func testPersistedInFlightMarkerRoundTripsThroughAFreshGateInstance() throws {
        let clock = TestClock(referenceDate)
        let firstLaunchGate = makeGate(account: accountA, clock: clock)
        firstLaunchGate.markBroadcastInFlight()
        let persistedInFlightUntil = try XCTUnwrap(firstLaunchGate.currentInFlightUntil())

        let secondLaunchGate = makeGate(account: accountA, clock: clock)

        XCTAssertEqual(secondLaunchGate.currentInFlightUntil(), persistedInFlightUntil)
        XCTAssertTrue(secondLaunchGate.currentlyBlocked())

        XCTAssertEqual(
            MigrationSyncGate.persistedInFlightUntil(directory: testGeneralStorageDirectory, accountUUID: accountA, logger: logger),
            persistedInFlightUntil
        )
    }

    /// `clearBroadcastInFlight()`'s file write is durable too: a fresh gate instance constructed
    /// after the clear must not see a stale marker.
    func testClearedInFlightMarkerStaysClearedForAFreshGateInstance() throws {
        let clock = TestClock(referenceDate)
        let firstLaunchGate = makeGate(account: accountA, clock: clock)
        firstLaunchGate.markBroadcastInFlight()
        firstLaunchGate.clearBroadcastInFlight()

        let secondLaunchGate = makeGate(account: accountA, clock: clock)

        XCTAssertNil(secondLaunchGate.currentInFlightUntil())
        XCTAssertFalse(secondLaunchGate.currentlyBlocked())
    }

    /// Back-compat, first evolution: a gate file persisted before the in-flight marker existed
    /// never carries an `inFlightUntilEpochSeconds` key at all (not merely a `null` value) -- the
    /// synthesized `Codable` conformance must decode it via `decodeIfPresent` rather than throwing.
    func testOldGateFileWithoutInFlightFieldStillDecodes() throws {
        let fileURL = testGeneralStorageDirectory.appendingPathComponent(MigrationSyncGate.fileName(accountUUID: accountA))
        try Data("{\"version\":1}".utf8).write(to: fileURL)

        let gate = makeGate(account: accountA, clock: TestClock(referenceDate))

        XCTAssertNil(gate.currentInFlightUntil())
        XCTAssertFalse(gate.currentlyBlocked())
    }

    /// Back-compat, second evolution (2026-08-07): a gate file written while the post-broadcast
    /// privacy buffer still existed carries a `resumeAtEpochSeconds` key this envelope no longer
    /// declares. It must load GRACEFULLY -- the unknown key ignored, the in-flight marker beside
    /// it honored -- rather than throwing and taking a live marker down with it. The buffer value
    /// itself is deliberately dropped: no timed condition can block sync any more, even one a
    /// pre-upgrade launch persisted.
    func testOldGateFileWithABufferFieldLoadsGracefullyAndIgnoresTheBuffer() throws {
        let fileURL = testGeneralStorageDirectory.appendingPathComponent(MigrationSyncGate.fileName(accountUUID: accountA))
        let resumeAtEpochSeconds = referenceDate.addingTimeInterval(600).timeIntervalSince1970
        let inFlightUntil = referenceDate.addingTimeInterval(30)
        let legacyJSON = """
        {"version":1,"resumeAtEpochSeconds":\(resumeAtEpochSeconds),\
        "inFlightUntilEpochSeconds":\(inFlightUntil.timeIntervalSince1970)}
        """
        try Data(legacyJSON.utf8).write(to: fileURL)

        let gate = makeGate(account: accountA, clock: TestClock(referenceDate))

        XCTAssertEqual(gate.currentInFlightUntil(), inFlightUntil, "the marker beside the stale buffer must survive the read")
        XCTAssertTrue(gate.currentlyBlocked(), "precondition: the marker is live")

        // Past the marker, the stale 600 s buffer must NOT keep the gate shut.
        let clock = TestClock(referenceDate)
        let laterGate = makeGate(account: accountA, clock: clock)
        clock.now = inFlightUntil.addingTimeInterval(1)
        XCTAssertFalse(laterGate.currentlyBlocked(), "a persisted buffer from the old format must not block sync")
    }

    /// A buffer-only legacy file (the common case: the last thing a pre-upgrade launch wrote after
    /// a broadcast) reads as an OPEN gate, and the stale key is gone from disk after the gate's
    /// next write.
    func testLegacyBufferOnlyGateFileReadsAsOpenAndIsRewrittenWithoutTheStaleKey() throws {
        let fileURL = testGeneralStorageDirectory.appendingPathComponent(MigrationSyncGate.fileName(accountUUID: accountA))
        let resumeAtEpochSeconds = referenceDate.addingTimeInterval(600).timeIntervalSince1970
        try Data("{\"version\":1,\"resumeAtEpochSeconds\":\(resumeAtEpochSeconds)}".utf8).write(to: fileURL)

        let gate = makeGate(account: accountA, clock: TestClock(referenceDate))
        XCTAssertFalse(gate.currentlyBlocked(), "a legacy buffer must not block a post-upgrade launch")
        XCTAssertNil(
            MigrationSyncGate.persistedInFlightUntil(directory: testGeneralStorageDirectory, accountUUID: accountA, logger: logger)
        )

        gate.markBroadcastInFlight()

        XCTAssertFalse(
            try persistedGateKeys(at: fileURL).contains("resumeAtEpochSeconds"),
            "the next write must drop the stale key"
        )
    }

    // MARK: - MigrationSchedule persistence (A10)

    /// A10 round trip: `encode(to:)` omits `proposalHandle` (a process-lifetime plan-cache key no
    /// persisted copy could honor), so a nonzero-handle schedule decodes back with handle `0` —
    /// the documented "re-propose instead of committing a persisted copy" contract — and every
    /// display field survives unchanged.
    func testMigrationScheduleEncodeOmitsProposalHandleSoARoundTripDecodesItAsZero() throws {
        let schedule = MigrationSchedule(
            transfers: [
                MigrationTransferProposal(
                    id: 4,
                    amount: Zatoshi(200_000_000),
                    anchorHeight: 3_500_000,
                    nextExecutableAfterHeight: 3_500_040,
                    expiryHeight: 3_540_000
                )
            ],
            estimatedDurationHours: 7,
            proposalHandle: 42,
            preparations: [
                MigrationPreparationStep(id: 1, layer: 0, index: 0, broadcastHeight: 3_500_000, dependsOn: []),
                MigrationPreparationStep(id: 2, layer: 1, index: 0, broadcastHeight: 3_500_020, dependsOn: [1])
            ]
        )

        let encoded = try JSONEncoder().encode(schedule)
        let decoded = try JSONDecoder().decode(MigrationSchedule.self, from: encoded)

        XCTAssertEqual(decoded.proposalHandle, 0, "a persisted handle can never identify a live plan; encode must not persist it")
        XCTAssertEqual(decoded.transfers, schedule.transfers)
        XCTAssertEqual(decoded.estimatedDurationHours, schedule.estimatedDurationHours)
        XCTAssertEqual(decoded.preparations, schedule.preparations)

        let json = try XCTUnwrap(String(data: encoded, encoding: .utf8))
        XCTAssertFalse(json.contains("proposalHandle"), "the key itself must be absent, not merely zeroed")
    }

    /// Back-compat: a copy persisted before `proposalHandle`/`preparations` existed (neither key
    /// present) still decodes — handle `0`, empty preparations.
    func testMigrationScheduleLegacyJSONWithoutHandleOrPreparationsStillDecodes() throws {
        let legacyJSON = """
        {"transfers":[],"estimatedDurationHours":3}
        """

        let decoded = try JSONDecoder().decode(MigrationSchedule.self, from: Data(legacyJSON.utf8))

        XCTAssertEqual(decoded.transfers, [])
        XCTAssertEqual(decoded.estimatedDurationHours, 3)
        XCTAssertEqual(decoded.proposalHandle, 0)
        XCTAssertEqual(decoded.preparations, [])
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
    /// evaluating on the first subscriber (0 -> 1), and stop again once the last one detaches
    /// (1 -> 0). OBSERVABLE REWIRED 2026-08-05: the old probe was the `readyBroadcastProvider`
    /// invocation count, deleted with the gate's forward-looking clause (D1) — the injected
    /// clock now stands in, since every recompute (and each ticker iteration's delay
    /// computation) reads `now()`, while an idle, unsubscribed gate reads it never.
    func testTickerTicksOnlyWhileSubscribed() async throws {
        let clock = CountingClock(referenceDate)
        let gate = MigrationSyncGate(
            directory: testGeneralStorageDirectory,
            accountUUID: accountA,
            tickInterval: 0.02,
            now: { clock.tick() },
            logger: logger
        )

        // No subscriber yet: several tick intervals' worth of real time must produce no reads
        // beyond construction's own.
        let countAfterInit = clock.count
        try await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertEqual(clock.count, countAfterInit, "the ticker must not run with no subscriber attached")

        // Attaching a subscriber starts evaluation: the clock-read count must grow.
        let cancellable = gate.blockedStream.sink { _ in }
        let deadline = Date().addingTimeInterval(2)
        while clock.count < countAfterInit + 4, Date() < deadline {
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        XCTAssertGreaterThanOrEqual(clock.count, countAfterInit + 4, "the ticker must evaluate while subscribed")

        // Detaching stops it: the count must stop growing across a further quiet period.
        cancellable.cancel()
        // A tick may already be in flight at the moment of cancellation; let it settle before
        // snapshotting the count both sides of the quiet period.
        try await Task.sleep(nanoseconds: 50_000_000)
        let countAfterCancel = clock.count
        try await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertEqual(clock.count, countAfterCancel, "the ticker must stop once the last subscriber detaches")
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

    /// Subscribe-time value, "blocked" half: when the gate file already carries a live in-flight
    /// marker at init -- a second gate instance over a file a prior instance already wrote via
    /// `markBroadcastInFlight()`, standing in for a relaunch mid-broadcast -- the very first
    /// (synchronous) emission is `true`, without waiting for any tick. Exercises
    /// `MigrationSyncGate`'s documented init-time seed (loads `cachedInFlightUntil` from the file
    /// once, then seeds `blockedSubject` from it) through the public `blockedStream`, complementing
    /// `testPersistedInFlightMarkerRoundTripsThroughAFreshGateInstance` above (which checks the same
    /// init-time load via `currentInFlightUntil()`/`currentlyBlocked()` rather than the stream).
    func testBlockedStreamSubscribeTimeSeedIsTrueWhenAlreadyLiveInTheGateFileAtInit() {
        let clock = TestClock(referenceDate)
        let firstLaunchGate = makeGate(account: accountA, clock: clock)
        firstLaunchGate.markBroadcastInFlight()

        let secondLaunchGate = makeGate(account: accountA, clock: clock)
        var received: [Bool] = []
        let cancellable = secondLaunchGate.blockedStream.sink { received.append($0) }
        defer { cancellable.cancel() }

        XCTAssertEqual(received, [true])
    }

    /// Emission after `markBroadcastInFlight()`: a subscriber already attached before a submit must
    /// receive the fresh `true` value promptly, without waiting for the periodic ticker -- pinned by
    /// using a `tickInterval` far longer than the test's timeout, so only the marking call's own
    /// `recomputeAsync()` (never a coincidental tick) can possibly deliver it.
    ///
    /// Canary (R3-D report): commenting out `recomputeAsync()` inside `markBroadcastInFlight()`
    /// makes this test time out and fail red, since with that line gone nothing would ever publish a
    /// fresh value before the next tick 3600 s away.
    func testBlockedStreamEmitsTrueAfterMarkBroadcastInFlightWithoutWaitingForATick() async throws {
        let clock = TestClock(referenceDate)
        let gate = MigrationSyncGate(
            directory: testGeneralStorageDirectory,
            accountUUID: accountA,
            // Long enough that no real tick can plausibly fire during this test's timeout below.
            tickInterval: 3600,
            now: { clock.now },
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

        gate.markBroadcastInFlight()

        await fulfillment(of: [trueReceivedWithNoTick], timeout: 5)
        XCTAssertEqual(received, [false, true])
    }


    // (The "overdue flips on" tick test was deleted 2026-08-05 with the gate's forward-looking
    // ready-broadcast clause — D1; see `MigrationSyncGate`'s type doc.
    // The ticker's remaining job is the in-flight marker's own self-expiry, pinned below; the
    // post-broadcast buffer that used to be the other half went on 2026-08-07.)

    /// Tick re-evaluation: with a live in-flight marker already seeded at subscribe time (so the
    /// gate reads `true`), advancing the INJECTED clock past the marker's self-expiry must have the
    /// next tick re-evaluate to `false`. Uses a fresh gate over a file a prior instance already
    /// wrote via `markBroadcastInFlight()` (rather than arming the gate under test) precisely so the
    /// `true` -> `false` transition observed here is unambiguously a TICK's doing, not another
    /// marking-triggered recompute -- that path is
    /// `testBlockedStreamEmitsTrueAfterMarkBroadcastInFlightWithoutWaitingForATick` above.
    func testBlockedStreamTickEmitsFalseOnceTheInjectedClockPassesTheMarkerExpiry() async throws {
        let clock = TestClock(referenceDate)
        let firstLaunchGate = makeGate(account: accountA, clock: clock)
        firstLaunchGate.markBroadcastInFlight()

        let gate = MigrationSyncGate(
            directory: testGeneralStorageDirectory,
            accountUUID: accountA,
            tickInterval: 0.02,
            now: { clock.now },
            logger: logger
        )

        var received: [Bool] = []
        let falseAfterExpiry = expectation(description: "a tick re-evaluates false once the marker has expired")
        let cancellable = gate.blockedStream.sink { value in
            received.append(value)
            if value == false { falseAfterExpiry.fulfill() }
        }
        defer { cancellable.cancel() }
        XCTAssertEqual(received, [true], "precondition: the live marker seeds true at subscribe time")

        // Advance the injected clock past the persisted marker expiry; the next tick must
        // re-evaluate to false.
        clock.now = referenceDate.addingTimeInterval(MigrationSyncGate.broadcastInFlightGuardDuration + 1)

        await fulfillment(of: [falseAfterExpiry], timeout: 5)
        XCTAssertEqual(received, [true, false])
    }

    /// Duplicate collapse: several ticks that all agree with the already-published value must not
    /// produce any additional emissions -- pins `.removeDuplicates()` in `blockedStream`'s pipeline.
    func testBlockedStreamCollapsesConsecutiveIdenticalTickEvaluationsIntoNoExtraEmissions() async throws {
        let clock = CountingClock(referenceDate)
        let gate = MigrationSyncGate(
            directory: testGeneralStorageDirectory,
            accountUUID: accountA,
            tickInterval: 0.02,
            now: { clock.tick() },
            logger: logger
        )

        var received: [Bool] = []
        let cancellable = gate.blockedStream.sink { received.append($0) }
        defer { cancellable.cancel() }
        XCTAssertEqual(received, [false], "precondition: fresh gate seeds false")

        // Recompute activity is observed through the injected clock (see
        // `testTickerTicksOnlyWhileSubscribed`'s rewired observable): wait until enough reads
        // prove several recomputes ran, rather than merely that nothing ticked.
        let baseline = clock.count
        let deadline = Date().addingTimeInterval(5)
        while clock.count < baseline + 6, Date() < deadline {
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        XCTAssertGreaterThanOrEqual(clock.count, baseline + 6, "several ticks must actually have evaluated")

        XCTAssertEqual(received, [false], "ticks agreeing with the seed must not add any emissions")
    }

    // MARK: - Concurrent send serialization

    // (Finding 7's stale-recompute reproduction was deleted 2026-08-05: it held generation 1
    // suspended INSIDE `recompute()` via the `readyBroadcastProvider` await, and that await —
    // the only suspension point the recompute path ever had — is gone with the gate's
    // forward-looking clause (D1). `recompute()` now runs draw-to-publish without suspending,
    // so the reproduced interleaving is unbuildable; the generation-ordered `publish` funnel
    // stays as the belt for plain cross-thread races.)


    // MARK: - Lock split regression (deadlock on synchronous cancel during publish)

    /// Regression for the reviewer's Important finding on the sync-gate lock split: a `blockedStream`
    /// subscriber that cancels *synchronously*, from inside its own `receiveValue` handler, in
    /// response to a value delivered through `publish(_:generation:)` (a marking-triggered
    /// emission -- NOT the synchronous subscribe-time seed, which bypasses `publish(_:generation:)`
    /// entirely) drives Combine's `receiveCancel` synchronously on the SAME thread, still inside
    /// `publish`'s lock critical section around `blockedSubject.send(_:)`. Before the lock split this
    /// was a single `sendLock`: `subscriberDetached()`'s re-entrant `lock()` on that same,
    /// already-held, non-recursive `NSLock` deadlocked the thread and left the lock forever held,
    /// wedging the whole gate -- every later `currentInFlightUntil()` / `currentlyBlocked()` /
    /// `markBroadcastInFlight()` / subscribe would hang too. After the split, `subscriberDetached()` only
    /// ever touches `subscriptionLock`, a separate, uncontended lock, so the re-entrant call during
    /// `send` no longer contends anything `publish()` holds.
    ///
    /// The risky calls run on a background `Task`, gated by expectations fulfilled from inside the
    /// relevant closures, with the outer `fulfillment` below as the single bound on the whole
    /// scenario: pre-fix, the synchronous `cancel()` deadlocks that Task's thread permanently, so
    /// nothing after it -- including the second `markBroadcastInFlight()`, which needs the very same
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
            // deterministically `false` here (fresh gate, nothing in flight yet) -- only a `true`
            // value can be the marking-triggered publish this test targets.
            if value {
                cancellable?.cancel()
                publishedValueCancelledSynchronously.fulfill()
            }
        }
        XCTAssertEqual(received, [false], "precondition: the synchronous seed must be the unblocked value")

        let secondSubscriberReceivedAValue = expectation(description: "a new subscriber after the scenario still receives a value")
        let scenarioCompleted = expectation(description: "gate remains usable after the cancel-during-publish scenario")

        Task {
            // Triggers a recompute that publishes `true` (a live marker now exists); the
            // synchronous cancel above fires from inside that publish's `send`.
            gate.markBroadcastInFlight()

            // Pre-fix this never fires: the sink's `receiveValue` is stuck inside
            // `cancellable?.cancel()` -> `subscriberDetached()` re-locking the same lock `publish()`
            // is still holding.
            await self.fulfillment(of: [publishedValueCancelledSynchronously], timeout: 5)
            XCTAssertEqual(received, [false, true])

            // The gate must not be wedged: a fresh `markBroadcastInFlight()` plus a brand-new
            // subscriber must still work. Pre-fix, the lock is left permanently held by the
            // deadlocked cancel above, so this direct, synchronous call would hang right here too.
            gate.markBroadcastInFlight()
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
            try await broadcaster.broadcast(rawTransaction: Data([0x01]), to: endpoint, useTor: true, onWillSubmit: { })
        }
        await factory.awaitCallsStarted(1)
        let second = Task {
            try await broadcaster.broadcast(rawTransaction: Data([0x02]), to: endpoint, useTor: true, onWillSubmit: { })
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
            _ = try await broadcaster.broadcast(rawTransaction: Data([0x03]), to: endpoint, useTor: true, onWillSubmit: { })
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
            MigrationBroadcaster.map(outcome: .transportError, successTxId: mappedTxId),
            MigrationTransferResult.networkError(retryable: true)
        )
    }

    func testMapGenericRejectionIsInvalidNote() {
        XCTAssertEqual(
            MigrationBroadcaster.map(outcome: .rejected(errorCode: -25, message: "missing inputs"), successTxId: mappedTxId),
            MigrationTransferResult.invalidNote
        )
    }

    func testMapExpiringSoonRejectionIsExpired() {
        XCTAssertEqual(
            MigrationBroadcaster.map(outcome: .rejected(errorCode: -26, message: "tx-expiring-soon"), successTxId: mappedTxId),
            MigrationTransferResult.expired
        )
    }

    func testMapExpiredRejectionIsCaseInsensitive() {
        XCTAssertEqual(
            MigrationBroadcaster.map(outcome: .rejected(errorCode: -1, message: "Transaction has EXPIRED"), successTxId: mappedTxId),
            MigrationTransferResult.expired
        )
    }

    func testMapSuccessCarriesProvidedTxId() {
        XCTAssertEqual(
            MigrationBroadcaster.map(outcome: .submitted, successTxId: mappedTxId),
            MigrationTransferResult.success(txId: mappedTxId)
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
                successTxId: mappedTxId
            ),
            MigrationTransferResult.success(txId: mappedTxId)
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
                MigrationBroadcaster.map(outcome: .rejected(errorCode: -26, message: message), successTxId: mappedTxId),
                MigrationTransferResult.success(txId: mappedTxId),
                "expected duplicate message \"\(message)\" to map to success"
            )
        }
    }

    func testMapDuplicateRejectionMessageMatchIsCaseInsensitive() {
        XCTAssertEqual(
            MigrationBroadcaster.map(
                outcome: .rejected(errorCode: -26, message: "Transaction ALREADY In Block Chain"),
                successTxId: mappedTxId
            ),
            MigrationTransferResult.success(txId: mappedTxId)
        )
    }

    /// The duplicate check runs before the expiry sniffing: the "already known" RPC code identifies
    /// a duplicate even when the message alone would read as an expiry.
    func testMapDuplicateDetectionWinsOverExpirySniffing() {
        XCTAssertEqual(
            MigrationBroadcaster.map(
                outcome: .rejected(errorCode: -27, message: "transaction has expired"),
                successTxId: mappedTxId
            ),
            MigrationTransferResult.success(txId: mappedTxId)
        )
    }

    /// Fragment specificity: a message merely containing "already" (an already-spent input) is not a
    /// duplicate re-submission and stays on the invalidNote path.
    func testMapNonDuplicateRejectionMentioningAlreadyStaysInvalidNote() {
        XCTAssertEqual(
            MigrationBroadcaster.map(
                outcome: .rejected(errorCode: -25, message: "input already spent"),
                successTxId: mappedTxId
            ),
            MigrationTransferResult.invalidNote
        )
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
        welding.proposeSendMaxTransferAccountUUIDRecipientMemoOrchardOnlyThrowableError =
            ZcashError.rustProposeSendMaxTransfer(RedactedRustError(kind: .unclassified, message: "boom"))
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
        let txid = TxId([UInt8](repeating: 0xCD, count: 32))

        try await migration.recordImmediateMigration(txid: txid)

        XCTAssertEqual(receivedTxid, Data(txid.id))
        XCTAssertEqual(receivedAccount, accountA)
    }

    // MARK: - Residual locking and the run-count estimate (delegation)

    /// `lockMigrationResidual()` is a straight delegation to the welding lock call, bound to this
    /// actor's own account: the total the welding reports comes back untouched.
    func testLockMigrationResidualForwardsTotalAndAccount() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.lockMigrationResidualAccountUUIDReturnValue = Zatoshi(38_000)
        let migration = makeMigration(welding: welding, account: accountA)

        let locked = try await migration.lockMigrationResidual()

        XCTAssertEqual(locked, Zatoshi(38_000))
        XCTAssertEqual(welding.lockMigrationResidualAccountUUIDReceivedAccountUUID, accountA)
    }

    /// A zero locked total is a legitimate outcome (nothing was spendable, or everything spendable
    /// was already locked), not an error: it passes through unchanged.
    func testLockMigrationResidualZeroTotalPassesThrough() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.lockMigrationResidualAccountUUIDReturnValue = Zatoshi.zero
        let migration = makeMigration(welding: welding, account: accountA)

        let locked = try await migration.lockMigrationResidual()

        XCTAssertEqual(locked, Zatoshi.zero)
    }

    /// The concurrent-lock race (and any other engine failure) surfaces as the welding's own
    /// `rustMigrationLockResidual`, rethrown untouched so the caller can retry.
    func testLockMigrationResidualRethrowsWhenWeldingThrows() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.lockMigrationResidualAccountUUIDThrowableError = ZcashError.rustMigrationLockResidual("boom")
        let migration = makeMigration(welding: welding, account: accountA)

        do {
            _ = try await migration.lockMigrationResidual()
            XCTFail("Expected lockMigrationResidual to rethrow the welding error")
        } catch ZcashError.rustMigrationLockResidual {
            // expected
        } catch {
            XCTFail("Expected rustMigrationLockResidual but got \(error)")
        }
    }

    /// `unlockMigrationResidual()` is the release half: a straight delegation returning the
    /// welding's cleared-lock count, bound to this actor's own account.
    func testUnlockMigrationResidualForwardsCountAndAccount() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.unlockMigrationResidualAccountUUIDReturnValue = 4
        let migration = makeMigration(welding: welding, account: accountA)

        let cleared = try await migration.unlockMigrationResidual()

        XCTAssertEqual(cleared, 4)
        XCTAssertEqual(welding.unlockMigrationResidualAccountUUIDReceivedAccountUUID, accountA)
    }

    func testUnlockMigrationResidualRethrowsWhenWeldingThrows() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.unlockMigrationResidualAccountUUIDThrowableError = ZcashError.rustMigrationUnlockResidual("boom")
        let migration = makeMigration(welding: welding, account: accountA)

        do {
            _ = try await migration.unlockMigrationResidual()
            XCTFail("Expected unlockMigrationResidual to rethrow the welding error")
        } catch ZcashError.rustMigrationUnlockResidual {
            // expected
        } catch {
            XCTFail("Expected rustMigrationUnlockResidual but got \(error)")
        }
    }

    /// `estimateMigrationRuns()` returns the welding's estimate untouched: every per-run field
    /// (crossings, preparation layers/transactions, migratable value) and the final residual flow
    /// through, so the model's derived queries answer over exactly what the engine reported.
    func testEstimateMigrationRunsReturnsWeldingEstimateUntouched() async throws {
        let welding = ZcashRustBackendWeldingMock()
        let estimate = Self.makeRunEstimate()
        welding.estimateMigrationRunsAccountUUIDReturnValue = estimate
        let migration = makeMigration(welding: welding, account: accountA)

        let returned = try await migration.estimateMigrationRuns()

        XCTAssertEqual(returned, estimate)
        XCTAssertEqual(welding.estimateMigrationRunsAccountUUIDReceivedAccountUUID, accountA)
    }

    func testEstimateMigrationRunsRethrowsWhenWeldingThrows() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.estimateMigrationRunsAccountUUIDThrowableError = ZcashError.rustMigrationEstimateRuns("boom")
        let migration = makeMigration(welding: welding, account: accountA)

        do {
            _ = try await migration.estimateMigrationRuns()
            XCTFail("Expected estimateMigrationRuns to rethrow the welding error")
        } catch ZcashError.rustMigrationEstimateRuns {
            // expected
        } catch {
            XCTFail("Expected rustMigrationEstimateRuns but got \(error)")
        }
    }

    // MARK: - Broadcast composition (I1 canary)

    /// Canary for the privacy-critical composition in `OrchardMigration.broadcastAndRecord`: a
    /// pre-broadcast Tor failure must fail closed — throw, record nothing, and leave the sync gate
    /// open (the in-flight marker armed as a belt is cleared, since nothing reached the network).
    /// Drives the real actor through the ``MigrationBroadcasting`` seam (a fake transport), a real
    /// ``MigrationSyncGate``, and a welding mock, so a future regression that reorders "record"
    /// before "broadcast", or adds a direct-transport fallback on Tor failure, would turn this test
    /// red.
    func testPerformBroadcastFailsClosedOnTorUnavailableWithoutRecordingOrGating() async throws {
        let prepared = PreparedMigrationTransfer(
            id: 0,
            txid: TxId([UInt8](repeating: 0xAB, count: 32)),
            pczt: Data([0x01, 0x02])
        )
        let welding = ZcashRustBackendWeldingMock()
        welding.migrationTakeBroadcastTransactionIdForReturnValue = prepared
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
            _ = try await migration.performBroadcast(
                MigrationBroadcastInstruction(id: prepared.id),
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
        XCTAssertNil(gate.currentInFlightUntil(), "a fail-closed pre-submit throw must leave no marker behind")
        XCTAssertFalse(gate.currentlyBlocked())
    }

    // MARK: - Helpers

    /// The top-level keys of the gate file at `fileURL`, read as raw JSON rather than through
    /// `GateState` — so a field the envelope no longer declares is still visible to an assertion.
    private func persistedGateKeys(at fileURL: URL) throws -> [String] {
        let json = try XCTUnwrap(
            JSONSerialization.jsonObject(with: try Data(contentsOf: fileURL)) as? [String: Any]
        )
        return Array(json.keys)
    }

    private func makeGate(account: AccountUUID, clock: TestClock) -> MigrationSyncGate {
        MigrationSyncGate(
            directory: testGeneralStorageDirectory,
            accountUUID: account,
            // A long tick keeps the background re-evaluation out of these deterministic assertions.
            tickInterval: 3600,
            now: { clock.now },
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
                id: UInt32(index),
                amount: amount,
                anchorHeight: 2_000_000 + index,
                nextExecutableAfterHeight: 2_000_100 + index,
                expiryHeight: 2_010_000 + index
            )
            transfers.append(transfer)
        }
        return MigrationSchedule(transfers: transfers, estimatedDurationHours: count * 6, proposalHandle: 1, preparations: [])
    }

    /// Builds a deliberately non-trivial `MigrationRunEstimate` fixture: two runs whose fields are
    /// all distinct (so any cross-wiring of a field in the pass-through would break equality) plus
    /// a non-zero final residual.
    static func makeRunEstimate() -> MigrationRunEstimate {
        MigrationRunEstimate(
            runs: [
                MigrationRunEstimate.Run(
                    migratable: Zatoshi(75_000_000),
                    crossings: 15,
                    preparationLayers: 2,
                    preparationTransactions: 5,
                    actions: 125,
                    keystoneSigningSessions: 2
                ),
                MigrationRunEstimate.Run(
                    migratable: Zatoshi(1_200_000),
                    crossings: 3,
                    preparationLayers: 1,
                    preparationTransactions: 1,
                    actions: 25,
                    keystoneSigningSessions: 1
                )
            ],
            finalResidual: Zatoshi(42_000)
        )
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

/// A `now` closure double that counts its reads — the rewired observable for the
/// subscription-gated-ticker pins above (the old observable, `readyBroadcastProvider`, was
/// deleted with the gate's forward-looking clause — D1). Always returns the same fixed instant,
/// so the counted reads never move any time-based condition.
private final class CountingClock: @unchecked Sendable {
    private let lock = NSLock()
    private let fixed: Date
    private var reads = 0

    init(_ fixed: Date) {
        self.fixed = fixed
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return reads
    }

    func tick() -> Date {
        lock.lock()
        defer { lock.unlock() }
        reads += 1
        return fixed
    }
}

// `GatedTorClientFactory` and `StubTorBootstrapError` were promoted to
// `Tests/TestUtils/MigrationTestDoubles.swift` so `OrchardMigrationHostTests` can reuse them for the
// shared-broadcaster single-bootstrap canary.
