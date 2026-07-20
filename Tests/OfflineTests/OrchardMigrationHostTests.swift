//
//  OrchardMigrationHostTests.swift
//  OfflineTests
//
//  Tests for `OrchardMigrationHost`: the per-synchronizer owner of the migration machinery. Driven
//  through the host's injecting initializer against `ZcashRustBackendWeldingMock`, the shared
//  `MigrationBroadcasting` seam, and real temp-file-backed `MigrationSyncGate`s (as established by
//  the other migration test files). No network, no real FFI. Covers per-account actor identity and
//  caching, the single shared Tor bootstrap across accounts, the wallet-scope `isSyncBlocked()`
//  predicate (including dormant-account enumeration and degrade-open), and the wallet-scope
//  `syncBlockedStream`.
//

import Combine
import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class OrchardMigrationHostTests: ZcashTestCase {
    private let accountA = AccountUUID(id: [UInt8](repeating: 0x0A, count: 16))
    private let accountB = AccountUUID(id: [UInt8](repeating: 0x0B, count: 16))
    private let accountD = AccountUUID(id: [UInt8](repeating: 0x0D, count: 16))
    private let referenceDate = Date(timeIntervalSince1970: 1_700_000_000)
    private let buffer: TimeInterval = 600
    private let submissionEndpoint = LightWalletEndpoint(address: "submit.example", port: 9067)

    private var clock: TestClock!

    override func setUp() {
        super.setUp()
        clock = TestClock(referenceDate)
    }

    override func tearDown() {
        clock = nil
        super.tearDown()
    }

    // MARK: - Per-account identity and caching

    /// Same account resolves to the same cached actor; distinct accounts get distinct actors; and
    /// driving each actor reaches the welding with that actor's own account UUID.
    func testMigrationForAccountCachesPerAccountAndRoutesTheRightUUID() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.migrationStateForReturnValue = MigrationState.notStarted
        welding.migrationHasOverdueTransfersForReturnValue = false
        let host = makeHost(welding: welding, broadcaster: ScriptedBroadcaster(script: .throwing(ZcashError.migrationTorUnavailable)))

        let firstA = await host.migration(for: accountA)
        let secondA = await host.migration(for: accountA)
        let firstB = await host.migration(for: accountB)

        XCTAssertTrue(firstA === secondA, "the same account must resolve to the same cached actor")
        XCTAssertFalse(firstA === firstB, "distinct accounts must get distinct actors")

        // Driving each actor (sequentially) reaches the welding with that actor's own account UUID.
        _ = try await firstA.migrationState()
        XCTAssertEqual(welding.migrationStateForReceivedAccount, accountA)
        _ = try await firstB.migrationState()
        XCTAssertEqual(welding.migrationStateForReceivedAccount, accountB)
    }

    // MARK: - Shared broadcaster (single Tor bootstrap across accounts)

    /// Shared-broadcaster canary: two accounts each broadcasting (over Tor) through their own actor go
    /// through the host's ONE `MigrationBroadcaster`, so exactly ONE Tor bootstrap happens — counted
    /// via the broadcaster's injectable `torClientFactory`. If each actor built its own broadcaster
    /// (the latent multi-account hazard this host closes), the count would be two. Held gated and
    /// resolved with a failure so no real Arti runtime/connection is ever driven (offline).
    func testTwoAccountsBroadcastingShareASingleTorBootstrap() async throws {
        let factory = GatedTorClientFactory()
        let sharedBroadcaster = MigrationBroadcaster(
            torDirURL: testGeneralStorageDirectory,
            logger: logger,
            torClientFactory: factory.make
        )

        let prepared = PreparedMigrationTransfer(
            id: "transfer-0",
            txid: Data(repeating: 0xAB, count: 32),
            pczt: Data([0x01, 0x02])
        )
        // A fresh mock per account keeps the two concurrent broadcast flows off a shared mutable mock.
        let perAccountFactory: (AccountUUID, any MigrationBroadcasting) -> OrchardMigration = { [testGeneralStorageDirectory, buffer, clock] accountUUID, broadcaster in
            let accountWelding = ZcashRustBackendWeldingMock()
            accountWelding.migrationNextDueTransferForReturnValue = prepared
            accountWelding.migrationExtractBroadcastTxPcztForReturnValue = Data([0x07])
            accountWelding.migrationHasOverdueTransfersForReturnValue = false
            return OrchardMigration(
                welding: accountWelding,
                accountUUID: accountUUID,
                broadcaster: broadcaster,
                syncGate: MigrationSyncGate(
                    directory: testGeneralStorageDirectory!,
                    accountUUID: accountUUID,
                    bufferDuration: buffer,
                    tickInterval: 3600,
                    now: { clock!.now },
                    overdueProvider: { false },
                    logger: logger
                ),
                logger: logger
            )
        }

        let clockValue = clock!
        let host = OrchardMigrationHost(
            welding: ZcashRustBackendWeldingMock(),
            sharedBroadcaster: sharedBroadcaster,
            generalStorageURL: testGeneralStorageDirectory,
            tickInterval: 3600,
            now: { clockValue.now },
            logger: logger,
            actorFactory: perAccountFactory
        )

        let migrationA = await host.migration(for: accountA)
        let migrationB = await host.migration(for: accountB)
        let options = MigrationNetworkPrivacyOptions(useTor: true, submissionEndpoint: submissionEndpoint)

        let taskA = Task { try await migrationA.executeNextPendingTransfer(options: options) }
        // Wait for account A's broadcast to have started the (single) bootstrap.
        await factory.awaitCallsStarted(1)
        let taskB = Task { try await migrationB.executeNextPendingTransfer(options: options) }
        // Scheduling aid only: let B reach the shared broadcaster's cached bootstrap while A holds it.
        for _ in 0..<50 {
            await Task.yield()
        }

        let countWhileInFlight = await factory.callCount
        XCTAssertEqual(countWhileInFlight, 1, "two accounts must share ONE Tor bootstrap through the host's shared broadcaster")

        await factory.resolve(throwing: StubTorBootstrapError())
        await assertThrowsMigrationTorUnavailable(taskA)
        await assertThrowsMigrationTorUnavailable(taskB)

        let finalCount = await factory.callCount
        XCTAssertEqual(finalCount, 1, "the failing bootstrap was shared by both accounts, not driven twice")
    }

    // MARK: - Wallet-scope isSyncBlocked (dormant enumeration + degrade-open)

    /// Dormant-account enumeration: a persisted gate file for an account whose actor is never created
    /// still blocks sync. Account B's privacy buffer is written by a throwaway gate; a FRESH host that
    /// never instantiates B's actor enumerates [A, B] via the welding, reads B's gate file directly,
    /// and reports blocked while the buffer is live — then unblocked once the injected clock passes it.
    func testIsSyncBlockedEnumeratesDormantAccountsFromTheirPersistedGateFiles() async throws {
        // Persist a live privacy buffer for B (resumeAt = referenceDate + buffer), then discard the gate.
        let dormantGateB = MigrationSyncGate(
            directory: testGeneralStorageDirectory,
            accountUUID: accountB,
            bufferDuration: buffer,
            tickInterval: 3600,
            now: { [clock] in clock!.now },
            overdueProvider: { false },
            logger: logger
        )
        dormantGateB.markBroadcast()

        let welding = ZcashRustBackendWeldingMock()
        welding.listAccountsReturnValue = [makeAccount(accountA), makeAccount(accountB)]
        welding.migrationHasOverdueTransfersForReturnValue = false
        let host = makeHost(welding: welding, broadcaster: ScriptedBroadcaster(script: .throwing(ZcashError.migrationTorUnavailable)))

        let blockedWhileBuffered = await host.isSyncBlocked()
        XCTAssertTrue(blockedWhileBuffered, "a dormant account's live gate file must block sync after a fresh launch")

        clock.now = referenceDate.addingTimeInterval(buffer + 1)
        let blockedAfterExpiry = await host.isSyncBlocked()
        XCTAssertFalse(blockedAfterExpiry, "once the buffer elapses and nothing is overdue, sync is no longer blocked")
    }

    /// Degrade-open: if the welding's account enumeration throws, `isSyncBlocked()` returns `false`
    /// (sync allowed) and never crashes — matching `OrchardMigration.isSyncBlocked()`'s behavior.
    func testIsSyncBlockedDegradesOpenWhenAccountEnumerationThrows() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.listAccountsThrowableError = StubHostWeldingError()
        let host = makeHost(welding: welding, broadcaster: ScriptedBroadcaster(script: .throwing(ZcashError.migrationTorUnavailable)))

        let blocked = await host.isSyncBlocked()
        XCTAssertFalse(blocked, "an account-enumeration failure must degrade open, not crash")
    }

    // MARK: - Wallet-scope syncBlockedStream

    /// Subscribe-time seed: a fresh host with nothing blocked seeds `false` on the very first
    /// (synchronous) emission, before the subscription-started ticker can schedule its first recompute.
    func testSyncBlockedStreamSeedsFalseOnSubscribe() {
        let welding = ZcashRustBackendWeldingMock()
        welding.listAccountsReturnValue = []
        let host = makeHost(welding: welding, broadcaster: ScriptedBroadcaster(script: .throwing(ZcashError.migrationTorUnavailable)))

        var received: [Bool] = []
        let cancellable = host.syncBlockedStream.sink { received.append($0) }
        defer { cancellable.cancel() }

        XCTAssertEqual(received, [false])
    }

    /// Emission after a hosted actor broadcasts: with a subscriber already attached and the account's
    /// actor created, a successful broadcast through that actor marks its gate, which the host observes
    /// through the account's per-account stream and re-evaluates the wallet predicate — publishing
    /// `true` without waiting for the (long) periodic ticker.
    func testSyncBlockedStreamEmitsTrueAfterAHostedActorBroadcasts() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.listAccountsReturnValue = [makeAccount(accountA)]
        welding.migrationHasOverdueTransfersForReturnValue = false
        welding.migrationNextDueTransferForReturnValue = PreparedMigrationTransfer(
            id: "transfer-0",
            txid: Data(repeating: 0xAB, count: 32),
            pczt: Data([0x01, 0x02])
        )
        welding.migrationExtractBroadcastTxPcztForReturnValue = Data([0x07])
        welding.migrationRecordTransferResultTransferIdResultForClosure = { _, _, _ in }

        // A tick far longer than the timeout, so only the broadcast (not a coincidental tick) can
        // deliver the `true`.
        let host = makeHost(
            welding: welding,
            broadcaster: ScriptedBroadcaster(script: .outcome(.submitted)),
            tickInterval: 3600,
            gateTickInterval: 3600
        )

        var received: [Bool] = []
        let blockedEmitted = expectation(description: "wallet stream emitted true after a hosted broadcast")
        let cancellable = host.syncBlockedStream.sink { value in
            received.append(value)
            if value {
                blockedEmitted.fulfill()
            }
        }
        defer { cancellable.cancel() }

        let migration = await host.migration(for: accountA)
        _ = try await migration.executeNextPendingTransfer(
            options: MigrationNetworkPrivacyOptions(useTor: false, submissionEndpoint: submissionEndpoint)
        )

        await fulfillment(of: [blockedEmitted], timeout: 5)
        XCTAssertEqual(received.first, false, "precondition: the fresh host seeds false")
        XCTAssertEqual(received.last, true)
    }

    /// Ticker re-evaluation catching a dormant account's expiry: with only the periodic ticker (no
    /// actor ever created for the account), the stream reports `true` while the dormant account's
    /// buffer is live and re-evaluates to `false` once the injected clock passes it.
    func testSyncBlockedStreamTickerCatchesADormantAccountExpiry() async throws {
        let dormantGateD = MigrationSyncGate(
            directory: testGeneralStorageDirectory,
            accountUUID: accountD,
            bufferDuration: buffer,
            tickInterval: 3600,
            now: { [clock] in clock!.now },
            overdueProvider: { false },
            logger: logger
        )
        dormantGateD.markBroadcast()

        let welding = ZcashRustBackendWeldingMock()
        welding.listAccountsReturnValue = [makeAccount(accountD)]
        welding.migrationHasOverdueTransfersForReturnValue = false
        let host = makeHost(
            welding: welding,
            broadcaster: ScriptedBroadcaster(script: .throwing(ZcashError.migrationTorUnavailable)),
            tickInterval: 0.02
        )

        var received: [Bool] = []
        var sawBlocked = false
        let blockedByTick = expectation(description: "a tick observed the dormant account's live buffer")
        let unblockedByTick = expectation(description: "a tick observed the dormant account's buffer expire")
        let cancellable = host.syncBlockedStream.sink { value in
            received.append(value)
            if value {
                sawBlocked = true
                blockedByTick.fulfill()
            } else if sawBlocked {
                unblockedByTick.fulfill()
            }
        }
        defer { cancellable.cancel() }

        await fulfillment(of: [blockedByTick], timeout: 5)

        clock.now = referenceDate.addingTimeInterval(buffer + 1)
        await fulfillment(of: [unblockedByTick], timeout: 5)
        XCTAssertEqual(received.last, false)
    }

    /// Duplicate collapse: several ticks that all agree with the already-published value produce no
    /// extra emissions — pins `.removeDuplicates()` in the wallet stream's pipeline. A counting
    /// welding proves multiple recomputes actually ran.
    func testSyncBlockedStreamCollapsesConsecutiveIdenticalTicks() async throws {
        let counter = CallCounter()
        let tickedThreeTimes = expectation(description: "the ticker re-evaluated at least three times")
        let welding = ZcashRustBackendWeldingMock()
        welding.listAccountsClosure = {
            let count = await counter.increment()
            if count == 3 {
                tickedThreeTimes.fulfill()
            }
            // No accounts: every recompute agrees with the fresh-host `false` seed.
            return []
        }
        let host = makeHost(
            welding: welding,
            broadcaster: ScriptedBroadcaster(script: .throwing(ZcashError.migrationTorUnavailable)),
            tickInterval: 0.02
        )

        var received: [Bool] = []
        let cancellable = host.syncBlockedStream.sink { received.append($0) }
        defer { cancellable.cancel() }
        XCTAssertEqual(received, [false], "precondition: fresh host seeds false")

        await fulfillment(of: [tickedThreeTimes], timeout: 5)
        XCTAssertEqual(received, [false], "three ticks agreeing with the seed must not add emissions")
    }

    // MARK: - Helpers

    private func makeHost(
        welding: ZcashRustBackendWeldingMock,
        broadcaster: any MigrationBroadcasting,
        tickInterval: TimeInterval = 3600,
        gateTickInterval: TimeInterval = 3600
    ) -> OrchardMigrationHost {
        let clockValue = clock!
        return OrchardMigrationHost(
            welding: welding,
            sharedBroadcaster: broadcaster,
            generalStorageURL: testGeneralStorageDirectory,
            tickInterval: tickInterval,
            now: { clockValue.now },
            logger: logger,
            actorFactory: makeActorFactory(welding: welding, gateTickInterval: gateTickInterval)
        )
    }

    private func makeActorFactory(
        welding: ZcashRustBackendWeldingMock,
        gateTickInterval: TimeInterval
    ) -> (AccountUUID, any MigrationBroadcasting) -> OrchardMigration {
        let storage = testGeneralStorageDirectory!
        let clockValue = clock!
        let bufferDuration = buffer
        return { accountUUID, broadcaster in
            OrchardMigration(
                welding: welding,
                accountUUID: accountUUID,
                broadcaster: broadcaster,
                syncGate: MigrationSyncGate(
                    directory: storage,
                    accountUUID: accountUUID,
                    bufferDuration: bufferDuration,
                    tickInterval: gateTickInterval,
                    now: { clockValue.now },
                    overdueProvider: { (try? await welding.migrationHasOverdueTransfers(for: accountUUID)) ?? false },
                    logger: logger
                ),
                logger: logger
            )
        }
    }

    private func makeAccount(_ uuid: AccountUUID) -> Account {
        Account(
            id: uuid,
            name: nil,
            keySource: nil,
            seedFingerprint: nil,
            hdAccountIndex: nil,
            ufvk: nil,
            uivk: nil
        )
    }

    private func assertThrowsMigrationTorUnavailable(_ task: Task<MigrationTransferResult?, Error>) async {
        do {
            _ = try await task.value
            XCTFail("Expected migrationTorUnavailable to be thrown")
        } catch ZcashError.migrationTorUnavailable {
            // expected
        } catch {
            XCTFail("Expected migrationTorUnavailable but got \(error)")
        }
    }
}

/// A generic, non-`ZcashError` failure for stubbing a welding enumeration error in the host's
/// degrade-open path.
private struct StubHostWeldingError: Error {}

/// A minimal thread-safe call counter for pinning "the ticker actually re-evaluated N times".
private actor CallCounter {
    private var count = 0

    func increment() -> Int {
        count += 1
        return count
    }
}
