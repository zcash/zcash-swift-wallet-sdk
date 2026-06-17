//
//  SubmitPlanStoreTests.swift
//  ZcashLightClientKitTests
//

import SQLite
import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class SubmitPlanStoreTests: ZcashTestCase {
    private var databaseURL: URL!

    override func setUp() async throws {
        try await super.setUp()
        databaseURL = testGeneralStorageDirectory.appendingPathComponent("submit_plans_test.db")
    }

    private func makeStore() -> SubmitPlanStore {
        SubmitPlanStore(databaseURL: databaseURL, logger: NullLogger())
    }

    private var endpointA: LightWalletEndpoint {
        LightWalletEndpoint(address: "a.example.com", port: 443, secure: true)
    }

    private var endpointB: LightWalletEndpoint {
        LightWalletEndpoint(address: "b.example.com", port: 9067, secure: false)
    }

    func testUnknownTransactionHasNoPlan() async {
        let store = makeStore()
        let plan = await store.plan(for: Data(repeating: 0x01, count: 32))
        XCTAssertNil(plan)
    }

    func testMarkAwaitingCreatesAwaitingPlan() async {
        let store = makeStore()
        let txId = Data(repeating: 0x02, count: 32)

        await store.markAwaitingSubmission(txIds: [txId])

        let plan = await store.plan(for: txId)
        XCTAssertEqual(plan, StoredSubmitPlan.awaiting)
    }

    func testRecordPlanTransitionsToReady() async {
        let store = makeStore()
        let txId = Data(repeating: 0x03, count: 32)

        await store.markAwaitingSubmission(txIds: [txId])
        await store.recordPlan(txId: txId, endpoints: [endpointA, endpointB])

        let plan = await store.plan(for: txId)
        XCTAssertEqual(plan, StoredSubmitPlan.ready([endpointA, endpointB]))
    }

    func testRecordPlanWithoutPriorAwaitingRowCreatesReadyPlan() async {
        let store = makeStore()
        let txId = Data(repeating: 0x04, count: 32)

        await store.recordPlan(txId: txId, endpoints: [endpointA])

        let plan = await store.plan(for: txId)
        XCTAssertEqual(plan, StoredSubmitPlan.ready([endpointA]))
    }

    func testMarkAwaitingDoesNotOverwriteRecordedPlan() async {
        let store = makeStore()
        let txId = Data(repeating: 0x05, count: 32)

        await store.recordPlan(txId: txId, endpoints: [endpointA])
        await store.markAwaitingSubmission(txIds: [txId])

        let plan = await store.plan(for: txId)
        XCTAssertEqual(plan, StoredSubmitPlan.ready([endpointA]))
    }

    func testPlansPersistAcrossStoreInstances() async {
        let txId = Data(repeating: 0x06, count: 32)
        let firstStore = makeStore()
        await firstStore.recordPlan(txId: txId, endpoints: [endpointA])

        let secondStore = makeStore()
        let plan = await secondStore.plan(for: txId)
        XCTAssertEqual(plan, StoredSubmitPlan.ready([endpointA]))
    }

    func testAllPlannedTransactionIdsListsEveryRow() async {
        let store = makeStore()
        let awaitingTxId = Data(repeating: 0x07, count: 32)
        let readyTxId = Data(repeating: 0x08, count: 32)

        await store.markAwaitingSubmission(txIds: [awaitingTxId])
        await store.recordPlan(txId: readyTxId, endpoints: [endpointA])

        let txIds = await store.allPlannedTransactionIds()
        XCTAssertEqual(Set(txIds), Set([awaitingTxId, readyTxId]))
    }

    func testDeletePlansRemovesOnlyGivenIds() async {
        let store = makeStore()
        let keptTxId = Data(repeating: 0x09, count: 32)
        let removedTxId = Data(repeating: 0x0A, count: 32)
        await store.recordPlan(txId: keptTxId, endpoints: [endpointA])
        await store.recordPlan(txId: removedTxId, endpoints: [endpointB])

        await store.deletePlans(txIds: [removedTxId])

        let removed = await store.plan(for: removedTxId)
        XCTAssertNil(removed)
        let kept = await store.plan(for: keptTxId)
        XCTAssertEqual(kept, StoredSubmitPlan.ready([endpointA]))
    }

    func testClearRemovesEverything() async {
        let store = makeStore()
        let txId = Data(repeating: 0x0B, count: 32)
        await store.recordPlan(txId: txId, endpoints: [endpointA])

        await store.clear()

        let plan = await store.plan(for: txId)
        XCTAssertNil(plan)
        let txIds = await store.allPlannedTransactionIds()
        XCTAssertTrue(txIds.isEmpty)
    }

    func testCorruptedEndpointsJSONIsTreatedAsAwaiting() async throws {
        let txId = Data(repeating: 0x0C, count: 32)
        let store = makeStore()
        await store.recordPlan(txId: txId, endpoints: [endpointA])

        // Corrupt the row behind the store's back.
        let connection = try Connection(databaseURL.path)
        try connection.run("UPDATE tx_submit_plans SET endpoints = 'not-json'")

        let freshStore = makeStore()
        let plan = await freshStore.plan(for: txId)
        XCTAssertEqual(plan, StoredSubmitPlan.awaiting)
    }

    func testUnopenableDatabaseReportsStoreUnavailable() async {
        // A directory at the database path makes SQLite open fail.
        let blockedURL = testGeneralStorageDirectory.appendingPathComponent("blocked.db")
        try? FileManager.default.createDirectory(at: blockedURL, withIntermediateDirectories: true)
        let store = SubmitPlanStore(databaseURL: blockedURL, logger: NullLogger())
        let txId = Data(repeating: 0x0D, count: 32)

        await store.markAwaitingSubmission(txIds: [txId])
        await store.recordPlan(txId: txId, endpoints: [endpointA])

        // Reads must fail safe: `nil` would mean "legacy transaction" and
        // re-enable the default-endpoint auto-submit fallback.
        let plan = await store.plan(for: txId)
        XCTAssertEqual(plan, StoredSubmitPlan.storeUnavailable)
        let txIds = await store.allPlannedTransactionIds()
        XCTAssertTrue(txIds.isEmpty)
    }

    func testWipeDeletesDatabaseFileAndStoreRestartsFresh() async {
        let txId = Data(repeating: 0x0F, count: 32)
        let store = makeStore()
        await store.recordPlan(txId: txId, endpoints: [endpointA])
        XCTAssertTrue(FileManager.default.fileExists(atPath: databaseURL.path))

        await store.wipe()

        XCTAssertFalse(FileManager.default.fileExists(atPath: databaseURL.path))
        let plan = await store.plan(for: txId)
        XCTAssertNil(plan, "A wiped store must start from scratch, not report unavailable")
    }

    func testFreshDatabaseIsStampedWithSchemaVersion() async throws {
        let store = makeStore()
        await store.markAwaitingSubmission(txIds: [Data(repeating: 0x10, count: 32)])

        let connection = try Connection(databaseURL.path)
        let version = try connection.scalar("PRAGMA user_version") as? Int64
        XCTAssertEqual(version, 1)
    }

    func testNewerSchemaDisablesStore() async throws {
        // Simulate a database written by a future SDK version.
        let connection = try Connection(databaseURL.path)
        try connection.run("PRAGMA user_version = 99")

        let store = makeStore()
        let plan = await store.plan(for: Data(repeating: 0x11, count: 32))
        XCTAssertEqual(plan, StoredSubmitPlan.storeUnavailable)
    }

    func testStoreCreatesMissingParentDirectory() async {
        // Fresh installs / aliased synchronizers start without the general
        // storage directory; the store must create it rather than latch into
        // its disabled state.
        let nestedURL = testGeneralStorageDirectory
            .appendingPathComponent("not-yet-created")
            .appendingPathComponent("submit_plans_test.db")
        let store = SubmitPlanStore(databaseURL: nestedURL, logger: NullLogger())
        let txId = Data(repeating: 0x0E, count: 32)

        await store.markAwaitingSubmission(txIds: [txId])

        let plan = await store.plan(for: txId)
        XCTAssertEqual(plan, StoredSubmitPlan.awaiting)
        XCTAssertTrue(FileManager.default.fileExists(atPath: nestedURL.path))
    }
}
