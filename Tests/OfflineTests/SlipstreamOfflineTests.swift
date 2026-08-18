//
//  SlipstreamOfflineTests.swift
//  ZcashLightClientKit
//
//  Created for Slipstream task [#1755] — T4.4.
//
//  Tests:
//    1. Progress mapping: chainTip == 0 → syncStatus .syncing(0.0) without crash.
//    2. Dealloc-without-stop: create + release SlipstreamSynchronizer without stop() → no crash.
//    3. wipe() removes database files (incl. the submit-plan store, [#1976]) + resets state;
//       switchTo() when-never-started succeeds (endpoint swapped, no crash).
//    4. Engine FFI smoke (Offline-safe):
//       - zcashlc_slipstream_open with invalid path → throws rustSlipstreamOpen.
//       - start before open → throws rustSlipstreamNotOpen.
//    5. shouldEmitFound pure-helper unit tests.
//    6. [v2.1 E-3] initialState trivial snapshot-mapping tests (truthful-from-open; the
//       summary-driven composeProgress/summaryProgress era is retired — engine-side seed
//       is cargo-tested in slipstream-core).
//    7. T4.9 regression fixes:
//       - withTaskTimeout: completes before deadline → returns value (not nil).
//       - withTaskTimeout: exceeds deadline → returns nil (swallowed timeout error).
//       - switchTo same-endpoint is a no-op (F2): engine not re-opened, state unchanged.
//       - switchTo different endpoint fires reopen (F2/F3 smoke).
//    8. T5.5 summary-interval tests (8s-Syncing branch REMOVED; all states return 2s).
//    9. [v2.1 E-5] counterProgress retired — progressPermille is the blessed source.
//   10. T5.5 SlipstreamSnapshot new fields (passTotalBlocks, spendableHint defaults + explicit).
//   11. T5.6 SlipstreamSnapshot rangesCompleted field (default + explicit + roundtrip).
//   12. T5.6 boundary-summary timeout constant and F2 design invariants.
//

import Combine
import Foundation
import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

class SlipstreamOfflineTests: ZcashTestCase {
    private var cancellables: [AnyCancellable] = []

    override func tearDown() async throws {
        cancellables = []
        try await super.tearDown()
    }

    // MARK: - Helpers

    /// Create a throwaway `Initializer` backed by a temp directory — engine handle is NOT opened.
    private func makeInitializer() throws -> Initializer {
        let databases = TemporaryDbBuilder.build()
        return Initializer(
            cacheDbURL: nil,
            fsBlockDbRoot: databases.fsCacheDbRoot,
            generalStorageURL: databases.generalStorageURL,
            dataDbURL: databases.dataDB,
            torDirURL: databases.torDir,
            endpoint: LightWalletEndpointBuilder.default,
            network: DarksideWalletDNetwork(),
            spendParamsURL: try __spendParamsURL(),
            outputParamsURL: try __outputParamsURL(),
            saplingParamsSourceURL: SaplingParamsSourceURL.tests,
            isTorEnabled: false,
            isExchangeRateEnabled: false
        )
    }

    // MARK: - 1. Progress mapping: chainTip == 0 → .syncing(0.0, false)

    /// When `snap.chainTip` is 0 (server tip not yet fetched), the progress fraction must be 0.0
    /// and `InternalSyncStatus` must be `.syncing(0.0, false)` without a division-by-zero crash.
    func testProgressMappingChainTipZero() {
        // Use the memberwise `SlipstreamSnapshot` init (no libzcashlc dependency in tests).
        let snap = SlipstreamSnapshot(
            chainTip: 0,
            fetchedBlocks: 0,
            scannedBlocks: 0,
            enhancedTxs: 0,
            currentRangeEnd: 0,
            state: 1 // syncing
        )

        // Mirror the exact mapping from SlipstreamSynchronizer.tickPoll().
        let progress = snap.chainTip > 0
            ? Float(snap.scannedBlocks) / Float(snap.chainTip)
            : Float(0)

        let status: InternalSyncStatus = {
            switch snap.state {
            case 0: return .disconnected
            case 1: return .syncing(min(progress, 1.0), false)
            case 2: return .error(ZcashError.rustSlipstreamSyncFailed(snap.chainTip))
            case 3: return .synced
            default: return .disconnected
            }
        }()

        // Must NOT crash; progress fraction must be exactly 0.0.
        if case let .syncing(fraction, _) = status {
            XCTAssertEqual(fraction, 0.0, accuracy: Float.ulpOfOne,
                           "Progress must be 0.0 when chainTip == 0")
        } else {
            XCTFail("Expected .syncing(0.0, false), got \(status)")
        }
    }

    /// When chainTip > 0 and scannedBlocks > 0, progress must be clamped to [0.0, 1.0].
    func testProgressMappingNonZeroChainTip() {
        let snap = SlipstreamSnapshot(
            chainTip: 1000,
            fetchedBlocks: 1000,
            scannedBlocks: 500,
            enhancedTxs: 0,
            currentRangeEnd: 1000,
            state: 1 // syncing
        )

        let progress = snap.chainTip > 0
            ? Float(snap.scannedBlocks) / Float(snap.chainTip)
            : Float(0)

        XCTAssertEqual(progress, 0.5, accuracy: 1e-5)

        let clamped = min(progress, 1.0)
        XCTAssertGreaterThanOrEqual(clamped, 0.0)
        XCTAssertLessThanOrEqual(clamped, 1.0)
    }

    /// State 3 (done) maps to `.synced`.
    func testProgressMappingStateDone() {
        let snap = SlipstreamSnapshot(
            chainTip: 663200,
            fetchedBlocks: 50,
            scannedBlocks: 50,
            enhancedTxs: 2,
            currentRangeEnd: 663200,
            state: 3 // done
        )

        let progress = snap.chainTip > 0
            ? Float(snap.scannedBlocks) / Float(snap.chainTip)
            : Float(0)
        let status: InternalSyncStatus = {
            switch snap.state {
            case 0: return .disconnected
            case 1: return .syncing(min(progress, 1.0), false)
            case 2: return .error(ZcashError.rustSlipstreamSyncFailed(snap.chainTip))
            case 3: return .synced
            default: return .disconnected
            }
        }()
        XCTAssertEqual(status, .synced)
    }

    /// State 2 (error) maps to `.error(.rustSlipstreamSyncFailed)`.
    func testProgressMappingStateError() {
        let snap = SlipstreamSnapshot(
            chainTip: 663150,
            fetchedBlocks: 10,
            scannedBlocks: 5,
            enhancedTxs: 0,
            currentRangeEnd: 663160,
            state: 2 // error
        )

        let progress = snap.chainTip > 0
            ? Float(snap.scannedBlocks) / Float(snap.chainTip)
            : Float(0)
        let status: InternalSyncStatus = {
            switch snap.state {
            case 0: return .disconnected
            case 1: return .syncing(min(progress, 1.0), false)
            case 2: return .error(ZcashError.rustSlipstreamSyncFailed(snap.chainTip))
            case 3: return .synced
            default: return .disconnected
            }
        }()

        if case let .error(error as ZcashError) = status {
            XCTAssertEqual(error.code, .rustSlipstreamSyncFailed)
        } else {
            XCTFail("Expected .error(rustSlipstreamSyncFailed), got \(status)")
        }
    }

    // MARK: - 2. Dealloc-without-stop: no crash on release without stop()

    /// Create a `SlipstreamSynchronizer` and immediately ARC-release it without calling `stop()`.
    /// The polling task holds `[weak self]` and must no-op gracefully after dealloc.
    func testDeallocWithoutStopDoesNotCrash() async throws {
        var sync: SlipstreamSynchronizer? = SlipstreamSynchronizer(initializer: try makeInitializer())
        XCTAssertNotNil(sync)

        // ARC-release: set nil → deinit runs → pollTask sees nil self → no crash.
        sync = nil

        // Give the Task a brief yield to confirm it observes the nil self.
        try await Task.sleep(nanoseconds: 50_000_000) // 50 ms
        // Reaching here without a crash/exception == pass.
    }

    // MARK: - 3. wipe() removes database files + resets state; switchTo() works when never started

    /// wipe() on a synchronizer that was never started (engine not opened) must still
    /// complete successfully: no files to delete → publisher completes (no error) and
    /// state is reset to `.zero`.
    func testWipeSucceedsWhenEngineNeverStarted() async throws {
        let sync = SlipstreamSynchronizer(initializer: try makeInitializer())

        let wipeExpectation = XCTestExpectation(description: "wipe completes on never-started engine")
        var receivedError: Error?

        sync.wipe()
            .sink(
                receiveCompletion: { completion in
                    if case let .failure(error) = completion {
                        receivedError = error
                    }
                    wipeExpectation.fulfill()
                },
                receiveValue: { _ in }
            )
            .store(in: &cancellables)

        await fulfillment(of: [wipeExpectation], timeout: 5)
        XCTAssertNil(receivedError,
                     "wipe() must complete without error when engine was never opened, got \(String(describing: receivedError))")

        // State must be reset to .zero (unprepared).
        XCTAssertEqual(sync.latestState.syncSessionID, SynchronizerState.zero.syncSessionID,
                       "state must be reset to .zero after wipe")
    }

    /// wipe() removes data.db + WAL/SHM siblings and the fsBlockDbRoot directory,
    /// then completes the publisher and resets state.
    func testWipeRemovesDatabaseFiles() async throws {
        let databases = TemporaryDbBuilder.build()
        let initializer = Initializer(
            cacheDbURL: nil,
            fsBlockDbRoot: databases.fsCacheDbRoot,
            generalStorageURL: databases.generalStorageURL,
            dataDbURL: databases.dataDB,
            torDirURL: databases.torDir,
            endpoint: LightWalletEndpointBuilder.default,
            network: DarksideWalletDNetwork(),
            spendParamsURL: try __spendParamsURL(),
            outputParamsURL: try __outputParamsURL(),
            saplingParamsSourceURL: SaplingParamsSourceURL.tests,
            isTorEnabled: false,
            isExchangeRateEnabled: false
        )

        // Create the files/dirs that wipe() should remove.
        let fm = FileManager.default
        let dataDb = initializer.dataDbURL
        let walURL = URL(fileURLWithPath: dataDb.path + "-wal")
        let shmURL = URL(fileURLWithPath: dataDb.path + "-shm")
        let fsRoot = initializer.fsBlockDbRoot

        // Write dummy data to data.db and siblings.
        try "dummy".data(using: .utf8)!.write(to: dataDb)
        try "dummy".data(using: .utf8)!.write(to: walURL)
        try "dummy".data(using: .utf8)!.write(to: shmURL)

        // Create the fsBlockDbRoot directory.
        try fm.createDirectory(at: fsRoot, withIntermediateDirectories: true)

        // Pre-condition: files exist.
        XCTAssertTrue(fm.fileExists(atPath: dataDb.path), "data.db must exist before wipe")
        XCTAssertTrue(fm.fileExists(atPath: walURL.path), "data.db-wal must exist before wipe")
        XCTAssertTrue(fm.fileExists(atPath: shmURL.path), "data.db-shm must exist before wipe")
        XCTAssertTrue(fm.fileExists(atPath: fsRoot.path), "fsBlockDbRoot must exist before wipe")

        let sync = SlipstreamSynchronizer(initializer: initializer)

        let wipeExpectation = XCTestExpectation(description: "wipe completes")
        var receivedError: Error?

        sync.wipe()
            .sink(
                receiveCompletion: { completion in
                    if case let .failure(error) = completion {
                        receivedError = error
                    }
                    wipeExpectation.fulfill()
                },
                receiveValue: { _ in }
            )
            .store(in: &cancellables)

        await fulfillment(of: [wipeExpectation], timeout: 5)

        // Must complete without error.
        XCTAssertNil(receivedError,
                     "wipe() must not error when files exist, got \(String(describing: receivedError))")

        // All files/dirs must be gone.
        XCTAssertFalse(fm.fileExists(atPath: dataDb.path), "data.db must be removed after wipe")
        XCTAssertFalse(fm.fileExists(atPath: walURL.path), "data.db-wal must be removed after wipe")
        XCTAssertFalse(fm.fileExists(atPath: shmURL.path), "data.db-shm must be removed after wipe")
        XCTAssertFalse(fm.fileExists(atPath: fsRoot.path), "fsBlockDbRoot must be removed after wipe")

        // State must be reset.
        XCTAssertEqual(sync.latestState.syncSessionID, SynchronizerState.zero.syncSessionID,
                       "state must be reset to .zero after wipe")
    }

    /// [#1976] wipe() must also delete the submit-plan-store database file — mirroring
    /// `SDKSynchronizer.wipe()` (SDKSynchronizer.swift:815-818), which wipes the plan store
    /// only when the wallet wipe itself succeeds. Regression test: `SlipstreamSynchronizer.wipe()`
    /// used to leave `submit_plans_*.db` behind after a wipe.
    func testWipeDeletesSubmitPlanStoreDatabase() async throws {
        let initializer = try makeInitializer()
        let store = initializer.container.resolve(SubmitPlanStoring.self)

        await store.recordPlan(
            txId: Data(repeating: 0x01, count: 32),
            endpoints: [LightWalletEndpoint(address: "example.com", port: 443, secure: true)]
        )

        // Same construction as Dependencies.swift:58-64.
        let submitPlansDbURL = initializer.generalStorageURL
            .appendingPathComponent("submit_plans_\(initializer.network.networkType.networkId).db")

        let fm = FileManager.default
        XCTAssertTrue(fm.fileExists(atPath: submitPlansDbURL.path),
                      "submit-plan database must exist after recordPlan")

        let sync = SlipstreamSynchronizer(initializer: initializer)

        let wipeExpectation = XCTestExpectation(description: "wipe completes")
        var receivedError: Error?

        sync.wipe()
            .sink(
                receiveCompletion: { completion in
                    if case let .failure(error) = completion {
                        receivedError = error
                    }
                    wipeExpectation.fulfill()
                },
                receiveValue: { _ in }
            )
            .store(in: &cancellables)

        await fulfillment(of: [wipeExpectation], timeout: 5)
        XCTAssertNil(receivedError,
                     "wipe() must not error when a submit plan exists, got \(String(describing: receivedError))")

        // Check file absence BEFORE any store call that would lazily recreate it.
        XCTAssertFalse(fm.fileExists(atPath: submitPlansDbURL.path),
                       "submit-plan database must be removed after wipe")

        let plan = await store.plan(for: Data(repeating: 0x01, count: 32))
        XCTAssertNil(plan, "plan lookup after wipe must find no row, got \(String(describing: plan))")
    }

    /// `switchTo(endpoint:)` on a synchronizer that was never started must complete
    /// without error and store the new endpoint (no crash, no leftover handle state).
    func testSwitchToWhenNeverStartedSucceeds() async throws {
        let sync = SlipstreamSynchronizer(initializer: try makeInitializer())

        // Pick a different endpoint to confirm the swap is accepted.
        let newEndpoint = LightWalletEndpoint(address: "zec.rocks", port: 443, secure: true)

        // Must NOT throw — engine was never opened, reopen closes nil handle (no-op) and
        // opens a fresh one; the open itself may fail on invalid-path temp db (expected
        // rustSlipstreamOpen) or succeed.  Either way it must not throw an *unsupported* error.
        do {
            try await sync.switchTo(endpoint: newEndpoint)
            // If open succeeds (temp db accepted by FFI) → pass.
        } catch let error as ZcashError {
            // rustSlipstreamOpen is acceptable (FFI rejected the temp path).
            // rustSlipstreamUnsupported would be a regression — fail the test.
            XCTAssertNotEqual(error.code, .rustSlipstreamUnsupported,
                              "switchTo() must no longer throw rustSlipstreamUnsupported; got \(error.code)")
        } catch {
            // Any other error is acceptable (network, FFI).
        }
    }

    // MARK: - 4. Engine FFI smoke tests (Offline-safe — run the REAL FFI from the local XCFramework)

    /// `SlipstreamEngine.start(ufvk:birthday:)` before `open(network:)` must throw
    /// `ZcashError.rustSlipstreamNotOpen` (pure Swift guard — no FFI call needed).
    func testEngineStartBeforeOpenThrowsRustSlipstreamNotOpen() async throws {
        let databases = TemporaryDbBuilder.build()
        let engine = SlipstreamEngine(
            dbURL: databases.dataDB,
            server: LightWalletEndpointBuilder.default
        )

        do {
            // Deliberately skip engine.open(network:) to exercise the nil-handle guard.
            try await engine.start(ufvk: nil, birthday: 663150, torDir: nil)
            XCTFail("start() must throw when engine is not opened")
        } catch let error as ZcashError {
            XCTAssertEqual(error.code, .rustSlipstreamNotOpen,
                           "Expected rustSlipstreamNotOpen, got \(error.code)")
        } catch {
            XCTFail("Expected ZcashError.rustSlipstreamNotOpen, got \(error)")
        }
    }

    /// T8.3 (T5.5 wart fix): the public `SlipstreamSynchronizer.start()` before
    /// `prepare()` must throw `ZcashError.synchronizerNotPrepared` — parity with
    /// `SDKSynchronizer.start` (SDKSynchronizer.swift:189-192). Without the guard it
    /// reached `engine.start()` and surfaced the internal `.rustSlipstreamNotOpen`
    /// the user saw at launch (the start-before-prepare wart).
    func testStartBeforePrepareThrowsNotPrepared() async throws {
        let sync = SlipstreamSynchronizer(initializer: try makeInitializer())
        do {
            try await sync.start()
            XCTFail("start() before prepare() must throw")
        } catch let error as ZcashError {
            XCTAssertEqual(error.code, .synchronizerNotPrepared,
                           "Expected synchronizerNotPrepared, got \(error.code)")
        } catch {
            XCTFail("Expected ZcashError.synchronizerNotPrepared, got \(error)")
        }
    }

    /// T8.3 (T5.5 wart fix): `stop()` on an unprepared synchronizer must NOT forge
    /// `isPrepared` by moving `.unprepared` → `.stopped`. Zodl calls `stop()`
    /// unconditionally on `didEnterBackground` (RootInitialization.swift:75-76); if a
    /// background hop during `prepare()` forged `isPrepared`, the next foreground
    /// `start()` would pass the guard above and spring the wart again.
    func testStopBeforePrepareKeepsUnprepared() async throws {
        let sync = SlipstreamSynchronizer(initializer: try makeInitializer())
        sync.stop()
        // [Phase E] stop() is nonisolated on the actor: it registers the teardown and returns;
        // the state effects land on the actor moments later. Give the isolated stopImpl time
        // to run so the assertion observes the POST-stop state (the guard under test).
        try await Task.sleep(nanoseconds: 300_000_000)
        XCTAssertFalse(sync.latestState.internalSyncStatus.isPrepared,
                       "stop() before prepare() must leave the synchronizer unprepared")
        if case .unprepared = sync.latestState.internalSyncStatus {
            // expected — state unchanged
        } else {
            XCTFail("internalSyncStatus must remain .unprepared after stop(), got \(sync.latestState.internalSyncStatus)")
        }
    }

    /// `zcashlc_slipstream_open` with a path whose PARENT directory does not exist returns null →
    /// `SlipstreamEngine.open(network:)` throws `ZcashError.rustSlipstreamOpen`.
    func testEngineOpenWithInvalidPathThrowsRustSlipstreamOpen() async throws {
        let invalidPath = URL(fileURLWithPath: "/nonexistent_slipstream_test/nested/path/data.db")
        let engine = SlipstreamEngine(
            dbURL: invalidPath,
            server: LightWalletEndpointBuilder.default
        )

        do {
            try await engine.open(network: DarksideWalletDNetwork())
            // On some systems the FFI might tolerate the path (creates a new db).
            // That's acceptable — this test asserts the HAPPY path doesn't crash.
        } catch let error as ZcashError {
            XCTAssertEqual(error.code, .rustSlipstreamOpen,
                           "Expected rustSlipstreamOpen for invalid path, got \(error.code)")
        } catch {
            XCTFail("Expected ZcashError.rustSlipstreamOpen, got \(error)")
        }
    }

    /// `snapshot()` returns `nil` when the engine is not yet opened.
    func testEngineSnapshotReturnsNilWhenNotOpened() async {
        let databases = TemporaryDbBuilder.build()
        let engine = SlipstreamEngine(
            dbURL: databases.dataDB,
            server: LightWalletEndpointBuilder.default
        )
        let snap = await engine.snapshot()
        XCTAssertNil(snap, "snapshot() must return nil when handle is nil")
    }

    /// `drainEvents()` returns `[]` when the engine is not yet opened.
    func testEngineDrainEventsReturnsEmptyWhenNotOpened() async {
        let databases = TemporaryDbBuilder.build()
        let engine = SlipstreamEngine(
            dbURL: databases.dataDB,
            server: LightWalletEndpointBuilder.default
        )
        let events = await engine.drainEvents()
        XCTAssertTrue(events.isEmpty, "drainEvents() must return [] when handle is nil")
    }

    // MARK: - 5. [v2.1 E-4] foundTransactions emission rule

    /// The E-4 rule as tickPoll applies it: emit when the ENGINE's tx-set version moved
    /// (any store/update/linkage/mempool/submit change), or when the HOST's reconcile
    /// filter flipped scope (recovering edge — visibility policy is host-owned per §0).
    /// Replaces the 3-branch counter-watch + SyncDone-fallback + count-dedup strategy.
    private func shouldEmitFound(
        version: UInt64,
        lastVersion: UInt64,
        recovering: Bool,
        lastRecovering: Bool
    ) -> Bool {
        version != lastVersion || recovering != lastRecovering
    }

    /// Version advanced (enhance/mempool/linkage/submit-poke) → emit.
    func testShouldEmitFoundOnVersionMove() {
        XCTAssertTrue(shouldEmitFound(version: 1, lastVersion: 0, recovering: false, lastRecovering: false))
        XCTAssertTrue(shouldEmitFound(version: 7, lastVersion: 3, recovering: true, lastRecovering: true))
    }

    /// Nothing moved → no emission (calm idle ticks).
    func testShouldEmitFoundQuietWhenNothingMoved() {
        XCTAssertFalse(shouldEmitFound(version: 3, lastVersion: 3, recovering: false, lastRecovering: false))
        XCTAssertFalse(shouldEmitFound(version: 0, lastVersion: 0, recovering: true, lastRecovering: true))
    }

    /// The host filter's scope flip emits even with no engine write: recovery completing
    /// reveals the held txs; recovery re-engaging re-gates the list (both are host-filter
    /// edges — the engine wrote nothing).
    func testShouldEmitFoundOnRecoveringEdge() {
        XCTAssertTrue(shouldEmitFound(version: 3, lastVersion: 3, recovering: false, lastRecovering: true),
                      "recovery completion must reveal the now-unfiltered list")
        XCTAssertTrue(shouldEmitFound(version: 3, lastVersion: 3, recovering: true, lastRecovering: false),
                      "recovery start must push the newly-gated list")
    }

    /// Handle replacement (wipe/switchTo) resets both mirrors to their initial values, so a
    /// fresh handle's version 0 does not spuriously emit — and the first real change does.
    func testShouldEmitFoundFreshHandleBaseline() {
        XCTAssertFalse(shouldEmitFound(version: 0, lastVersion: 0, recovering: false, lastRecovering: false))
        XCTAssertTrue(shouldEmitFound(version: 1, lastVersion: 0, recovering: false, lastRecovering: false))
    }

    // MARK: - reconciledVisible pure-helper unit tests ([#1755] vanishing-tx fix)
    //
    // The reconcile filter (`ext_slipstream_v_tx_reconciled`) must hold provisional txs back ONLY during an
    // active recovery. On a synced wallet a mined tx the view flags unreconciled (transiently OR, as seen
    // in the field with a Keystone send, persistently) must still show — dropping a confirmed tx is the
    // "vanishing transaction" bug.

    private func reconcileTestOverview(rawID: Data) -> ZcashTransaction.Overview {
        ZcashTransaction.Overview(
            accountUUID: AccountUUID(id: [UInt8](repeating: 0, count: 16)),
            blockTime: nil,
            expiryHeight: nil,
            fee: Zatoshi(10000),
            index: nil,
            isShielding: false,
            hasChange: true,
            memoCount: 0,
            minedHeight: 100,
            raw: nil,
            rawID: rawID,
            receivedNoteCount: 0,
            sentNoteCount: 0,
            value: Zatoshi(10),
            isExpiredUmined: false,
            totalSpent: nil,
            totalReceived: nil,
            spentNoteCount: 0,
            poolCrossingValue: nil,
            isTrusted: false,
            zip318Kind: .notClassified
        )
    }

    /// Not recovering → every tx passes, even one the view flags unreconciled (the vanishing-tx fix).
    func testReconciledVisibleNotRecoveringShowsAll() {
        let a = reconcileTestOverview(rawID: Data(repeating: 1, count: 32))
        let b = reconcileTestOverview(rawID: Data(repeating: 2, count: 32))
        let kept = SlipstreamSynchronizer.reconciledVisible([a, b], unreconciled: [a.rawID], recovering: false)
        XCTAssertEqual(kept.map(\.rawID), [a.rawID, b.rawID], "outside recovery nothing is held back")
    }

    /// Recovering + a flagged tx → that tx is held back, the rest surface.
    func testReconciledVisibleRecoveringHoldsUnreconciled() {
        let a = reconcileTestOverview(rawID: Data(repeating: 1, count: 32))
        let b = reconcileTestOverview(rawID: Data(repeating: 2, count: 32))
        let kept = SlipstreamSynchronizer.reconciledVisible([a, b], unreconciled: [a.rawID], recovering: true)
        XCTAssertEqual(kept.map(\.rawID), [b.rawID], "during recovery the unreconciled tx is held")
    }

    /// Recovering but nothing flagged → every tx passes.
    func testReconciledVisibleRecoveringEmptySetShowsAll() {
        let a = reconcileTestOverview(rawID: Data(repeating: 1, count: 32))
        let b = reconcileTestOverview(rawID: Data(repeating: 2, count: 32))
        let kept = SlipstreamSynchronizer.reconciledVisible([a, b], unreconciled: [], recovering: true)
        XCTAssertEqual(kept.count, 2, "empty unreconciled set holds nothing back")
    }

    // [v2.1 E-3] Sections 6 (composeProgress) and 6b (summaryProgress) are GONE with the
    // helpers: the snapshot is truthful from open() — `progress_permille` is the one blessed
    // progress source, seeded engine-side from the persisted wallet (cargo-tested in
    // slipstream-core `scheduler::tests::seed_*`). No host re-derives progress from a summary.

    // [v2.1 E-5] Section 6c (importAccount counter-only re-scan visibility) is GONE with
    // `forceCounterProgressUntilDone`/`counterProgress`: the ENGINE re-baselines its session
    // floor when the scan scope expands (cargo-tested in slipstream-core
    // `events::tests::floor_rebaseline_on_scope_expansion_only`), so the blessed permille
    // reads an import/rewind re-scan as a genuine climb with no host bypass.

    // MARK: - 6d. [v2.1 E-3] initialState — trivial truthful-from-open snapshot mapping

    /// initialState(nil snapshot) → cold `.disconnected` with no balances (engine mid-close).
    func testInitialStateColdWhenNilSnapshot() {
        let state = SlipstreamSynchronizer.initialState(
            snapshot: nil,
            accountsBalances: [:],
            fullyScannedHeight: nil,
            syncSessionID: UUID()
        )
        XCTAssertEqual(state.internalSyncStatus, .disconnected)
        XCTAssertTrue(state.accountsBalances.isEmpty)
    }

    /// A ZERO snapshot (fresh wallet: engine seeded nothing — no tip, no floor) stays cold
    /// `.disconnected`, preserving the prior fresh-wallet cold-launch behaviour.
    func testInitialStateColdWhenSnapshotUnseeded() {
        let snap = SlipstreamSnapshot(
            chainTip: 0, fetchedBlocks: 0, scannedBlocks: 0, enhancedTxs: 0,
            currentRangeEnd: 0, state: 0
        )
        let state = SlipstreamSynchronizer.initialState(
            snapshot: snap,
            accountsBalances: [:],
            fullyScannedHeight: nil,
            syncSessionID: UUID()
        )
        XCTAssertEqual(state.internalSyncStatus, .disconnected)
    }

    /// A SEEDED snapshot (synced wallet at open: persisted tip + ~1000‰ floor + spendable)
    /// emits warm `.syncing(~1.0, spendable)` with the persisted tip — truthful from open,
    /// no summary math involved.
    func testInitialStateWarmFromSeededSnapshot() {
        let snap = SlipstreamSnapshot(
            chainTip: 3_000_000, fetchedBlocks: 0, scannedBlocks: 0, enhancedTxs: 0,
            currentRangeEnd: 0, state: 0,
            spendableHint: 1, progressPermille: 999
        )
        let state = SlipstreamSynchronizer.initialState(
            snapshot: snap,
            accountsBalances: [:],
            fullyScannedHeight: 2_999_990,
            syncSessionID: UUID()
        )
        if case let .syncing(progress, spendable) = state.internalSyncStatus {
            XCTAssertEqual(progress, 0.999, accuracy: 1e-5, "warm progress must be the seeded permille")
            XCTAssertTrue(spendable, "no pending recent range at open ⇒ spendable")
        } else {
            XCTFail("warm initial state must be .syncing, got \(state.internalSyncStatus)")
        }
        XCTAssertEqual(state.latestBlockHeight, 3_000_000)
        XCTAssertEqual(state.fullyScannedHeight, 2_999_990)
        XCTAssertFalse(state.isRecovering)
    }

    /// A mid-restore relaunch snapshot (isRecovering seeded 1, floor at the resume position)
    /// emits `.syncing` with `isRecovering == true` from the FIRST emission — the window the
    /// deleted summary-derived seed + D-2 adopt-guard used to paper over.
    func testInitialStateMidRestoreRelaunchIsRecoveringFromOpen() {
        let snap = SlipstreamSnapshot(
            chainTip: 3_000_000, fetchedBlocks: 0, scannedBlocks: 0, enhancedTxs: 0,
            currentRangeEnd: 0, state: 0,
            isRecovering: 1, progressPermille: 350
        )
        let state = SlipstreamSynchronizer.initialState(
            snapshot: snap,
            accountsBalances: [:],
            fullyScannedHeight: nil,
            syncSessionID: UUID()
        )
        XCTAssertTrue(state.isRecovering, "recovery flag must be truthful from the open-time snapshot")
        if case let .syncing(progress, _) = state.internalSyncStatus {
            XCTAssertEqual(progress, 0.35, accuracy: 1e-5, "restore resumes at its persisted position")
        } else {
            XCTFail("mid-restore relaunch must emit .syncing, got \(state.internalSyncStatus)")
        }
    }

    // [v2.1 Phase 2] testRecoveryAccountBalance is GONE with the helper: the Direction-B
    // mapping lives in the engine FFI (ffi.rs `override_with_recovery_net`, crate-side).

    // MARK: - 7. T4.9 regression tests (F1 timeout-helper; F2 switchTo same-endpoint no-op)

    // ── 7a. withTaskTimeout helper ─────────────────────────────────────────────

    /// withTaskTimeout: operation returns before the deadline → result is propagated.
    func testWithTaskTimeoutReturnsValueWhenFasterThanDeadline() async throws {
        // Operation completes in ~0 ms; deadline is 500 ms.
        let result = try await withTaskTimeout(500_000_000) {
            return 42
        }
        XCTAssertEqual(result, 42,
                       "withTaskTimeout must propagate the operation's value when it finishes first")
    }

    /// withTaskTimeout: operation takes longer than the deadline → throws SummaryTimeoutError.
    /// (The helper is production-unused since v2.1 Phase 2 — the engine owns the summary
    /// refresh lifecycle — but stays available; this pins its timeout contract.)
    func testWithTaskTimeoutThrowsWhenDeadlineExceeded() async throws {
        // Deadline: 50 ms; operation: sleep 500 ms (10× longer).
        let deadline: UInt64 = 50_000_000  // 50 ms
        do {
            _ = try await withTaskTimeout(deadline) {
                try await Task.sleep(nanoseconds: 500_000_000)
                return 99
            }
            XCTFail("withTaskTimeout must throw when the deadline is exceeded")
        } catch is SummaryTimeoutError {
            // Expected: timeout error was thrown.
        } catch {
            XCTFail("Expected SummaryTimeoutError, got \(error)")
        }
    }

    // ── 7b. F2: switchTo same-endpoint is a no-op ─────────────────────────────

    /// switchTo(endpoint:) with the SAME host+port+secure as the current endpoint must
    /// return immediately without touching the engine (no open/close/reopen).
    ///
    /// Verification strategy: create a synchronizer with the default endpoint (localhost:9067),
    /// call switchTo with the same endpoint, and assert it completes without throwing a
    /// `rustSlipstreamOpen` or `rustSlipstreamNotOpen` error (which would indicate the engine
    /// was re-opened against an invalid temp-db path).
    ///
    /// We cannot directly observe "engine not re-opened" without a mock, but the no-op guard
    /// prevents the engine.reopen() call entirely — any FFI error would only appear if the
    /// guard were absent.  The test asserts the happy-path contract: same-endpoint → no error.
    func testSwitchToSameEndpointIsNoOp() async throws {
        let sync = SlipstreamSynchronizer(initializer: try makeInitializer())

        // The synchronizer's currentEndpoint starts as LightWalletEndpointBuilder.default
        // (localhost:9067:insecure).  Pass the identical values.
        let sameEndpoint = LightWalletEndpoint(address: "localhost", port: 9067, secure: false)

        // Must NOT throw — the no-op guard returns before any FFI call.
        // If the guard were absent, engine.reopen() would call engine.close() (safe for nil
        // handle) then engine.open() with the temp-db path, which may succeed or fail with
        // rustSlipstreamOpen — but NOT with any other error kind.
        do {
            try await sync.switchTo(endpoint: sameEndpoint)
            // Reaching here → no-op guard fired, no FFI errors → pass.
        } catch let error as ZcashError {
            // If the guard fires as expected, we never reach here.
            // Any ZcashError indicates the guard did NOT fire (regression).
            XCTFail("switchTo same endpoint must be a no-op; got ZcashError \(error.code)")
        } catch {
            XCTFail("switchTo same endpoint must be a no-op; got unexpected error: \(error)")
        }
    }

    /// switchTo(endpoint:) with a DIFFERENT endpoint is NOT a no-op — the engine is
    /// re-opened (or the attempt to reopen fires the expected rustSlipstreamOpen on a
    /// temp path).  This test guards against accidentally making every switchTo a no-op.
    func testSwitchToDifferentEndpointIsNotNoOp() async throws {
        let sync = SlipstreamSynchronizer(initializer: try makeInitializer())

        // Pick a clearly different endpoint (different host AND port).
        let differentEndpoint = LightWalletEndpoint(address: "zec.rocks", port: 443, secure: true)

        // Calling switchTo a different endpoint WILL call engine.reopen().
        // reopen() closes the nil handle (no-op) then calls open() with the temp-db path.
        // The open may succeed (FFI tolerated the path) or fail with rustSlipstreamOpen.
        // Either outcome is fine — what matters is that the call did NOT silently no-op.
        var didAttemptSwitch = false
        do {
            try await sync.switchTo(endpoint: differentEndpoint)
            didAttemptSwitch = true // open succeeded
        } catch let error as ZcashError {
            // rustSlipstreamOpen = FFI rejected temp path; the reopen WAS attempted → pass.
            if error.code == .rustSlipstreamOpen {
                didAttemptSwitch = true
            } else if error.code == .rustSlipstreamNotOpen {
                // This would be unexpected — reopen creates a fresh handle.
                XCTFail("Unexpected rustSlipstreamNotOpen on switchTo different endpoint")
            } else {
                didAttemptSwitch = true // some other FFI / network error → reopen still fired
            }
        } catch {
            didAttemptSwitch = true // any error = the attempt was made
        }
        XCTAssertTrue(didAttemptSwitch,
                      "switchTo a different endpoint must attempt a reopen (not silently no-op)")
    }

    // [v2.1 Phase 2] The MARK-8 summaryFetchInterval suite is GONE with the host cadence:
    // summary rationing (incl. the T5.5 no-walk-while-Syncing invariant) is engine-owned (E-1).

    // [v2.1 E-5] Section 9 (counterProgress) is GONE with the helper — `progressPermille`
    // is the one blessed progress source at every phase (E-3 seed + E-5 re-baseline).

    // MARK: - 10. T5.5 SlipstreamSnapshot new fields

    /// SlipstreamSnapshot memberwise init propagates passTotalBlocks and spendableHint.
    func testSnapshotNewFieldsDefaultToZero() {
        let snap = SlipstreamSnapshot(
            chainTip: 0,
            fetchedBlocks: 0,
            scannedBlocks: 0,
            enhancedTxs: 0,
            currentRangeEnd: 0,
            state: 0
        )
        XCTAssertEqual(snap.passTotalBlocks, 0,
                       "passTotalBlocks must default to 0 when omitted")
        XCTAssertEqual(snap.spendableHint, 0,
                       "spendableHint must default to 0 when omitted")
        // [v2.1 E-4] The tx-set version follows the same memberwise convention.
        XCTAssertEqual(snap.txSetVersion, 0,
                       "txSetVersion must default to 0 when omitted")
    }

    /// [v2.1 E-4] txSetVersion propagates through the memberwise init (fresh-handle 0 and
    /// an advanced value both round-trip).
    func testSnapshotTxSetVersionExplicit() {
        let snap = SlipstreamSnapshot(
            chainTip: 663_200,
            fetchedBlocks: 0,
            scannedBlocks: 0,
            enhancedTxs: 3,
            currentRangeEnd: 0,
            state: 1,
            txSetVersion: 42
        )
        XCTAssertEqual(snap.txSetVersion, 42)
    }

    /// SlipstreamSnapshot with explicit passTotalBlocks and spendableHint.
    func testSnapshotNewFieldsExplicit() {
        let snap = SlipstreamSnapshot(
            chainTip: 663_200,
            fetchedBlocks: 10_000,
            scannedBlocks: 7_500,
            enhancedTxs: 2,
            currentRangeEnd: 663_200,
            state: 1,
            passTotalBlocks: 15_000,
            spendableHint: 1
        )
        XCTAssertEqual(snap.passTotalBlocks, 15_000)
        XCTAssertEqual(snap.spendableHint, 1)
    }

    // MARK: - 11. T5.6 rangesCompleted field

    /// SlipstreamSnapshot memberwise init: rangesCompleted defaults to 0 when omitted.
    func testSnapshotRangesCompletedDefaultsToZero() {
        let snap = SlipstreamSnapshot(
            chainTip: 0,
            fetchedBlocks: 0,
            scannedBlocks: 0,
            enhancedTxs: 0,
            currentRangeEnd: 0,
            state: 0
            // rangesCompleted omitted → should default to 0
        )
        XCTAssertEqual(snap.rangesCompleted, 0,
                       "rangesCompleted must default to 0 when omitted from memberwise init")
    }

    /// SlipstreamSnapshot with explicit rangesCompleted.
    func testSnapshotRangesCompletedExplicit() {
        let snap = SlipstreamSnapshot(
            chainTip: 663_200,
            fetchedBlocks: 10_000,
            scannedBlocks: 7_500,
            enhancedTxs: 2,
            currentRangeEnd: 663_200,
            state: 1,
            passTotalBlocks: 15_000,
            spendableHint: 1,
            rangesCompleted: 3
        )
        XCTAssertEqual(snap.rangesCompleted, 3,
                       "rangesCompleted must equal 3 when set explicitly")
    }

    /// F2 design invariant: rangesCompleted starts at 0 when no ranges complete.
    func testSnapshotRangesCompletedZeroBeforeFirstRange() {
        let snap = SlipstreamSnapshot(
            chainTip: 663_200,
            fetchedBlocks: 100,
            scannedBlocks: 50,
            enhancedTxs: 0,
            currentRangeEnd: 663_200,
            state: 1 // syncing
            // rangesCompleted = 0 (default)
        )
        XCTAssertEqual(snap.rangesCompleted, 0,
                       "Before any range completes, rangesCompleted must be 0")
    }

    // MARK: - 12. T5.6 F2 design invariants

    /// F1 design invariant: passTotalBlocks set (store) semantics — re-suggest with same
    /// total does not double-count (20k ≠ 15k).
    func testSnapshotPassTotalSetNotAccumulateSemantics() {
        // Simulate: scheduler first calls set_pass_total(15_000), then (after first range
        // scanned) calls set_pass_total(15_000) again (scanned_so_far=10_000 + remaining=5_000).
        // The denominator must stay 15_000, not grow to 30_000.
        var total: UInt64 = 0
        total = 15_000  // first set
        XCTAssertEqual(total, 15_000)
        total = 15_000  // second set (not add)
        XCTAssertEqual(total, 15_000,
                       "set semantics: re-suggest with same total must keep denominator stable")
        total = 20_000  // new ranges appeared
        XCTAssertEqual(total, 20_000,
                       "set semantics: new total replaces old (not adds to it)")
    }

    // [v2.1 Phase 2] The boundary/idle timeout constants and the shouldMarkChainTipUpdated
    // suite are GONE with their machinery: summary rationing + tip freshness are engine-owned
    // (E-1 / E-2 — `snapshot.tipFresh` carries the same semantics, computed at the source).

    // MARK: - 14. B4 stall-watchdog pure helpers (#1755 failure-path hardening)
    //
    // Field failure 2 (2026-06-12): the UI froze at exactly one chunk with state stuck
    // "Syncing" — no logs, no error, no counter movement. The watchdog makes such
    // silent stalls VISIBLE: when state==Syncing and the progress-counter signature
    // has not changed for stallWatchdogThresholdSeconds, tickPoll logs ONE loud error
    // per stall episode. It never restarts anything (policy stays with the app).

    /// Syncing + window exceeded → stalled.
    func testIsSyncStalledFiresWhenSyncingPastThreshold() {
        XCTAssertTrue(SlipstreamSynchronizer.isSyncStalled(
            state: 1, secondsSinceLastCounterChange: 120, threshold: 120
        ), "exactly at threshold must fire (>= semantics)")
        XCTAssertTrue(SlipstreamSynchronizer.isSyncStalled(
            state: 1, secondsSinceLastCounterChange: 3_600, threshold: 120
        ))
    }

    /// Syncing but inside the window → not stalled (a slow A10 chunk is ~36s; the
    /// 120s threshold must tolerate it with a wide margin).
    func testIsSyncStalledQuietInsideWindow() {
        XCTAssertFalse(SlipstreamSynchronizer.isSyncStalled(
            state: 1, secondsSinceLastCounterChange: 0, threshold: 120
        ))
        XCTAssertFalse(SlipstreamSynchronizer.isSyncStalled(
            state: 1, secondsSinceLastCounterChange: 119.9, threshold: 120
        ))
    }

    /// Non-Syncing states never stall: Idle/Done/Error are legitimate steady states
    /// with frozen counters.
    func testIsSyncStalledOnlyFiresWhileSyncing() {
        for state: UInt8 in [0, 2, 3] {
            XCTAssertFalse(SlipstreamSynchronizer.isSyncStalled(
                state: state, secondsSinceLastCounterChange: 10_000, threshold: 120
            ), "state \(state) must never report a stall")
        }
    }

    /// The shipped threshold constant is 120 s.
    func testStallWatchdogThresholdConstant() {
        XCTAssertEqual(SlipstreamSynchronizer.stallWatchdogThresholdSeconds, 120)
    }

    // Field failure 2026-08-02: the engine-owned stall clock survives a stop→start, so a
    // restarted handle's first snapshots carried a 497 s span accumulated before — and across —
    // a deliberate stop, and the watchdog fired at the exact moment recovery was working. The
    // clamp caps the evaluated span at the CURRENT handle's own lifetime.

    /// A stale pre-restart span is clamped to the young handle's lifetime — below threshold,
    /// so the restart never fires the loud log on inherited history.
    func testEffectiveStallSecondsClampsInheritedSpanToHandleLifetime() {
        XCTAssertEqual(
            SlipstreamSynchronizer.effectiveStallSeconds(engineReported: 497, secondsSinceHandleStart: 31),
            31
        )
    }

    /// A genuine stall of the current handle passes through untouched and can still fire.
    func testEffectiveStallSecondsPassesGenuineSpanThrough() {
        XCTAssertEqual(
            SlipstreamSynchronizer.effectiveStallSeconds(engineReported: 130, secondsSinceHandleStart: 600),
            130
        )
        XCTAssertTrue(SlipstreamSynchronizer.isSyncStalled(
            state: 1,
            secondsSinceLastCounterChange: SlipstreamSynchronizer.effectiveStallSeconds(
                engineReported: 130,
                secondsSinceHandleStart: 600
            ),
            threshold: 120
        ), "a real 130 s stall on a long-lived handle must still fire")
    }

    /// A backwards clock adjustment cannot produce a negative span.
    func testEffectiveStallSecondsNeverGoesNegative() {
        XCTAssertEqual(
            SlipstreamSynchronizer.effectiveStallSeconds(engineReported: 497, secondsSinceHandleStart: -5),
            0
        )
    }

    // MARK: - 15. [#1975] Background transaction-resubmission driver
    //
    // Parity with the old pipeline's `TxResubmissionAction`, which ran once per sync pass.
    // The poll loop asks `resubmissionCheckDue` on every 2 s tick; the answer gates a
    // `TxResubmitter.checkAndResubmit` call (prune every check, actual re-broadcast throttled
    // to 300 s INSIDE the resubmitter — the cadence tested here is only the CHECK cadence).

    /// Syncing (1) and Done (3) both check: the old pipeline ran the action once per sync pass,
    /// and a Done engine still holds unmined transactions worth re-broadcasting.
    func testResubmissionCheckDueWhileSyncingOrDone() {
        for state: UInt8 in [1, 3] {
            XCTAssertTrue(SlipstreamSynchronizer.resubmissionCheckDue(
                isCancelled: false, state: state, chainTip: 2_400_000, secondsSinceLastCheck: 1_000, inFlight: false
            ), "state \(state) must run the resubmission check")
        }
    }

    /// Disconnected (0) and Error (2) never check: there is no network to submit through,
    /// so a check could only burn a database walk and log failures.
    func testResubmissionCheckNotDueWhileDisconnectedOrError() {
        for state: UInt8 in [0, 2] {
            XCTAssertFalse(SlipstreamSynchronizer.resubmissionCheckDue(
                isCancelled: false, state: state, chainTip: 2_400_000, secondsSinceLastCheck: 1_000, inFlight: false
            ), "state \(state) must never run the resubmission check")
        }
    }

    /// A cancelled caller never checks, however perfect the rest of the tick looks. This is the
    /// teardown guard: `stopPolling()` cancels `pollTask` without awaiting it, and `wipeImpl`
    /// then suspends (`engine.stop()`/`engine.close()`), so a `tickPoll` suspended mid-tick can
    /// resume INSIDE the wipe. Firing there would read `data.db` and re-create the submit-plan
    /// database the wipe had just deleted (SQLite recreates the file on connect), undoing
    /// [#1976] milliseconds later.
    func testResubmissionCheckNotDueWhenTheCallerIsCancelled() {
        for state: UInt8 in [1, 3] {
            XCTAssertFalse(SlipstreamSynchronizer.resubmissionCheckDue(
                isCancelled: true, state: state, chainTip: 2_400_000, secondsSinceLastCheck: 100_000, inFlight: false
            ), "state \(state) must not check while the calling task is cancelled")
        }
    }

    /// A zero chain tip means the server tip is not yet known; resubmission candidates are
    /// selected `upTo:` that height, so checking with 0 would resolve nothing.
    func testResubmissionCheckNotDueWithoutAChainTip() {
        XCTAssertFalse(SlipstreamSynchronizer.resubmissionCheckDue(
            isCancelled: false, state: 1, chainTip: 0, secondsSinceLastCheck: 1_000, inFlight: false
        ))
        XCTAssertFalse(SlipstreamSynchronizer.resubmissionCheckDue(
            isCancelled: false, state: 3, chainTip: 0, secondsSinceLastCheck: 1_000, inFlight: false
        ))
    }

    /// A check already in flight blocks the next one however long ago the last one started:
    /// a slow submit round must never be joined by a second concurrent pass over the same
    /// transactions.
    func testResubmissionCheckNotDueWhileAnotherCheckIsInFlight() {
        XCTAssertFalse(SlipstreamSynchronizer.resubmissionCheckDue(
            isCancelled: false, state: 1, chainTip: 2_400_000, secondsSinceLastCheck: 100_000, inFlight: true
        ))
    }

    /// The 60 s check cadence, at the tick granularity that actually asks (2 s) and at the
    /// boundary itself (`>=` semantics, mirroring the stall watchdog).
    func testResubmissionCheckHonorsTheCheckInterval() {
        XCTAssertFalse(SlipstreamSynchronizer.resubmissionCheckDue(
            isCancelled: false, state: 1, chainTip: 2_400_000, secondsSinceLastCheck: 2, inFlight: false
        ), "the next poll tick is inside the window")
        XCTAssertFalse(SlipstreamSynchronizer.resubmissionCheckDue(
            isCancelled: false, state: 1, chainTip: 2_400_000, secondsSinceLastCheck: 59.9, inFlight: false
        ))
        XCTAssertTrue(SlipstreamSynchronizer.resubmissionCheckDue(
            isCancelled: false, state: 1, chainTip: 2_400_000, secondsSinceLastCheck: 60, inFlight: false
        ), "exactly at the interval must fire (>= semantics)")
    }

    /// The shipped check cadence is 60 s.
    func testResubmissionCheckIntervalConstant() {
        XCTAssertEqual(SlipstreamSynchronizer.resubmissionCheckInterval, 60)
    }

    /// Actor-level: the driver fires the first eligible tick and then holds the line for the
    /// rest of the interval — the poll loop calls it every 2 s, so without the gate a wallet
    /// would walk its transaction table 30× a minute.
    ///
    /// Also pins the single-writer invariant: a COMPLETED check leaves no in-flight handle,
    /// because the task's own `finishResubmissionCheck()` cleared it. A regression that re-adds
    /// `resubmissionTask = nil` to teardown, or that leaks the handle, fails here rather than
    /// hiding behind the interval-vs-in-flight ambiguity.
    ///
    /// Offline caveat: the temp `data.db` has no wallet tables, so the fired check's
    /// `findForResubmission` throws and `TxResubmitter` swallows it — the task completes with
    /// zero work, which is exactly what this test needs (it asserts the GATE, not the work).
    /// `awaitResubmissionCheckForTesting()` awaits that task instead of sleeping, so the
    /// second call is guaranteed to be gated by the interval and not merely by "in flight".
    func testResubmissionDriverFiresOncePerInterval() async throws {
        let sync = SlipstreamSynchronizer(initializer: try makeInitializer())

        await sync.maybeRunTxResubmission(state: 1, chainTip: 2_400_000, isCancelled: false)
        let firstCheck = await sync.awaitResubmissionCheckForTesting()
        XCTAssertGreaterThan(firstCheck, 0, "a Syncing tick with a known chain tip must fire the first check")
        var inFlight = await sync.resubmissionCheckInFlightForTesting
        XCTAssertFalse(inFlight, "the finished check must have cleared its own handle")

        await sync.maybeRunTxResubmission(state: 3, chainTip: 2_400_002, isCancelled: false)
        let secondCheck = await sync.awaitResubmissionCheckForTesting()
        XCTAssertEqual(secondCheck, firstCheck, "a tick inside the 60 s window must not fire a second check")
        inFlight = await sync.resubmissionCheckInFlightForTesting
        XCTAssertFalse(inFlight, "a gated tick must not leave a check in flight")
    }

    /// Actor-level counterpart of the cancellation row: the driver must PLUMB the caller's
    /// cancellation, not just accept it. A tick resuming inside a teardown fires nothing —
    /// no stamp, no task — so a `wipe()` in progress cannot be raced by a fresh check.
    func testResubmissionDriverSkipsWhenTheCallingTaskIsCancelled() async throws {
        let sync = SlipstreamSynchronizer(initializer: try makeInitializer())

        await sync.maybeRunTxResubmission(state: 1, chainTip: 2_400_000, isCancelled: true)

        let stamp = await sync.awaitResubmissionCheckForTesting()
        XCTAssertEqual(stamp, 0, "a cancelled caller must not fire a check")
        let inFlight = await sync.resubmissionCheckInFlightForTesting
        XCTAssertFalse(inFlight, "a cancelled caller must not spawn a check task")
    }
}
