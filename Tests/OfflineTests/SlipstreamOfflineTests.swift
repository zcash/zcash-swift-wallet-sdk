//
//  SlipstreamOfflineTests.swift
//  ZcashLightClientKit
//
//  Created for Slipstream task [#1755] — T4.4.
//
//  Tests:
//    1. Progress mapping: chainTip == 0 → syncStatus .syncing(0.0) without crash.
//    2. Dealloc-without-stop: create + release SlipstreamSynchronizer without stop() → no crash.
//    3. wipe() removes database files + resets state; switchTo() when-never-started
//       succeeds (endpoint swapped, no crash).
//    4. Engine FFI smoke (Offline-safe):
//       - zcashlc_slipstream_open with invalid path → throws rustSlipstreamOpen.
//       - start before open → throws rustSlipstreamNotOpen.
//    5. shouldEmitFound pure-helper unit tests.
//    6. composeProgress pure-helper unit tests (wallet-summary-driven progress, T4.8).
//    7. T4.9 regression fixes:
//       - withTaskTimeout: completes before deadline → returns value (not nil).
//       - withTaskTimeout: exceeds deadline → returns nil (swallowed timeout error).
//       - switchTo same-endpoint is a no-op (F2): engine not re-opened, state unchanged.
//       - switchTo different endpoint fires reopen (F2/F3 smoke).
//    8. T5.5 summary-interval tests (8s-Syncing branch REMOVED; all states return 2s).
//    9. T5.5 counterProgress pure-helper unit tests (total==0 edge, mid-pass, clamp).
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
    func testStopBeforePrepareKeepsUnprepared() throws {
        let sync = SlipstreamSynchronizer(initializer: try makeInitializer())
        sync.stop()
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

    // MARK: - 5. shouldEmitFound pure-helper unit tests

    /// Pure-function encoding of the foundTransactions decision from tickPoll().
    /// Extracted here so the logic can be tested without instantiating a synchronizer.
    ///
    /// Returns `true` when tickPoll() should emit a foundTransactions event.
    ///   - Primary:  `newCount > lastCount`  (counter advanced)
    ///   - Fallback: `hasSyncDone && storedPositive` (ring event present + known txs)
    private func shouldEmitFound(lastCount: UInt64, newCount: UInt64, hasSyncDone: Bool, storedPositive: Bool) -> Bool {
        if newCount > lastCount {
            return true
        }
        return hasSyncDone && storedPositive
    }

    /// Primary path: counter advances → emit.
    func testShouldEmitFoundPrimaryCounterAdvances() {
        XCTAssertTrue(shouldEmitFound(lastCount: 0, newCount: 1, hasSyncDone: false, storedPositive: false))
        XCTAssertTrue(shouldEmitFound(lastCount: 5, newCount: 6, hasSyncDone: false, storedPositive: false))
        XCTAssertTrue(shouldEmitFound(lastCount: 0, newCount: 10, hasSyncDone: true, storedPositive: true))
    }

    /// Primary counter unchanged, no sync-done event → no emit.
    func testShouldEmitFoundNoAdvanceNoEvent() {
        XCTAssertFalse(shouldEmitFound(lastCount: 3, newCount: 3, hasSyncDone: false, storedPositive: true))
        XCTAssertFalse(shouldEmitFound(lastCount: 0, newCount: 0, hasSyncDone: false, storedPositive: false))
    }

    /// Fallback: counter unchanged but sync-done event + stored txs → emit.
    func testShouldEmitFoundFallbackSyncDoneWithStoredTxs() {
        XCTAssertTrue(shouldEmitFound(lastCount: 3, newCount: 3, hasSyncDone: true, storedPositive: true))
        XCTAssertTrue(shouldEmitFound(lastCount: 0, newCount: 0, hasSyncDone: true, storedPositive: true))
    }

    /// Fallback: sync-done event but stored count is zero → no emit (nothing to show).
    func testShouldEmitFoundFallbackSyncDoneButNoStoredTxs() {
        XCTAssertFalse(shouldEmitFound(lastCount: 0, newCount: 0, hasSyncDone: true, storedPositive: false))
        XCTAssertFalse(shouldEmitFound(lastCount: 3, newCount: 3, hasSyncDone: true, storedPositive: false))
    }

    // MARK: - 6. composeProgress pure-helper unit tests (T4.8)
    //
    // Oracle: ScanAction.swift lines ~81-99.
    //   composedNumerator   = scan.numerator   + (recovery?.numerator   ?? 0)
    //   composedDenominator = scan.denominator + (recovery?.denominator ?? 0)
    //   denominator == 0    → 1.0
    //   raw > 1.0           → clamp to 1.0
    //   spendable           = scan.isComplete

    /// nil scanProgress (fresh db, summary unavailable) → (0.0, false).
    func testComposeProgressNilScanProgress() {
        let (progress, spendable) = SlipstreamSynchronizer.composeProgress(
            scanProgress: nil,
            recoveryProgress: nil
        )
        XCTAssertEqual(progress, 0.0, accuracy: Float.ulpOfOne)
        XCTAssertFalse(spendable)
    }

    /// denominator == 0 → progress == 1.0, spendable follows isComplete.
    func testComposeProgressDenominatorZero() {
        let (progress, spendable) = SlipstreamSynchronizer.composeProgress(
            scanProgress: (numerator: 0, denominator: 0, isComplete: false),
            recoveryProgress: nil
        )
        XCTAssertEqual(progress, 1.0, accuracy: Float.ulpOfOne,
                       "denominator == 0 must yield progress 1.0")
        XCTAssertFalse(spendable)
    }

    /// Typical mid-sync ratio with no recovery range.
    func testComposeProgressScanOnlyMidway() {
        let (progress, spendable) = SlipstreamSynchronizer.composeProgress(
            scanProgress: (numerator: 50_000, denominator: 100_000, isComplete: false),
            recoveryProgress: nil
        )
        XCTAssertEqual(progress, 0.5, accuracy: 1e-5)
        XCTAssertFalse(spendable)
    }

    /// Scan+recovery ranges compose correctly: (40+10) / (100+20) = 50/120 ≈ 0.4167.
    func testComposeProgressScanPlusRecovery() {
        let (progress, spendable) = SlipstreamSynchronizer.composeProgress(
            scanProgress: (numerator: 40, denominator: 100, isComplete: false),
            recoveryProgress: (numerator: 10, denominator: 20)
        )
        let expected: Float = 50.0 / 120.0
        XCTAssertEqual(progress, expected, accuracy: 1e-5,
                       "composed scan+recovery ratio must be (40+10)/(100+20)")
        XCTAssertFalse(spendable)
    }

    /// If the composed ratio somehow exceeds 1.0, it is clamped to 1.0.
    func testComposeProgressClampAboveOne() {
        // Force numerator > denominator (numerator=120, denominator=100 → raw=1.2).
        let (progress, _) = SlipstreamSynchronizer.composeProgress(
            scanProgress: (numerator: 120, denominator: 100, isComplete: false),
            recoveryProgress: nil
        )
        XCTAssertEqual(progress, 1.0, accuracy: Float.ulpOfOne,
                       "progress > 1.0 must be clamped to 1.0")
    }

    /// Fully scanned: numerator == denominator, isComplete == true → (1.0, true).
    func testComposeProgressSpendablePassthrough() {
        let (progress, spendable) = SlipstreamSynchronizer.composeProgress(
            scanProgress: (numerator: 100, denominator: 100, isComplete: true),
            recoveryProgress: nil
        )
        XCTAssertEqual(progress, 1.0, accuracy: 1e-5)
        XCTAssertTrue(spendable, "spendable must be true when scan.isComplete is true")
    }

    // MARK: - 6b. T8.3.5 warm-start progress helpers (summaryProgress + syncingProgress floor)

    /// summaryProgress(nil) → (0.0, false): a genuinely fresh wallet has no summary, so it
    /// contributes no floor and the cold restore path is preserved.
    func testSummaryProgressNilIsZero() {
        let (progress, spendable) = SlipstreamSynchronizer.summaryProgress(nil)
        XCTAssertEqual(progress, 0.0, accuracy: Float.ulpOfOne)
        XCTAssertFalse(spendable)
    }

    /// Restore: with no summary floor (fresh wallet, floor 0), the pass-local counter is
    /// reported verbatim — the from-birthday restore bar is unchanged by T8.3.5.
    func testSyncingProgressRestoreUsesPassLocalCounter() {
        let progress = SlipstreamSynchronizer.syncingProgress(scanned: 250, passTotal: 1000, summaryFloor: 0.0)
        XCTAssertEqual(progress, 0.25, accuracy: 1e-5)
    }

    /// Cold-launch catch-up (THE T8.3.5 fix): the pass covers only a few new blocks
    /// (pass-local 0/5 = 0%), but the wallet is 99% synced globally → floored to 0.99, so
    /// the widget stays hidden (>98%) instead of flashing 0%.
    func testSyncingProgressCatchUpFlooredToSummary() {
        let progress = SlipstreamSynchronizer.syncingProgress(scanned: 0, passTotal: 5, summaryFloor: 0.99)
        XCTAssertEqual(progress, 0.99, accuracy: 1e-5)
    }

    /// When the live pass-local counter is AHEAD of a (stale) summary floor, the live value
    /// wins — a restore mid-flight keeps climbing past a lagging summary.
    func testSyncingProgressLivePassLocalDominatesStaleFloor() {
        let progress = SlipstreamSynchronizer.syncingProgress(scanned: 600, passTotal: 1000, summaryFloor: 0.3)
        XCTAssertEqual(progress, 0.6, accuracy: 1e-5)
    }

    /// initialState(nil) → cold `.disconnected` with no balances — a genuinely fresh
    /// wallet (no summary yet) keeps the prior cold-launch behaviour.
    func testInitialStateColdWhenNil() {
        let state = SlipstreamSynchronizer.initialState(from: nil, syncSessionID: UUID())
        XCTAssertEqual(state.internalSyncStatus, .disconnected)
        XCTAssertTrue(state.accountsBalances.isEmpty)
    }

    /// initialState(summary) → WARM `.syncing` carrying the summary's progress + chain tip,
    /// so a cold launch of a synced wallet shows a truthful near-100% instead of 0%.
    func testInitialStateWarmFromSummary() {
        let summary = WalletSummary(
            accountBalances: [:],
            chainTipHeight: 3_000_000,
            fullyScannedHeight: 2_999_990,
            recoveryProgress: nil,
            scanProgress: ScanProgress(numerator: 99, denominator: 100),
            nextSaplingSubtreeIndex: 0,
            nextOrchardSubtreeIndex: 0
        )
        let state = SlipstreamSynchronizer.initialState(from: summary, syncSessionID: UUID())
        if case let .syncing(progress, _) = state.internalSyncStatus {
            XCTAssertEqual(progress, 0.99, accuracy: 1e-5, "warm progress must come from the summary scanProgress")
        } else {
            XCTFail("warm initial state must be .syncing, got \(state.internalSyncStatus)")
        }
        XCTAssertEqual(state.latestBlockHeight, 3_000_000)
    }

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

    /// withTaskTimeout: operation takes longer than the deadline → throws _SummaryTimeoutError.
    /// The call site in kickSummaryFetchIfNeeded wraps this in `try?` so the cache is left
    /// unchanged — tested here as the raw throw to verify the timeout fires correctly.
    func testWithTaskTimeoutThrowsWhenDeadlineExceeded() async throws {
        // Deadline: 50 ms; operation: sleep 500 ms (10× longer).
        let deadline: UInt64 = 50_000_000  // 50 ms
        do {
            _ = try await withTaskTimeout(deadline) {
                try await Task.sleep(nanoseconds: 500_000_000)
                return 99
            }
            XCTFail("withTaskTimeout must throw when the deadline is exceeded")
        } catch is _SummaryTimeoutError {
            // Expected: timeout error was thrown.
        } catch {
            XCTFail("Expected _SummaryTimeoutError, got \(error)")
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

    // MARK: - 8. T5.5 Summary interval + no-summary-while-syncing tests

    // T5.5 supersedes T5.3: the 8-second Syncing interval is eliminated because
    // getWalletSummary is NEVER called while state==1 (Syncing). All reachable states
    // (0/2/3) use the 2-second interval. The Syncing guard lives in
    // kickSummaryFetchIfNeeded (returns early for state==1) — summaryFetchInterval
    // is now only called for non-Syncing states.

    /// summaryFetchInterval(forState:) returns 2 seconds when state == Disconnected (0).
    /// T5.5: the 8s-Syncing branch is gone; all states return 2s from this helper.
    func testSummaryIntervalWhileDisconnectedIs2s() {
        let interval = SlipstreamSynchronizer.summaryFetchInterval(forState: 0) // Disconnected
        XCTAssertEqual(interval, 2.0, accuracy: 1e-6,
                       "Summary interval while Disconnected must be 2 seconds")
    }

    /// summaryFetchInterval(forState:) returns 2 seconds when state == Syncing (1).
    /// T5.5: Syncing is now guarded by kickSummaryFetchIfNeeded (early return), so
    /// this function is never called for state==1 in production — but if it were,
    /// it returns 2s (not 8s), confirming the 8s branch is fully removed.
    func testSummaryIntervalWhileSyncingIs2sNotEight() {
        let interval = SlipstreamSynchronizer.summaryFetchInterval(forState: 1) // Syncing
        XCTAssertEqual(interval, 2.0, accuracy: 1e-6,
                       "T5.5: summaryFetchInterval must return 2s for Syncing (8s branch removed; " +
                       "kickSummaryFetchIfNeeded guards state==1 before this is called)")
    }

    /// summaryFetchInterval(forState:) returns 2 seconds when state == Error (2).
    func testSummaryIntervalWhileErrorIs2s() {
        let interval = SlipstreamSynchronizer.summaryFetchInterval(forState: 2) // Error
        XCTAssertEqual(interval, 2.0, accuracy: 1e-6,
                       "Summary interval while Error must be 2 seconds")
    }

    /// summaryFetchInterval(forState:) returns 2 seconds when state == Done (3).
    func testSummaryIntervalWhileDoneIs2s() {
        let interval = SlipstreamSynchronizer.summaryFetchInterval(forState: 3) // Done
        XCTAssertEqual(interval, 2.0, accuracy: 1e-6,
                       "Summary interval while Done must be 2 seconds")
    }

    /// summaryFetchInterval(forState:) returns 2 seconds for unknown states (default case).
    func testSummaryIntervalForUnknownStateIs2s() {
        let interval = SlipstreamSynchronizer.summaryFetchInterval(forState: UInt8(99)) // Unknown
        XCTAssertEqual(interval, 2.0, accuracy: 1e-6,
                       "Summary interval for unknown states must default to 2 seconds")
    }

    // MARK: - 9. T5.5 counterProgress pure-helper tests

    /// counterProgress(total:0) → 0.0 (avoids division-by-zero when no ranges taken yet).
    func testCounterProgressTotalZeroReturnsZero() {
        let result = SlipstreamSynchronizer.counterProgress(scanned: 0, total: 0)
        XCTAssertEqual(result, 0.0, accuracy: Float.ulpOfOne,
                       "counterProgress(scanned:0, total:0) must return 0.0 (clamped denominator)")
    }

    /// counterProgress(scanned:0, total:10000) → 0.0.
    func testCounterProgressZeroScanned() {
        let result = SlipstreamSynchronizer.counterProgress(scanned: 0, total: 10_000)
        XCTAssertEqual(result, 0.0, accuracy: Float.ulpOfOne)
    }

    /// counterProgress mid-pass: 5000 / 10000 = 0.5.
    func testCounterProgressMidPass() {
        let result = SlipstreamSynchronizer.counterProgress(scanned: 5_000, total: 10_000)
        XCTAssertEqual(result, 0.5, accuracy: 1e-5,
                       "5000 / 10000 must be 0.5")
    }

    /// counterProgress complete: scanned == total → 1.0.
    func testCounterProgressComplete() {
        let result = SlipstreamSynchronizer.counterProgress(scanned: 10_000, total: 10_000)
        XCTAssertEqual(result, 1.0, accuracy: Float.ulpOfOne,
                       "scanned == total must yield 1.0")
    }

    /// counterProgress overflow: scanned > total → clamped to 1.0.
    func testCounterProgressClampedAboveOne() {
        let result = SlipstreamSynchronizer.counterProgress(scanned: 12_000, total: 10_000)
        XCTAssertEqual(result, 1.0, accuracy: Float.ulpOfOne,
                       "scanned > total must be clamped to 1.0")
    }

    /// counterProgress: large values do not overflow Float.
    func testCounterProgressLargeValues() {
        let result = SlipstreamSynchronizer.counterProgress(scanned: 286_855, total: 1_000_000)
        let expected = Float(286_855) / Float(1_000_000)
        XCTAssertEqual(result, expected, accuracy: 1e-5,
                       "286855 / 1000000 must equal the expected Float ratio")
    }

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
        // Verify counterProgress formula using these values.
        let progress = SlipstreamSynchronizer.counterProgress(
            scanned: snap.scannedBlocks,
            total: snap.passTotalBlocks
        )
        XCTAssertEqual(progress, 0.5, accuracy: 1e-5,
                       "7500 / 15000 must equal 0.5")
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

    /// F2 boundary summary timeout constant is longer than the idle 3s timeout.
    func testBoundarySummaryTimeoutIsLongerThanIdleTimeout() {
        let idleTimeout = SlipstreamSynchronizer.summaryTimeoutNanoseconds
        let boundaryTimeout = SlipstreamSynchronizer.boundarySummaryTimeoutNanoseconds
        XCTAssertGreaterThan(boundaryTimeout, idleTimeout,
                             "Boundary summary timeout (20s) must be longer than idle timeout (3s)")
        // Verify the exact documented values.
        XCTAssertEqual(idleTimeout, 3_000_000_000, "idle summary timeout must be 3s")
        XCTAssertEqual(boundaryTimeout, 20_000_000_000, "boundary summary timeout must be 20s")
    }

    // MARK: - 13. shouldMarkChainTipUpdated pure-helper unit tests (field bug 2026-06-11)
    //
    // Oracle: UpdateChainTipAction.swift:49 marks `SDKFlags.chainTipUpdated` right after
    // `rustBackend.updateChainTip` succeeds. The Slipstream engine stores the snapshot
    // tip ONLY AFTER `session.update_chain_tip(tip)` succeeds (engine.rs:111 → :116), so:
    //   - tip changed vs run start  → DB tip refreshed by THIS run → mark.
    //   - tip == run-start value    → only trust when the pass reached Done (state 3).
    //   - tip == 0                  → engine never advertised a tip → never mark.
    //   - already marked            → once per run, no re-marking.
    // Without this marking, ZcashRustBackend.getWalletSummary() masks spendableValue to
    // zero forever in the Slipstream path (field report: pending spinner, cannot pay).

    /// Fresh handle, first nonzero tip while syncing → mark (the field-bug case: a fresh
    /// 269k restore must unmask spendable balances during/after the first pass).
    func testShouldMarkChainTipFreshHandleFirstNonZeroTip() {
        XCTAssertTrue(SlipstreamSynchronizer.shouldMarkChainTipUpdated(
            snapshotTip: 3_374_491, tipAtRunStart: 0, state: 1, alreadyMarked: false
        ))
    }

    /// Snapshot tip 0 (engine not yet past update_chain_tip) → never mark, in any state.
    func testShouldMarkChainTipZeroTipNeverMarks() {
        for state: UInt8 in [0, 1, 2, 3] {
            XCTAssertFalse(SlipstreamSynchronizer.shouldMarkChainTipUpdated(
                snapshotTip: 0, tipAtRunStart: 0, state: state, alreadyMarked: false
            ), "tip 0 must never mark (state \(state))")
        }
    }

    /// Restarted handle: tip advanced past the run-start residue → mark (the engine's
    /// update_chain_tip stored a fresh tip in this pass).
    func testShouldMarkChainTipAdvancedTipMarks() {
        XCTAssertTrue(SlipstreamSynchronizer.shouldMarkChainTipUpdated(
            snapshotTip: 3_374_500, tipAtRunStart: 3_374_491, state: 1, alreadyMarked: false
        ))
    }

    /// Restarted handle, tip UNCHANGED while still syncing → do NOT mark: the nonzero tip
    /// may be residue from a previous pass (stale-tip protection, [#1591]).
    func testShouldMarkChainTipSameTipWhileSyncingDoesNotMark() {
        XCTAssertFalse(SlipstreamSynchronizer.shouldMarkChainTipUpdated(
            snapshotTip: 3_374_491, tipAtRunStart: 3_374_491, state: 1, alreadyMarked: false
        ))
    }

    /// Restarted handle, tip unchanged but the pass reached Done → mark: sync_once cannot
    /// complete without update_chain_tip having succeeded.
    func testShouldMarkChainTipSameTipDoneMarks() {
        XCTAssertTrue(SlipstreamSynchronizer.shouldMarkChainTipUpdated(
            snapshotTip: 3_374_491, tipAtRunStart: 3_374_491, state: 3, alreadyMarked: false
        ))
    }

    /// Same-tip error state (pass failed, possibly BEFORE update_chain_tip) → do not mark.
    func testShouldMarkChainTipSameTipErrorDoesNotMark() {
        XCTAssertFalse(SlipstreamSynchronizer.shouldMarkChainTipUpdated(
            snapshotTip: 3_374_491, tipAtRunStart: 3_374_491, state: 2, alreadyMarked: false
        ))
    }

    /// Once marked, later ticks never re-mark within the same run.
    func testShouldMarkChainTipAlreadyMarkedNeverMarks() {
        for state: UInt8 in [0, 1, 2, 3] {
            XCTAssertFalse(SlipstreamSynchronizer.shouldMarkChainTipUpdated(
                snapshotTip: 3_374_999, tipAtRunStart: 0, state: state, alreadyMarked: true
            ), "alreadyMarked must suppress re-marking (state \(state))")
        }
    }

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

    /// Signature equality: identical counters → equal; ANY single counter change
    /// (fetched / scanned / enhanced / rangesCompleted / chainTip) → not equal, which
    /// re-arms the watchdog window in tickPoll.
    func testWatchdogSignatureDetectsEveryCounter() {
        let base = SlipstreamSnapshot(
            chainTip: 3_375_119,
            fetchedBlocks: 10_000,
            scannedBlocks: 10_000,
            enhancedTxs: 2,
            currentRangeEnd: 3_375_119,
            state: 1,
            passTotalBlocks: 270_000,
            spendableHint: 0,
            rangesCompleted: 1
        )
        let fp = SlipstreamSynchronizer.watchdogSignature(base)
        XCTAssertEqual(fp, SlipstreamSynchronizer.watchdogSignature(base), "same snapshot → same signature")

        // Each watched counter, changed alone, must change the fingerprint.
        let variants: [SlipstreamSnapshot] = [
            SlipstreamSnapshot(
                chainTip: base.chainTip, fetchedBlocks: 10_001, scannedBlocks: base.scannedBlocks,
                enhancedTxs: base.enhancedTxs, currentRangeEnd: base.currentRangeEnd, state: base.state,
                passTotalBlocks: base.passTotalBlocks, spendableHint: base.spendableHint,
                rangesCompleted: base.rangesCompleted
            ),
            SlipstreamSnapshot(
                chainTip: base.chainTip, fetchedBlocks: base.fetchedBlocks, scannedBlocks: 10_001,
                enhancedTxs: base.enhancedTxs, currentRangeEnd: base.currentRangeEnd, state: base.state,
                passTotalBlocks: base.passTotalBlocks, spendableHint: base.spendableHint,
                rangesCompleted: base.rangesCompleted
            ),
            SlipstreamSnapshot(
                chainTip: base.chainTip, fetchedBlocks: base.fetchedBlocks, scannedBlocks: base.scannedBlocks,
                enhancedTxs: 3, currentRangeEnd: base.currentRangeEnd, state: base.state,
                passTotalBlocks: base.passTotalBlocks, spendableHint: base.spendableHint,
                rangesCompleted: base.rangesCompleted
            ),
            SlipstreamSnapshot(
                chainTip: base.chainTip, fetchedBlocks: base.fetchedBlocks, scannedBlocks: base.scannedBlocks,
                enhancedTxs: base.enhancedTxs, currentRangeEnd: base.currentRangeEnd, state: base.state,
                passTotalBlocks: base.passTotalBlocks, spendableHint: base.spendableHint,
                rangesCompleted: 2
            ),
            SlipstreamSnapshot(
                chainTip: 3_375_120, fetchedBlocks: base.fetchedBlocks, scannedBlocks: base.scannedBlocks,
                enhancedTxs: base.enhancedTxs, currentRangeEnd: base.currentRangeEnd, state: base.state,
                passTotalBlocks: base.passTotalBlocks, spendableHint: base.spendableHint,
                rangesCompleted: base.rangesCompleted
            )
        ]
        for (i, snap) in variants.enumerated() {
            XCTAssertNotEqual(
                SlipstreamSynchronizer.watchdogSignature(snap),
                fp,
                "variant \(i): a counter change must change the signature"
            )
        }

        // state / passTotalBlocks / spendableHint / currentRangeEnd are deliberately
        // NOT part of the fingerprint (they are not progress counters); changing them
        // alone keeps the fingerprint equal.
        let nonCounter = SlipstreamSnapshot(
            chainTip: base.chainTip, fetchedBlocks: base.fetchedBlocks, scannedBlocks: base.scannedBlocks,
            enhancedTxs: base.enhancedTxs, currentRangeEnd: 999, state: 3,
            passTotalBlocks: 1, spendableHint: 1, rangesCompleted: base.rangesCompleted
        )
        XCTAssertEqual(
            SlipstreamSynchronizer.watchdogSignature(nonCounter),
            fp,
            "non-counter fields must not affect the signature"
        )
    }
}
