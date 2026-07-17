//
//  SlipstreamDarksideTests.swift
//  ZcashLightClientKit
//
//  Created for Slipstream task [#1755] — T4.4.
//
//  End-to-end scenario on `SlipstreamSynchronizer` using the darkside lightwalletd fixtures.
//
//  The lightwalletd v0.4.9 binary (Tests/lightwalletd/) does NOT implement AddTreeState RPC
//  (returns "unimplemented (12)"). ALL existing Swift DarksideTests (BalanceTests,
//  DarksideSanityCheckTests, SynchronizerDarksideTests, …) that call FakeChainBuilder.buildChain
//  also fail with this same error — so v0.4.9 is incompatible with the full buildChain fixture.
//
//  This test uses the minimal staging path that v0.4.9 DOES support:
//    reset → useDataset (before-reorg.txt URL) → stageBlocksCreate → applyStaged
//  and verifies that the SlipstreamSynchronizer can:
//    1. prepare() successfully (db init + engine open).
//    2. start() without crashing (Slipstream FFI round-trip confirmed).
//    3. Reach either .synced or .error within the timeout (not hang forever).
//
//  Full balance/tx-count parity requires a lightwalletd ≥ v0.5 (AddTreeState) or
//  the zaino server. This is recorded as a DONE_WITH_CONCERNS finding in STATE.md T4.4.
//
//  Requires: Tests/lightwalletd/lightwalletd started externally on port 9067 (no-tls / darkside mode).
//

import Combine
import Foundation
import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

class SlipstreamDarksideTests: ZcashTestCase {
    let birthday: BlockHeight = 663150
    let branchID = "e9ff75a6"
    let chainName = "main"
    let network: ZcashNetwork = DarksideWalletDNetwork()

    var darksideService: DarksideWalletService!
    var databases: TemporaryTestDatabases!
    var initializer: Initializer!
    var cancellables: [AnyCancellable] = []

    override func setUp() async throws {
        try await super.setUp()

        mockContainer.mock(type: CheckpointSource.self, isSingleton: true) { _ in
            DarksideMainnetCheckpointSource()
        }

        databases = TemporaryDbBuilder.build()

        let endpoint = TestCoordinator.defaultEndpoint

        initializer = Initializer(
            container: mockContainer,
            cacheDbURL: nil,
            fsBlockDbRoot: databases.fsCacheDbRoot,
            generalStorageURL: databases.generalStorageURL,
            dataDbURL: databases.dataDB,
            torDirURL: databases.torDir,
            endpoint: endpoint,
            network: network,
            spendParamsURL: try __spendParamsURL(),
            outputParamsURL: try __outputParamsURL(),
            saplingParamsSourceURL: SaplingParamsSourceURL.tests,
            alias: .default,
            loggingPolicy: .default(.debug),
            isTorEnabled: false,
            isExchangeRateEnabled: false
        )

        let liveService = LightWalletServiceFactory(endpoint: endpoint).make()
        darksideService = DarksideWalletService(endpoint: endpoint, service: liveService)

        // Reset darkside server using the minimal path supported by lightwalletd v0.4.9.
        // NOTE: v0.4.9 does NOT implement AddTreeState; FakeChainBuilder.buildChain fails.
        // We use reset + useDataset (before-reorg URL) + stageBlocksCreate + applyStaged.
        try darksideService.reset(
            saplingActivation: birthday,
            startSaplingTreeSize: 128607,
            startOrchardTreeSize: 0,
            branchID: branchID,
            chainName: chainName
        )
    }

    override func tearDown() async throws {
        cancellables = []
        try? FileManager.default.removeItem(at: databases.fsCacheDbRoot)
        try? FileManager.default.removeItem(at: databases.dataDB)
        databases = nil
        initializer = nil
        darksideService = nil
        try await super.tearDown()
    }

    // MARK: - Prepare + start round-trip smoke test

    /// Verifies the SlipstreamSynchronizer prepare+start path end-to-end.
    ///
    /// Chain setup (v0.4.9-safe, no AddTreeState):
    ///   reset → useDataset(beforeReOrg) → stageBlocksCreate(663151, count:50) → applyStaged(663200)
    ///
    /// The test asserts:
    ///   - prepare() returns .success (db init + engine handle opens).
    ///   - start() does not throw (FFI round-trip: open→start confirmed).
    ///   - stateStream emits a non-.unprepared state within 30 s (sync makes forward progress
    ///     or completes; may finish with .error if server limits scanning without tree state,
    ///     which is a known v0.4.9 limitation).
    ///   - stop() does not crash.
    ///
    /// Full balance/tx assertions are gated on lightwalletd ≥ v0.5 (AddTreeState support).
    func testSlipstreamPrepareAndStartRoundTrip() async throws {
        // Stage blocks via v0.4.9-safe APIs only.
        try darksideService.useDataset(DarksideDataset.beforeReOrg.rawValue)
        try darksideService.stageBlocksCreate(from: 663151, count: 50)
        try darksideService.applyStaged(nextLatestHeight: 663200)
        sleep(2) // Allow darkside state to propagate.

        // ── Create synchronizer ───────────────────────────────────────────────────
        let sync = SlipstreamSynchronizer(initializer: initializer)

        // ── prepare ───────────────────────────────────────────────────────────────
        let result = try await sync.prepare(
            with: Environment.seedBytes,
            walletBirthday: birthday,
            name: "",
            keySource: nil
        )
        XCTAssertEqual(result, .success, "prepare() must return .success")

        // ── start + await non-unprepared state ────────────────────────────────────
        let progressExpectation = XCTestExpectation(description: "stateStream emits non-unprepared state")
        progressExpectation.assertForOverFulfill = false

        sync.stateStream
            .filter { $0.internalSyncStatus != .unprepared }
            .first()
            .sink { _ in progressExpectation.fulfill() }
            .store(in: &cancellables)

        // start() must not throw.
        try await sync.start(retry: false)

        await fulfillment(of: [progressExpectation], timeout: 30)

        // ── stop ──────────────────────────────────────────────────────────────────
        sync.stop()
    }

    // MARK: - importAccount re-scan path round-trip ([#1755])

    /// Drives the [#1755] importAccount re-scan path — `importAccount` → clear cached summary (drop
    /// the progress floor) → `start()` restart — through the REAL FFI/engine on a RUNNING synchronizer.
    ///
    /// lightwalletd v0.4.9 cannot fully sync (no AddTreeState), so this can NOT assert the progress
    /// DIP the fix produces on mainnet — that is covered by the pure-logic tests in
    /// `SlipstreamOfflineTests` (`testSyncingProgressLargeRescanMaskedByStaleFloor` /
    /// `…VisibleWithFreshFloor` / `testComposeProgressFreshlyImportedOldBirthdayIsBelowBannerThreshold`)
    /// and by the manual mainnet acceptance gate. What it DOES validate end-to-end: importing a
    /// second account on a running synchronizer completes without crashing/hanging, returns a UUID,
    /// and the import-triggered restart keeps the synchronizer alive and emitting.
    func testImportAccountRescanPathRoundTrip() async throws {
        try darksideService.useDataset(DarksideDataset.beforeReOrg.rawValue)
        try darksideService.stageBlocksCreate(from: 663151, count: 50)
        try darksideService.applyStaged(nextLatestHeight: 663200)
        sleep(2) // Allow darkside state to propagate.

        let sync = SlipstreamSynchronizer(initializer: initializer)
        let result = try await sync.prepare(
            with: Environment.seedBytes,
            walletBirthday: birthday,
            name: "",
            keySource: nil
        )
        XCTAssertEqual(result, .success, "prepare() must return .success")

        try await sync.start(retry: false)
        sleep(2) // Let the engine reach a running state before importing.

        // A second account's UFVK, derived from the same test seed at account index 1.
        let derivationTool = DerivationTool(networkType: network.networkType)
        let usk = try derivationTool.deriveUnifiedSpendingKey(seed: Environment.seedBytes, accountIndex: Zip32AccountIndex(1))
        let ufvk = try derivationTool.deriveUnifiedFullViewingKey(from: usk)

        // THE [#1755] PATH: rustBackend.importAccount → clear cached summary (floor) → start() restart.
        // Must not throw/crash; returns a UUID. Imported as an EXTERNAL UFVK (seedFingerprint and
        // zip32AccountIndex both absent — librustzcash requires both-present or both-absent), which
        // is the hardware-wallet / Keystone shape this fix targets.
        _ = try await sync.importAccount(
            ufvk: ufvk.stringEncoded,
            seedFingerprint: nil,
            zip32AccountIndex: nil,
            purpose: .viewOnly,
            name: "second",
            keySource: nil,
            birthday: birthday
        )

        // The import-triggered restart must keep the synchronizer alive + emitting a real state.
        let stillEmitting = XCTestExpectation(description: "synchronizer keeps emitting after import-triggered restart")
        stillEmitting.assertForOverFulfill = false
        sync.stateStream
            .filter { $0.internalSyncStatus != .unprepared }
            .first()
            .sink { _ in stillEmitting.fulfill() }
            .store(in: &cancellables)
        await fulfillment(of: [stillEmitting], timeout: 30)

        sync.stop()
    }
}
