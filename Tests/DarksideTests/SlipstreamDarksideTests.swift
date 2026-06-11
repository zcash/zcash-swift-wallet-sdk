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
            for: .restoreWallet,
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
}
