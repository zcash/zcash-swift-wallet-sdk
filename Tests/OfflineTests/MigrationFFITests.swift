//
//  MigrationFFITests.swift
//  OfflineTests
//
//  Exercises the Orchard -> Ironwood migration FFI marshaling and the empty-DB state machine
//  through the real ZcashRustBackend welding, against a freshly initialized, never-synced wallet
//  database (no network, no scanning). Complements MigrationLogicTests.swift (pure logic, mocked
//  welding) and OrchardMigrationCompositionTests.swift (actor composition, mocked welding): this is
//  the one place the SDK's committed migration FFI (rust/src/migration.rs, welded in
//  ZcashRustBackend) is exercised through the real libzcashlc, so a marshaling regression (wrong
//  sentinel, wrong error mapping, wrong tag) shows up here rather than only downstream.
//
//  Ports Tests/OfflineTests/MigrationFFITests.swift from the michal/MOB-1455-ironwood-migration-
//  prototype-ffi branch (commit 86450d54) to the committed API: method names/signatures changed
//  (ZcashRustBackendWelding.migrationState(for:) etc.), MigrationTransferResult.success now takes
//  `txId:` (display-hex) rather than `txid:`, and there is no `migrationInitializePostUpgrade` in
//  the committed surface -- account creation now goes through the standard `createAccount` fixture
//  pattern instead.
//
//  The balance-bearing paths (note splitting, proposing/signing transfers) need a seeded, synced
//  wallet with a real Orchard balance -- a documented integration gap, consistent with every other
//  file under OfflineTests (no network, no lightwalletd) -- so they are not covered here.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class MigrationFFITests: XCTestCase {
    var dbData: URL!
    var rustBackend: ZcashRustBackendWelding!
    var account: AccountUUID!
    var usk: UnifiedSpendingKey!

    override func setUp() async throws {
        try await super.setUp()

        dbData = try __dataDbURL()
        rustBackend = ZcashRustBackend.makeForTests(
            dbData: dbData,
            fsBlockDbRoot: Environment.uniqueTestTempDirectory,
            networkType: .testnet
        )

        let dbInit = try await rustBackend.initDataDb(seed: nil)
        guard case .success = dbInit else {
            XCTFail("Failed to initDataDb. Expected `.success`, got \(String(describing: dbInit))")
            return
        }

        // A real, created account -- mirroring ZcashRustBackendTests/IronwoodFFITests -- rather than
        // a bare, never-registered AccountUUID: some migration welding calls read the wallet schema
        // (via the engine's `open_wallet`), so the fixture needs an actual `accounts` row to be
        // representative of real usage, even though this specific empty-DB state machine happens not
        // to depend on it for most of the assertions below (see the throwing tests further down).
        let checkpointSource = CheckpointSourceFactory.fromBundle(for: .testnet)
        let treeState = checkpointSource.latestKnownCheckpoint().treeState()
        usk = try await rustBackend.createAccount(
            seed: Environment.seedBytes,
            treeState: treeState,
            recoverUntil: nil,
            name: "",
            keySource: nil
        )
        let accounts = try await rustBackend.listAccounts()
        account = try XCTUnwrap(accounts.first?.id)
    }

    override func tearDown() {
        super.tearDown()
        try? FileManager.default.removeItem(at: dbData!)
        rustBackend = nil
        account = nil
        usk = nil
    }

    // MARK: - Empty-DB state machine

    func testFreshWalletMigrationStateIsNotStarted() async throws {
        let state = try await rustBackend.migrationState(for: account)
        XCTAssertEqual(state, MigrationState.notStarted)
    }

    func testFreshWalletMigrationProgressIsNil() async throws {
        let progress = try await rustBackend.migrationProgress(for: account)
        XCTAssertNil(progress)
    }

    func testFreshWalletHasNoOverdueTransfers() async throws {
        let hasOverdue = try await rustBackend.migrationHasOverdueTransfers(for: account)
        XCTAssertFalse(hasOverdue)
    }

    func testFreshWalletHasNoInvalidTransfers() async throws {
        let hasInvalid = try await rustBackend.migrationHasInvalidTransfers(for: account)
        XCTAssertFalse(hasInvalid)
    }

    func testFreshWalletHasNoNextDueTransfer() async throws {
        let nextDue = try await rustBackend.migrationNextDueTransfer(for: account)
        XCTAssertNil(nextDue)
    }

    /// Unlike `isNoteSplitNeeded`/`residualAfterMigration` (which read the spendable Orchard balance
    /// and so throw `NotSynced` on this never-synced fixture), `pendingTransferProposal` short-
    /// circuits to `Ok(None)` as soon as it sees no active migration run -- it never reaches the
    /// target-height read. So on a fresh db it marshals as a benign `nil` (a NULL pointer with no
    /// recorded last-error), not a throw: the pointer-sentinel analog of `nextDueTransfer`'s nil.
    func testFreshWalletHasNoPendingTransferProposal() async throws {
        let pending = try await rustBackend.migrationPendingTransferProposal(for: account)
        XCTAssertNil(pending)
    }

    /// `isNoteSplitNeeded` plans fresh against the live balance. On this never-synced fixture the
    /// engine reports "nothing to migrate" (no spendable Orchard notes), which the FFI maps to a
    /// benign `false` — the same answer the platform's "does anything remain" sequential-runs check
    /// consumes. (The v1 crate threw `NotSynced` here; the final engine plans over whatever the
    /// wallet database knows.)
    func testFreshUnsyncedWalletIsNoteSplitNeededIsFalse() async throws {
        let needed = try await rustBackend.migrationIsNoteSplitNeeded(for: account)
        XCTAssertFalse(needed, "a fresh wallet with nothing to migrate needs no note split")
    }

    /// Same root behavior as `isNoteSplitNeeded` above: with nothing to migrate there is no note
    /// split and therefore no residual — `nil`, not a throw. (The v1 crate threw `NotSynced` on
    /// this fixture.)
    func testFreshUnsyncedWalletResidualAfterMigrationIsNil() async throws {
        let residual = try await rustBackend.migrationResidualAfterMigration(for: account)
        XCTAssertNil(residual, "a fresh wallet with nothing to migrate has no residual")
    }

    // MARK: - Residual locking

    /// On a fresh wallet with no spendable Orchard notes, locking the residual locks nothing:
    /// `Zatoshi(0)` is the legitimate "nothing was spendable" answer, not an error. (The
    /// account-creation fixture gives the wallet a chain tip via the checkpoint birthday, which
    /// the lock path's note selection targets — the same reason `isNoteSplitNeeded` plans
    /// benignly above.)
    func testFreshWalletLockResidualLocksNothing() async throws {
        let locked = try await rustBackend.lockMigrationResidual(accountUUID: account)
        XCTAssertEqual(locked, Zatoshi(0))
    }

    /// The release half on a fresh wallet: no locks exist, so the cleared-output count is `0`.
    func testFreshWalletUnlockResidualClearsNothing() async throws {
        let unlocked = try await rustBackend.unlockMigrationResidual(accountUUID: account)
        XCTAssertEqual(unlocked, 0)
    }

    /// Lock-then-unlock on the empty wallet is a stable round trip (both legs `0`), pinning that
    /// a no-op lock leaves no stray lock state behind for unlock to find.
    func testLockThenUnlockResidualOnFreshWalletIsAZeroRoundTrip() async throws {
        let locked = try await rustBackend.lockMigrationResidual(accountUUID: account)
        XCTAssertEqual(locked, Zatoshi(0))

        let unlocked = try await rustBackend.unlockMigrationResidual(accountUUID: account)
        XCTAssertEqual(unlocked, 0)
    }

    // MARK: - Run-count estimate

    /// On a fresh wallet with nothing to migrate, the run-count estimate is the ZERO-RUN
    /// estimate — `runCount` 0 and no residual — a legitimate answer decoded from a non-null
    /// FFI struct, not an error: the estimate analog of the empty propose schedule (and of
    /// `isNoteSplitNeeded`'s benign `false` above).
    func testFreshWalletEstimateMigrationRunsIsZeroRuns() async throws {
        let estimate = try await rustBackend.estimateMigrationRuns(accountUUID: account)

        XCTAssertEqual(estimate.runCount, 0)
        XCTAssertTrue(estimate.runs.isEmpty)
        XCTAssertEqual(estimate.finalResidual, .zero)
        XCTAssertEqual(estimate.totalSigningSessions(maxTransactionsPerSession: 1), 0)
    }

    // MARK: - Invalid-state transitions

    /// A commit without a matching previewed plan is the plan-stale contract: the engine signs
    /// exactly the plan the most recent propose call cached (ZIP 318 draws fresh schedule
    /// randomness on every proposal), so committing with nothing cached must surface
    /// `migrationPlanStale` — the actionable "propose again" signal — not a generic failure.
    func testSignAndStoreWithoutAPreviewedPlanThrowsPlanStale() async throws {
        let emptySchedule = MigrationSchedule(transfers: [], estimatedDurationHours: 0)
        do {
            try await rustBackend.migrationSignAndStoreSchedule(emptySchedule, usk: usk, for: account)
            XCTFail("Expected committing without a previewed plan to throw")
        } catch ZcashError.migrationPlanStale {
            // expected
        } catch {
            XCTFail("Expected migrationPlanStale but got \(error)")
        }
    }

    /// Ported from the prototype's `testRecordTransferResultWithNoActiveRunThrows`: recording a
    /// result against a transfer id with no active migration run throws
    /// `MigrationError::InvalidState(NoActiveRun)` -- a deterministic, sync-independent throw (this
    /// path never touches the wallet schema at all). Uses `.networkError` rather than `.success` to
    /// keep the test focused on the "no active run" contract, sidestepping the unrelated txid-hex
    /// validation `.success` carries (see `TxIdTests.testTxIdStringRoundTripsThroughRawBytesForAnAsymmetricFixture`
    /// / `testTxIdRawBytesRoundTripThroughDisplayHexStringForAnAsymmetricFixture` for the conversion
    /// helpers themselves, and
    /// `OrchardMigrationCompositionTests.testExecuteNextPendingTransferRecordsTheDocumentedByteOrderForAnAsymmetricTxId`
    /// for that validation exercised through this same welding record path).
    func testRecordTransferResultWithNoActiveRunThrows() async throws {
        do {
            try await rustBackend.migrationRecordTransferResult(
                transferId: "does-not-exist",
                result: MigrationTransferResult.networkError(retryable: true),
                for: account
            )
            XCTFail("Expected recording a result with no active migration run to throw")
        } catch ZcashError.rustMigrationRecordTransferResult {
            // expected
        } catch {
            XCTFail("Expected rustMigrationRecordTransferResult but got \(error)")
        }
    }

    /// Ported from the prototype's `testExtractBroadcastTxWithInvalidPcztThrows`: garbage PCZT bytes
    /// fail the crate's deserialization before any wallet-state check, so this is deterministic
    /// regardless of sync state.
    func testExtractBroadcastTxWithInvalidPcztThrows() async throws {
        do {
            _ = try await rustBackend.migrationExtractBroadcastTx(pczt: Data([0, 1, 2, 3]), for: account)
            XCTFail("Expected extracting a tx from invalid PCZT bytes to throw")
        } catch ZcashError.rustMigrationExtractBroadcastTx {
            // expected
        } catch {
            XCTFail("Expected rustMigrationExtractBroadcastTx but got \(error)")
        }
    }

    // MARK: - Immediate migration (send-max lane)

    /// MOB-1513: `migrationRecordImmediateRun` validates `txid.count == 32` in Swift before making
    /// any FFI call (the C side reads it as a fixed 32-byte buffer with no length parameter, so this
    /// guard is load-bearing, not defensive-only). A short txid must never reach the FFI.
    func testMigrationRecordImmediateRunRejectsNon32ByteTxid() async throws {
        do {
            try await rustBackend.migrationRecordImmediateRun(txid: Data([0x01, 0x02, 0x03]), for: account)
            XCTFail("Expected a non-32-byte txid to be rejected before any FFI call")
        } catch ZcashError.migrationRecordImmediateRunInvalidTxId(let length) {
            XCTAssertEqual(length, 3)
        } catch {
            XCTFail("Expected migrationRecordImmediateRunInvalidTxId but got \(error)")
        }
    }

    /// This fixture's `createAccount` call installs a checkpoint `treeState` (mirroring every other
    /// test in this file), which already gives `chain_height()` a height to report -- so unlike the
    /// balance-bearing paths, recording an immediate run does NOT require a real sync to succeed
    /// (the documented "no chain tip yet" failure mode applies before any account has been created
    /// at all, which this offline suite's setup always provides). This exercises the real FFI
    /// marshaling end-to-end (db/account bytes, the fixed 32-byte txid buffer, the boolean success
    /// mapping) and the `derive_state` fold reading it straight back: an unmined, unrecognized txid
    /// falls into the documented fallback-pending bucket (`recorded_at_height + 40`, not yet
    /// elapsed), so the state machine reports `InProgress(0 of 1)`, not a re-offer.
    func testMigrationRecordImmediateRunThenMigrationStateReportsInProgress() async throws {
        let txid = Data(repeating: 0xAB, count: 32)

        try await rustBackend.migrationRecordImmediateRun(txid: txid, for: account)

        let state = try await rustBackend.migrationState(for: account)
        guard case .inProgress(let progress) = state else {
            XCTFail("Expected .inProgress after recording an immediate run with an unmined txid, got \(state)")
            return
        }
        XCTAssertEqual(progress.completedTransfers, 0)
        XCTAssertEqual(progress.totalTransfers, 1)
    }

    // MARK: - Ironwood activation height

    /// Verified against the pinned rust source directly: zcash_protocol 0.10.0 @ e0e1277
    /// (components/zcash_protocol/src/consensus.rs), `impl Parameters for MainNetwork` ->
    /// `NetworkUpgrade::Nu6_3 => Some(BlockHeight(3_428_143))`. Also asserts the public
    /// `OrchardMigration.ironwoodActivationHeight(for:)` accessor delegates to the same value, so
    /// the public surface -- not just the internal backend -- is test-covered.
    func testIronwoodActivationHeightMainnet() throws {
        let height = try XCTUnwrap(ZcashRustBackend.ironwoodActivationHeight(networkType: .mainnet))
        XCTAssertEqual(height, 3_428_143)

        let publicHeight = try XCTUnwrap(OrchardMigration.ironwoodActivationHeight(for: .mainnet))
        XCTAssertEqual(publicHeight, height)

        // The public `ZcashNetwork.ironwoodActivationHeight` extension (the app-facing home that
        // replaces hosts' hardcoded NU heights) resolves to the same value.
        let networkHeight = try XCTUnwrap(ZcashNetworkBuilder.network(for: .mainnet).ironwoodActivationHeight)
        XCTAssertEqual(networkHeight, height)
    }

    /// Verified against the pinned rust source directly: zcash_protocol 0.10.0 @ e0e1277
    /// (components/zcash_protocol/src/consensus.rs), `impl Parameters for TestNetwork` ->
    /// `NetworkUpgrade::Nu6_3 => Some(BlockHeight(4_134_000))`. Matches the brief's expectation
    /// exactly; no discrepancy to flag.
    func testIronwoodActivationHeightTestnet() throws {
        let height = try XCTUnwrap(ZcashRustBackend.ironwoodActivationHeight(networkType: .testnet))
        XCTAssertEqual(height, 4_134_000)

        // The public `ZcashNetwork.ironwoodActivationHeight` extension resolves to the same value.
        let networkHeight = try XCTUnwrap(ZcashNetworkBuilder.network(for: .testnet).ironwoodActivationHeight)
        XCTAssertEqual(networkHeight, height)
    }

    /// The public `ZcashNetwork.ironwoodActivationHeight` extension on a custom (regtest-slot)
    /// network resolves through the same FFI path and reports `nil` -- the documented "no known
    /// Ironwood activation for that network" case: the regtest network id carries no fixed NU6.3
    /// height. Registers the same idempotent custom heights as
    /// `testOrchardMigrationRegistersCustomActivationHeightsOnInit` /
    /// `RegtestActivationHeightsTests.testRegtestConsensusBranchIdReflectsCustomActivationHeights`
    /// (`zcashlc_set_custom_network` is process-global and a conflicting re-registration asserts, so
    /// identical values keep every registrant idempotent regardless of run order).
    func testIronwoodActivationHeightForCustomNetworkIsNil() {
        let activationHeights = NetworkActivationHeights(
            overwinter: 1,
            sapling: 1,
            blossom: 1,
            heartwood: 1,
            canopy: 1,
            nu5: 100,
            nu6: 200
        )
        _ = ZcashRustBackend.setCustomNetwork(base: .regtest, activationHeights)
        let network = ZcashNetworkBuilder.custom(base: .mainnet, activationHeights: activationHeights)

        XCTAssertNil(network.ironwoodActivationHeight)
    }

    // MARK: - Marshaling determinism

    func testMigrationProgressNilIsStableAcrossRepeatedCalls() async throws {
        let first = try await rustBackend.migrationProgress(for: account)
        let second = try await rustBackend.migrationProgress(for: account)
        XCTAssertNil(first)
        XCTAssertEqual(first, second)
    }

    func testMigrationNextDueTransferNilIsStableAcrossRepeatedCalls() async throws {
        let first = try await rustBackend.migrationNextDueTransfer(for: account)
        let second = try await rustBackend.migrationNextDueTransfer(for: account)
        XCTAssertNil(first)
        XCTAssertEqual(first, second)
    }

    func testMigrationPendingTransferProposalNilIsStableAcrossRepeatedCalls() async throws {
        let first = try await rustBackend.migrationPendingTransferProposal(for: account)
        let second = try await rustBackend.migrationPendingTransferProposal(for: account)
        XCTAssertNil(first)
        XCTAssertEqual(first, second)
    }

    func testMigrationResidualAfterMigrationNilIsStableAcrossRepeatedCalls() async throws {
        let first = try await rustBackend.migrationResidualAfterMigration(for: account)
        let second = try await rustBackend.migrationResidualAfterMigration(for: account)
        XCTAssertNil(first)
        XCTAssertEqual(first, second)
    }

    /// The final engine does not support rebuild-on-expiry (an explicit upstream later-slice), so
    /// `refreshStaleTransfers` deterministically throws its member case, sync-independent.
    func testRefreshStaleTransfersAlwaysThrowsUnsupported() async throws {
        do {
            _ = try await rustBackend.migrationRefreshStaleTransfers(usk: usk, includeResidual: false, for: account)
            XCTFail("Expected migrationRefreshStaleTransfers to throw (unsupported by the final engine)")
        } catch ZcashError.rustMigrationRefreshStaleTransfers {
            // expected
        } catch {
            XCTFail("Expected rustMigrationRefreshStaleTransfers but got \(error)")
        }
    }

    /// Guards against last-error-channel pollution across calls: a throwing call
    /// (`refreshStaleTransfers`, which deterministically errors — see above) must not corrupt the
    /// next legitimate `false` answer from an ambiguous-bool-sentinel call (`hasOverdueTransfers`,
    /// which reads only the empty migration store on a fresh db) sandwiched around it.
    func testHasOverdueTransfersIsUnaffectedByAPrecedingThrowFromRefreshStaleTransfers() async throws {
        let before = try await rustBackend.migrationHasOverdueTransfers(for: account)
        XCTAssertFalse(before)

        do {
            _ = try await rustBackend.migrationRefreshStaleTransfers(usk: usk, includeResidual: false, for: account)
            XCTFail("Expected migrationRefreshStaleTransfers to throw")
        } catch {
            // Expected; the specific case is asserted by
            // testRefreshStaleTransfersAlwaysThrowsUnsupported above.
        }

        let after = try await rustBackend.migrationHasOverdueTransfers(for: account)
        XCTAssertFalse(after)
        XCTAssertEqual(before, after)
    }

    /// Complements the hygiene test above: that one covers a predecessor that itself throws (and so
    /// consumes/clears the FFI's last-error via `lastErrorMessage` on its own throw path). This one
    /// covers a predecessor that sets a last-error and returns *without ever throwing* --
    /// `ironwoodActivationHeight` mapping the FFI's `-1` sentinel to `nil` for a network id outside
    /// `{testnet, mainnet}` (`.regtest`) leaves that error unconsumed in the (thread-local) FFI error
    /// channel, pre-fix. A bool-sentinel migration call on a healthy, freshly initialized db must not
    /// misfire on it merely because it happens to run on the same thread afterward.
    func testABoolSentinelMigrationCallIsUnaffectedByAPrecedingUnconsumedIronwoodActivationHeightError() async throws {
        let staleProducerResult = ZcashRustBackend.ironwoodActivationHeight(networkType: .regtest)
        XCTAssertNil(staleProducerResult, "regtest has no fixed NU6.3 height; `-1` must still map to nil")

        let hasOverdue = try await rustBackend.migrationHasOverdueTransfers(for: account)
        XCTAssertFalse(hasOverdue)
    }

    // MARK: - Actor integration over real FFI (nil paths)

    /// Constructs a real `OrchardMigration` via the injecting initializer, wired to the SAME
    /// real-FFI-backed welding as the rest of this file (not a mock) plus a real, temp-file-backed
    /// `MigrationSyncGate`. On this fresh wallet `migrationNextDueTransfer` legitimately returns
    /// `nil`, so `executeNextPendingTransfer` must short-circuit before ever reaching the broadcaster
    /// -- proven here with a fake that fails the assertion (via a non-zero call count) rather than
    /// the test itself if that contract regresses. `rescheduleOverdueTransfer` likewise resolves
    /// `nil` (no active run), exercising the engine-backed pending-proposal accessor over real FFI.
    func testFreshWalletActorNextPendingTransferAndRescheduleAreNilOverRealFFI() async throws {
        let storageDirectory = try makeUniqueStorageDirectory()
        defer { try? FileManager.default.removeItem(at: storageDirectory) }

        let broadcaster = ScriptedBroadcaster(script: .throwing(ZcashError.migrationTorUnavailable))
        let migration = OrchardMigration(
            welding: rustBackend,
            accountUUID: account,
            broadcaster: broadcaster,
            syncGate: MigrationSyncGate(
                directory: storageDirectory,
                accountUUID: account,
                bufferDuration: 600,
                tickInterval: 3600,
                overdueProvider: { false },
                logger: logger
            ),
            logger: logger
        )

        let result = try await migration.executeNextPendingTransfer(
            options: MigrationNetworkPrivacyOptions(
                useTor: false,
                submissionEndpoint: LightWalletEndpoint(address: "default.example", port: 9067)
            )
        )
        XCTAssertNil(result)
        XCTAssertEqual(broadcaster.receivedCalls.count, 0)

        let rescheduled = try await migration.rescheduleOverdueTransfer()
        XCTAssertNil(rescheduled)
    }

    // MARK: - Custom network registration

    /// `OrchardMigration.init(config:)` builds its own `ZcashRustBackend` rather than sharing the
    /// synchronizer's, so it -- like `Initializer.setup` -- must register a custom network's
    /// activation heights with the Rust core itself; nothing else does it on this path. Pre-fix,
    /// every migration FFI call on a `.regtest`/custom network id (2) throws "custom network (id 2)
    /// used before it was configured" (see `rust/src/lib.rs`'s `parse_network`), which
    /// `migrationState()` surfaces as `rustMigrationState`, and which `isSyncBlocked()`/the gate's
    /// `overdueProvider` silently swallow via `try?` instead (finding 5's "migration dead on
    /// .custom/.regtest").
    ///
    /// `NetworkActivationHeights` here intentionally matches
    /// `RegtestActivationHeightsTests.testRegtestConsensusBranchIdReflectsCustomActivationHeights`'s
    /// values exactly: `zcashlc_set_custom_network` is process-global, `swift test` runs the whole
    /// `OfflineTests` bundle in one process, and a conflicting re-registration is a host
    /// configuration bug this code path asserts on (`assertionFailure`, live in a debug/test build).
    /// Identical values make both tests' registrations idempotent regardless of run order.
    ///
    /// The engine's store tables ride the wallet schema migrations (the FFI no longer creates
    /// them on first touch), so the fixture initializes the wallet database first — exactly like
    /// a real caller, whose `Initializer`/`prepare` runs `initDataDb` before any migration read —
    /// and then verifies `migrationState()` reads `NotStarted` over the custom network the
    /// `OrchardMigration` initializer registered.
    func testOrchardMigrationRegistersCustomActivationHeightsOnInit() async throws {
        let activationHeights = NetworkActivationHeights(
            overwinter: 1,
            sapling: 1,
            blossom: 1,
            heartwood: 1,
            canopy: 1,
            nu5: 100,
            nu6: 200
        )
        let network = ZcashNetworkBuilder.regtest(activationHeights: activationHeights)

        let storageDirectory = try makeUniqueStorageDirectory()
        defer { try? FileManager.default.removeItem(at: storageDirectory) }

        let migration = OrchardMigration(
            config: OrchardMigration.Config(
                dataDbURL: storageDirectory.appendingPathComponent("data.db"),
                fsBlockDbRoot: storageDirectory.appendingPathComponent("fs_cache", isDirectory: true),
                spendParamsURL: storageDirectory.appendingPathComponent("sapling-spend.params"),
                outputParamsURL: storageDirectory.appendingPathComponent("sapling-output.params"),
                network: network,
                accountUUID: AccountUUID(id: [UInt8](repeating: 9, count: 16)),
                torDirURL: storageDirectory.appendingPathComponent("tor", isDirectory: true),
                generalStorageURL: storageDirectory,
                loggingPolicy: .noLogging
            )
        )

        let initBackend = ZcashRustBackend.makeForTests(
            dbData: storageDirectory.appendingPathComponent("data.db"),
            fsBlockDbRoot: storageDirectory.appendingPathComponent("fs_cache", isDirectory: true),
            networkType: network.networkType
        )
        let dbInit = try await initBackend.initDataDb(seed: nil)
        guard case .success = dbInit else {
            XCTFail("Failed to initDataDb. Expected `.success`, got \(String(describing: dbInit))")
            return
        }

        do {
            let state = try await migration.migrationState()
            XCTAssertEqual(state, MigrationState.notStarted)
        } catch {
            XCTFail("Expected migrationState() to succeed once the custom network is registered by init(config:); got \(error)")
        }
    }

    // MARK: - Helpers

    private func makeUniqueStorageDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(
            "MigrationFFITests-\(UUID().uuidString)",
            isDirectory: true
        )
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
}
