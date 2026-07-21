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
}
