//
//  SlipstreamSynchronizerMigrationTests.swift
//  OfflineTests
//
//  Tests `SlipstreamSynchronizer`'s migration group (R4-C): the same 26 `Synchronizer` protocol
//  requirements `SDKSynchronizer` implements (see `SDKSynchronizerMigrationTests`), as thin forwards
//  to a seamed `OrchardMigrationHost`, plus the two SDK-enforced session-separation behaviors -- the
//  `start()` privacy gate and the `submitNoteSplit`/`executeNextPendingMigrationTransfer` broadcast
//  guard -- mirrored onto the actor.
//
//  Driven through the host's injecting initializer + a scripted actor factory, exactly like
//  `SDKSynchronizerMigrationTests`, with the host substituted into a real `SlipstreamSynchronizer` via
//  the same container-mock seam (`container.mock(type: OrchardMigrationHost.self, ...)`) that
//  `SlipstreamSynchronizer.init` resolves against.
//
//  The two enforcement suites need `latestState.internalSyncStatus` in a specific case (`.disconnected`
//  to satisfy `start(retry:)`'s `isPrepared` guard; `.syncing` to exercise the broadcast guard) without
//  going through `prepare()`/`start()` for real: unlike `SDKSynchronizer` (whose package-visible
//  `updateStatus(_:)` its own tests reuse directly), `SlipstreamSynchronizer`'s only OTHER way to reach
//  a non-`.unprepared` status is the real engine -- and driving `.syncing` through a genuine `start()`
//  spawns the real background poll loop, whose `tickPoll()` calls `engine.walletSummary()` (documented
//  as unsafe to call "mid-scan" -- it can run long against a wallet that is actively, unsuccessfully,
//  trying to reach a server) on the SAME actor `engine.stop()` needs, so a leaked in-flight summary
//  walk can block teardown well past any reasonable test deadline and bleed into whatever test the
//  process runs next (this was caught empirically: an earlier version of this suite that drove state
//  through real `prepare()`/`start()` calls intermittently starved
//  `WalletTests.testWalletInitialization`, elsewhere in this same `OfflineTests` target, of its mocked
//  service interaction). `SlipstreamSynchronizer.setInternalSyncStatusForTesting(_:)` -- a small
//  `internal` seam added alongside this suite for exactly this purpose -- sidesteps all of that: it
//  writes `stateSubject` directly, the same way `stopImpl()`/`tickPoll()` do internally, with no engine
//  or poll-loop involvement at all.
//
//  No network, no real FFI beyond local SQLite/key-derivation calls that `Initializer`/`TestsData`
//  already make offline elsewhere in this suite (see `WalletTests.testWalletInitialization` and
//  `SlipstreamOfflineTests` for precedent).
//

import Combine
import Foundation
@testable import TestUtils
import XCTest
@testable import ZcashLightClientKit

final class SlipstreamSynchronizerMigrationTests: ZcashTestCase {
    private let accountUUID = AccountUUID(id: [UInt8](repeating: 0x0A, count: 16))
    private let submissionEndpoint = LightWalletEndpoint(address: "submit.example", port: 9067)
    private var cancellables: [AnyCancellable] = []
    private static let uaString = """
    u1l9f0l4348negsncgr9pxd9d3qaxagmqv3lnexcplmufpq7muffvfaue6ksevfvd7wrz7xrvn95rc5zjtn7ugkmgh5rnxswmcj30y0pw52pn0zjvy38rn2esfgve64rj5pcmazxgpyuj
    """

    override func setUp() {
        super.setUp()
        cancellables = []
    }

    override func tearDown() {
        cancellables = []
        super.tearDown()
    }

    // MARK: - Forwarding (representatives: state, split, schedule, delivery, recovery, PCZT)

    func testMigrationStateForwardsToTheAccountsActor() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.migrationStateForReturnValue = .notStarted
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))

        let state = try await synchronizer.migrationState(accountUUID: accountUUID)

        XCTAssertEqual(state, .notStarted)
        XCTAssertEqual(welding.migrationStateForReceivedAccount, accountUUID)
    }

    func testPrepareNoteSplitForwardsToTheAccountsActor() async throws {
        let welding = ZcashRustBackendWeldingMock()
        let expected = NoteSplitProposal(outputNotes: [Zatoshi(500), Zatoshi(500)], fee: Zatoshi(100))
        welding.migrationPrepareNoteSplitForReturnValue = expected
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))

        let proposal = try await synchronizer.prepareNoteSplit(accountUUID: accountUUID)

        XCTAssertEqual(proposal, expected)
        XCTAssertEqual(welding.migrationPrepareNoteSplitForReceivedAccount, accountUUID)
    }

    func testProposeMigrationTransfersForwardsToTheAccountsActor() async throws {
        let welding = ZcashRustBackendWeldingMock()
        let expected = MigrationSchedule(transfers: [], estimatedDurationHours: 3)
        welding.migrationProposeTransfersForReturnValue = expected
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))

        let schedule = try await synchronizer.proposeMigrationTransfers(accountUUID: accountUUID)

        XCTAssertEqual(schedule, expected)
        XCTAssertEqual(welding.migrationProposeTransfersForReceivedAccount, accountUUID)
    }

    func testHasOverdueMigrationTransfersForwards() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.migrationHasOverdueTransfersForReturnValue = true
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))

        let overdue = try await synchronizer.hasOverdueMigrationTransfers(accountUUID: accountUUID)

        XCTAssertTrue(overdue)
        XCTAssertEqual(welding.migrationHasOverdueTransfersForReceivedAccount, accountUUID)
    }

    /// `refreshStaleMigrationTransfers`'s external-signer (Keystone) lane: a `nil` usk must reach
    /// the welding call as `nil`, not be coerced into some non-optional stand-in -- the engine
    /// itself branches on nilness to select the unsigned-rebuild path (see
    /// `OrchardMigration.refreshStaleTransfers(usk:)`) -- and the welding's post-refresh stored
    /// schedule must flow back to the caller unmodified (it is the truth the host re-displays and
    /// echoes on the consent-verified calls).
    func testRefreshStaleMigrationTransfersForwardsNilUskForTheExternalSignerLane() async throws {
        let welding = ZcashRustBackendWeldingMock()
        let expected = MigrationSchedule(
            transfers: [
                MigrationTransferProposal(
                    id: "3",
                    amount: Zatoshi(100_000_000),
                    anchorHeight: 3_600_000,
                    nextExecutableAfterHeight: 3_600_100,
                    expiryHeight: 3_640_000
                )
            ],
            estimatedDurationHours: 2
        )
        welding.migrationRefreshStaleTransfersUskForReturnValue = expected
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))

        let refreshed = try await synchronizer.refreshStaleMigrationTransfers(accountUUID: accountUUID, usk: nil)

        XCTAssertEqual(refreshed, expected)
        let received = welding.migrationRefreshStaleTransfersUskForReceivedArguments
        XCTAssertEqual(received?.account, accountUUID)
        XCTAssertNil(received?.usk, "a nil usk must forward as nil, selecting the external-signer lane")
    }

    /// The sibling of the nil-usk test above: a real spending key must forward untouched, selecting
    /// the in-process sign-anew lane, with the returned schedule again round-tripping unmodified.
    func testRefreshStaleMigrationTransfersForwardsARealUskForTheInProcessLane() async throws {
        let welding = ZcashRustBackendWeldingMock()
        let expected = MigrationSchedule(transfers: [], estimatedDurationHours: 0)
        welding.migrationRefreshStaleTransfersUskForReturnValue = expected
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))
        let usk = TestsData(networkType: .testnet).spendingKey

        let refreshed = try await synchronizer.refreshStaleMigrationTransfers(accountUUID: accountUUID, usk: usk)

        XCTAssertEqual(refreshed, expected)
        let received = welding.migrationRefreshStaleTransfersUskForReceivedArguments
        XCTAssertEqual(received?.account, accountUUID)
        XCTAssertEqual(received?.usk, usk)
    }

    func testCreateUnsignedNoteSplitPCZTsForwards() async throws {
        let welding = ZcashRustBackendWeldingMock()
        let expected = [MigrationUnsignedTransferPczt(id: "0", pczt: Data([0xAA, 0xBB]))]
        welding.migrationCreateUnsignedNoteSplitPcztsForReturnValue = expected
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))

        let pczts = try await synchronizer.createUnsignedNoteSplitPCZTs(accountUUID: accountUUID)

        XCTAssertEqual(pczts, expected)
        XCTAssertEqual(welding.migrationCreateUnsignedNoteSplitPcztsForReceivedAccount, accountUUID)
    }

    /// MOB-1513: the immediate lane's `proposeImmediateMigration` forwards to the per-account actor
    /// and returns its `ImmediateMigrationProposal` untouched -- unlike `proposeMigrationTransfers`,
    /// there is no engine schedule involved, so this is a plain one-hop forward like every other
    /// member in this group.
    func testProposeImmediateMigrationForwardsToTheAccountsActor() async throws {
        let welding = ZcashRustBackendWeldingMock()
        let ownAddress = UnifiedAddress(validatedEncoding: Self.uaString, networkType: .testnet)
        welding.getCurrentAddressAccountUUIDReturnValue = ownAddress
        var proposal = FfiProposal()
        var step = FfiProposalStep()
        var input = FfiProposedInput()
        var receivedOutput = FfiReceivedOutput()
        receivedOutput.value = 500_000
        input.receivedOutput = receivedOutput
        step.inputs = [input]
        var balance = FfiTransactionBalance()
        balance.feeRequired = 10_000
        step.balance = balance
        proposal.steps = [step]
        welding.proposeSendMaxTransferAccountUUIDRecipientMemoOrchardOnlyReturnValue = proposal
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))

        let immediateProposal = try await synchronizer.proposeImmediateMigration(accountUUID: accountUUID)

        XCTAssertEqual(immediateProposal.fee, Zatoshi(10_000))
        XCTAssertEqual(immediateProposal.amount, Zatoshi(500_000 - 10_000))
        XCTAssertEqual(welding.getCurrentAddressAccountUUIDReceivedAccountUUID, accountUUID)
        XCTAssertEqual(welding.proposeSendMaxTransferAccountUUIDRecipientMemoOrchardOnlyReceivedArguments?.recipient, ownAddress.stringEncoded)
    }

    /// `recordImmediateMigration` forwards the account and txid to the per-account actor, which in
    /// turn forwards to the welding record call -- this is NOT broadcast-sensitive (no
    /// `throwIfSyncingForMigrationBroadcast()` guard), matching the contract that only the two
    /// actual broadcasting members are guarded.
    func testRecordImmediateMigrationForwardsToTheAccountsActor() async throws {
        let welding = ZcashRustBackendWeldingMock()
        var receivedTxid: Data?
        var receivedAccount: AccountUUID?
        welding.migrationRecordImmediateRunTxidForClosure = { txid, account in
            receivedTxid = txid
            receivedAccount = account
        }
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))
        let txid = Data(repeating: 0xEF, count: 32)

        try await synchronizer.recordImmediateMigration(accountUUID: accountUUID, txid: txid)

        XCTAssertEqual(receivedTxid, txid)
        XCTAssertEqual(receivedAccount, accountUUID)
    }

    /// `lockMigrationResidual` — the "Lock balance" choice at migration `Complete` — forwards to
    /// the per-account actor and returns the welding's locked total untouched. Like the rest of the
    /// group it needs no `prepare()` and carries no broadcast guard (locking is a data-db write,
    /// nothing is broadcast).
    func testLockMigrationResidualForwardsToTheAccountsActor() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.lockMigrationResidualAccountUUIDReturnValue = Zatoshi(21_500)
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))

        let locked = try await synchronizer.lockMigrationResidual(accountUUID: accountUUID)

        XCTAssertEqual(locked, Zatoshi(21_500))
        XCTAssertEqual(welding.lockMigrationResidualAccountUUIDReceivedAccountUUID, accountUUID)
    }

    /// A lock failure (in particular the concurrent-lock race, which the caller may retry)
    /// propagates through the `Synchronizer` surface untouched.
    func testLockMigrationResidualPropagatesTheWeldingError() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.lockMigrationResidualAccountUUIDThrowableError = ZcashError.rustMigrationLockResidual("concurrent lock race")
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))

        do {
            _ = try await synchronizer.lockMigrationResidual(accountUUID: accountUUID)
            XCTFail("expected rustMigrationLockResidual to propagate")
        } catch ZcashError.rustMigrationLockResidual {
            // expected
        } catch {
            XCTFail("expected rustMigrationLockResidual, got \(error)")
        }
    }

    /// `unlockMigrationResidual` — the release half; "Migrate anyway" composes as this call
    /// followed by `proposeImmediateMigration` — forwards to the per-account actor and returns the
    /// cleared-lock count untouched.
    func testUnlockMigrationResidualForwardsToTheAccountsActor() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.unlockMigrationResidualAccountUUIDReturnValue = 7
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))

        let cleared = try await synchronizer.unlockMigrationResidual(accountUUID: accountUUID)

        XCTAssertEqual(cleared, 7)
        XCTAssertEqual(welding.unlockMigrationResidualAccountUUIDReceivedAccountUUID, accountUUID)
    }

    /// `estimateMigrationRuns` forwards to the per-account actor and hands the engine's
    /// `MigrationRunEstimate` through unchanged — pinned with a non-trivial two-run fixture so any
    /// field cross-wiring in the pass-through would break equality, and the derived signing-session
    /// math answers over exactly what the engine reported.
    func testEstimateMigrationRunsForwardsToTheAccountsActor() async throws {
        let welding = ZcashRustBackendWeldingMock()
        let estimate = MigrationRunEstimate(
            runs: [
                MigrationRunEstimate.Run(
                    migratable: Zatoshi(75_000_000),
                    crossings: 15,
                    preparationLayers: 2,
                    preparationTransactions: 5
                ),
                MigrationRunEstimate.Run(
                    migratable: Zatoshi(1_200_000),
                    crossings: 3,
                    preparationLayers: 1,
                    preparationTransactions: 1
                )
            ],
            finalResidual: Zatoshi(42_000)
        )
        welding.estimateMigrationRunsAccountUUIDReturnValue = estimate
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))

        let returned = try await synchronizer.estimateMigrationRuns(accountUUID: accountUUID)

        XCTAssertEqual(returned, estimate)
        XCTAssertEqual(welding.estimateMigrationRunsAccountUUIDReceivedAccountUUID, accountUUID)
        XCTAssertEqual(
            returned.totalSigningSessions(maxTransactionsPerSession: 8),
            estimate.totalSigningSessions(maxTransactionsPerSession: 8),
            "the derived signing-session math must answer over the forwarded runs"
        )
    }

    // MARK: - Forwarding: wallet-scope gate members

    func testIsMigrationSyncBlockedForwardsToHostPredicate() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.listAccountsReturnValue = [makeAccount(accountUUID)]
        welding.migrationHasOverdueTransfersForReturnValue = true
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))

        let blocked = await synchronizer.isMigrationSyncBlocked()

        // The inert protocol default always returns false; true here proves this is genuinely
        // wired to the host's own (engineered-non-default) predicate result.
        XCTAssertTrue(blocked)
    }

    func testMigrationSyncBlockedStreamForwardsToHostStream() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.listAccountsReturnValue = [makeAccount(accountUUID)]
        welding.migrationHasOverdueTransfersForReturnValue = true
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding, tickInterval: 0.02))

        var received: [Bool] = []
        let sawBlocked = expectation(description: "the forwarded stream observed the host's live blocked state")
        let cancellable = synchronizer.migrationSyncBlockedStream.sink { value in
            received.append(value)
            if value {
                sawBlocked.fulfill()
            }
        }
        cancellables.append(cancellable)

        await fulfillment(of: [sawBlocked], timeout: 5)
        // The inert protocol default only ever emits false; observing true here proves this is
        // genuinely wired to the host's own reactive stream, not the static default.
        XCTAssertEqual(received.first, false, "precondition: a fresh host seeds false")
        XCTAssertEqual(received.last, true)
    }

    func testMigrationPrivacySyncBufferDurationForwardsHostConstant() throws {
        let welding = ZcashRustBackendWeldingMock()
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))

        XCTAssertEqual(synchronizer.migrationPrivacySyncBufferDuration, OrchardMigration.privacySyncBufferDuration)
    }

    // MARK: - Defaults-override completeness

    /// One representative throwing member, scripted to SUCCEED via the host: the protocol-extension
    /// default (`public extension Synchronizer`) throws `MigrationUnimplemented` unconditionally for
    /// every throwing member in the group, so succeeding at all here already proves this is
    /// `SlipstreamSynchronizer`'s own witness, not the inert default falling through -- the whole
    /// point of R4-C. The gate members' override-vs-default distinction is already pinned above
    /// (`testIsMigrationSyncBlockedForwardsToHostPredicate` /
    /// `testMigrationSyncBlockedStreamForwardsToHostStream`).
    func testThrowingMigrationMemberIsSlipstreamSynchronizersOwnWitnessNotTheProtocolDefault() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.migrationStateForReturnValue = .notStarted
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))

        // If SlipstreamSynchronizer still fell through to the protocol default, this would throw
        // `MigrationUnimplemented` instead of returning the host-scripted value.
        let state = try await synchronizer.migrationState(accountUUID: accountUUID)
        XCTAssertEqual(state, .notStarted)
    }

    // MARK: - Enforcement: start() privacy gate

    func testStartThrowsMigrationSyncBlockedWhenHostReportsBlocked() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.listAccountsReturnValue = [makeAccount(accountUUID)]
        welding.migrationHasOverdueTransfersForReturnValue = true
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))
        await synchronizer.setInternalSyncStatusForTesting(.disconnected)

        do {
            try await synchronizer.start(retry: false)
            XCTFail("expected start() to throw migrationSyncBlocked")
        } catch let error as ZcashError {
            guard case .migrationSyncBlocked = error else {
                XCTFail("expected migrationSyncBlocked, got \(error)")
                return
            }
            XCTAssertEqual(error.code.rawValue, "ZRUST0125")
        } catch {
            XCTFail("expected a ZcashError, got \(error)")
        }
    }

    /// The gate passing is proven by NOT seeing `migrationSyncBlocked`: since this synchronizer's
    /// engine handle was never `open()`ed (no real `prepare()` call -- see the file header for why),
    /// `start()` proceeds past the gate straight into `engine.start(...)`, which throws the unrelated,
    /// purely-local `rustSlipstreamNotOpen` -- exactly the kind of "unrelated offline failure" this
    /// test already tolerates, and it never spawns the poll loop (the throw happens before
    /// `startPolling()`), so there is nothing to clean up afterward.
    func testStartProceedsPastTheGateWhenHostReportsUnblocked() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.listAccountsReturnValue = []
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))
        await synchronizer.setInternalSyncStatusForTesting(.disconnected)

        do {
            try await synchronizer.start(retry: false)
            // Also an acceptable outcome, should the engine tolerate starting unopened.
        } catch let error as ZcashError {
            if case .migrationSyncBlocked = error {
                XCTFail("start() must not report migrationSyncBlocked when the host reports unblocked")
            }
            // Any other ZcashError is an unrelated offline failure (expected: rustSlipstreamNotOpen,
            // since this synchronizer's engine was never opened) and is acceptable here -- only the
            // gate's behavior is under test.
        } catch {
            // Likewise tolerated as an unrelated offline failure.
        }
    }

    // MARK: - Enforcement: broadcast guard

    func testSubmitNoteSplitThrowsDuringSyncWithoutTouchingTheHost() async throws {
        let welding = ZcashRustBackendWeldingMock()
        let recorder = FactoryInvocationRecorder()
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding, factoryRecorder: recorder))
        await synchronizer.setInternalSyncStatusForTesting(.syncing(0.5, false))

        let proposal = NoteSplitProposal(outputNotes: [Zatoshi(1_000)], fee: Zatoshi(100))
        let usk = TestsData(networkType: .testnet).spendingKey
        let options = MigrationNetworkPrivacyOptions(useTor: false, submissionEndpoint: submissionEndpoint)

        do {
            _ = try await synchronizer.submitNoteSplit(accountUUID: accountUUID, proposal: proposal, usk: usk, options: options)
            XCTFail("expected migrationBroadcastDuringSync")
        } catch let error as ZcashError {
            guard case .migrationBroadcastDuringSync = error else {
                XCTFail("expected migrationBroadcastDuringSync, got \(error)")
                return
            }
            XCTAssertEqual(error.code.rawValue, "ZRUST0126")
        } catch {
            XCTFail("expected a ZcashError, got \(error)")
        }

        XCTAssertEqual(recorder.callCount, 0, "the guard must throw before the host is ever consulted")
        XCTAssertFalse(welding.migrationSignNoteSplitProposalUskForCalled, "the engine must never see a during-sync submission")
    }

    func testExecuteNextPendingMigrationTransferThrowsDuringSyncWithoutTouchingTheHost() async throws {
        let welding = ZcashRustBackendWeldingMock()
        let recorder = FactoryInvocationRecorder()
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding, factoryRecorder: recorder))
        await synchronizer.setInternalSyncStatusForTesting(.syncing(0.5, false))

        let options = MigrationNetworkPrivacyOptions(useTor: false, submissionEndpoint: submissionEndpoint)

        do {
            _ = try await synchronizer.executeNextPendingMigrationTransfer(accountUUID: accountUUID, options: options)
            XCTFail("expected migrationBroadcastDuringSync")
        } catch let error as ZcashError {
            guard case .migrationBroadcastDuringSync = error else {
                XCTFail("expected migrationBroadcastDuringSync, got \(error)")
                return
            }
            XCTAssertEqual(error.code.rawValue, "ZRUST0126")
        } catch {
            XCTFail("expected a ZcashError, got \(error)")
        }

        XCTAssertEqual(recorder.callCount, 0, "the guard must throw before the host is ever consulted")
        XCTAssertFalse(welding.migrationNextDueTransferForCalled, "the engine must never see a during-sync execution attempt")
    }

    /// Not-syncing companion: proves the guard does NOT trip outside the syncing case, and the call
    /// really does reach the per-account actor's engine call -- by stubbing the engine's first
    /// broadcast-flow step to throw a distinctive, non-`ZcashError` failure and observing it
    /// propagate untouched (rather than seeing `migrationBroadcastDuringSync`, or a crash from an
    /// unconfigured mock return value). Deliberately does NOT call `setInternalSyncStatusForTesting`:
    /// migration members work without `prepare()` (protocol doc, `Synchronizer.swift`), so the
    /// synchronizer's default freshly-constructed `.unprepared` state already satisfies "not syncing"
    /// for this guard.
    func testSubmitNoteSplitForwardsWhenNotSyncing() async throws {
        struct StubSigningFailure: Error, Equatable {}
        let welding = ZcashRustBackendWeldingMock()
        welding.migrationSignNoteSplitProposalUskForThrowableError = StubSigningFailure()
        let recorder = FactoryInvocationRecorder()
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding, factoryRecorder: recorder))

        let proposal = NoteSplitProposal(outputNotes: [Zatoshi(1_000)], fee: Zatoshi(100))
        let usk = TestsData(networkType: .testnet).spendingKey
        let options = MigrationNetworkPrivacyOptions(useTor: false, submissionEndpoint: submissionEndpoint)

        do {
            _ = try await synchronizer.submitNoteSplit(accountUUID: accountUUID, proposal: proposal, usk: usk, options: options)
            XCTFail("expected the stubbed signing failure to propagate")
        } catch let error as StubSigningFailure {
            XCTAssertEqual(error, StubSigningFailure())
        } catch {
            XCTFail("expected StubSigningFailure, got \(error)")
        }

        // Note: the mock's generated body checks `...ThrowableError` before bumping `...CallsCount`,
        // so `migrationSignNoteSplitProposalUskForCalled` stays false on this path -- catching the
        // exact stub type above (which can only originate from that one call site) plus the
        // recorder count already prove the call reached the engine.
        XCTAssertEqual(recorder.callCount, 1, "the host must be consulted when the synchronizer is not syncing")
    }

    /// Not-syncing companion for `executeNextPendingMigrationTransfer`, mirroring
    /// `testSubmitNoteSplitForwardsWhenNotSyncing()`.
    func testExecuteNextPendingMigrationTransferForwardsWhenNotSyncing() async throws {
        struct StubNextDueTransferFailure: Error, Equatable {}
        let welding = ZcashRustBackendWeldingMock()
        welding.migrationNextDueTransferForThrowableError = StubNextDueTransferFailure()
        let recorder = FactoryInvocationRecorder()
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding, factoryRecorder: recorder))

        let options = MigrationNetworkPrivacyOptions(useTor: false, submissionEndpoint: submissionEndpoint)

        do {
            _ = try await synchronizer.executeNextPendingMigrationTransfer(accountUUID: accountUUID, options: options)
            XCTFail("expected the stubbed next-due-transfer failure to propagate")
        } catch let error as StubNextDueTransferFailure {
            XCTAssertEqual(error, StubNextDueTransferFailure())
        } catch {
            XCTFail("expected StubNextDueTransferFailure, got \(error)")
        }

        // See the note in `testSubmitNoteSplitForwardsWhenNotSyncing()`: `...ThrowableError` bypasses
        // the mock's `...CallsCount` bump, so the recorder + exact stub type are the proof here.
        XCTAssertEqual(recorder.callCount, 1, "the host must be consulted when the synchronizer is not syncing")
    }

    // MARK: - Helpers

    /// Builds a `SlipstreamSynchronizer` whose one `OrchardMigrationHost` is `migrationHost`,
    /// substituted via the same container-mock seam `SlipstreamSynchronizer.init` resolves the
    /// production host through -- mirrors `SDKSynchronizerMigrationTests.makeSynchronizer(migrationHost:)`.
    private func makeSynchronizer(migrationHost: OrchardMigrationHost) throws -> SlipstreamSynchronizer {
        mockContainer.mock(type: OrchardMigrationHost.self, isSingleton: true) { _ in migrationHost }

        let initializer = Initializer(
            container: mockContainer,
            cacheDbURL: nil,
            fsBlockDbRoot: testTempDirectory,
            generalStorageURL: testGeneralStorageDirectory,
            dataDbURL: try __dataDbURL(),
            torDirURL: try __torDirURL(),
            endpoint: LightWalletEndpointBuilder.default,
            network: ZcashNetworkBuilder.network(for: .testnet),
            spendParamsURL: try __spendParamsURL(),
            outputParamsURL: try __outputParamsURL(),
            saplingParamsSourceURL: SaplingParamsSourceURL.tests,
            isTorEnabled: false,
            isExchangeRateEnabled: false
        )

        return SlipstreamSynchronizer(initializer: initializer)
    }

    /// Builds an `OrchardMigrationHost` via its injecting initializer, following R4-A/R4-B's seam
    /// (`OrchardMigrationHostTests` / `SDKSynchronizerMigrationTests`): `welding` backs both the
    /// wallet-scope predicate and every per-account actor the (scripted) `actorFactory` produces.
    /// `factoryRecorder`, when supplied, counts every `actorFactory` invocation -- i.e. every time
    /// `migrationHost.migration(for:)` actually built a per-account actor, which is what the
    /// broadcast guard's "never touched the host" assertions pin.
    private func makeHost(
        welding: ZcashRustBackendWeldingMock,
        broadcaster: any MigrationBroadcasting = ScriptedBroadcaster(script: .throwing(ZcashError.migrationTorUnavailable)),
        tickInterval: TimeInterval = 3600,
        factoryRecorder: FactoryInvocationRecorder? = nil
    ) -> OrchardMigrationHost {
        let storage = testGeneralStorageDirectory!
        return OrchardMigrationHost(
            welding: welding,
            sharedBroadcaster: broadcaster,
            generalStorageURL: storage,
            tickInterval: tickInterval,
            now: { Date() },
            logger: logger,
            actorFactory: { accountUUID, broadcaster in
                factoryRecorder?.recordCall()
                return OrchardMigration(
                    welding: welding,
                    accountUUID: accountUUID,
                    broadcaster: broadcaster,
                    syncGate: MigrationSyncGate(
                        directory: storage,
                        accountUUID: accountUUID,
                        bufferDuration: 600,
                        tickInterval: tickInterval,
                        now: { Date() },
                        overdueProvider: { (try? await welding.migrationHasOverdueTransfers(for: accountUUID)) ?? false },
                        logger: logger
                    ),
                    logger: logger
                )
            }
        )
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
}

/// Records how many times a scripted `OrchardMigrationHost` `actorFactory` closure ran -- mirrors
/// `SDKSynchronizerMigrationTests`'s helper of the same name/purpose.
private final class FactoryInvocationRecorder {
    private(set) var callCount = 0

    func recordCall() {
        callCount += 1
    }
}
