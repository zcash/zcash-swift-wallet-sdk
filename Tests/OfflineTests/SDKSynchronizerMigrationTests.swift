//
//  SDKSynchronizerMigrationTests.swift
//  OfflineTests
//
//  Tests `SDKSynchronizer`'s migration group (R4-B): the 23 protocol requirements as thin forwards
//  to a seamed `OrchardMigrationHost`, and the two SDK-enforced session-separation behaviors --
//  the start() privacy gate and the submitNoteSplit/executeNextPendingMigrationTransfer broadcast
//  guard. Driven through the host's injecting initializer + a scripted actor factory, mirroring
//  R4-A's `OrchardMigrationHostTests` seam, with the host substituted into a real `SDKSynchronizer`
//  via the container-mock seam (`container.mock(type: OrchardMigrationHost.self, ...)`) that
//  `SDKSynchronizer.init` resolves against, same as `sdkFlags`/`submitPlanStore`.
//
//  No network, no real FFI beyond local SQLite/key-derivation calls that `Initializer`/
//  `TestsData` already make offline elsewhere in this suite.
//

import Combine
import Foundation
@testable import TestUtils
import XCTest
@testable import ZcashLightClientKit

final class SDKSynchronizerMigrationTests: ZcashTestCase {
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

    func testProposeMigrationTransfersForwardsIncludeResidual() async throws {
        let welding = ZcashRustBackendWeldingMock()
        let expected = MigrationSchedule(transfers: [], estimatedDurationHours: 3)
        welding.migrationProposeTransfersIncludeResidualForReturnValue = expected
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))

        let schedule = try await synchronizer.proposeMigrationTransfers(accountUUID: accountUUID, includeResidual: true)

        XCTAssertEqual(schedule, expected)
        let received = welding.migrationProposeTransfersIncludeResidualForReceivedArguments
        XCTAssertEqual(received?.account, accountUUID)
        XCTAssertEqual(received?.includeResidual, true)
    }

    func testIsSyncRequiredBeforeNextMigrationTransferForwards() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.migrationIsSyncRequiredForReturnValue = true
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))

        let required = try await synchronizer.isSyncRequiredBeforeNextMigrationTransfer(accountUUID: accountUUID)

        XCTAssertTrue(required)
        XCTAssertEqual(welding.migrationIsSyncRequiredForReceivedAccount, accountUUID)
    }

    func testHasOverdueMigrationTransfersForwards() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.migrationHasOverdueTransfersForReturnValue = true
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))

        let overdue = try await synchronizer.hasOverdueMigrationTransfers(accountUUID: accountUUID)

        XCTAssertTrue(overdue)
        XCTAssertEqual(welding.migrationHasOverdueTransfersForReceivedAccount, accountUUID)
    }

    /// The sequential-runs contract at the API level: `.complete` is per-run, and the authority
    /// for "does anything remain to migrate" is a fresh propose — an empty schedule means no, a
    /// non-empty one is the next run's proposal. Hosts must not latch "never migrate again" off
    /// the state machine alone.
    func testAfterCompleteProposeMigrationTransfersAnswersWhetherAnythingRemains() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.migrationStateForReturnValue = .complete
        welding.migrationProposeTransfersIncludeResidualForReturnValue = MigrationSchedule(
            transfers: [],
            estimatedDurationHours: 0
        )
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))

        let state = try await synchronizer.migrationState(accountUUID: accountUUID)
        XCTAssertEqual(state, .complete)

        let remains = try await synchronizer.proposeMigrationTransfers(accountUUID: accountUUID, includeResidual: false)
        XCTAssertTrue(remains.transfers.isEmpty, "an empty schedule is the 'nothing remains' answer")

        // Funds arrive later (or a large balance needed another round): the same call now answers
        // with the next run's proposal.
        let nextRun = MigrationSchedule(
            transfers: [
                MigrationTransferProposal(
                    id: "3",
                    amount: Zatoshi(100_000_000),
                    anchorHeight: BlockHeight(1_000),
                    nextExecutableAfterHeight: BlockHeight(1_010),
                    expiryHeight: BlockHeight(70_000)
                )
            ],
            estimatedDurationHours: 1
        )
        welding.migrationProposeTransfersIncludeResidualForReturnValue = nextRun
        let proposed = try await synchronizer.proposeMigrationTransfers(accountUUID: accountUUID, includeResidual: false)
        XCTAssertEqual(proposed, nextRun, "a non-empty schedule is the next run's proposal")
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

    // MARK: - Enforcement: start() privacy gate

    func testStartThrowsMigrationSyncBlockedWhenHostReportsBlocked() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.listAccountsReturnValue = [makeAccount(accountUUID)]
        welding.migrationHasOverdueTransfersForReturnValue = true
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))
        await synchronizer.updateStatus(.stopped)

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

    func testStartProceedsPastTheGateWhenHostReportsUnblocked() async throws {
        let welding = ZcashRustBackendWeldingMock()
        welding.listAccountsReturnValue = []
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding))
        await synchronizer.updateStatus(.stopped)

        do {
            try await synchronizer.start(retry: false)
            // Ideal outcome: the gate passed and start() ran to completion offline.
        } catch let error as ZcashError {
            if case .migrationSyncBlocked = error {
                XCTFail("start() must not report migrationSyncBlocked when the host reports unblocked")
            }
            // Any other ZcashError is an unrelated offline failure (no live lightwalletd) and is
            // acceptable here -- only the gate's behavior is under test.
        } catch {
            // Likewise tolerated as an unrelated offline failure.
        }

        synchronizer.stop()
    }

    // MARK: - Enforcement: broadcast guard

    func testSubmitNoteSplitThrowsDuringSyncWithoutTouchingTheHost() async throws {
        let welding = ZcashRustBackendWeldingMock()
        let recorder = FactoryInvocationRecorder()
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding, factoryRecorder: recorder))
        await synchronizer.updateStatus(.syncing(0.5, false))

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
        await synchronizer.updateStatus(.syncing(0.5, false))

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
    /// unconfigured mock return value).
    func testSubmitNoteSplitForwardsWhenNotSyncing() async throws {
        struct StubSigningFailure: Error, Equatable {}
        let welding = ZcashRustBackendWeldingMock()
        welding.migrationSignNoteSplitProposalUskForThrowableError = StubSigningFailure()
        let recorder = FactoryInvocationRecorder()
        let synchronizer = try makeSynchronizer(migrationHost: makeHost(welding: welding, factoryRecorder: recorder))
        await synchronizer.updateStatus(.stopped)

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
        await synchronizer.updateStatus(.stopped)

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

    // MARK: - Resource lifecycle: migration-host registration must not retain the Initializer

    /// Regression test: `SDKSynchronizer.init` registers a factory closure for `OrchardMigrationHost`
    /// on `initializer.container`. If that closure captures `initializer` with no capture list, the
    /// result is a cycle -- `initializer` owns `container` (`Initializer.container: DIContainer`),
    /// `container` stores the closure, and the closure captures `initializer` right back
    /// (`initializer -> container -> closure -> initializer`). Once that happens, `initializer` (and
    /// everything it owns: the container, the resolved `OrchardMigrationHost`, every per-account actor)
    /// outlives the synchronizer that built it for as long as the container itself stays reachable --
    /// e.g. this test's `mockContainer`, which `ZcashTestCase` keeps alive for the whole test method,
    /// well past this test's own local scope.
    ///
    /// Deliberately does NOT go through `makeSynchronizer(migrationHost:)`/`makeHost(welding:)` like
    /// every other test in this file: pre-mocking `OrchardMigrationHost` would mean `SDKSynchronizer.init`
    /// resolves the *mock* dependency, and `DIContainer.resolve`'s singleton-cache write-back
    /// (`dependencies[key] = Dependency(factory: dependency.factory, ...)`) always writes into the
    /// non-mock `dependencies` dictionary, even when what it just resolved came from `mockedDependencies`
    /// -- so a pre-registered mock overwrites (and thereby immediately releases) the real,
    /// initializer-capturing closure before it is ever invoked, which would hide this exact bug. Letting
    /// `SDKSynchronizer.init` register and resolve the real `OrchardMigrationHost(initializer:)` is what
    /// exercises the production code path the bug lives in.
    ///
    /// Also deliberately does NOT go through `SDKSynchronizer.init(initializer:)` (the public convenience
    /// initializer): that convenience initializer builds its `CompactBlockProcessor` with
    /// `walletBirthdayProvider: { initializer.walletBirthday }`, an unrelated, pre-existing closure (predates
    /// this migration work) that captures `initializer` and ends up retained by the container too, via
    /// `Dependencies.setupCompactBlockProcessor`'s `UTXOFetcher` registration
    /// (`UTXOFetcherConfig(walletBirthdayProvider: config.walletBirthdayProvider)`). That is a second,
    /// independent container/`Initializer` cycle -- out of scope here (not part of the migration-host
    /// registration this test targets) -- that would otherwise keep `initializer` alive regardless of
    /// this fix and make the test unable to isolate the one cycle it exists to catch. Calling the
    /// designated initializer directly, with a `walletBirthdayProvider` that returns a constant instead of
    /// capturing `initializer`, sidesteps that unrelated cycle without touching any production code.
    func testMigrationHostRegistrationDoesNotLeakTheInitializer() throws {
        weak var weakInitializer: Initializer?
        weak var weakSynchronizer: SDKSynchronizer?

        func buildAndReleaseSynchronizer() throws {
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
            let blockProcessor = CompactBlockProcessor(
                initializer: initializer,
                walletBirthdayProvider: { 0 }
            )
            let synchronizer = SDKSynchronizer(
                status: .unprepared,
                initializer: initializer,
                transactionEncoder: WalletTransactionEncoder(initializer: initializer),
                transactionRepository: initializer.transactionRepository,
                blockProcessor: blockProcessor,
                syncSessionTicker: .live
            )

            weakInitializer = initializer
            weakSynchronizer = synchronizer
        }

        try buildAndReleaseSynchronizer()

        XCTAssertNil(weakSynchronizer, "SDKSynchronizer should deallocate once every strong reference to it goes out of scope")
        XCTAssertNil(
            weakInitializer,
            """
            Initializer should deallocate once its owning SDKSynchronizer is gone -- a non-nil value means the \
            OrchardMigrationHost registration closure is still retaining it (initializer -> container -> closure -> initializer)
            """
        )
    }

    // MARK: - Helpers

    /// Builds an `SDKSynchronizer` whose one `OrchardMigrationHost` is `migrationHost`, substituted
    /// via the same container-mock seam `SDKSynchronizer.init` resolves the production host through.
    private func makeSynchronizer(migrationHost: OrchardMigrationHost) throws -> SDKSynchronizer {
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

        return SDKSynchronizer(initializer: initializer)
    }

    /// Builds an `OrchardMigrationHost` via its injecting initializer, following R4-A's
    /// `OrchardMigrationHostTests` seam: `welding` backs both the wallet-scope predicate and every
    /// per-account actor the (scripted) `actorFactory` produces. `factoryRecorder`, when supplied,
    /// counts every `actorFactory` invocation -- i.e. every time `migrationHost.migration(for:)`
    /// actually built (or reused... no, `migration(for:)` caches, so this only fires once per
    /// account) a per-account actor, which is what the broadcast guard's "never touched the host"
    /// assertions pin.
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

/// Records how many times a scripted `OrchardMigrationHost` `actorFactory` closure ran -- i.e. how
/// many times `migrationHost.migration(for:)` actually had to build a per-account actor. Mutated
/// synchronously from the (non-async) `actorFactory` closure, which this suite's tests only ever
/// invoke serially -- mirroring how `ZcashRustBackendWeldingMock`'s own plain `CallsCount` fields
/// are mutated in this codebase's generated mocks.
private final class FactoryInvocationRecorder {
    private(set) var callCount = 0

    func recordCall() {
        callCount += 1
    }
}
