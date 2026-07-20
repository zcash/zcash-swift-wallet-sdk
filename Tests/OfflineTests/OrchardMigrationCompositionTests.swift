//
//  OrchardMigrationCompositionTests.swift
//  OfflineTests
//
//  Actor-composition tests for `OrchardMigration`, driven through its internal injecting
//  initializer against `ZcashRustBackendWeldingMock` plus hand-written fakes for the
//  `MigrationBroadcasting` seam and a real, temp-file-backed `MigrationSyncGate` (as established by
//  MigrationLogicTests.swift's I1 canary test). No network, no real FFI: this file exercises the
//  composition wiring (call order, what gets recorded, when the sync gate is marked) over those
//  seams, complementing MigrationFFITests.swift (real FFI) and MigrationLogicTests.swift (pure
//  logic).
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class OrchardMigrationCompositionTests: ZcashTestCase {
    private let accountA = AccountUUID(id: [UInt8](repeating: 0x33, count: 16))
    private let referenceDate = Date(timeIntervalSince1970: 1_700_000_000)
    private let buffer: TimeInterval = 600
    private let defaultEndpoint = LightWalletEndpoint(address: "default.example", port: 9067)
    private let usk = UnifiedSpendingKey(network: .testnet, bytes: [UInt8](repeating: 0xEE, count: 32))

    private var welding: ZcashRustBackendWeldingMock!
    private var clock: TestClock!
    private var gate: MigrationSyncGate!

    override func setUp() {
        super.setUp()
        welding = ZcashRustBackendWeldingMock()
        clock = TestClock(referenceDate)
        gate = makeGate(account: accountA, clock: clock)
    }

    override func tearDown() {
        welding = nil
        clock = nil
        gate = nil
        super.tearDown()
    }

    // MARK: - submitNoteSplit composition

    /// Proves the full `sign -> extract -> broadcast -> gate marked -> record` order for the
    /// success path, and that the mapped result is returned. The `record` closure additionally
    /// asserts the gate is already marked at the moment it runs, pinning "the privacy gate marks
    /// strictly before record" — the buffer protects a landed broadcast even when the engine's
    /// record bookkeeping subsequently fails.
    func testSubmitNoteSplitOrdersSignExtractBroadcastMarksGateThenRecordsOnSuccess() async throws {
        let recorder = CompositionOrderRecorder()
        let proposal = NoteSplitProposal(outputNotes: [Zatoshi(100_000)], fee: Zatoshi(5_000))
        let prepared = makePreparedTransfer(id: "split-0")
        let rawTransaction = Data([0x02, 0x03])

        welding.migrationSignNoteSplitProposalUskForClosure = { receivedProposal, receivedUsk, receivedAccount in
            recorder.record("sign")
            XCTAssertEqual(receivedProposal, proposal)
            XCTAssertEqual(receivedUsk, self.usk)
            XCTAssertEqual(receivedAccount, self.accountA)
            return prepared
        }
        welding.migrationExtractBroadcastTxPcztForClosure = { pczt, _ in
            recorder.record("extract")
            XCTAssertEqual(pczt, prepared.pczt)
            return rawTransaction
        }
        welding.migrationRecordTransferResultTransferIdResultForClosure = { transferId, result, _ in
            recorder.record("record")
            XCTAssertEqual(transferId, prepared.id)
            XCTAssertEqual(result, MigrationTransferResult.success(txId: prepared.txid.toHexStringTxId()))
            // Ordering proof: the gate must already be marked when record runs.
            XCTAssertNotNil(self.gate.currentResumeAt())
        }

        let broadcaster = ScriptedBroadcaster(script: .outcome(.submitted))
        broadcaster.onBroadcast = { recorder.record("broadcast") }
        let migration = makeMigration(broadcaster: broadcaster)

        let result = try await migration.submitNoteSplit(
            proposal: proposal,
            usk: usk,
            options: MigrationNetworkPrivacyOptions(useTor: false, submissionEndpoint: defaultEndpoint)
        )

        XCTAssertEqual(result, MigrationTransferResult.success(txId: prepared.txid.toHexStringTxId()))
        XCTAssertEqual(recorder.events, ["sign", "extract", "broadcast", "record"])
        XCTAssertEqual(broadcaster.receivedCalls.count, 1)
        XCTAssertEqual(broadcaster.receivedCalls.first?.endpoint, defaultEndpoint)
        XCTAssertNotNil(gate.currentResumeAt(), "gate must be marked after a successful broadcast")
    }

    /// Transport failure is *returned*, not thrown: recorded as a retryable network error, and the
    /// privacy-buffer gate is left untouched (only a `.success` marks it).
    func testSubmitNoteSplitOnTransportFailureRecordsNetworkErrorAndLeavesGateUntouched() async throws {
        let proposal = NoteSplitProposal(outputNotes: [Zatoshi(100_000)], fee: Zatoshi(5_000))
        let prepared = makePreparedTransfer(id: "split-0")
        welding.migrationSignNoteSplitProposalUskForReturnValue = prepared
        welding.migrationExtractBroadcastTxPcztForReturnValue = Data([0x02, 0x03])
        welding.migrationRecordTransferResultTransferIdResultForClosure = { _, _, _ in }
        let broadcaster = ScriptedBroadcaster(script: .outcome(.transportError))
        let migration = makeMigration(broadcaster: broadcaster)

        // A plain `try await` (no do/catch) already proves this does not throw; the assertions below
        // pin down the recorded/gate side effects.
        let result = try await migration.submitNoteSplit(
            proposal: proposal,
            usk: usk,
            options: MigrationNetworkPrivacyOptions(useTor: false, submissionEndpoint: defaultEndpoint)
        )

        XCTAssertEqual(result, MigrationTransferResult.networkError(retryable: true))
        XCTAssertEqual(
            welding.migrationRecordTransferResultTransferIdResultForReceivedArguments?.result,
            MigrationTransferResult.networkError(retryable: true)
        )
        XCTAssertNil(gate.currentResumeAt())
    }

    /// The sibling of MigrationLogicTests' `testExecuteNextPendingTransferFailsClosedOnTor...`
    /// canary, driven through `submitNoteSplit` instead of `executeNextPendingTransfer`: both public
    /// entry points share the same private `broadcastAndRecord` composition, so the fail-closed Tor
    /// guarantee must hold from this call site too.
    func testSubmitNoteSplitFailsClosedOnTorUnavailableWithoutRecordingOrGating() async throws {
        let proposal = NoteSplitProposal(outputNotes: [Zatoshi(100_000)], fee: Zatoshi(5_000))
        let prepared = makePreparedTransfer(id: "split-0")
        welding.migrationSignNoteSplitProposalUskForReturnValue = prepared
        welding.migrationExtractBroadcastTxPcztForReturnValue = Data([0x02, 0x03])
        welding.migrationRecordTransferResultTransferIdResultForClosure = { _, _, _ in }
        let broadcaster = ScriptedBroadcaster(script: .throwing(ZcashError.migrationTorUnavailable))
        let migration = makeMigration(broadcaster: broadcaster)

        do {
            _ = try await migration.submitNoteSplit(
                proposal: proposal,
                usk: usk,
                options: MigrationNetworkPrivacyOptions(useTor: true, submissionEndpoint: defaultEndpoint)
            )
            XCTFail("Expected migrationTorUnavailable to be thrown")
        } catch ZcashError.migrationTorUnavailable {
            // expected
        } catch {
            XCTFail("Expected migrationTorUnavailable but got \(error)")
        }

        XCTAssertEqual(broadcaster.receivedCalls.count, 1)
        XCTAssertFalse(welding.migrationRecordTransferResultTransferIdResultForCalled)
        XCTAssertNil(gate.currentResumeAt())
    }

    // MARK: - executeNextPendingTransfer composition

    func testExecuteNextPendingTransferReturnsNilWhenNothingDueWithNoBroadcastNoRecordNoGateChange() async throws {
        welding.migrationNextDueTransferForReturnValue = nil
        let broadcaster = ScriptedBroadcaster(script: .throwing(StubEngineError()))
        let migration = makeMigration(broadcaster: broadcaster)

        let result = try await migration.executeNextPendingTransfer(options: MigrationNetworkPrivacyOptions(useTor: false, submissionEndpoint: defaultEndpoint))

        XCTAssertNil(result)
        XCTAssertEqual(broadcaster.receivedCalls.count, 0)
        XCTAssertFalse(welding.migrationRecordTransferResultTransferIdResultForCalled)
        XCTAssertNil(gate.currentResumeAt())
    }

    func testExecuteNextPendingTransferSuccessPathRecordsAndMarksGate() async throws {
        let prepared = makePreparedTransfer(id: "transfer-1")
        welding.migrationNextDueTransferForReturnValue = prepared
        welding.migrationExtractBroadcastTxPcztForReturnValue = Data([0x07])
        welding.migrationRecordTransferResultTransferIdResultForClosure = { _, _, _ in }
        let broadcaster = ScriptedBroadcaster(script: .outcome(.submitted))
        let migration = makeMigration(broadcaster: broadcaster)

        let result = try await migration.executeNextPendingTransfer(options: MigrationNetworkPrivacyOptions(useTor: false, submissionEndpoint: defaultEndpoint))

        XCTAssertEqual(result, MigrationTransferResult.success(txId: prepared.txid.toHexStringTxId()))
        XCTAssertEqual(
            welding.migrationRecordTransferResultTransferIdResultForReceivedArguments?.result,
            MigrationTransferResult.success(txId: prepared.txid.toHexStringTxId())
        )
        XCTAssertNotNil(gate.currentResumeAt())
    }

    /// M5: seam-based coverage of the rejection branch's generic (non-expiry) message, at the
    /// composition level -- not just the pure `map` table already covered by MigrationLogicTests.
    func testExecuteNextPendingTransferInvalidNoteRejectionRecordsAndLeavesGateUntouched() async throws {
        let prepared = makePreparedTransfer(id: "transfer-1")
        welding.migrationNextDueTransferForReturnValue = prepared
        welding.migrationExtractBroadcastTxPcztForReturnValue = Data([0x07])
        welding.migrationRecordTransferResultTransferIdResultForClosure = { _, _, _ in }
        let broadcaster = ScriptedBroadcaster(script: .outcome(.rejected(errorCode: -25, message: "missing inputs")))
        let migration = makeMigration(broadcaster: broadcaster)

        let result = try await migration.executeNextPendingTransfer(options: MigrationNetworkPrivacyOptions(useTor: false, submissionEndpoint: defaultEndpoint))

        XCTAssertEqual(result, MigrationTransferResult.invalidNote)
        XCTAssertEqual(
            welding.migrationRecordTransferResultTransferIdResultForReceivedArguments?.result,
            MigrationTransferResult.invalidNote
        )
        XCTAssertNil(gate.currentResumeAt())
    }

    /// M5: seam-based coverage of the rejection branch's expiry message, at the composition level.
    func testExecuteNextPendingTransferExpiredRejectionRecordsAndLeavesGateUntouched() async throws {
        let prepared = makePreparedTransfer(id: "transfer-1")
        welding.migrationNextDueTransferForReturnValue = prepared
        welding.migrationExtractBroadcastTxPcztForReturnValue = Data([0x07])
        welding.migrationRecordTransferResultTransferIdResultForClosure = { _, _, _ in }
        let broadcaster = ScriptedBroadcaster(script: .outcome(.rejected(errorCode: -26, message: "tx-expiring-soon")))
        let migration = makeMigration(broadcaster: broadcaster)

        let result = try await migration.executeNextPendingTransfer(options: MigrationNetworkPrivacyOptions(useTor: false, submissionEndpoint: defaultEndpoint))

        XCTAssertEqual(result, MigrationTransferResult.expired)
        XCTAssertEqual(
            welding.migrationRecordTransferResultTransferIdResultForReceivedArguments?.result,
            MigrationTransferResult.expired
        )
        XCTAssertNil(gate.currentResumeAt())
    }

    /// Broadcaster single-endpoint discipline: exactly one call, to the options' required
    /// submission endpoint.
    func testBroadcasterReceivesExactlyOneCallToTheResolvedEndpoint() async throws {
        let prepared = makePreparedTransfer(id: "transfer-1")
        welding.migrationNextDueTransferForReturnValue = prepared
        welding.migrationExtractBroadcastTxPcztForReturnValue = Data([0x07])
        welding.migrationRecordTransferResultTransferIdResultForClosure = { _, _, _ in }
        let overrideEndpoint = LightWalletEndpoint(address: "override.example", port: 443)
        XCTAssertNotEqual(overrideEndpoint, defaultEndpoint)
        let broadcaster = ScriptedBroadcaster(script: .outcome(.submitted))
        let migration = makeMigration(broadcaster: broadcaster)

        _ = try await migration.executeNextPendingTransfer(
            options: MigrationNetworkPrivacyOptions(useTor: false, submissionEndpoint: overrideEndpoint)
        )

        XCTAssertEqual(broadcaster.receivedCalls.count, 1)
        XCTAssertEqual(broadcaster.receivedCalls.first?.endpoint, overrideEndpoint)
    }

    // MARK: - Txid byte order (welding record path)

    /// Finding 12: pins the EXACT bytes `migrationRecordTransferResult` receives across the welding
    /// record boundary, using an ascending, asymmetric txid fixture -- reversing it changes every
    /// byte, so a byte-order regression cannot hide the way it could behind this file's other tests'
    /// symmetric `makePreparedTransfer`/`Data(repeating: 0xAB, count: 32)` fixture (reversing 32
    /// identical bytes is a no-op; those tests would stay green even if the byte-order reversal
    /// silently dropped out of `OrchardMigration.broadcastAndRecord`).
    ///
    /// `expectedDisplayTxId` is hand-derived from the documented convention (reverse `prepared.txid`'s
    /// byte order, then hex-encode -- see `PreparedMigrationTransfer.txid` and
    /// `MigrationTransferResult.success`'s doc comments) independently of `Data.toHexStringTxId()`,
    /// not produced by running it and pasting the output. See `TxIdTests` for the same convention
    /// pinned directly against the conversion helpers themselves, off the actor.
    func testExecuteNextPendingTransferRecordsTheDocumentedByteOrderForAnAsymmetricTxId() async throws {
        let rawTxId: [UInt8] = (0..<32).map { UInt8($0) }
        let expectedDisplayTxId = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
        let prepared = PreparedMigrationTransfer(id: "transfer-1", txid: Data(rawTxId), pczt: Data([0x01, 0x02]))
        welding.migrationNextDueTransferForReturnValue = prepared
        welding.migrationExtractBroadcastTxPcztForReturnValue = Data([0x07])
        welding.migrationRecordTransferResultTransferIdResultForClosure = { _, _, _ in }
        let broadcaster = ScriptedBroadcaster(script: .outcome(.submitted))
        let migration = makeMigration(broadcaster: broadcaster)

        let result = try await migration.executeNextPendingTransfer(options: MigrationNetworkPrivacyOptions(useTor: false, submissionEndpoint: defaultEndpoint))

        XCTAssertEqual(result, MigrationTransferResult.success(txId: expectedDisplayTxId))
        XCTAssertEqual(
            welding.migrationRecordTransferResultTransferIdResultForReceivedArguments?.result,
            MigrationTransferResult.success(txId: expectedDisplayTxId)
        )
    }

    // MARK: - Record failure after a successful broadcast

    /// When the broadcast succeeded but recording the result throws, the privacy gate must already
    /// be marked (the broadcast DID land — the 10-minute buffer protects it independently of engine
    /// bookkeeping), and the call must surface the distinguishable
    /// `migrationRecordFailedAfterBroadcast` so the host knows the engine reconciles later.
    func testExecuteNextPendingTransferRecordThrowAfterSuccessfulBroadcastMarksGateAndThrowsWrapped() async throws {
        let prepared = makePreparedTransfer(id: "transfer-1")
        welding.migrationNextDueTransferForReturnValue = prepared
        welding.migrationExtractBroadcastTxPcztForReturnValue = Data([0x07])
        welding.migrationRecordTransferResultTransferIdResultForThrowableError = StubEngineError()
        let broadcaster = ScriptedBroadcaster(script: .outcome(.submitted))
        let migration = makeMigration(broadcaster: broadcaster)

        do {
            _ = try await migration.executeNextPendingTransfer(options: MigrationNetworkPrivacyOptions(useTor: false, submissionEndpoint: defaultEndpoint))
            XCTFail("Expected migrationRecordFailedAfterBroadcast to be thrown")
        } catch ZcashError.migrationRecordFailedAfterBroadcast {
            // expected
        } catch {
            XCTFail("Expected migrationRecordFailedAfterBroadcast but got \(error)")
        }

        XCTAssertEqual(broadcaster.receivedCalls.count, 1)
        XCTAssertNotNil(gate.currentResumeAt(), "a real broadcast must start the privacy buffer even when recording fails")
    }

    /// The sibling of the test above for the other public broadcast flow.
    func testSubmitNoteSplitRecordThrowAfterSuccessfulBroadcastMarksGateAndThrowsWrapped() async throws {
        let proposal = NoteSplitProposal(outputNotes: [Zatoshi(100_000)], fee: Zatoshi(5_000))
        welding.migrationSignNoteSplitProposalUskForReturnValue = makePreparedTransfer(id: "split-0")
        welding.migrationExtractBroadcastTxPcztForReturnValue = Data([0x02, 0x03])
        welding.migrationRecordTransferResultTransferIdResultForThrowableError = StubEngineError()
        let broadcaster = ScriptedBroadcaster(script: .outcome(.submitted))
        let migration = makeMigration(broadcaster: broadcaster)

        do {
            _ = try await migration.submitNoteSplit(
                proposal: proposal,
                usk: usk,
                options: MigrationNetworkPrivacyOptions(useTor: false, submissionEndpoint: defaultEndpoint)
            )
            XCTFail("Expected migrationRecordFailedAfterBroadcast to be thrown")
        } catch ZcashError.migrationRecordFailedAfterBroadcast {
            // expected
        } catch {
            XCTFail("Expected migrationRecordFailedAfterBroadcast but got \(error)")
        }

        XCTAssertNotNil(gate.currentResumeAt(), "a real broadcast must start the privacy buffer even when recording fails")
    }

    /// A record failure on a non-success outcome (here a transport error — nothing verifiably
    /// landed) propagates the raw error unwrapped and the gate stays untouched: the
    /// record-failed-after-broadcast contract is reserved for outcomes that map to success.
    func testExecuteNextPendingTransferRecordThrowOnTransportErrorPropagatesRawAndLeavesGateUntouched() async throws {
        let prepared = makePreparedTransfer(id: "transfer-1")
        welding.migrationNextDueTransferForReturnValue = prepared
        welding.migrationExtractBroadcastTxPcztForReturnValue = Data([0x07])
        welding.migrationRecordTransferResultTransferIdResultForThrowableError = StubEngineError()
        let broadcaster = ScriptedBroadcaster(script: .outcome(.transportError))
        let migration = makeMigration(broadcaster: broadcaster)

        do {
            _ = try await migration.executeNextPendingTransfer(options: MigrationNetworkPrivacyOptions(useTor: false, submissionEndpoint: defaultEndpoint))
            XCTFail("Expected the raw record error to be rethrown")
        } catch is StubEngineError {
            // expected
        } catch {
            XCTFail("Expected StubEngineError but got \(error)")
        }

        XCTAssertNil(gate.currentResumeAt())
    }

    // MARK: - Broadcast single-flight

    /// Pins the single-flight discipline of the broadcast flows: with one `executeNextPendingTransfer`
    /// deliberately suspended inside its broadcast, a second concurrent call must not re-fetch and
    /// re-broadcast the same bytes. It waits for the in-flight flow, then proceeds fresh — its own
    /// due-transfer re-fetch runs after the record, returns nil, and the call returns nil.
    /// Deterministic: the broadcaster suspends until the test opens it, and the welding vends the one
    /// due transfer only until its result is recorded.
    func testConcurrentExecuteNextPendingTransferBroadcastsExactlyOnce() async throws {
        let prepared = makePreparedTransfer(id: "transfer-1")
        welding.migrationNextDueTransferForClosure = { [welding] _ in
            // The engine contract: the transfer stays "next due" until its result is recorded.
            welding?.migrationRecordTransferResultTransferIdResultForCalled == true ? nil : prepared
        }
        welding.migrationExtractBroadcastTxPcztForReturnValue = Data([0x07])
        welding.migrationRecordTransferResultTransferIdResultForClosure = { _, _, _ in }
        let broadcaster = GatedBroadcaster(outcome: MigrationBroadcastOutcome.submitted)
        let migration = makeMigration(broadcaster: broadcaster)
        let options = MigrationNetworkPrivacyOptions(useTor: false, submissionEndpoint: defaultEndpoint)

        let first = Task {
            try await migration.executeNextPendingTransfer(options: options)
        }
        // The first caller is provably suspended inside its broadcast before the second one starts.
        await broadcaster.awaitBroadcastsStarted(1)
        let second = Task {
            try await migration.executeNextPendingTransfer(options: options)
        }
        // Scheduling aid only (correctness must not depend on it): give the second caller ample
        // opportunity to reach the actor while the first broadcast is still in flight, so a missing
        // single-flight guard reliably manifests as a second fetch/broadcast.
        for _ in 0..<50 {
            await Task.yield()
        }
        await broadcaster.open()

        let firstResult = try await first.value
        let secondResult = try await second.value

        let broadcastsStarted = await broadcaster.startedCount
        XCTAssertEqual(broadcastsStarted, 1, "the same due transfer must be broadcast exactly once")
        XCTAssertEqual(firstResult, MigrationTransferResult.success(txId: prepared.txid.toHexStringTxId()))
        XCTAssertNil(secondResult, "the concurrent caller must observe the recorded outcome and find nothing due")
        XCTAssertEqual(welding.migrationNextDueTransferForCallsCount, 2, "the concurrent caller re-fetches after the in-flight flow finishes")
        XCTAssertEqual(welding.migrationRecordTransferResultTransferIdResultForCallsCount, 1)
    }

    /// The single-flight discipline spans the different broadcast entry points: a `submitNoteSplit`
    /// arriving while an `executeNextPendingTransfer` broadcast is in flight runs strictly after it —
    /// its signing does not even start until the in-flight flow has recorded. Both flows then
    /// broadcast their own (different) transactions.
    func testSubmitNoteSplitWaitsForInFlightExecuteNextPendingTransfer() async throws {
        let recorder = CompositionOrderRecorder()
        let dueTransfer = makePreparedTransfer(id: "transfer-1")
        let splitTransfer = makePreparedTransfer(id: "split-0")
        let proposal = NoteSplitProposal(outputNotes: [Zatoshi(100_000)], fee: Zatoshi(5_000))
        welding.migrationNextDueTransferForClosure = { [welding] _ in
            welding?.migrationRecordTransferResultTransferIdResultForCalled == true ? nil : dueTransfer
        }
        welding.migrationSignNoteSplitProposalUskForClosure = { _, _, _ in
            recorder.record("sign")
            return splitTransfer
        }
        welding.migrationExtractBroadcastTxPcztForReturnValue = Data([0x07])
        welding.migrationRecordTransferResultTransferIdResultForClosure = { transferId, _, _ in
            recorder.record("record:\(transferId)")
        }
        let broadcaster = GatedBroadcaster(outcome: MigrationBroadcastOutcome.submitted)
        let migration = makeMigration(broadcaster: broadcaster)

        let transferCall = Task {
            try await migration.executeNextPendingTransfer(options: MigrationNetworkPrivacyOptions(useTor: false, submissionEndpoint: defaultEndpoint))
        }
        await broadcaster.awaitBroadcastsStarted(1)
        let splitCall = Task {
            try await migration.submitNoteSplit(
                proposal: proposal,
                usk: self.usk,
                options: MigrationNetworkPrivacyOptions(useTor: false, submissionEndpoint: defaultEndpoint)
            )
        }
        // Scheduling aid only, as in the sibling test above.
        for _ in 0..<50 {
            await Task.yield()
        }
        await broadcaster.open()

        let transferResult = try await transferCall.value
        let splitResult = try await splitCall.value

        XCTAssertEqual(transferResult, MigrationTransferResult.success(txId: dueTransfer.txid.toHexStringTxId()))
        XCTAssertEqual(splitResult, MigrationTransferResult.success(txId: splitTransfer.txid.toHexStringTxId()))
        let broadcastsStarted = await broadcaster.startedCount
        XCTAssertEqual(broadcastsStarted, 2, "each flow broadcasts its own transaction, strictly serialized")
        XCTAssertEqual(
            recorder.events,
            ["record:transfer-1", "sign", "record:split-0"],
            "the note split must not even sign until the in-flight transfer flow has recorded"
        )
    }

    // MARK: - Keystone flow

    /// Documents the engine's prep-first contract at the actor level: immediately after
    /// `storeSignedNoteSplitPCZT`, the engine keeps reporting the split as the next due transfer
    /// (mirrored here by stubbing `migrationNextDueTransfer` to return the same prepared transfer
    /// `storeSignedNoteSplitPczt` handed back), so `executeNextPendingTransfer` broadcasts it.
    func testKeystoneFlowStoreSignedNoteSplitPCZTThenExecuteNextBroadcastsThePrepTransfer() async throws {
        let prepTransfer = makePreparedTransfer(id: "prep:run-0")
        welding.migrationStoreSignedNoteSplitPcztForReturnValue = prepTransfer
        welding.migrationNextDueTransferForReturnValue = prepTransfer
        welding.migrationExtractBroadcastTxPcztForClosure = { pczt, _ in
            XCTAssertEqual(pczt, prepTransfer.pczt)
            return Data([0x0A])
        }
        welding.migrationRecordTransferResultTransferIdResultForClosure = { _, _, _ in }
        let broadcaster = ScriptedBroadcaster(script: .outcome(.submitted))
        let migration = makeMigration(broadcaster: broadcaster)

        let stored = try await migration.storeSignedNoteSplitPCZT(Data([0x09]))
        XCTAssertEqual(stored, prepTransfer)

        let result = try await migration.executeNextPendingTransfer(options: MigrationNetworkPrivacyOptions(useTor: false, submissionEndpoint: defaultEndpoint))

        XCTAssertEqual(result, MigrationTransferResult.success(txId: prepTransfer.txid.toHexStringTxId()))
        XCTAssertEqual(welding.migrationRecordTransferResultTransferIdResultForReceivedArguments?.transferId, prepTransfer.id)
    }

    // MARK: - isSyncBlocked degrade path

    /// When the engine's overdue query throws, `isSyncBlocked` must degrade to the persisted
    /// gate-file (privacy-buffer) state rather than crash or propagate -- checked both with no gate
    /// file (unblocked) and with an active buffer (blocked), so the fallback is proven to actually
    /// read the file, not just swallow the error into a hardcoded answer.
    func testIsSyncBlockedDegradesToGateFileStateWhenWeldingHasOverdueThrows() async throws {
        welding.migrationHasOverdueTransfersForThrowableError = StubEngineError()
        let migration = makeMigration(broadcaster: ScriptedBroadcaster(script: .throwing(StubEngineError())))

        let blockedWithNoGateFile = await migration.isSyncBlocked()
        XCTAssertFalse(blockedWithNoGateFile)

        gate.markBroadcast()

        let blockedWithGateFile = await migration.isSyncBlocked()
        XCTAssertTrue(blockedWithGateFile)
    }

    // MARK: - Helpers

    private func makeMigration(broadcaster: any MigrationBroadcasting) -> OrchardMigration {
        OrchardMigration(
            welding: welding,
            accountUUID: accountA,
            broadcaster: broadcaster,
            syncGate: gate,
            logger: logger
        )
    }

    private func makeGate(account: AccountUUID, clock: TestClock) -> MigrationSyncGate {
        MigrationSyncGate(
            directory: testGeneralStorageDirectory,
            accountUUID: account,
            bufferDuration: buffer,
            // A long tick keeps the background re-evaluation out of these deterministic assertions.
            tickInterval: 3600,
            now: { clock.now },
            overdueProvider: { false },
            logger: logger
        )
    }

    private func makePreparedTransfer(id: String) -> PreparedMigrationTransfer {
        PreparedMigrationTransfer(id: id, txid: Data(repeating: 0xAB, count: 32), pczt: Data([0x01, 0x02]))
    }
}

/// Records the order in which the broadcast composition's collaborators are invoked, so a test can
/// assert the exact sign -> extract -> broadcast -> record sequence
/// `OrchardMigration.broadcastAndRecord` promises. `OrchardMigration` is an actor and every awaited
/// call in the composition is sequential, so a plain array is sufficient.
private final class CompositionOrderRecorder {
    private(set) var events: [String] = []

    func record(_ event: String) {
        events.append(event)
    }
}

/// A ``MigrationBroadcasting`` fake with a test-controlled suspension: every `broadcast` call
/// suspends until ``open()`` is called, giving single-flight tests a deterministic in-flight window.
/// Starts are observable via ``awaitBroadcastsStarted(_:)``; once opened, suspended and future
/// broadcasts complete immediately with the scripted outcome. An actor, because these tests
/// deliberately call it from concurrent tasks.
private actor GatedBroadcaster: MigrationBroadcasting {
    private let outcome: MigrationBroadcastOutcome
    private var isOpen = false
    private(set) var startedCount = 0
    private var pendingBroadcasts: [CheckedContinuation<Void, Never>] = []
    private var startObservers: [(threshold: Int, continuation: CheckedContinuation<Void, Never>)] = []

    init(outcome: MigrationBroadcastOutcome) {
        self.outcome = outcome
    }

    func broadcast(
        rawTransaction: Data,
        to endpoint: LightWalletEndpoint,
        useTor: Bool
    ) async throws -> MigrationBroadcastOutcome {
        startedCount += 1
        notifyStartObservers()
        if !isOpen {
            await withCheckedContinuation { continuation in
                pendingBroadcasts.append(continuation)
            }
        }
        return outcome
    }

    /// Returns once at least `count` broadcasts have started (immediately when they already have).
    func awaitBroadcastsStarted(_ count: Int) async {
        if startedCount >= count {
            return
        }
        await withCheckedContinuation { continuation in
            startObservers.append((threshold: count, continuation: continuation))
        }
    }

    /// Releases every suspended broadcast and lets all future ones complete immediately.
    func open() {
        isOpen = true
        let pending = pendingBroadcasts
        pendingBroadcasts = []
        for continuation in pending {
            continuation.resume()
        }
    }

    private func notifyStartObservers() {
        let ready = startObservers.filter { $0.threshold <= startedCount }
        startObservers.removeAll { $0.threshold <= startedCount }
        for observer in ready {
            observer.continuation.resume()
        }
    }
}

/// A generic, non-`ZcashError` failure for stubbing welding calls that must fail for reasons
/// unrelated to what a given test is actually asserting (e.g. an engine call the test never expects
/// to succeed but also never inspects the error from).
private struct StubEngineError: Error {}
