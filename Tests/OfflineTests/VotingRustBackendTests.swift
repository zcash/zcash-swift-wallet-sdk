//
//  VotingRustBackendTests.swift
//  ZcashLightClientKitTests
//

import XCTest
import SQLite3
@testable import ZcashLightClientKit

// Shared fixtures for tests that round-trip persisted voting recovery state
// through the Rust voting database.
private let roundTripWalletId = "test-wallet"
private let roundTripRoundId = "round"
private let roundTripBundleIndex: UInt32 = 0
private let roundTripProposalId: UInt32 = 1
private let roundTripShareIndex0: UInt32 = 0
private let roundTripShareIndex1: UInt32 = 1
private let roundTripSnapshotHeight: UInt64 = 1
private let roundTripVoteCommitmentTreePosition: UInt64 = 42
private let roundTripDelegationTxHash = "delegation-tx-hash"
private let roundTripVoteTxHash = "vote-tx-hash"
private let roundTripCommitmentBundleJson = #"{"vote_commitment":[1,2,3],"proposal_id":1}"#
private let roundTripHelperAURL = "https://helper-a.example"
private let roundTripHelperBURL = "https://helper-b.example"
private let roundTripFirstSubmitAt: UInt64 = 1000
private let roundTripSecondSubmitAt: UInt64 = 2000
private let roundTripCreatedAt: Int64 = 1_000
private let roundTripDiversifierByteCount = 11
private let roundTripEligibleNoteValue: UInt64 = 13_000_000
private let roundTripSQLiteSuccessCode = SQLITE_OK
private let roundTripSQLiteDoneCode = SQLITE_DONE
private let roundTripRoundParameter = [UInt8](repeating: 0x07, count: votingFieldElementByteCount)
private let roundTripKeystoneSignature = [UInt8](repeating: 0x01, count: votingKeystoneSignatureByteCount)
private let roundTripPcztSighash = [UInt8](repeating: 0x02, count: votingPcztSighashByteCount)
private let roundTripRandomizedKey = [UInt8](repeating: 0x03, count: votingRandomizedKeyByteCount)
private let roundTripShareNullifier = String(repeating: "dd", count: votingShareNullifierByteCount)
private let roundTripVoteCommitment = [UInt8](repeating: 0xAA, count: votingFieldElementByteCount)

final class VotingRustBackendTests: XCTestCase {
    private var dbPath: String?

    override func tearDown() {
        if let dbPath {
            try? FileManager.default.removeItem(atPath: dbPath)
        }
        dbPath = nil
        super.tearDown()
    }

    // MARK: - computeShareNullifier

    func test_computeShareNullifier_returnsExpectedValueForKnownFixture() throws {
        var voteCommitment = [UInt8](repeating: 0, count: votingFieldElementByteCount)
        voteCommitment[0] = 0x01
        var primaryBlind = [UInt8](repeating: 0, count: votingFieldElementByteCount)
        primaryBlind[0] = 0x03

        let nullifier = try VotingRustBackend.computeShareNullifier(
            voteCommitment: voteCommitment,
            shareIndex: 0,
            primaryBlind: primaryBlind
        )

        // Captured from the Rust reference implementation
        // (`zcash_voting::share_tracking::compute_share_nullifier`) for the
        // fixture above.
        XCTAssertEqual(
            nullifier,
            "058ffd2e1ba7acaf97b167accfb4ec141b91c0ee2a0f552631851ac97ca1e61d"
        )
    }

    func test_computeShareNullifier_throwsInvalidData_whenInputsAreNot32Bytes() {
        let valid = [UInt8](repeating: 0x01, count: votingFieldElementByteCount)
        let tooShort = [UInt8](repeating: 0x01, count: votingFieldElementByteCount - 1)
        let tooLong = [UInt8](repeating: 0x01, count: votingFieldElementByteCount + 1)

        for (vc, blind, label) in [
            (tooShort, valid, "voteCommitment too short"),
            (tooLong, valid, "voteCommitment too long"),
            (valid, tooShort, "primaryBlind too short"),
            (valid, tooLong, "primaryBlind too long")
        ] {
            XCTAssertThrowsError(
                try VotingRustBackend.computeShareNullifier(
                    voteCommitment: vc,
                    shareIndex: 0,
                    primaryBlind: blind
                ),
                label
            ) { error in
                guard case VotingRustBackendError.invalidData = error else {
                    XCTFail("\(label): expected .invalidData, got \(error)")
                    return
                }
            }
        }
    }

    // MARK: - Database lifecycle

    func test_open_succeedsAndCreatesFile() throws {
        let backend = VotingRustBackend()
        let path = makeTempDbPath()

        try backend.open(path: path)
        backend.close()

        XCTAssertTrue(FileManager.default.fileExists(atPath: path))
    }

    func test_open_secondTime_throwsDatabaseAlreadyOpen() throws {
        let backend = VotingRustBackend()
        let path = makeTempDbPath()

        try backend.open(path: path)
        defer { backend.close() }

        XCTAssertThrowsError(try backend.open(path: path)) { error in
            guard case VotingRustBackendError.databaseAlreadyOpen = error else {
                XCTFail("expected .databaseAlreadyOpen, got \(error)")
                return
            }
        }
    }

    func test_close_isIdempotent() throws {
        let backend = VotingRustBackend()
        let path = makeTempDbPath()

        try backend.open(path: path)
        backend.close()
        backend.close() // second close must not crash

        // Re-opening after close must succeed.
        try backend.open(path: path)
        backend.close()
    }

    func test_close_waitsForInFlightDatabaseOperationBeforeFreeingHandle() throws {
        let backend = VotingRustBackend()
        let path = makeTempDbPath()
        try backend.open(path: path)

        let operationStarted = XCTestExpectation(description: "operation started")
        let operationFinished = XCTestExpectation(description: "operation finished")
        let releaseOperation = DispatchSemaphore(value: 0)
        let closeFinished = DispatchSemaphore(value: 0)

        DispatchQueue.global().async {
            do {
                try backend.withLockedHandleForTesting {
                    operationStarted.fulfill()
                    releaseOperation.wait()
                }
                operationFinished.fulfill()
            } catch {
                XCTFail("unexpected error: \(error)")
            }
        }

        wait(for: [operationStarted], timeout: 1.0)

        DispatchQueue.global().async {
            backend.close()
            closeFinished.signal()
        }

        XCTAssertEqual(
            closeFinished.wait(timeout: .now() + .milliseconds(100)),
            .timedOut,
            "`close()` returned while a database operation still held the handle"
        )

        releaseOperation.signal()
        wait(for: [operationFinished], timeout: 1.0)
        XCTAssertEqual(closeFinished.wait(timeout: .now() + .seconds(1)), .success)

        XCTAssertThrowsError(try backend.setWalletId("wallet-after-close")) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    // MARK: - requireHandle gating

    func test_setWalletId_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(try backend.setWalletId("wallet")) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_resetTreeClient_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(try backend.resetTreeClient()) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_generateVanWitness_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(
            try backend.generateVanWitness(roundId: "round1", bundleIndex: 0, anchorHeight: 0)
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    // MARK: - Foundation helpers

    func test_decomposeWeight_returnsFixedWidthBinaryDecomposition() throws {
        XCTAssertEqual(try VotingRustBackend.decomposeWeight(0).filter { $0 != 0 }, [])
        XCTAssertEqual(try VotingRustBackend.decomposeWeight(1).filter { $0 != 0 }, [1])
        XCTAssertEqual(try VotingRustBackend.decomposeWeight(8).filter { $0 != 0 }, [8])
        XCTAssertEqual(
            try VotingRustBackend.decomposeWeight(11).filter { $0 != 0 }.sorted(),
            [1, 2, 8]
        )
    }

    func test_warmProvingCaches_doesNotThrow() throws {
        XCTAssertNoThrow(try VotingRustBackend.warmProvingCaches())
        XCTAssertNoThrow(try VotingRustBackend.warmProvingCaches())
    }

    func test_generateDelegationInputs_rejectsShortSeeds() {
        let short = [UInt8](repeating: 0x01, count: votingMinSeedByteCount - 1)
        let valid = [UInt8](repeating: 0x02, count: votingMinSeedByteCount)
        XCTAssertThrowsError(
            try VotingRustBackend.generateDelegationInputs(
                senderSeed: short,
                hotkeySeed: valid,
                networkId: 1,
                accountIndex: 0
            )
        ) { error in
            guard case VotingRustBackendError.invalidData = error else {
                XCTFail("expected .invalidData, got \(error)")
                return
            }
        }
    }

    func test_generateDelegationInputs_withFvk_rejectsBadLengths() {
        struct Case {
            let fvk: [UInt8]
            let hotkey: [UInt8]
            let fingerprint: [UInt8]
            let label: String
        }

        let validHotkey = [UInt8](repeating: 0x02, count: votingMinSeedByteCount)
        let validFvk = [UInt8](repeating: 0x03, count: votingOrchardFvkByteCount)
        let validFp = [UInt8](repeating: 0x04, count: votingSeedFingerprintByteCount)
        let cases: [Case] = [
            .init(fvk: [UInt8](repeating: 0, count: votingOrchardFvkByteCount - 1), hotkey: validHotkey, fingerprint: validFp, label: "fvk too short"),
            .init(fvk: validFvk, hotkey: [UInt8](repeating: 0, count: votingMinSeedByteCount - 1), fingerprint: validFp, label: "hotkey too short"),
            .init(fvk: validFvk, hotkey: validHotkey, fingerprint: [UInt8](repeating: 0, count: votingSeedFingerprintByteCount - 1), label: "fingerprint too short")
        ]
        for testCase in cases {
            let fvk = testCase.fvk
            let hotkey = testCase.hotkey
            let fp = testCase.fingerprint
            let label = testCase.label
            XCTAssertThrowsError(
                try VotingRustBackend.generateDelegationInputs(
                    senderFvk: fvk,
                    hotkeySeed: hotkey,
                    networkId: 1,
                    seedFingerprint: fp
                ),
                label
            ) { error in
                guard case VotingRustBackendError.invalidData = error else {
                    XCTFail("\(label): expected .invalidData, got \(error)")
                    return
                }
            }
        }
    }

    func test_extractOrchardFvk_invalidUfvk_throwsRustError() {
        XCTAssertThrowsError(
            try VotingRustBackend.extractOrchardFvk(ufvk: "not-a-ufvk", networkId: 1)
        ) { error in
            guard case VotingRustBackendError.rustError = error else {
                XCTFail("expected .rustError, got \(error)")
                return
            }
        }
    }

    func test_extractPcztSighash_emptyInput_throwsRustError() {
        XCTAssertThrowsError(
            try VotingRustBackend.extractPcztSighash(pczt: [])
        ) { error in
            guard case VotingRustBackendError.rustError = error else {
                XCTFail("expected .rustError, got \(error)")
                return
            }
        }
    }

    func test_validatePirProof_rejectsBadLengths() {
        struct Case {
            let root: [UInt8]
            let nfBounds: [UInt8]
            let path: [UInt8]
            let nullifier: [UInt8]
            let expectedRoot: [UInt8]
            let label: String
        }

        let validRoot = [UInt8](repeating: 0x01, count: votingPirRootByteCount)
        let validBounds = [UInt8](repeating: 0x02, count: votingPirNullifierBoundsByteCount)
        let validPath = [UInt8](repeating: 0x03, count: votingPirPathByteCount)
        let validNullifier = [UInt8](repeating: 0x04, count: votingPirNullifierByteCount)
        let validExpectedRoot = [UInt8](repeating: 0x05, count: votingPirRootByteCount)

        let badRoot = [UInt8](repeating: 0, count: votingPirRootByteCount - 1)
        let badBounds = [UInt8](repeating: 0, count: votingPirNullifierBoundsByteCount - 1)
        let badPath = [UInt8](repeating: 0, count: votingPirPathByteCount - 1)
        let badNullifier = [UInt8](repeating: 0, count: votingPirNullifierByteCount - 1)

        let cases: [Case] = [
            .init(
                root: badRoot,
                nfBounds: validBounds,
                path: validPath,
                nullifier: validNullifier,
                expectedRoot: validExpectedRoot,
                label: "root too short"
            ),
            .init(
                root: validRoot,
                nfBounds: badBounds,
                path: validPath,
                nullifier: validNullifier,
                expectedRoot: validExpectedRoot,
                label: "nfBounds too short"
            ),
            .init(
                root: validRoot,
                nfBounds: validBounds,
                path: badPath,
                nullifier: validNullifier,
                expectedRoot: validExpectedRoot,
                label: "path too short"
            ),
            .init(
                root: validRoot,
                nfBounds: validBounds,
                path: validPath,
                nullifier: badNullifier,
                expectedRoot: validExpectedRoot,
                label: "nullifier too short"
            ),
            .init(
                root: validRoot,
                nfBounds: validBounds,
                path: validPath,
                nullifier: validNullifier,
                expectedRoot: badRoot,
                label: "expectedRoot too short"
            )
        ]
        for testCase in cases {
            let proof = VotingPirProof(
                root: testCase.root,
                nfBounds: testCase.nfBounds,
                leafPosition: 0,
                path: testCase.path,
                nullifier: testCase.nullifier,
                expectedRoot: testCase.expectedRoot
            )
            XCTAssertThrowsError(
                try VotingRustBackend.validatePirProof(proof),
                testCase.label
            ) { error in
                guard case VotingRustBackendError.invalidData = error else {
                    XCTFail("\(testCase.label): expected .invalidData, got \(error)")
                    return
                }
            }
        }
    }

    // MARK: - Round lifecycle

    func test_initRound_andGetRoundState_roundTripPersistsParams() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        let valid = [UInt8](repeating: 0x07, count: votingFieldElementByteCount)
        try backend.initRound(
            roundId: "round-1",
            snapshotHeight: 1234,
            eaPublicKey: valid,
            ncRoot: valid,
            nullifierImtRoot: valid
        )

        let state = try backend.getRoundState(roundId: "round-1")
        XCTAssertEqual(state.roundId, "round-1")
        XCTAssertEqual(state.snapshotHeight, 1234)
        XCTAssertEqual(state.phase, .initialized)
        XCTAssertNil(state.hotkeyAddress)
        XCTAssertNil(state.delegatedWeight)
        XCTAssertFalse(state.proofGenerated)
    }

    func test_initRound_rejectsInvalidParamLengths() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        let valid = [UInt8](repeating: 0x07, count: votingFieldElementByteCount)
        let short = [UInt8](repeating: 0x07, count: votingFieldElementByteCount - 1)

        XCTAssertThrowsError(
            try backend.initRound(
                roundId: "bad",
                snapshotHeight: 1,
                eaPublicKey: short,
                ncRoot: valid,
                nullifierImtRoot: valid
            )
        ) { error in
            guard case VotingRustBackendError.rustError = error else {
                XCTFail("expected .rustError, got \(error)")
                return
            }
        }
    }

    func test_listRounds_returnsEmpty_whenNoRoundsInitialized() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        let rounds = try backend.listRounds()
        XCTAssertTrue(rounds.isEmpty)
    }

    func test_listRounds_returnsInitializedRound() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        let valid = [UInt8](repeating: 0x07, count: votingFieldElementByteCount)
        try backend.initRound(
            roundId: "round-1",
            snapshotHeight: 42,
            eaPublicKey: valid,
            ncRoot: valid,
            nullifierImtRoot: valid
        )
        try backend.initRound(
            roundId: "round-2",
            snapshotHeight: 43,
            eaPublicKey: valid,
            ncRoot: valid,
            nullifierImtRoot: valid
        )

        let rounds = try backend.listRounds()
        XCTAssertEqual(rounds.count, 2)
        XCTAssertEqual(Set(rounds.map(\.roundId)), ["round-1", "round-2"])
    }

    func test_getVotes_returnsEmpty_forFreshRound() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        let valid = [UInt8](repeating: 0x07, count: votingFieldElementByteCount)
        try backend.initRound(
            roundId: "round",
            snapshotHeight: 1,
            eaPublicKey: valid,
            ncRoot: valid,
            nullifierImtRoot: valid
        )

        XCTAssertTrue(try backend.getVotes(roundId: "round").isEmpty)
    }

    // MARK: - Recovery state

    func test_delegationTxHash_roundTrips() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        try createRoundWithBundle(backend, roundId: roundTripRoundId)

        XCTAssertNil(
            try backend.getDelegationTxHash(
                roundId: roundTripRoundId,
                bundleIndex: roundTripBundleIndex
            )
        )

        try backend.storeDelegationTxHash(
            roundId: roundTripRoundId,
            bundleIndex: roundTripBundleIndex,
            txHash: roundTripDelegationTxHash
        )

        XCTAssertEqual(
            try backend.getDelegationTxHash(
                roundId: roundTripRoundId,
                bundleIndex: roundTripBundleIndex
            ),
            roundTripDelegationTxHash
        )
    }

    func test_storeDelegationTxHash_throwsRustError_whenBundleMissing() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        XCTAssertThrowsError(
            try backend.storeDelegationTxHash(roundId: "missing", bundleIndex: 0, txHash: "abc")
        ) { error in
            guard case VotingRustBackendError.rustError = error else {
                XCTFail("expected .rustError, got \(error)")
                return
            }
        }
    }

    func test_voteTxHash_roundTrips() throws {
        let backend = try makeReadyBackend(walletId: roundTripWalletId)
        defer { backend.close() }

        try createRoundWithBundle(backend, roundId: roundTripRoundId)
        try insertVoteRow(
            roundId: roundTripRoundId,
            walletId: roundTripWalletId,
            bundleIndex: roundTripBundleIndex,
            proposalId: roundTripProposalId
        )

        XCTAssertNil(
            try backend.getVoteTxHash(
                roundId: roundTripRoundId,
                bundleIndex: roundTripBundleIndex,
                proposalId: roundTripProposalId
            )
        )

        try backend.storeVoteTxHash(
            roundId: roundTripRoundId,
            bundleIndex: roundTripBundleIndex,
            proposalId: roundTripProposalId,
            txHash: roundTripVoteTxHash
        )

        XCTAssertEqual(
            try backend.getVoteTxHash(
                roundId: roundTripRoundId,
                bundleIndex: roundTripBundleIndex,
                proposalId: roundTripProposalId
            ),
            roundTripVoteTxHash
        )
    }

    func test_commitmentBundle_roundTrips() throws {
        let backend = try makeReadyBackend(walletId: roundTripWalletId)
        defer { backend.close() }

        try createRoundWithBundle(backend, roundId: roundTripRoundId)
        try insertVoteRow(
            roundId: roundTripRoundId,
            walletId: roundTripWalletId,
            bundleIndex: roundTripBundleIndex,
            proposalId: roundTripProposalId
        )

        XCTAssertNil(
            try backend.getCommitmentBundle(
                roundId: roundTripRoundId,
                bundleIndex: roundTripBundleIndex,
                proposalId: roundTripProposalId
            )
        )

        try backend.storeCommitmentBundle(
            roundId: roundTripRoundId,
            bundleIndex: roundTripBundleIndex,
            proposalId: roundTripProposalId,
            bundleJson: roundTripCommitmentBundleJson,
            voteCommitmentTreePosition: roundTripVoteCommitmentTreePosition
        )

        let stored = try XCTUnwrap(
            backend.getCommitmentBundle(
                roundId: roundTripRoundId,
                bundleIndex: roundTripBundleIndex,
                proposalId: roundTripProposalId
            )
        )
        XCTAssertEqual(stored.bundleJson, roundTripCommitmentBundleJson)
        XCTAssertEqual(stored.voteCommitmentTreePosition, roundTripVoteCommitmentTreePosition)
    }

    func test_keystoneSignature_roundTrips() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        try createRoundWithBundle(backend, roundId: roundTripRoundId)

        try backend.storeKeystoneSignature(
            roundId: roundTripRoundId,
            bundleIndex: roundTripBundleIndex,
            sig: roundTripKeystoneSignature,
            sighash: roundTripPcztSighash,
            randomizedKey: roundTripRandomizedKey
        )

        XCTAssertEqual(
            try backend.getKeystoneSignatures(roundId: roundTripRoundId),
            [
                VotingKeystoneSignatureRecord(
                    bundleIndex: roundTripBundleIndex,
                    sig: roundTripKeystoneSignature,
                    sighash: roundTripPcztSighash,
                    randomizedKey: roundTripRandomizedKey
                )
            ]
        )
    }

    func test_storeKeystoneSignature_rejectsBadLengths() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        let valid = [UInt8](repeating: 0x07, count: votingFieldElementByteCount)
        try backend.initRound(
            roundId: "round",
            snapshotHeight: 1,
            eaPublicKey: valid,
            ncRoot: valid,
            nullifierImtRoot: valid
        )

        struct Case {
            let sig: [UInt8]
            let sighash: [UInt8]
            let randomizedKey: [UInt8]
            let label: String
        }

        let validSig = [UInt8](repeating: 0x01, count: votingKeystoneSignatureByteCount)
        let validSighash = [UInt8](repeating: 0x02, count: votingPcztSighashByteCount)
        let validRk = [UInt8](repeating: 0x03, count: votingRandomizedKeyByteCount)

        let cases: [Case] = [
            .init(sig: [UInt8](repeating: 0, count: votingKeystoneSignatureByteCount - 1), sighash: validSighash, randomizedKey: validRk, label: "sig too short"),
            .init(sig: validSig, sighash: [UInt8](repeating: 0, count: votingPcztSighashByteCount - 1), randomizedKey: validRk, label: "sighash too short"),
            .init(sig: validSig, sighash: validSighash, randomizedKey: [UInt8](repeating: 0, count: votingRandomizedKeyByteCount - 1), label: "rk too short")
        ]
        for testCase in cases {
            XCTAssertThrowsError(
                try backend.storeKeystoneSignature(
                    roundId: "round",
                    bundleIndex: 0,
                    sig: testCase.sig,
                    sighash: testCase.sighash,
                    randomizedKey: testCase.randomizedKey
                ),
                testCase.label
            ) { error in
                guard case VotingRustBackendError.invalidData = error else {
                    XCTFail("\(testCase.label): expected .invalidData, got \(error)")
                    return
                }
            }
        }
    }

    func test_getKeystoneSignatures_returnsEmpty_forFreshRound() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        XCTAssertTrue(try backend.getKeystoneSignatures(roundId: "missing").isEmpty)
    }

    func test_clearRecoveryState_isNoop_onMissingRound() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        XCTAssertNoThrow(try backend.clearRecoveryState(roundId: "missing"))
    }

    // MARK: - Share delegation tracking

    func test_shareDelegationLifecycle_roundTripsHexNullifier() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        try createRoundWithBundle(backend, roundId: roundTripRoundId)

        try backend.recordShareDelegation(
            roundId: roundTripRoundId,
            bundleIndex: roundTripBundleIndex,
            proposalId: roundTripProposalId,
            shareIndex: roundTripShareIndex0,
            sentToURLs: [roundTripHelperAURL],
            nullifier: roundTripShareNullifier,
            submitAt: roundTripFirstSubmitAt
        )
        try backend.recordShareDelegation(
            roundId: roundTripRoundId,
            bundleIndex: roundTripBundleIndex,
            proposalId: roundTripProposalId,
            shareIndex: roundTripShareIndex1,
            sentToURLs: [roundTripHelperBURL],
            nullifier: roundTripShareNullifier,
            submitAt: roundTripSecondSubmitAt
        )

        let all = try backend.getShareDelegations(roundId: roundTripRoundId)
        XCTAssertEqual(all.count, 2)

        let share0 = try XCTUnwrap(all.first { $0.shareIndex == roundTripShareIndex0 })
        XCTAssertEqual(share0.roundId, roundTripRoundId)
        XCTAssertEqual(share0.bundleIndex, roundTripBundleIndex)
        XCTAssertEqual(share0.proposalId, roundTripProposalId)
        XCTAssertEqual(share0.sentToURLs, [roundTripHelperAURL])
        XCTAssertEqual(share0.nullifier, roundTripShareNullifier)
        XCTAssertFalse(share0.confirmed)
        XCTAssertEqual(share0.submitAt, roundTripFirstSubmitAt)

        XCTAssertEqual(try backend.getUnconfirmedDelegations(roundId: roundTripRoundId).count, 2)

        try backend.markShareConfirmed(
            roundId: roundTripRoundId,
            bundleIndex: roundTripBundleIndex,
            proposalId: roundTripProposalId,
            shareIndex: roundTripShareIndex0
        )

        let confirmedShare = try XCTUnwrap(
            backend.getShareDelegations(roundId: roundTripRoundId)
                .first { $0.shareIndex == roundTripShareIndex0 }
        )
        XCTAssertTrue(confirmedShare.confirmed)

        let unconfirmed = try backend.getUnconfirmedDelegations(roundId: roundTripRoundId)
        XCTAssertEqual(unconfirmed.count, 1)
        XCTAssertEqual(unconfirmed[0].shareIndex, roundTripShareIndex1)
    }

    func test_recordShareDelegation_rejectsInvalidNullifierLength() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        let bad = String(repeating: "aa", count: votingShareNullifierByteCount - 1)
        XCTAssertThrowsError(
            try backend.recordShareDelegation(
                roundId: "round",
                bundleIndex: 0,
                proposalId: 0,
                shareIndex: 0,
                sentToURLs: ["https://helper.example"],
                nullifier: bad,
                submitAt: 0
            )
        ) { error in
            guard case VotingRustBackendError.invalidData = error else {
                XCTFail("expected .invalidData, got \(error)")
                return
            }
        }
    }

    func test_getShareDelegations_returnsEmpty_forUnknownRound() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        XCTAssertTrue(try backend.getShareDelegations(roundId: "missing").isEmpty)
        XCTAssertTrue(try backend.getUnconfirmedDelegations(roundId: "missing").isEmpty)
    }

    // MARK: - Delegation workflow

    func test_setupBundles_returnsZero_forEmptyNotes() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        let valid = [UInt8](repeating: 0x07, count: votingFieldElementByteCount)
        try backend.initRound(
            roundId: "round",
            snapshotHeight: 1,
            eaPublicKey: valid,
            ncRoot: valid,
            nullifierImtRoot: valid
        )

        let result = try backend.setupBundles(roundId: "round", notes: [])
        XCTAssertEqual(result.bundleCount, 0)
        XCTAssertEqual(result.eligibleWeight, 0)
        XCTAssertEqual(try backend.getBundleCount(roundId: "round"), 0)
    }

    func test_buildPczt_rejectsInvalidSeedFingerprintLength() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        let params = VotingBuildPcztParams(
            roundId: "round",
            bundleIndex: 0,
            notes: [],
            fvk: [UInt8](repeating: 0, count: votingOrchardFvkByteCount),
            hotkeyRawAddress: [UInt8](repeating: 0, count: votingHotkeyRawAddressByteCount),
            consensusBranchId: 0,
            coinType: 0,
            seedFingerprint: [UInt8](repeating: 0, count: votingSeedFingerprintByteCount - 1),
            accountIndex: 0,
            roundName: "Round",
            addressIndex: 0
        )
        XCTAssertThrowsError(try backend.buildPczt(params)) { error in
            guard case VotingRustBackendError.invalidData = error else {
                XCTFail("expected .invalidData, got \(error)")
                return
            }
        }
    }

    func test_getDelegationSubmissionWithKeystoneSig_rejectsBadLengths() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        XCTAssertThrowsError(
            try backend.getDelegationSubmission(
                roundId: "round",
                bundleIndex: 0,
                keystoneSig: [UInt8](repeating: 0, count: votingKeystoneSignatureByteCount - 1),
                sighash: [UInt8](repeating: 0, count: votingPcztSighashByteCount)
            )
        ) { error in
            guard case VotingRustBackendError.invalidData = error else {
                XCTFail("expected .invalidData, got \(error)")
                return
            }
        }
        XCTAssertThrowsError(
            try backend.getDelegationSubmission(
                roundId: "round",
                bundleIndex: 0,
                keystoneSig: [UInt8](repeating: 0, count: votingKeystoneSignatureByteCount),
                sighash: [UInt8](repeating: 0, count: votingPcztSighashByteCount - 1)
            )
        ) { error in
            guard case VotingRustBackendError.invalidData = error else {
                XCTFail("expected .invalidData, got \(error)")
                return
            }
        }
    }

    // MARK: - Open database gating

    func test_initRound_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        let valid = [UInt8](repeating: 0, count: votingFieldElementByteCount)
        XCTAssertThrowsError(
            try backend.initRound(
                roundId: "r",
                snapshotHeight: 0,
                eaPublicKey: valid,
                ncRoot: valid,
                nullifierImtRoot: valid
            )
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_syncVoteTree_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(
            try backend.syncVoteTree(roundId: "round1", nodeUrl: "http://localhost")
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_listRounds_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(try backend.listRounds()) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_getRoundState_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(try backend.getRoundState(roundId: "r")) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_setupBundles_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(try backend.setupBundles(roundId: "r", notes: [])) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_storeVanPosition_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(
            try backend.storeVanPosition(roundId: "r", bundleIndex: 0, position: 0)
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_precomputeDelegationPir_beforeOpen_throwsDatabaseNotOpen() async {
        let backend = VotingRustBackend()
        do {
            _ = try await backend.precomputeDelegationPir(
                roundId: "round1",
                bundleIndex: 0,
                notes: [],
                pirEndpoints: ["https://stub"],
                expectedSnapshotHeight: 0,
                networkId: 1,
                pirResolver: PirSnapshotResolver(probe: FailingProbe())
            )
            XCTFail("expected .databaseNotOpen")
        } catch let error as VotingRustBackendError {
            guard case .databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func test_storeKeystoneSignature_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(
            try backend.storeKeystoneSignature(
                roundId: "r",
                bundleIndex: 0,
                sig: [UInt8](repeating: 0, count: votingKeystoneSignatureByteCount),
                sighash: [UInt8](repeating: 0, count: votingPcztSighashByteCount),
                randomizedKey: [UInt8](repeating: 0, count: votingRandomizedKeyByteCount)
            )
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_generateNoteWitnesses_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(
            try backend.generateNoteWitnesses(
                roundId: "round1",
                bundleIndex: 0,
                walletDbPath: "/tmp/wallet.sqlite",
                notes: [],
                networkId: 1
            )
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_buildAndProveDelegation_beforeOpen_throwsDatabaseNotOpen() async {
        let backend = VotingRustBackend()
        do {
            _ = try await backend.buildAndProveDelegation(
                roundId: "r",
                bundleIndex: 0,
                notes: [],
                hotkeyRawAddress: [UInt8](repeating: 0, count: votingHotkeyRawAddressByteCount),
                pirEndpoints: ["https://stub"],
                expectedSnapshotHeight: 0,
                networkId: 1,
                pirResolver: PirSnapshotResolver(probe: FailingProbe())
            )
            XCTFail("expected .databaseNotOpen")
        } catch let error as VotingRustBackendError {
            guard case .databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func test_generateNoteWitnesses_afterOpen_forwardsNetworkIdAndPropagatesRustError() throws {
        let backend = try makeOpenBackend()
        defer { backend.close() }

        XCTAssertThrowsError(
            try backend.generateNoteWitnesses(
                roundId: "round1",
                bundleIndex: 0,
                walletDbPath: "/tmp/nonexistent-wallet.sqlite",
                notes: [],
                networkId: 99
            )
        ) { error in
            guard case VotingRustBackendError.rustError(let message) = error else {
                XCTFail("expected .rustError, got \(error)")
                return
            }
            XCTAssertTrue(message.contains("Invalid network type"), "unexpected message: \(message)")
        }
    }

    func test_encryptShares_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(try backend.encryptShares(roundId: "round1", shares: [1])) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_encryptShares_afterOpen_propagatesRustError() throws {
        let backend = try makeOpenBackend()
        defer { backend.close() }

        XCTAssertThrowsError(try backend.encryptShares(roundId: "missing-round", shares: [1, 2])) { error in
            guard case VotingRustBackendError.rustError(let message) = error else {
                XCTFail("expected .rustError, got \(error)")
                return
            }
            XCTAssertTrue(message.contains("encrypt_shares failed"), "unexpected message: \(message)")
        }
    }

    func test_buildVoteCommitment_beforeOpen_throwsDatabaseNotOpen() async {
        let backend = VotingRustBackend()

        do {
            _ = try await backend.buildVoteCommitment(
                roundId: "round1",
                bundleIndex: 0,
                hotkeySeed: [UInt8](repeating: 1, count: votingMinSeedByteCount),
                networkId: 1,
                proposalId: 0,
                choice: 0,
                numOptions: 2,
                vanWitness: VotingVanWitness(
                    authPath: [[UInt8](repeating: 1, count: votingFieldElementByteCount)],
                    position: 0,
                    anchorHeight: 0
                ),
                singleShare: false
            )
            XCTFail("expected .databaseNotOpen")
        } catch let error as VotingRustBackendError {
            guard case .databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func test_buildVoteCommitment_afterOpen_rejectsShortSeedAndDoesNotReportProgress() async throws {
        let backend = try makeOpenBackend()
        defer { backend.close() }
        let progressReported = expectation(description: "progress must not be reported before seed validation")
        progressReported.isInverted = true

        do {
            _ = try await backend.buildVoteCommitment(
                roundId: "round1",
                bundleIndex: 0,
                hotkeySeed: [UInt8](repeating: 1, count: votingMinSeedByteCount - 1),
                networkId: 1,
                proposalId: 0,
                choice: 0,
                numOptions: 2,
                vanWitness: VotingVanWitness(
                    authPath: [],
                    position: 0,
                    anchorHeight: 0
                ),
                singleShare: false,
                progress: { _ in progressReported.fulfill() }
            )
            XCTFail("expected .rustError")
        } catch let error as VotingRustBackendError {
            guard case .rustError(let message) = error else {
                XCTFail("expected .rustError, got \(error)")
                return
            }
            XCTAssertTrue(message.contains("hotkey_seed must be at least"), "unexpected message: \(message)")
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        await fulfillment(of: [progressReported], timeout: 0.1)
    }

    func test_buildSharePayloads_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(
            try backend.buildSharePayloads(
                commitment: makeVoteCommitmentBundle(),
                voteDecision: 0,
                numOptions: 2,
                voteCommitmentTreePosition: 0,
                singleShare: false
            )
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_buildSharePayloads_afterOpen_rejectsCommitmentWithoutEncryptedShares() throws {
        let backend = try makeOpenBackend()
        defer { backend.close() }

        XCTAssertThrowsError(
            try backend.buildSharePayloads(
                commitment: makeVoteCommitmentBundle(encShares: []),
                voteDecision: 0,
                numOptions: 2,
                voteCommitmentTreePosition: 0,
                singleShare: false
            )
        ) { error in
            guard case VotingRustBackendError.rustError(let message) = error else {
                XCTFail("expected .rustError, got \(error)")
                return
            }
            XCTAssertTrue(message.contains("enc_shares must not be empty"), "unexpected message: \(message)")
        }
    }

    func test_voteSubmissionHelpers_afterOpen_buildPayloadsAndSignWithSyntheticCommitment() throws {
        let backend = try makeOpenBackend()
        defer { backend.close() }
        let commitment = makeVoteCommitmentBundle(proposalId: 7)

        let payloads = try backend.buildSharePayloads(
            commitment: commitment,
            voteDecision: 1,
            numOptions: 2,
            voteCommitmentTreePosition: 42,
            singleShare: false
        )

        XCTAssertEqual(payloads.count, commitment.encShares.count)
        XCTAssertEqual(payloads[0].sharesHash, commitment.sharesHash)
        XCTAssertEqual(payloads[0].proposalId, commitment.proposalId)
        XCTAssertEqual(payloads[0].voteDecision, 1)
        XCTAssertEqual(payloads[0].treePosition, 42)
        XCTAssertEqual(payloads[0].encShare.shareIndex, commitment.encShares[0].shareIndex)
        XCTAssertEqual(payloads[0].allEncShares.count, commitment.encShares.count)
        XCTAssertEqual(payloads[0].shareComms, commitment.shareComms)
        XCTAssertEqual(payloads[0].primaryBlind, commitment.shareBlinds[0])

        let nullifier = try VotingRustBackend.computeShareNullifier(
            voteCommitment: commitment.voteCommitment,
            shareIndex: payloads[0].encShare.shareIndex,
            primaryBlind: payloads[0].primaryBlind
        )
        XCTAssertEqual(nullifier.count, votingShareNullifierHexCharacterCount)

        let signature = try VotingRustBackend.signCastVote(
            hotkeySeed: [UInt8](repeating: 1, count: votingMinSeedByteCount),
            networkId: 1,
            commitment: commitment
        )
        XCTAssertFalse(signature.voteAuthSig.isEmpty)
    }

    func test_markVoteSubmitted_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(
            try backend.markVoteSubmitted(roundId: "round1", bundleIndex: 0, proposalId: 0)
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error)")
                return
            }
        }
    }

    func test_markVoteSubmitted_afterOpen_missingVote_throwsRustError() throws {
        let backend = try makeOpenBackend()
        defer { backend.close() }

        XCTAssertThrowsError(
            try backend.markVoteSubmitted(roundId: "missing-round", bundleIndex: 0, proposalId: 0)
        ) { error in
            assertNoVoteFound(error)
        }
    }

    func test_signCastVote_invalidCommitment_throwsRustError() {
        XCTAssertThrowsError(
            try VotingRustBackend.signCastVote(
                hotkeySeed: [UInt8](repeating: 1, count: votingMinSeedByteCount),
                networkId: 1,
                commitment: makeVoteCommitmentBundle(voteRoundId: "too-short")
            )
        ) { error in
            guard case VotingRustBackendError.rustError = error else {
                XCTFail("expected .rustError, got \(error)")
                return
            }
        }
    }

    func test_signCastVote_rejectsShortSeed() {
        XCTAssertThrowsError(
            try VotingRustBackend.signCastVote(
                hotkeySeed: [UInt8](repeating: 1, count: votingMinSeedByteCount - 1),
                networkId: 1,
                commitment: makeVoteCommitmentBundle()
            )
        ) { error in
            guard case VotingRustBackendError.rustError(let message) = error else {
                XCTFail("expected .rustError, got \(error)")
                return
            }
            XCTAssertTrue(message.contains("hotkey_seed must be at least"), "unexpected message: \(message)")
        }
    }

    func test_signCastVote_rejectsWrongSizedCanonicalFields() {
        let short = [UInt8](repeating: 1, count: votingFieldElementByteCount - 1)

        let cases: [(String, VotingVoteCommitmentBundle, String)] = [
            (
                "rVpkBytes",
                makeVoteCommitmentBundle(rVpkBytes: short),
                "r_vpk_bytes must be 32 bytes"
            ),
            (
                "vanNullifier",
                makeVoteCommitmentBundle(vanNullifier: short),
                "van_nullifier must be 32 bytes"
            ),
            (
                "voteAuthorityNoteNew",
                makeVoteCommitmentBundle(voteAuthorityNoteNew: short),
                "vote_authority_note_new must be 32 bytes"
            ),
            (
                "voteCommitment",
                makeVoteCommitmentBundle(voteCommitment: short),
                "vote_commitment must be 32 bytes"
            ),
            (
                "alphaV",
                makeVoteCommitmentBundle(alphaV: short),
                "alpha_v must be 32 bytes"
            )
        ]

        for (label, commitment, expectedMessage) in cases {
            XCTAssertThrowsError(
                try VotingRustBackend.signCastVote(
                    hotkeySeed: [UInt8](repeating: 1, count: votingMinSeedByteCount),
                    networkId: 1,
                    commitment: commitment
                ),
                label
            ) { error in
                guard case VotingRustBackendError.rustError(let message) = error else {
                    XCTFail("\(label): expected .rustError, got \(error)")
                    return
                }
                XCTAssertTrue(
                    message.contains(expectedMessage),
                    "\(label): unexpected message: \(message)"
                )
            }
        }
    }

    func test_signCastVote_validFixture_returnsSignature() throws {
        let signature = try VotingRustBackend.signCastVote(
            hotkeySeed: [UInt8](repeating: 1, count: votingMinSeedByteCount),
            networkId: 1,
            commitment: makeVoteCommitmentBundle()
        )

        XCTAssertFalse(signature.voteAuthSig.isEmpty)
    }

    // MARK: - setWalletId

    func test_setWalletId_succeedsAfterOpen() throws {
        let backend = VotingRustBackend()
        try backend.open(path: makeTempDbPath())
        defer { backend.close() }

        XCTAssertNoThrow(try backend.setWalletId("wallet-id-1"))
        // Idempotent: setting again must succeed too.
        XCTAssertNoThrow(try backend.setWalletId("wallet-id-2"))
    }

    // MARK: - resetTreeClient

    func test_resetTreeClient_succeedsAfterOpen_withEmptyRoundId() throws {
        let backend = VotingRustBackend()
        try backend.open(path: makeTempDbPath())
        defer { backend.close() }

        // Empty round ID resets all in-memory tree clients; safe to call on a
        // fresh handle that has no clients yet.
        XCTAssertNoThrow(try backend.resetTreeClient())
    }

    // MARK: - precomputeDelegationPir resolver gating

    func test_precomputeDelegationPir_emptyEndpoints_throwsResolverError() async throws {
        let backend = VotingRustBackend()
        try backend.open(path: makeTempDbPath())
        defer { backend.close() }

        do {
            _ = try await backend.precomputeDelegationPir(
                roundId: "round1",
                bundleIndex: 0,
                notes: [],
                pirEndpoints: [],
                expectedSnapshotHeight: 0,
                networkId: 1
            )
            XCTFail("expected PirSnapshotResolverError.noEndpointsConfigured")
        } catch PirSnapshotResolverError.noEndpointsConfigured {
            // expected
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    // MARK: - Helpers

    private func makeTempDbPath() -> String {
        let unique = ProcessInfo.processInfo.globallyUniqueString
        let path = "\(NSTemporaryDirectory())VotingRustBackendTests-\(unique).sqlite"
        dbPath = path
        return path
    }

    private func makeReadyBackend(walletId: String = roundTripWalletId) throws -> VotingRustBackend {
        let backend = VotingRustBackend()
        try backend.open(path: makeTempDbPath())
        try backend.setWalletId(walletId)
        return backend
    }

    private func createRoundWithBundle(
        _ backend: VotingRustBackend,
        roundId: String
    ) throws {
        try backend.initRound(
            roundId: roundId,
            snapshotHeight: roundTripSnapshotHeight,
            eaPublicKey: roundTripRoundParameter,
            ncRoot: roundTripRoundParameter,
            nullifierImtRoot: roundTripRoundParameter
        )

        let result = try backend.setupBundles(
            roundId: roundId,
            notes: [makeEligibleNote()]
        )
        XCTAssertEqual(result.bundleCount, 1)
    }

    private func makeEligibleNote() -> VotingNoteInfo {
        VotingNoteInfo(
            commitment: [UInt8](repeating: 0x01, count: votingFieldElementByteCount),
            nullifier: [UInt8](repeating: 0x02, count: votingFieldElementByteCount),
            value: roundTripEligibleNoteValue,
            position: 0,
            diversifier: [UInt8](repeating: 0, count: roundTripDiversifierByteCount),
            rho: [UInt8](repeating: 0, count: votingFieldElementByteCount),
            rseed: [UInt8](repeating: 0, count: votingFieldElementByteCount),
            scope: 0,
            ufvkStr: ""
        )
    }

    // TODO: Consider replacing this raw SQLite insertion with a proper Rust-side test helper
    // so we don't reach into the Rust-managed votes table directly.
    // https://github.com/zcash/zcash-swift-wallet-sdk/pull/1724#discussion_r3222196789
    private func insertVoteRow(
        roundId: String,
        walletId: String,
        bundleIndex: UInt32,
        proposalId: UInt32
    ) throws {
        let path = try XCTUnwrap(dbPath)
        var db: OpaquePointer?
        try requireSQLite(
            sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, nil),
            db,
            message: "open voting database"
        )
        defer { sqlite3_close(db) }

        let sql = """
        INSERT INTO votes (
            round_id,
            wallet_id,
            bundle_index,
            proposal_id,
            choice,
            commitment,
            created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        """
        var statement: OpaquePointer?
        try requireSQLite(
            sqlite3_prepare_v2(db, sql, -1, &statement, nil),
            db,
            message: "prepare vote insert"
        )
        defer { sqlite3_finalize(statement) }

        let sqliteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        let commitment = roundTripVoteCommitment

        try roundId.withCString { roundIdPointer in
            try requireSQLite(
                sqlite3_bind_text(statement, 1, roundIdPointer, -1, sqliteTransient),
                db,
                message: "bind round_id"
            )
        }
        try walletId.withCString { walletIdPointer in
            try requireSQLite(
                sqlite3_bind_text(statement, 2, walletIdPointer, -1, sqliteTransient),
                db,
                message: "bind wallet_id"
            )
        }
        try requireSQLite(
            sqlite3_bind_int64(statement, 3, sqlite3_int64(bundleIndex)),
            db,
            message: "bind bundle_index"
        )
        try requireSQLite(
            sqlite3_bind_int64(statement, 4, sqlite3_int64(proposalId)),
            db,
            message: "bind proposal_id"
        )
        try requireSQLite(
            sqlite3_bind_int64(statement, 5, 0),
            db,
            message: "bind choice"
        )
        try commitment.withUnsafeBufferPointer { buffer in
            try requireSQLite(
                sqlite3_bind_blob(statement, 6, buffer.baseAddress, Int32(buffer.count), sqliteTransient),
                db,
                message: "bind commitment"
            )
        }
        try requireSQLite(
            sqlite3_bind_int64(statement, 7, sqlite3_int64(roundTripCreatedAt)),
            db,
            message: "bind created_at"
        )

        try requireSQLite(
            sqlite3_step(statement),
            db,
            expected: roundTripSQLiteDoneCode,
            message: "insert vote row"
        )
    }

    private func requireSQLite(
        _ code: Int32,
        _ db: OpaquePointer?,
        expected: Int32 = roundTripSQLiteSuccessCode,
        message: String
    ) throws {
        guard code == expected else {
            let details = db.map { String(cString: sqlite3_errmsg($0)) } ?? "unknown SQLite error"
            throw NSError(
                domain: "VotingRustBackendTests.SQLite",
                code: Int(code),
                userInfo: [NSLocalizedDescriptionKey: "\(message): \(details)"]
            )
        }
    }

    private func makeOpenBackend() throws -> VotingRustBackend {
        let backend = VotingRustBackend()
        try backend.open(path: makeTempDbPath())
        try backend.setWalletId("wallet")
        return backend
    }

    private func assertNoVoteFound(
        _ error: Error,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard case VotingRustBackendError.rustError(let message) = error else {
            XCTFail("expected .rustError, got \(error)", file: file, line: line)
            return
        }
        XCTAssertTrue(message.contains("no vote found"), "unexpected message: \(message)", file: file, line: line)
    }

    private func makeVoteCommitmentBundle(
        voteRoundId: String = String(repeating: "a", count: votingVoteRoundIdHexCharacterCount),
        vanNullifier: [UInt8] = [UInt8](repeating: 1, count: votingFieldElementByteCount),
        voteAuthorityNoteNew: [UInt8] = [UInt8](repeating: 2, count: votingFieldElementByteCount),
        voteCommitment: [UInt8] = [UInt8](repeating: 3, count: votingFieldElementByteCount),
        proposalId: UInt32 = 0,
        encShares: [VotingWireEncryptedShare] = [
            VotingWireEncryptedShare(
                ciphertext1: [UInt8](repeating: 5, count: votingFieldElementByteCount),
                ciphertext2: [UInt8](repeating: 6, count: votingFieldElementByteCount),
                shareIndex: 0
            )
        ],
        rVpkBytes: [UInt8] = [UInt8](repeating: 10, count: votingFieldElementByteCount),
        alphaV: [UInt8] = [UInt8](repeating: 11, count: votingFieldElementByteCount)
    ) -> VotingVoteCommitmentBundle {
        VotingVoteCommitmentBundle(
            vanNullifier: vanNullifier,
            voteAuthorityNoteNew: voteAuthorityNoteNew,
            voteCommitment: voteCommitment,
            proposalId: proposalId,
            proof: [4],
            encShares: encShares,
            anchorHeight: 1,
            voteRoundId: voteRoundId,
            sharesHash: [7],
            shareBlinds: [[UInt8](repeating: 8, count: votingFieldElementByteCount)],
            shareComms: [[UInt8](repeating: 9, count: votingFieldElementByteCount)],
            rVpkBytes: rVpkBytes,
            alphaV: alphaV
        )
    }
}

// MARK: - Test doubles

/// Probe stub that reports every endpoint as matching, so we can drive the
/// resolver into the FFI call without contacting a real server.
private struct AlwaysMatchingProbe: PirSnapshotProbing {
    func probe(url: String, expectedSnapshotHeight: BlockHeight) async -> PirSnapshotProbeOutcome {
        PirSnapshotProbeOutcome(url: url, status: .matching(height: expectedSnapshotHeight))
    }
}

/// Probe stub used where endpoint probing must not happen.
private struct FailingProbe: PirSnapshotProbing {
    func probe(url: String, expectedSnapshotHeight: BlockHeight) async -> PirSnapshotProbeOutcome {
        XCTFail("closed voting backend should fail before probing PIR endpoints")
        return PirSnapshotProbeOutcome(url: url, status: .matching(height: expectedSnapshotHeight))
    }
}
