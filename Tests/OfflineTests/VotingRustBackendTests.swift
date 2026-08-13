//
//  VotingRustBackendTests.swift
//  ZcashLightClientKitTests
//

import XCTest
import SQLite3
@testable import ZcashLightClientKit

// Shared fixtures for tests that round-trip persisted voting recovery state
// through the Rust voting database.

/// Builds a round identifier that satisfies the Rust round-parameter validation,
/// which requires 64 lowercase hex characters encoding a canonical Pallas field
/// element. `tag` occupies the low byte so each caller gets a distinct round
/// while staying canonical.
private func hexRoundId(_ tag: UInt8) -> String {
    String(format: "%02x", tag) + String(repeating: "00", count: 31)
}

private let roundTripWalletId = "test-wallet"
private let roundTripRoundId = hexRoundId(0x01)
/// A well-formed round identifier that is never initialized, for tests that
/// exercise lookups against a round the database does not know about.
private let missingRoundId = hexRoundId(0xfe)
private let roundTripNetworkId: UInt32 = 1
private let roundTripBundleIndex: UInt32 = 0
private let roundTripProposalId: UInt32 = 1
private let roundTripShareIndex: UInt32 = 0
private let roundTripSnapshotHeight: UInt64 = 1
private let roundTripVoteCommitmentTreePosition: UInt64 = 42
private let roundTripDelegationTxHash = "delegation-tx-hash"
private let roundTripVoteTxHash = "vote-tx-hash"
private let roundTripHelperURL = "https://helper-a.example"
private let roundTripSubmitAt: UInt64 = 1000
private let roundTripCreatedAt: Int64 = 1_000
private let roundTripDiversifierByteCount = 11
private let roundTripEligibleNoteValue: UInt64 = 13_000_000
private let roundTripSQLiteSuccessCode = SQLITE_OK
private let roundTripSQLiteDoneCode = SQLITE_DONE
private let roundTripRoundParameter = [UInt8](repeating: 0x07, count: votingFieldElementByteCount)
private let roundTripSpendAuthSignature = [UInt8](repeating: 0x01, count: votingSpendAuthSignatureByteCount)
private let roundTripPcztSighash = [UInt8](repeating: 0x02, count: votingPcztSighashByteCount)
private let roundTripRandomizedKey = [UInt8](repeating: 0x03, count: votingRandomizedKeyByteCount)
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
        XCTAssertEqual(nullifier.count, votingShareNullifierHexCharacterCount)
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
                    XCTFail("\(label): expected .invalidData, got \(error.localizedDescription)")
                    return
                }
            }
        }
    }

    // MARK: - Database lifecycle

    func test_open_succeedsAndCreatesFile() throws {
        let backend = VotingRustBackend()
        let path = makeTempDbPath()

        try backend.open(path: path, networkId: roundTripNetworkId)
        backend.close()

        XCTAssertTrue(FileManager.default.fileExists(atPath: path))
    }

    func test_open_secondTime_throwsDatabaseAlreadyOpen() throws {
        let backend = VotingRustBackend()
        let path = makeTempDbPath()

        try backend.open(path: path, networkId: roundTripNetworkId)
        defer { backend.close() }

        XCTAssertThrowsError(try backend.open(path: path, networkId: roundTripNetworkId)) { error in
            guard case VotingRustBackendError.databaseAlreadyOpen = error else {
                XCTFail("expected .databaseAlreadyOpen, got \(error.localizedDescription)")
                return
            }
        }
    }

    func test_open_rejectsUnknownNetworkId() throws {
        // The network is fixed when the handle is opened, so an unknown id is
        // rejected once, here, rather than by each database-bound call.
        let backend = VotingRustBackend()

        XCTAssertThrowsError(try backend.open(path: makeTempDbPath(), networkId: 99)) { error in
            guard case VotingRustBackendError.rustError = error else {
                XCTFail("expected .rustError, got \(error.localizedDescription)")
                return
            }
        }
    }

    func test_close_isIdempotent() throws {
        let backend = VotingRustBackend()
        let path = makeTempDbPath()

        try backend.open(path: path, networkId: roundTripNetworkId)
        backend.close()
        backend.close() // second close must not crash

        // Re-opening after close must succeed.
        try backend.open(path: path, networkId: roundTripNetworkId)
        backend.close()
    }

    func test_close_waitsForInFlightDatabaseOperationBeforeFreeingHandle() throws {
        let backend = VotingRustBackend()
        let path = makeTempDbPath()
        try backend.open(path: path, networkId: roundTripNetworkId)

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
                XCTFail("unexpected error: \(error.localizedDescription)")
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
                XCTFail("expected .databaseNotOpen, got \(error.localizedDescription)")
                return
            }
        }
    }

    // MARK: - requireHandle gating

    func test_setWalletId_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(try backend.setWalletId("wallet")) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error.localizedDescription)")
                return
            }
        }
    }

    func test_resetTreeClient_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(try backend.resetTreeClient()) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error.localizedDescription)")
                return
            }
        }
    }

    func test_generateVanWitness_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(
            try backend.generateVanWitness(roundId: hexRoundId(0x11), bundleIndex: 0, anchorHeight: 0)
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error.localizedDescription)")
                return
            }
        }
    }

    // MARK: - Hotkey generation

    func test_generateHotkey_producesIndependentSecretsAndDerivedAddress() throws {
        let first = try VotingRustBackend.generateHotkey(networkId: roundTripNetworkId)
        let second = try VotingRustBackend.generateHotkey(networkId: roundTripNetworkId)

        XCTAssertFalse(first.storedSecret.isEmpty)
        XCTAssertFalse(first.rawOrchardAddress.isEmpty)
        XCTAssertNotEqual(
            first.storedSecret,
            second.storedSecret,
            "hotkeys must be independently random"
        )
        XCTAssertEqual(first.addressIndex, second.addressIndex)
    }

    func test_generateHotkey_rejectsUnknownNetworkId() {
        XCTAssertThrowsError(try VotingRustBackend.generateHotkey(networkId: 99)) { error in
            guard case VotingRustBackendError.rustError = error else {
                XCTFail("expected .rustError, got \(error.localizedDescription)")
                return
            }
        }
    }

    func test_generateHotkey_redactsSecretFromDescription() throws {
        let hotkey = try VotingRustBackend.generateHotkey(networkId: roundTripNetworkId)

        XCTAssertEqual("\(hotkey)", "--redacted--")
        XCTAssertEqual(String(describing: hotkey), "--redacted--")
    }

    // MARK: - Foundation helpers

    // The former `test_decomposeWeight_returnsFixedWidthBinaryDecomposition` is
    // gone: `zcashlc_voting_decompose_weight` was removed with no replacement,
    // because weight decomposition is now internal to `zcash_voting`'s bundling.

    func test_warmProvingCaches_doesNotThrow() throws {
        XCTAssertNoThrow(try VotingRustBackend.warmProvingCaches())
        XCTAssertNoThrow(try VotingRustBackend.warmProvingCaches())
    }

    func test_generateDelegationInputs_rejectsShortSenderSeed() throws {
        let short = [UInt8](repeating: 0x01, count: votingMinSeedByteCount - 1)
        let hotkey = try VotingRustBackend.generateHotkey(networkId: roundTripNetworkId)
        XCTAssertThrowsError(
            try VotingRustBackend.generateDelegationInputs(
                senderSeed: short,
                hotkeyStoredSecret: hotkey.storedSecret,
                networkId: roundTripNetworkId,
                accountIndex: 0
            )
        ) { error in
            guard case VotingRustBackendError.invalidData = error else {
                XCTFail("expected .invalidData, got \(error.localizedDescription)")
                return
            }
        }
    }

    func test_generateDelegationInputs_rejectsMalformedStoredSecret() {
        // The stored-secret length is `zcash_voting`'s invariant, so a malformed
        // secret must surface as a Rust error rather than a Swift-side check.
        XCTAssertThrowsError(
            try VotingRustBackend.generateDelegationInputs(
                senderSeed: [UInt8](repeating: 0x02, count: votingMinSeedByteCount),
                hotkeyStoredSecret: [UInt8](repeating: 0x03, count: votingMinSeedByteCount),
                networkId: roundTripNetworkId,
                accountIndex: 0
            )
        ) { error in
            guard case VotingRustBackendError.rustError = error else {
                XCTFail("expected .rustError, got \(error.localizedDescription)")
                return
            }
        }
    }

    func test_generateDelegationInputs_withFvk_rejectsBadLengths() throws {
        struct Case {
            let fvk: [UInt8]
            let fingerprint: [UInt8]
            let label: String
        }

        let hotkey = try VotingRustBackend.generateHotkey(networkId: roundTripNetworkId)
        let validFvk = [UInt8](repeating: 0x03, count: votingOrchardFvkByteCount)
        let validFp = [UInt8](repeating: 0x04, count: votingSeedFingerprintByteCount)
        let cases: [Case] = [
            .init(
                fvk: [UInt8](repeating: 0, count: votingOrchardFvkByteCount - 1),
                fingerprint: validFp,
                label: "fvk too short"
            ),
            .init(
                fvk: validFvk,
                fingerprint: [UInt8](repeating: 0, count: votingSeedFingerprintByteCount - 1),
                label: "fingerprint too short"
            )
        ]
        for testCase in cases {
            let fvk = testCase.fvk
            let fingerprint = testCase.fingerprint
            let label = testCase.label
            XCTAssertThrowsError(
                try VotingRustBackend.generateDelegationInputs(
                    senderFvk: fvk,
                    hotkeyStoredSecret: hotkey.storedSecret,
                    networkId: roundTripNetworkId,
                    seedFingerprint: fingerprint
                ),
                label
            ) { error in
                guard case VotingRustBackendError.invalidData = error else {
                    XCTFail("\(label): expected .invalidData, got \(error.localizedDescription)")
                    return
                }
            }
        }
    }

    func test_extractOrchardFvk_invalidUfvk_throwsRustError() {
        XCTAssertThrowsError(
            try VotingRustBackend.extractOrchardFvk(ufvk: "not-a-ufvk", networkId: roundTripNetworkId)
        ) { error in
            guard case VotingRustBackendError.rustError = error else {
                XCTFail("expected .rustError, got \(error.localizedDescription)")
                return
            }
        }
    }

    func test_extractPcztSighash_emptyInput_throwsRustError() {
        XCTAssertThrowsError(
            try VotingRustBackend.extractPcztSighash(pczt: [])
        ) { error in
            guard case VotingRustBackendError.rustError = error else {
                XCTFail("expected .rustError, got \(error.localizedDescription)")
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
                    XCTFail("\(testCase.label): expected .invalidData, got \(error.localizedDescription)")
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
            roundId: hexRoundId(0x21),
            snapshotHeight: 1234,
            eaPublicKey: valid,
            ncRoot: valid,
            nullifierImtRoot: valid
        )

        let state = try backend.getRoundState(roundId: hexRoundId(0x21))
        XCTAssertEqual(state.roundId, hexRoundId(0x21))
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
                roundId: hexRoundId(0x41),
                snapshotHeight: 1,
                eaPublicKey: short,
                ncRoot: valid,
                nullifierImtRoot: valid
            )
        ) { error in
            guard case VotingRustBackendError.rustError = error else {
                XCTFail("expected .rustError, got \(error.localizedDescription)")
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
            roundId: hexRoundId(0x21),
            snapshotHeight: 42,
            eaPublicKey: valid,
            ncRoot: valid,
            nullifierImtRoot: valid
        )
        try backend.initRound(
            roundId: hexRoundId(0x22),
            snapshotHeight: 43,
            eaPublicKey: valid,
            ncRoot: valid,
            nullifierImtRoot: valid
        )

        let rounds = try backend.listRounds()
        XCTAssertEqual(rounds.count, 2)
        XCTAssertEqual(Set(rounds.map(\.roundId)), [hexRoundId(0x21), hexRoundId(0x22)])
    }

    func test_getVotes_returnsEmpty_forFreshRound() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        let valid = [UInt8](repeating: 0x07, count: votingFieldElementByteCount)
        try backend.initRound(
            roundId: roundTripRoundId,
            snapshotHeight: 1,
            eaPublicKey: valid,
            ncRoot: valid,
            nullifierImtRoot: valid
        )

        XCTAssertTrue(try backend.getVotes(roundId: roundTripRoundId).isEmpty)
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
            try backend.storeDelegationTxHash(roundId: missingRoundId, bundleIndex: 0, txHash: "abc")
        ) { error in
            guard case VotingRustBackendError.rustError = error else {
                XCTFail("expected .rustError, got \(error.localizedDescription)")
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

    // The former `test_commitmentBundle_roundTrips` is gone: the recovery bundle
    // JSON is no longer supplied by the caller. `zcash_voting` writes it inside
    // `vote::commit`, whose proof is too expensive for a unit test, so the only
    // remaining caller-supplied half is the tree position covered below.

    func test_recordVcPosition_succeedsForExistingVote() throws {
        let backend = try makeReadyBackend(walletId: roundTripWalletId)
        defer { backend.close() }

        try createRoundWithBundle(backend, roundId: roundTripRoundId)
        try insertVoteRow(
            roundId: roundTripRoundId,
            walletId: roundTripWalletId,
            bundleIndex: roundTripBundleIndex,
            proposalId: roundTripProposalId
        )

        XCTAssertNoThrow(
            try backend.recordVcPosition(
                roundId: roundTripRoundId,
                bundleIndex: roundTripBundleIndex,
                proposalId: roundTripProposalId,
                voteCommitmentTreePosition: roundTripVoteCommitmentTreePosition
            )
        )

        // The bundle JSON is only written by `vote::commit`, so a vote that has
        // a position but no committed bundle still reads back as absent.
        XCTAssertNil(
            try backend.getCommitmentBundle(
                roundId: roundTripRoundId,
                bundleIndex: roundTripBundleIndex,
                proposalId: roundTripProposalId
            )
        )
    }

    func test_recordVcPosition_throwsRustError_whenVoteMissing() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        try createRoundWithBundle(backend, roundId: roundTripRoundId)

        XCTAssertThrowsError(
            try backend.recordVcPosition(
                roundId: roundTripRoundId,
                bundleIndex: roundTripBundleIndex,
                proposalId: roundTripProposalId,
                voteCommitmentTreePosition: roundTripVoteCommitmentTreePosition
            )
        ) { error in
            guard case VotingRustBackendError.rustError(let message) = error else {
                XCTFail("expected .rustError, got \(error.localizedDescription)")
                return
            }
            XCTAssertTrue(message.contains("record_vc_position failed"), "unexpected message: \(message)")
        }
    }

    func test_recordVcPosition_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(
            try backend.recordVcPosition(
                roundId: hexRoundId(0x31),
                bundleIndex: 0,
                proposalId: 0,
                voteCommitmentTreePosition: 0
            )
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error.localizedDescription)")
                return
            }
        }
    }

    func test_keystoneSignature_roundTrips() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        try createRoundWithBundle(backend, roundId: roundTripRoundId)

        try backend.storeKeystoneSignature(
            roundId: roundTripRoundId,
            bundleIndex: roundTripBundleIndex,
            sig: roundTripSpendAuthSignature,
            sighash: roundTripPcztSighash,
            randomizedKey: roundTripRandomizedKey
        )

        XCTAssertEqual(
            try backend.getKeystoneSignatures(roundId: roundTripRoundId),
            [
                VotingKeystoneSignatureRecord(
                    bundleIndex: roundTripBundleIndex,
                    sig: roundTripSpendAuthSignature,
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
            roundId: roundTripRoundId,
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

        let validSig = [UInt8](repeating: 0x01, count: votingSpendAuthSignatureByteCount)
        let validSighash = [UInt8](repeating: 0x02, count: votingPcztSighashByteCount)
        let validRk = [UInt8](repeating: 0x03, count: votingRandomizedKeyByteCount)

        let cases: [Case] = [
            .init(
                sig: [UInt8](repeating: 0, count: votingSpendAuthSignatureByteCount - 1),
                sighash: validSighash,
                randomizedKey: validRk,
                label: "sig too short"
            ),
            .init(
                sig: validSig,
                sighash: [UInt8](repeating: 0, count: votingPcztSighashByteCount - 1),
                randomizedKey: validRk,
                label: "sighash too short"
            ),
            .init(
                sig: validSig,
                sighash: validSighash,
                randomizedKey: [UInt8](repeating: 0, count: votingRandomizedKeyByteCount - 1),
                label: "rk too short"
            )
        ]
        for testCase in cases {
            XCTAssertThrowsError(
                try backend.storeKeystoneSignature(
                    roundId: roundTripRoundId,
                    bundleIndex: 0,
                    sig: testCase.sig,
                    sighash: testCase.sighash,
                    randomizedKey: testCase.randomizedKey
                ),
                testCase.label
            ) { error in
                guard case VotingRustBackendError.invalidData = error else {
                    XCTFail("\(testCase.label): expected .invalidData, got \(error.localizedDescription)")
                    return
                }
            }
        }
    }

    func test_getKeystoneSignatures_returnsEmpty_forFreshRound() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        XCTAssertTrue(try backend.getKeystoneSignatures(roundId: missingRoundId).isEmpty)
    }

    func test_clearRecoveryState_isNoop_onMissingRound() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        XCTAssertNoThrow(try backend.clearRecoveryState(roundId: missingRoundId))
    }

    // MARK: - Share delegation tracking

    // The former `test_shareDelegationLifecycle_roundTripsHexNullifier` and
    // `test_recordShareDelegation_rejectsInvalidNullifierLength` are gone: the
    // share nullifier is no longer a caller-supplied argument. `zcash_voting`
    // derives it from the committed vote's recovery bundle, so recording a share
    // now requires a real `vote::commit` and its proof — too expensive for a unit
    // test. Only the missing-vote rejection below remains observable offline.

    func test_recordShareDelegation_throwsRustError_whenVoteNotCommitted() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        try createRoundWithBundle(backend, roundId: roundTripRoundId)

        XCTAssertThrowsError(
            try backend.recordShareDelegation(
                roundId: roundTripRoundId,
                bundleIndex: roundTripBundleIndex,
                proposalId: roundTripProposalId,
                shareIndex: roundTripShareIndex,
                sentToURLs: [roundTripHelperURL],
                submitAt: roundTripSubmitAt
            )
        ) { error in
            guard case VotingRustBackendError.rustError(let message) = error else {
                XCTFail("expected .rustError, got \(error.localizedDescription)")
                return
            }
            XCTAssertTrue(message.contains("share::record failed"), "unexpected message: \(message)")
        }
    }

    func test_recordShareDelegation_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(
            try backend.recordShareDelegation(
                roundId: hexRoundId(0x31),
                bundleIndex: 0,
                proposalId: 0,
                shareIndex: 0,
                sentToURLs: [roundTripHelperURL],
                submitAt: 0
            )
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error.localizedDescription)")
                return
            }
        }
    }

    func test_getShareDelegations_returnsEmpty_forUnknownRound() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        XCTAssertTrue(try backend.getShareDelegations(roundId: missingRoundId).isEmpty)
        XCTAssertTrue(try backend.getUnconfirmedDelegations(roundId: missingRoundId).isEmpty)
    }

    // MARK: - Delegation workflow

    /// An empty note set used to produce an empty bundle layout. The canonical
    /// bundling policy now rejects it instead, so a caller with nothing to vote
    /// with learns that directly rather than receiving a zero-weight layout that
    /// only fails later in the delegation flow.
    func test_setupBundles_rejectsEmptyNotes() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        let valid = [UInt8](repeating: 0x07, count: votingFieldElementByteCount)
        try backend.initRound(
            roundId: roundTripRoundId,
            snapshotHeight: 1,
            eaPublicKey: valid,
            ncRoot: valid,
            nullifierImtRoot: valid
        )

        XCTAssertThrowsError(try backend.setupBundles(roundId: roundTripRoundId, notes: [])) { error in
            guard case VotingRustBackendError.rustError = error else {
                XCTFail("expected .rustError, got \(error.localizedDescription)")
                return
            }
        }
        XCTAssertEqual(try backend.getBundleCount(roundId: roundTripRoundId), 0)
    }

    func test_buildPczt_rejectsInvalidSeedFingerprintLength() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        let hotkey = try VotingRustBackend.generateHotkey(networkId: roundTripNetworkId)
        let params = VotingBuildPcztParams(
            roundId: roundTripRoundId,
            bundleIndex: 0,
            notes: [],
            keys: VotingDelegationKeyInputs(
                fvk: [UInt8](repeating: 0, count: votingOrchardFvkByteCount),
                hotkeyStoredSecret: hotkey.storedSecret,
                seedFingerprint: [UInt8](repeating: 0, count: votingSeedFingerprintByteCount - 1),
                accountIndex: 0,
                roundName: "Round"
            ),
            consensusBranchId: 0
        )
        XCTAssertThrowsError(try backend.buildPczt(params)) { error in
            guard case VotingRustBackendError.invalidData = error else {
                XCTFail("expected .invalidData, got \(error.localizedDescription)")
                return
            }
        }
    }

    func test_getDelegationSubmission_rejectsBadLengths() throws {
        let backend = try makeReadyBackend()
        defer { backend.close() }

        XCTAssertThrowsError(
            try backend.getDelegationSubmission(
                roundId: roundTripRoundId,
                bundleIndex: 0,
                signature: [UInt8](repeating: 0, count: votingSpendAuthSignatureByteCount - 1),
                sighash: [UInt8](repeating: 0, count: votingPcztSighashByteCount)
            )
        ) { error in
            guard case VotingRustBackendError.invalidData = error else {
                XCTFail("expected .invalidData, got \(error.localizedDescription)")
                return
            }
        }
        XCTAssertThrowsError(
            try backend.getDelegationSubmission(
                roundId: roundTripRoundId,
                bundleIndex: 0,
                signature: [UInt8](repeating: 0, count: votingSpendAuthSignatureByteCount),
                sighash: [UInt8](repeating: 0, count: votingPcztSighashByteCount - 1)
            )
        ) { error in
            guard case VotingRustBackendError.invalidData = error else {
                XCTFail("expected .invalidData, got \(error.localizedDescription)")
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
                roundId: hexRoundId(0x31),
                snapshotHeight: 0,
                eaPublicKey: valid,
                ncRoot: valid,
                nullifierImtRoot: valid
            )
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error.localizedDescription)")
                return
            }
        }
    }

    func test_syncVoteTree_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(
            try backend.syncVoteTree(roundId: hexRoundId(0x11), nodeUrl: "http://localhost")
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error.localizedDescription)")
                return
            }
        }
    }

    func test_listRounds_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(try backend.listRounds()) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error.localizedDescription)")
                return
            }
        }
    }

    func test_getRoundState_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(try backend.getRoundState(roundId: hexRoundId(0x31))) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error.localizedDescription)")
                return
            }
        }
    }

    func test_setupBundles_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(try backend.setupBundles(roundId: hexRoundId(0x31), notes: [])) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error.localizedDescription)")
                return
            }
        }
    }

    func test_storeVanPosition_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(
            try backend.storeVanPosition(roundId: hexRoundId(0x31), bundleIndex: 0, position: 0)
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error.localizedDescription)")
                return
            }
        }
    }

    func test_precomputeDelegationPir_beforeOpen_throwsDatabaseNotOpen() async {
        let backend = VotingRustBackend()
        do {
            _ = try await backend.precomputeDelegationPir(
                roundId: hexRoundId(0x11),
                bundleIndex: 0,
                notes: [],
                pirEndpoints: ["https://stub"],
                expectedSnapshotHeight: 0,
                pirResolver: PirSnapshotResolver(probe: FailingProbe())
            )
            XCTFail("expected .databaseNotOpen")
        } catch let error as VotingRustBackendError {
            guard case .databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error.localizedDescription)")
                return
            }
        } catch {
            XCTFail("unexpected error: \(error.localizedDescription)")
        }
    }

    func test_storeKeystoneSignature_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(
            try backend.storeKeystoneSignature(
                roundId: hexRoundId(0x31),
                bundleIndex: 0,
                sig: [UInt8](repeating: 0, count: votingSpendAuthSignatureByteCount),
                sighash: [UInt8](repeating: 0, count: votingPcztSighashByteCount),
                randomizedKey: [UInt8](repeating: 0, count: votingRandomizedKeyByteCount)
            )
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error.localizedDescription)")
                return
            }
        }
    }

    func test_generateNoteWitnesses_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(
            try backend.generateNoteWitnesses(
                roundId: hexRoundId(0x11),
                bundleIndex: 0,
                walletDbPath: "/tmp/wallet.sqlite",
                notes: [],
                networkId: roundTripNetworkId
            )
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error.localizedDescription)")
                return
            }
        }
    }

    func test_buildAndProveDelegation_beforeOpen_throwsDatabaseNotOpen() async throws {
        let backend = VotingRustBackend()
        let params = try makeDelegationProofParams()
        do {
            _ = try await backend.buildAndProveDelegation(
                params,
                pirEndpoints: ["https://stub"],
                expectedSnapshotHeight: 0,
                pirResolver: PirSnapshotResolver(probe: FailingProbe())
            )
            XCTFail("expected .databaseNotOpen")
        } catch let error as VotingRustBackendError {
            guard case .databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error.localizedDescription)")
                return
            }
        } catch {
            XCTFail("unexpected error: \(error.localizedDescription)")
        }
    }

    func test_buildAndProveDelegation_rejectsInvalidSeedFingerprintLength() async throws {
        let backend = try makeOpenBackend()
        defer { backend.close() }

        let params = try makeDelegationProofParams(
            seedFingerprint: [UInt8](repeating: 0, count: votingSeedFingerprintByteCount - 1)
        )
        do {
            _ = try await backend.buildAndProveDelegation(
                params,
                pirEndpoints: ["https://stub"],
                expectedSnapshotHeight: 0,
                pirResolver: PirSnapshotResolver(probe: FailingProbe())
            )
            XCTFail("expected .invalidData")
        } catch let error as VotingRustBackendError {
            guard case .invalidData = error else {
                XCTFail("expected .invalidData, got \(error.localizedDescription)")
                return
            }
        } catch {
            XCTFail("unexpected error: \(error.localizedDescription)")
        }
    }

    func test_generateNoteWitnesses_afterOpen_forwardsNetworkIdAndPropagatesRustError() throws {
        let backend = try makeOpenBackend()
        defer { backend.close() }

        XCTAssertThrowsError(
            try backend.generateNoteWitnesses(
                roundId: hexRoundId(0x11),
                bundleIndex: 0,
                walletDbPath: "/tmp/nonexistent-wallet.sqlite",
                notes: [],
                networkId: 99
            )
        ) { error in
            guard case VotingRustBackendError.rustError(let message) = error else {
                XCTFail("expected .rustError, got \(error.localizedDescription)")
                return
            }
            XCTAssertTrue(message.contains("Invalid network type"), "unexpected message: \(message)")
        }
    }

    // MARK: - commitVote

    func test_commitVote_beforeOpen_throwsDatabaseNotOpen() async throws {
        let backend = VotingRustBackend()
        let hotkey = try VotingRustBackend.generateHotkey(networkId: roundTripNetworkId)

        do {
            _ = try await backend.commitVote(
                roundId: hexRoundId(0x11),
                bundleIndex: 0,
                hotkeyStoredSecret: hotkey.storedSecret,
                proposalId: 0,
                choice: 0,
                numOptions: 2,
                voteCommitmentTreePosition: 0,
                vanWitness: makeVanWitness(),
                singleShare: false
            )
            XCTFail("expected .databaseNotOpen")
        } catch let error as VotingRustBackendError {
            guard case .databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error.localizedDescription)")
                return
            }
        } catch {
            XCTFail("unexpected error: \(error.localizedDescription)")
        }
    }

    func test_commitVote_afterOpen_rejectsMalformedStoredSecretBeforeReportingProgress() async throws {
        let backend = try makeOpenBackend()
        defer { backend.close() }
        let progressReported = expectation(
            description: "progress must not be reported before the hotkey is reconstructed"
        )
        progressReported.isInverted = true

        do {
            _ = try await backend.commitVote(
                roundId: hexRoundId(0x11),
                bundleIndex: 0,
                hotkeyStoredSecret: [UInt8](repeating: 1, count: votingFieldElementByteCount),
                proposalId: 0,
                choice: 0,
                numOptions: 2,
                voteCommitmentTreePosition: 0,
                vanWitness: makeVanWitness(),
                singleShare: false,
                progress: { _ in progressReported.fulfill() }
            )
            XCTFail("expected .rustError")
        } catch let error as VotingRustBackendError {
            guard case .rustError(let message) = error else {
                XCTFail("expected .rustError, got \(error.localizedDescription)")
                return
            }
            XCTAssertTrue(
                message.contains("failed to reconstruct voting hotkey"),
                "unexpected message: \(message)"
            )
        } catch {
            XCTFail("unexpected error: \(error.localizedDescription)")
        }

        await fulfillment(of: [progressReported], timeout: 0.1)
    }

    // MARK: - markVoteSubmitted

    func test_markVoteSubmitted_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()
        XCTAssertThrowsError(
            try backend.markVoteSubmitted(
                roundId: hexRoundId(0x11),
                bundleIndex: 0,
                proposalId: 0,
                txHash: roundTripVoteTxHash
            )
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error.localizedDescription)")
                return
            }
        }
    }

    func test_markVoteSubmitted_afterOpen_missingVote_throwsRustError() throws {
        let backend = try makeOpenBackend()
        defer { backend.close() }

        XCTAssertThrowsError(
            try backend.markVoteSubmitted(
                roundId: missingRoundId,
                bundleIndex: 0,
                proposalId: 0,
                txHash: roundTripVoteTxHash
            )
        ) { error in
            guard case VotingRustBackendError.rustError(let message) = error else {
                XCTFail("expected .rustError, got \(error.localizedDescription)")
                return
            }
            XCTAssertTrue(
                message.contains("record_submission failed"),
                "unexpected message: \(message)"
            )
        }
    }

    // MARK: - setWalletId

    func test_setWalletId_succeedsAfterOpen() throws {
        let backend = VotingRustBackend()
        try backend.open(path: makeTempDbPath(), networkId: roundTripNetworkId)
        defer { backend.close() }

        XCTAssertNoThrow(try backend.setWalletId("wallet-id-1"))
        // Idempotent: setting again must succeed too.
        XCTAssertNoThrow(try backend.setWalletId("wallet-id-2"))
    }

    // MARK: - resetTreeClient

    func test_resetTreeClient_succeedsAfterOpen_withEmptyRoundId() throws {
        let backend = VotingRustBackend()
        try backend.open(path: makeTempDbPath(), networkId: roundTripNetworkId)
        defer { backend.close() }

        // Empty round ID resets all in-memory tree clients; safe to call on a
        // fresh handle that has no clients yet.
        XCTAssertNoThrow(try backend.resetTreeClient())
    }

    // MARK: - precomputeDelegationPir resolver gating

    func test_precomputeDelegationPir_emptyEndpoints_throwsResolverError() async throws {
        let backend = VotingRustBackend()
        try backend.open(path: makeTempDbPath(), networkId: roundTripNetworkId)
        defer { backend.close() }

        do {
            _ = try await backend.precomputeDelegationPir(
                roundId: hexRoundId(0x11),
                bundleIndex: 0,
                notes: [],
                pirEndpoints: [],
                expectedSnapshotHeight: 0
            )
            XCTFail("expected PirSnapshotResolverError.noEndpointsConfigured")
        } catch PirSnapshotResolverError.noEndpointsConfigured {
            // expected
        } catch {
            XCTFail("unexpected error: \(error.localizedDescription)")
        }
    }

    // MARK: - precomputeDelegationPir layout gating

    /// Pins that the `.unknown` sentinel layout (`polyLen` 0) fails closed
    /// inside `zcash_voting` at the FFI boundary: the crate rejects the layout
    /// locally, before issuing any network request. The probe stub satisfies
    /// snapshot resolution offline, so the failure can only be the layout
    /// rejection, not a resolver or transport error.
    func test_precomputeDelegationPir_unknownLayout_failsClosedThroughFFI() async throws {
        let backend = VotingRustBackend()
        try backend.open(path: makeTempDbPath(), networkId: roundTripNetworkId)
        defer { backend.close() }

        do {
            _ = try await backend.precomputeDelegationPir(
                roundId: hexRoundId(0x11),
                bundleIndex: 0,
                notes: [],
                pirEndpoints: ["https://stub"],
                expectedSnapshotHeight: 0,
                pirLayout: .unknown,
                pirResolver: PirSnapshotResolver(probe: MatchingProbe())
            )
            XCTFail("expected .rustError for the unknown PIR layout")
        } catch let error as VotingRustBackendError {
            guard case .rustError(let message) = error else {
                XCTFail("expected .rustError, got \(error.localizedDescription)")
                return
            }
            XCTAssertTrue(
                message.contains("pir_layout is unknown"),
                "expected the crate's unknown-layout rejection, got: \(message)"
            )
        } catch {
            XCTFail("unexpected error: \(error.localizedDescription)")
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
        try backend.open(path: makeTempDbPath(), networkId: roundTripNetworkId)
        try backend.setWalletId(walletId)
        return backend
    }

    private func makeVanWitness() -> VotingVanWitness {
        VotingVanWitness(
            authPath: [[UInt8](repeating: 1, count: votingFieldElementByteCount)],
            position: 0,
            anchorHeight: 0
        )
    }

    private func makeDelegationProofParams(
        seedFingerprint: [UInt8] = [UInt8](repeating: 0x04, count: votingSeedFingerprintByteCount)
    ) throws -> VotingDelegationProofParams {
        let hotkey = try VotingRustBackend.generateHotkey(networkId: roundTripNetworkId)
        return VotingDelegationProofParams(
            roundId: roundTripRoundId,
            bundleIndex: roundTripBundleIndex,
            notes: [],
            keys: VotingDelegationKeyInputs(
                fvk: [UInt8](repeating: 0x03, count: votingOrchardFvkByteCount),
                hotkeyStoredSecret: hotkey.storedSecret,
                seedFingerprint: seedFingerprint,
                accountIndex: 0,
                roundName: "Round"
            )
        )
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

    // TODO: [#1855] Consider replacing this raw SQLite insertion with a proper Rust-side test
    // helper so we don't reach into the Rust-managed votes table directly.
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
        try backend.open(path: makeTempDbPath(), networkId: roundTripNetworkId)
        try backend.setWalletId("wallet")
        return backend
    }
}

// MARK: - Test doubles

/// Probe stub used where endpoint probing must not happen.
private struct FailingProbe: PirSnapshotProbing {
    func probe(url: String, expectedSnapshotHeight: BlockHeight) async -> PirSnapshotProbeOutcome {
        XCTFail("closed voting backend should fail before probing PIR endpoints")
        return PirSnapshotProbeOutcome(url: url, status: .matching(height: expectedSnapshotHeight))
    }
}

/// Probe stub that reports every endpoint as serving the expected snapshot,
/// letting resolution succeed offline so a test can reach the FFI itself.
private struct MatchingProbe: PirSnapshotProbing {
    func probe(url: String, expectedSnapshotHeight: BlockHeight) async -> PirSnapshotProbeOutcome {
        PirSnapshotProbeOutcome(url: url, status: .matching(height: expectedSnapshotHeight))
    }
}
