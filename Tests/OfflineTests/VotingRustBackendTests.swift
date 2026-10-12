//
//  VotingRustBackendTests.swift
//  ZcashLightClientKitTests
//

import XCTest
@testable import ZcashLightClientKit

/// Builds a round identifier that satisfies the Rust round-parameter validation,
/// which requires 64 lowercase hex characters encoding a canonical Pallas field
/// element. `tag` occupies the low byte so each caller gets a distinct round
/// while staying canonical.
private func hexRoundId(_ tag: UInt8) -> String {
    String(format: "%02x", tag) + String(repeating: "00", count: 31)
}

private let roundTripNetworkId: UInt32 = 1
private let roundTripVoteTxHash = "vote-tx-hash"
private let roundTripHelperURL = "https://helper-a.example"

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

    func test_generateHotkey_rejectsUnknownNetworkId() {
        XCTAssertThrowsError(try VotingRustBackend.generateHotkey(networkId: 99)) { error in
            guard case VotingRustBackendError.rustError = error else {
                XCTFail("expected .rustError, got \(error.localizedDescription)")
                return
            }
        }
    }

    // MARK: - Foundation helpers

    // The former `test_decomposeWeight_returnsFixedWidthBinaryDecomposition` is
    // gone: `zcashlc_voting_decompose_weight` was removed with no replacement,
    // because weight decomposition is now internal to `zcash_voting`'s bundling.

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

    // MARK: - Recovery state

    // The former `test_commitmentBundle_roundTrips` is gone: the recovery bundle
    // JSON is no longer supplied by the caller. `zcash_voting` writes it inside
    // `vote::commit`, whose proof is too expensive for a unit test, so the only
    // remaining caller-supplied half is the tree position covered below.

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

    // MARK: - Share delegation tracking

    // The former `test_shareDelegationLifecycle_roundTripsHexNullifier` and
    // `test_recordShareDelegation_rejectsInvalidNullifierLength` are gone: the
    // share nullifier is no longer a caller-supplied argument. `zcash_voting`
    // derives it from the committed vote's recovery bundle, so recording a share
    // now requires a real `vote::commit` and its proof — too expensive for a unit
    // test. Only the missing-vote rejection below remains observable offline.

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

    // MARK: - Helpers

    private func makeTempDbPath() -> String {
        let unique = ProcessInfo.processInfo.globallyUniqueString
        let path = "\(NSTemporaryDirectory())VotingRustBackendTests-\(unique).sqlite"
        dbPath = path
        return path
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
