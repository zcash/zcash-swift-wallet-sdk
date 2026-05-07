//
//  VotingRustBackendTests.swift
//  ZcashLightClientKitTests
//

import XCTest
@testable import ZcashLightClientKit

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
        // Well-formed 32-byte fixtures.
        var voteCommitment = [UInt8](repeating: 0, count: 32)
        voteCommitment[0] = 0x01
        var primaryBlind = [UInt8](repeating: 0, count: 32)
        primaryBlind[0] = 0x03

        let nullifier = try VotingRustBackend.computeShareNullifier(
            voteCommitment: voteCommitment,
            shareIndex: 0,
            primaryBlind: primaryBlind
        )

        // Captured from the Rust reference implementation
        // (`zcash_voting::share_tracking::compute_share_nullifier`) for the
        // fixture above. Update only if the upstream algorithm intentionally
        // changes. A mismatch otherwise indicates the FFI wrapper is feeding
        // arguments incorrectly or mangling the output.
        XCTAssertEqual(
            nullifier,
            "058ffd2e1ba7acaf97b167accfb4ec141b91c0ee2a0f552631851ac97ca1e61d"
        )
    }

    func test_computeShareNullifier_throwsInvalidData_whenInputsAreNot32Bytes() {
        let valid = [UInt8](repeating: 0x01, count: 32)
        let tooShort = [UInt8](repeating: 0x01, count: 31)
        let tooLong = [UInt8](repeating: 0x01, count: 33)

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
                pirResolver: PirSnapshotResolver(probe: AlwaysMatchingProbe())
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
        let path = NSTemporaryDirectory()
            + "VotingRustBackendTests-\(ProcessInfo.processInfo.globallyUniqueString).sqlite"
        dbPath = path
        return path
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
