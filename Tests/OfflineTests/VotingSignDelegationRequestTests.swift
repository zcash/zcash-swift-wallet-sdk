//
//  VotingSignDelegationRequestTests.swift
//  ZcashLightClientKitTests
//

import XCTest
@testable import ZcashLightClientKit

/// Builds a round identifier that satisfies the Rust round-parameter validation,
/// which requires 64 lowercase hex characters encoding a canonical Pallas field
/// element. `tag` occupies the low byte so each caller gets a distinct round.
private func signHexRoundId(_ tag: UInt8) -> String {
    String(format: "%02x", tag) + String(repeating: "00", count: 31)
}

private let signWalletId = "test-wallet"
private let signNetworkId: UInt32 = 1
/// A well-formed round identifier that is never initialized, so the crate has no
/// stored signing request to answer with.
private let signMissingRoundId = signHexRoundId(0xfc)
/// Orchard FVK length. The value is never used as a key here: the crate reads
/// only the account index, seed fingerprint and network out of the delegation
/// keys when loading a signing request.
private let signFvk = [UInt8](repeating: 0, count: 96)
private let signSeedFingerprint = [UInt8](repeating: 7, count: 32)
private let signSeed = [UInt8](repeating: 9, count: 32)
private let signRoundName = "chp-offline"

final class VotingSignDelegationRequestTests: XCTestCase {
    private var dbPath: String?

    override func tearDown() {
        if let dbPath {
            try? FileManager.default.removeItem(atPath: dbPath)
        }
        dbPath = nil
        super.tearDown()
    }

    func test_signDelegationRequest_shortSeed_throwsInvalidData() throws {
        let backend = VotingRustBackend()

        XCTAssertThrowsError(
            try backend.signDelegationRequest(
                roundId: signMissingRoundId,
                bundleIndex: 0,
                keys: try makeKeys(),
                seed: [UInt8](repeating: 9, count: 31)
            )
        ) { error in
            guard case VotingRustBackendError.invalidData(let message) = error else {
                XCTFail("expected .invalidData, got \(error.localizedDescription)")
                return
            }
            XCTAssertTrue(
                message.contains("seed must be at least"),
                "unexpected message: \(message)"
            )
        }
    }

    func test_signDelegationRequest_beforeOpen_throwsDatabaseNotOpen() throws {
        let backend = VotingRustBackend()

        XCTAssertThrowsError(
            try backend.signDelegationRequest(
                roundId: signMissingRoundId,
                bundleIndex: 0,
                keys: try makeKeys(),
                seed: signSeed
            )
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error.localizedDescription)")
                return
            }
        }
    }

    func test_signDelegationRequest_afterOpen_missingRound_throwsRustError() throws {
        let backend = try makeOpenBackend()
        defer { backend.close() }

        XCTAssertThrowsError(
            try backend.signDelegationRequest(
                roundId: signMissingRoundId,
                bundleIndex: 0,
                keys: try makeKeys(),
                seed: signSeed
            )
        ) { error in
            guard case VotingRustBackendError.rustError(let message) = error else {
                XCTFail("expected .rustError, got \(error.localizedDescription)")
                return
            }
            XCTAssertTrue(
                message.contains("signing_request failed"),
                "unexpected message: \(message)"
            )
        }
    }

    // MARK: - Helpers

    /// A hotkey secret has to be real: the FFI reconstructs a `VotingHotkey`
    /// from it before it can build the delegation keys the signing request is
    /// loaded through. `generateHotkey` is static and needs no database.
    private func makeKeys() throws -> VotingDelegationKeyInputs {
        let hotkey = try VotingRustBackend.generateHotkey(networkId: signNetworkId)
        return VotingDelegationKeyInputs(
            fvk: signFvk,
            hotkeyStoredSecret: hotkey.storedSecret,
            seedFingerprint: signSeedFingerprint,
            accountIndex: 0,
            roundName: signRoundName
        )
    }

    private func makeTempDbPath() -> String {
        let unique = ProcessInfo.processInfo.globallyUniqueString
        let path = "\(NSTemporaryDirectory())VotingSignDelegationRequestTests-\(unique).sqlite"
        dbPath = path
        return path
    }

    private func makeOpenBackend() throws -> VotingRustBackend {
        let backend = VotingRustBackend()
        try backend.open(path: makeTempDbPath(), networkId: signNetworkId)
        try backend.setWalletId(signWalletId)
        return backend
    }
}
