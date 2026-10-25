//
//  VotingKeyTypesTests.swift
//  ZcashLightClientKitTests
//

import XCTest
@testable import ZcashLightClientKit

/// The voting API takes its key material through these wrappers, so a value of
/// the wrong shape is rejected when it is wrapped rather than by each FFI call.
final class VotingKeyTypesTests: XCTestCase {
    // MARK: - VotingSeed

    func test_seed_rejectsFewerThan32Bytes() {
        assertInvalidData(try VotingSeed(bytes: bytes(votingMinSeedByteCount - 1)))
    }

    func test_seed_acceptsAtLeast32Bytes() throws {
        XCTAssertEqual(try VotingSeed(bytes: bytes(votingMinSeedByteCount)).bytes.count, votingMinSeedByteCount)
        XCTAssertEqual(try VotingSeed(bytes: bytes(64)).bytes.count, 64)
    }

    func test_seed_isRedacted() throws {
        assertRedacted(try VotingSeed(bytes: bytes(votingMinSeedByteCount)))
    }

    // MARK: - VotingSeedFingerprint

    func test_seedFingerprint_requiresExactly32Bytes() throws {
        assertInvalidData(try VotingSeedFingerprint(bytes: bytes(votingSeedFingerprintByteCount - 1)))
        assertInvalidData(try VotingSeedFingerprint(bytes: bytes(votingSeedFingerprintByteCount + 1)))
        XCTAssertEqual(
            try VotingSeedFingerprint(bytes: bytes(votingSeedFingerprintByteCount)).bytes.count,
            votingSeedFingerprintByteCount
        )
    }

    func test_seedFingerprint_codableRoundTripAndRejectsWrongLength() throws {
        let fingerprint = try VotingSeedFingerprint(bytes: bytes(votingSeedFingerprintByteCount))
        let decoded = try JSONDecoder().decode(
            VotingSeedFingerprint.self,
            from: try JSONEncoder().encode(fingerprint)
        )
        XCTAssertEqual(decoded, fingerprint)

        let short = try JSONEncoder().encode(bytes(votingSeedFingerprintByteCount - 1))
        assertInvalidData(try JSONDecoder().decode(VotingSeedFingerprint.self, from: short))
    }

    // MARK: - VotingHotkeySecret

    func test_hotkeySecret_requiresExactly64Bytes() {
        // 32 bytes was accepted by the old `[UInt8]` parameter and only failed
        // inside Rust; the wrapper now rejects it before any FFI call.
        assertInvalidData(try VotingHotkeySecret(bytes: bytes(votingFieldElementByteCount)))
        assertInvalidData(try VotingHotkeySecret(bytes: bytes(votingHotkeyStoredSecretByteCount + 1)))
    }

    func test_hotkeySecret_rebuildsFromPersistedBytes() throws {
        let hotkey = try VotingRustBackend.generateHotkey(network: .mainnet)

        let rebuilt = try VotingHotkeySecret(bytes: hotkey.storedSecret.bytes)

        XCTAssertEqual(rebuilt, hotkey.storedSecret)
    }

    func test_hotkeySecret_isRedacted() throws {
        assertRedacted(try VotingHotkeySecret(bytes: bytes(votingHotkeyStoredSecretByteCount)))
    }

    // MARK: - VotingOrchardFullViewingKey

    func test_orchardFvk_requiresExactly96Bytes() throws {
        assertInvalidData(try VotingOrchardFullViewingKey(bytes: bytes(votingOrchardFvkByteCount - 1)))
        assertInvalidData(try VotingOrchardFullViewingKey(bytes: bytes(votingOrchardFvkByteCount + 1)))
        XCTAssertEqual(
            try VotingOrchardFullViewingKey(bytes: bytes(votingOrchardFvkByteCount)).bytes.count,
            votingOrchardFvkByteCount
        )
    }

    func test_orchardFvk_isRedacted() throws {
        assertRedacted(try VotingOrchardFullViewingKey(bytes: bytes(votingOrchardFvkByteCount)))
    }

    // MARK: - Decoding FFI output into the wrappers

    func test_generateDelegationInputs_decodesIntoTypedKeys() throws {
        let hotkey = try VotingRustBackend.generateHotkey(network: .mainnet)

        let inputs = try VotingRustBackend.generateDelegationInputs(
            senderSeed: try VotingSeed(bytes: bytes(votingMinSeedByteCount, value: 0x02)),
            hotkeyStoredSecret: hotkey.storedSecret,
            network: .mainnet,
            accountIndex: Zip32AccountIndex(0)
        )

        XCTAssertEqual(inputs.fvk.bytes.count, votingOrchardFvkByteCount)
        XCTAssertEqual(inputs.seedFingerprint.bytes.count, votingSeedFingerprintByteCount)
        XCTAssertEqual(inputs.hotkeyRawAddress, hotkey.rawOrchardAddress)
    }

    // MARK: - Heights

    func test_negativeHeight_isRejectedAtTheFFIBoundary() {
        assertInvalidData(try BlockHeight(-1).votingFFIHeight())
    }

    func test_heightBeyondBlockHeight_isRejectedInsteadOfTrapping() {
        assertInvalidData(try BlockHeight.fromVotingFFI(UInt64.max))
    }

    // MARK: - Helpers

    private func bytes(_ count: Int, value: UInt8 = 0x01) -> [UInt8] {
        [UInt8](repeating: value, count: count)
    }

    private func assertInvalidData<T>(
        _ expression: @autoclosure () throws -> T,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try expression(), file: file, line: line) { error in
            guard case VotingRustBackendError.invalidData = error else {
                XCTFail("expected .invalidData, got \(error.localizedDescription)", file: file, line: line)
                return
            }
        }
    }

    private func assertRedacted<T>(_ value: T, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual("\(value)", "--redacted--", file: file, line: line)
        XCTAssertEqual(String(reflecting: value), "--redacted--", file: file, line: line)
    }
}
