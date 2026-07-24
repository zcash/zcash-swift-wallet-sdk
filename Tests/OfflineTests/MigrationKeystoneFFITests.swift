//
//  MigrationKeystoneFFITests.swift
//  OfflineTests
//
//  Exercises the Keystone batch-signing UR bridge (rust/src/migration_keystone.rs, welded via the
//  four `migrationKeystone*` members of ZcashRustBackendWelding) through the real libzcashlc.
//  Unlike MigrationFFITests.swift, this bridge is DB-free and account-free -- pure PCZT/UR
//  operations over caller-held bytes -- so this suite needs neither a wallet database nor a
//  created account: a bare `ZcashRustBackend.makeForTests` instance is enough.
//
//  Only the negative (throwing) path is reachable offline: a real batch-signing round trip needs
//  an actual Keystone device response, which this suite deliberately does not attempt to fake.
//  These tests instead prove the marshaling + error path end-to-end through the real dylib --
//  garbage input reaches the rust layer and comes back as the documented `ZcashError` case, not a
//  crash, a hang, or a silently wrong success.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class MigrationKeystoneFFITests: XCTestCase {
    var rustBackend: ZcashRustBackendWelding!

    override func setUp() async throws {
        try await super.setUp()

        // No `initDataDb`/account fixture: none of the four calls under test touch the wallet
        // database, so a bare backend instance (unopened db path) is representative of real usage.
        rustBackend = ZcashRustBackend.makeForTests(
            fsBlockDbRoot: Environment.uniqueTestTempDirectory,
            networkType: .testnet
        )
    }

    override func tearDown() {
        super.tearDown()
        rustBackend = nil
    }

    // MARK: - decodeKeystoneSignBatchPart

    /// A scanned string that is not a UR at all must fail `ur::decode` before any CBOR/registry-
    /// type work, deterministically and without a session in flight.
    func testDecodeSignBatchPartWithNonURStringThrows() async {
        do {
            _ = try await rustBackend.migrationKeystoneDecodeSignBatchPart("definitely-not-a-ur", expectedRequestId: Data())
            XCTFail("Expected decoding a non-UR string to throw")
        } catch ZcashError.rustMigrationKeystoneDecodeSignBatchPart {
            // expected
        } catch {
            XCTFail("Expected rustMigrationKeystoneDecodeSignBatchPart but got \(error)")
        }
    }

    /// `migrationKeystoneResetSignBatchDecoder()` must leave the (process-global) decode session in
    /// a clean, working state -- not corrupted, not stuck -- so a decode attempt right after a
    /// reset still fails the SAME documented way on garbage input, rather than crashing, hanging,
    /// or spuriously succeeding on stale session state.
    func testResetSignBatchDecoderThenDecodeOfGarbagePartStillThrows() async {
        await rustBackend.migrationKeystoneResetSignBatchDecoder()

        do {
            _ = try await rustBackend.migrationKeystoneDecodeSignBatchPart("definitely-not-a-ur", expectedRequestId: Data())
            XCTFail("Expected decoding a non-UR string right after a reset to throw")
        } catch ZcashError.rustMigrationKeystoneDecodeSignBatchPart {
            // expected
        } catch {
            XCTFail("Expected rustMigrationKeystoneDecodeSignBatchPart but got \(error)")
        }
    }

    // MARK: - buildKeystoneSignBatchQRParts

    /// A byte blob that is not a serialized PCZT must fail `pczt::parse` inside the build step,
    /// before redaction or UR/QR encoding are ever attempted.
    func testBuildSignBatchQRPartsWithNonPcztByteBlobThrows() async {
        let pczts = [MigrationUnsignedTransferPczt(id: "1", pczt: Data([0, 1, 2, 3]))]

        do {
            _ = try await rustBackend.migrationKeystoneBuildSignBatchQrParts(
                requestId: Data([0xAB, 0xCD]),
                pczts: pczts,
                maxFragmentLen: 200
            )
            XCTFail("Expected building QR parts from a non-PCZT byte blob to throw")
        } catch ZcashError.rustMigrationKeystoneBuildSignBatchQrParts {
            // expected
        } catch {
            XCTFail("Expected rustMigrationKeystoneBuildSignBatchQrParts but got \(error)")
        }
    }

    // MARK: - applyKeystoneBatchSignatures

    /// A syntactically-invalid PCZT paired with a syntactically-invalid batch-signature response
    /// must throw: either the response fails to parse as a `BatchSignResponse` first, or (were it
    /// somehow parsed) its signature-set count would not match the one PCZT supplied -- both are
    /// documented failure modes of `apply_batch_signatures`, and both surface through the same
    /// `ZcashError` case.
    func testApplyBatchSignaturesWithInvalidPcztAndResponseThrows() async {
        let pczts = [MigrationUnsignedTransferPczt(id: "1", pczt: Data([0, 1, 2, 3]))]

        do {
            _ = try await rustBackend.migrationKeystoneApplyBatchSignatures(
                pczts: pczts,
                batchSignResponse: Data([0, 1, 2, 3])
            )
            XCTFail("Expected applying batch signatures with a syntactically-invalid PCZT/response pair to throw")
        } catch ZcashError.rustMigrationKeystoneApplyBatchSignatures {
            // expected
        } catch {
            XCTFail("Expected rustMigrationKeystoneApplyBatchSignatures but got \(error)")
        }
    }
}
