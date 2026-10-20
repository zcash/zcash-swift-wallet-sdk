//
//  ZcashErrorLocalizedTests.swift
//  OfflineTests
//
//  Created by Lukáš Korba on 2026-05-12.
//

import XCTest
@testable import ZcashLightClientKit

class ZcashErrorLocalizedTests: XCTestCase {
    // MARK: - LocalizedError conformance

    func testLocalizedDescriptionContainsErrorCode() {
        let error = ZcashError.rustCreateToAddress(.stub)
        XCTAssertTrue(
            error.localizedDescription.contains("ZRUST0002"),
            "localizedDescription should contain the error code but got: \(error.localizedDescription)"
        )
    }

    func testLocalizedDescriptionContainsMessage() {
        let error = ZcashError.rustCreateToAddress(.stub)
        XCTAssertTrue(
            error.localizedDescription.contains("Error from rust layer when calling ZcashRustBackend.createToAddress"),
            "localizedDescription should contain the human-readable message but got: \(error.localizedDescription)"
        )
    }

    /// MOB-1201: the redacted rust detail must reach `localizedDescription`, because that is the
    /// string a user pastes into a support ticket. Without it five reports across three app
    /// versions all read identically and named no cause.
    func testLocalizedDescriptionCarriesRedactedRustDetail() {
        let error = ZcashError.rustCreateToAddress(.stub)
        XCTAssertEqual(
            error.localizedDescription,
            "ZRUST0002: Error from rust layer when calling ZcashRustBackend.createToAddress "
                + "(the transaction builder returned an error)"
        )
    }

    /// Guards the generated `detail` switch against silently matching nothing. The stencil selects
    /// cases by payload TYPE, and a filter that compiles but matches no case produces a `detail`
    /// that is always nil — which looks exactly like the bug this all exists to fix, while every
    /// single-case test still passes.
    func testEveryRedactedCarrierRendersItsDetail() {
        let carriers: [ZcashError] = [
            .rustCreateToAddress(.stub),
            .rustProposeTransfer(.stub),
            .rustProposeTransferFromURI(.stub),
            .rustProposeSendMaxTransfer(.stub),
            .rustProposeOrchardToIronwoodMigration(.stub)
        ]

        for error in carriers {
            XCTAssertEqual(
                error.detail,
                RedactedRustError.stub.message,
                "\(error.code.rawValue) carries a RedactedRustError but renders no detail"
            )
        }
    }

    /// The redaction boundary. A case whose payload is still a raw `String` renders nothing extra,
    /// because that string has not been through the rust-side classifier and may hold an amount or
    /// an address.
    func testUnredactedStringPayloadIsNotRendered() {
        let error = ZcashError.rustGetTransaction("Insufficient balance (have 1.2, need 2.0)")
        XCTAssertNil(error.detail)
        XCTAssertEqual(
            error.localizedDescription,
            "ZRUST0150: Error from rust layer when calling ZcashRustBackend.getTransaction"
        )
    }

    func testScanRequiredIsItsOwnCode() {
        XCTAssertEqual(ZcashError.rustProposalScanRequired.code.rawValue, "ZRUST0153")
        XCTAssertNil(ZcashError.rustProposalScanRequired.detail)
    }

    func testInsufficientFundsCarriesAmountsButNotInTheDescription() {
        let error = ZcashError.rustProposalInsufficientFunds(Zatoshi(120_000_000), Zatoshi(200_000_000))

        XCTAssertEqual(error.code.rawValue, "ZRUST0154")
        XCTAssertFalse(error.localizedDescription.contains("120000000"))
        XCTAssertFalse(error.localizedDescription.contains("200000000"))
    }

    func testUnknownErrorLocalizedDescription() {
        let inner = NSError(domain: "GRPCStatus", code: 14, userInfo: [NSLocalizedDescriptionKey: "Transport became inactive"])
        let error = ZcashError.unknown(inner)
        XCTAssertEqual(
            error.localizedDescription,
            "ZUNKWN0001: Some error happened that is not handled as `ZcashError`. All errors in the SDK are (should be) `ZcashError`."
        )
    }

    func testServiceBlockStreamFailedLocalizedDescription() {
        let error = ZcashError.serviceBlockStreamFailed(.timeOut)
        XCTAssertTrue(
            error.localizedDescription.contains("ZSRVC0000"),
            "localizedDescription should contain ZSRVC0000 but got: \(error.localizedDescription)"
        )
    }

    // MARK: - NSError bridge produces meaningful description instead of ordinal

    func testNSErrorLocalizedDescriptionIsNotOrdinal() {
        let error = ZcashError.rustCreateToAddress(.stub)
        let nsError = error as NSError

        // Before LocalizedError conformance, this would be:
        // "The operation couldn't be completed. (ZcashLightClientKit.ZcashError error 29.)"
        // After: "ZRUST0002: Error from rust layer when calling ZcashRustBackend.createToAddress"
        XCTAssertFalse(
            nsError.localizedDescription.contains("error 29"),
            "NSError.localizedDescription should NOT contain the opaque ordinal 'error 29'"
        )
        XCTAssertTrue(
            nsError.localizedDescription.contains("ZRUST0002"),
            "NSError.localizedDescription should contain the error code ZRUST0002"
        )
    }

    func testNSErrorLocalizedDescriptionForUnknown() {
        let inner = NSError(domain: "test", code: 0)
        let error = ZcashError.unknown(inner) as NSError

        XCTAssertFalse(
            error.localizedDescription.contains("error 0"),
            "NSError.localizedDescription should NOT contain the opaque ordinal 'error 0'"
        )
        XCTAssertTrue(
            error.localizedDescription.contains("ZUNKWN0001"),
            "NSError.localizedDescription should contain the error code ZUNKWN0001"
        )
    }

    // MARK: - Error code and message properties

    func testErrorCodeProperty() {
        let error = ZcashError.rustCreateToAddress(.stub)
        XCTAssertEqual(error.code, .rustCreateToAddress)
        XCTAssertEqual(error.code.rawValue, "ZRUST0002")
    }

    func testErrorMessageProperty() {
        let error = ZcashError.rustCreateToAddress(.stub)
        XCTAssertEqual(error.message, "Error from rust layer when calling ZcashRustBackend.createToAddress")
    }

    // MARK: - Migration error codes (R4-B)

    func testMigrationSyncBlockedErrorCode() {
        XCTAssertEqual(ZcashError.migrationSyncBlocked.code, .migrationSyncBlocked)
        XCTAssertEqual(ZcashError.migrationSyncBlocked.code.rawValue, "ZRUST0125")
    }

    func testMigrationBroadcastDuringSyncErrorCode() {
        XCTAssertEqual(ZcashError.migrationBroadcastDuringSync.code, .migrationBroadcastDuringSync)
        XCTAssertEqual(ZcashError.migrationBroadcastDuringSync.code.rawValue, "ZRUST0126")
    }
}

private extension RedactedRustError {
    static let stub = RedactedRustError(
        kind: .builderFailed,
        message: "the transaction builder returned an error"
    )
}
