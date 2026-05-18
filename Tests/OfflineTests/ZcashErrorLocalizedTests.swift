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
        let error = ZcashError.rustCreateToAddress("Insufficient funds")
        XCTAssertTrue(
            error.localizedDescription.contains("ZRUST0002"),
            "localizedDescription should contain the error code but got: \(error.localizedDescription)"
        )
    }

    func testLocalizedDescriptionContainsMessage() {
        let error = ZcashError.rustCreateToAddress("Insufficient funds")
        XCTAssertTrue(
            error.localizedDescription.contains("Error from rust layer when calling ZcashRustBackend.createToAddress"),
            "localizedDescription should contain the human-readable message but got: \(error.localizedDescription)"
        )
    }

    func testLocalizedDescriptionFormat() {
        let error = ZcashError.rustCreateToAddress("Insufficient funds")
        XCTAssertEqual(
            error.localizedDescription,
            "ZRUST0002: Error from rust layer when calling ZcashRustBackend.createToAddress"
        )
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
        let error = ZcashError.rustCreateToAddress("some rust error")
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
        let error = ZcashError.rustCreateToAddress("test")
        XCTAssertEqual(error.code, .rustCreateToAddress)
        XCTAssertEqual(error.code.rawValue, "ZRUST0002")
    }

    func testErrorMessageProperty() {
        let error = ZcashError.rustCreateToAddress("test")
        XCTAssertEqual(error.message, "Error from rust layer when calling ZcashRustBackend.createToAddress")
    }
}
