//
//  CreatedTransactionTests.swift
//  ZcashLightClientKitTests
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class CreatedTransactionTests: ZcashTestCase {
    func testInitFromOverviewMapsFields() throws {
        let raw = Data([0x01, 0x02, 0x03])
        let rawID = Data(repeating: 0xAB, count: 32)
        let overview = Self.makeTransaction(raw: raw, rawID: rawID)

        let created = try CreatedTransaction(overview: overview)

        XCTAssertEqual(created.txId, rawID)
        XCTAssertEqual(created.raw, raw)
        XCTAssertEqual(created.expiryHeight, 123_456)
        XCTAssertEqual(created.encodedTransaction, EncodedTransaction(transactionId: rawID, raw: raw))
    }

    func testInitFromOverviewWithoutRawThrowsNotEncoded() {
        let rawID = Data(repeating: 0xCD, count: 32)
        let overview = Self.makeTransaction(raw: nil, rawID: rawID)

        XCTAssertThrowsError(try CreatedTransaction(overview: overview)) { error in
            guard case let TransactionEncoderError.notEncoded(txId) = error else {
                XCTFail("Expected notEncoded but got \(error)")
                return
            }
            XCTAssertEqual(txId, rawID)
        }
    }

    func testSubmissionTimingDefault() {
        XCTAssertEqual(SubmissionTiming.default.responseTimeout, 30)
        XCTAssertEqual(SubmissionTiming.default.postAcceptanceGraceDelay, 5)
    }

    static func makeTransaction(raw: Data?, rawID: Data) -> ZcashTransaction.Overview {
        ZcashTransaction.Overview(
            accountUUID: TestsData.mockedAccountUUID,
            blockTime: nil,
            expiryHeight: 123_456,
            fee: Zatoshi(10_000),
            index: 0,
            isShielding: false,
            hasChange: false,
            memoCount: 0,
            minedHeight: nil,
            raw: raw,
            rawID: rawID,
            receivedNoteCount: 0,
            sentNoteCount: 1,
            value: Zatoshi(-1_000),
            isExpiredUmined: false,
            totalSpent: nil,
            totalReceived: nil
        )
    }
}
