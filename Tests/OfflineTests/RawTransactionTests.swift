//
//  SubmitTransactionTests.swift
//  ZcashLightClientKit-Unit-Tests
//
//  Created by Francisco Gindre on 12/10/19.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit
@testable import SwiftProtobuf

class RawTransactionTests: XCTestCase {
    var rawTx: Data!
    var transactionRepository: TransactionSQLDAO!

    let txFromAndroidSDK = String(bytes: TestCoordinator.loadResource(name: "txFromAndroidSDK", extension: "txt"), encoding: .utf8)!
        .trimmingCharacters(in: .whitespacesAndNewlines)

    let txBase64String = String(bytes: TestCoordinator.loadResource(name: "txBase64String", extension: "txt"), encoding: .utf8)!
        .trimmingCharacters(in: .whitespacesAndNewlines)

    override func setUp() {
        super.setUp()
        rawTx = Data(base64Encoded: txBase64String)
    }

    override func tearDown() {
        super.tearDown()
        transactionRepository = nil
    }

    func testDeserialize() {
        guard let raw = Data(base64Encoded: txFromAndroidSDK) else {
            XCTFail("no raw data")
            return
        }

        let rawTransaction = RawTransaction.with({ rawTr in
            rawTr.data = raw
        })

        XCTAssertNotNil(rawTransaction)
    }
}
