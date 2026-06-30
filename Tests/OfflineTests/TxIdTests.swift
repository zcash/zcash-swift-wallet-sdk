//
//  TxIdTests.swift
//  ZcashLightClientKit-Unit-Tests
//
//  Created by Francisco Gindre on 1/10/20.
//

import XCTest
@testable import TestUtils

class TxIdTests: XCTestCase {
    func testTxIdAsString() {
        let transactionId = "5cf915c5d01007c39d602e08ab59d98aba366e2fb7ac01f2cdad4bf4f8f300bb"
        let expectedTxIdString = "bb00f3f8f44badcdf201acb72f6e36ba8ad959ab082e609dc30710d0c515f95c"

        XCTAssertEqual(Data(fromHexEncodedString: transactionId)!.toHexStringTxId(), expectedTxIdString)
    }
}
