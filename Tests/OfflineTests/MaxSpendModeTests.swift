//
//  MaxSpendModeTests.swift
//  ZcashLightClientKitTests
//
//  Created by Michal Fousek on 2026-07-29.
//

import XCTest
import libzcashlc
@testable import ZcashLightClientKit

final class MaxSpendModeTests: XCTestCase {
    func testMaxSpendableMapsToFfiMaxSpendable() throws {
        XCTAssertEqual(MaxSpendMode.maxSpendable.ffiMode, MaxSpendable)
    }

    func testEverythingMapsToFfiEverything() throws {
        XCTAssertEqual(MaxSpendMode.everything.ffiMode, Everything)
    }

    func testTheTwoModesMapToDifferentFfiValues() throws {
        XCTAssertNotEqual(MaxSpendMode.maxSpendable.ffiMode, MaxSpendMode.everything.ffiMode)
    }
}
