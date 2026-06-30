//
//  NullBytesTests.swift
//  ZcashLightClientKit-Unit-Tests
//
//  Created by Francisco Gindre on 6/5/20.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

class NullBytesTests: XCTestCase {
    let networkType = NetworkType.mainnet

    func testZaddrNullBytes() throws {
        // this is a valid zAddr. if you send ZEC to it, you will be contributing to Human Rights Foundation. see more ways to help at https://paywithz.cash/
        let validZaddr = "zs1gqtfu59z20s9t20mxlxj86zpw6p69l0ev98uxrmlykf2nchj2dw8ny5e0l22kwmld2afc37gkfp"
        let zAddrWithNullBytes = "\(validZaddr)\0something else that makes the address invalid"

        XCTAssertFalse(DerivationTool(networkType: networkType).isValidSaplingAddress(zAddrWithNullBytes))
    }

    func testTaddrNullBytes() throws {
        // this is a valid tAddr. if you send ZEC to it, you will be contributing to Human Rights Foundation. see more ways to help at https://paywithz.cash/
        let validTAddr = "t1J5pTRzJi7j8Xw9VJTrPxPEkaigr69gKVT"
        let tAddrWithNullBytes = "\(validTAddr)\0fasdfasdf"

        XCTAssertFalse(DerivationTool(networkType: networkType).isValidTransparentAddress(tAddrWithNullBytes))
    }

    // TODO: [#716] fix, https://github.com/zcash/ZcashLightClientKit/issues/716
    func testderiveExtendedFullViewingKeyWithNullBytes() throws {
//        let wrongSpendingKeys = SaplingExtendedSpendingKey(validatedEncoding: "secret-extended-key-main1qw28psv0qqqqpqr2ru0kss5equx6h0xjsuk5299xrsgdqnhe0cknkl8uqff34prwkyuegyhh5d4rdr8025nl7e0hm8r2txx3fuea5mq\0uy3wnsr9tlajsg4wwvw0xcfk8357k4h850rgj72kt4rx3fjdz99zs9f4neda35cq8tn3848yyvlg4w38gx75cyv9jdpve77x9eq6rtl6d9qyh8det4edevlnc70tg5kse670x50764gzhy60dta0yv3wsd4fsuaz686lgszc7nc9vv") // this spending key corresponds to the "demo app reference seed"
//
//        let goodSpendingKeys = SaplingExtendedSpendingKey(validatedEncoding: "secret-extended-key-main1qw28psv0qqqqpqr2ru0kss5equx6h0xjsuk5299xrsgdqnhe0cknkl8uqff34prwkyuegyhh5d4rdr8025nl7e0hm8r2txx3fuea5mquy3wnsr9tlajsg4wwvw0xcfk8357k4h850rgj72kt4rx3fjdz99zs9f4neda35cq8tn3848yyvlg4w38gx75cyv9jdpve77x9eq6rtl6d9qyh8det4edevlnc70tg5kse670x50764gzhy60dta0yv3wsd4fsuaz686lgszc7nc9vv")
//
//        XCTAssertThrowsError(
//            try DerivationTool(networkType: networkType)deriveSaplingExtendedFullViewingKey(wrongSpendingKeys, networkType: networkType),
//            "Should have thrown an error but didn't! this is dangerous!"
//        ) { error in
//            guard let rustError = error as? RustWeldingError else {
//                XCTFail("Expected RustWeldingError")
//                return
//            }
//
//            switch rustError {
//            case .malformedStringInput:
//                XCTAssertTrue(true)
//            default:
//                XCTFail("expected \(RustWeldingError.malformedStringInput) and got \(rustError)")
//            }
//        }
//
//        XCTAssertNoThrow(try DerivationTool(networkType: networkType)deriveSaplingExtendedFullViewingKey(goodSpendingKeys, networkType: networkType))
    }

    func testCheckNullBytes() throws {
        // this is a valid zAddr. if you send ZEC to it, you will be contributing to Human Rights Foundation. see more ways to help at https://paywithz.cash/
        let validZaddr = "zs1gqtfu59z20s9t20mxlxj86zpw6p69l0ev98uxrmlykf2nchj2dw8ny5e0l22kwmld2afc37gkfp"

        XCTAssertFalse(validZaddr.containsCStringNullBytesBeforeStringEnding())
        XCTAssertTrue(
            "zs1gqtfu59z20s\u{0}9t20mxlxj86zpw6p69l0ev98uxrmlykf2nchj2dw8ny5e0l22kwmld2afc37gkfp"
                .containsCStringNullBytesBeforeStringEnding()
        )
        XCTAssertTrue("\u{0}".containsCStringNullBytesBeforeStringEnding())
        XCTAssertFalse("".containsCStringNullBytesBeforeStringEnding())
    }

    func testTrimTrailingNullBytes() throws {
        let nullTrailedString = "This Is a memo with text and trailing null bytes\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}"

        let nonNullTrailedString = "This Is a memo with text and trailing null bytes"

        let trimmedString = String(nullTrailedString.reversed().drop(while: { $0 == "\u{0}" }).reversed())

        XCTAssertEqual(trimmedString, nonNullTrailedString)
    }
}
