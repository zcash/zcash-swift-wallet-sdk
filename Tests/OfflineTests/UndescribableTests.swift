//
//  UndescribableTests.swift
//
//
//  Created by Francisco Gindre on 8/30/22.
//

import XCTest
@testable import ZcashLightClientKit

struct SomeStructure: Undescribable {
    var info: String
}

enum SomeError: Error {
    case sensitiveThingFailed(SomeStructure)
}

struct EnclosingStruct {
    var someStructure: SomeStructure
}

final class UndescribableTests: XCTestCase {
    func testDescriptionIsRedacted() throws {
        let info = "important info"
        let someStructure = SomeStructure(info: info)

        let description = String(describing: someStructure)
        XCTAssertFalse(description.contains(info))
        XCTAssertEqual(description, "--redacted--")
    }

    func testDumpIsRedacted() {
        let info = "important info"
        let someStructure = SomeStructure(info: info)
        var stream = ""
        dump(someStructure, to: &stream, indent: 0)
        XCTAssertFalse(stream.contains(info))
        XCTAssertEqual(stream, "- --redacted--\n")
    }

    func testPrintIsRedacted() {
        let info = "important info"
        let someStructure = SomeStructure(info: info)
        var stream = ""

        print(someStructure, to: &stream)
        XCTAssertFalse(stream.contains(info))
        XCTAssertEqual(stream, "--redacted--\n")
    }

    func testMirroringIsRedacted() {
        let info = "important info"
        let someStructure = SomeStructure(info: info)
        var str = ""
        debugPrint(someStructure, to: &str)
        XCTAssertFalse(str.contains(info))
        XCTAssertEqual(str, "--redacted--\n")
    }

    func testLocalizedErrorIsRedacted() {
        let info = "importantInfo"
        let description = "\(SomeError.sensitiveThingFailed(SomeStructure(info: info)))"
        XCTAssertFalse(description.contains(info))
        XCTAssertEqual(description, "sensitiveThingFailed(--redacted--)")
    }

    func testNestedStructuresCantDescribeUndescribable() {
        let info = "important info"
        let nested = EnclosingStruct(someStructure: SomeStructure(info: info))

        var dumpStream = ""
        dump(nested, to: &dumpStream)
        XCTAssertFalse(dumpStream.contains(info))

        var debugStream = ""

        debugPrint(nested, to: &debugStream)
        XCTAssertFalse(debugStream.contains(info))
        var printStream = ""

        print(nested, to: &printStream)
        XCTAssertFalse(printStream.contains(info))

        XCTAssertFalse(String(describing: nested).contains(info))
    }

    func testSpendingKeyCantBeDescribed() {
        let key = SaplingExtendedFullViewingKey(
            validatedEncoding: """
            zxviewtestsapling1qdxykmuaqqqqpqqg3x5c02p4rhw0rtszr8ln4xl7g6wg6qzsqgn445qsu3cq4vd6l5smlqrckkl2x5rnrauzc4gp665q3zyw0qf2sfdsx5wpp832htfavq\
            k72uchuuvq2dpmgk8jfaza5t5l56u66fpx0sr8ewp9s3wj2txavmhhlazn5rj8mshh470fkrmzg4xarhrqlygg8f486307ujhndwhsw2h7ddzf89k3534aeu0ypz2tjgrzlcqtat\
            380vhe8awm03f58cqgegsaj
            """
        )

        var str = ""
        debugPrint(key, to: &str)

        XCTAssertEqual(str, "--redacted--\n")
    }
}
