//
//  MemoTests.swift
//  ZcashLightClientKit-Unit-Tests
//
//  Created by Francisco Gindre on 4/23/20.
//

import XCTest
@testable import ZcashLightClientKit

class MemoTests: XCTestCase {
    /**
    Non-utf8 memos are properly ignored
    */
    func testNonUnicodeMemos() throws {
        XCTAssertNil(Self.randomMemoData()!.asZcashTransactionMemo())
    }

    /**
    Memo length is correct, padding characters are ignored
    */
    func testMemoLength() throws {
        XCTAssertEqual(validMemoData.count, 512)
        XCTAssertEqual(
            validMemoData.asZcashTransactionMemo()!.trimmingCharacters(in: .controlCharacters).count,
            Self.validMemoDataExpectedString.count
        )
    }
    /**
    Verify support for common unicode characters
    */
    func testUnicodeCharacters() throws {
        let memo = validMemoData.asZcashTransactionMemo()!.trimmingCharacters(in: .controlCharacters)
        XCTAssertNotNil(memo)
        XCTAssertEqual(memo, Self.validMemoDataExpectedString)
    }

    func testEmojiUnicodeCharacters() throws {
        let memo = Self.emojiMemoData.asZcashTransactionMemo()!.trimmingCharacters(in: .controlCharacters)
        XCTAssertNotNil(memo)
        XCTAssertEqual(memo, Self.expectedEmojiMemoString)
    }

    /**
    Blank memos are ignored
    */
    func testBlankMemos() throws {
        // This is an example of a functional test case.
        XCTAssertEqual(emptyMemoData.asZcashTransactionMemo(), String(data: emptyMemoData, encoding: .utf8))
    }

    /**
    test canonical memos
    */
    func testCanonicalBlankMemos() throws {
        XCTAssertNil(Self.canonicalEmptyMemo().asZcashTransactionMemo())
    }

    /* Test conversion to string */

    func testEmptyMemoToString() {
        let memo: Memo = .empty
        XCTAssertNil(memo.toString())
    }

    func testTextMemoToString() throws {
        let memo: Memo = .text(try MemoText(Self.validMemoDataExpectedString))
        XCTAssertEqual(memo.toString(), Self.validMemoDataExpectedString)
    }

    func testFutureMemoToString() throws {
        let memo: Memo = .future(try MemoBytes(bytes: Self.validMemoDataExpectedString.data(using: .utf8)!.bytes))
        XCTAssertNil(memo.toString())
    }

    func testArbitraryMemoToString() {
        let memo: Memo = .arbitrary(Self.validMemoDataExpectedString.data(using: .utf8)!.bytes)
        XCTAssertNil(memo.toString())
    }

    func testEmptyTextMemo() throws {
        let emptyMemoBytes = try MemoBytes(bytes: [])

        XCTAssertNoThrow(try emptyMemoBytes.intoMemo())
    }

    /**
    *******
    * mocked memos
    * ******
    */

    /**
    Real text:  "Here's gift from the Zec Fairy @ ECC!"
    */
    static let validMemoDataExpectedString = "Here's gift from the Zec Fairy @ ECC!"

    static let validMemoDataBase64 = """
    SGVyZSdzIGdpZnQgZnJvbSB0aGUgWmVjIEZhaXJ5IEAgRUNDIQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    """

    let validMemoData = Data(base64Encoded: validMemoDataBase64)!

    let emptyMemoData = Data([UInt8](repeating: 0, count: 512))

    let totallyRandomDataMemo = randomMemoData()!

    static let emojiDataBase64 = """
    8J+SlfCfkpXwn5KV8J+mk/CfppPwn6aT8J+bofCfm6Hwn5uhAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    """

    static let emojiMemoData = Data(base64Encoded: emojiDataBase64)!

    static let expectedEmojiMemoString = "💕💕💕🦓🦓🦓🛡🛡🛡"

    static func canonicalEmptyMemo() -> Data {
        var bytes = [UInt8](repeating: 0, count: 512)
        bytes[0] = UInt8(0xF6)
        return Data(bytes: &bytes, count: 512)
    }

    static func randomMemoData() -> Data? {
        let length: Int = 512
        var keyData = Data(count: length)
        let result = keyData.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, length, $0.baseAddress!)
        }
        if result == errSecSuccess {
            return keyData
        } else {
            print("Problem generating random bytes")
            return nil
        }
    }
}
