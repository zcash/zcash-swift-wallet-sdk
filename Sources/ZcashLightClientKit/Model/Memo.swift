//
//  Memo.swift
//
//
//  Created by Pacu on 5/11/22.
//

import Foundation

public enum Memo: Equatable {
    case empty
    case text(MemoText)
    case future(MemoBytes)
    case arbitrary([UInt8])

    /// Parses the given bytes as in ZIP-302
    public init(bytes: [UInt8]) throws {
        self = try MemoBytes(bytes: bytes).intoMemo()
    }

    /// Converts these memo bytes into a ZIP-302 Memo
    public init(memoBytes: MemoBytes) throws {
        self = try memoBytes.intoMemo()
    }

    /// Creates a `.text(TextMemo)` Memo using the `UTF8View` of the given string
    /// - Throws:
    ///   - `MemoBytes.Errors.tooLong(length)` if the UTF-8 length
    /// of this string is greater than `MemoBytes.capacity`  (512 bytes)
    public init(string: String) throws {
        self = .text(try MemoText(String(string.utf8)))
    }

    /// Represent memo as String. Only `.text` memo can be represented as String.
    /// - Returns: Valid String if it can be created from memo; otherwise `nil`.
    public func toString() -> String? {
        switch self {
        case .empty, .future, .arbitrary:
            return nil

        case .text(let text):
            return text.string
        }
    }
}

public extension Memo {
    /// Use this function to know the size of this text in memo bytes.
    /// - Parameter memotext: the string you want to turn into a
    /// a memo.
    /// - Returns: the size of this string in bytes using UTF-8 encoding.
    /// - note: According to ZIP-302, memos have a length limit of 512 bytes.
    /// Attempting to create a memo that exceeds that capacity will
    /// throw an error.
    static func length(for memoText: String) -> Int {
        memoText.lengthOfBytes(using: .utf8)
    }
}

public extension Memo {
    func asMemoBytes() throws -> MemoBytes {
        switch self {
        case .empty:
            return MemoBytes.empty()

        case .text(let textMemo):
            guard let bytes = textMemo.string.data(using: .utf8)?.bytes else {
                throw ZcashError.memoTextInvalidUTF8
            }

            return try MemoBytes(bytes: bytes)

        case .future(let memoBytes):
            return memoBytes

        case .arbitrary(var arbitraryBytes):
            arbitraryBytes.insert(0xFF, at: 0)
            return try MemoBytes(bytes: arbitraryBytes)
        }
    }
}

/// A wrapper on `String` so that `Memo` can't be created with an invalid String
public struct MemoText: Equatable {
    public let string: String

    init(_ string: String) throws {
        let trimmedString = String(string.reversed().drop(while: { $0 == "\u{0}" }).reversed())

        guard trimmedString.count == string.count else {
            throw ZcashError.memoTextInputEndsWithNullBytes
        }

        guard string.utf8.count <= MemoBytes.capacity else {
            throw ZcashError.memoTextInputTooLong(string.utf8.count)
        }

        self.string = string
    }
}

public struct MemoBytes: Equatable {
    public enum Errors: Error {
        /// Invalid UTF-8 Bytes where detected when attempting to create a Text Memo
        case invalidUTF8
        /// Trailing null-bytes were found when attempting to create a Text memo
        case endsWithNullBytes
        /// the resulting bytes provided are too long to be stored as a Memo in any of its forms.
        case tooLong(Int)
    }

    public static let capacity: Int = 512

    public let bytes: [UInt8]

    /// Copies the given bytes into the inner array if this struct in the context of ZIP-302
    /// and returns a `MemoBytes`  struct
    /// - Throws: `Errors.tooLong(bytes.count)` if the count is greater than
    /// 512 bytes.
    ///
    public init(bytes: [UInt8]) throws {
        guard bytes.count <= Self.capacity else { throw ZcashError.memoBytesInputTooLong(bytes.count) }

        var rawBytes = [UInt8](repeating: 0x0, count: Self.capacity)

        // replacing range is quite slow an inefficient. Use bare metal impl
        _ = bytes.withUnsafeBufferPointer { ptr in
            memmove(&rawBytes[0], ptr.baseAddress, ptr.count)
        }

        self.bytes = rawBytes
    }

    init(contiguousBytes: ContiguousArray<UInt8>) throws {
        guard contiguousBytes.capacity <= Self.capacity else { throw ZcashError.memoBytesInputTooLong(contiguousBytes.capacity) }

        var rawBytes = [UInt8](repeating: 0x0, count: Self.capacity)

        _ = contiguousBytes.withUnsafeBufferPointer { ptr in
            memmove(&rawBytes[0], ptr.baseAddress, ptr.count)
        }

        self.bytes = rawBytes
    }

    public static func empty() -> Self {
        // swiftlint:disable:next force_try
        try! Self(bytes: .emptyMemoBytes)
    }
}

public extension MemoBytes {
    /// Parsing of the MemoBytes in terms of ZIP-302 Specification
    /// See https://zips.z.cash/zip-0302#specification
    /// - Returns:
    ///   - `.text(MemoText)` If the first byte (byte 0) has a value of 0xF4 or smaller
    ///   - `.future(MemoBytes)`  If the memo matches any of these patterns, then this memo is from the future,
    ///     because these ranges are reserved for future updates to this specification:
    ///      - The first byte has a value of 0xF5.
    ///      - The first byte has a value of 0xF6, and the remaining 511 bytes are not all 0x00.
    ///      - The first byte has a value between 0xF7 and 0xFE inclusive.
    ///   - `.arbitrary(Bytes)` when the first byte is 0xFF. The Bytes don't include the 0xFF leading byte.
    /// - Throws:
    ///  - `MemoBytes.Errors.invalidUTF8` when the case of Text memo is found but then invalid UTF-8 is found
    func intoMemo() throws -> Memo {
        switch self.bytes[0] {
        case 0x00 ... 0xF4:
            let unpaddedBytes = self.unpaddedRawBytes()
            guard let validatedUTF8String = String(bytes: unpaddedBytes, encoding: .utf8) else {
                throw ZcashError.memoBytesInvalidUTF8
            }

            return .text(try MemoText(validatedUTF8String))

        case 0xF5:
            return Memo.future(self)

        case 0xF6:
            return self.bytes.dropFirst().first(where: { $0 != 0 }) == nil ?
                Memo.empty :
                Memo.future(self)

        case 0xF7 ... 0xFE:
            return Memo.future(self)

        case 0xFF:
            return .arbitrary([UInt8](bytes[1...]))

        default:
            return .future(self)
        }
    }
}

extension MemoBytes {
    ///  Returns raw bytes, excluding null padding
    func unpaddedRawBytes() -> [UInt8] {
        self.bytes.unpaddedRawBytes()
    }
}

extension Array where Element == UInt8 {
    static var emptyMemoBytes: [UInt8] {
        var emptyMemo = [UInt8](repeating: 0x00, count: MemoBytes.capacity)
        emptyMemo[0] = 0xF6
        return emptyMemo
    }

    func unpaddedRawBytes() -> [UInt8] {
        guard let lastNullByte = self.enumerated()
            .reversed()
            .first(where: { $0.1 != 0 })
            .map({ $0.0 + 1 }) else {
                return []
        }

        return [UInt8](self[0 ..< lastNullByte])
    }
}

extension Optional where WrappedType == String {
    func intoMemo() throws -> Memo {
        switch self {
        case .none:
            return .empty
        case .some(let string):
            return try Memo(string: string)
        }
    }
}

extension Data {
    func intoMemoBytes() throws -> MemoBytes? {
        try MemoBytes(bytes: self.bytes)
    }
}
