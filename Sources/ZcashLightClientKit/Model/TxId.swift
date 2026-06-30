//
//  TxId.swift
//  ZcashLightClientKit
//
//  Created by Lukáš Korba on 2026-27-11.
//

import Foundation

public struct TxId: Equatable, Hashable, Identifiable {
    public var id: [UInt8]

    private static func txIdStringToBytes(_ txId: String) throws -> [UInt8] {
        guard txId.count == 64 else {
            throw ZcashError.txIdNot32Bytes
        }

        var bytes: [UInt8] = []
        bytes.reserveCapacity(txId.count / 2)

        var index = txId.startIndex

        while index < txId.endIndex {
            let nextIndex = txId.index(index, offsetBy: 2)
            let byteString = txId[index..<nextIndex]

            if let byte = UInt8(byteString, radix: 16) {
                bytes.append(byte)
            } else {
                throw ZcashError.txIdInvalidHexEncoding
            }

            index = nextIndex
        }

        return bytes.reversed()
    }

    public init(_ id: [UInt8]) {
        self.id = id
    }

    public init(_ id: String) throws {
        self.id = try TxId.txIdStringToBytes(id)
    }
}
