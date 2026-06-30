//
//  ZcashSDK+extensions.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 12/8/20.
//

import Foundation

public typealias ConsensusBranchID = Int32

public extension ConsensusBranchID {
    func toString() -> String {
        String(format: "%02x", self)
    }

    static func fromString(_ str: String) -> ConsensusBranchID? {
        guard let bitpattern = UInt32(str, radix: 16) else { return nil }
        return Int32(bitPattern: bitpattern)
    }
}

extension NetworkType {
    init?(_ string: String) {
        switch string {
        case "main":
            self = .mainnet
        case "test":
            self = .testnet
        default:
            return nil
        }
    }
}
