//
//  ZcashCompactBlock.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 12/09/2019.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import Foundation

public typealias BlockHeight = Int
public typealias CompactBlockRange = ClosedRange<BlockHeight>

extension BlockHeight {
    static func empty() -> BlockHeight {
        BlockHeight(-1)
    }
}

/**
A Zcash compact block to store on cache DB
*/
public struct ZcashCompactBlock {
    struct Meta {
        let hash: Data
        let time: UInt32
        let saplingOutputs: UInt32
        let orchardOutputs: UInt32
    }

    public let height: BlockHeight
    public let data: Data

    let meta: Meta
}

extension ZcashCompactBlock: Encodable {
    enum CodingKeys: CodingKey {
        case height
        case data
        case meta
    }

    public func encode(to encoder: Encoder) throws {
        do {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(data, forKey: .data)
            try container.encode(height, forKey: .height)
        } catch {
            throw ZcashError.compactBlockEncode(error)
        }
    }
}

extension ZcashCompactBlock {
    init(compactBlock: CompactBlock) {
        self.height = Int(compactBlock.height)
        self.data = (try? compactBlock.serializedData()) ?? Data()
        let outputs = compactBlock.outputCount
        self.meta = Meta(
            hash: compactBlock.hash,
            time: compactBlock.time,
            saplingOutputs: outputs.0,
            orchardOutputs: outputs.1
        )
    }
}

extension CompactBlock {
    /// O(n) sum of all CompactTx sapling outputs and Orchard Actions
    /// - Returns: a tuple (SaplingOutputs, OrchardActions)
    var outputCount: (UInt32, UInt32) {
        vtx.compactMap { compactTx -> (UInt32, UInt32) in
            (UInt32(compactTx.outputs.count), UInt32(compactTx.actions.count))
        }
        .reduce((0, 0)) { partialResult, txOutputActionPair in
            (partialResult.0 + txOutputActionPair.0, partialResult.1 + txOutputActionPair.1)
        }
    }
}
extension ZcashCompactBlock: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        if lhs.height != rhs.height {
            return false
        }

        return lhs.data == rhs.data
    }
}

extension ZcashCompactBlock: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(height)
        hasher.combine(data)
    }
}
