//
//  Protocolbuffer+Extensions.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 12/09/2019.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import Foundation

extension CompactBlockRange {
    func blockRange() -> BlockRange {
        BlockRange(startHeight: lowerBound, endHeight: upperBound)
    }
}

extension BlockID {
    init(height: UInt64) {
        self = BlockID()
        self.height = height
    }

    init(height: BlockHeight) {
        self.init(height: UInt64(height))
    }

    func compactBlockHeight() -> BlockHeight? {
        BlockHeight(exactly: self.height)
    }
}

extension BlockRange {
    init(startHeight: Int, endHeight: Int? = nil) {
        self = BlockRange()
        self.start = BlockID(height: UInt64(startHeight))
        if let endHeight {
            self.end = BlockID(height: UInt64(endHeight))
        }
    }

    var compactBlockRange: CompactBlockRange {
        return Int(self.start.height) ... Int(self.end.height)
    }
}

extension Array where Element == CompactBlock {
    func asZcashCompactBlocks() -> [ZcashCompactBlock] {
        self.map { ZcashCompactBlock(compactBlock: $0) }
    }
}
