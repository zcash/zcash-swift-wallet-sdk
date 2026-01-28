//
//  FakeStorage.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 12/09/2019.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//
import Foundation
@testable import ZcashLightClientKit

class ZcashConsoleFakeStorage: CompactBlockRepository {
    func createDirectories() throws {}

    func create() async throws {}

    func clear(upTo height: ZcashLightClientKit.BlockHeight) async throws { }
    
    func clear() async throws {}

    func wipe() throws {}

    func write(blocks: [ZcashCompactBlock]) async throws {
        fakeSave(blocks: blocks)
    }

    func latestHeight() async -> BlockHeight {
        return self.latestBlockHeight
    }

    func latestBlock() throws -> ZcashLightClientKit.ZcashCompactBlock {
        return ZcashCompactBlock(
            height: latestBlockHeight,
            data: Data(),
            meta: ZcashCompactBlock.Meta(
                hash: Data(),
                time: 1,
                saplingOutputs: 2,
                orchardOutputs: 2
            )
        )
    }

    func rewind(to height: BlockHeight) async throws {
        fakeRewind(to: height)
    }
    
    var latestBlockHeight: BlockHeight = 0
    var delay = DispatchTimeInterval.milliseconds(300)
    
    init(latestBlockHeight: BlockHeight = 0) {
        self.latestBlockHeight = latestBlockHeight
    }
    
    private func fakeSave(blocks: [ZcashCompactBlock]) {
        blocks.forEach {
            LoggerProxy.debug("saving block \($0)")
            self.latestBlockHeight = $0.height
        }
    }
    
    private func fakeRewind(to height: BlockHeight) {
        LoggerProxy.debug("rewind to \(height)")
        self.latestBlockHeight = min(self.latestBlockHeight, height)
    }
}

struct SandblastSimulator {
    ///  Creates an array of Zcash CompactBlock from a mainnet sandblasted block of 500K bytes
    ///  this is not good for syncing but for performance benchmarking of block storage.
    func sandblast(with range: CompactBlockRange) throws -> [ZcashCompactBlock]? {
        let jsonFile = Bundle.module.url(forResource: "sandblasted_mainnet_block", withExtension: "json")!
        let fileHandle = try FileHandle(forReadingFrom: jsonFile)

        let sandblastedBlock = try CompactBlock(jsonUTF8Data: fileHandle.availableData)

        return [CompactBlock](repeating: sandblastedBlock, count: range.count)
            .enumerated()
            .map { sandblastedBlock in
                let height = range.lowerBound + sandblastedBlock.offset
                
                var block = sandblastedBlock.element
                
                block.height = UInt64(height)
                
                return block
            }
            .asZcashCompactBlocks()
    }
}
