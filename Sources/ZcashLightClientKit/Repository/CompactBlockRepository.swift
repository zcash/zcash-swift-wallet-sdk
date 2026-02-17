//
//  CompactBlockStoring.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 12/09/2019.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import Foundation

protocol CompactBlockRepository {
    /// Creates the underlying directory structure without initializing the metadata database.
    /// Call this before opening database handles.
    func createDirectories() throws

    /// Creates the underlying repository (directories + metadata database).
    /// Requires database handles to be open first.
    func create() async throws

    /**
    Gets the height of the highest block that is currently stored.
    */
    func latestHeight() async throws -> BlockHeight

    /**
    Write the given blocks to this store, which may be anything from an in-memory cache to a DB.
    - Parameters:
        - Parameter blocks: array of blocks to be written to storage
        - Throws: an error when there's a failure
    */
    func write(blocks: [ZcashCompactBlock]) async throws

    /**
    Remove every block above and including the given height.
     
    After this operation, the data store will look the same as one that has not yet stored the given block height.
    Meaning, if max height is 100 block and rewindTo(50) is called, then the highest block remaining will be 49.
     
    - Parameter height: the height to rewind to
    */
    func rewind(to height: BlockHeight) async throws

    /// Clear only blocks with height lower or equal than `height` from the repository.
    func clear(upTo height: BlockHeight) async throws

    /// Clears the repository and reinitializes (for use during sync)
    func clear() async throws

    /// Clears the repository without reinitializing (for use during wipe)
    func wipe() throws
}
