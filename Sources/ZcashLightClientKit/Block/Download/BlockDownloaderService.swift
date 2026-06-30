//
//  BlockDownloader.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 17/09/2019.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import Foundation

enum BlockDownloaderServiceError: Error {
    case timeout
    case generalError(error: Error)
}
/**
Represents what a compact block downloaded should provide to its clients
*/
protocol BlockDownloaderService {
    var storage: CompactBlockRepository { get }

    /**
    Downloads and stores the given block range.
    */
    func downloadBlockRange(_ heightRange: CompactBlockRange, mode: ServiceMode) async throws

    /**
    Restore the download progress up to the given height.
    */
    func rewind(to height: BlockHeight) async throws

    /**
    Returns the height of the latest compact block stored locally.
    BlockHeight.empty() if no blocks are stored yet
    */
    func lastDownloadedBlockHeight() async throws -> BlockHeight

    /**
    Returns the latest block height
    */
    func latestBlockHeight(mode: ServiceMode) async throws -> BlockHeight

    /**
    Gets the transaction for the Id given
    - Parameter txId: Data representing the transaction Id
    */
    func fetchTransaction(txId: Data, mode: ServiceMode) async throws -> (tx: ZcashTransaction.Fetched?, status: TransactionStatus)

    func fetchUnspentTransactionOutputs(tAddress: String, startHeight: BlockHeight, mode: ServiceMode) throws -> AsyncThrowingStream<UnspentTransactionOutputEntity, Error>

    func fetchUnspentTransactionOutputs(tAddresses: [String], startHeight: BlockHeight, mode: ServiceMode) throws -> AsyncThrowingStream<UnspentTransactionOutputEntity, Error>

    func closeConnections()
}

/**
Serves as a source of compact blocks received from the light wallet server. Once started, it will use the given
lightwallet service to request all the appropriate blocks and compact block store to persist them. By delegating to
these dependencies, the downloader remains agnostic to the particular implementation of how to retrieve and store
data; although, by default the SDK uses gRPC and SQL.
- Property lightwalletService: the service used for requesting compact blocks
- Property storage: responsible for persisting the compact blocks that are received
*/
class BlockDownloaderServiceImpl {
    let lightwalletService: LightWalletService
    let storage: CompactBlockRepository

    init(service: LightWalletService, storage: CompactBlockRepository) {
        self.lightwalletService = service
        self.storage = storage
    }
}

extension BlockDownloaderServiceImpl: BlockDownloaderService {
    func closeConnections() {
        Task {
            await lightwalletService.closeConnections()
        }
    }

    func fetchUnspentTransactionOutputs(
        tAddresses: [String],
        startHeight: BlockHeight,
        mode: ServiceMode
    ) throws -> AsyncThrowingStream<UnspentTransactionOutputEntity, Error> {
        try lightwalletService.fetchUTXOs(for: tAddresses, height: startHeight, mode: mode)
    }

    func fetchUnspentTransactionOutputs(tAddress: String, startHeight: BlockHeight, mode: ServiceMode) throws -> AsyncThrowingStream<UnspentTransactionOutputEntity, Error> {
        try lightwalletService.fetchUTXOs(for: tAddress, height: startHeight, mode: mode)
    }

    func latestBlockHeight(mode: ServiceMode) async throws -> BlockHeight {
        try await lightwalletService.latestBlockHeight(mode: mode)
    }

    func downloadBlockRange( _ heightRange: CompactBlockRange, mode: ServiceMode) async throws {
        let stream: AsyncThrowingStream<ZcashCompactBlock, Error> = try lightwalletService.blockRange(heightRange, mode: mode)
        do {
            var compactBlocks: [ZcashCompactBlock] = []
            for try await compactBlock in stream {
                compactBlocks.append(compactBlock)
            }
            try await self.storage.write(blocks: compactBlocks)
        } catch {
            throw ZcashError.blockDownloaderServiceDownloadBlockRange(error)
        }
    }

    func rewind(to height: BlockHeight) async throws {
        try await self.storage.rewind(to: height)
    }

    func lastDownloadedBlockHeight() async throws -> BlockHeight {
        try await self.storage.latestHeight()
    }

    func fetchTransaction(txId: Data, mode: ServiceMode) async throws -> (tx: ZcashTransaction.Fetched?, status: TransactionStatus) {
        try await lightwalletService.fetchTransaction(txId: txId, mode: mode)
    }
}
