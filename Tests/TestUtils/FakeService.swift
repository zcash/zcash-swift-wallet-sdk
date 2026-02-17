//
//  FakeService.swift
//  ZcashLightClientKitTests
//
//  Created by Francisco Gindre on 10/23/19.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import Foundation
import SwiftProtobuf
@testable import ZcashLightClientKit

struct LightWalletServiceMockResponse: LightWalletServiceResponse {
    var errorCode: Int32
    var errorMessage: String
    var unknownFields: UnknownStorage
}

struct MockCancellable: CancellableCall {
    func cancel() {}
}

class MockLightWalletService: LightWalletService {
    func getTaddressTxids(_ request: ZcashLightClientKit.TransparentAddressBlockFilter, mode: ServiceMode) throws -> AsyncThrowingStream<ZcashLightClientKit.RawTransaction, any Error> {
        try service.getTaddressTxids(request, mode: mode)
    }
    
    var connectionStateChange: ((ZcashLightClientKit.ConnectionState, ZcashLightClientKit.ConnectionState) -> Void)? {
        get { service.connectionStateChange }
        set { service.connectionStateChange = newValue }
    }
    var mockLightDInfo: LightWalletdInfo?
    var queue = DispatchQueue(label: "mock service queue")

    func blockStream(startHeight: BlockHeight, endHeight: BlockHeight, mode: ServiceMode) throws -> AsyncThrowingStream<ZcashCompactBlock, Error> {
        try service.blockStream(startHeight: startHeight, endHeight: endHeight, mode: mode)
    }

    func latestBlock(mode: ServiceMode) async throws -> ZcashLightClientKit.BlockID {
        throw "Not mocked"
    }

    func closeConnections() async {
    }

    func fetchUTXOs(for tAddress: String, height: BlockHeight, mode: ServiceMode) throws -> AsyncThrowingStream<UnspentTransactionOutputEntity, Error> {
        try service.fetchUTXOs(for: tAddress, height: height, mode: mode)
    }

    func fetchUTXOs(for tAddresses: [String], height: BlockHeight, mode: ServiceMode) throws -> AsyncThrowingStream<UnspentTransactionOutputEntity, Error> {
        try service.fetchUTXOs(for: tAddresses, height: height, mode: mode)
    }

    private var service: LightWalletService
    
    var latestHeight: BlockHeight

    init(latestBlockHeight: BlockHeight, service: LightWalletService) {
        self.latestHeight = latestBlockHeight
        self.service = service
    }
    
    func latestBlockHeight(mode: ServiceMode) async throws -> BlockHeight {
        latestHeight
    }

    func getInfo(mode: ServiceMode) async throws -> LightWalletdInfo {
        guard let info = mockLightDInfo else {
            throw ZcashError.serviceGetInfoFailed(.generalError(message: "Not Implemented"))
        }
        return info
    }

    func blockRange(_ range: CompactBlockRange, mode: ServiceMode) throws -> AsyncThrowingStream<ZcashCompactBlock, Error> {
        try service.blockRange(range, mode: mode)
    }
    
    func submit(spendTransaction: Data, mode: ServiceMode) async throws -> LightWalletServiceResponse {
        LightWalletServiceMockResponse(errorCode: 0, errorMessage: "", unknownFields: UnknownStorage())
    }

    func fetchTransaction(txId: Data, mode: ServiceMode) async throws -> (tx: ZcashTransaction.Fetched?, status: TransactionStatus) {
        return (nil, .txidNotRecognized)
    }

    func getSubtreeRoots(_ request: ZcashLightClientKit.GetSubtreeRootsArg, mode: ServiceMode) throws -> AsyncThrowingStream<ZcashLightClientKit.SubtreeRoot, Error> {
        try service.getSubtreeRoots(request, mode: mode)
    }
    
    func getTreeState(_ id: BlockID, mode: ServiceMode) async throws -> TreeState {
        try await service.getTreeState(id, mode: mode)
    }
    
    func getMempoolStream() throws -> AsyncThrowingStream<RawTransaction, any Error> {
        try service.getMempoolStream()
    }
    
    @DBActor
    func checkSingleUseTransparentAddresses(
        dbHandle: OpaquePointer,
        accountUUID: AccountUUID,
        mode: ServiceMode
    ) async throws -> TransparentAddressCheckResult {
        .notFound
    }

    @DBActor
    func updateTransparentAddressTransactions(
        address: String,
        start: BlockHeight,
        end: BlockHeight,
        dbHandle: OpaquePointer,
        mode: ServiceMode
    ) async throws -> TransparentAddressCheckResult {
        .notFound
    }

    @DBActor
    func fetchUTXOsByAddress(
        address: String,
        dbHandle: OpaquePointer,
        accountUUID: AccountUUID,
        mode: ServiceMode
    ) async throws -> TransparentAddressCheckResult {
        .notFound
    }
}
