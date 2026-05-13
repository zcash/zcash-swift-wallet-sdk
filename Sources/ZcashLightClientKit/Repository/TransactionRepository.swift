//
//  TransactionRepository.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 11/16/19.
//

import Foundation

protocol TransactionRepository {
    func closeDBConnection()
    func countAll() async throws -> Int
    func countUnmined() async throws -> Int
    func isInitialized() async throws -> Bool
    func fetchTxidsWithMemoContaining(searchTerm: String) async throws -> [Data]
    func find(rawID: Data) async throws -> ZcashTransaction.Overview
    func find(offset: Int, limit: Int, kind: TransactionKind) async throws -> [ZcashTransaction.Overview]
    func find(in range: CompactBlockRange, limit: Int, kind: TransactionKind) async throws -> [ZcashTransaction.Overview]
    func find(from: ZcashTransaction.Overview, limit: Int, kind: TransactionKind) async throws -> [ZcashTransaction.Overview]
    func findPendingTransactions(latestHeight: BlockHeight, offset: Int, limit: Int) async throws -> [ZcashTransaction.Overview]
    func findReceived(offset: Int, limit: Int) async throws -> [ZcashTransaction.Overview]
    func findSent(offset: Int, limit: Int) async throws -> [ZcashTransaction.Overview]
    func findForResubmission(upTo: BlockHeight) async throws -> [ZcashTransaction.Overview]
    // sourcery: mockedName="findMemosForRawID"
    func findMemos(for rawID: Data) async throws -> [Memo]
    // sourcery: mockedName="findMemosForZcashTransaction"
    func findMemos(for transaction: ZcashTransaction.Overview) async throws -> [Memo]
    func getRecipients(for rawID: Data) async throws -> [TransactionRecipient]
    func getTransactionOutputs(for rawID: Data) async throws -> [ZcashTransaction.Output]
    func debugDatabase(sql: String) -> String
}

protocol RawTransactionLookup {
    func find(rawTransaction: Data) async throws -> ZcashTransaction.Overview
}
