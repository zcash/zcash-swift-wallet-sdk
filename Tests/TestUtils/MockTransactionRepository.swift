//
//  MockTransactionRepository.swift
//  ZcashLightClientKit-Unit-Tests
//
//  Created by Francisco Gindre on 12/6/19.
//

import Foundation
@testable import ZcashLightClientKit

enum MockTransactionRepositoryError: Error {
    case notImplemented
}

class MockTransactionRepository {
    enum Kind {
        case sent
        case received
    }

    var unminedCount: Int
    var receivedCount: Int
    var sentCount: Int
    var scannedHeight: BlockHeight
    var reference: [Kind] = []
    var network: ZcashNetwork

    var transactions: [ZcashTransaction.Overview] = []
    var receivedTransactions: [ZcashTransaction.Overview] = []
    var sentTransactions: [ZcashTransaction.Overview] = []

    var allCount: Int {
        receivedCount + sentCount
    }

    init(
        unminedCount: Int,
        receivedCount: Int,
        sentCount: Int,
        scannedHeight: BlockHeight,
        network: ZcashNetwork
    ) {
        self.unminedCount = unminedCount
        self.receivedCount = receivedCount
        self.sentCount = sentCount
        self.scannedHeight = scannedHeight
        self.network = network
    }

    func referenceArray() -> [Kind] {
        var template: [Kind] = []

        for _ in 0 ..< sentCount {
            template.append(.sent)
        }
        for _ in 0 ..< receivedCount {
            template.append(.received)
        }

        return template.shuffled()
    }

    func randomBlockHeight() -> BlockHeight {
        BlockHeight.random(in: network.constants.saplingActivationHeight ... 1_000_000)
    }

    func randomTimeInterval() -> TimeInterval {
        Double.random(in: Date().timeIntervalSince1970 - 1000000.0 ... Date().timeIntervalSince1970)
    }
}

extension MockTransactionRepository.Kind: Equatable {}

// MARK: - TransactionRepository
extension MockTransactionRepository: TransactionRepository {
    func fetchTxidsWithMemoContaining(searchTerm: String) async throws -> [Data] {
        []
    }

    func findForResubmission(upTo: ZcashLightClientKit.BlockHeight) async throws -> [ZcashLightClientKit.ZcashTransaction.Overview] {
        []
    }

    func getTransactionOutputs(for rawID: Data) async throws -> [ZcashLightClientKit.ZcashTransaction.Output] {
        []
    }

    func findPendingTransactions(latestHeight: ZcashLightClientKit.BlockHeight, offset: Int, limit: Int) async throws -> [ZcashTransaction.Overview] {
        []
    }

    func getRecipients(for rawID: Data) -> [TransactionRecipient] {
        []
    }

    func closeDBConnection() { }

    func countAll() throws -> Int {
        allCount
    }

    func countUnmined() throws -> Int {
        unminedCount
    }

    func findBy(rawId: Data) throws -> ZcashTransaction.Overview? {
        transactions.first(where: { $0.rawID == rawId })
    }

    func lastScannedHeight() throws -> BlockHeight {
        scannedHeight
    }

    func firstUnenhancedHeight() throws -> ZcashLightClientKit.BlockHeight? {
        nil
    }

    func isInitialized() throws -> Bool {
        true
    }

    func generate() {
        var txArray: [ZcashTransaction.Overview] = []
        reference = referenceArray()
        for index in 0 ..< reference.count {
            txArray.append(mockTx(index: index, kind: reference[index]))
        }
        transactions = txArray
    }

    func mockTx(index: Int, kind: Kind) -> ZcashTransaction.Overview {
        switch kind {
        case .received:
            return mockReceived(index)
        case .sent:
            return mockSent(index)
        }
    }

    func mockSent(_ index: Int) -> ZcashTransaction.Overview {
        return ZcashTransaction.Overview(
            accountUUID: TestsData.mockedAccountUUID,
            blockTime: randomTimeInterval(),
            expiryHeight: BlockHeight.max,
            fee: Zatoshi(2),
            index: index,
            isShielding: false,
            hasChange: true,
            memoCount: 0,
            minedHeight: randomBlockHeight(),
            raw: Data(),
            rawID: Data(),
            receivedNoteCount: 0,
            sentNoteCount: 1,
            value: Zatoshi(-Int64.random(in: 1 ... Zatoshi.Constants.oneZecInZatoshi)),
            isExpiredUmined: false,
            totalSpent: nil,
            totalReceived: nil
        )
    }

    func mockReceived(_ index: Int) -> ZcashTransaction.Overview {
        return ZcashTransaction.Overview(
            accountUUID: TestsData.mockedAccountUUID,
            blockTime: randomTimeInterval(),
            expiryHeight: BlockHeight.max,
            fee: Zatoshi(2),
            index: index,
            isShielding: false,
            hasChange: true,
            memoCount: 0,
            minedHeight: randomBlockHeight(),
            raw: Data(),
            rawID: Data(),
            receivedNoteCount: 1,
            sentNoteCount: 0,
            value: Zatoshi(Int64.random(in: 1 ... Zatoshi.Constants.oneZecInZatoshi)),
            isExpiredUmined: false,
            totalSpent: nil,
            totalReceived: nil
        )
    }

    func slice(txs: [ZcashTransaction.Overview], offset: Int, limit: Int) -> [ZcashTransaction.Overview] {
        guard offset < txs.count else { return [] }

        return Array(txs[offset ..< min(offset + limit, txs.count - offset)])
    }

    func find(rawID: Data) throws -> ZcashTransaction.Overview {
        guard let transaction = transactions.first(where: { $0.rawID == rawID }) else {
            throw ZcashError.transactionRepositoryEntityNotFound
        }

        return transaction
    }

    func find(offset: Int, limit: Int, kind: TransactionKind) throws -> [ZcashLightClientKit.ZcashTransaction.Overview] {
        throw MockTransactionRepositoryError.notImplemented
    }

    func find(in range: CompactBlockRange, limit: Int, kind: TransactionKind) throws -> [ZcashTransaction.Overview] {
        throw MockTransactionRepositoryError.notImplemented
    }

    func find(from: ZcashTransaction.Overview, limit: Int, kind: TransactionKind) throws -> [ZcashTransaction.Overview] {
        throw MockTransactionRepositoryError.notImplemented
    }

    func findReceived(offset: Int, limit: Int) throws -> [ZcashTransaction.Overview] {
        throw MockTransactionRepositoryError.notImplemented
    }

    func findSent(offset: Int, limit: Int) throws -> [ZcashTransaction.Overview] {
        throw MockTransactionRepositoryError.notImplemented
    }

    func findMemos(for rawID: Data) throws -> [ZcashLightClientKit.Memo] {
        throw MockTransactionRepositoryError.notImplemented
    }

    func findMemos(for transaction: ZcashLightClientKit.ZcashTransaction.Overview) throws -> [ZcashLightClientKit.Memo] {
        throw MockTransactionRepositoryError.notImplemented
    }

    func debugDatabase(sql: String) -> String {
        ""
    }
}

extension Array {
    func indices(where function: (_ element: Element) -> Bool) -> [Int]? {
        guard !self.isEmpty else { return nil }

        var idx: [Int] = []

        for index in 0 ..< self.count where function(self[index]) {
            idx.append(index)
        }

        guard !idx.isEmpty else { return nil }
        return idx
    }
}
