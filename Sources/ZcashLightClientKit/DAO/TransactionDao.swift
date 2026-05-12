//
//  TransactionDao.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 11/15/19.
//

import Foundation
import SQLite

extension Connection {
    func debugQuery(_ sql: String) -> String {
        do {
            let rows = try self.prepare(sql)
            var result = ""
            
            for row in rows {
                let stringRow = row.map { value -> String in
                    if let value {
                        return "\(value)"
                    }
                    return "NULL"
                }
                .joined(separator: " | ")
                
                result = "\(result)\n\(stringRow)"
            }
            
            return result.isEmpty ? "No results" : result
        } catch {
            return "Error: \(error)"
        }
    }
}

class TransactionSQLDAO: TransactionRepository, RawTransactionLookup {
    enum NotesTableStructure {
        static let transactionID = SQLite.Expression<Int>("tx")
        static let memo = SQLite.Expression<Blob>("memo")
    }

    enum UserMetadata {
        static let txid = SQLite.Expression<Blob>("txid")
        static let memoCount = SQLite.Expression<Int>("memo_count")
        static let memo = SQLite.Expression<String>("memo")
    }

    let dbProvider: ConnectionProvider
    
    private let blockDao: BlockSQLDAO
    private let transactionsView = View("v_transactions")
    private let txOutputsView = View("v_tx_outputs")
    private let traceClosure: ((String) -> Void)?
    
    init(dbProvider: ConnectionProvider, traceClosure: ((String) -> Void)? = nil) {
        self.dbProvider = dbProvider
        self.blockDao = BlockSQLDAO(dbProvider: dbProvider)
        self.traceClosure = traceClosure
    }

    private func connection() throws -> Connection {
        let conn = try dbProvider.connection()
        conn.trace(traceClosure)
        return conn
    }

    private func debugConnection() throws -> Connection {
        let conn = try dbProvider.debugConnection()
        conn.trace(traceClosure)
        return conn
    }

    func closeDBConnection() {
        dbProvider.close()
    }

    func isInitialized() async throws -> Bool {
        true
    }

    func resolveMissingBlockTimes(for transactions: [ZcashTransaction.Overview]) async throws -> [ZcashTransaction.Overview] {
        var transactionsCopy = transactions
        
        for i in 0..<transactions.count {
            let transaction = transactions[i]
            
            guard transaction.blockTime == nil else {
                continue
            }
            
            if let expiryHeight = transaction.expiryHeight {
                if let block = try await blockForHeight(expiryHeight) {
                    transactionsCopy[i].blockTime = TimeInterval(block.time)
                }
            }
        }
        
        return transactionsCopy
    }
    
    @DBActor
    func fetchTxidsWithMemoContaining(searchTerm: String) async throws -> [Data] {
        let query = transactionsView
            .join(txOutputsView, on: transactionsView[UserMetadata.txid] == txOutputsView[UserMetadata.txid])
            .filter(transactionsView[UserMetadata.memoCount] > 0)
            .filter(txOutputsView[UserMetadata.memo].like("%\(searchTerm)%"))

        var txids: [Data] = []
        for row in try connection().prepare(query) {
            let txidBlob = try row.get(txOutputsView[UserMetadata.txid])
            let txid = Data(blob: txidBlob)
            txids.append(txid)
        }
        
        return txids
    }
    
    @DBActor
    func blockForHeight(_ height: BlockHeight) async throws -> Block? {
        try blockDao.block(at: height)
    }

    @DBActor
    func countAll() async throws -> Int {
        do {
            return try connection().scalar(transactionsView.count)
        } catch {
            throw ZcashError.transactionRepositoryCountAll(error)
        }
    }
    
    @DBActor
    func countUnmined() async throws -> Int {
        do {
            return try connection().scalar(transactionsView.filter(ZcashTransaction.Overview.Column.minedHeight == nil).count)
        } catch {
            throw ZcashError.transactionRepositoryCountUnmined(error)
        }
    }

    func find(rawID: Data) async throws -> ZcashTransaction.Overview {
        let query = transactionsView
            .filter(ZcashTransaction.Overview.Column.rawID == Blob(bytes: rawID.bytes))
            .limit(1)

        return try await execute(query) { try ZcashTransaction.Overview(row: $0) }
    }

    func find(rawTransaction: Data) async throws -> ZcashTransaction.Overview {
        let query = transactionsView
            .filter(ZcashTransaction.Overview.Column.raw == Blob(bytes: rawTransaction.bytes))
            .limit(1)

        return try await execute(query) { try ZcashTransaction.Overview(row: $0) }
    }

    func find(offset: Int, limit: Int, kind: TransactionKind) async throws -> [ZcashTransaction.Overview] {
        let query = transactionsView
            .order((ZcashTransaction.Overview.Column.minedHeight ?? BlockHeight.max).desc)
            .filterQueryFor(kind: kind)
            .limit(limit, offset: offset)

        let transactions: [ZcashTransaction.Overview] = try await execute(query) { try ZcashTransaction.Overview(row: $0) }

        return try await resolveMissingBlockTimes(for: transactions)
    }

    func find(in range: CompactBlockRange, limit: Int, kind: TransactionKind) async throws -> [ZcashTransaction.Overview] {
        let query = transactionsView
            .order((ZcashTransaction.Overview.Column.minedHeight ?? BlockHeight.max).desc)
            .filter(
                ZcashTransaction.Overview.Column.minedHeight >= BlockHeight(range.lowerBound) &&
                ZcashTransaction.Overview.Column.minedHeight <= BlockHeight(range.upperBound)
            )
            .filterQueryFor(kind: kind)
            .limit(limit)

        return try await execute(query) { try ZcashTransaction.Overview(row: $0) }
    }

    func find(from transaction: ZcashTransaction.Overview, limit: Int, kind: TransactionKind) async throws -> [ZcashTransaction.Overview] {
        guard
            let transactionBlockHeight = transaction.minedHeight
        else { throw ZcashError.transactionRepositoryTransactionMissingRequiredFields }
        
        let transactionIndex = transaction.index ?? Int.max
        let query = transactionsView
            .order((ZcashTransaction.Overview.Column.minedHeight ?? BlockHeight.max).desc)
            .filter(
                transactionBlockHeight > ZcashTransaction.Overview.Column.minedHeight
                || (
                    transactionBlockHeight == ZcashTransaction.Overview.Column.minedHeight &&
                    transactionIndex > (ZcashTransaction.Overview.Column.index ?? -1)
                )
            )
            .filterQueryFor(kind: kind)
            .limit(limit)
        
        return try await execute(query) { try ZcashTransaction.Overview(row: $0) }
    }

    func findForResubmission(upTo: BlockHeight) async throws -> [ZcashTransaction.Overview] {
        let query = transactionsView
            .filter(
                ZcashTransaction.Overview.Column.minedHeight == nil &&
                ZcashTransaction.Overview.Column.expiryHeight > upTo
            )
            .filterQueryFor(kind: .sent)
            .limit(Int.max)

        return try await execute(query) { try ZcashTransaction.Overview(row: $0) }
    }
    
    func findReceived(offset: Int, limit: Int) async throws -> [ZcashTransaction.Overview] {
        let query = transactionsView
            .filterQueryFor(kind: .received)
            .order((ZcashTransaction.Overview.Column.minedHeight ?? BlockHeight.max).desc)
            .limit(limit, offset: offset)

        return try await execute(query) { try ZcashTransaction.Overview(row: $0) }
    }

    func findSent(offset: Int, limit: Int) async throws -> [ZcashTransaction.Overview] {
        let query = transactionsView
            .filterQueryFor(kind: .sent)
            .order((ZcashTransaction.Overview.Column.minedHeight ?? BlockHeight.max).desc)
            .limit(limit, offset: offset)

        return try await execute(query) { try ZcashTransaction.Overview(row: $0) }
    }

    func findPendingTransactions(latestHeight: BlockHeight, offset: Int, limit: Int) async throws -> [ZcashTransaction.Overview] {
        let query = transactionsView
            .filterPendingFrom(latestHeight)
            .order((ZcashTransaction.Overview.Column.minedHeight ?? BlockHeight.max).desc)
            .limit(limit, offset: offset)

        return try await execute(query) { try ZcashTransaction.Overview(row: $0) }
    }

    func findMemos(for rawID: Data) async throws -> [Memo] {
        do {
            return try await getTransactionOutputs(for: rawID)
                .compactMap { $0.memo }
        } catch {
            throw ZcashError.transactionRepositoryFindMemos(error)
        }
    }
    
    func findMemos(for transaction: ZcashTransaction.Overview) async throws -> [Memo] {
        try await findMemos(for: transaction.rawID)
    }

    func getTransactionOutputs(for rawID: Data) async throws -> [ZcashTransaction.Output] {
        let query = self.txOutputsView
            .filter(ZcashTransaction.Output.Column.rawID == Blob(bytes: rawID.bytes))

        return try await execute(query) { try ZcashTransaction.Output(row: $0) }
    }

    func getRecipients(for rawID: Data) async throws -> [TransactionRecipient] {
        try await getTransactionOutputs(for: rawID).map { $0.recipient }
    }

    private func execute<Entity>(_ query: View, createEntity: (Row) throws -> Entity) async throws -> Entity {
        let entities: [Entity] = try await execute(query, createEntity: createEntity)
        
        guard let entity = entities.first else {
            throw ZcashError.transactionRepositoryEntityNotFound
        }
        
        return entity
    }

    @DBActor
    private func execute<Entity>(_ query: View, createEntity: (Row) throws -> Entity) async throws -> [Entity] {
        do {
            let entities = try connection()
                .prepare(query)
                .map(createEntity)

            return entities
        } catch {
            if let error = error as? ZcashError {
                throw error
            } else {
                throw ZcashError.transactionRepositoryQueryExecute(error)
            }
        }
    }
    
    func debugDatabase(sql: String) -> String {
        guard let connection = try? debugConnection() else {
            return "Connection failed"
        }
        
        return connection.debugQuery(sql)
    }
}

private extension View {
    func filterPendingFrom(_ latestHeight: BlockHeight) -> View {
        filter(
            // transaction has not expired
            ZcashTransaction.Overview.Column.expiredUnmined == false &&
            // transaction is "sent"
            ZcashTransaction.Overview.Column.value < 0 &&
            // transaction has not been mined yet OR
            // it has been within the latest `defaultStaleTolerance` blocks
            (
                ZcashTransaction.Overview.Column.minedHeight == nil ||
                ZcashTransaction.Overview.Column.minedHeight > (latestHeight - ZcashSDK.defaultStaleTolerance)
            )
        )
    }
}

private extension View {
    func filterQueryFor(kind: TransactionKind) -> View {
        switch kind {
        case .all:
            return self
        case .sent:
            return filter(ZcashTransaction.Overview.Column.value < 0)
        case .received:
            return filter(ZcashTransaction.Overview.Column.value >= 0)
        }
    }
}

extension Data {
    init(blob: SQLite.Blob) {
        let bytes = blob.bytes
        self = Data(bytes: bytes, count: bytes.count)
    }
    
    var bytes: [UInt8] {
        return [UInt8](self)
    }
}

extension Array where Element == UInt8 {
    var data: Data {
        return Data(self)
    }
}
