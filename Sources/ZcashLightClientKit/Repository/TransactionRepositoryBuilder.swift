//
//  TransactionRepositoryBuilder.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 12/9/19.
//

import Foundation

enum TransactionRepositoryBuilder {
    static func build(initializer: Initializer) -> TransactionRepository {
        TransactionSQLDAO(dbProvider: SimpleConnectionProvider(path: initializer.dataDbURL.path, readonly: true))
    }

    static func build(dataDbURL: URL) -> TransactionRepository {
        TransactionSQLDAO(dbProvider: SimpleConnectionProvider(path: dataDbURL.path, readonly: true))
    }
}

enum PagedTransactionRepositoryBuilder {
    static func build(initializer: Initializer, kind: TransactionKind = .all) -> PaginatedTransactionRepository {
        return PagedTransactionDAO(repository: initializer.transactionRepository, kind: kind)
    }
}
