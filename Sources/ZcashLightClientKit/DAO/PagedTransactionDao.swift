//
//  PagedTransactionDAO.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 12/9/19.
//

import Foundation

class PagedTransactionDAO: PaginatedTransactionRepository {
    let pageSize: Int
    let transactionRepository: TransactionRepository
    let kind: TransactionKind

    var pageCount: Int {
        get async {
            guard pageSize > 0 else {
                return 0
            }
            return await itemCount / pageSize
        }
    }

    var itemCount: Int {
        get async {
            guard let count = try? await transactionRepository.countAll() else {
                return 0
            }
            return count
        }
    }

    init(repository: TransactionRepository, pageSize: Int = 30, kind: TransactionKind = .all) {
        self.transactionRepository = repository
        self.pageSize = pageSize
        self.kind = kind
    }

    func page(_ number: Int) async throws -> [ZcashTransaction.Overview]? {
        let offset = number * pageSize
        guard offset < (await itemCount) else { return nil }
        return try await transactionRepository.find(offset: offset, limit: pageSize, kind: kind)
    }

    func page(_ number: Int, result: @escaping (Result<[ZcashTransaction.Overview]?, Error>) -> Void) {
        Task(priority: .userInitiated) {
            do {
                result(.success(try await self.page(number)))
            } catch {
                result(.failure(error))
            }
        }
    }
}
