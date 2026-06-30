//
//  PagedTransactionRepository.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 12/6/19.
//

import Foundation

public protocol PaginatedTransactionRepository {
    /**
    The page size of this repository
    */
    var pageSize: Int { get }

    /**
    How many pages are in total
    */
    var pageCount: Int { get async }

    /**
    How many items are to be displayed in total
    */
    var itemCount: Int { get async }

    /**
    Returns the page number if exists.
    */
    func page(_ number: Int) async throws -> [ZcashTransaction.Overview]?

    /**
    Returns the page number if exists.
    */
    func page(_ number: Int, result: @escaping (Result<[ZcashTransaction.Overview]?, Error>) -> Void)
}
