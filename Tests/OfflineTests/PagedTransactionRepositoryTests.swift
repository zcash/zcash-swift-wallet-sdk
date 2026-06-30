//
//  PagedTransactionRepositoryTests.swift
//  ZcashLightClientKit-Unit-Tests
//
//  Created by Francisco Gindre on 12/6/19.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

class PagedTransactionRepositoryTests: XCTestCase {
    var pagedTransactionRepository: PaginatedTransactionRepository!
    var transactionRepository: TransactionRepository!

    override func setUp() {
        super.setUp()
        transactionRepository = MockTransactionRepository(
            unminedCount: 5,
            receivedCount: 150,
            sentCount: 100,
            scannedHeight: 1000000,
            network: ZcashNetworkBuilder.network(for: .testnet)
        )
        pagedTransactionRepository = PagedTransactionDAO(repository: transactionRepository)
    }

    override func tearDown() {
        super.tearDown()
        pagedTransactionRepository = nil
        transactionRepository = nil
    }

    func testBrowsePages() async {
        let pageSize = pagedTransactionRepository.pageSize
        let pageCount = await pagedTransactionRepository.pageCount
        let totalItems = await pagedTransactionRepository.itemCount

        for index in 0 ..< pageCount / pageSize {
            guard let page = try? await pagedTransactionRepository.page(index) else {
                XCTFail("page failed to get page \(index)")
                return
            }
            if index < pageCount {
                XCTAssert(page.count == pageSize)
            } else {
                // last page has to have the remainding items
                XCTAssertEqual(page.count, totalItems - (pageSize * pageCount))
            }
        }
    }
}
