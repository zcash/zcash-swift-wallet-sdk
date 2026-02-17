//
//  TransactionRepositoryTests.swift
//  ZcashLightClientKit-Unit-Tests
//
//  Created by Francisco Gindre on 11/16/19.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

class TransactionRepositoryTests: XCTestCase {
    var transactionRepository: TransactionRepository!

    override func setUp() async throws {
        try await super.setUp()
        let rustBackend = try await ZcashRustBackend.openForTests(
            dbData: TestDbBuilder.prePopulatedMainnetDataDbURL()!,
            fsBlockDbRoot: Environment.uniqueTestTempDirectory,
            networkType: .mainnet
        )
        transactionRepository = try! await TestDbBuilder.transactionRepository(rustBackend: rustBackend)
    }
    
    override func tearDown() {
        super.tearDown()
        transactionRepository = nil
    }
    
    func testCount() async throws {
        let count = try await self.transactionRepository.countAll()
        XCTAssertNotNil(count)
        XCTAssertEqual(count, 21)
    }
    
    func testCountUnmined() async throws {
        let count = try await self.transactionRepository.countUnmined()
        XCTAssertNotNil(count)
        XCTAssertEqual(count, 0)
    }

    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testFindInRange() async throws {
        let transactions = try await self.transactionRepository.find(in: 663218...663974, limit: 3, kind: .received)
        XCTAssertEqual(transactions.count, 3)
        XCTAssertEqual(transactions[0].minedHeight, 663974)
        XCTAssertEqual(transactions[0].isSentTransaction, false)
        XCTAssertEqual(transactions[1].minedHeight, 663953)
        XCTAssertEqual(transactions[1].isSentTransaction, false)
        XCTAssertEqual(transactions[2].minedHeight, 663229)
        XCTAssertEqual(transactions[2].isSentTransaction, false)
    }
    
    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testFindByTxId() async throws {
        let id = Data(fromHexEncodedString: "01af48bcc4e9667849a073b8b5c539a0fc19de71aac775377929dc6567a36eff")!
        let transaction = try await self.transactionRepository.find(rawID: id)
        XCTAssertEqual(transaction.rawID, id)
        XCTAssertEqual(transaction.minedHeight, 663922)
        XCTAssertEqual(transaction.index, 1)
    }
    
    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testFindAllSentTransactions() async throws {
        let transactions = try await self.transactionRepository.find(offset: 0, limit: Int.max, kind: .sent)
        XCTAssertEqual(transactions.count, 13)
        transactions.forEach { XCTAssertEqual($0.isSentTransaction, true) }
    }
    
    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testFindAllReceivedTransactions() async throws {
        let transactions = try await self.transactionRepository.find(offset: 0, limit: Int.max, kind: .received)
        XCTAssertEqual(transactions.count, 8)
        transactions.forEach { XCTAssertEqual($0.isSentTransaction, false) }
    }
    
    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testFindAllTransactions() async throws {
        let transactions = try await self.transactionRepository.find(offset: 0, limit: Int.max, kind: .all)
        XCTAssertEqual(transactions.count, 21)
    }

    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testFindReceivedOffsetLimit() async throws {
        let transactions = try await self.transactionRepository.findReceived(offset: 3, limit: 3)
        XCTAssertEqual(transactions.count, 3)
        XCTAssertEqual(transactions[0].minedHeight, 663229)
        XCTAssertEqual(transactions[1].minedHeight, 663218)
        XCTAssertEqual(transactions[2].minedHeight, 663202)
    }

    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testFindSentOffsetLimit() async throws {
        let transactions = try await self.transactionRepository.findSent(offset: 3, limit: 3)
        XCTAssertEqual(transactions.count, 3)
        XCTAssertEqual(transactions[0].minedHeight, 664022)
        XCTAssertEqual(transactions[1].minedHeight, 664012)
        XCTAssertEqual(transactions[2].minedHeight, 663956)
    }

    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testGetTransactionOutputs() async throws {
        let rawID = Data(fromHexEncodedString: "08cb5838ffd2c18ce15e7e8c50174940cd9526fff37601986f5480b7ca07e534")!

        let outputs = try await self.transactionRepository.getTransactionOutputs(for: rawID)
        XCTAssertEqual(outputs.count, 2)
    }

    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testFindMemoForTransaction() async throws {
        let rawID = Data(fromHexEncodedString: "08cb5838ffd2c18ce15e7e8c50174940cd9526fff37601986f5480b7ca07e534")!
        let transaction = ZcashTransaction.Overview(
            accountUUID: TestsData.mockedAccountUUID,
            blockTime: nil,
            expiryHeight: nil,
            fee: nil,
            index: nil,
            isShielding: false,
            hasChange: false,
            memoCount: 0,
            minedHeight: nil,
            raw: nil,
            rawID: rawID,
            receivedNoteCount: 0,
            sentNoteCount: 0,
            value: Zatoshi(-1000),
            isExpiredUmined: false,
            totalSpent: nil,
            totalReceived: nil
        )

        let memos = try await self.transactionRepository.findMemos(for: transaction)

        guard memos.count == 1 else {
            XCTFail("Expected transaction to have one memo, found \(memos.count)")
            return
        }

        XCTAssertEqual(memos[0].toString(), "Some funds")
    }

    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testFindMemoForReceivedTransaction() async throws {
        let rawID = Data(fromHexEncodedString: "1f49cfcfcdebd5cb9085d9ff2efbcda87121dda13f2c791113fcf2e79ba82108")!
        let transaction = ZcashTransaction.Overview(
            accountUUID: TestsData.mockedAccountUUID,
            blockTime: 1,
            expiryHeight: nil,
            fee: nil,
            index: 0,
            isShielding: false,
            hasChange: false,
            memoCount: 1,
            minedHeight: 0,
            raw: nil,
            rawID: rawID,
            receivedNoteCount: 1,
            sentNoteCount: 0,
            value: .zero,
            isExpiredUmined: false,
            totalSpent: nil,
            totalReceived: nil
        )

        let memos = try await self.transactionRepository.findMemos(for: transaction)
        XCTAssertEqual(memos.count, 1)
        XCTAssertEqual(memos[0].toString(), "first mainnet tx from the SDK")
    }

    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testFindMemoForSentTransaction() async throws {
        let rawID = Data(fromHexEncodedString: "08cb5838ffd2c18ce15e7e8c50174940cd9526fff37601986f5480b7ca07e534")!
        let transaction = ZcashTransaction.Overview(
            accountUUID: TestsData.mockedAccountUUID,
            blockTime: 1,
            expiryHeight: nil,
            fee: nil,
            index: 0,
            isShielding: false,
            hasChange: false,
            memoCount: 1,
            minedHeight: nil,
            raw: nil,
            rawID: rawID,
            receivedNoteCount: 0,
            sentNoteCount: 2,
            value: .zero,
            isExpiredUmined: false,
            totalSpent: nil,
            totalReceived: nil
        )

        let memos = try await self.transactionRepository.findMemos(for: transaction)
        XCTAssertEqual(memos.count, 1)
        XCTAssertEqual(memos[0].toString(), "Some funds")
    }
    
    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testFindAllPerformance() {
        // This is an example of a performance test case.
        self.measure {
            let expectation = expectation(description: "Measure")
            Task(priority: .userInitiated) {
                // Put the code you want to measure the time of here.
                do {
                    _ = try await self.transactionRepository.find(offset: 0, limit: Int.max, kind: .all)
                    expectation.fulfill()
                } catch {
                    XCTFail("find all failed")
                }
            }
            wait(for: [expectation], timeout: 2)
        }
    }
    
    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testFindAllFrom() async throws {
        let rawID = Data(fromHexEncodedString: "5d9b91e31a6d3f94844a4c330e727a2d5d0643f6caa6c75573b28aefe859e8d2")!
        let transaction = try await self.transactionRepository.find(rawID: rawID)
        let transactionsFrom = try await self.transactionRepository.find(from: transaction, limit: Int.max, kind: .all)

        XCTAssertEqual(transactionsFrom.count, 15)

        transactionsFrom.forEach { preceededTransaction in
            guard let precedingHeight = preceededTransaction.minedHeight, let transactionHeight = transaction.minedHeight else {
                XCTFail("Transactions are missing mined heights.")
                return
            }

            guard let precedingBlockTime = preceededTransaction.blockTime, let transactionBlockTime = transaction.blockTime else {
                XCTFail("Transactions are missing block time.")
                return
            }

            XCTAssertLessThanOrEqual(precedingHeight, transactionHeight)
            XCTAssertLessThan(precedingBlockTime, transactionBlockTime)
        }
    }
}

extension Data {
    init?(fromHexEncodedString string: String) {
        // Convert 0 ... 9, a ... f, A ...F to their decimal value,
        // return nil for all other input characters
        func decodeNibble(bytes: UInt16) -> UInt8? {
            switch bytes {
            case 0x30 ... 0x39:
                return UInt8(bytes - 0x30)
            case 0x41 ... 0x46:
                return UInt8(bytes - 0x41 + 10)
            case 0x61 ... 0x66:
                return UInt8(bytes - 0x61 + 10)
            default:
                return nil
            }
        }

        self.init(capacity: string.utf16.count / 2)
        var even = true
        var byte: UInt8 = 0
        for char in string.utf16 {
            guard let val = decodeNibble(bytes: char) else { return nil }
            if even {
                byte = val << 4
            } else {
                byte += val
                self.append(byte)
            }
            even.toggle()
        }
        guard even else { return nil }
    }
}
