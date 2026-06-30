//
//  FetchUTXOsActionTests.swift
//
//
//  Created by Lukáš Korba on 18.05.2023.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class FetchUTXOsActionTests: ZcashTestCase {
    func testFetchUTXOsAction_NextAction() async throws {
        let loggerMock = LoggerMock()
        let uTXOFetcherMock = UTXOFetcherMock()

        loggerMock.debugFileFunctionLineClosure = { _, _, _, _ in }
        let insertedEntity = UnspentTransactionOutputEntityMock(address: "addr", txid: Data(), index: 0, script: Data(), valueZat: 1, height: 2)
        let skippedEntity = UnspentTransactionOutputEntityMock(address: "addr2", txid: Data(), index: 1, script: Data(), valueZat: 2, height: 3)
        uTXOFetcherMock.fetchDidFetchReturnValue = (inserted: [insertedEntity], skipped: [skippedEntity])

        mockContainer.mock(type: Logger.self, isSingleton: true) { _ in loggerMock }
        mockContainer.mock(type: UTXOFetcher.self, isSingleton: true) { _ in uTXOFetcherMock }

        let fetchUTXOsAction = FetchUTXOsAction(container: mockContainer)

        let syncContext = ActionContextMock.default()
        syncContext.underlyingSyncControlData = SyncControlData(
            latestBlockHeight: 0,
            latestScannedHeight: 0,
            firstUnenhancedHeight: nil
        )

        do {
            let nextContext = try await fetchUTXOsAction.run(with: syncContext) { event in
                guard case .storedUTXOs(let result) = event else {
                    XCTFail("testFetchUTXOsAction_NextAction event expected to be .storedUTXOs but received \(event)")
                    return
                }
                XCTAssertEqual(result.inserted as! [UnspentTransactionOutputEntityMock], [insertedEntity])
                XCTAssertEqual(result.skipped as! [UnspentTransactionOutputEntityMock], [skippedEntity])
            }
            XCTAssertTrue(loggerMock.debugFileFunctionLineCalled, "logger.debug(...) is expected to be called.")
            XCTAssertTrue(uTXOFetcherMock.fetchDidFetchCalled, "utxoFetcher.fetch() is expected to be called.")

            let acResult = nextContext.checkStateIs(.handleSaplingParams)
            XCTAssertTrue(acResult == .true, "Check of state failed with '\(acResult)'")
        } catch {
            XCTFail("testFetchUTXOsAction_NextAction is not expected to fail. \(error)")
        }
    }
}
