//
//  WalletTransactionEncoderCreatedTransactionTests.swift
//  ZcashLightClientKitTests
//
//  Tests for the view-independent created-transaction lookup (MOB-1703): a transaction the
//  rust layer has committed must be submittable even when `v_transactions` has no row for it.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class WalletTransactionEncoderCreatedTransactionTests: ZcashTestCase {
    private var rustBackend: ZcashRustBackendWeldingMock!
    private var repository: TransactionRepositoryMock!

    private let txidA = Data(repeating: 0xA1, count: 32)
    private let txidB = Data(repeating: 0xB2, count: 32)
    private let rawA = Data([0x01, 0x02])
    private let rawB = Data([0x03, 0x04])

    override func setUp() async throws {
        try await super.setUp()
        rustBackend = ZcashRustBackendWeldingMock()
        repository = TransactionRepositoryMock()
        repository.closeDBConnectionClosure = { }
    }

    override func tearDown() async throws {
        rustBackend = nil
        repository = nil
        try await super.tearDown()
    }

    private func makeOverview(rawID: Data, raw: Data?) -> ZcashTransaction.Overview {
        ZcashTransaction.Overview(
            accountUUID: TestsData.mockedAccountUUID,
            blockTime: nil,
            expiryHeight: 123_456,
            fee: Zatoshi(10_000),
            index: 0,
            isShielding: false,
            hasChange: false,
            memoCount: 0,
            minedHeight: nil,
            raw: raw,
            rawID: rawID,
            receivedNoteCount: 0,
            sentNoteCount: 1,
            value: Zatoshi(-1_000),
            isExpiredUmined: false,
            totalSpent: nil,
            totalReceived: nil,
            spentNoteCount: 0,
            poolCrossingValue: nil,
            isTrusted: false,
            zip318Kind: .notClassified
        )
    }

    private func makeEncoder() -> WalletTransactionEncoder {
        WalletTransactionEncoder(
            rustBackend: rustBackend,
            dataDb: testTempDirectory.appendingPathComponent("data.db"),
            fsBlockDbRoot: testTempDirectory,
            service: LightWalletServiceMock(),
            repository: repository,
            outputParams: testTempDirectory.appendingPathComponent("output.params"),
            spendParams: testTempDirectory.appendingPathComponent("spend.params"),
            networkType: .testnet,
            logger: submissionLifecycleLogger(),
            sdkFlags: SDKFlags(torEnabled: false, exchangeRateEnabled: false)
        )
    }

    // MARK: - createdTransactions(forTxIds:)

    func testAllVisibleMapsOverviewsAndNeverTouchesFFI() async throws {
        repository.findRawIDClosure = { rawID in
            self.makeOverview(rawID: rawID, raw: rawID == self.txidA ? self.rawA : self.rawB)
        }

        let created = try await makeEncoder().createdTransactions(forTxIds: [txidA, txidB])

        XCTAssertEqual(created.map(\.txId), [txidA, txidB])
        XCTAssertEqual(created.map(\.raw), [rawA, rawB])
        XCTAssertEqual(created.map(\.expiryHeight), [123_456, 123_456])
        XCTAssertEqual(repository.closeDBConnectionCallsCount, 0)
        XCTAssertFalse(rustBackend.getStoredTransactionTxIdCalled)
    }

    func testInvisibleTransactionIsBuiltFromBackendStore() async throws {
        repository.findRawIDClosure = { rawID in
            if rawID == self.txidA {
                return self.makeOverview(rawID: rawID, raw: self.rawA)
            }
            throw ZcashError.transactionRepositoryEntityNotFound
        }
        rustBackend.getStoredTransactionTxIdClosure = { txId in
            XCTAssertEqual(txId, self.txidB, "Only the invisible txid may fall back to the FFI")
            return (raw: self.rawB, expiryHeight: 654_321)
        }

        let created = try await makeEncoder().createdTransactions(forTxIds: [txidA, txidB])

        XCTAssertEqual(created.map(\.txId), [txidA, txidB])
        XCTAssertEqual(created.map(\.raw), [rawA, rawB])
        XCTAssertEqual(created.last?.expiryHeight, 654_321)
        // The view lookup is retried once on a fresh connection before falling back.
        XCTAssertEqual(repository.closeDBConnectionCallsCount, 1)
        XCTAssertEqual(rustBackend.getStoredTransactionTxIdCallsCount, 1)
    }

    func testStaleSnapshotRecoversAfterConnectionReopen() async throws {
        var findCallsForB = 0
        repository.findRawIDClosure = { rawID in
            if rawID == self.txidA {
                return self.makeOverview(rawID: rawID, raw: self.rawA)
            }
            findCallsForB += 1
            if findCallsForB == 1 {
                throw ZcashError.transactionRepositoryEntityNotFound
            }
            return self.makeOverview(rawID: rawID, raw: self.rawB)
        }

        let created = try await makeEncoder().createdTransactions(forTxIds: [txidA, txidB])

        XCTAssertEqual(created.map(\.txId), [txidA, txidB])
        XCTAssertEqual(created.map(\.raw), [rawA, rawB])
        XCTAssertEqual(repository.closeDBConnectionCallsCount, 1)
        XCTAssertFalse(rustBackend.getStoredTransactionTxIdCalled, "A recovered view lookup must not touch the FFI")
    }

    func testMissingEverywhereThrowsCreatedTransactionNotFound() async throws {
        repository.findRawIDClosure = { _ in
            throw ZcashError.transactionRepositoryEntityNotFound
        }
        rustBackend.getStoredTransactionTxIdClosure = { _ in nil }

        do {
            _ = try await makeEncoder().createdTransactions(forTxIds: [txidA])
            XCTFail("Expected transactionRepositoryCreatedTransactionNotFound")
        } catch ZcashError.transactionRepositoryCreatedTransactionNotFound(let txId) {
            XCTAssertEqual(txId, txidA.toHexStringTxId())
        }
    }

    // MARK: - createProposedTransactionsForSubmission

    func testCreateProposedTransactionsForSubmissionUsesRustTxIds() async throws {
        // ensureParams only checks file readability.
        try Data([0x00]).write(to: testTempDirectory.appendingPathComponent("output.params"))
        try Data([0x00]).write(to: testTempDirectory.appendingPathComponent("spend.params"))

        rustBackend.createProposedTransactionsProposalUskReturnValue = [txidA, txidB]
        repository.findRawIDClosure = { rawID in
            if rawID == self.txidA {
                return self.makeOverview(rawID: rawID, raw: self.rawA)
            }
            throw ZcashError.transactionRepositoryEntityNotFound
        }
        rustBackend.getStoredTransactionTxIdClosure = { _ in (raw: self.rawB, expiryHeight: nil) }

        let created = try await makeEncoder().createProposedTransactionsForSubmission(
            proposal: Proposal.testOnlyFakeProposal(totalFee: 10),
            spendingKey: TestsData(networkType: .testnet).spendingKey
        )

        XCTAssertEqual(created.map(\.txId), [txidA, txidB])
        XCTAssertEqual(created.map(\.raw), [rawA, rawB])
        XCTAssertNil(created.last?.expiryHeight)
    }
}
