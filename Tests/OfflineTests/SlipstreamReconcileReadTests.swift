//
//  SlipstreamReconcileReadTests.swift
//  ZcashLightClientKit-Unit-Tests
//
//  [#1755] Covers the SDK read side of the slipstream reconciliation gate:
//  `TransactionSQLDAO.unreconciledTxids()` reads the `slipstream_v_tx_reconciled`
//  view (the view's SQL logic itself is proven in the engine's `reconcile.rs`
//  Rust tests). Here we verify the Swift blob-read returns the right txid set,
//  and that a database WITHOUT the view (legacy / non-slipstream) degrades to an
//  empty set instead of throwing — so nothing is ever held back by mistake.
//

import XCTest
import SQLite
@testable import ZcashLightClientKit

final class SlipstreamReconcileReadTests: XCTestCase {
    private func tempDBPath() -> String {
        (NSTemporaryDirectory() as NSString).appendingPathComponent("reconcile-\(UUID().uuidString).db")
    }

    func testUnreconciledTxidsReturnsOnlyTheUnreconciledRows() async throws {
        let path = tempDBPath()
        // A view is just a SELECT; the DAO issues `SELECT txid ... WHERE reconciled = 0`, so a
        // same-shaped table exercises the exact read path without rebuilding upstream's schema.
        let setup = try Connection(path)
        try setup.run("CREATE TABLE slipstream_v_tx_reconciled (txid BLOB, reconciled INTEGER)")

        let unreconciled = Data(repeating: 0xAA, count: 32)
        let reconciled = Data(repeating: 0xBB, count: 32)
        try setup.run(
            "INSERT INTO slipstream_v_tx_reconciled (txid, reconciled) VALUES (?, 0)",
            Blob(bytes: [UInt8](unreconciled))
        )
        try setup.run(
            "INSERT INTO slipstream_v_tx_reconciled (txid, reconciled) VALUES (?, 1)",
            Blob(bytes: [UInt8](reconciled))
        )

        let dao = TransactionSQLDAO(dbProvider: SimpleConnectionProvider(path: path, readonly: true))
        let result = try await dao.unreconciledTxids()

        XCTAssertEqual(result, Set([unreconciled]), "only the reconciled=0 txid should be returned")
    }

    func testUnreconciledTxidsReturnsEmptyWhenViewAbsent() async throws {
        let path = tempDBPath()
        _ = try Connection(path) // create an empty DB with no reconcile view

        let dao = TransactionSQLDAO(dbProvider: SimpleConnectionProvider(path: path, readonly: true))
        let result = try await dao.unreconciledTxids()

        XCTAssertEqual(result, Set<Data>(), "a DB without the view must hold nothing back")
    }

    // MARK: - recoveryBalances (Σ reconciled, mined account_balance_delta)

    func testRecoveryBalancesSumsReconciledMinedDeltas() async throws {
        let path = tempDBPath()
        let setup = try Connection(path)
        // Same-shaped tables exercise the exact read path without rebuilding upstream's schema (the SUM /
        // mined / reconciled gating is what we verify here; v_transactions' own correctness is upstream's).
        try setup.run("CREATE TABLE v_transactions (account_uuid BLOB, mined_height INTEGER, txid BLOB, account_balance_delta INTEGER)")
        try setup.run("CREATE TABLE slipstream_v_tx_reconciled (txid BLOB, reconciled INTEGER)")

        let accountA = [UInt8](Data(repeating: 0x01, count: 16))
        let accountB = [UInt8](Data(repeating: 0x02, count: 16))
        let txReconciled = [UInt8](Data(repeating: 0xA1, count: 32)) // mined + reconciled → counted
        let txDangling = [UInt8](Data(repeating: 0xB2, count: 32))   // mined + reconciled=0 (phantom) → excluded
        let txUnmined = [UInt8](Data(repeating: 0xC3, count: 32))     // reconciled but UNMINED → excluded
        let txAccountB = [UInt8](Data(repeating: 0xD4, count: 32))    // second account, counted

        // account A: +4 ZEC (reconciled, mined) + 5 ZEC phantom (unreconciled) + 1 ZEC unmined → expect 4 ZEC.
        try setup.run("INSERT INTO v_transactions VALUES (?, 100, ?, ?)", Blob(bytes: accountA), Blob(bytes: txReconciled), 400_000_000)
        try setup.run("INSERT INTO v_transactions VALUES (?, 200, ?, ?)", Blob(bytes: accountA), Blob(bytes: txDangling), 500_000_000)
        try setup.run("INSERT INTO v_transactions VALUES (?, NULL, ?, ?)", Blob(bytes: accountA), Blob(bytes: txUnmined), 100_000_000)
        // account B: +2 ZEC (reconciled, mined).
        try setup.run("INSERT INTO v_transactions VALUES (?, 300, ?, ?)", Blob(bytes: accountB), Blob(bytes: txAccountB), 200_000_000)

        try setup.run("INSERT INTO slipstream_v_tx_reconciled VALUES (?, 1)", Blob(bytes: txReconciled))
        try setup.run("INSERT INTO slipstream_v_tx_reconciled VALUES (?, 0)", Blob(bytes: txDangling))
        try setup.run("INSERT INTO slipstream_v_tx_reconciled VALUES (?, 1)", Blob(bytes: txUnmined))
        try setup.run("INSERT INTO slipstream_v_tx_reconciled VALUES (?, 1)", Blob(bytes: txAccountB))

        let dao = TransactionSQLDAO(dbProvider: SimpleConnectionProvider(path: path, readonly: true))
        let result = try await dao.recoveryBalances()

        XCTAssertEqual(
            result[AccountUUID(id: accountA)],
            Zatoshi(400_000_000),
            "account A: only the reconciled, mined +4 ZEC counts — the +5 phantom (unreconciled) and +1 unmined are excluded"
        )
        XCTAssertEqual(result[AccountUUID(id: accountB)], Zatoshi(200_000_000), "account B: reconciled, mined +2 ZEC")
        XCTAssertEqual(result.count, 2, "exactly the two accounts with reconciled mined txs")
    }

    func testRecoveryBalancesReturnsEmptyWhenViewsAbsent() async throws {
        let path = tempDBPath()
        _ = try Connection(path) // empty DB: no v_transactions, no reconcile view

        let dao = TransactionSQLDAO(dbProvider: SimpleConnectionProvider(path: path, readonly: true))
        let result = try await dao.recoveryBalances()

        XCTAssertEqual(result, [:], "a DB without the views reports no recovery balance (caller keeps the live summary)")
    }
}
