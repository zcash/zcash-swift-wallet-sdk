//
//  SlipstreamReconcileReadTests.swift
//  ZcashLightClientKit-Unit-Tests
//
//  [#1755] Covers the SDK read side of the slipstream reconciliation gate:
//  `TransactionSQLDAO.unreconciledTxids()` reads the `ext_slipstream_v_tx_reconciled`
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
        try setup.run("CREATE TABLE ext_slipstream_v_tx_reconciled (txid BLOB, reconciled INTEGER)")

        let unreconciled = Data(repeating: 0xAA, count: 32)
        let reconciled = Data(repeating: 0xBB, count: 32)
        try setup.run(
            "INSERT INTO ext_slipstream_v_tx_reconciled (txid, reconciled) VALUES (?, 0)",
            Blob(bytes: [UInt8](unreconciled))
        )
        try setup.run(
            "INSERT INTO ext_slipstream_v_tx_reconciled (txid, reconciled) VALUES (?, 1)",
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

    // [v2.1 Phase 2] The recoveryBalances DAO tests are GONE with the DAO method: the
    // Σ-reconciled recovery balance is resolved inside `zcashlc_slipstream_wallet_summary`
    // (the engine view is crate-tested in slipstream-core; the FFI resolution in rust/).
}
