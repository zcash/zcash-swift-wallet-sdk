//
//  TransactionRepository.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 11/16/19.
//

import Foundation

protocol TransactionRepository {
    func closeDBConnection()
    func countAll() async throws -> Int
    func countUnmined() async throws -> Int
    func isInitialized() async throws -> Bool
    func fetchTxidsWithMemoContaining(searchTerm: String) async throws -> [Data]
    func find(rawID: Data) async throws -> ZcashTransaction.Overview
    func find(offset: Int, limit: Int, kind: TransactionKind) async throws -> [ZcashTransaction.Overview]
    func find(in range: CompactBlockRange, limit: Int, kind: TransactionKind) async throws -> [ZcashTransaction.Overview]
    func find(from: ZcashTransaction.Overview, limit: Int, kind: TransactionKind) async throws -> [ZcashTransaction.Overview]
    func findPendingTransactions(latestHeight: BlockHeight, offset: Int, limit: Int) async throws -> [ZcashTransaction.Overview]
    func findReceived(offset: Int, limit: Int) async throws -> [ZcashTransaction.Overview]
    func findSent(offset: Int, limit: Int) async throws -> [ZcashTransaction.Overview]
    func findForResubmission(upTo: BlockHeight) async throws -> [ZcashTransaction.Overview]
    // sourcery: mockedName="findMemosForRawID"
    func findMemos(for rawID: Data) async throws -> [Memo]
    // sourcery: mockedName="findMemosForZcashTransaction"
    func findMemos(for transaction: ZcashTransaction.Overview) async throws -> [Memo]
    func getRecipients(for rawID: Data) async throws -> [TransactionRecipient]
    func getTransactionOutputs(for rawID: Data) async throws -> [ZcashTransaction.Output]
    func debugDatabase(sql: String) -> String

    /// [#1755] Txids whose `account_balance_delta` is not yet final during a deep recovery — read from
    /// the slipstream-owned `slipstream_v_tx_reconciled` view. A recent-first restore can scan a spend
    /// before its input's origin block, so the spend is transiently unattributed and the tx reads as a
    /// phantom "+receive". Consumers hold these txs out of the Activity list until they reconcile. The
    /// default returns an empty set: a DB without the view (legacy / non-slipstream) holds nothing back.
    func unreconciledTxids() async throws -> Set<Data>

    /// [#1755] Per-account as-recovered balance during a recent-first restore: Σ `account_balance_delta`
    /// over the wallet's MINED transactions whose delta is final — excluding the txids the
    /// `slipstream_v_tx_reconciled` view marks `reconciled = 0`. A tx is unreconciled exactly when it has a
    /// dangling shielded spend (the backfill scanned the spend before its input's origin block), which is
    /// the same condition that makes its delta transiently wrong. Summing only correct deltas can never
    /// over-count and converges to the true total as the backfill links spends; it is consistent with the
    /// (reconciled) Activity list by construction. Default empty: a DB without the view (legacy /
    /// non-slipstream) reports nothing and the caller keeps the live summary.
    func recoveryBalances() async throws -> [AccountUUID: Zatoshi]
}

extension TransactionRepository {
    func unreconciledTxids() async throws -> Set<Data> { [] }
    func recoveryBalances() async throws -> [AccountUUID: Zatoshi] { [:] }
}
