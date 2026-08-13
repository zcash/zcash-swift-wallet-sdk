//
//  TransactionEncoder.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 2019-11-20.
//

import Foundation

typealias TransactionEncoderResultBlock = (_ result: Result<EncodedTransaction, Error>) -> Void

public enum TransactionEncoderError: Error {
    case notFound(txId: Data)
    case notEncoded(txId: Data)
    case missingParams
    case spendingKeyWrongNetwork
    case couldNotExpand(txId: Data)
    case submitError(code: Int, message: String)
}

protocol TransactionEncoder {
    /// Creates a proposal for transferring funds to the given recipient.
    ///
    /// - Parameter accountUUID: the account from which to transfer funds.
    /// - Parameter recipient: string containing the recipient's address.
    /// - Parameter amount: the amount to send in Zatoshi.
    /// - Parameter memoBytes: an optional memo to include as part of the proposal's transactions. Use `nil` when sending to transparent receivers otherwise the function will throw an error.
    ///
    /// If `prepare()` hasn't already been called since creation of the synchronizer instance or since the last wipe then this method throws
    /// `SynchronizerErrors.notPrepared`.
    func proposeTransfer(
        accountUUID: AccountUUID,
        recipient: String,
        amount: Zatoshi,
        memoBytes: MemoBytes?
    ) async throws -> Proposal

    /// Proposes migrating the account's entire Orchard balance into the Ironwood pool.
    func proposeOrchardToIronwoodMigration(accountUUID: AccountUUID) async throws -> Proposal

    /// Creates a proposal for shielding any transparent funds received by the given account.
    ///
    /// - Parameter accountUUID:the account from which to shield funds.
    /// - Parameter shieldingThreshold: the minimum transparent balance required before a proposal will be created.
    /// - Parameter memoBytes: an optional memo to include as part of the proposal's transactions.
    /// - Parameter transparentReceiver: a specific transparent receiver within the account
    ///             that should be the source of transparent funds. Default is `nil` which
    ///             will select whichever of the account's transparent receivers has funds
    ///             to shield.
    ///
    /// Returns the proposal, or `nil` if the transparent balance that would be shielded
    /// is zero or below `shieldingThreshold`.
    ///
    /// If `prepare()` hasn't already been called since creation of the synchronizer instance or since the last wipe then this method throws
    /// `SynchronizerErrors.notPrepared`.
    func proposeShielding(
        accountUUID: AccountUUID,
        shieldingThreshold: Zatoshi,
        memoBytes: MemoBytes?,
        transparentReceiver: String?
    ) async throws -> Proposal?

    /// Creates the transactions in the given proposal.
    ///
    /// - Parameter proposal: the proposal for which to create transactions.
    /// - Parameter spendingKey: the `UnifiedSpendingKey` associated with the account for which the proposal was created.
    /// - Throws:
    ///     - `walletTransEncoderCreateTransactionMissingSaplingParams` if the sapling parameters aren't downloaded.
    ///     - Some `ZcashError.rust*` if the creation of transaction(s) fails.
    ///
    /// If `prepare()` hasn't already been called since creation of the synchronizer instance or since the last wipe then this method throws
    /// `SynchronizerErrors.notPrepared`.
    func createProposedTransactions(
        proposal: Proposal,
        spendingKey: UnifiedSpendingKey
    ) async throws -> [ZcashTransaction.Overview]

    /// Creates a transaction proposal to fulfill a [ZIP-321](https://zips.z.cash/zip-0321), throwing an exception whenever things are missing. When the provided wallet implementation
    /// doesn't throw an exception, we wrap the issue into a descriptive exception ourselves (rather than using
    /// double-bangs for things).
    ///
    /// - Parameters:
    /// - Parameter uri: a valid ZIP-321 payment URI.
    /// - Parameter accountUUID: the account the proposal should be made from.
    /// - Throws:
    ///     - `walletTransEncoderCreateTransactionMissingSaplingParams` if the sapling parameters aren't downloaded.
    ///     - Some `ZcashError.rust*` if the creation of transaction fails.
    func proposeFulfillingPaymentFromURI(
        _ uri: String,
        accountUUID: AccountUUID
    ) async throws -> Proposal

    /// submits a transaction to the Zcash peer-to-peer network.
    /// - Parameter transaction: a transaction overview
    func submit(transaction: EncodedTransaction) async throws

    /// Asks the connected lightwalletd backend whether it has the given txid in mempool or chain.
    /// Returns `false` if the server reports `txidNotRecognized` or if the verification call itself fails.
    func isTransactionKnownToServer(txId: Data) async -> Bool

    /// Tries to fetch the transaction for the given transaction ids.
    /// - Parameter txIds: an array of transaction ids to be fetched from the DB.
    func fetchTransactionsForTxIds(_ txIds: [Data]) async throws -> [ZcashTransaction.Overview]

    /// Builds submittable `CreatedTransaction` values for transactions the rust layer has already
    /// created and stored, keyed by their transaction ids.
    ///
    /// Unlike `fetchTransactionsForTxIds`, this must not depend on the transaction being visible
    /// in `v_transactions`: a created transaction whose row is missing from the view (MOB-1703)
    /// must still be returned, so it can be broadcast.
    /// - Parameter txIds: an array of transaction ids, as returned by the create call.
    func createdTransactions(forTxIds txIds: [Data]) async throws -> [CreatedTransaction]

    /// Creates the transactions in the given proposal and returns them ready for submission.
    ///
    /// Same creation semantics as `createProposedTransactions`, but the result carries the raw
    /// transaction bytes needed for broadcast and does not require the created transactions to be
    /// visible in `v_transactions`.
    func createProposedTransactionsForSubmission(
        proposal: Proposal,
        spendingKey: UnifiedSpendingKey
    ) async throws -> [CreatedTransaction]

    func closeDBConnection()
}

extension TransactionEncoder {
    /// Default implementation preserving the historical behavior: read the overviews from
    /// `v_transactions` and wrap them. Conformers backed by the rust layer override this with a
    /// view-independent lookup.
    func createdTransactions(forTxIds txIds: [Data]) async throws -> [CreatedTransaction] {
        try await fetchTransactionsForTxIds(txIds).map { try CreatedTransaction(overview: $0) }
    }

    /// Default implementation preserving the historical behavior: create via
    /// `createProposedTransactions` and wrap the returned overviews.
    func createProposedTransactionsForSubmission(
        proposal: Proposal,
        spendingKey: UnifiedSpendingKey
    ) async throws -> [CreatedTransaction] {
        try await createProposedTransactions(proposal: proposal, spendingKey: spendingKey)
            .map { try CreatedTransaction(overview: $0) }
    }
}
