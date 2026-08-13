//
//  TransactionDataRequest.swift
//
//
//  Created by Lukáš Korba on 08-15-2024.
//

import Foundation

/// A type describing the mined-ness of transactions that should be returned in response to a
/// `TransactionDataRequest`.
enum TransactionStatusFilter: Equatable {
    /// Only mined transactions should be returned.
    case mined
    /// Only mempool transactions should be returned.
    case mempool
    /// Both mined transactions and transactions in the mempool should be returned.
    case all
}

/// A type used to filter transactions to be returned in response to a `TransactionDataRequest`,
/// in terms of the spentness of the transaction's transparent outputs.
enum OutputStatusFilter: Equatable {
    /// Only transactions that have currently-unspent transparent outputs should be returned.
    case unspent
    /// All transactions corresponding to the data request should be returned, irrespective of
    /// whether or not those transactions produce transparent outputs that are currently unspent.
    case all
}

package struct TransactionsInvolvingAddress: Equatable {
    /// The address to request transactions and/or UTXOs for.
    let address: String
    /// Only transactions mined at heights greater than or equal to this height should be
    /// returned.
    let blockRangeStart: UInt32
    /// If set, only transactions mined at heights less than this height should be returned.
    let blockRangeEnd: UInt32?
    /// If `request_at` is set, the caller evaluating this request should attempt to
    /// retrieve transaction data related to the specified address at a time that is as close
    /// as practical to the specified instant, and in a fashion that decorrelates this request
    /// to a light wallet server from other requests made by the same caller.
    ///
    /// This may be ignored by callers that are able to satisfy the request without exposing
    /// correlations between addresses to untrusted parties; for example, a wallet application
    /// that uses a private, trusted-for-privacy supplier of chain data can safely ignore this
    /// field.
    let requestAt: Date?
    /// The caller should respond to this request only with transactions that conform to the
    /// specified transaction status filter.
    let txStatusFilter: TransactionStatusFilter
    /// The caller should respond to this request only with transactions containing outputs
    /// that conform to the specified output status filter.
    let outputStatusFilter: OutputStatusFilter
}

/// A request for transaction data enhancement, spentness check, or discovery
/// of spends from a given transparent address within a specific block range.
package enum TransactionDataRequest: Equatable {
    /// Information about the chain's view of a transaction is requested.
    ///
    /// The caller evaluating this request on behalf of the wallet backend should respond to this
    /// request by determining the status of the specified transaction with respect to the main
    /// chain; if using `lightwalletd` for access to chain data, this may be obtained by
    /// interpreting the results of the `GetTransaction` RPC method. It should then call
    /// `ZcashRustBackend.setTransactionStatus` to provide the resulting transaction status
    /// information to the wallet backend.
    case getStatus([UInt8])
    /// Transaction enhancement (download of complete raw transaction data) is requested.
    ///
    /// The caller evaluating this request on behalf of the wallet backend should respond to this
    /// request by providing complete data for the specified transaction to
    /// `ZcashRustBackend.decryptAndStoreTransaction`; if using `lightwalletd` for access to chain
    /// state, this may be obtained via the `GetTransaction` RPC method. If no data is available
    /// for the specified transaction, this should be reported to the backend using
    /// `ZcashRustBackend.setTransactionStatus`. A `TransactionDataRequest.enhancement` request
    /// subsumes any previously existing `TransactionDataRequest.getStatus` request.
    case enhancement([UInt8])
    /// Information about transactions that receive or spend funds belonging to the specified
    /// transparent address is requested.
    ///
    /// Fully transparent transactions, and transactions that do not contain either shielded inputs
    /// or shielded outputs belonging to the wallet, may not be discovered by the process of chain
    /// scanning; as a consequence, the wallet must actively query to find transactions that spend
    /// such funds. Ideally we'd be able to query by `OutPoint` but this is not currently
    /// functionality that is supported by the light wallet server.
    ///
    /// The caller evaluating this request on behalf of the wallet backend should respond to this
    /// request by detecting transactions involving the specified address within the provided block
    /// range; if using `lightwalletd` for access to chain data, this may be performed using the
    /// `GetTaddressTransactions` RPC method. It should then call `ZcashRustBackend.decryptAndStoreTransaction`
    /// for each transaction so detected.
    case transactionsInvolvingAddress(TransactionsInvolvingAddress)
}

/// Metadata about the status of a transaction obtained by inspecting the chain state.
package enum TransactionStatus: Equatable {
    /// The requested transaction ID was not recognized by the node.
    case txidNotRecognized
    /// The requested transaction ID corresponds to a transaction that is recognized by the node,
    /// but is in the mempool or is otherwise not mined in the main chain (but may have been mined
    /// on a fork that was reorged away).
    case notInMainChain
    /// The requested transaction ID corresponds to a transaction that has been included in the
    /// block at the provided height.
    case mined(BlockHeight)
}
