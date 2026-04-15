//
//  Broadcaster.swift
//  ZcashLightClientKit
//
//  Created by Adam Tucker on 2026-04-15.
//

import Combine
import Foundation

/// Protocol for creating transactions without immediate submission,
/// and for submitting raw transaction data to specific endpoints.
///
/// This separates the concerns of transaction creation and network
/// submission from the broader synchronization lifecycle managed
/// by ``Synchronizer``. Use this to implement custom broadcast
/// strategies such as submitting to multiple lightwalletd servers
/// in parallel.
///
/// Typical usage:
/// ```swift
/// // 1. Create the transaction(s)
/// let txs = try await synchronizer.broadcaster.createProposedTransactions(
///     proposal: proposal, spendingKey: spendingKey
/// )
///
/// // 2. Submit to one or more endpoints
/// for endpoint in endpoints {
///     try await synchronizer.broadcaster.submit(txs[0].raw!, to: endpoint)
/// }
/// ```
public protocol Broadcaster: AnyObject {
    /// Creates the transactions in the given proposal without submitting
    /// them to the network.
    ///
    /// - Parameter proposal: the proposal for which to create transactions.
    /// - Parameter spendingKey: the `UnifiedSpendingKey` associated with the
    ///   account for which the proposal was created.
    /// - Returns: An array of transaction overviews. Each overview's `raw`
    ///   property contains the serialized transaction bytes suitable for
    ///   later submission via ``submit(_:to:)``.
    ///
    /// If `prepare()` hasn't already been called since creation of the
    /// synchronizer instance or since the last wipe then this method throws
    /// `ZcashError.synchronizerNotPrepared`.
    func createProposedTransactions(
        proposal: Proposal,
        spendingKey: UnifiedSpendingKey
    ) async throws -> [ZcashTransaction.Overview]

    /// Finalizes a PCZT that has been separately proven and signed,
    /// stores it in the wallet, and returns the resulting transactions
    /// without submitting them to the network.
    ///
    /// - Parameter pcztWithProofs: the PCZT with proofs added.
    /// - Parameter pcztWithSigs: the PCZT with signatures added.
    /// - Returns: An array of transaction overviews with `raw` bytes.
    ///
    /// If `prepare()` hasn't already been called since creation of the
    /// synchronizer instance or since the last wipe then this method throws
    /// `ZcashError.synchronizerNotPrepared`.
    func createTransactionFromPCZT(
        pcztWithProofs: Pczt,
        pcztWithSigs: Pczt
    ) async throws -> [ZcashTransaction.Overview]

    /// Submits raw transaction bytes to a specific lightwalletd endpoint.
    ///
    /// Creates an ephemeral connection to the given endpoint, submits the
    /// transaction, and tears down the connection. Respects the current
    /// Tor configuration.
    ///
    /// - Parameter rawTransaction: the raw serialized transaction bytes.
    /// - Parameter endpoint: the `LightWalletEndpoint` to submit to.
    func submit(
        _ rawTransaction: Data,
        to endpoint: LightWalletEndpoint
    ) async throws
}
