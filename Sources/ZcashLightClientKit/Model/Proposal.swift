//
//  Proposal.swift
//
//
//  Created by Jack Grigg on 20/02/2024.
//

import Foundation

/// A data structure that describes a series of transactions to be created.
public struct Proposal: Equatable {
    /// PIR witness configuration attached to a proposal.
    ///
    /// Set `serverURL` before calling `createProposedTransactions` so the SDK
    /// can fetch Orchard witnesses from the PIR server when the wallet is not
    /// fully synced.  The SDK sets `usePIRWitnesses` internally based on sync
    /// status and retry logic.
    public struct PIRWitnessConfig: Equatable, Sendable {
        public let serverURL: String
        public internal(set) var usePIRWitnesses: Bool

        public init(serverURL: String) {
            self.serverURL = serverURL
            self.usePIRWitnesses = false
        }
    }

    let inner: FfiProposal

    /// Optional PIR witness configuration. When set, the SDK will use the
    /// provided server URL to fetch Orchard witnesses if the wallet is not
    /// fully synced, enabling spending before scanning completes.
    public var pirWitnessConfig: PIRWitnessConfig?

    /// Returns the number of transactions that this proposal will create.
    ///
    /// This is equal to the number of `TransactionSubmitResult`s that will be returned
    /// from `Synchronizer.createProposedTransactions`.
    ///
    /// Proposals always create at least one transaction.
    public func transactionCount() -> Int {
        inner.steps.count
    }

    /// Returns the total fee to be paid across all proposed transactions, in zatoshis.
    public func totalFeeRequired() -> Zatoshi {
        inner.steps.reduce(Zatoshi.zero) { acc, step in
            acc + Zatoshi(Int64(step.balance.feeRequired))
        }
    }
}

public extension Proposal {
    /// IMPORTANT: This function is for testing purposes only. It produces fake invalid
    /// data that can be used to check UI elements, but will always produce an error when
    /// passed to `Synchronizer.createProposedTransactions`. It should never be called in
    /// production code.
    static func testOnlyFakeProposal(totalFee: UInt64) -> Self {
        let ffiProposal = FfiProposal()
        var balance = FfiTransactionBalance()

        balance.feeRequired = totalFee

        return Self(inner: ffiProposal)
    }
}
