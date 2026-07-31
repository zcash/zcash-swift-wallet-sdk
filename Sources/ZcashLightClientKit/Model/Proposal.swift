//
//  Proposal.swift
//
//
//  Created by Jack Grigg on 20/02/2024.
//

import Foundation

/// A data structure that describes a series of transactions to be created.
public struct Proposal: Equatable {
    let inner: FfiProposal

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

    /// Whether any transaction in this proposal spends notes received in the legacy
    /// Orchard pool.
    ///
    /// Post-NU6.3 (Ironwood), spending legacy Orchard notes crosses the Orchard
    /// turnstile, publicly revealing the value that leaves the pool. Wallets use this
    /// to warn before sending. Only wallet notes (`receivedOutput` inputs) are
    /// considered — prior-step references (e.g. the ephemeral transparent leg of a
    /// ZIP 320 TEX proposal) are not wallet notes. Ironwood inputs (which the FFI
    /// encodes as a raw value the current generated enum does not name) do not count
    /// as Orchard.
    public var spendsLegacyOrchardFunds: Bool {
        inner.steps.contains { step in
            step.inputs.contains { input in
                guard case .receivedOutput(let output) = input.value else {
                    return false
                }
                return output.valuePool == .orchard
            }
        }
    }
}

public extension Proposal {
    /// IMPORTANT: This function is for testing purposes only. It produces fake invalid
    /// data that can be used to check UI elements, but will always produce an error when
    /// passed to `Synchronizer.createProposedTransactions`. It should never be called in
    /// production code.
    ///
    /// Set `spendsLegacyOrchardFunds` to `true` to produce a fake proposal whose
    /// `spendsLegacyOrchardFunds` property is `true`.
    static func testOnlyFakeProposal(totalFee: UInt64, spendsLegacyOrchardFunds: Bool = false) -> Self {
        var ffiProposal = FfiProposal()
        var balance = FfiTransactionBalance()

        balance.feeRequired = totalFee

        if spendsLegacyOrchardFunds {
            var receivedOutput = FfiReceivedOutput()
            receivedOutput.txid = Data(repeating: 0, count: 32)
            receivedOutput.valuePool = .orchard
            receivedOutput.index = 0
            receivedOutput.value = 0

            var input = FfiProposedInput()
            input.value = FfiProposedInput.OneOf_Value.receivedOutput(receivedOutput)

            var step = FfiProposalStep()
            step.inputs = [input]

            ffiProposal.steps = [step]
        }

        return Self(inner: ffiProposal)
    }
}
