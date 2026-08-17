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
    /// This property describes the proposal's inputs only — it does not know or care whether NU6.3 is active; callers
    /// deciding whether to warn should apply their own network/activation context if they support pre-activation
    /// networks. Only wallet notes (`receivedOutput` inputs) are considered: prior-step references point at outputs
    /// created by an earlier step of this same proposal, so any legacy-Orchard value entering the proposal necessarily
    /// appears as a `receivedOutput` in some step. Ironwood (ZIP 2005) inputs do not count as Orchard.
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

    /// Returns the total value this proposal spends, before its fee is deducted, in zatoshis.
    ///
    /// This is the sum of the values of every step's inputs (only the `.receivedOutput` case draws
    /// new value from the wallet; an input that is a prior step's own output or change does not)
    /// minus the sum of every step's proposed change values.
    ///
    /// Combine with `totalFeeRequired()` to derive the maximum amount a "spend max" proposal can
    /// send to its recipient: `totalSpendValue() - totalFeeRequired()`.
    public func totalSpendValue() -> Zatoshi {
        inner.steps.reduce(Zatoshi.zero) { total, step in
            let stepInputs = step.inputs.reduce(Zatoshi.zero) { inputTotal, input in
                guard case .receivedOutput(let output) = input.value else {
                    return inputTotal
                }
                return inputTotal + Zatoshi(Int64(output.value))
            }
            let stepChange = step.balance.proposedChange.reduce(Zatoshi.zero) { changeTotal, change in
                changeTotal + Zatoshi(Int64(change.value))
            }
            return total + stepInputs - stepChange
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
            receivedOutput.txid = Data(repeating: 0, count: TxId.byteLength)
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
