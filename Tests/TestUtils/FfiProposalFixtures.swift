//
//  FfiProposalFixtures.swift
//  TestUtils
//

import Foundation
@testable import ZcashLightClientKit

/// A shared `FfiProposal`/`Proposal` fixture builder for offline tests.
///
/// `ProposalTests`, `SDKSynchronizerProposeSendMaxTests`, and `SlipstreamSynchronizerSendMaxTests`
/// each used to hand-roll their own private version of this builder. This is the shared home for it,
/// following this directory's `MigrationTestDoubles.swift` precedent. `ProposalSpendsOrchardTests`,
/// `SDKSynchronizerMigrationTests`, `SlipstreamSynchronizerMigrationTests`, and `MigrationLogicTests`
/// keep their own narrower builders for now; they are not migrated here.
enum FfiProposalFixtures {
    /// A single proposed-change entry for a fixture step. Conforms to `ExpressibleByIntegerLiteral` so
    /// call sites can spell change values as bare `UInt64` literals, defaulting to non-ephemeral change.
    struct ChangeValue: ExpressibleByIntegerLiteral {
        let value: UInt64
        let isEphemeral: Bool

        init(value: UInt64, isEphemeral: Bool = false) {
            self.value = value
            self.isEphemeral = isEphemeral
        }

        init(integerLiteral value: UInt64) {
            self.init(value: value)
        }
    }

    /// The inputs, proposed change, and fee for one step of a fixture proposal.
    struct Step {
        let inputs: [FfiProposedInput]
        let changeValues: [ChangeValue]
        let fee: UInt64

        /// The designated initializer: takes fully-formed inputs, so any mix of `receivedOutput`,
        /// `priorStepOutput`, and `priorStepChange` references can be expressed.
        init(inputs: [FfiProposedInput], changeValues: [ChangeValue], fee: UInt64) {
            self.inputs = inputs
            self.changeValues = changeValues
            self.fee = fee
        }

        /// Convenience for the common case where every input is a fresh wallet spend. Wraps each
        /// value as a `receivedOutput` input and delegates to the designated initializer.
        init(inputValues: [UInt64], changeValues: [ChangeValue], fee: UInt64) {
            self.init(
                inputs: inputValues.map { FfiProposalFixtures.receivedOutputInput($0) },
                changeValues: changeValues,
                fee: fee
            )
        }
    }

    /// An input that draws fresh value from a wallet note.
    static func receivedOutputInput(_ value: UInt64) -> FfiProposedInput {
        var receivedOutput = FfiReceivedOutput()
        receivedOutput.value = value
        var input = FfiProposedInput()
        input.receivedOutput = receivedOutput
        return input
    }

    /// An input that references a payment made by an earlier step of the same proposal.
    static func priorStepOutputInput(stepIndex: UInt32, paymentIndex: UInt32) -> FfiProposedInput {
        var priorStepOutput = FfiPriorStepOutput()
        priorStepOutput.stepIndex = stepIndex
        priorStepOutput.paymentIndex = paymentIndex
        var input = FfiProposedInput()
        input.priorStepOutput = priorStepOutput
        return input
    }

    /// An input that references a change (or ephemeral) output produced by an earlier step of the
    /// same proposal.
    static func priorStepChangeInput(stepIndex: UInt32, changeIndex: UInt32) -> FfiProposedInput {
        var priorStepChange = FfiPriorStepChange()
        priorStepChange.stepIndex = stepIndex
        priorStepChange.changeIndex = changeIndex
        var input = FfiProposedInput()
        input.priorStepChange = priorStepChange
        return input
    }

    /// Builds a multi-step `FfiProposal` from step specs. This is the designated builder: every
    /// other `FfiProposal`/`Proposal` builder below delegates to it.
    static func makeFfiProposal(steps: [Step]) -> FfiProposal {
        let ffiSteps: [FfiProposalStep] = steps.map { stepSpec in
            var balance = FfiTransactionBalance()
            balance.feeRequired = stepSpec.fee
            balance.proposedChange = stepSpec.changeValues.map { changeSpec in
                var change = FfiChangeValue()
                change.value = changeSpec.value
                change.isEphemeral = changeSpec.isEphemeral
                return change
            }

            var step = FfiProposalStep()
            step.inputs = stepSpec.inputs
            step.balance = balance
            return step
        }

        var ffiProposal = FfiProposal()
        ffiProposal.steps = ffiSteps
        return ffiProposal
    }

    /// Single-step convenience for tests that only care about a proposal's required fee, e.g. a
    /// mocked rust-backend return value. Delegates to `makeFfiProposal(steps:)`.
    static func makeFfiProposal(feeRequired: UInt64) -> FfiProposal {
        makeFfiProposal(steps: [Step(inputs: [], changeValues: [], fee: feeRequired)])
    }

    /// Builds a multi-step `Proposal` from step specs. Delegates to `makeFfiProposal(steps:)`.
    static func makeProposal(steps: [Step]) -> Proposal {
        Proposal(inner: makeFfiProposal(steps: steps))
    }
}
