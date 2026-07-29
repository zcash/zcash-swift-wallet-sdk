//
//  ProposalTests.swift
//  ZcashLightClientKitTests
//
//  Created by Michal Fousek on 2026-07-29.
//

import XCTest
@testable import ZcashLightClientKit

final class ProposalTests: XCTestCase {
    // MARK: - totalSpendValue()

    func testTotalSpendValueWithInputsOnly() throws {
        let proposal = Self.makeProposal(
            steps: [
                Self.Step(inputValues: [1_000_000, 500_000], changeValues: [], fee: 10_000)
            ]
        )

        XCTAssertEqual(proposal.totalSpendValue(), Zatoshi(1_000_000 + 500_000))
    }

    func testTotalSpendValueWithInputsAndChangeSubtractsTheChange() throws {
        let proposal = Self.makeProposal(
            steps: [
                Self.Step(inputValues: [1_000_000], changeValues: [200_000], fee: 10_000)
            ]
        )

        XCTAssertEqual(proposal.totalSpendValue(), Zatoshi(1_000_000 - 200_000))
    }

    func testTotalSpendValueWithMultipleChangeOutputsInAStep() throws {
        let proposal = Self.makeProposal(
            steps: [
                Self.Step(inputValues: [1_000_000], changeValues: [120_000, 80_000], fee: 10_000)
            ]
        )

        XCTAssertEqual(proposal.totalSpendValue(), Zatoshi(1_000_000 - 120_000 - 80_000))
    }

    func testTotalSpendValueSumsAcrossMultipleSteps() throws {
        let proposal = Self.makeProposal(
            steps: [
                Self.Step(inputValues: [1_000_000], changeValues: [100_000], fee: 5_000),
                Self.Step(inputValues: [300_000, 200_000], changeValues: [50_000], fee: 5_000)
            ]
        )

        let expected = Zatoshi((1_000_000 - 100_000) + (300_000 + 200_000 - 50_000))
        XCTAssertEqual(proposal.totalSpendValue(), expected)
    }

    func testTotalSpendValueIgnoresInputsThatAreNotReceivedOutputs() throws {
        let inputs = [
            Self.receivedOutputInput(1_000_000),
            Self.priorStepOutputInput(stepIndex: 0, paymentIndex: 0),
            Self.priorStepChangeInput(stepIndex: 0, changeIndex: 0)
        ]
        let proposal = Self.makeProposal(
            steps: [
                Self.Step(inputs: inputs, changeValues: [], fee: 10_000)
            ]
        )

        // Only the `receivedOutput` input draws new value from the wallet; the prior-step
        // references must not be double-counted.
        XCTAssertEqual(proposal.totalSpendValue(), Zatoshi(1_000_000))
    }

    func testTotalSpendValueIsZeroWhenThereAreNoSteps() throws {
        let proposal = Self.makeProposal(steps: [])

        XCTAssertEqual(proposal.totalSpendValue(), Zatoshi.zero)
    }

    // MARK: - Relationship with totalFeeRequired()

    func testMaxSendableAmountIsTotalSpendValueMinusTotalFeeRequired() throws {
        let proposal = Self.makeProposal(
            steps: [
                Self.Step(inputValues: [2_000_000], changeValues: [], fee: 15_000)
            ]
        )

        XCTAssertEqual(proposal.totalFeeRequired(), Zatoshi(15_000))
        XCTAssertEqual(proposal.totalSpendValue(), Zatoshi(2_000_000))

        let maxSendable = proposal.totalSpendValue() - proposal.totalFeeRequired()
        XCTAssertEqual(maxSendable, Zatoshi(2_000_000 - 15_000))
    }

    func testMaxSendableAmountAcrossMultipleStepsWithChange() throws {
        let proposal = Self.makeProposal(
            steps: [
                Self.Step(inputValues: [1_000_000], changeValues: [50_000], fee: 10_000),
                Self.Step(inputValues: [500_000], changeValues: [], fee: 5_000)
            ]
        )

        let maxSendable = proposal.totalSpendValue() - proposal.totalFeeRequired()

        XCTAssertEqual(maxSendable, Zatoshi((1_000_000 - 50_000 - 10_000) + (500_000 - 5_000)))
    }
}

// MARK: - FfiProposal fixture builders

extension ProposalTests {
    private struct Step {
        let inputs: [FfiProposedInput]
        let changeValues: [UInt64]
        let fee: UInt64

        init(inputValues: [UInt64], changeValues: [UInt64], fee: UInt64) {
            self.inputs = inputValues.map { ProposalTests.receivedOutputInput($0) }
            self.changeValues = changeValues
            self.fee = fee
        }

        init(inputs: [FfiProposedInput], changeValues: [UInt64], fee: UInt64) {
            self.inputs = inputs
            self.changeValues = changeValues
            self.fee = fee
        }
    }

    private static func receivedOutputInput(_ value: UInt64) -> FfiProposedInput {
        var receivedOutput = FfiReceivedOutput()
        receivedOutput.value = value
        var input = FfiProposedInput()
        input.receivedOutput = receivedOutput
        return input
    }

    private static func priorStepOutputInput(stepIndex: UInt32, paymentIndex: UInt32) -> FfiProposedInput {
        var priorStepOutput = FfiPriorStepOutput()
        priorStepOutput.stepIndex = stepIndex
        priorStepOutput.paymentIndex = paymentIndex
        var input = FfiProposedInput()
        input.priorStepOutput = priorStepOutput
        return input
    }

    private static func priorStepChangeInput(stepIndex: UInt32, changeIndex: UInt32) -> FfiProposedInput {
        var priorStepChange = FfiPriorStepChange()
        priorStepChange.stepIndex = stepIndex
        priorStepChange.changeIndex = changeIndex
        var input = FfiProposedInput()
        input.priorStepChange = priorStepChange
        return input
    }

    private static func makeProposal(steps: [Step]) -> Proposal {
        let ffiSteps: [FfiProposalStep] = steps.map { stepSpec in
            var balance = FfiTransactionBalance()
            balance.feeRequired = stepSpec.fee
            balance.proposedChange = stepSpec.changeValues.map { value in
                var change = FfiChangeValue()
                change.value = value
                return change
            }

            var step = FfiProposalStep()
            step.inputs = stepSpec.inputs
            step.balance = balance
            return step
        }

        var ffiProposal = FfiProposal()
        ffiProposal.steps = ffiSteps
        return Proposal(inner: ffiProposal)
    }
}
