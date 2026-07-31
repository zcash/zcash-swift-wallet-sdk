//
//  ProposalSpendsOrchardTests.swift
//  OfflineTests
//

import XCTest
@testable import ZcashLightClientKit

final class ProposalSpendsOrchardTests: XCTestCase {
    func testReceivedOrchardOutputSpendsLegacyOrchardFunds() {
        let output = Self.makeReceivedOutput(valuePool: .orchard)
        let input = Self.makeProposedInput(FfiProposedInput.OneOf_Value.receivedOutput(output))
        let proposal = Self.makeProposal(steps: [Self.makeStep(inputs: [input])])

        XCTAssertTrue(proposal.spendsLegacyOrchardFunds)
    }

    func testSaplingAndTransparentInputsDoNotSpendLegacyOrchardFunds() {
        let saplingOutput = Self.makeReceivedOutput(valuePool: .sapling)
        let transparentOutput = Self.makeReceivedOutput(valuePool: .transparent)
        let inputs = [
            Self.makeProposedInput(FfiProposedInput.OneOf_Value.receivedOutput(saplingOutput)),
            Self.makeProposedInput(FfiProposedInput.OneOf_Value.receivedOutput(transparentOutput))
        ]
        let proposal = Self.makeProposal(steps: [Self.makeStep(inputs: inputs)])

        XCTAssertFalse(proposal.spendsLegacyOrchardFunds)
    }

    func testIronwoodInputDoesNotCountAsOrchard() throws {
        // Construct via `rawValue:` rather than `.UNRECOGNIZED(4)` directly, so this test keeps covering
        // Ironwood decode-path-stable even after a future proto regeneration names case 4.
        let ironwoodPool = try XCTUnwrap(FfiValuePool(rawValue: 4))
        let output = Self.makeReceivedOutput(valuePool: ironwoodPool)
        let input = Self.makeProposedInput(FfiProposedInput.OneOf_Value.receivedOutput(output))
        let proposal = Self.makeProposal(steps: [Self.makeStep(inputs: [input])])

        XCTAssertFalse(proposal.spendsLegacyOrchardFunds)
    }

    func testPriorStepReferencesDoNotCountAsWalletNotes() {
        var priorStepOutput = FfiPriorStepOutput()
        priorStepOutput.stepIndex = 0
        priorStepOutput.paymentIndex = 0

        var priorStepChange = FfiPriorStepChange()
        priorStepChange.stepIndex = 0
        priorStepChange.changeIndex = 0

        let inputs = [
            Self.makeProposedInput(FfiProposedInput.OneOf_Value.priorStepOutput(priorStepOutput)),
            Self.makeProposedInput(FfiProposedInput.OneOf_Value.priorStepChange(priorStepChange))
        ]
        let proposal = Self.makeProposal(steps: [Self.makeStep(inputs: inputs)])

        XCTAssertFalse(proposal.spendsLegacyOrchardFunds)
    }

    func testOrchardInputInSecondStepIsDetected() {
        let transparentOutput = Self.makeReceivedOutput(valuePool: .transparent)
        let firstStep = Self.makeStep(
            inputs: [Self.makeProposedInput(FfiProposedInput.OneOf_Value.receivedOutput(transparentOutput))]
        )

        let orchardOutput = Self.makeReceivedOutput(valuePool: .orchard)
        let secondStep = Self.makeStep(
            inputs: [Self.makeProposedInput(FfiProposedInput.OneOf_Value.receivedOutput(orchardOutput))]
        )

        let proposal = Self.makeProposal(steps: [firstStep, secondStep])

        XCTAssertTrue(proposal.spendsLegacyOrchardFunds)
    }

    func testProposalWithNoStepsDoesNotSpendLegacyOrchardFunds() {
        let proposal = Self.makeProposal(steps: [])

        XCTAssertFalse(proposal.spendsLegacyOrchardFunds)
    }

    func testFactoryDefaultsToNotSpendingLegacyOrchardFunds() {
        let proposal = Proposal.testOnlyFakeProposal(totalFee: 0)

        XCTAssertFalse(proposal.spendsLegacyOrchardFunds)
    }

    func testFactoryCanProduceProposalThatSpendsLegacyOrchardFunds() {
        let proposal = Proposal.testOnlyFakeProposal(totalFee: 0, spendsLegacyOrchardFunds: true)

        XCTAssertTrue(proposal.spendsLegacyOrchardFunds)
    }

    func testFactoryTotalFeeIsZeroInBothBranches() {
        // testOnlyFakeProposal never attaches its `balance` (and thus `totalFee`) to any step, in either
        // branch, so totalFeeRequired() is always Zatoshi.zero. Pin both branches so a future edit can't
        // change fee behavior in only one of them.
        XCTAssertEqual(
            Proposal.testOnlyFakeProposal(totalFee: 10, spendsLegacyOrchardFunds: false).totalFeeRequired(),
            Zatoshi.zero
        )
        XCTAssertEqual(
            Proposal.testOnlyFakeProposal(totalFee: 10, spendsLegacyOrchardFunds: true).totalFeeRequired(),
            Zatoshi.zero
        )
    }

    // MARK: - Helpers

    private static func makeReceivedOutput(
        valuePool: FfiValuePool,
        index: UInt32 = 0,
        value: UInt64 = 0
    ) -> FfiReceivedOutput {
        var output = FfiReceivedOutput()
        output.txid = Data(repeating: 0xAB, count: 32)
        output.valuePool = valuePool
        output.index = index
        output.value = value
        return output
    }

    private static func makeProposedInput(_ value: FfiProposedInput.OneOf_Value) -> FfiProposedInput {
        var input = FfiProposedInput()
        input.value = value
        return input
    }

    private static func makeStep(inputs: [FfiProposedInput]) -> FfiProposalStep {
        var step = FfiProposalStep()
        step.inputs = inputs
        return step
    }

    private static func makeProposal(steps: [FfiProposalStep]) -> Proposal {
        var ffiProposal = FfiProposal()
        ffiProposal.steps = steps
        return Proposal(inner: ffiProposal)
    }
}
