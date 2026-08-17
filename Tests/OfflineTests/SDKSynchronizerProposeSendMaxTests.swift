//
//  SDKSynchronizerProposeSendMaxTests.swift
//  ZcashLightClientKitTests
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class SDKSynchronizerProposeSendMaxTests: ZcashTestCase {
    private let recipientAddress = "zs1vp7kvlqr4n9gpehztr76lcn6skkss9p8keqs3nv8avkdtjrcctrvmk9a7u494kluv756jeee5k0"
    private let transparentAddress = "t1dRJRY7GmyeykJnMH38mdQoaZtFhn1QmGz"

    // MARK: - Pass-through to the rust backend

    func testProposeSendMaxPassesArgumentsThroughToTheRustBackendAndReturnsTheWrappedProposal() async throws {
        let rustBackend = ZcashRustBackendWeldingMock()
        let ffiProposal = Self.makeFfiProposal(feeRequired: 5_000)
        rustBackend.proposeSendMaxTransferAccountUUIDToMemoModeReturnValue = ffiProposal

        let synchronizer = try makeSynchronizer(rustBackend: rustBackend)
        await synchronizer.updateStatus(.stopped)

        let accountUUID = TestsData.mockedAccountUUID
        let recipient = Recipient.sapling(SaplingAddress(validatedEncoding: recipientAddress))
        let memo = try Memo(string: "thank you")
        let mode = MaxSpendMode.everything

        let proposal = try await synchronizer.proposeSendMax(
            accountUUID: accountUUID,
            recipient: recipient,
            memo: memo,
            mode: mode
        )

        XCTAssertEqual(proposal, Proposal(inner: ffiProposal))
        XCTAssertEqual(rustBackend.proposeSendMaxTransferAccountUUIDToMemoModeCallsCount, 1)

        let receivedArguments = try XCTUnwrap(rustBackend.proposeSendMaxTransferAccountUUIDToMemoModeReceivedArguments)
        XCTAssertEqual(receivedArguments.accountUUID, accountUUID)
        XCTAssertEqual(receivedArguments.address, recipient.stringEncoded)
        XCTAssertEqual(receivedArguments.memo, try memo.asMemoBytes())
        XCTAssertEqual(receivedArguments.mode, mode)
    }

    func testProposeSendMaxAllowsNilMemoForTransparentRecipientAndPassesArgumentsThrough() async throws {
        let rustBackend = ZcashRustBackendWeldingMock()
        let ffiProposal = Self.makeFfiProposal(feeRequired: 1_000)
        rustBackend.proposeSendMaxTransferAccountUUIDToMemoModeReturnValue = ffiProposal

        let synchronizer = try makeSynchronizer(rustBackend: rustBackend)
        await synchronizer.updateStatus(.stopped)

        let recipient = Recipient.transparent(TransparentAddress(validatedEncoding: transparentAddress))

        let proposal = try await synchronizer.proposeSendMax(
            accountUUID: TestsData.mockedAccountUUID,
            recipient: recipient,
            memo: nil,
            mode: .maxSpendable
        )

        XCTAssertEqual(proposal, Proposal(inner: ffiProposal))

        let receivedArguments = try XCTUnwrap(rustBackend.proposeSendMaxTransferAccountUUIDToMemoModeReceivedArguments)
        XCTAssertEqual(receivedArguments.address, recipient.stringEncoded)
        XCTAssertNil(receivedArguments.memo)
        XCTAssertEqual(receivedArguments.mode, .maxSpendable)
    }

    // MARK: - Guards

    func testProposeSendMaxThrowsWhenMemoIsSuppliedForATransparentRecipient() async throws {
        let rustBackend = ZcashRustBackendWeldingMock()
        let synchronizer = try makeSynchronizer(rustBackend: rustBackend)
        await synchronizer.updateStatus(.stopped)

        let recipient = Recipient.transparent(TransparentAddress(validatedEncoding: transparentAddress))
        let memo = try Memo(string: "not allowed")

        do {
            _ = try await synchronizer.proposeSendMax(
                accountUUID: TestsData.mockedAccountUUID,
                recipient: recipient,
                memo: memo,
                mode: .maxSpendable
            )
            XCTFail("Expected proposeSendMax to throw synchronizerSendMemoToTransparentAddress")
        } catch let error as ZcashError {
            guard case .synchronizerSendMemoToTransparentAddress = error else {
                XCTFail("Expected synchronizerSendMemoToTransparentAddress but got \(error)")
                return
            }
        }

        XCTAssertEqual(
            rustBackend.proposeSendMaxTransferAccountUUIDToMemoModeCallsCount,
            0,
            "The rust backend must not be reached when the memo-to-transparent-recipient guard rejects the request"
        )
    }

    func testProposeSendMaxThrowsWhenSynchronizerIsNotPrepared() async throws {
        let rustBackend = ZcashRustBackendWeldingMock()
        let synchronizer = try makeSynchronizer(rustBackend: rustBackend)
        // Status is left at its initial `.unprepared` value; `updateStatus` is deliberately not called.

        let recipient = Recipient.sapling(SaplingAddress(validatedEncoding: recipientAddress))

        do {
            _ = try await synchronizer.proposeSendMax(
                accountUUID: TestsData.mockedAccountUUID,
                recipient: recipient,
                memo: nil,
                mode: .maxSpendable
            )
            XCTFail("Expected proposeSendMax to throw when the synchronizer isn't prepared")
        } catch let error as ZcashError {
            guard case .synchronizerNotPrepared = error else {
                XCTFail("Expected synchronizerNotPrepared but got \(error)")
                return
            }
        }
    }

    // MARK: - Helpers

    private func makeSynchronizer(rustBackend: ZcashRustBackendWelding) throws -> SDKSynchronizer {
        mockContainer.mock(type: ZcashRustBackendWelding.self, isSingleton: true) { _ in rustBackend }
        mockContainer.mock(type: LightWalletService.self, isSingleton: true) { _ in LightWalletServiceMock() }
        mockContainer.mock(type: TransactionRepository.self, isSingleton: true) { _ in TransactionRepositoryMock() }
        mockContainer.mock(type: Logger.self, isSingleton: true) { _ in submissionLifecycleLogger() }

        let initializer = Initializer(
            container: mockContainer,
            cacheDbURL: nil,
            fsBlockDbRoot: testTempDirectory,
            generalStorageURL: testGeneralStorageDirectory,
            dataDbURL: try __dataDbURL(),
            torDirURL: try __torDirURL(),
            endpoint: LightWalletEndpointBuilder.default,
            network: ZcashNetworkBuilder.network(for: .testnet),
            spendParamsURL: try __spendParamsURL(),
            outputParamsURL: try __outputParamsURL(),
            saplingParamsSourceURL: SaplingParamsSourceURL.tests,
            isTorEnabled: false,
            isExchangeRateEnabled: false
        )

        return SDKSynchronizer(initializer: initializer)
    }

    private static func makeFfiProposal(feeRequired: UInt64) -> FfiProposal {
        var balance = FfiTransactionBalance()
        balance.feeRequired = feeRequired

        var step = FfiProposalStep()
        step.balance = balance

        var proposal = FfiProposal()
        proposal.steps = [step]
        return proposal
    }
}
