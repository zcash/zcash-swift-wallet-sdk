//
//  SlipstreamSynchronizerSendMaxTests.swift
//  ZcashLightClientKit
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

/// `proposeSendMax`'s prepared-state guard on `SlipstreamSynchronizer` -- this actor's analog of
/// `SDKSynchronizerProposeSendMaxTests.testProposeSendMaxThrowsWhenSynchronizerIsNotPrepared`. The
/// synchronizer is built the same mocked-rust-backend way that sibling suite builds `SDKSynchronizer`
/// (`makeSynchronizer(rustBackend:)`), substituted through the same container-mock seam
/// `SlipstreamSynchronizer.init` resolves both `rustBackend` and its own `OrchardMigrationHost`
/// through -- see `SlipstreamSynchronizerMigrationTests.makeSynchronizer(migrationHost:)` for that
/// same seam applied to the migration host specifically.
final class SlipstreamSynchronizerSendMaxTests: ZcashTestCase {
    private let recipientAddress = "zs1vp7kvlqr4n9gpehztr76lcn6skkss9p8keqs3nv8avkdtjrcctrvmk9a7u494kluv756jeee5k0"

    /// A synchronizer that never had `prepare()` called must reject `proposeSendMax` with
    /// `synchronizerNotPrepared`, mirroring `SDKSynchronizer`'s `throwIfUnprepared()` contract
    /// (`SDKSynchronizerProposeSendMaxTests.testProposeSendMaxThrowsWhenSynchronizerIsNotPrepared`).
    /// The rust backend is pre-armed with a valid proposal so that, absent the guard, the call would
    /// succeed instead of throwing -- proving a failure here comes from the missing guard, not some
    /// unrelated backend error.
    func testProposeSendMaxThrowsWhenSynchronizerIsNotPrepared() async throws {
        let rustBackend = ZcashRustBackendWeldingMock()
        rustBackend.proposeSendMaxTransferAccountUUIDToMemoModeReturnValue = FfiProposalFixtures.makeFfiProposal(feeRequired: 5_000)
        let synchronizer = try makeSynchronizer(rustBackend: rustBackend)
        // Status is left at its initial `.unprepared` value -- `prepare()` is deliberately not called.

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

        XCTAssertEqual(
            rustBackend.proposeSendMaxTransferAccountUUIDToMemoModeCallsCount,
            0,
            "The rust backend must not be reached when the synchronizer isn't prepared"
        )
    }

    // MARK: - Helpers

    private func makeSynchronizer(rustBackend: ZcashRustBackendWelding) throws -> SlipstreamSynchronizer {
        mockContainer.mock(type: ZcashRustBackendWelding.self, isSingleton: true) { _ in rustBackend }
        mockContainer.mock(type: LightWalletService.self, isSingleton: true) { _ in LightWalletServiceMock() }
        mockContainer.mock(type: TransactionRepository.self, isSingleton: true) { _ in TransactionRepositoryMock() }

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

        return SlipstreamSynchronizer(initializer: initializer)
    }
}
