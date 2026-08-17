//
//  SlipstreamSynchronizerGuardTests.swift
//  ZcashLightClientKit
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

/// Prepared-state guards on the four `SlipstreamSynchronizer.propose*` methods that, unlike
/// `proposeSendMax`, did not yet reject calls made before `prepare()`. Sibling coverage to
/// `SlipstreamSynchronizerSendMaxTests.testProposeSendMaxThrowsWhenSynchronizerIsNotPrepared`, one test
/// per method: `proposeTransfer`, `proposeShielding`, `proposeOrchardToIronwoodMigration`, and
/// `proposefulfillingPaymentURI`. Each mirrors the corresponding `SDKSynchronizer` method's
/// `throwIfUnprepared()` contract. The synchronizer is built the same mocked-rust-backend way as that
/// sibling suite (`makeSynchronizer(rustBackend:)`), substituted through the same container-mock seam
/// `SlipstreamSynchronizer.init` resolves `rustBackend` through.
final class SlipstreamSynchronizerGuardTests: ZcashTestCase {
    private let recipientAddress = "zs1vp7kvlqr4n9gpehztr76lcn6skkss9p8keqs3nv8avkdtjrcctrvmk9a7u494kluv756jeee5k0"

    /// A synchronizer that never had `prepare()` called must reject `proposeTransfer` with
    /// `synchronizerNotPrepared`. The rust backend is pre-armed with a valid proposal so that, absent
    /// the guard, the call would succeed instead of throwing -- proving a failure here comes from the
    /// missing guard, not some unrelated backend error.
    func testProposeTransferThrowsWhenSynchronizerIsNotPrepared() async throws {
        let rustBackend = ZcashRustBackendWeldingMock()
        rustBackend.proposeTransferAccountUUIDToValueMemoReturnValue =
            FfiProposalFixtures.makeFfiProposal(feeRequired: 5_000)
        let synchronizer = try makeSynchronizer(rustBackend: rustBackend)
        // Status is left at its initial `.unprepared` value -- `prepare()` is deliberately not called.

        let recipient = Recipient.sapling(SaplingAddress(validatedEncoding: recipientAddress))

        do {
            _ = try await synchronizer.proposeTransfer(
                accountUUID: TestsData.mockedAccountUUID,
                recipient: recipient,
                amount: Zatoshi(10_000),
                memo: nil
            )
            XCTFail("Expected proposeTransfer to throw when the synchronizer isn't prepared")
        } catch let error as ZcashError {
            guard case .synchronizerNotPrepared = error else {
                XCTFail("Expected synchronizerNotPrepared but got \(error)")
                return
            }
        }

        XCTAssertEqual(
            rustBackend.proposeTransferAccountUUIDToValueMemoCallsCount,
            0,
            "The rust backend must not be reached when the synchronizer isn't prepared"
        )
    }

    /// A synchronizer that never had `prepare()` called must reject `proposeShielding` with
    /// `synchronizerNotPrepared`. Pre-armed the same way as the transfer case above.
    func testProposeShieldingThrowsWhenSynchronizerIsNotPrepared() async throws {
        let rustBackend = ZcashRustBackendWeldingMock()
        rustBackend.proposeShieldingAccountUUIDMemoShieldingThresholdTransparentReceiverReturnValue =
            FfiProposalFixtures.makeFfiProposal(feeRequired: 5_000)
        let synchronizer = try makeSynchronizer(rustBackend: rustBackend)
        // Status is left at its initial `.unprepared` value -- `prepare()` is deliberately not called.

        do {
            _ = try await synchronizer.proposeShielding(
                accountUUID: TestsData.mockedAccountUUID,
                shieldingThreshold: Zatoshi(10_000),
                memo: try Memo(string: "shielding")
            )
            XCTFail("Expected proposeShielding to throw when the synchronizer isn't prepared")
        } catch let error as ZcashError {
            guard case .synchronizerNotPrepared = error else {
                XCTFail("Expected synchronizerNotPrepared but got \(error)")
                return
            }
        }

        XCTAssertEqual(
            rustBackend.proposeShieldingAccountUUIDMemoShieldingThresholdTransparentReceiverCallsCount,
            0,
            "The rust backend must not be reached when the synchronizer isn't prepared"
        )
    }

    /// A synchronizer that never had `prepare()` called must reject `proposeOrchardToIronwoodMigration`
    /// with `synchronizerNotPrepared`. Pre-armed the same way as the transfer case above.
    func testProposeOrchardToIronwoodMigrationThrowsWhenSynchronizerIsNotPrepared() async throws {
        let rustBackend = ZcashRustBackendWeldingMock()
        rustBackend.proposeOrchardToIronwoodMigrationAccountUUIDReturnValue =
            FfiProposalFixtures.makeFfiProposal(feeRequired: 5_000)
        let synchronizer = try makeSynchronizer(rustBackend: rustBackend)
        // Status is left at its initial `.unprepared` value -- `prepare()` is deliberately not called.

        do {
            _ = try await synchronizer.proposeOrchardToIronwoodMigration(accountUUID: TestsData.mockedAccountUUID)
            XCTFail("Expected proposeOrchardToIronwoodMigration to throw when the synchronizer isn't prepared")
        } catch let error as ZcashError {
            guard case .synchronizerNotPrepared = error else {
                XCTFail("Expected synchronizerNotPrepared but got \(error)")
                return
            }
        }

        XCTAssertEqual(
            rustBackend.proposeOrchardToIronwoodMigrationAccountUUIDCallsCount,
            0,
            "The rust backend must not be reached when the synchronizer isn't prepared"
        )
    }

    /// A synchronizer that never had `prepare()` called must reject `proposefulfillingPaymentURI` with
    /// `synchronizerNotPrepared`. The guard must fire before any URI parsing, so the URI content itself
    /// is unimportant here -- a syntactically plausible testnet ZIP-321 URI is used, pre-armed the same
    /// way as the transfer case above.
    func testProposefulfillingPaymentURIThrowsWhenSynchronizerIsNotPrepared() async throws {
        let rustBackend = ZcashRustBackendWeldingMock()
        rustBackend.proposeTransferFromURIAccountUUIDReturnValue =
            FfiProposalFixtures.makeFfiProposal(feeRequired: 5_000)
        let synchronizer = try makeSynchronizer(rustBackend: rustBackend)
        // Status is left at its initial `.unprepared` value -- `prepare()` is deliberately not called.

        let paymentURI = "zcash:\(recipientAddress)?amount=0.0002"

        do {
            _ = try await synchronizer.proposefulfillingPaymentURI(paymentURI, accountUUID: TestsData.mockedAccountUUID)
            XCTFail("Expected proposefulfillingPaymentURI to throw when the synchronizer isn't prepared")
        } catch let error as ZcashError {
            guard case .synchronizerNotPrepared = error else {
                XCTFail("Expected synchronizerNotPrepared but got \(error)")
                return
            }
        }

        XCTAssertEqual(
            rustBackend.proposeTransferFromURIAccountUUIDCallsCount,
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
