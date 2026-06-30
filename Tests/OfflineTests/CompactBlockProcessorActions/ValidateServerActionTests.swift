//
//  ValidateServerActionTests.swift
//
//
//  Created by Lukáš Korba on 16.05.2023.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class ValidateServerActionTests: ZcashTestCase {
    var underlyingChainName = ""
    var underlyingNetworkType = NetworkType.testnet
    var underlyingSaplingActivationHeight: BlockHeight?
    var underlyingConsensusBranchID = ""

    override func setUp() {
        super.setUp()

        underlyingChainName = "test"
        underlyingNetworkType = .testnet
        underlyingSaplingActivationHeight = nil
        underlyingConsensusBranchID = "c2d6d0b4"
    }

    func testValidateServerAction_NextAction() async throws {
        let validateServerAction = setupAction()

        do {
            let context = ActionContextMock.default()
            let nextContext = try await validateServerAction.run(with: context) { _ in }

            let acResult = nextContext.checkStateIs(.fetchUTXO)
            XCTAssertTrue(acResult == .true, "Check of state failed with '\(acResult)'")
        } catch {
            XCTFail("testValidateServerAction_NextAction is not expected to fail. \(error)")
        }
    }

    func testValidateServerAction_ChainNameError() async throws {
        underlyingChainName = "invalid"

        let validateServerAction = setupAction()

        do {
            _ = try await validateServerAction.run(with: ActionContextMock()) { _ in }
            XCTFail("testValidateServerAction_ChainNameError is expected to fail.")
        } catch ZcashError.compactBlockProcessorChainName(let chainName) {
            XCTAssertEqual(chainName, "invalid")
        } catch {
            XCTFail("""
            testValidateServerAction_ChainNameError is expected to fail but error \(error) doesn't match \
            ZcashError.compactBlockProcessorChainName
            """)
        }
    }

    func testValidateServerAction_NetworkMatchError() async throws {
        underlyingNetworkType = .mainnet

        let validateServerAction = setupAction()

        do {
            _ = try await validateServerAction.run(with: ActionContextMock()) { _ in }
            XCTFail("testValidateServerAction_NetworkMatchError is expected to fail.")
        } catch let ZcashError.compactBlockProcessorNetworkMismatch(expected, found) {
            XCTAssertEqual(expected, .mainnet)
            XCTAssertEqual(found, .testnet)
        } catch {
            XCTFail("""
            testValidateServerAction_NetworkMatchError is expected to fail but error \(error) doesn't match \
            ZcashError.compactBlockProcessorNetworkMismatch
            """)
        }
    }

    func testValidateServerAction_SaplingActivationError() async throws {
        underlyingSaplingActivationHeight = 1

        let validateServerAction = setupAction()

        do {
            _ = try await validateServerAction.run(with: ActionContextMock()) { _ in }
            XCTFail("testValidateServerAction_SaplingActivationError is expected to fail.")
        } catch let ZcashError.compactBlockProcessorSaplingActivationMismatch(expected, found) {
            XCTAssertEqual(expected, 280_000)
            XCTAssertEqual(found, 1)
        } catch {
            XCTFail("""
            testValidateServerAction_SaplingActivationError is expected to fail but error \(error) doesn't match \
            ZcashError.compactBlockProcessorSaplingActivationMismatch
            """)
        }
    }

    func testValidateServerAction_ConsensusBranchIDError_InvalidRemoteBranch() async throws {
        underlyingConsensusBranchID = "1 1"

        let validateServerAction = setupAction()

        do {
            _ = try await validateServerAction.run(with: ActionContextMock()) { _ in }
            XCTFail("testValidateServerAction_ConsensusBranchIDError_InvalidRemoteBranch is expected to fail.")
        } catch ZcashError.compactBlockProcessorConsensusBranchID {
        } catch {
            XCTFail("""
            testValidateServerAction_ConsensusBranchIDError_InvalidRemoteBranch is expected to fail but error \(error) doesn't match \
            ZcashError.compactBlockProcessorConsensusBranchID
            """)
        }
    }

    func testValidateServerAction_ConsensusBranchIDError_ValidRemoteBranch() async throws {
        underlyingConsensusBranchID = "1"

        let validateServerAction = setupAction()

        do {
            _ = try await validateServerAction.run(with: ActionContextMock()) { _ in }
            XCTFail("testValidateServerAction_ConsensusBranchIDError_ValidRemoteBranch is expected to fail.")
        } catch let ZcashError.compactBlockProcessorWrongConsensusBranchId(expected, found) {
            XCTAssertEqual(expected, -1026109260)
            XCTAssertEqual(found, 1)
        } catch {
            XCTFail("""
            testValidateServerAction_ConsensusBranchIDError_ValidRemoteBranch is expected to fail but error \(error) doesn't match \
            ZcashError.compactBlockProcessorWrongConsensusBranchId
            """)
        }
    }

    private func setupAction() -> ValidateServerAction {
        let config: CompactBlockProcessor.Configuration = .standard(
            for: ZcashNetworkBuilder.network(for: underlyingNetworkType), walletBirthday: 0
        )

        let rustBackendMock = ZcashRustBackendWeldingMock()
        rustBackendMock.consensusBranchIdForHeightClosure = { height in
            XCTAssertEqual(height, 2, "")
            return -1026109260
        }

        let lightWalletdInfoMock = LightWalletdInfoMock()
        lightWalletdInfoMock.underlyingConsensusBranchID = underlyingConsensusBranchID
        lightWalletdInfoMock.underlyingSaplingActivationHeight = UInt64(underlyingSaplingActivationHeight ?? config.saplingActivation)
        lightWalletdInfoMock.underlyingBlockHeight = 2
        lightWalletdInfoMock.underlyingChainName = underlyingChainName

        let serviceMock = LightWalletServiceMock()
        serviceMock.getInfoModeReturnValue = lightWalletdInfoMock

        mockContainer.mock(type: ZcashRustBackendWelding.self, isSingleton: true) { _ in rustBackendMock }
        mockContainer.mock(type: LightWalletService.self, isSingleton: true) { _ in serviceMock }
        mockContainer.mock(type: SDKFlags.self, isSingleton: true) { _ in SDKFlags(torEnabled: false, exchangeRateEnabled: false) }

        return ValidateServerAction(
            container: mockContainer,
            configProvider: CompactBlockProcessor.ConfigProvider(config: config)
        )
    }
}
