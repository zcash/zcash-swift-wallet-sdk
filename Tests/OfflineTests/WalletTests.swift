//
//  WalletTests.swift
//  ZcashLightClientKitTests
//
//  Created by Francisco Gindre on 13/09/2019.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import Foundation
import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

class WalletTests: ZcashTestCase {
    let testFileManager = FileManager()
    var dbData: URL! = nil
    var paramDestination: URL! = nil
    var network = ZcashNetworkBuilder.network(for: .testnet)
    var seedData = Data(base64Encoded: "9VDVOZZZOWWHpZtq1Ebridp3Qeux5C+HwiRR0g7Oi7HgnMs8Gfln83+/Q1NnvClcaSwM4ADFL1uZHxypEWlWXg==")!

    override func setUpWithError() throws {
        try super.setUpWithError()
        dbData = try __dataDbURL()
        paramDestination = try __documentsDirectory().appendingPathComponent("parameters")
    }

    override func tearDownWithError() throws {
        try super.tearDownWithError()
        if testFileManager.fileExists(atPath: dbData.absoluteString) {
            try testFileManager.trashItem(at: dbData, resultingItemURL: nil)
        }
    }

    func testWalletInitialization() async throws {
        let mockContainer = DIContainer()
        mockContainer.isTestEnvironment = true

        let serviceMock = LightWalletServiceMock()
        mockContainer.mock(type: LightWalletService.self, isSingleton: true) { _ in serviceMock }
        let latestBlockHeight = network.constants.saplingActivationHeight + ZcashSDK.maxReorgSize + 1
        serviceMock.latestBlockHeightModeReturnValue = latestBlockHeight
        serviceMock.getTreeStateModeClosure = { _, _ in
            throw ZcashError.rustTorLwdGetTreeState("test")
        }

        let wallet = Initializer(
            container: mockContainer,
            cacheDbURL: nil,
            fsBlockDbRoot: testTempDirectory,
            generalStorageURL: testGeneralStorageDirectory,
            dataDbURL: try __dataDbURL(),
            torDirURL: try __torDirURL(),
            endpoint: LightWalletEndpointBuilder.default,
            network: network,
            spendParamsURL: try __spendParamsURL(),
            outputParamsURL: try __outputParamsURL(),
            saplingParamsSourceURL: SaplingParamsSourceURL.tests,
            isTorEnabled: false,
            isExchangeRateEnabled: false
        )

        let synchronizer = SDKSynchronizer(initializer: wallet)
        do {
            guard case .success = try await synchronizer.prepare(
                with: seedData.bytes,
                walletBirthday: nil,
                name: "",
                keySource: nil
            ) else {
                XCTFail("Failed to initDataDb. Expected `.success` got: `.seedRequired`")
                return
            }
        } catch {
            XCTFail("shouldn't fail here. Got error: \(error)")
        }

        XCTAssertEqual(
            serviceMock.getTreeStateModeReceivedArguments?.id.height,
            UInt64(latestBlockHeight - ZcashSDK.maxReorgSize)
        )

        // fileExists actually sucks, so attempting to delete the file and checking what happens is far better :)
        XCTAssertNoThrow( try FileManager.default.removeItem(at: dbData!) )
    }

    /// MOB-1512: when the rust layer reports that the provided seed isn't relevant to the accounts already present in the
    /// wallet database (for example, a restored `data.db` that belongs to a different wallet than the seed available to the
    /// caller), `Initializer.initialize` must surface `.seedNotRelevant` to the caller instead of silently proceeding as if
    /// initialization succeeded.
    func testInitializePropagatesSeedNotRelevantFromRustBackend() async throws {
        let rustBackendMock = ZcashRustBackendWeldingMock()
        rustBackendMock.initBlockMetadataDbClosure = { }
        rustBackendMock.initDataDbSeedClosure = { _ in DbInitResult.seedNotRelevant }

        mockContainer.mock(type: ZcashRustBackendWelding.self, isSingleton: true) { _ in rustBackendMock }

        let initializer = Initializer(
            container: mockContainer,
            cacheDbURL: nil,
            fsBlockDbRoot: testTempDirectory,
            generalStorageURL: testGeneralStorageDirectory,
            dataDbURL: try __dataDbURL(),
            torDirURL: try __torDirURL(),
            endpoint: LightWalletEndpointBuilder.default,
            network: network,
            spendParamsURL: try __spendParamsURL(),
            outputParamsURL: try __outputParamsURL(),
            saplingParamsSourceURL: SaplingParamsSourceURL.tests,
            isTorEnabled: false,
            isExchangeRateEnabled: false
        )

        let result = try await initializer.initialize(
            with: seedData.bytes,
            walletBirthday: 663194,
            name: ""
        )

        guard case .seedNotRelevant = result else {
            XCTFail("Expected `.seedNotRelevant` when rustBackend.initDataDb() reports it, got \(result) instead.")
            return
        }
    }

    /// Companion regression test for `testInitializePropagatesSeedNotRelevantFromRustBackend`: the pre-existing
    /// `.seedRequired` propagation must keep working once `initialize` switches exhaustively over `DbInitResult`.
    func testInitializePropagatesSeedRequiredFromRustBackend() async throws {
        let rustBackendMock = ZcashRustBackendWeldingMock()
        rustBackendMock.initBlockMetadataDbClosure = { }
        rustBackendMock.initDataDbSeedClosure = { _ in DbInitResult.seedRequired }

        mockContainer.mock(type: ZcashRustBackendWelding.self, isSingleton: true) { _ in rustBackendMock }

        let initializer = Initializer(
            container: mockContainer,
            cacheDbURL: nil,
            fsBlockDbRoot: testTempDirectory,
            generalStorageURL: testGeneralStorageDirectory,
            dataDbURL: try __dataDbURL(),
            torDirURL: try __torDirURL(),
            endpoint: LightWalletEndpointBuilder.default,
            network: network,
            spendParamsURL: try __spendParamsURL(),
            outputParamsURL: try __outputParamsURL(),
            saplingParamsSourceURL: SaplingParamsSourceURL.tests,
            isTorEnabled: false,
            isExchangeRateEnabled: false
        )

        let result = try await initializer.initialize(
            with: nil,
            walletBirthday: 663194,
            name: ""
        )

        guard case .seedRequired = result else {
            XCTFail("Expected `.seedRequired` when rustBackend.initDataDb() reports it, got \(result) instead.")
            return
        }
    }
}
