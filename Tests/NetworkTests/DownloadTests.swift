//
//  DownloadTests.swift
//  ZcashLightClientKitTests
//
//  Created by Francisco Gindre on 10/16/19.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import XCTest
import SQLite
@testable import TestUtils
@testable import ZcashLightClientKit

class DownloadTests: ZcashTestCase {
    let testFileManager = FileManager()
    var network = ZcashNetworkBuilder.network(for: .testnet)

    override func setUp() async throws {
        try await super.setUp()

        Dependencies.setup(
            in: mockContainer,
            urls: Initializer.URLs(
                fsBlockDbRoot: testTempDirectory,
                dataDbURL: try! __dataDbURL(),
                torDirURL: try! __torDirURL(),
                generalStorageURL: testGeneralStorageDirectory,
                spendParamsURL: try! __spendParamsURL(),
                outputParamsURL: try! __outputParamsURL()
            ),
            alias: .default,
            networkType: .testnet,
            endpoint: LightWalletEndpointBuilder.default,
            loggingPolicy: .default(.debug),
            isTorEnabled: false,
            isExchangeRateEnabled: false
        )
        
        mockContainer.mock(type: LatestBlocksDataProvider.self, isSingleton: true) { _ in LatestBlocksDataProviderMock() }
    }

    override func tearDownWithError() throws {
        try super.tearDownWithError()
    }

    func testSingleDownload() async throws {
        let rustBackend = try await ZcashRustBackend.openForTests(fsBlockDbRoot: self.testTempDirectory, networkType: self.network.networkType)
        mockContainer.mock(type: ZcashRustBackendWelding.self, isSingleton: true) { _ in
            rustBackend
        }
        mockContainer.mock(type: LightWalletService.self, isSingleton: true) { _ in
            LightWalletServiceFactory(endpoint: LightWalletEndpointBuilder.eccTestnet).make()
        }
        let storage = mockContainer.resolve(CompactBlockRepository.self)
        try await storage.create()

        let blockCount = 100
        let activationHeight = network.constants.saplingActivationHeight
        let range = activationHeight ... activationHeight + blockCount
        
        let processorConfig = CompactBlockProcessor.Configuration.standard(
            for: network,
            walletBirthday: network.constants.saplingActivationHeight
        )

        let compactBlockProcessor = CompactBlockProcessor(container: mockContainer, config: processorConfig)
        
        do {
            try await compactBlockProcessor.blockDownloaderService.downloadBlockRange(range, mode: .direct)
        } catch {
            XCTFail("Download failed with error: \(error)")
        }

        let latestHeight = try await storage.latestHeight()
        XCTAssertEqual(latestHeight, range.upperBound)

        await compactBlockProcessor.stop()
    }
}
