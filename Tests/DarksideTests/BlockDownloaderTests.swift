//
//  BlockDownloaderTests.swift
//  ZcashLightClientKitTests
//
//  Created by Francisco Gindre on 18/09/2019.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

class BlockDownloaderTests: ZcashTestCase {
    let branchID = "2bb40e60"
    let chainName = "main"

    let testFileManager = FileManager()
    var darksideWalletService: DarksideWalletService!
    var downloader: BlockDownloaderService!
    var service: LightWalletService!
    var storage: CompactBlockRepository!
    var network = DarksideWalletDNetwork()
    var rustBackend: ZcashRustBackendWelding!

    override func setUp() async throws {
        try await super.setUp()

        mockContainer.mock(type: CheckpointSource.self, isSingleton: true) { _ in
            return DarksideMainnetCheckpointSource()
        }
        
        testTempDirectory = Environment.uniqueTestTempDirectory

        service = LightWalletServiceFactory(endpoint: LightWalletEndpointBuilder.default).make()

        rustBackend = try await ZcashRustBackend.openForTests(
            fsBlockDbRoot: testTempDirectory,
            networkType: network.networkType
        )

        storage = FSCompactBlockRepository(
            fsBlockDbRoot: testTempDirectory,
            metadataStore: FSMetadataStore.live(
                fsBlockDbRoot: testTempDirectory,
                rustBackend: rustBackend,
                logger: logger
            ),
            blockDescriptor: .live,
            contentProvider: DirectoryListingProviders.defaultSorted,
            logger: logger
        )
        try await storage.create()

        downloader = BlockDownloaderServiceImpl(service: service, storage: storage)
        darksideWalletService = DarksideWalletService(endpoint: LightWalletEndpointBuilder.default, service: service as! LightWalletGRPCService)
        
        try FakeChainBuilder.buildChain(darksideWallet: darksideWalletService, branchID: branchID, chainName: chainName)
        try darksideWalletService.applyStaged(nextLatestHeight: 663250)

        sleep(2)
    }
    
    override func tearDown() {
        super.tearDown()
        try? testFileManager.removeItem(at: testTempDirectory)
        darksideWalletService = nil
        service = nil
        storage = nil
        downloader = nil
        rustBackend = nil
        testTempDirectory = nil
    }

    func testSmallDownload() async {
        let lowerRange: BlockHeight = self.network.constants.saplingActivationHeight
        let upperRange: BlockHeight = self.network.constants.saplingActivationHeight + 99
        
        let range = CompactBlockRange(uncheckedBounds: (lowerRange, upperRange))
        do {
            try await downloader.downloadBlockRange(range, mode: .direct)
            
            // check what was 'stored'
            let latestHeight = try await self.storage.latestHeight()
            XCTAssertEqual(latestHeight, upperRange)
            
            let resultHeight = try await self.downloader.lastDownloadedBlockHeight()
            XCTAssertEqual(resultHeight, upperRange)
        } catch {
            XCTFail("testSmallDownload() shouldn't fail \(error)")
        }
    }
    
    func testFailure() async {
        let awfulDownloader = BlockDownloaderServiceImpl(
            service: AwfulLightWalletService(
                latestBlockHeight: self.network.constants.saplingActivationHeight + 1000,
                service: darksideWalletService
            ),
            storage: ZcashConsoleFakeStorage()
        )
        
        let lowerRange: BlockHeight = self.network.constants.saplingActivationHeight
        let upperRange: BlockHeight = self.network.constants.saplingActivationHeight + 99
        
        let range = CompactBlockRange(uncheckedBounds: (lowerRange, upperRange))

        do {
            try await awfulDownloader.downloadBlockRange(range, mode: .direct)
        } catch {
            XCTAssertNotNil(error)
        }
    }
}

/// Helper functions

extension BlockDownloaderTests {
    func validate(result: Result<BlockHeight, Error>, against height: BlockHeight) -> Bool {
        switch result {
        case .success(let resultHeight):
            return resultHeight == height
        default:
            return false
        }
    }
}
