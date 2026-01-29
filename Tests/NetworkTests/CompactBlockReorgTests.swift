//
//  CompactBlockReorgTests.swift
//  ZcashLightClientKit-Unit-Tests
//
//  Created by Francisco Gindre on 11/13/19.
//
//  Copyright © 2019 Electric Coin Company. All rights reserved.

import Combine
import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

class CompactBlockReorgTests: ZcashTestCase {
    var processorConfig: CompactBlockProcessor.Configuration!
    let testFileManager = FileManager()
    var cancellables: [AnyCancellable] = []
    var processorEventHandler: CompactBlockProcessorEventHandler! = CompactBlockProcessorEventHandler()
    var rustBackend: ZcashRustBackendWelding!
    var rustBackendMockHelper: RustBackendMockHelper!
    var processor: CompactBlockProcessor!
    var syncStartedExpect: XCTestExpectation!
    var updatedNotificationExpectation: XCTestExpectation!
    var stopNotificationExpectation: XCTestExpectation!
    var finishedNotificationExpectation: XCTestExpectation!
    var reorgNotificationExpectation: XCTestExpectation!
    let network = ZcashNetworkBuilder.network(for: .testnet)
    let mockLatestHeight = ZcashNetworkBuilder.network(for: .testnet).constants.saplingActivationHeight + 2000
    let sdkFlags = SDKFlags(torEnabled: false, exchangeRateEnabled: false)

    override func setUp() async throws {
        try await super.setUp()
        logger = OSLogger(logLevel: .debug)

        let pathProvider = DefaultResourceProvider(network: network)
        processorConfig = CompactBlockProcessor.Configuration(
            alias: .default,
            fsBlockCacheRoot: testTempDirectory,
            dataDb: pathProvider.dataDbURL,
            torDir: pathProvider.torDirURL,
            spendParamsURL: pathProvider.spendParamsURL,
            outputParamsURL: pathProvider.outputParamsURL,
            saplingParamsSourceURL: SaplingParamsSourceURL.tests,
            walletBirthdayProvider: { ZcashNetworkBuilder.network(for: .testnet).constants.saplingActivationHeight },
            network: ZcashNetworkBuilder.network(for: .testnet)
        )

        let liveService = LightWalletServiceFactory(endpoint: LightWalletEndpointBuilder.eccTestnet).make()
        let service = MockLightWalletService(
            latestBlockHeight: mockLatestHeight,
            service: liveService
        )

        rustBackend = try await ZcashRustBackend.openForTests(
            dbData: processorConfig.dataDb,
            fsBlockDbRoot: processorConfig.fsBlockCacheRoot,
            networkType: network.networkType
        )

        let branchID = try rustBackend.consensusBranchIdFor(height: Int32(mockLatestHeight))
        service.mockLightDInfo = LightdInfo.with { info in
            info.blockHeight = UInt64(mockLatestHeight)
            info.branch = "asdf"
            info.buildDate = "today"
            info.buildUser = "testUser"
            info.chainName = "test"
            info.consensusBranchID = branchID.toString()
            info.estimatedHeight = UInt64(mockLatestHeight)
            info.saplingActivationHeight = UInt64(network.constants.saplingActivationHeight)
        }

        let realCache = FSCompactBlockRepository(
            fsBlockDbRoot: processorConfig.fsBlockCacheRoot,
            metadataStore: FSMetadataStore.live(
                fsBlockDbRoot: processorConfig.fsBlockCacheRoot,
                rustBackend: rustBackend,
                logger: logger
            ),
            blockDescriptor: .live,
            contentProvider: DirectoryListingProviders.defaultSorted,
            logger: logger
        )

        try await realCache.create()

        let initResult = try await rustBackend.initDataDb(seed: nil)
        guard case .success = initResult else {
            XCTFail("initDataDb failed. Expected Success but got .seedRequired")
            return
        }

        rustBackendMockHelper = await RustBackendMockHelper(rustBackend: rustBackend)

        Dependencies.setup(
            in: mockContainer,
            urls: Initializer.URLs(
                fsBlockDbRoot: testTempDirectory,
                dataDbURL: processorConfig.dataDb,
                torDirURL: processorConfig.torDir,
                generalStorageURL: testGeneralStorageDirectory,
                spendParamsURL: processorConfig.spendParamsURL,
                outputParamsURL: processorConfig.outputParamsURL
            ),
            alias: .default,
            networkType: .testnet,
            endpoint: LightWalletEndpointBuilder.default,
            loggingPolicy: .default(.debug),
            isTorEnabled: false,
            isExchangeRateEnabled: false
        )
        
        self.rustBackendMockHelper.rustBackendMock.putSaplingSubtreeRootsStartIndexRootsClosure = { _, _ in }
        self.rustBackendMockHelper.rustBackendMock.updateChainTipHeightClosure = { _ in }

        mockContainer.mock(type: LatestBlocksDataProvider.self, isSingleton: true) { [self] _ in
            LatestBlocksDataProviderImpl(service: service, rustBackend: self.rustBackend, sdkFlags: sdkFlags)
        }
        mockContainer.mock(type: ZcashRustBackendWelding.self, isSingleton: true) { _ in self.rustBackendMockHelper.rustBackendMock }
        mockContainer.mock(type: LightWalletService.self, isSingleton: true) { _ in service }
        mockContainer.mock(type: CompactBlockRepository.self, isSingleton: true) { _ in realCache }

        processor = CompactBlockProcessor(container: mockContainer, config: processorConfig)
        
        syncStartedExpect = XCTestExpectation(description: "\(self.description) syncStartedExpect")
        stopNotificationExpectation = XCTestExpectation(description: "\(self.description) stopNotificationExpectation")
        updatedNotificationExpectation = XCTestExpectation(description: "\(self.description) updatedNotificationExpectation")
        finishedNotificationExpectation = XCTestExpectation(description: "\(self.description) finishedNotificationExpectation")
        reorgNotificationExpectation = XCTestExpectation(description: "\(self.description) reorgNotificationExpectation")

        let eventClosure: CompactBlockProcessor.EventClosure = { [weak self] event in
            switch event {
            case .failed: self?.processorFailed(event: event)
            case .handledReorg: self?.processorHandledReorg(event: event)
            default: break
            }
        }

        await self.processor.updateEventClosure(identifier: "tests", closure: eventClosure)
    }

    override func tearDown() async throws {
        try await super.tearDown()
        await processor.stop()
        try? FileManager.default.removeItem(at: processorConfig.dataDb)
        cancellables = []
        processorEventHandler = nil
        processor = nil
        rustBackend = nil
        rustBackendMockHelper = nil
    }
    
    func processorHandledReorg(event: CompactBlockProcessor.Event) {
        if case let .handledReorg(reorg, rewind) = event {
            XCTAssertTrue( reorg == 0 || reorg > self.network.constants.saplingActivationHeight)
            XCTAssertTrue( rewind == 0 || rewind > self.network.constants.saplingActivationHeight)
            XCTAssertTrue( rewind <= reorg )
            reorgNotificationExpectation.fulfill()
        } else {
            XCTFail("CompactBlockProcessor reorg notification is malformed")
        }
    }
    
    func processorFailed(event: CompactBlockProcessor.Event) {
        if case let .failed(error) = event {
            XCTFail("CompactBlockProcessor failed with Error: \(error)")
        } else {
            XCTFail("CompactBlockProcessor failed")
        }
    }
    
    private func startProcessing() async {
        XCTAssertNotNil(processor)

        let expectations: [CompactBlockProcessorEventHandler.EventIdentifier: XCTestExpectation] = [
            .startedSyncing: syncStartedExpect,
            .stopped: stopNotificationExpectation,
            .progressUpdated: updatedNotificationExpectation,
            .finished: finishedNotificationExpectation,
            .handleReorg: reorgNotificationExpectation
        ]

        await processorEventHandler.subscribe(to: processor, expectations: expectations)
        await processor.start()
    }
    
    func testNotifiesReorg() async {
        await startProcessing()

        await fulfillment(
            of: [
                syncStartedExpect,
                reorgNotificationExpectation,
                finishedNotificationExpectation
            ],
            timeout: 300,
            enforceOrder: true
        )
    }
    
    private func expectedBatches(currentHeight: BlockHeight, targetHeight: BlockHeight, batchSize: Int) -> Int {
        (abs(currentHeight - targetHeight) / batchSize)
    }
}
