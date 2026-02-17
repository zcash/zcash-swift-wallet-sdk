//
//  TransactionEnhancementTests.swift
//  ZcashLightClientKit-Unit-Tests
//
//  Created by Francisco Gindre on 4/15/20.
//

import Combine
import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

class TransactionEnhancementTests: ZcashTestCase {
    var cancellables: [AnyCancellable] = []
    var processorEventHandler: CompactBlockProcessorEventHandler! = CompactBlockProcessorEventHandler()
    let mockLatestHeight = BlockHeight(663250)
    let targetLatestHeight = BlockHeight(663251)
    let walletBirthday = BlockHeight(663150)
    let network = DarksideWalletDNetwork()
    let branchID = "2bb40e60"
    let chainName = "main"

    let testFileManager = FileManager()

    var initializer: Initializer!
    var processorConfig: CompactBlockProcessor.Configuration!
    var processor: CompactBlockProcessor!
    var rustBackend: ZcashRustBackendWelding!
    var darksideWalletService: DarksideWalletService!
    var downloader: BlockDownloaderServiceImpl!
    var syncStartedExpect: XCTestExpectation!
    var updatedNotificationExpectation: XCTestExpectation!
    var stopNotificationExpectation: XCTestExpectation!
    var finishedNotificationExpectation: XCTestExpectation!
    var reorgNotificationExpectation: XCTestExpectation!
    var afterReorgIdleNotification: XCTestExpectation!
    var txFoundNotificationExpectation: XCTestExpectation!
    var waitExpectation: XCTestExpectation!
    let sdkFlags = SDKFlags(torEnabled: false, exchangeRateEnabled: false)

    override func setUp() async throws {
        try await super.setUp()
        
        logger = OSLogger(logLevel: .debug)
        
        syncStartedExpect = XCTestExpectation(description: "\(self.description) syncStartedExpect")
        stopNotificationExpectation = XCTestExpectation(description: "\(self.description) stopNotificationExpectation")
        updatedNotificationExpectation = XCTestExpectation(description: "\(self.description) updatedNotificationExpectation")
        finishedNotificationExpectation = XCTestExpectation(description: "\(self.description) finishedNotificationExpectation")
        afterReorgIdleNotification = XCTestExpectation(description: "\(self.description) afterReorgIdleNotification")
        reorgNotificationExpectation = XCTestExpectation(description: "\(self.description) reorgNotificationExpectation")
        txFoundNotificationExpectation = XCTestExpectation(description: "\(self.description) txFoundNotificationExpectation")
        
        waitExpectation = XCTestExpectation(description: "\(self.description) waitExpectation")

        let checkpointSource = CheckpointSourceFactory.fromBundle(for: network.networkType)
        let birthday = checkpointSource.birthday(for: walletBirthday)

        let pathProvider = DefaultResourceProvider(network: network)
        processorConfig = CompactBlockProcessor.Configuration(
            alias: .default,
            fsBlockCacheRoot: testTempDirectory,
            dataDb: pathProvider.dataDbURL,
            torDir: pathProvider.torDirURL,
            spendParamsURL: pathProvider.spendParamsURL,
            outputParamsURL: pathProvider.outputParamsURL,
            saplingParamsSourceURL: SaplingParamsSourceURL.tests,
            walletBirthdayProvider: { birthday.height },
            network: network
        )

        try? FileManager.default.removeItem(at: processorConfig.fsBlockCacheRoot)
        try? FileManager.default.removeItem(at: processorConfig.dataDb)

        rustBackend = try await ZcashRustBackend.openForTests(
            dbData: processorConfig.dataDb,
            fsBlockDbRoot: testTempDirectory,
            networkType: network.networkType
        )

        let dbInit = try await rustBackend.initDataDb(seed: nil)

        do {
            _ = try await rustBackend.createAccount(
                seed: Environment.seedBytes,
                treeState: birthday.treeState(),
                recoverUntil: nil,
                name: "",
                keySource: nil
            )
        } catch {
            XCTFail("Failed to create account. Error: \(error)")
            return
        }
        
        guard case .success = dbInit else {
            XCTFail("Failed to initDataDb. Expected `.success` got: \(String(describing: dbInit))")
            return
        }

        let service = DarksideWalletService()
        darksideWalletService = service
        
        let storage = FSCompactBlockRepository(
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
        try! await storage.create()
        
        downloader = BlockDownloaderServiceImpl(service: service, storage: storage)
        
        Dependencies.setup(
            in: mockContainer,
            urls: Initializer.URLs(
                fsBlockDbRoot: testTempDirectory,
                dataDbURL: pathProvider.dataDbURL,
                torDirURL: pathProvider.torDirURL,
                generalStorageURL: testGeneralStorageDirectory,
                spendParamsURL: pathProvider.spendParamsURL,
                outputParamsURL: pathProvider.outputParamsURL
            ),
            alias: .default,
            networkType: .testnet,
            endpoint: LightWalletEndpointBuilder.default,
            loggingPolicy: .default(.debug),
            isTorEnabled: false,
            isExchangeRateEnabled: false
        )
        
        mockContainer.mock(type: LatestBlocksDataProvider.self, isSingleton: true) { [self] _ in
            LatestBlocksDataProviderImpl(service: service, rustBackend: self.rustBackend, sdkFlags: sdkFlags)
        }
        mockContainer.mock(type: ZcashRustBackendWelding.self, isSingleton: true) { _ in self.rustBackend }
        
        processor = CompactBlockProcessor(
            container: mockContainer,
            config: processorConfig
        )

        let eventClosure: CompactBlockProcessor.EventClosure = { [weak self] event in
            switch event {
            case .failed: self?.processorFailed(event: event)
            default: break
            }
        }

        await self.processor.updateEventClosure(identifier: "tests", closure: eventClosure)
    }

    override func tearDown() async throws {
        try await super.tearDown()
        await self.processor.stop()
        try? FileManager.default.removeItem(at: processorConfig.fsBlockCacheRoot)
        try? FileManager.default.removeItem(at: processorConfig.dataDb)
        processorEventHandler = nil
        initializer = nil
        processorConfig = nil
        processor = nil
        darksideWalletService = nil
        downloader = nil
        testTempDirectory = nil
    }
    
    private func startProcessing() async throws {
        XCTAssertNotNil(processor)

        let expectations: [CompactBlockProcessorEventHandler.EventIdentifier: XCTestExpectation] = [
            .startedSyncing: syncStartedExpect,
            .stopped: stopNotificationExpectation,
            .progressUpdated: updatedNotificationExpectation,
            .foundTransactions: txFoundNotificationExpectation,
            .finished: finishedNotificationExpectation
        ]

        await processorEventHandler.subscribe(to: processor, expectations: expectations)
        await processor.start()
    }
    
    func testBasicEnhancement() async throws {
        let targetLatestHeight = BlockHeight(663200)
        
        do {
            try FakeChainBuilder.buildChain(darksideWallet: darksideWalletService, branchID: branchID, chainName: chainName)

            try darksideWalletService.applyStaged(nextLatestHeight: targetLatestHeight)
        } catch {
            XCTFail("Error: \(error)")
            return
        }

        sleep(3)

        /**
        connect to dLWD
        request latest height -> receive firstLatestHeight
        */
        do {
            dump("first latest height:  \(try await darksideWalletService.latestBlockHeight(mode: .direct))")
        } catch {
            XCTFail("Error: \(error)")
            return
        }

        /**
        download and sync blocks from walletBirthday to firstLatestHeight
        */
        do {
            try await startProcessing()
        } catch {
            XCTFail("Error: \(error)")
        }

        await fulfillment(
            of: [
                syncStartedExpect,
                txFoundNotificationExpectation,
                finishedNotificationExpectation
            ],
            timeout: 30
        )
    }
    
    func processorFailed(event: CompactBlockProcessor.Event) {
        if case let .failed(error) = event {
            XCTFail("CompactBlockProcessor failed with Error: \(error)")
        } else {
            XCTFail("CompactBlockProcessor failed")
        }
    }
}
