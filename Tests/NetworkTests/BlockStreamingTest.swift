//
//  BlockStreamingTest.swift
//  ZcashLightClientKit-Unit-Tests
//
//  Created by Francisco Gindre on 5/25/21.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

class BlockStreamingTest: ZcashTestCase {
    let testFileManager = FileManager()
    var rustBackend: ZcashRustBackendWelding!
    var endpoint: LightWalletEndpoint!
    var service: LightWalletService!
    var storage: FSCompactBlockRepository!
    var processorConfig: CompactBlockProcessor.Configuration!
    var latestBlockHeight: BlockHeight!
    var startHeight: BlockHeight!

    override func setUp() async throws {
        try await super.setUp()
        logger = OSLogger(logLevel: .debug)

        rustBackend = try await ZcashRustBackend.openForTests(fsBlockDbRoot: testTempDirectory, networkType: .testnet)
        logger = OSLogger(logLevel: .debug)

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
        mockContainer.mock(type: ZcashRustBackendWelding.self, isSingleton: true) { _ in self.rustBackend }

        let endpoint = LightWalletEndpoint(
            address: LightWalletEndpointBuilder.eccTestnet.host,
            port: 9067,
            secure: true,
            singleCallTimeoutInMillis: 10000,
            streamingCallTimeoutInMillis: 10000
        )
        let service = LightWalletServiceFactory(endpoint: endpoint).make()

        latestBlockHeight = try await service.latestBlockHeight(mode: .direct)
        startHeight = latestBlockHeight - 10_000
    }

    override func tearDownWithError() throws {
        try super.tearDownWithError()
        rustBackend = nil
        try? FileManager.default.removeItem(at: __dataDbURL())
        endpoint = nil
        service = nil
        storage = nil
        processorConfig = nil
    }

    private func makeDependencies(timeout: Int64) async throws {
        let endpoint = LightWalletEndpoint(
            address: LightWalletEndpointBuilder.eccTestnet.host,
            port: 9067,
            secure: true,
            singleCallTimeoutInMillis: timeout,
            streamingCallTimeoutInMillis: timeout
        )
        self.endpoint = endpoint
        service = LightWalletServiceFactory(endpoint: endpoint).make()
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

        processorConfig = CompactBlockProcessor.Configuration.standard(
            for: ZcashNetworkBuilder.network(for: .testnet),
            walletBirthday: ZcashNetworkBuilder.network(for: .testnet).constants.saplingActivationHeight
        )

        mockContainer.mock(type: LightWalletService.self, isSingleton: true) { _ in
            LightWalletServiceFactory(endpoint: endpoint).make()
        }

        let transactionRepositoryMock = TransactionRepositoryMock()
        mockContainer.mock(type: TransactionRepository.self, isSingleton: true) { _ in transactionRepositoryMock }

        let blockDownloader = BlockDownloaderImpl(
            service: service,
            downloaderService: BlockDownloaderServiceImpl(service: service, storage: storage),
            storage: storage,
            metrics: SDKMetricsImpl(),
            logger: logger
        )
        mockContainer.mock(type: BlockDownloader.self, isSingleton: true) { _ in blockDownloader }
    }

    func testStream() async throws {
        try await makeDependencies(timeout: 10000)

        var blocks: [ZcashCompactBlock] = []
        let stream = try service.blockStream(startHeight: startHeight, endHeight: latestBlockHeight, mode: .direct)
        
        do {
            for try await compactBlock in stream {
                blocks.append(compactBlock)
            }
        } catch {
            XCTFail("failed with error: \(error)")
        }

        XCTAssertEqual(blocks.count, latestBlockHeight - startHeight + 1)
    }

    func testStreamCancellation() async throws {
        try await makeDependencies(timeout: 10000)

        let action = DownloadAction(container: mockContainer, configProvider: CompactBlockProcessor.ConfigProvider(config: processorConfig))
        let blockDownloader = mockContainer.resolve(BlockDownloader.self)

        let context = ActionContextMock()
        context.updateStateClosure = { _ in }

        let expectation = XCTestExpectation()

        let cancelableTask = Task {
            do {
                _ = try await action.run(with: context, didUpdate: { _ in })
                let lastDownloadedHeight = await blockDownloader.latestDownloadedBlockHeight()
                // Just to be sure that download was interrupted before download was finished.
                XCTAssertLessThan(lastDownloadedHeight, latestBlockHeight)
                expectation.fulfill()
            } catch {
                XCTFail("Downloading failed with error: \(error)")
                expectation.fulfill()
            }
        }

        DispatchQueue.global().asyncAfter(deadline: .now() + 1.0) {
            cancelableTask.cancel()
        }

        await fulfillment(of: [expectation], timeout: 5)
        await action.stop()
    }
    
    func testStreamTimeout() async throws {
        try await makeDependencies(timeout: 100)

        let action = DownloadAction(container: mockContainer, configProvider: CompactBlockProcessor.ConfigProvider(config: processorConfig))
        let syncControlData = SyncControlData(
            latestBlockHeight: latestBlockHeight,
            latestScannedHeight: startHeight,
            firstUnenhancedHeight: nil
        )
        let context = ActionContextMock()
        context.updateStateClosure = { _ in }
        context.underlyingSyncControlData = syncControlData
        context.lastScannedHeight = startHeight

        let date = Date()

        do {
            _ = try await action.run(with: context, didUpdate: { _ in })
            XCTFail("It is expected that this downloading fails.")
        } catch {
            if let lwdError = error as? ZcashError {
                switch lwdError {
                case .serviceBlockStreamFailed:
                    XCTAssert(true)
                default:
                    XCTFail("LWD Service error found, but should have been a timeLimit reached \(lwdError)")
                }
            } else {
                XCTFail("Error should have been a timeLimit reached Error")
            }
        }

        let now = Date()

        let elapsed = now.timeIntervalSince(date)
        print("took \(elapsed) seconds")

        await action.stop()
    }
}
