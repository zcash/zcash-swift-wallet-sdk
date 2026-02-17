//
//  SynchronizerTests.swift
//  
//
//  Created by Lukáš Korba on 13.12.2022.
//

import Combine
import XCTest
@testable import ZcashLightClientKit
@testable import TestUtils

class SynchronizerTests: ZcashTestCase {
    class MockLatestBlockHeightProvider: LatestBlockHeightProvider {
        let birthday: BlockHeight
        
        init(birthday: BlockHeight) {
            self.birthday = birthday
        }

        func latestBlockHeight(streamer: CompactTxStreamerAsyncClient) async throws -> BlockHeight {
            self.birthday
        }
    }

    var coordinator: TestCoordinator!
    var cancellables: [AnyCancellable] = []
    var sdkSynchronizerInternalSyncStatusHandler: SDKSynchronizerInternalSyncStatusHandler! = SDKSynchronizerInternalSyncStatusHandler()
    var rustBackend: ZcashRustBackendWelding!

    let seedPhrase = """
    wish puppy smile loan doll curve hole maze file ginger hair nose key relax knife witness cannon grab despair throw review deal slush frame
    """

    var birthday: BlockHeight = 1_730_000

    override func setUp() async throws {
        try await super.setUp()
        rustBackend = try await ZcashRustBackend.openForTests(fsBlockDbRoot: testTempDirectory, networkType: .mainnet)
    }

    override func tearDown() {
        super.tearDown()
        coordinator = nil
        cancellables = []
        sdkSynchronizerInternalSyncStatusHandler = nil
        rustBackend = nil
    }

    // TODO: [#1521] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1521
    func _testHundredBlocksSync() async throws {
        guard let seedData = Data(base64Encoded: "9VDVOZZZOWWHpZtq1Ebridp3Qeux5C+HwiRR0g7Oi7HgnMs8Gfln83+/Q1NnvClcaSwM4ADFL1uZHxypEWlWXg==") else {
            XCTFail("seedData expected to be successfuly instantiated.")
            return
        }
        let seedBytes = [UInt8](seedData)
        let network = ZcashNetworkBuilder.network(for: .mainnet)
        let endpoint = LightWalletEndpoint(address: "lightwalletd.electriccoin.co", port: 9067, secure: true)

        var synchronizer: SDKSynchronizer?
        for _ in 1...5 {
            let databases = TemporaryDbBuilder.build()
            let initializer = Initializer(
                cacheDbURL: nil,
                fsBlockDbRoot: databases.fsCacheDbRoot,
                generalStorageURL: testGeneralStorageDirectory,
                dataDbURL: databases.dataDB,
                torDirURL: databases.torDir,
                endpoint: endpoint,
                network: network,
                spendParamsURL: try __spendParamsURL(),
                outputParamsURL: try __outputParamsURL(),
                saplingParamsSourceURL: SaplingParamsSourceURL.tests,
                alias: .default,
                loggingPolicy: .default(.debug),
                isTorEnabled: false,
                isExchangeRateEnabled: false
            )
            
            try? FileManager.default.removeItem(at: databases.fsCacheDbRoot)
            try? FileManager.default.removeItem(at: databases.dataDB)
            
            synchronizer = SDKSynchronizer(initializer: initializer)
            
            guard let synchronizer else { fatalError("Synchronizer not initialized.") }
            
            _ = try await synchronizer.prepare(with: seedBytes, walletBirthday: birthday, for: .existingWallet, name: "", keySource: nil)
            
            let syncSyncedExpectation = XCTestExpectation(description: "synchronizerSynced Expectation")
            sdkSynchronizerInternalSyncStatusHandler.subscribe(to: synchronizer.stateStream, expectations: [.synced: syncSyncedExpectation])
            
            await (synchronizer.blockProcessor.service as? LightWalletGRPCService)?.latestBlockHeightProvider = MockLatestBlockHeightProvider(
                birthday: self.birthday + 99
            )
            
            try await synchronizer.start()
            
            await fulfillment(of: [syncSyncedExpectation], timeout: 100)
        }
    }
}
