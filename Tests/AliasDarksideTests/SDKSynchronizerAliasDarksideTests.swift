//
//  SDKSynchronizerAliasDarksideTests.swift
//
//
//  Created by Michal Fousek on 28.03.2023.
//

import Combine
import Foundation
@testable import TestUtils
import XCTest
@testable import ZcashLightClientKit

/*
 This test creates multiple instances of the `SDKSynchronizer` and then run sync on those in parallel. To achieve this it's required to run multiple
 instances of the lightwalletd in darkside mode.

 How to run this test:
 1. Have binary of lightwalletd which you want to use in directory which is in $PATH.
 2. Go to directory where this file is and then go there in `scripts/` directory.
 3. First check file `servers_config.zsh`. Aliases count should be same as aliases count defined in `aliases` variable. And starting port should be
    same as `startingPort`.
 4. Use `run_darkside_servers.zsh` script to run all the servers. This script also creates rundir for each instance of the lightwalletd in the current
    directory. You can find logs there.
 5. Run this test.
 6. When you are done use `kill_and_clean_servers.zsh` script to shutdown servers and clean all the data (pidfile, rundirs, logs).
 */
class SDKSynchronizerAliasDarksideTests: ZcashTestCase {
    // Test creates instance of the `SDKSynchronizer` for each of these aliases.
    let aliases: [ZcashSynchronizerAlias] = [.default, .custom("custom-1"), .custom("custom-2"), .custom("custom-3"), .custom("custom-4")]
    // First instance of the `SDKSynchronizer` uses this port. Second one uses startPort + 1, thirs one uses startPort + 2 and so on.
    let startingPort = 9167
    // How many blocks to sync in each instance of the `SDKSynchronizer`.
    let syncLength = 2000
    var coordinators: [TestCoordinator] = []
    let branchID = "2bb40e60"
    let chainName = "main"
    let network = DarksideWalletDNetwork()
    var birthday: BlockHeight = 663150

    override func setUp() async throws {
        try await super.setUp()

        for (index, alias) in aliases.enumerated() {
            let endpoint = LightWalletEndpoint(
                address: Constants.address,
                port: startingPort + index,
                secure: false,
                singleCallTimeoutInMillis: 10000,
                streamingCallTimeoutInMillis: 1000000
            )

            let coordinator = try await TestCoordinator(
                alias: alias,
                container: mockContainer,
                walletBirthday: birthday,
                network: network,
                callPrepareInConstructor: true,
                endpoint: endpoint
            )

            try await coordinator.reset(
                saplingActivation: birthday,
                startSaplingTreeSize: 128607,
                startOrchardTreeSize: 0,
                branchID: branchID,
                chainName: chainName
            )

            coordinators.append(coordinator)
        }
    }

    override func tearDown() async throws {
        try await super.tearDown()
        for coordinator in coordinators {
            try await coordinator.stop()
            try? FileManager.default.removeItem(at: coordinator.databases.fsCacheDbRoot)
            try? FileManager.default.removeItem(at: coordinator.databases.dataDB)
        }
        coordinators = []
    }

    func testMultipleSynchronizersCanRunAtOnce() async throws {
        var expectations: [XCTestExpectation] = []

        for coordinator in coordinators {
            try FakeChainBuilder.buildChain(darksideWallet: coordinator.service, branchID: branchID, chainName: chainName, length: syncLength)
            try coordinator.applyStaged(blockheight: birthday + syncLength)
            sleep(2)
        }

        for coordinator in coordinators {
            let expectation = XCTestExpectation(description: "Synchronizer \(coordinator.synchronizer.alias.description) expectation")
            expectations.append(expectation)

            try await coordinator.sync(
                completion: { _ in
                    expectation.fulfill()
                },
                error: self.handleError
            )
        }

        await fulfillment(of: expectations, timeout: TimeInterval(aliases.count * 5))
    }

    func handleError(_ error: Error?) async {
        guard let testError = error else {
            XCTFail("failed with nil error")
            return
        }
        XCTFail("Failed with error: \(testError)")
    }
}
