//
//  DarksideSanityCheckTests.swift
//  ZcashLightClientKit-Unit-Tests
//
//  Created by Francisco Gindre on 5/21/20.
//

import Foundation
@testable import TestUtils
import XCTest
@testable import ZcashLightClientKit

class DarksideSanityCheckTests: ZcashTestCase {
    let sendAmount: Int64 = 1000
    var birthday: BlockHeight = 663150
    let defaultLatestHeight: BlockHeight = 663175
    var coordinator: TestCoordinator!
    var syncedExpectation = XCTestExpectation(description: "synced")
    var sentTransactionExpectation = XCTestExpectation(description: "sent")
    var expectedReorgHeight: BlockHeight = 665188
    var expectedRewindHeight: BlockHeight = 665188
    var network = DarksideWalletDNetwork()
    var reorgExpectation = XCTestExpectation(description: "reorg")
    let branchID = "2bb40e60"
    let chainName = "main"

    override func setUp() async throws {
        try await super.setUp()

        mockContainer.mock  (type: CheckpointSource.self, isSingleton: true) { _ in
            return DarksideMainnetCheckpointSource()
        }

        self.coordinator = try await TestCoordinator(
            container: mockContainer,
            walletBirthday: birthday,
            network: network
        )

        try await coordinator.reset(
            saplingActivation: self.birthday,
            startSaplingTreeSize: 128607,
            startOrchardTreeSize: 0,
            branchID: self.branchID,
            chainName: self.chainName
        )

        try self.coordinator.resetBlocks(dataset: .default)
    }

    override func tearDown() async throws {
        try await super.tearDown()
        let coordinator = self.coordinator!
        self.coordinator = nil

        try await coordinator.stop()
        try? FileManager.default.removeItem(at: coordinator.databases.fsCacheDbRoot)
        try? FileManager.default.removeItem(at: coordinator.databases.dataDB)
    }

    func testDarkside() async throws {
//        let expectedFirstBlock = (height: BlockHeight(663150), hash: "0000000002fd3be4c24c437bd22620901617125ec2a3a6c902ec9a6c06f734fc")
        let expectedLastBlock = (height: BlockHeight(663200), hash: "2fc7b4682f5ba6ba6f86e170b40f0aa9302e1d3becb2a6ee0db611ff87835e4a")

        try coordinator.service.addTreeState(
            // swiftlint:disable line_length
            try TreeState(jsonString:
                """
                {
                    "network": "main",
                    "height": "663150",
                    "hash": "0000000002fd3be4c24c437bd22620901617125ec2a3a6c902ec9a6c06f734fc",
                    "time": 1576821833,
                    "saplingTree": "01ec6278a1bed9e1b080fd60ef50eb17411645e3746ff129283712bc4757ecc833001001b4e1d4a26ac4a2810b57a14f4ffb69395f55dde5674ecd2462af96f9126e054701a36afb68534f640938bdffd80dfcb3f4d5e232488abbf67d049b33a761e7ed6901a16e35205fb7fe626a9b13fc43e1d2b98a9c241f99f93d5e93a735454073025401f5b9bcbf3d0e3c83f95ee79299e8aeadf30af07717bda15ffb7a3d00243b58570001fa6d4c2390e205f81d86b85ace0b48f3ce0afb78eeef3e14c70bcfd7c5f0191c0000011bc9521263584de20822f9483e7edb5af54150c4823c775b2efc6a1eded9625501a6030f8d4b588681eddb66cad63f09c5c7519db49500fc56ebd481ce5e903c22000163f4eec5a2fe00a5f45e71e1542ff01e937d2210c99f03addcce5314a5278b2d0163ab01f46a3bb6ea46f5a19d5bdd59eb3f81e19cfa6d10ab0fd5566c7a16992601fa6980c053d84f809b6abcf35690f03a11f87b28e3240828e32e3f57af41e54e01319312241b0031e3a255b0d708750b4cb3f3fe79e3503fe488cc8db1dd00753801754bb593ea42d231a7ddf367640f09bbf59dc00f2c1d2003cc340e0c016b5b13"
                }
                """)
        )
        try coordinator.applyStaged(blockheight: expectedLastBlock.height)

        sleep(1)

        let syncExpectation = XCTestExpectation(description: "sync to \(expectedLastBlock.height)")

        try await coordinator.sync(
            completion: { _ in
                syncExpectation.fulfill()
            },
            error: { error in
                guard let error else {
                    XCTFail("failed with unknown error")
                    return
                }
                XCTFail("failed with error: \(error)")
                return
            }
        )

        await fulfillment(of: [syncExpectation], timeout: 5)

        // TODO: [#1247] needs to review this to properly solve, https://github.com/zcash/ZcashLightClientKit/issues/1247
//        let blocksDao = BlockSQLDAO(dbProvider: SimpleConnectionProvider(path: coordinator.databases.dataDB.absoluteString, readonly: false))
//
//        let firstBlock = try blocksDao.block(at: expectedFirstBlock.height)
//        let lastBlock = try blocksDao.block(at: expectedLastBlock.height)
//
//        XCTAssertEqual(firstBlock?.hash.toHexStringTxId(), expectedFirstBlock.hash)
//        XCTAssertEqual(lastBlock?.hash.toHexStringTxId(), expectedLastBlock.hash)
    }
}
