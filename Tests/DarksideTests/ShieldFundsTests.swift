//
//  ShieldFundsTests.swift
//  ZcashLightClientSample
//
//  Created by Francisco Gindre on 4/12/22.
//  Copyright © 2022 Electric Coin Company. All rights reserved.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

// FIXME: [#587] disabled until https://github.com/zcash/ZcashLightClientKit/issues/587 fixed
class ShieldFundsTests: ZcashTestCase {
    let sendAmount = Zatoshi(1000)
    var birthday: BlockHeight = 1631000
    var coordinator: TestCoordinator!
    var syncedExpectation = XCTestExpectation(description: "synced")
    var sentTransactionExpectation = XCTestExpectation(description: "sent")

    let branchID = "e9ff75a6"
    let chainName = "main"
    let network = DarksideWalletDNetwork()

    override func setUp() async throws {
        try await super.setUp()

        mockContainer.mock(type: CheckpointSource.self, isSingleton: true) { _ in
            return DarksideMainnetCheckpointSource()
        }

        self.coordinator = try await TestCoordinator(
            container: mockContainer,
            walletBirthday: birthday,
            network: network
        )

        try await coordinator.reset(
            saplingActivation: birthday,
            startSaplingTreeSize: 1120954,
            startOrchardTreeSize: 0,
            branchID: self.branchID,
            chainName: self.chainName
        )

        try coordinator.service.clearAddedUTXOs()
    }

    override func tearDown() async throws {
        try await super.tearDown()
        let coordinator = self.coordinator!
        self.coordinator = nil

        try await coordinator.stop()
        try? FileManager.default.removeItem(at: coordinator.databases.fsCacheDbRoot)
        try? FileManager.default.removeItem(at: coordinator.databases.dataDB)
    }

    /// Tests shielding funds from a UTXO
    ///
    /// This test uses the dataset `shield-funds` on the repo `darksidewalletd-test-data`
    /// (see: https://github.com/zcash-hackworks/darksidewalletd-test-data)
    /// The dataset consists on a wallet that has no shielded funds and suddenly encounters a UTXO
    /// at `utxoHeight` with 10000 zatoshi that will attempt to shield them.
    ///
    /// Steps:
    /// 1. load the dataset
    /// 2. applyStaged to `utxoHeight - 1`
    /// 3. sync up to that height
    /// at this point the balance should be all zeroes for transparent and shielded funds
    /// 4. Add the UTXO to darksidewalletd fake chain
    /// 5. advance chain to the `utxoHeight`
    /// 6. Sync and find the UXTO on chain.
    /// at this point the balance should be zero for shielded, then zero verified transparent funds
    /// and 10000 zatoshi of total (not verified) transparent funds.
    /// 7. stage ten blocks and confirm the transparent funds at `utxoHeight + 10`
    /// 8. sync up to chain tip.
    /// the transparent funds should be 10000 zatoshis both total and verified
    /// 9. shield the funds
    /// when funds are shielded the UTXOs should be marked as spend and not shown on the balance.
    /// now balance should be zero shielded, zero transaparent.
    /// 10. clear the UTXO from darksidewalletd's cache
    /// 11. stage the pending shielding transaction in darksidewalletd ad `utxoHeight + 12`
    /// 12. advance the chain tip to sync the now mined shielding transaction
    /// 13. sync up to chain tip
    /// Now it should verify that the balance has been shielded. The resulting balance should be zero
    /// transparent funds and `10000 - fee` total shielded funds,  zero verified shielded funds.
    /// 14. proceed confirm the shielded funds by staging ten more blocks
    /// 15. sync up to the new chain tip
    /// verify that the shielded transactions are confirmed
    ///
    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testShieldFunds() async throws {
        let accountUUID = TestsData.mockedAccountUUID

        // 1. load the dataset
        try coordinator.service.useDataset(from: "https://raw.githubusercontent.com/zcash-hackworks/darksidewalletd-test-data/master/shield-funds/1631000.txt")

        sleep(1)
        try coordinator.stageBlockCreate(height: birthday + 1, count: 200, nonce: 0)

        sleep(1)

        let utxoHeight = BlockHeight(1631177)
        var shouldContinue = false
        var initialTotalBalance = Zatoshi(-1)
        var initialVerifiedBalance = Zatoshi(-1)

        var initialTransparentBalance: Zatoshi = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.unshielded ?? .zero

        let utxo = try GetAddressUtxosReply(jsonString:
            """
            {
                "txid": "3md9M0OOpPBsF02Rp2b7CJZMpv093bjLuSCIG1RPioU=",
                "script": "dqkU1mkF+eETNMCYyJs0OZcygn0KDi+IrA==",
                "valueZat": "10000",
                "height": "1631177",
                "address": "t1dRJRY7GmyeykJnMH38mdQoaZtFhn1QmGz"
            }
            """)
        // 2. applyStaged to `utxoHeight - 1`
        try coordinator.service.applyStaged(nextLatestHeight: utxoHeight - 1)
        sleep(2)

        let preTxExpectation = XCTestExpectation(description: "pre receive")

        // 3. sync up to that height
        do {
            try await coordinator.sync(
                completion: { synchronizer in
                    initialVerifiedBalance = try await synchronizer.getAccountsBalances()[accountUUID]?.saplingBalance.spendableValue ?? .zero
                    initialTotalBalance = try await synchronizer.getAccountsBalances()[accountUUID]?.saplingBalance.total() ?? .zero
                    preTxExpectation.fulfill()
                    shouldContinue = true
                },
                error: self.handleError
            )
        } catch {
            await handleError(error)
        }

        await fulfillment(of: [preTxExpectation], timeout: 10)

        guard shouldContinue else {
            XCTFail("pre receive sync failed")
            return
        }

        // at this point the balance should be all zeroes for transparent and shielded funds
        XCTAssertEqual(initialTotalBalance, Zatoshi.zero)
        XCTAssertEqual(initialVerifiedBalance, Zatoshi.zero)
        initialTransparentBalance = (try? await coordinator.synchronizer.getAccountsBalances()[accountUUID])?.unshielded ?? .zero

        XCTAssertEqual(initialTransparentBalance, .zero)

        // 4. Add the UTXO to darksidewalletd fake chain
        try coordinator.service.addUTXO(utxo)

        sleep(1)

        // 5. advance chain to the `utxoHeight`
        try coordinator.service.applyStaged(nextLatestHeight: utxoHeight)

        sleep(1)

        let tFundsDetectionExpectation = XCTestExpectation(description: "t funds detection expectation")
        shouldContinue = false

        // 6. Sync and find the UXTO on chain.
        do {
            try await coordinator.sync(
                completion: { _ in
                    shouldContinue = true
                    tFundsDetectionExpectation.fulfill()
                },
                error: self.handleError
            )
        } catch {
            await handleError(error)
        }
        await fulfillment(of: [tFundsDetectionExpectation], timeout: 2)

        // at this point the balance should be zero for shielded, then zero verified transparent funds
        // and 10000 zatoshi of total (not verified) transparent funds.
        let tFundsDetectedBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.unshielded ?? .zero

        XCTAssertEqual(tFundsDetectedBalance, Zatoshi(10000))

        let tFundsConfirmationSyncExpectation = XCTestExpectation(description: "t funds confirmation")

        shouldContinue = false

        // 7. stage ten blocks and confirm the transparent funds at `utxoHeight + 10`
        try coordinator.applyStaged(blockheight: utxoHeight + 10)

        sleep(2)

        // 8. sync up to chain tip.
        do {
            try await coordinator.sync(
                completion: { _ in
                    shouldContinue = true
                    tFundsConfirmationSyncExpectation.fulfill()
                },
                error: self.handleError
            )
        } catch {
            await handleError(error)
        }

        await fulfillment(of: [tFundsConfirmationSyncExpectation], timeout: 5)

        // the transparent funds should be 10000 zatoshis both total and verified
        let confirmedTFundsBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.unshielded ?? .zero

        XCTAssertEqual(confirmedTFundsBalance, Zatoshi(10000))

        // 9. shield the funds
        let shieldFundsExpectation = XCTestExpectation(description: "shield funds")

        shouldContinue = false

        var shieldingPendingTx: ZcashTransaction.Overview?

        // shield the funds
        do {
//            let pendingTx = try await coordinator.synchronizer.shieldFunds(
//                spendingKey: coordinator.spendingKey,
//                memo: try Memo(string: "shield funds"),
//                shieldingThreshold: Zatoshi(10000)
//            )
//            shouldContinue = true
//            XCTAssertEqual(pendingTx.value, Zatoshi(10000) - pendingTx.fee!)
//            shieldingPendingTx = pendingTx
            shieldFundsExpectation.fulfill()
        } catch {
            shieldFundsExpectation.fulfill()
            XCTFail("Failed With error: \(error)")
        }

        await fulfillment(of: [shieldFundsExpectation], timeout: 30)

        guard shouldContinue else { return }

        let postShieldingBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.unshielded ?? .zero
        // when funds are shielded the UTXOs should be marked as spend and not shown on the balance.
        // now balance should be zero shielded, zero transaparent.
        // verify that the balance has been marked as spent regardless of confirmation
        // FIXME: [#720] this should be zero, https://github.com/zcash/ZcashLightClientKit/issues/720
        XCTAssertEqual(postShieldingBalance, Zatoshi(10000))
        var expectedBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.saplingBalance.total() ?? .zero
        XCTAssertEqual(expectedBalance, .zero)

        // 10. clear the UTXO from darksidewalletd's cache
        try coordinator.service.clearAddedUTXOs()

        guard let rawTxData = shieldingPendingTx?.raw else {
            XCTFail("Pending transaction has no raw data")
            return
        }

        let rawTx = RawTransaction.with({ raw in
            raw.data = rawTxData
        })

        // 11. stage the pending shielding transaction in darksidewalletd ad `utxoHeight + 1`
        try coordinator.service.stageTransaction(rawTx, at: utxoHeight + 10 + 1)

        sleep(1)

        // 12. advance the chain tip to sync the now mined shielding transaction
        try coordinator.service.applyStaged(nextLatestHeight: utxoHeight + 10 + 1)

        sleep(1)

        // 13. sync up to chain tip
        let postShieldSyncExpectation = XCTestExpectation(description: "sync Post shield")
        shouldContinue = false
        do {
            try await coordinator.sync(
                completion: { _ in
                    shouldContinue = true
                    postShieldSyncExpectation.fulfill()
                },
                error: self.handleError
            )
        } catch {
            await handleError(error)
            postShieldSyncExpectation.fulfill()
        }

        await fulfillment(of: [postShieldSyncExpectation], timeout: 3)

        guard shouldContinue else { return }

        // Now it should verify that the balance has been shielded. The resulting balance should be zero
        // transparent funds and `10000 - fee` total shielded funds,  zero verified shielded funds.
        let postShieldingShieldedBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.unshielded ?? .zero

        XCTAssertEqual(postShieldingShieldedBalance, .zero)

        expectedBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.saplingBalance.total() ?? .zero
        XCTAssertEqual(expectedBalance, Zatoshi(9000))

        // 14. proceed confirm the shielded funds by staging ten more blocks
        try coordinator.service.applyStaged(nextLatestHeight: utxoHeight + 10 + 1 + 10)

        sleep(2)
        let confirmationExpectation = XCTestExpectation(description: "confirmation expectation")

        shouldContinue = false

        // 15. sync up to the new chain tip
        do {
            try await coordinator.sync(
                completion: { _ in
                    shouldContinue = true
                    confirmationExpectation.fulfill()
                },
                error: self.handleError
            )
        } catch {
            await handleError(error)
            confirmationExpectation.fulfill()
        }

        await fulfillment(of: [confirmationExpectation], timeout: 5)

        guard shouldContinue else { return }

        // verify that there's a confirmed transaction that's the shielding transaction
        let clearedTransaction = await coordinator.synchronizer.transactions.first(
            where: { $0.rawID == shieldingPendingTx?.rawID }
        )

        XCTAssertNotNil(clearedTransaction)

        expectedBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.saplingBalance.total() ?? .zero
        XCTAssertEqual(expectedBalance, Zatoshi(9000))
        let postShieldingConfirmationShieldedBalance = try await coordinator.synchronizer.getAccountsBalances()[accountUUID]?.unshielded ?? .zero
        XCTAssertEqual(postShieldingConfirmationShieldedBalance, .zero)
    }

    func handleError(_ error: Error?) async {
        _ = try? await coordinator.stop()
        guard let testError = error else {
            XCTFail("failed with nil error")
            return
        }
        XCTFail("Failed with error: \(testError)")
    }
}
