//
//  Stubs.swift
//  ZcashLightClientKitTests
//
//  Created by Francisco Gindre on 18/09/2019.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import Foundation
import GRPC
import SwiftProtobuf
@testable import ZcashLightClientKit

extension String: @retroactive Error { }

class AwfulLightWalletService: MockLightWalletService {
    override func latestBlockHeight(mode: ServiceMode) async throws -> BlockHeight {
        throw ZcashError.serviceLatestBlockFailed(.criticalError)
    }

    override func blockRange(_ range: CompactBlockRange, mode: ServiceMode) -> AsyncThrowingStream<ZcashCompactBlock, Error> {
        AsyncThrowingStream { continuation in continuation.finish(throwing: ZcashError.serviceSubmitFailed(.invalidBlock)) }
    }

    /// Submits a raw transaction over lightwalletd.
    override func submit(spendTransaction: Data, mode: ServiceMode) async throws -> LightWalletServiceResponse {
        throw ZcashError.serviceSubmitFailed(.invalidBlock)
    }
}

extension LightWalletServiceMockResponse: Error { }

class SlightlyBadLightWalletService: MockLightWalletService {
    /// Submits a raw transaction over lightwalletd.
    override func submit(spendTransaction: Data, mode: ServiceMode) async throws -> LightWalletServiceResponse {
        throw LightWalletServiceMockResponse.error
    }
}

extension LightWalletServiceMockResponse {
    static var error: LightWalletServiceMockResponse {
        LightWalletServiceMockResponse(
            errorCode: -100,
            errorMessage: "Ohhh this is bad, really bad, you lost all your internet money",
            unknownFields: UnknownStorage()
        )
    }

    static var success: LightWalletServiceMockResponse {
        LightWalletServiceMockResponse(errorCode: 0, errorMessage: "", unknownFields: UnknownStorage())
    }
}

class RustBackendMockHelper {
    let rustBackendMock: ZcashRustBackendWeldingMock

    init(
        rustBackend: ZcashRustBackendWelding,
        consensusBranchID: Int32? = nil
    ) async {
        self.rustBackendMock = ZcashRustBackendWeldingMock()
        self.rustBackendMock.consensusBranchIdForHeightClosure = { height in
            if let consensusBranchID {
                return consensusBranchID
            } else {
                return try rustBackend.consensusBranchIdFor(height: height)
            }
        }

        setupDefaultMock(rustBackend: rustBackend)
    }

    private func setupDefaultMock(rustBackend: ZcashRustBackendWelding) {
        rustBackendMock.latestCachedBlockHeightReturnValue = .empty()
        rustBackendMock.initBlockMetadataDbClosure = { }
        rustBackendMock.writeBlocksMetadataBlocksClosure = { _ in }
        rustBackendMock.getTransparentBalanceAccountUUIDReturnValue = 0
        rustBackendMock.listTransparentReceiversAccountUUIDReturnValue = []
        rustBackendMock.getCurrentAddressAccountUUIDThrowableError = ZcashError.rustGetCurrentAddress("mocked error")
        rustBackendMock.getNextAvailableAddressAccountUUIDReceiverFlagsThrowableError = ZcashError.rustGetNextAvailableAddress("mocked error")
        rustBackendMock.createAccountSeedTreeStateRecoverUntilNameKeySourceThrowableError = ZcashError.rustInitAccountsTableViewingKeyCotainsNullBytes
        rustBackendMock.getMemoTxIdOutputPoolOutputIndexReturnValue = nil
        rustBackendMock.initDataDbSeedReturnValue = .seedRequired
        rustBackendMock.putUnspentTransparentOutputTxidIndexScriptValueHeightClosure = { _, _, _, _, _ in }
        rustBackendMock.proposeTransferAccountUUIDToValueMemoThrowableError = ZcashError.rustCreateToAddress("mocked error")
        let error = ZcashError.rustShieldFunds("mocked error")
        rustBackendMock.proposeShieldingAccountUUIDMemoShieldingThresholdTransparentReceiverThrowableError = error
        rustBackendMock.createProposedTransactionsProposalUskThrowableError = ZcashError.rustCreateToAddress("mocked error")
        rustBackendMock.decryptAndStoreTransactionTxBytesMinedHeightThrowableError = ZcashError.rustDecryptAndStoreTransaction("mock fail")

        rustBackendMock.initDataDbSeedClosure = { seed in
            try await rustBackend.initDataDb(seed: seed)
        }

        rustBackendMock.rewindToHeightHeightClosure = { height in
            try await rustBackend.rewindToHeight(height: height)
        }

        rustBackendMock.rewindCacheToHeightHeightClosure = { _ in }

        rustBackendMock.suggestScanRangesClosure = {
            try await rustBackend.suggestScanRanges()
        }

        rustBackendMock.scanBlocksFromHeightFromStateLimitClosure = { fromHeight, fromState, limit in
            try await rustBackend.scanBlocks(fromHeight: fromHeight, fromState: fromState, limit: limit)
        }
    }

    private static func shouldSucceed(successRate: Float) -> Bool {
        let random = Float.random(in: 0.0...1.0)
        return random <= successRate
    }
}

extension SaplingParamsSourceURL {
    static let tests = SaplingParamsSourceURL(
        spendParamFileURL: Bundle.module.url(forResource: "sapling-spend", withExtension: "params")!,
        outputParamFileURL: Bundle.module.url(forResource: "sapling-output", withExtension: "params")!
    )
}

extension CompactBlockProcessor.Configuration {
    /// Standard configuration for most compact block processors
    static func standard(
        alias: ZcashSynchronizerAlias = .default,
        for network: ZcashNetwork,
        walletBirthday: BlockHeight
    ) -> CompactBlockProcessor.Configuration {
        let pathProvider = DefaultResourceProvider(network: network)
        return CompactBlockProcessor.Configuration(
            alias: alias,
            fsBlockCacheRoot: pathProvider.fsCacheURL,
            dataDb: pathProvider.dataDbURL,
            torDir: pathProvider.torDirURL,
            spendParamsURL: pathProvider.spendParamsURL,
            outputParamsURL: pathProvider.outputParamsURL,
            saplingParamsSourceURL: SaplingParamsSourceURL.tests,
            walletBirthdayProvider: { walletBirthday },
            network: network
        )
    }
}

extension SynchronizerState {
    static var mock: SynchronizerState {
        SynchronizerState(
            syncSessionID: .nullID,
            accountsBalances: [:],
            internalSyncStatus: .syncing(0, false),
            latestBlockHeight: 222222
        )
    }
}

/// Stub TransactionEncoder for tests that don't need actual encoding
class StubTransactionEncoder: TransactionEncoder {
    func proposeTransfer(
        accountUUID: AccountUUID,
        recipient: String,
        amount: Zatoshi,
        memoBytes: MemoBytes?
    ) async throws -> Proposal {
        throw ZcashError.synchronizerNotPrepared
    }

    func proposeShielding(
        accountUUID: AccountUUID,
        shieldingThreshold: Zatoshi,
        memoBytes: MemoBytes?,
        transparentReceiver: String?
    ) async throws -> Proposal? {
        throw ZcashError.synchronizerNotPrepared
    }

    func proposeFulfillingPaymentFromURI(
        _ uri: String,
        accountUUID: AccountUUID
    ) async throws -> Proposal {
        throw ZcashError.synchronizerNotPrepared
    }

    func createProposedTransactions(
        proposal: Proposal,
        spendingKey: UnifiedSpendingKey
    ) async throws -> [ZcashTransaction.Overview] {
        throw ZcashError.synchronizerNotPrepared
    }

    func submit(transaction: EncodedTransaction) async throws {
        throw ZcashError.synchronizerNotPrepared
    }

    func fetchTransactionsForTxIds(_ txIds: [Data]) async throws -> [ZcashTransaction.Overview] {
        throw ZcashError.synchronizerNotPrepared
    }

    func closeDBConnection() { }
}
