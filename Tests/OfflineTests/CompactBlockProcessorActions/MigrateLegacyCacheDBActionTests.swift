//
//  MigrateLegacyCacheDBActionTests.swift
//
//
//  Created by Lukáš Korba on 23.05.2023.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class MigrateLegacyCacheDBActionTests: ZcashTestCase {
    var underlyingAlias: ZcashSynchronizerAlias?
    var underlyingCacheDbURL: URL?
    var underlyingFsBlockCacheRoot: URL?

    override func setUp() {
        super.setUp()

        underlyingAlias = nil
        underlyingCacheDbURL = nil
        underlyingFsBlockCacheRoot = nil
    }

    func testMigrateLegacyCacheDBAction_noCacheDbURL() async throws {
        let compactBlockRepositoryMock = CompactBlockRepositoryMock()
        let transactionRepositoryMock = TransactionRepositoryMock()
        let zcashFileManagerMock = ZcashFileManagerMock()

        let migrateLegacyCacheDBAction = setupAction(
            compactBlockRepositoryMock,
            transactionRepositoryMock,
            zcashFileManagerMock
        )

        do {
            let context = ActionContextMock.default()
            let nextContext = try await migrateLegacyCacheDBAction.run(with: context) { _ in }

            XCTAssertFalse(compactBlockRepositoryMock.createCalled, "storage.create() is not expected to be called.")
            XCTAssertFalse(zcashFileManagerMock.isReadableFileAtPathCalled, "fileManager.isReadableFile() is not expected to be called.")
            XCTAssertFalse(zcashFileManagerMock.removeItemAtCalled, "fileManager.removeItem() is not expected to be called.")

            let acResult = nextContext.checkStateIs(.validateServer)
            XCTAssertTrue(acResult == .true, "Check of state failed with '\(acResult)'")
        } catch {
            XCTFail("testMigrateLegacyCacheDBAction_noCacheDbURL is not expected to fail. \(error)")
        }
    }

    func testMigrateLegacyCacheDBAction_noFsBlockCacheRoot() async throws {
        let compactBlockRepositoryMock = CompactBlockRepositoryMock()
        let transactionRepositoryMock = TransactionRepositoryMock()
        let zcashFileManagerMock = ZcashFileManagerMock()

        underlyingCacheDbURL = DefaultResourceProvider(network: ZcashNetworkBuilder.network(for: .testnet)).fsCacheURL

        let migrateLegacyCacheDBAction = setupAction(
            compactBlockRepositoryMock,
            transactionRepositoryMock,
            zcashFileManagerMock
        )

        do {
            let context = ActionContextMock.default()
            _ = try await migrateLegacyCacheDBAction.run(with: context) { _ in }
            XCTFail("testMigrateLegacyCacheDBAction_noFsBlockCacheRoot is expected to fail.")
        } catch ZcashError.compactBlockProcessorCacheDbMigrationFsCacheMigrationFailedSameURL {
            XCTAssertFalse(compactBlockRepositoryMock.createCalled, "storage.create() is not expected to be called.")
            XCTAssertFalse(zcashFileManagerMock.isReadableFileAtPathCalled, "fileManager.isReadableFile() is not expected to be called.")
            XCTAssertFalse(zcashFileManagerMock.removeItemAtCalled, "fileManager.removeItem() is not expected to be called.")
        } catch {
            XCTFail("""
            testMigrateLegacyCacheDBAction_noFsBlockCacheRoot is expected to fail with \
            ZcashError.compactBlockProcessorCacheDbMigrationFsCacheMigrationFailedSameURL but received \(error)
            """)
        }
    }

    func testMigrateLegacyCacheDBAction_aliasDoesntMatchDefault() async throws {
        let compactBlockRepositoryMock = CompactBlockRepositoryMock()
        let transactionRepositoryMock = TransactionRepositoryMock()
        let zcashFileManagerMock = ZcashFileManagerMock()

        // any valid URL needed...
        underlyingCacheDbURL = DefaultResourceProvider(network: ZcashNetworkBuilder.network(for: .testnet)).fsCacheURL
        underlyingFsBlockCacheRoot = DefaultResourceProvider(network: ZcashNetworkBuilder.network(for: .testnet)).dataDbURL

        underlyingAlias = .custom("any")

        let migrateLegacyCacheDBAction = setupAction(
            compactBlockRepositoryMock,
            transactionRepositoryMock,
            zcashFileManagerMock
        )

        do {
            let context = ActionContextMock.default()
            let nextContext = try await migrateLegacyCacheDBAction.run(with: context) { _ in }

            XCTAssertFalse(compactBlockRepositoryMock.createCalled, "storage.create() is not expected to be called.")
            XCTAssertFalse(zcashFileManagerMock.isReadableFileAtPathCalled, "fileManager.isReadableFile() is not expected to be called.")
            XCTAssertFalse(zcashFileManagerMock.removeItemAtCalled, "fileManager.removeItem() is not expected to be called.")

            let acResult = nextContext.checkStateIs(.validateServer)
            XCTAssertTrue(acResult == .true, "Check of state failed with '\(acResult)'")
        } catch {
            XCTFail("testMigrateLegacyCacheDBAction_aliasDoesntMatchDefault is not expected to fail. \(error)")
        }
    }

    func testMigrateLegacyCacheDBAction_isNotReadableFile() async throws {
        let compactBlockRepositoryMock = CompactBlockRepositoryMock()
        let transactionRepositoryMock = TransactionRepositoryMock()
        let zcashFileManagerMock = ZcashFileManagerMock()

        // any valid URL needed...
        underlyingCacheDbURL = DefaultResourceProvider(network: ZcashNetworkBuilder.network(for: .testnet)).fsCacheURL
        underlyingFsBlockCacheRoot = DefaultResourceProvider(network: ZcashNetworkBuilder.network(for: .testnet)).dataDbURL

        zcashFileManagerMock.isReadableFileAtPathReturnValue = false

        let migrateLegacyCacheDBAction = setupAction(
            compactBlockRepositoryMock,
            transactionRepositoryMock,
            zcashFileManagerMock
        )

        do {
            let context = ActionContextMock.default()
            let nextContext = try await migrateLegacyCacheDBAction.run(with: context) { _ in }

            XCTAssertFalse(compactBlockRepositoryMock.createCalled, "storage.create() is not expected to be called.")
            XCTAssertTrue(zcashFileManagerMock.isReadableFileAtPathCalled, "fileManager.isReadableFile() is expected to be called.")
            XCTAssertFalse(zcashFileManagerMock.removeItemAtCalled, "fileManager.removeItem() is not expected to be called.")

            let acResult = nextContext.checkStateIs(.validateServer)
            XCTAssertTrue(acResult == .true, "Check of state failed with '\(acResult)'")
        } catch {
            XCTFail("testMigrateLegacyCacheDBAction_isNotReadableFile is not expected to fail. \(error)")
        }
    }

    func testMigrateLegacyCacheDBAction_removeItemFailed() async throws {
        let compactBlockRepositoryMock = CompactBlockRepositoryMock()
        let transactionRepositoryMock = TransactionRepositoryMock()
        let zcashFileManagerMock = ZcashFileManagerMock()

        // any valid URL needed...
        underlyingCacheDbURL = DefaultResourceProvider(network: ZcashNetworkBuilder.network(for: .testnet)).fsCacheURL
        underlyingFsBlockCacheRoot = DefaultResourceProvider(network: ZcashNetworkBuilder.network(for: .testnet)).dataDbURL

        zcashFileManagerMock.isReadableFileAtPathReturnValue = true
        zcashFileManagerMock.removeItemAtClosure = { _ in throw "remove failed" }

        let migrateLegacyCacheDBAction = setupAction(
            compactBlockRepositoryMock,
            transactionRepositoryMock,
            zcashFileManagerMock
        )

        do {
            let context = ActionContextMock.default()
            _ = try await migrateLegacyCacheDBAction.run(with: context) { _ in }
        } catch ZcashError.compactBlockProcessorCacheDbMigrationFailedToDeleteLegacyDb {
            XCTAssertFalse(compactBlockRepositoryMock.createCalled, "storage.create() is not expected to be called.")
            XCTAssertTrue(zcashFileManagerMock.isReadableFileAtPathCalled, "fileManager.isReadableFile() is expected to be called.")
            XCTAssertTrue(zcashFileManagerMock.removeItemAtCalled, "fileManager.removeItem() is expected to be called.")
        } catch {
            XCTFail("""
            testMigrateLegacyCacheDBAction_removeItemFailed is expected to fail with \
            ZcashError.compactBlockProcessorCacheDbMigrationFailedToDeleteLegacyDb but received \(error)
            """)
        }
    }

    func testMigrateLegacyCacheDBAction_nextAction() async throws {
        let compactBlockRepositoryMock = CompactBlockRepositoryMock()
        let transactionRepositoryMock = TransactionRepositoryMock()
        let zcashFileManagerMock = ZcashFileManagerMock()

        // any valid URL needed...
        underlyingCacheDbURL = DefaultResourceProvider(network: ZcashNetworkBuilder.network(for: .testnet)).fsCacheURL
        underlyingFsBlockCacheRoot = DefaultResourceProvider(network: ZcashNetworkBuilder.network(for: .testnet)).dataDbURL

        zcashFileManagerMock.isReadableFileAtPathReturnValue = true
        zcashFileManagerMock.removeItemAtClosure = { _ in }
        compactBlockRepositoryMock.createClosure = { }

        let migrateLegacyCacheDBAction = setupAction(
            compactBlockRepositoryMock,
            transactionRepositoryMock,
            zcashFileManagerMock
        )

        do {
            let context = ActionContextMock.default()
            let nextContext = try await migrateLegacyCacheDBAction.run(with: context) { _ in }

            XCTAssertTrue(compactBlockRepositoryMock.createCalled, "storage.create() is expected to be called.")
            XCTAssertTrue(zcashFileManagerMock.isReadableFileAtPathCalled, "fileManager.isReadableFile() is expected to be called.")
            XCTAssertTrue(zcashFileManagerMock.removeItemAtCalled, "fileManager.removeItem() is expected to be called.")

            let acResult = nextContext.checkStateIs(.validateServer)
            XCTAssertTrue(acResult == .true, "Check of state failed with '\(acResult)'")
        } catch {
            XCTFail("testMigrateLegacyCacheDBAction_nextAction is not expected to fail. \(error)")
        }
    }

    private func setupAction(
        _ compactBlockRepositoryMock: CompactBlockRepositoryMock = CompactBlockRepositoryMock(),
        _ transactionRepositoryMock: TransactionRepositoryMock = TransactionRepositoryMock(),
        _ zcashFileManagerMock: ZcashFileManagerMock = ZcashFileManagerMock(),
        _ loggerMock: LoggerMock = LoggerMock()
    ) -> MigrateLegacyCacheDBAction {
        mockContainer.mock(type: CompactBlockRepository.self, isSingleton: true) { _ in compactBlockRepositoryMock }
        mockContainer.mock(type: TransactionRepository.self, isSingleton: true) { _ in transactionRepositoryMock }
        mockContainer.mock(type: ZcashFileManager.self, isSingleton: true) { _ in zcashFileManagerMock }
        mockContainer.mock(type: Logger.self, isSingleton: true) { _ in loggerMock }

        return MigrateLegacyCacheDBAction(
            container: mockContainer,
            configProvider: setupConfig()
        )
    }

    private func setupConfig() -> CompactBlockProcessor.ConfigProvider {
        let defaultConfig = CompactBlockProcessor.Configuration.standard(
            for: ZcashNetworkBuilder.network(for: .testnet), walletBirthday: 0
        )

        let config = CompactBlockProcessor.Configuration(
            alias: underlyingAlias ?? defaultConfig.alias,
            cacheDbURL: underlyingCacheDbURL ?? defaultConfig.cacheDbURL,
            fsBlockCacheRoot: underlyingFsBlockCacheRoot ?? defaultConfig.fsBlockCacheRoot,
            dataDb: defaultConfig.dataDb,
            torDir: defaultConfig.torDir,
            spendParamsURL: defaultConfig.spendParamsURL,
            outputParamsURL: defaultConfig.outputParamsURL,
            saplingParamsSourceURL: defaultConfig.saplingParamsSourceURL,
            walletBirthdayProvider: defaultConfig.walletBirthdayProvider,
            saplingActivation: defaultConfig.saplingActivation,
            network: defaultConfig.network
        )

        return CompactBlockProcessor.ConfigProvider(config: config)
    }
}
