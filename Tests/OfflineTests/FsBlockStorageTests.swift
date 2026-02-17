//
//  FsBlockStorageTests.swift
//  
//
//  Created by Francisco Gindre on 12/15/22.
//
import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

var logger = OSLogger(logLevel: .debug)

final class FsBlockStorageTests: ZcashTestCase {
    let testFileManager = FileManager()
    var fsBlockDb: URL!
    var rustBackend: ZcashRustBackendWelding!

    override func setUp() async throws {
        try await super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
        self.fsBlockDb = testTempDirectory.appendingPathComponent("FsBlockDb-\(Int.random(in: 0 ... .max))")
        try self.testFileManager.createDirectory(at: self.fsBlockDb, withIntermediateDirectories: false)

        rustBackend = ZcashRustBackend.makeForTests(fsBlockDbRoot: testTempDirectory, networkType: .testnet)
        try await rustBackend.openDb()
    }

    override func tearDown() async throws {
        try await super.tearDown()
        rustBackend = nil
    }

    func testLatestHeightEmptyCache() async throws {
        let emptyCache: FSCompactBlockRepository = .emptyTemporaryCache

        try await emptyCache.create()

        let latestHeight = try await emptyCache.latestHeight()
        XCTAssertEqual(latestHeight, .empty())
    }

    func testRewindEmptyCacheDoesNothing() async throws {
        let emptyCache: FSCompactBlockRepository = .emptyTemporaryCache

        try await emptyCache.create()

        try await emptyCache.rewind(to: 1000000)
    }

    func testWhenBlockIsStoredItFollowsTheDescribedFormat() async throws {
        let blockNameFixture = "This-is-a-fixture"

        let freshCache = FSCompactBlockRepository(
            fsBlockDbRoot: testTempDirectory,
            metadataStore: .mock,
            blockDescriptor: ZcashCompactBlockDescriptor(
                height: { _ in nil },
                describe: { _ in blockNameFixture },
                compare: { _, _ in nil }
            ),
            contentProvider: DirectoryListingProviders.defaultSorted,
            logger: logger
        )

        try await freshCache.create()

        let fakeBlock = StubBlockCreator.createRandomDataBlock(with: 1234)!

        try await freshCache.write(blocks: [fakeBlock])

        let blockFilename = freshCache.blocksDirectory
            .appendingPathComponent(blockNameFixture)
            .path

        XCTAssertTrue(FileManager.default.isReadableFile(atPath: blockFilename))
    }

    func testWhenBlockIsStoredItFollowsTheFilenameConvention() async throws {
        let freshCache = FSCompactBlockRepository(
            fsBlockDbRoot: testTempDirectory,
            metadataStore: .mock,
            blockDescriptor: .live,
            contentProvider: DirectoryListingProviders.defaultSorted,
            logger: logger
        )

        try await freshCache.create()

        let fakeBlock = StubBlockCreator.createRandomDataBlock(with: 1234)!
        let fakeBlockHash = fakeBlock.meta.hash.toHexStringTxId()

        try await freshCache.write(blocks: [fakeBlock])

        let blockFilename = freshCache.blocksDirectory
            .appendingPathComponent(
                "\(1234)-\(fakeBlockHash)-compactblock"
            )
            .path

        XCTAssertTrue(FileManager.default.isReadableFile(atPath: blockFilename))
    }

    func testRewindDeletesTheRightBlocks() async throws {
        let contentProvider = DirectoryListingProviders.defaultSorted
        let freshCache = FSCompactBlockRepository(
            fsBlockDbRoot: testTempDirectory,
            metadataStore: .mock,
            blockDescriptor: .live,
            contentProvider: contentProvider,
            logger: logger
        )

        try await freshCache.create()

        let blockRange = CompactBlockRange(uncheckedBounds: (1000, 2000))

        let fakeBlocks = StubBlockCreator.createBlockRange(blockRange)!

        let rewindHeight = BlockHeight(1500)

        try await freshCache.write(blocks: fakeBlocks)

        let contents = try contentProvider.listContents(of: freshCache.blocksDirectory)

        XCTAssertEqual(contents.count, blockRange.count)

        guard let firstStoredBlock = contents.first else {
            XCTFail("no stored block")
            return
        }

        guard let filename = try firstStoredBlock.resourceValues(forKeys: [URLResourceKey.nameKey]).name else {
            XCTFail("no filename")
            return
        }
        
        XCTAssertEqual(ZcashCompactBlockDescriptor.live.height(filename), 1000)

        guard let lastStoredBlock = contents.last else {
            XCTFail("no stored block")
            return
        }

        XCTAssertEqual(ZcashCompactBlockDescriptor.live.height(lastStoredBlock.lastPathComponent), 2000)

        try await freshCache.rewind(to: rewindHeight)

        let afterRewindContents = try contentProvider.listContents(of: freshCache.blocksDirectory)

        XCTAssertEqual(afterRewindContents.count, 501)

        guard let firstStoredBlockAfterRewind = afterRewindContents.first else {
            XCTFail("no stored block")
            return
        }

        XCTAssertEqual(ZcashCompactBlockDescriptor.live.height(firstStoredBlockAfterRewind.lastPathComponent), 1000)

        guard let lastStoredBlockAfterRewind = afterRewindContents.last else {
            XCTFail("no stored block")
            return
        }

        XCTAssertEqual(ZcashCompactBlockDescriptor.live.height(lastStoredBlockAfterRewind.lastPathComponent), 1500)
    }

    func testGetLatestHeight() async throws {
        let freshCache = FSCompactBlockRepository(
            fsBlockDbRoot: testTempDirectory,
            metadataStore: .live(fsBlockDbRoot: testTempDirectory, rustBackend: rustBackend, logger: logger),
            blockDescriptor: .live,
            contentProvider: DirectoryListingProviders.defaultSorted,
            logger: logger
        )

        try await freshCache.create()

        let blockRange = CompactBlockRange(uncheckedBounds: (1000, 2000))

        let fakeBlocks = StubBlockCreator.createBlockRange(blockRange)!

        try await freshCache.write(blocks: fakeBlocks)

        let latestHeight = try await freshCache.latestHeight()

        XCTAssertEqual(latestHeight, 2000)
    }

    func testBlockDescriptorFiltersBlocksGreaterThan() throws {
        let cacheList = [
            "1000-DEADBEEF-block",
            "1001-DEADBEEF1-block",
            "1002-DEADBEEF2-block",
            "1003-DEADBEEF3-block",
            "1004-DEADBEEF4-block",
            "1005-DEADBEEF5-block",
            "1006-DEADBEEF6-block",
            "1007-DEADBEEF7-block",
            "1008-DEADBEEF8-block",
            "1009-DEADBEEF9-block",
            "1010-DEADBEEFA-block"
        ]

        XCTAssertEqual(
            try cacheList.filter { try $0.filterGreaterThan(1006, with: .live) },
            [
                "1007-DEADBEEF7-block",
                "1008-DEADBEEF8-block",
                "1009-DEADBEEF9-block",
                "1010-DEADBEEFA-block"
            ]
        )
    }

    func testBlockDescriptorFiltersThrowsIfFileDescriptorFails() throws {
        let cacheList = [
            "1000-DEADBEEF-block",
            "1001-DEADBEEF1-block",
            "1002-DEADBEEF2-block",
            "1003-DEADBEEF3-block",
            "1004-DEADBEEF4-block",
            "1005-DEADBEEF5-block",
            "a-DEADBEEF6-block",
            "1007-DEADBEEF7-block",
            "1008-DEADBEEF8-block",
            "1009-DEADBEEF9-block",
            "1010-DEADBEEFA-block"
        ]

        XCTAssertThrowsError(try cacheList.filter { try $0.filterGreaterThan(1006, with: .live) })
    }

    func testRewindBlockSelectTheProperFilesByName() throws {
        let cacheList = try [
            "1000-DEADBEEF-block",
            "1001-DEADBEEF1-block",
            "1002-DEADBEEF2-block",
            "1003-DEADBEEF3-block",
            "1004-DEADBEEF4-block",
            "1005-DEADBEEF5-block",
            "1006-DEADBEEF6-block",
            "1007-DEADBEEF7-block",
            "1008-DEADBEEF8-block",
            "1009-DEADBEEF9-block",
            "1010-DEADBEEFA-block"
        ].map { filename in
            var url = self.fsBlockDb.appendingPathComponent(filename)
            guard self.testFileManager.createFile(atPath: url.path, contents: nil) else {
                XCTFail("couldn't create file at \(url.absoluteString)")
                throw "couldn't create file at \(url.path)"
            }
            var resourceValues = URLResourceValues()
            resourceValues.name = filename

            try url.setResourceValues(resourceValues)

            return url
        }

        let expectedDeleteList = try [
            "1007-DEADBEEF7-block",
            "1008-DEADBEEF8-block",
            "1009-DEADBEEF9-block",
            "1010-DEADBEEFA-block"
        ].reversed().map { filename in
            var url = self.fsBlockDb.appendingPathComponent(filename)
            var resourceValues = URLResourceValues()
            resourceValues.name = filename
            try url.setResourceValues(resourceValues)
            return url
        }

        XCTAssertEqual(
            try FSCompactBlockRepository.filterBlockFiles(from: cacheList, toRewind: 1006, with: .live),
            expectedDeleteList
        )
    }

    func testClearTheCache() async throws {
        let fsBlockCache = FSCompactBlockRepository(
            fsBlockDbRoot: testTempDirectory,
            metadataStore: .live(fsBlockDbRoot: testTempDirectory, rustBackend: rustBackend, logger: logger),
            blockDescriptor: .live,
            contentProvider: DirectoryListingProviders.naive,
            logger: logger
        )

        try await fsBlockCache.create()

        guard let stubBlocks = StubBlockCreator.createBlockRange(1000 ... 1010) else {
            XCTFail("Something Happened. Creating Stub blocks failed")
            return
        }

        try await fsBlockCache.write(blocks: stubBlocks)
        var latestHeight = try await fsBlockCache.latestHeight()
        XCTAssertEqual(latestHeight, 1010)

        try await fsBlockCache.clear()

        latestHeight = try await fsBlockCache.latestHeight()
        XCTAssertEqual(latestHeight, .empty())
    }

    func testCreateDoesntFailWhenAlreadyCreated() async throws {
        let freshCache = FSCompactBlockRepository(
            fsBlockDbRoot: testTempDirectory,
            metadataStore: .mock,
            blockDescriptor: .live,
            contentProvider: DirectoryListingProviders.defaultSorted,
            logger: logger
        )

        try await freshCache.create()
        try await freshCache.create()
    }

    func testStoringTenSandblastedBlocks() async throws {
        let realCache = FSCompactBlockRepository(
            fsBlockDbRoot: testTempDirectory,
            metadataStore: .live(fsBlockDbRoot: testTempDirectory, rustBackend: rustBackend, logger: logger),
            blockDescriptor: .live,
            contentProvider: DirectoryListingProviders.defaultSorted,
            logger: logger
        )

        try await realCache.create()

        guard let sandblastedBlocks = try SandblastSimulator().sandblast(with: CompactBlockRange(uncheckedBounds: (10, 19))) else {
            XCTFail("failed to create sandblasted blocks")
            return
        }

        try await realCache.write(blocks: sandblastedBlocks)

        let latestHeight = try await realCache.latestHeight()

        XCTAssertEqual(latestHeight, 19)
    }

    func testStoringTenSandblastedBlocksFailsAndThrows() async throws {
        let realCache = FSCompactBlockRepository(
            fsBlockDbRoot: testTempDirectory,
            metadataStore: .live(fsBlockDbRoot: testTempDirectory, rustBackend: rustBackend, logger: logger),
            blockDescriptor: .live,
            contentProvider: DirectoryListingProviders.defaultSorted,
            fileWriter: FSBlockFileWriter(writeToURL: { _, _ in  throw FixtureError.arbitraryError }),
            logger: logger
        )

        try await realCache.create()

        guard let sandblastedBlocks = try SandblastSimulator().sandblast(with: CompactBlockRange(uncheckedBounds: (10, 19))) else {
            XCTFail("failed to create sandblasted blocks")
            return
        }

        do {
            try await realCache.write(blocks: sandblastedBlocks)
            XCTFail("This call should have failed")
        } catch {
            if let error = error as? ZcashError, case let .blockRepositoryWriteBlock(url, _) = error {
                XCTAssertEqual(url, sandblastedBlocks[0])
            } else {
                XCTFail("Unexpected error thrown: \(error)")
            }
        }
    }

    func testStoringTenSandblastedBlocksAndRewindFiveThenStoreThemBack() async throws {
        let realCache = FSCompactBlockRepository(
            fsBlockDbRoot: testTempDirectory,
            metadataStore: .live(fsBlockDbRoot: testTempDirectory, rustBackend: rustBackend, logger: logger),
            blockDescriptor: .live,
            contentProvider: DirectoryListingProviders.defaultSorted,
            logger: logger
        )

        try await realCache.create()

        guard let sandblastedBlocks = try SandblastSimulator().sandblast(with: CompactBlockRange(uncheckedBounds: (10, 19))) else {
            XCTFail("failed to create sandblasted blocks")
            return
        }

        let startTime = Date()
        try await realCache.write(blocks: sandblastedBlocks)
        let endTime = Date()

        let timePassed = startTime.distance(to: endTime)

        XCTAssertLessThan(timePassed, 0.5)

        let latestHeight = try await realCache.latestHeight()

        XCTAssertEqual(latestHeight, 19)

        try await realCache.rewind(to: 14)

        let rewoundHeight = try await realCache.latestHeight()

        XCTAssertEqual(rewoundHeight, 14)

        let blockSlice = [ZcashCompactBlock](sandblastedBlocks[5...])
        try await realCache.write(blocks: blockSlice)

        let newLatestHeight = try await realCache.latestHeight()

        XCTAssertEqual(newLatestHeight, 19)
    }

    func testMetadataStoreThrowsWhenRustThrows() async {
        guard let sandblastedBlocks = try? SandblastSimulator().sandblast(with: CompactBlockRange(uncheckedBounds: (10, 19))) else {
            XCTFail("failed to create sandblasted blocks")
            return
        }
        let mockBackend = await RustBackendMockHelper(rustBackend: rustBackend)
        
        mockBackend.rustBackendMock.writeBlocksMetadataBlocksThrowableError = ZcashError.rustWriteBlocksMetadataAllocationProblem

        do {
            try await FSMetadataStore.saveBlocksMeta(
                sandblastedBlocks,
                fsBlockDbRoot: testTempDirectory,
                rustBackend: mockBackend.rustBackendMock,
                logger: logger
            )
        } catch ZcashError.rustWriteBlocksMetadataAllocationProblem {
            // this is fine
        } catch {
            XCTFail("Expected `CompactBlockRepositoryError.failedToWriteMetadata` but found: \(error)")
        }
    }

    func testMetadataStoreThrowsWhenRewindFails() async {
        let expectedHeight = BlockHeight(1000)

        let mockBackend = await RustBackendMockHelper(rustBackend: rustBackend)
        mockBackend.rustBackendMock.rewindCacheToHeightHeightThrowableError = ZcashError.rustRewindToHeight(Int32(expectedHeight), "oops")

        do {
            try await FSMetadataStore.live(
                fsBlockDbRoot: testTempDirectory,
                rustBackend: mockBackend.rustBackendMock,
                logger: logger
            )
            .rewindToHeight(expectedHeight)
            XCTFail("rewindToHeight should fail")
        } catch {
            guard let error = error as? ZcashError else {
                XCTFail("Expected ZcashError. Found \(error)")
                return
            }

            switch error {
            case let .rustRewindToHeight(height, _):
                XCTAssertEqual(BlockHeight(height), expectedHeight)
            default:
                XCTFail("Expected `ZcashError.rustRewindToHeight`. Found \(error)")
            }
        }
    }

    // Disabled for now becasue we are not getting consistent results on GA Ci
    func disable_testPerformanceExample() async throws {
        // NOTE: performance tests don't work with async code. Thanks Apple!
        let freshCache = FSCompactBlockRepository(
            fsBlockDbRoot: testTempDirectory,
            metadataStore: .live(fsBlockDbRoot: testTempDirectory, rustBackend: rustBackend, logger: logger),
            blockDescriptor: .live,
            contentProvider: DirectoryListingProviders.defaultSorted,
            logger: logger
        )

        try await freshCache.create()

        let blockRange = CompactBlockRange(uncheckedBounds: (1000, 2000))

        let fakeBlocks = try SandblastSimulator().sandblast(with: blockRange)!

        let startTime = Date()
        try await freshCache.write(blocks: fakeBlocks)
        let endTime = Date()

        let latestHeight = try await freshCache.latestHeight()

        XCTAssertEqual(latestHeight, 2000)

        let total = startTime.distance(to: endTime)
        //        let totalKiloBytes = fakeBlocks.map { $0.data.count }.reduce(0, +) / 1024 // 245055
        XCTAssertGreaterThan(1.5, total)
    }
}

extension FSCompactBlockRepository {
    static var emptyTemporaryCache: FSCompactBlockRepository {
        FSCompactBlockRepository(
            fsBlockDbRoot: URL(fileURLWithPath: NSString(
                string: NSTemporaryDirectory()
            ).appendingPathComponent("tmp-\(Int.random(in: 0 ... .max))")),
            metadataStore: .mock,
            blockDescriptor: ZcashCompactBlockDescriptor(
                height: { _ in BlockHeight() },
                describe: { _ in "123456-deadbeef-block" },
                compare: { _, _ in nil }
            ),
            contentProvider: SortedDirectoryContentProvider(
                fileManager: FileManager.default,
                sorting: { _, _ in false }
            ),
            logger: OSLogger(logLevel: .debug)
        )
    }
}

enum FixtureError: Error, Equatable {
    case arbitraryError
}

extension FSMetadataStore {
    static let mock = FSMetadataStore(
        saveBlocksMeta: { _ in },
        rewindToHeight: { _ in },
        initFsBlockDbRoot: { },
        latestHeight: { .empty() },
        reopenBlockDb: { }
    )
}
