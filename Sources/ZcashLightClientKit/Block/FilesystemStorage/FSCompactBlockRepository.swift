//
//  CompactBlockFsStorage.swift
//  
//
//  Created by Francisco Gindre on 12/15/22.
//

import Foundation

class FSCompactBlockRepository {
    let fsBlockDbRoot: URL
    let blockDescriptor: ZcashCompactBlockDescriptor
    let contentProvider: SortedDirectoryListing
    let fileWriter: FSBlockFileWriter
    let metadataStore: FSMetadataStore
    let logger: Logger

    private let fileManager = FileManager()
    private let storageBatchSize = 10

    var blocksDirectory: URL {
        fsBlockDbRoot.appendingPathComponent("blocks", isDirectory: true)
    }

    /// Initializes an instance of the Filesystem based compact block repository
    /// - Parameter fsBlockDbRoot: The `URL` pointing to where the blocks should be writen
    /// write access must be **guaranteed**.
    /// - Parameter blockDescriptor: A `ZcashCompactBlockDescriptor` that is used to turn a
    /// `ZcashCompactBlock` into the filename that will hold it on cache
    /// - parameter contentProvider: `SortedDirectoryListing` implementation. This injects the
    /// behaviour of traversing a Directory in an ordered fashion which is not guaranteed by `Foundation`'s `FileManager`
    init(
        fsBlockDbRoot: URL,
        metadataStore: FSMetadataStore,
        blockDescriptor: ZcashCompactBlockDescriptor,
        contentProvider: SortedDirectoryListing,
        fileWriter: FSBlockFileWriter = .atomic,
        logger: Logger
    ) {
        self.fsBlockDbRoot = fsBlockDbRoot
        self.metadataStore = metadataStore
        self.blockDescriptor = blockDescriptor
        self.contentProvider = contentProvider
        self.fileWriter = fileWriter
        self.logger = logger
    }
}

extension FSCompactBlockRepository: CompactBlockRepository {
    func createDirectories() throws {
        if !fileManager.fileExists(atPath: blocksDirectory.path) {
            do {
                try fileManager.createDirectory(at: blocksDirectory, withIntermediateDirectories: true)
            } catch {
                throw ZcashError.blockRepositoryCreateBlocksCacheDirectory(blocksDirectory, error)
            }
        }
    }

    func create() async throws {
        try createDirectories()

        do {
            try await self.metadataStore.initFsBlockDbRoot()
        } catch {
            logger.error("Blocks metadata store init failed with error: \(error)")
            throw error
        }
    }

    func latestHeight() async throws -> BlockHeight {
        try await metadataStore.latestHeight()
    }

    func write(blocks: [ZcashCompactBlock]) async throws {
        do {
            var savedBlocks: [ZcashCompactBlock] = []

            for block in blocks {
                // check if file exists
                let blockURL = self.urlForBlock(block)

                if self.blockExistsInCache(block) {
                    // remove if needed
                    do {
                        try self.fileManager.removeItem(at: blockURL)
                    } catch {
                        throw ZcashError.blockRepositoryRemoveExistingBlock(blockURL, error)
                    }
                }

                // store atomically
                do {
                    try self.fileWriter.writeToURL(block.data, blockURL)
                } catch {
                    logger.error("Failed to write block: \(block.height) to path: \(blockURL.path) with error: \(error)")
                    throw ZcashError.blockRepositoryWriteBlock(block, error)
                }

                savedBlocks.append(block)

                if (savedBlocks.count % storageBatchSize) == 0 {
                    try await self.metadataStore.saveBlocksMeta(savedBlocks)
                    savedBlocks.removeAll(keepingCapacity: true)
                }
            }

            // if there are any remaining blocks on the cache store them
            try await self.metadataStore.saveBlocksMeta(savedBlocks)
        } catch {
            logger.error("failed to Block save to cache error: \(error)")
            throw error
        }
    }

    func rewind(to height: BlockHeight) async throws {
        try await metadataStore.rewindToHeight(height)
        // Reverse the cached contents to browse from higher to lower heights
        let sortedCachedContents = try contentProvider.listContents(of: blocksDirectory)

        // it that bears no elements then there's nothing to do.
        guard let deleteList = try Self.filterBlockFiles(
            from: sortedCachedContents,
            toRewind: height,
            with: self.blockDescriptor
        ),
            !deleteList.isEmpty
        else { return }

        for item in deleteList {
            do {
                try self.fileManager.removeItem(at: item)
            } catch {
                throw ZcashError.blockRepositoryRemoveBlockAfterRewind(item, error)
            }
        }
    }

    func clear(upTo height: BlockHeight) async throws {
        let files = try filesWithHeight(upTo: height)
        logger.debug("Clearing up to height \(height). Clearing \(files.count) blocks from cache.")
        for url in files {
            do {
                try self.fileManager.removeItem(at: url)
            } catch {
                throw ZcashError.blockRepositoryRemoveBlockClearingCache(url, error)
            }
        }
    }

    func clear() async throws {
        try wipe()
        try createDirectories()
        try await metadataStore.reopenBlockDb()
        try await metadataStore.initFsBlockDbRoot()
    }

    func wipe() throws {
        if self.fileManager.fileExists(atPath: self.fsBlockDbRoot.path) {
            do {
                try self.fileManager.removeItem(at: self.fsBlockDbRoot)
            } catch {
                throw ZcashError.blockRepositoryRemoveBlocksCacheDirectory(fsBlockDbRoot, error)
            }
        }
    }
}

extension FSCompactBlockRepository {
    static let filenameComparison: (String, String) -> Int? = { lhs, rhs in
        guard
            let leftHeightStr = lhs.split(separator: "-").first,
            let leftHeight = BlockHeight(leftHeightStr),
            let rightHeightStr = rhs.split(separator: "-").first,
            let rightHeight = BlockHeight(rightHeightStr)
        else { return nil }

        return leftHeight - rightHeight
    }

    static let filenameDescription: (ZcashCompactBlock) -> String = { block in
        [
            "\(block.height)",
            block.meta.hash.toHexStringTxId(),
            "compactblock"
        ]
            .joined(separator: "-")
    }

    static let filenameToHeight: (String) -> BlockHeight? = { block in
        block.split(separator: "-")
            .first
            .flatMap { BlockHeight(String($0)) }
    }
}

extension FSCompactBlockRepository {
    /// Filters block files from a sorted list of filenames from the FsCache directory
    /// with the goal of rewinding up to height `toHeight` and parsing the filenames
    /// with the given `blockDescriptor`
    /// - note: it is assumed that the `sortedList` is ascending.
    /// - Parameter sortedList: ascending list of block filenames
    /// - Parameter toHeight:
    static func filterBlockFiles(
        from sortedList: [URL],
        toRewind toHeight: BlockHeight,
        with blockDescriptor: ZcashCompactBlockDescriptor
    ) throws -> [URL]? {
        // Reverse the cached contents to browse from higher to lower heights
        let sortedCachedContents = sortedList.reversed()

        // pick the blocks that are higher than the rewind height
        // then return their URLs
        let deleteList = try sortedCachedContents.filter({ url in
            guard let filename = try url.resourceValues(forKeys: [.nameKey]).name else {
                throw ZcashError.blockRepositoryGetFilename(url)
            }

            return try filename.filterGreaterThan(toHeight, with: blockDescriptor)
        })

        guard !deleteList.isEmpty else { return nil }

        return deleteList
    }

    func urlForBlock(_ block: ZcashCompactBlock) -> URL {
        self.blocksDirectory.appendingPathComponent(
            self.blockDescriptor.describe(block)
        )
    }

    func blockExistsInCache(_ block: ZcashCompactBlock) -> Bool {
        self.fileManager.fileExists(
            atPath: urlForBlock(block).path
        )
    }

    func filesWithHeight(upTo height: BlockHeight) throws -> [URL] {
        let sortedCachedContents = try contentProvider.listContents(of: blocksDirectory)

        return try sortedCachedContents.filter { url in
            guard let filename = try url.resourceValues(forKeys: [.nameKey]).name else { throw ZcashError.blockRepositoryGetFilename(url) }
            return try filename.filterLowerThanOrEqual(height, with: blockDescriptor)
        }
    }
}
// MARK: Associated and Helper types

struct FSBlockFileWriter {
    let writeToURL: (Data, URL) throws -> Void
}

extension FSBlockFileWriter {
    static let atomic = FSBlockFileWriter(writeToURL: { data, url in
        try data.write(to: url, options: .atomic)
    })
}

struct FSMetadataStore {
    let saveBlocksMeta: ([ZcashCompactBlock]) async throws -> Void
    let rewindToHeight: (BlockHeight) async throws -> Void
    let initFsBlockDbRoot: () async throws -> Void
    let latestHeight: () async throws -> BlockHeight
    let reopenBlockDb: () async throws -> Void
}

extension FSMetadataStore {
    static func live(fsBlockDbRoot: URL, rustBackend: ZcashRustBackendWelding, logger: Logger) -> FSMetadataStore {
        FSMetadataStore { blocks in
            try await FSMetadataStore.saveBlocksMeta(
                blocks,
                fsBlockDbRoot: fsBlockDbRoot,
                rustBackend: rustBackend,
                logger: logger
            )
        } rewindToHeight: { height in
            try await rustBackend.rewindCacheToHeight(height: Int32(height))
        } initFsBlockDbRoot: {
            try await rustBackend.initBlockMetadataDb()
        } latestHeight: {
            try await rustBackend.latestCachedBlockHeight()
        } reopenBlockDb: {
            try await rustBackend.reopenBlockDb()
        }
    }
}

extension FSMetadataStore {
    /// saves blocks to the FsBlockDb metadata database.
    /// - Parameter blocks: Array of `ZcashCompactBlock` to save
    /// - Throws: `CompactBlockRepositoryError.failedToWriteMetadata` if the
    /// operation fails. the underlying error is logged through `LoggerProxy`
    /// - Note: This shouldn't be called in parallel by many threads or workers. Won't do anything if `blocks` is empty
    static func saveBlocksMeta(
        _ blocks: [ZcashCompactBlock],
        fsBlockDbRoot: URL,
        rustBackend: ZcashRustBackendWelding,
        logger: Logger
    ) async throws {
        guard !blocks.isEmpty else { return }

        do {
            try await rustBackend.writeBlocksMetadata(blocks: blocks)
        } catch {
            logger.error("Failed to write metadata with error: \(error)")
            throw error
        }
    }
}

struct ZcashCompactBlockDescriptor {
    let height: (String) -> BlockHeight?
    let describe: (ZcashCompactBlock) -> String
    let compare: (String, String) -> Int?
}

extension ZcashCompactBlockDescriptor {
    /// describes the block following this convention: `HEIGHT-BLOCKHASHHEX-compactblock`
    static let live = ZcashCompactBlockDescriptor(
        height: FSCompactBlockRepository.filenameToHeight,
        describe: FSCompactBlockRepository.filenameDescription,
        compare: FSCompactBlockRepository.filenameComparison
    )
}

enum DirectoryListingProviders {
    /// returns an ascending list of files from a given directory.
    static let `defaultSorted` = SortedDirectoryContentProvider(
        fileManager: FileManager.default,
        sorting: URL.areInIncreasingOrderByFilename
    )

    /// the default sorting of FileManager
    static let naive = FileManager.default
}

class SortedDirectoryContentProvider: SortedDirectoryListing {
    let fileManager: FileManager
    let sorting: (URL, URL) throws -> Bool

    /// inits the `SortedDirectoryContentProvider`
    /// - Parameter fileManager: an instance of `FileManager`
    /// - Parameter sorting: A predicate that returns `true` if its
    ///   first argument should be ordered before its second argument;
    ///   otherwise, `false`.
    init(fileManager: FileManager, sorting: @escaping (URL, URL) throws -> Bool) {
        self.fileManager = fileManager
        self.sorting = sorting
    }

    /// lists the contents of the given directory on `url` using the
    /// sorting provided by `sorting` property of this provider.
    /// - Parameter url: url to list the contents from. It must be a directory or the call will fail.
    /// - Returns an array with the contained files or an empty one if the directory is empty
    /// - Throws: rethrows any errors from the underlying `FileManager`
    func listContents(of url: URL) throws -> [URL] {
        do {
            return try fileManager.contentsOfDirectory(
                at: url,
                includingPropertiesForKeys: [.nameKey, .isDirectoryKey],
                options: [.skipsHiddenFiles]
            )
            .sorted(by: sorting)
        } catch {
            throw ZcashError.blockRepositoryReadDirectoryContent(url, error)
        }
    }
}

protocol SortedDirectoryListing {
    func listContents(of url: URL) throws -> [URL]
}

// MARK: Extensions
extension URL {
    /// asumes that URLs are from the same directory for efficiency reasons
    static let areInIncreasingOrderByFilename: (URL, URL) throws -> Bool = { lhs, rhs in
        guard let lhsName = try lhs.resourceValues(forKeys: [.nameKey, .isDirectoryKey]).name else {
            throw ZcashError.blockRepositoryGetFilenameAndIsDirectory(lhs)
        }

        guard let rhsName = try rhs.resourceValues(forKeys: [.nameKey, .isDirectoryKey]).name else {
            throw ZcashError.blockRepositoryGetFilenameAndIsDirectory(rhs)
        }

        guard let strcmp = FSCompactBlockRepository.filenameComparison(lhsName, rhsName) else {
            throw ZcashError.blockRepositoryGetFilenameAndIsDirectory(lhs)
        }

        return strcmp < 0
    }
}

extension FileManager: SortedDirectoryListing {
    func listContents(of url: URL) throws -> [URL] {
        do {
            return try contentsOfDirectory(
                at: url,
                includingPropertiesForKeys: [.nameKey, .isDirectoryKey],
                options: .skipsSubdirectoryDescendants
            )
        } catch {
            throw ZcashError.blockRepositoryReadDirectoryContent(url, error)
        }
    }
}

extension String {
    /// a sorting filter to be used on URL or path arrays from `FileManager`.
    /// - Parameter height: the height of the block we want to filter from
    /// - Parameter descriptor: The block descriptor that corresponds to the filename
    /// convention of the FsBlockDb
    /// - Returns if the height from this filename is greater that the one received by parameter
    /// - Throws: `CompactBlockRepositoryError.malformedCacheEntry` if this String
    /// can't be parsed by the given `ZcashCompactBlockDescriptor`
    func filterGreaterThan(_ height: BlockHeight, with descriptor: ZcashCompactBlockDescriptor) throws -> Bool {
        guard let blockHeight = descriptor.height(self) else {
            throw ZcashError.blockRepositoryParseHeightFromFilename(self)
        }

        return blockHeight > height
    }

    func filterLowerThanOrEqual(_ height: BlockHeight, with descriptor: ZcashCompactBlockDescriptor) throws -> Bool {
        guard let blockHeight = descriptor.height(self) else {
            throw ZcashError.blockRepositoryParseHeightFromFilename(self)
        }

        return blockHeight <= height
    }
}
