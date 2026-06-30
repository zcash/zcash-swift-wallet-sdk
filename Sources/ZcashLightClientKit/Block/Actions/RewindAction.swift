//
//  RewindAction.swift
//
//
//  Created by Lukáš Korba on 09.08.2023.
//

import Foundation

final class RewindAction {
    var downloader: BlockDownloader
    let rustBackend: ZcashRustBackendWelding
    var downloaderService: BlockDownloaderService
    let logger: Logger

    init(container: DIContainer) {
        downloader = container.resolve(BlockDownloader.self)
        rustBackend = container.resolve(ZcashRustBackendWelding.self)
        downloaderService = container.resolve(BlockDownloaderService.self)
        logger = container.resolve(Logger.self)
    }

    private func update(context: ActionContext) async -> ActionContext {
        await context.update(state: .processSuggestedScanRanges)
        return context
    }
}

extension RewindAction: Action {
    var removeBlocksCacheWhenFailed: Bool { false }

    func run(with context: ActionContext, didUpdate: @escaping (CompactBlockProcessor.Event) async -> Void) async throws -> ActionContext {
        guard let requestedRewindHeight = await context.requestedRewindHeight else {
            return await update(context: context)
        }
        var rewindHeight = BlockHeight(requestedRewindHeight)

        logger.debug("Executing rewind.")
        let rewindResult = try await rustBackend.rewindToHeight(height: rewindHeight)
        switch rewindResult {
        case let .success(height):
            rewindHeight = height
        case let .requestedHeightTooLow(safeHeight):
            let retryResult = try await rustBackend.rewindToHeight(height: safeHeight)
            switch retryResult {
            case let .success(height):
                rewindHeight = height
            default:
                throw ZcashError.rustRewindToHeight(Int32(safeHeight), lastErrorMessage(fallback: "`rewindToHeight` unable to rewind"))
            }
        }

        await downloader.rewind(latestDownloadedBlockHeight: rewindHeight)

        // clear cache
        try await downloaderService.rewind(to: rewindHeight)

        return await update(context: context)
    }

    func stop() async { }
}
