//
//  EnhanceAction.swift
//
//
//  Created by Michal Fousek on 05.05.2023.
//

import Foundation

final class EnhanceAction {
    var blockEnhancer: BlockEnhancer
    let configProvider: CompactBlockProcessor.ConfigProvider
    let logger: Logger

    init(container: DIContainer, configProvider: CompactBlockProcessor.ConfigProvider) {
        blockEnhancer = container.resolve(BlockEnhancer.self)
        self.configProvider = configProvider
        logger = container.resolve(Logger.self)
    }

    func decideWhatToDoNext(context: ActionContext, lastScannedHeight: BlockHeight) async -> ActionContext {
        guard await context.syncControlData.latestScannedHeight != nil else {
            await context.update(state: .clearCache)
            return context
        }

        let latestBlockHeight = await context.syncControlData.latestBlockHeight
        if lastScannedHeight >= latestBlockHeight {
            await context.update(state: .clearCache)
        } else {
            await context.update(state: .txResubmission)
        }

        return context
    }
}

extension EnhanceAction: Action {
    var removeBlocksCacheWhenFailed: Bool { false }

    func run(with context: ActionContext, didUpdate: @escaping (CompactBlockProcessor.Event) async -> Void) async throws -> ActionContext {
        // Use `BlockEnhancer` to enhance blocks.
        // This action is executed on each downloaded and scanned batch (typically each 100 blocks). But we want to run enhancement each 1000 blocks.

        // if latestScannedHeight >= context.scanRanges.scanRange.upperBound then everything is processed and sync process should continue to end.
        // If latestScannedHeight < context.scanRanges.scanRange.upperBound then set state to `download` because there are blocks to
        // download and scan.

        let config = await configProvider.config
        guard let lastScannedHeight = await context.lastScannedHeight else {
            throw ZcashError.compactBlockProcessorLastScannedHeight
        }

        guard let firstUnenhancedHeight = await context.syncControlData.firstUnenhancedHeight else {
            return await decideWhatToDoNext(context: context, lastScannedHeight: lastScannedHeight)
        }

        let latestBlockHeight = await context.syncControlData.latestBlockHeight
        let lastEnhancedHeight: BlockHeight
        if let lastEnhancedHeightInContext = await context.lastEnhancedHeight {
            lastEnhancedHeight = lastEnhancedHeightInContext
        } else {
            lastEnhancedHeight = -1
        }
        let enhanceRangeStart = max(firstUnenhancedHeight, lastEnhancedHeight + 1)
        let enhanceRangeEnd = min(latestBlockHeight, lastScannedHeight)

        // This may happen:
        // For example whole enhance range is 0...2100 Without this force enhance is done for ranges: 0...1000, 1001...2000. And that's it.
        // Last 100 blocks isn't enhanced.
        //
        // This force makes sure that all the blocks are enhanced even when last enhance happened < 1000 blocks ago.
        let forceEnhance = enhanceRangeEnd == latestBlockHeight && enhanceRangeEnd - enhanceRangeStart <= config.enhanceBatchSize

        if enhanceRangeStart <= enhanceRangeEnd && (forceEnhance || (lastScannedHeight - lastEnhancedHeight >= config.enhanceBatchSize)) {
            let enhanceRange = enhanceRangeStart...enhanceRangeEnd
            let transactions = try await blockEnhancer.enhance(
                at: enhanceRange,
                didEnhance: { progress in
                    if let foundTx = progress.lastFoundTransaction, progress.newlyMined {
                        await didUpdate(.minedTransaction(foundTx))
                    }
                }
            )

            await context.update(lastEnhancedHeight: enhanceRange.upperBound)

            if let transactions {
                await didUpdate(.foundTransactions(transactions, enhanceRange))
            }
        } else {
            logger.sync("Action called but skipped for not enough blocks scanned from the last time.")
        }

        return await decideWhatToDoNext(context: context, lastScannedHeight: lastScannedHeight)
    }

    func stop() async { }
}
