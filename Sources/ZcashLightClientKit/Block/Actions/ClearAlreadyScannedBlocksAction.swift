//
//  ClearCacheForLastScannedBatch.swift
//
//
//  Created by Michal Fousek on 08.05.2023.
//

import Foundation

final class ClearAlreadyScannedBlocksAction {
    let storage: CompactBlockRepository
    let transactionRepository: TransactionRepository

    init(container: DIContainer) {
        storage = container.resolve(CompactBlockRepository.self)
        transactionRepository = container.resolve(TransactionRepository.self)
    }
}

extension ClearAlreadyScannedBlocksAction: Action {
    var removeBlocksCacheWhenFailed: Bool { false }

    func run(with context: ActionContext, didUpdate: @escaping (CompactBlockProcessor.Event) async -> Void) async throws -> ActionContext {
        guard let lastScannedHeight = await context.lastScannedHeight else {
            throw ZcashError.compactBlockProcessorLastScannedHeight
        }

        try await storage.clear(upTo: lastScannedHeight)

        await context.update(state: .enhance)
        return context
    }

    func stop() async { }
}
