//
//  ClearCacheAction.swift
//
//
//  Created by Michal Fousek on 05.05.2023.
//

import Foundation

final class ClearCacheAction {
    let storage: CompactBlockRepository

    init(container: DIContainer) {
        storage = container.resolve(CompactBlockRepository.self)
    }
}

extension ClearCacheAction: Action {
    var removeBlocksCacheWhenFailed: Bool { false }

    func run(with context: ActionContext, didUpdate: @escaping (CompactBlockProcessor.Event) async -> Void) async throws -> ActionContext {
        try await storage.clear()

        await context.update(state: .processSuggestedScanRanges)

        return context
    }

    func stop() async { }
}
