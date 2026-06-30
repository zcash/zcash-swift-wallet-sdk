//
//  SaplingParamsAction.swift
//
//
//  Created by Michal Fousek on 05.05.2023.
//

import Foundation

final class SaplingParamsAction {
    let saplingParametersHandler: SaplingParametersHandler
    let logger: Logger

    init(container: DIContainer) {
        saplingParametersHandler = container.resolve(SaplingParametersHandler.self)
        logger = container.resolve(Logger.self)
    }
}

extension SaplingParamsAction: Action {
    var removeBlocksCacheWhenFailed: Bool { false }

    func run(with context: ActionContext, didUpdate: @escaping (CompactBlockProcessor.Event) async -> Void) async throws -> ActionContext {
        logger.debug("Fetching sapling parameters")
        try await saplingParametersHandler.handleIfNeeded()

        await context.update(state: .updateSubtreeRoots)

        return context
    }

    func stop() async { }
}
