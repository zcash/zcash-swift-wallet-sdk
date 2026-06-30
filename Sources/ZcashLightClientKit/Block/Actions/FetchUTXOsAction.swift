//
//  FetchUTXOsAction.swift
//
//
//  Created by Michal Fousek on 05.05.2023.
//

import Foundation

final class FetchUTXOsAction {
    var utxoFetcher: UTXOFetcher
    let logger: Logger

    init(container: DIContainer) {
        utxoFetcher = container.resolve(UTXOFetcher.self)
        logger = container.resolve(Logger.self)
    }
}

extension FetchUTXOsAction: Action {
    var removeBlocksCacheWhenFailed: Bool { false }

    func run(with context: ActionContext, didUpdate: @escaping (CompactBlockProcessor.Event) async -> Void) async throws -> ActionContext {
        logger.debug("Fetching UTXOs")
        let result = try await utxoFetcher.fetch() { _ in }
        await didUpdate(.storedUTXOs(result))

        await context.update(state: .handleSaplingParams)
        return context
    }

    func stop() async { }
}
