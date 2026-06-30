//
//  Updatesubtreerootsaction.swift
//
//
//  Created by Lukas Korba on 01.08.2023.
//

import Foundation

final class UpdateSubtreeRootsAction {
    let configProvider: CompactBlockProcessor.ConfigProvider
    let rustBackend: ZcashRustBackendWelding
    var service: LightWalletService
    let logger: Logger

    init(container: DIContainer, configProvider: CompactBlockProcessor.ConfigProvider) {
        self.configProvider = configProvider
        service = container.resolve(LightWalletService.self)
        rustBackend = container.resolve(ZcashRustBackendWelding.self)
        logger = container.resolve(Logger.self)
    }
}

extension UpdateSubtreeRootsAction: Action {
    var removeBlocksCacheWhenFailed: Bool { false }

    func run(with context: ActionContext, didUpdate: @escaping (CompactBlockProcessor.Event) async -> Void) async throws -> ActionContext {
        var request = GetSubtreeRootsArg()
        request.shieldedProtocol = .sapling

        logger.debug("Attempt to get subtree roots, this may fail because lightwalletd may not support Spend before Sync.")
        // ServiceMode to resolve
        let stream = try service.getSubtreeRoots(request, mode: .direct)

        var saplingRoots: [SubtreeRoot] = []

        do {
            for try await subtreeRoot in stream {
                saplingRoots.append(subtreeRoot)
            }
        } catch ZcashError.serviceSubtreeRootsStreamFailed(LightWalletServiceError.timeOut) {
            throw ZcashError.serviceSubtreeRootsStreamFailed(LightWalletServiceError.timeOut)
        } catch {
            await context.update(state: .updateChainTip)
        }

        logger.debug("Sapling tree has \(saplingRoots.count) subtrees")
        do {
            try await rustBackend.putSaplingSubtreeRoots(startIndex: UInt64(request.startIndex), roots: saplingRoots)

            await context.update(state: .updateChainTip)
        } catch {
            logger.debug("putSaplingSubtreeRoots failed with error \(error.localizedDescription)")
            throw ZcashError.compactBlockProcessorPutSaplingSubtreeRoots(error)
        }

        if !saplingRoots.isEmpty {
            logger.debug("Found Sapling subtree roots, SbS supported, fetching Orchard subtree roots")

            var orchardRequest = GetSubtreeRootsArg()
            orchardRequest.shieldedProtocol = .orchard

            // ServiceMode to resolve
            let stream = try service.getSubtreeRoots(orchardRequest, mode: .direct)

            var orchardRoots: [SubtreeRoot] = []

            do {
                for try await subtreeRoot in stream {
                    orchardRoots.append(subtreeRoot)
                }
            } catch ZcashError.serviceSubtreeRootsStreamFailed(LightWalletServiceError.timeOut) {
                throw ZcashError.serviceSubtreeRootsStreamFailed(LightWalletServiceError.timeOut)
            }

            logger.debug("Orchard tree has \(orchardRoots.count) subtrees")
            do {
                try await rustBackend.putOrchardSubtreeRoots(startIndex: UInt64(orchardRequest.startIndex), roots: orchardRoots)

                await context.update(state: .updateChainTip)
            } catch {
                logger.debug("putOrchardSubtreeRoots failed with error \(error.localizedDescription)")
                throw ZcashError.compactBlockProcessorPutOrchardSubtreeRoots(error)
            }
        }

        return context
    }

    func stop() async { }
}
