//
//  UpdateSubtreeRootsAction.swift
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

            // Ironwood (NU6.3) is Orchard note-version V3 and rides a separate subtree-root stream.
            // It is dormant until a lightwalletd serves it: a server that does not support the Ironwood
            // shielded protocol will error or return nothing here, which must NOT break sync. So the
            // fetch is best-effort — a failed/empty Ironwood fetch is logged and skipped. A genuine
            // store failure on roots we did receive is still surfaced.
            logger.debug("Fetching Ironwood subtree roots (best-effort; Ironwood is dormant pre-NU6.3)")

            var ironwoodRequest = GetSubtreeRootsArg()
            ironwoodRequest.shieldedProtocol = .ironwood

            var ironwoodRoots: [SubtreeRoot] = []
            do {
                let ironwoodStream = try service.getSubtreeRoots(ironwoodRequest, mode: .direct)
                for try await subtreeRoot in ironwoodStream {
                    ironwoodRoots.append(subtreeRoot)
                }
            } catch ZcashError.serviceSubtreeRootsStreamFailed(LightWalletServiceError.timeOut) {
                // A stream timeout is a transport problem, not an "Ironwood not
                // supported" signal: rethrow it into the retry machinery like the
                // Sapling/Orchard streams do, so a server that black-holes this
                // stream doesn't silently add the full streaming deadline to
                // every sync pass. Genuine "unsupported protocol" errors still
                // fall through to the best-effort skip below.
                throw ZcashError.serviceSubtreeRootsStreamFailed(LightWalletServiceError.timeOut)
            } catch {
                logger.debug("Ironwood subtree roots unavailable (\(error.localizedDescription)); skipping")
                ironwoodRoots = []
            }

            if !ironwoodRoots.isEmpty {
                logger.debug("Ironwood tree has \(ironwoodRoots.count) subtrees")
                do {
                    try await rustBackend.putIronwoodSubtreeRoots(startIndex: UInt64(ironwoodRequest.startIndex), roots: ironwoodRoots)

                    await context.update(state: .updateChainTip)
                } catch {
                    logger.debug("putIronwoodSubtreeRoots failed with error \(error.localizedDescription)")
                    throw ZcashError.compactBlockProcessorPutIronwoodSubtreeRoots(error)
                }
            }
        }

        return context
    }

    func stop() async { }
}
