//
//  SaplingParametersHandler.swift
//
//
//  Created by Lukáš Korba on 23.11.2022.
//

import Foundation

struct SaplingParametersHandlerConfig {
    let outputParamsURL: URL
    let spendParamsURL: URL
    let saplingParamsSourceURL: SaplingParamsSourceURL
}

protocol SaplingParametersHandler {
    func handleIfNeeded() async throws
}

struct SaplingParametersHandlerImpl {
    let config: SaplingParametersHandlerConfig
    let rustBackend: ZcashRustBackendWelding
    let logger: Logger
}

extension SaplingParametersHandlerImpl: SaplingParametersHandler {
    func handleIfNeeded() async throws {
        try Task.checkCancellation()

        do {
            let accounts = try await rustBackend.listAccounts()

            var totalSaplingBalanceTrigger = false
            var totalTransparentBalanceTrigger = false
            let accountBalances = try await rustBackend.getWalletSummary()?.accountBalances

            for account in accounts {
                let totalSaplingBalance = accountBalances?[account.id]?.saplingBalance.total().amount ?? 0

                if totalSaplingBalance > 0 {
                    totalSaplingBalanceTrigger = true
                    break
                }

                let totalTransparentBalance = try await rustBackend.getTransparentBalance(accountUUID: account.id)

                if totalTransparentBalance > 0 {
                    totalTransparentBalanceTrigger = true
                    break
                }
            }

            // Download Sapling parameters only if sapling funds are detected.
            guard totalSaplingBalanceTrigger || totalTransparentBalanceTrigger else { return }
        } catch {
            // if sapling balance can't be detected of we fail to obtain the balance
            // for some reason we shall not proceed to download the parameters and
            // retry in the following attempt to sync.
            logger.error("Couldn't Fetch shielded balance. Won't attempt to download sapling parameters")
            return
        }

        try await SaplingParameterDownloader.downloadParamsIfnotPresent(
            retryEnabled: true,
            spendURL: config.spendParamsURL,
            spendSourceURL: config.saplingParamsSourceURL.spendParamFileURL,
            outputURL: config.outputParamsURL,
            outputSourceURL: config.saplingParamsSourceURL.outputParamFileURL,
            logger: logger
        )
    }
}
