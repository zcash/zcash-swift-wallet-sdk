//
//  AutomaticTxResubmissionGuard.swift
//  ZcashLightClientKit
//
//  Created by Adam Tucker on 2026-05-11.
//

import Foundation

actor AutomaticTxResubmissionGuard {
    private enum Constants {
        static let fileName = "automatic-resubmission-excluded-tx-ids"
    }

    private let fileManager: FileManager
    private let fileURL: URL
    private let logger: Logger

    private var excludedTransactionIds = Set<String>()
    private var hasLoadedFromStorage = false

    init(
        storageURL: URL,
        fileManager: FileManager = .default,
        logger: Logger
    ) {
        self.fileManager = fileManager
        self.fileURL = storageURL.appendingPathComponent(Constants.fileName)
        self.logger = logger
    }

    func excludeFromAutomaticResubmission(_ transactions: [ZcashTransaction.Overview]) {
        loadFromStorageIfNeeded()

        let transactionIds = Set(transactions.map(\.resubmissionGuardId))
        guard !transactionIds.isEmpty else { return }

        excludedTransactionIds.formUnion(transactionIds)
        saveToStorage()
    }

    func filterAutomaticallyResubmittable(
        _ transactions: [ZcashTransaction.Overview]
    ) -> [ZcashTransaction.Overview] {
        loadFromStorageIfNeeded()
        retainExclusionsFor(transactions)

        return transactions.filter { !excludedTransactionIds.contains($0.resubmissionGuardId) }
    }

    private func retainExclusionsFor(_ transactions: [ZcashTransaction.Overview]) {
        let currentCandidateIds = Set(transactions.map(\.resubmissionGuardId))
        let retainedTransactionIds = excludedTransactionIds.intersection(currentCandidateIds)

        guard retainedTransactionIds != excludedTransactionIds else { return }

        excludedTransactionIds = retainedTransactionIds
        saveToStorage()
    }

    private func loadFromStorageIfNeeded() {
        guard !hasLoadedFromStorage else { return }

        defer { hasLoadedFromStorage = true }

        guard fileManager.fileExists(atPath: fileURL.path) else { return }

        do {
            let contents = try String(contentsOf: fileURL, encoding: .utf8)
            excludedTransactionIds = Set(
                contents
                    .components(separatedBy: .newlines)
                    .filter { !$0.isEmpty }
            )
        } catch {
            logger.warn("Failed to load automatic resubmission exclusions: \(error)")
        }
    }

    private func saveToStorage() {
        do {
            try fileManager.createDirectory(
                at: fileURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )

            let contents = excludedTransactionIds.sorted().joined(separator: "\n")
            try contents.write(to: fileURL, atomically: true, encoding: .utf8)
        } catch {
            logger.warn("Failed to store automatic resubmission exclusions: \(error)")
        }
    }
}

private extension ZcashTransaction.Overview {
    var resubmissionGuardId: String {
        rawID.hexEncodedString()
    }
}
