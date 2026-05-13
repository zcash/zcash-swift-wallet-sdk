//
//  PendingSubmitPlanStore.swift
//  ZcashLightClientKit
//
//  Created by Adam Tucker on 2026-05-12.
//

import Foundation
import Security

protocol PendingSubmitPlanPersistence {
    func load() throws -> Data?
    func save(_ data: Data) throws
    func clear() throws
}

struct TransactionSubmitPlan {
    let endpoints: [LightWalletEndpoint]

    init(endpoints: [LightWalletEndpoint]) {
        precondition(!endpoints.isEmpty, "Transaction submit plan must include at least one endpoint.")
        self.endpoints = endpoints
    }
}

actor PendingSubmitPlanStore {
    enum StoredSubmitPlan {
        case awaitingPlan
        case ready(TransactionSubmitPlan)
    }

    private let persistence: PendingSubmitPlanPersistence?
    private let logger: Logger

    private var plansByTransactionId: [String: [StoredEndpoint]] = [:]
    // In-memory cache only. After restart, raw transaction submissions recover
    // the transaction id through RawTransactionLookup before recording endpoints.
    private var transactionIdsByRawTransaction: [String: String] = [:]
    private var loadedFromPersistence = false

    init(
        persistence: PendingSubmitPlanPersistence? = nil,
        logger: Logger
    ) {
        self.persistence = persistence
        self.logger = logger
    }

    func markAwaitingSubmitPlan(_ transactions: [ZcashTransaction.Overview]) {
        loadFromPersistenceIfNeeded()

        var changed = false
        for transaction in transactions {
            let transactionId = transaction.rawID.stablePlanKey
            if let raw = transaction.raw {
                transactionIdsByRawTransaction[raw.stablePlanKey] = transactionId
            }
            if plansByTransactionId[transactionId] == nil {
                plansByTransactionId[transactionId] = []
                changed = true
            }
        }

        if changed {
            saveToPersistence()
        }
    }

    func addSubmitEndpoint(
        rawTransaction: Data,
        endpoint: LightWalletEndpoint
    ) {
        loadFromPersistenceIfNeeded()

        guard let transactionId = transactionIdsByRawTransaction[rawTransaction.stablePlanKey] else {
            return
        }

        addSubmitEndpoint(transactionId: transactionId, endpoint: endpoint)
    }

    func addSubmitEndpoint(
        transaction: ZcashTransaction.Overview,
        endpoint: LightWalletEndpoint
    ) {
        loadFromPersistenceIfNeeded()
        if let raw = transaction.raw {
            transactionIdsByRawTransaction[raw.stablePlanKey] = transaction.rawID.stablePlanKey
        }
        addSubmitEndpoint(transactionId: transaction.rawID.stablePlanKey, endpoint: endpoint)
    }

    func getSubmitPlan(for transactionId: Data) -> StoredSubmitPlan? {
        loadFromPersistenceIfNeeded()

        switch plansByTransactionId[transactionId.stablePlanKey] {
        case nil:
            return nil
        case let endpoints? where endpoints.isEmpty:
            return .awaitingPlan
        case let endpoints?:
            return .ready(TransactionSubmitPlan(endpoints: endpoints.map(\.endpoint)))
        }
    }

    func retainPlans(for transactionIds: [Data]) {
        loadFromPersistenceIfNeeded()

        let retainedTransactionIds = Set(transactionIds.map(\.stablePlanKey))
        let previousPlanCount = plansByTransactionId.count
        plansByTransactionId = plansByTransactionId.filter { retainedTransactionIds.contains($0.key) }
        transactionIdsByRawTransaction = transactionIdsByRawTransaction.filter { retainedTransactionIds.contains($0.value) }

        if plansByTransactionId.count != previousPlanCount {
            saveToPersistence()
        }
    }

    func clear() {
        plansByTransactionId.removeAll()
        transactionIdsByRawTransaction.removeAll()
        do {
            try persistence?.clear()
        } catch {
            logger.warn("Failed to clear pending submit plans: \(error)")
        }
    }

    private func addSubmitEndpoint(
        transactionId: String,
        endpoint: LightWalletEndpoint
    ) {
        let storedEndpoint = StoredEndpoint(endpoint: endpoint)
        var endpoints = plansByTransactionId[transactionId] ?? []
        guard !endpoints.contains(storedEndpoint) else { return }

        endpoints.append(storedEndpoint)
        plansByTransactionId[transactionId] = endpoints
        saveToPersistence()
    }

    private func loadFromPersistenceIfNeeded() {
        guard !loadedFromPersistence else { return }
        defer { loadedFromPersistence = true }

        do {
            guard
                let data = try persistence?.load(),
                !data.isEmpty
            else {
                return
            }

            let storedPlans = try JSONDecoder().decode(StoredPlans.self, from: data)
            guard storedPlans.version == StoredPlans.currentVersion else {
                throw PendingSubmitPlanStoreError.unsupportedVersion(storedPlans.version)
            }
            plansByTransactionId = storedPlans.plansByTransactionId
        } catch {
            logger.warn("Failed to load pending submit plans: \(error)")
        }
    }

    private func saveToPersistence() {
        do {
            let storedPlans = StoredPlans(plansByTransactionId: plansByTransactionId)
            let data = try JSONEncoder().encode(storedPlans)
            try persistence?.save(data)
        } catch {
            logger.warn("Failed to store pending submit plans: \(error)")
        }
    }
}

private struct StoredPlans: Codable {
    let version: Int
    let plansByTransactionId: [String: [StoredEndpoint]]

    static let currentVersion = 1

    init(
        version: Int = Self.currentVersion,
        plansByTransactionId: [String: [StoredEndpoint]]
    ) {
        self.version = version
        self.plansByTransactionId = plansByTransactionId
    }
}

private enum PendingSubmitPlanStoreError: Error {
    case unsupportedVersion(Int)
}

private struct StoredEndpoint: Codable, Equatable {
    let host: String
    let port: Int
    let secure: Bool
    let singleCallTimeoutInMillis: Int64
    let streamingCallTimeoutInMillis: Int64

    init(endpoint: LightWalletEndpoint) {
        host = endpoint.host
        port = endpoint.port
        secure = endpoint.secure
        singleCallTimeoutInMillis = endpoint.singleCallTimeoutInMillis
        streamingCallTimeoutInMillis = endpoint.streamingCallTimeoutInMillis
    }

    var endpoint: LightWalletEndpoint {
        LightWalletEndpoint(
            address: host,
            port: port,
            secure: secure,
            singleCallTimeoutInMillis: singleCallTimeoutInMillis,
            streamingCallTimeoutInMillis: streamingCallTimeoutInMillis
        )
    }
}

private extension Data {
    var stablePlanKey: String { hexEncodedString() }
}

struct KeychainSubmitPlanPersistence: PendingSubmitPlanPersistence {
    private enum Constants {
        static let service = "cash.z.ecc.ZcashLightClientKit.pending-submit-plans"
    }

    private let account: String

    init(
        alias: ZcashSynchronizerAlias,
        networkType: NetworkType
    ) {
        self.account = "\(networkType.networkId)_\(alias.description)"
    }

    func load() throws -> Data? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        switch status {
        case errSecSuccess:
            return item as? Data
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainSubmitPlanPersistenceError.unhandledStatus(status)
        }
    }

    func save(_ data: Data) throws {
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]

        let updateStatus = SecItemUpdate(baseQuery as CFDictionary, attributes as CFDictionary)
        switch updateStatus {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            var addQuery = baseQuery
            attributes.forEach { addQuery[$0.key] = $0.value }
            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw KeychainSubmitPlanPersistenceError.unhandledStatus(addStatus)
            }
        default:
            throw KeychainSubmitPlanPersistenceError.unhandledStatus(updateStatus)
        }
    }

    func clear() throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainSubmitPlanPersistenceError.unhandledStatus(status)
        }
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Constants.service,
            kSecAttrAccount as String: account
        ]
    }
}

private enum KeychainSubmitPlanPersistenceError: Error {
    case unhandledStatus(OSStatus)
}
