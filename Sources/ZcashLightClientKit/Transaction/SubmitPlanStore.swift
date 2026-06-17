//
//  SubmitPlanStore.swift
//  ZcashLightClientKit
//

import Foundation
import SQLite

/// The stored retry plan for one transaction created through `Broadcaster`.
enum StoredSubmitPlan: Equatable {
    /// Created via `Broadcaster` but never submitted by the caller.
    /// Resubmission must skip it.
    case awaiting
    /// Submitted to these endpoints; resubmission retries through them.
    case ready([LightWalletEndpoint])
    /// The store cannot be read, so whether a plan exists is unknown.
    /// Resubmission must skip the transaction: auto-submitting something the
    /// app may never have released is worse than delaying a retry.
    case storeUnavailable
}

protocol SubmitPlanStoring {
    func markAwaitingSubmission(txIds: [Data]) async
    func recordPlan(txId: Data, endpoints: [LightWalletEndpoint]) async
    /// `nil` means the store was read successfully and has no row — a legacy
    /// transaction unknown to this store. Read failures return
    /// `.storeUnavailable`, never `nil`.
    func plan(for txId: Data) async -> StoredSubmitPlan?
    func allPlannedTransactionIds() async -> [Data]
    func deletePlans(txIds: [Data]) async
    func clear() async
    /// Deletes the backing database file and resets the store so it can start
    /// fresh. Part of `Synchronizer.wipe()`.
    func wipe() async
}

/// SQLite-backed store for per-transaction submit plans.
///
/// Writes are best-effort: I/O failures are logged and swallowed so a
/// persistence problem can never fail a send. Reads fail safe: when the store
/// cannot be opened or read, lookups report `.storeUnavailable` so background
/// resubmission skips the affected transactions instead of falling back to an
/// endpoint the user didn't choose.
actor SubmitPlanStore: SubmitPlanStoring {
    private let databaseURL: URL
    private let logger: Logger

    private var cachedConnection: Connection?
    private var connectionFailed = false

    private let table = Table("tx_submit_plans")
    private let txIdColumn = SQLite.Expression<Blob>("tx_id")
    private let endpointsColumn = SQLite.Expression<String>("endpoints")

    init(databaseURL: URL, logger: Logger) {
        self.databaseURL = databaseURL
        self.logger = logger
    }

    func markAwaitingSubmission(txIds: [Data]) {
        guard let connection = connection() else { return }
        do {
            for txId in txIds {
                let insert = table.insert(
                    or: .ignore,
                    txIdColumn <- Blob(bytes: txId.bytes),
                    endpointsColumn <- "[]"
                )
                try connection.run(insert)
            }
        } catch {
            // The awaiting mark is what keeps background resubmission away
            // from transactions the app never submitted. If it cannot be
            // written, fail the store closed for this session so lookups
            // report `.storeUnavailable` instead of `nil` (legacy) for the
            // unmarked transactions.
            cachedConnection = nil
            connectionFailed = true
            logger.warn("SubmitPlanStore failed to mark transactions awaiting submission; disabling the store: \(error)")
        }
    }

    func recordPlan(txId: Data, endpoints: [LightWalletEndpoint]) {
        guard !endpoints.isEmpty else { return }
        guard let connection = connection() else { return }
        do {
            let storedEndpoints = endpoints.map { StoredEndpoint(endpoint: $0) }
            let encoded = try JSONEncoder().encode(storedEndpoints)
            let json = String(data: encoded, encoding: .utf8) ?? "[]"
            let upsert = table.insert(
                or: .replace,
                txIdColumn <- Blob(bytes: txId.bytes),
                endpointsColumn <- json
            )
            try connection.run(upsert)
        } catch {
            logger.warn("SubmitPlanStore failed to record submit plan: \(error)")
        }
    }

    func plan(for txId: Data) -> StoredSubmitPlan? {
        guard let connection = connection() else { return .storeUnavailable }
        do {
            let query = table.filter(txIdColumn == Blob(bytes: txId.bytes))
            guard let row = try connection.pluck(query) else { return nil }

            let json = row[endpointsColumn]
            guard
                let data = json.data(using: .utf8),
                let storedEndpoints = try? JSONDecoder().decode([StoredEndpoint].self, from: data)
            else {
                // Never silently fall back to an endpoint the user didn't choose:
                // an undecodable plan behaves as awaiting until pruning removes it.
                logger.warn("SubmitPlanStore found undecodable endpoints for a plan; treating it as awaiting.")
                return .awaiting
            }

            return storedEndpoints.isEmpty ? .awaiting : .ready(storedEndpoints.map(\.endpoint))
        } catch {
            logger.warn("SubmitPlanStore failed to load submit plan: \(error)")
            return .storeUnavailable
        }
    }

    func allPlannedTransactionIds() -> [Data] {
        guard let connection = connection() else { return [] }
        do {
            return try connection.prepare(table.select(txIdColumn)).map { row in
                Data(row[txIdColumn].bytes)
            }
        } catch {
            logger.warn("SubmitPlanStore failed to list submit plans: \(error)")
            return []
        }
    }

    func deletePlans(txIds: [Data]) {
        guard !txIds.isEmpty else { return }
        guard let connection = connection() else { return }
        do {
            for txId in txIds {
                try connection.run(table.filter(txIdColumn == Blob(bytes: txId.bytes)).delete())
            }
        } catch {
            logger.warn("SubmitPlanStore failed to delete submit plans: \(error)")
        }
    }

    func clear() {
        guard let connection = connection() else { return }
        do {
            try connection.run(table.delete())
        } catch {
            logger.warn("SubmitPlanStore failed to clear submit plans: \(error)")
        }
    }

    func wipe() {
        // Drop the connection first so the file handle is closed, then remove
        // the file itself: row deletion alone would leave transaction ids and
        // endpoints recoverable from SQLite free pages after a wallet wipe.
        cachedConnection = nil
        connectionFailed = false
        guard FileManager.default.fileExists(atPath: databaseURL.path) else { return }
        do {
            try FileManager.default.removeItem(at: databaseURL)
        } catch {
            logger.warn("SubmitPlanStore failed to delete its database file: \(error)")
        }
    }

    private static let schemaVersion: Int64 = 1

    private func connection() -> Connection? {
        if let cachedConnection { return cachedConnection }
        guard !connectionFailed else { return nil }

        do {
            let directoryURL = databaseURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)

            var resourceValues = URLResourceValues()
            resourceValues.isExcludedFromBackup = true
            var mutableDirectoryURL = directoryURL
            try mutableDirectoryURL.setResourceValues(resourceValues)

            let connection = try Connection(databaseURL.path)

            let schemaVersion = try connection.scalar("PRAGMA user_version") as? Int64 ?? 0
            guard schemaVersion <= Self.schemaVersion else {
                // Written by a newer SDK; don't touch it (a downgraded SDK
                // misreading rows could resurrect the legacy fallback).
                connectionFailed = true
                logger.warn(
                    "SubmitPlanStore database schema \(schemaVersion) is newer than the supported \(Self.schemaVersion); submit plans are disabled."
                )
                return nil
            }

            try connection.run(table.create(ifNotExists: true) { builder in
                builder.column(txIdColumn, primaryKey: true)
                builder.column(endpointsColumn, defaultValue: "[]")
            })
            if schemaVersion < Self.schemaVersion {
                try connection.run("PRAGMA user_version = \(Self.schemaVersion)")
            }

            cachedConnection = connection
            return connection
        } catch {
            connectionFailed = true
            logger.warn("SubmitPlanStore could not open its database; submit plans are disabled: \(error)")
            return nil
        }
    }
}

/// Codable persistence shape for one endpoint.
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
