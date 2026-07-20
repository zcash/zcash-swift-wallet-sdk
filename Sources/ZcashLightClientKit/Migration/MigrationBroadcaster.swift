//
//  MigrationBroadcaster.swift
//  ZcashLightClientKit
//

import Foundation

/// The raw outcome of a single broadcast attempt, before it is mapped to a public
/// ``MigrationTransferResult``. Kept separate so the mapping can be a pure, table-tested function.
enum MigrationBroadcastOutcome: Equatable {
    /// The submit RPC completed and the server accepted the transaction (`errorCode == 0`).
    case submitted
    /// The submit RPC completed but the server rejected the transaction (`errorCode != 0`).
    /// `errorCode` is the zcashd `sendrawtransaction` code lightwalletd forwards; the mapping uses
    /// it (with the message) to tell duplicate re-submissions from real rejections.
    case rejected(errorCode: Int32, message: String)
    /// A transport-level error was thrown *after* the connection was established (a mid-submit
    /// stream failure), as opposed to a failure to connect at all.
    case transportError
}

/// The broadcast entry point `OrchardMigration` depends on.
///
/// Exists so tests can substitute a fake transport for ``MigrationBroadcaster``'s real network I/O
/// without changing how `OrchardMigration` is composed. `MigrationBroadcaster` is the only production
/// conformer.
protocol MigrationBroadcasting {
    /// Submits `rawTransaction` to `endpoint` exactly once. See
    /// ``MigrationBroadcaster/broadcast(rawTransaction:to:useTor:)`` for the full contract (fail-closed
    /// Tor, throw-vs-return split).
    func broadcast(
        rawTransaction: Data,
        to endpoint: LightWalletEndpoint,
        useTor: Bool
    ) async throws -> MigrationBroadcastOutcome
}

/// Broadcasts one migration transaction to one endpoint, and nothing more.
///
/// This type is deliberately minimal: it does not fetch transactions, retry, race multiple
/// endpoints, or fall back between transports. Its one job is a single submit attempt, with two
/// transports:
///
/// - **Tor (`useTor == true`)** is *fail-closed*. It uses its own dedicated ``TorClient`` in its own
///   on-disk directory (independent of the app's main Tor toggle and the synchronizer's Tor client),
///   built lazily and cached as a single bootstrap `Task` shared by every concurrent caller (see
///   `dedicatedTorClient()`). If that runtime cannot be created/bootstrapped, or the isolated
///   connection cannot be opened *before* the submit RPC is attempted, it throws
///   ``ZcashError/migrationTorUnavailable`` and broadcasts nothing — it never falls back to a direct
///   connection. (This is a deliberate divergence from the Android SDK, which silently falls back.)
/// - **Direct (`useTor == false`)** opens a fresh, ephemeral gRPC service for exactly the resolved
///   endpoint, submits once, and closes it.
///
/// Once the connection is established, a thrown error from the submit RPC is reported as
/// ``MigrationBroadcastOutcome/transportError`` (a retryable network error), not as a fail-closed
/// Tor failure.
actor MigrationBroadcaster: MigrationBroadcasting {
    private let torDirURL: URL
    private let logger: Logger
    private let torClientFactory: @Sendable (URL) async throws -> TorClient

    /// The dedicated Tor client's bootstrap, cached as a `Task` on the first `useTor` broadcast so
    /// concurrent broadcasts await the exact SAME bootstrap attempt rather than each racing its own
    /// ``TorClient`` construction against the shared `migration_tor` directory (finding 8). `nil`
    /// before the first attempt, and again after a failed attempt clears it (see
    /// ``dedicatedTorClient()``) so the next broadcast retries with a fresh bootstrap instead of
    /// replaying the same cached failure forever.
    private var torClientTask: Task<TorClient, Error>?

    /// Creates a broadcaster.
    ///
    /// - Parameters:
    ///   - torDirURL: the main Tor directory; the dedicated migration Tor client is provisioned in
    ///     its `migration_tor` subdirectory.
    ///   - logger: injected logger.
    ///
    /// - Note: The `migration_tor` subdirectory is deliberately shared across every account's
    ///   ``OrchardMigration``/``MigrationBroadcaster`` in the process, not provisioned per account:
    ///   its contents are account-independent Arti state (circuits, guards, cached consensus
    ///   documents), so sharing the directory is safe. ``torClientTask`` additionally removes the
    ///   duplicate-bootstrap race within a single broadcaster: concurrent `useTor` broadcasts on one
    ///   instance bootstrap the shared directory at most once (see ``dedicatedTorClient()``).
    init(torDirURL: URL, logger: Logger) {
        self.init(torDirURL: torDirURL, logger: logger, torClientFactory: MigrationBroadcaster.bootstrapTorClient)
    }

    /// Injecting initializer for tests: substitutes the Tor-client factory ``dedicatedTorClient()``
    /// caches, so the bootstrap single-flight/clear-on-failure behavior can be pinned deterministically
    /// without a real Arti runtime. Production always goes through the default
    /// (``bootstrapTorClient(migrationTorDir:)``) via ``init(torDirURL:logger:)``.
    init(
        torDirURL: URL,
        logger: Logger,
        torClientFactory: @escaping @Sendable (URL) async throws -> TorClient
    ) {
        self.torDirURL = torDirURL
        self.logger = logger
        self.torClientFactory = torClientFactory
    }

    /// The zcashd `sendrawtransaction` RPC error code for a transaction the node already knows
    /// (`RPC_VERIFY_ALREADY_IN_CHAIN` / `RPC_TRANSACTION_ALREADY_IN_CHAIN`, "transaction already in
    /// block chain"). lightwalletd forwards zcashd's submit error codes verbatim, so this code on a
    /// rejection identifies a duplicate re-submission: the transaction landed on a previous attempt.
    static let duplicateSubmissionErrorCode: Int32 = -27

    /// Lowercased message fragments that identify a duplicate re-submission when the server does not
    /// use ``duplicateSubmissionErrorCode``: zcashd's "already in block chain" wording (with and
    /// without the space) and the mempool-acceptance duplicate reject reasons
    /// (`txn-already-in-mempool` / `txn-already-known`, plus the spelled-out mempool variant).
    static let duplicateSubmissionMessageFragments = [
        "already in block chain",
        "already in blockchain",
        "txn-already-in-mempool",
        "already in mempool",
        "txn-already-known"
    ]

    /// Maps a raw broadcast outcome to the public ``MigrationTransferResult``. Pure, so it is
    /// exhaustively table-testable.
    ///
    /// A server rejection is classified in order:
    /// 1. **Duplicate re-submission** — the rejection carries ``duplicateSubmissionErrorCode`` or a
    ///    ``duplicateSubmissionMessageFragments`` match (case-insensitive). The transaction already
    ///    landed on a previous attempt (e.g. a submit whose response was lost to a transport error
    ///    and was retried), so this maps to ``MigrationTransferResult/success(txId:)`` with the
    ///    prepared transfer's txid: the engine records the transfer as delivered and the privacy
    ///    gate marks, instead of parking the run on a bogus failure.
    /// 2. **Expiry** — an expiry-related message maps to ``MigrationTransferResult/expired``.
    /// 3. Anything else maps to ``MigrationTransferResult/invalidNote``. This InvalidNote/Expired
    ///    split is best-effort (the lightwalletd rejection reasons do not cleanly distinguish the
    ///    two); it mirrors the Android SDK's known ambiguity and is kept for parity.
    static func map(outcome: MigrationBroadcastOutcome, successTxId: String) -> MigrationTransferResult {
        switch outcome {
        case .submitted:
            return MigrationTransferResult.success(txId: successTxId)
        case .transportError:
            return MigrationTransferResult.networkError(retryable: true)
        case .rejected(let errorCode, let message):
            let lowered = message.lowercased()
            if errorCode == Self.duplicateSubmissionErrorCode
                || Self.duplicateSubmissionMessageFragments.contains(where: { lowered.contains($0) }) {
                return MigrationTransferResult.success(txId: successTxId)
            }
            if lowered.contains("expired") || lowered.contains("tx-expiring-soon") {
                return MigrationTransferResult.expired
            }
            return MigrationTransferResult.invalidNote
        }
    }

    /// Submits `rawTransaction` to `endpoint` exactly once.
    ///
    /// - Throws: ``ZcashError/migrationTorUnavailable`` when `useTor` is `true` and the dedicated Tor
    ///   runtime or connection cannot be established before the submit RPC is attempted. In that case
    ///   nothing is broadcast and the caller must record no result.
    /// - Returns: the raw outcome (submitted / rejected / transport error) for the caller to map.
    func broadcast(
        rawTransaction: Data,
        to endpoint: LightWalletEndpoint,
        useTor: Bool
    ) async throws -> MigrationBroadcastOutcome {
        if useTor {
            return try await broadcastOverTor(rawTransaction: rawTransaction, to: endpoint)
        } else {
            return await broadcastDirect(rawTransaction: rawTransaction, to: endpoint)
        }
    }

    /// Resolves the dedicated migration Tor client: bootstraps it on the first call, and reuses the
    /// same cached ``Task`` for every subsequent call -- including calls that arrive concurrently
    /// with an in-flight bootstrap, which await that SAME task instead of starting a second one.
    ///
    /// Fail-closed per call, recoverable across calls: when the cached task fails, THIS call (the one
    /// that created the cache entry) clears it before rethrowing -- see the inline comment for why
    /// only the creator is responsible for the clear. Every caller of that same failing attempt still
    /// observes the failure (they all await the same task), but a broadcast call that arrives after
    /// this one has returned retries with a fresh bootstrap rather than replaying the same cached
    /// failure forever.
    ///
    /// Not `private`: exercised directly by tests pinning the caching behavior (finding 8) without
    /// driving a real Tor connection through the full ``broadcast(rawTransaction:to:useTor:)``.
    func dedicatedTorClient() async throws -> TorClient {
        let migrationTorDir = torDirURL.appendingPathComponent("migration_tor", isDirectory: true)

        if let torClientTask {
            return try await torClientTask.value
        }

        let factory = torClientFactory
        let task = Task {
            try await factory(migrationTorDir)
        }
        torClientTask = task

        do {
            return try await task.value
        } catch {
            // This call is the one that created the cache entry (a concurrent joiner above only
            // reads `torClientTask` and returns via its own `try await torClientTask.value`, without
            // ever reaching this catch), so it alone clears it -- no race between this clear and a
            // joiner's read of the now-stale value they already captured.
            torClientTask = nil
            throw error
        }
    }

    // MARK: - Private

    private func broadcastOverTor(
        rawTransaction: Data,
        to endpoint: LightWalletEndpoint
    ) async throws -> MigrationBroadcastOutcome {
        // Fail-closed: any failure to build the runtime or open the isolated connection — i.e. any
        // failure *before* the submit RPC — is reported as Tor-unavailable, and nothing is broadcast.
        let runtime: TorClient
        do {
            runtime = try await dedicatedTorClient()
        } catch {
            logger.error("MigrationBroadcaster: dedicated Tor runtime unavailable: \(error)")
            throw ZcashError.migrationTorUnavailable
        }

        let connection: TorLwdConn
        do {
            let isolated = try await runtime.isolatedClient()
            connection = try await isolated.connectToLightwalletd(endpoint: endpoint.urlString)
        } catch {
            logger.error("MigrationBroadcaster: could not open isolated Tor connection to \(endpoint.host):\(endpoint.port): \(error)")
            throw ZcashError.migrationTorUnavailable
        }

        // The connection is established; a thrown error here is a mid-submit transport failure.
        do {
            let response = try connection.submit(spendTransaction: rawTransaction)
            return outcome(from: response)
        } catch {
            logger.error("MigrationBroadcaster: Tor submit transport failure: \(error)")
            return MigrationBroadcastOutcome.transportError
        }
    }

    private func broadcastDirect(
        rawTransaction: Data,
        to endpoint: LightWalletEndpoint
    ) async -> MigrationBroadcastOutcome {
        // A fresh, ephemeral gRPC service for exactly this endpoint, closed after the single attempt.
        let service = LightWalletGRPCService(endpoint: endpoint)

        do {
            let response = try await service.submit(spendTransaction: rawTransaction, mode: ServiceMode.direct)
            await service.closeConnections()
            return outcome(from: response)
        } catch {
            await service.closeConnections()
            logger.error("MigrationBroadcaster: direct submit transport failure: \(error)")
            return MigrationBroadcastOutcome.transportError
        }
    }

    private func outcome(from response: LightWalletServiceResponse) -> MigrationBroadcastOutcome {
        if response.errorCode == 0 {
            return MigrationBroadcastOutcome.submitted
        }
        return MigrationBroadcastOutcome.rejected(errorCode: response.errorCode, message: response.errorMessage)
    }

    /// Builds and bootstraps a fresh dedicated Tor client rooted at `migrationTorDir`. The default
    /// ``torClientFactory``; bootstraps eagerly so a runtime failure surfaces here (fail-closed)
    /// rather than mid-submit.
    ///
    /// - Note: Does not pre-create `migrationTorDir` itself: `TorClient.prepare()` ->
    ///   `resolveRuntime()` already ensures the directory exists before creating the runtime. Same
    ///   fail-closed error surface either way -- a directory-creation failure from either layer is
    ///   caught by ``broadcastOverTor(rawTransaction:to:)`` and reported as
    ///   ``ZcashError/migrationTorUnavailable``.
    private static func bootstrapTorClient(migrationTorDir: URL) async throws -> TorClient {
        let client = TorClient(torDir: migrationTorDir)
        try await client.prepare()
        return client
    }
}
