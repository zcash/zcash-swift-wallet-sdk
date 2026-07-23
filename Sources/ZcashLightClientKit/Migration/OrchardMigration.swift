//
//  OrchardMigration.swift
//  ZcashLightClientKit
//

import Combine
import Foundation

/// Per-broadcast network-privacy options for a migration transfer.
///
/// Independent of the app's global Tor toggle and of the synchronizer's networking: each migration
/// broadcast decides for itself whether to use Tor and which endpoint to hit.
///
/// - Note: Not declared `Sendable` because it stores a `LightWalletEndpoint`, which the pinned SDK
///   does not (yet) declare `Sendable`. Under this package's Swift 5.6 minimal concurrency checking
///   that is a non-issue; it should gain `Sendable` once the core endpoint type does.
public struct MigrationNetworkPrivacyOptions: Equatable {
    /// Whether to broadcast over the dedicated migration Tor client. When `true`, the broadcast is
    /// fail-closed: if Tor cannot be established it throws rather than falling back to a direct
    /// connection (see ``MigrationBroadcaster``).
    public let useTor: Bool

    /// The endpoint this broadcast is submitted to. The app picks the submission server explicitly
    /// for every migration transfer; the SDK never supplies a default. Per the migration privacy
    /// spec this should differ from the wallet's ordinary sync server, so a migration broadcast is
    /// not correlated with the wallet's sync traffic. A typed endpoint (an iOS-specific choice; the
    /// Android SDK passes a `host:port` string).
    public let submissionEndpoint: LightWalletEndpoint

    /// Creates network-privacy options.
    public init(useTor: Bool, submissionEndpoint: LightWalletEndpoint) {
        self.useTor = useTor
        self.submissionEndpoint = submissionEndpoint
    }
}

/// The app-facing entry point for driving an Orchard -> Ironwood pool migration for one
/// account.
///
/// `OrchardMigration` is deliberately independent of ``Synchronizer``: the app needs
/// ``isSyncBlocked()`` *before* any synchronizer exists (it gates whether sync should run at all), so
/// this type resolves everything from the wallet's data-db path and holds its own Rust backend rather
/// than borrowing the synchronizer's. One instance is bound to one account
/// (``Config/accountUUID``).
///
/// It composes three collaborators: the migration welding (the Rust engine surface), a fail-closed
/// ``MigrationBroadcaster``, and a persisted ``MigrationSyncGate`` (the 10-minute post-broadcast
/// privacy buffer plus the overdue-transfer block). The engine owns all migration state, including
/// the committed schedule; the SDK keeps no local copy of the proposal list.
actor OrchardMigration {
    /// The immutable configuration an ``OrchardMigration`` is built from.
    ///
    /// Beyond the migration's own inputs, this carries the paths the underlying `ZcashRustBackend`
    /// initializer requires. Migration signing itself needs no Sapling parameter files (the
    /// Orchard/Ironwood proving keys are internal to the Rust crate); `spendParamsURL` /
    /// `outputParamsURL` / `fsBlockDbRoot` exist purely because the shared backend initializer
    /// demands them, and are otherwise unused by the migration flow.
    ///
    /// - Note: Not declared `Sendable`. It holds `ZcashNetwork`, `LightWalletEndpoint`, and
    ///   `Initializer.LoggingPolicy` — none of which the pinned SDK declares `Sendable`, and
    ///   `LoggingPolicy.custom(Logger)` cannot be (a `Logger` is a non-`Sendable` reference). The
    ///   conformance is not needed: a `Config` only flows through this actor's synchronous
    ///   (nonisolated) initializer, never across an isolation boundary.
    struct Config {
        /// The wallet's data database — the migration engine's entire persisted state lives here.
        let dataDbURL: URL
        /// Filesystem root of the compact-block cache. Pass-through: required by the backend
        /// initializer, unused by migration.
        let fsBlockDbRoot: URL
        /// Sapling spend-parameters file. Pass-through: required by the backend initializer, unused
        /// by migration signing.
        let spendParamsURL: URL
        /// Sapling output-parameters file. Pass-through: required by the backend initializer, unused
        /// by migration signing.
        let outputParamsURL: URL
        /// The network this wallet is on.
        let network: ZcashNetwork
        /// The account this migration is bound to.
        let accountUUID: AccountUUID
        /// The main Tor directory; the dedicated migration Tor client is provisioned in its
        /// `migration_tor` subdirectory.
        let torDirURL: URL
        /// Directory for the SDK's general storage; the per-account sync-gate file lives here.
        let generalStorageURL: URL
        /// The logging policy, mirroring ``Initializer``'s.
        let loggingPolicy: Initializer.LoggingPolicy

        /// Creates a configuration.
        ///
        /// - Parameters:
        ///   - dataDbURL: the wallet's data database.
        ///   - fsBlockDbRoot: compact-block cache root (pass-through for the backend initializer).
        ///   - spendParamsURL: Sapling spend params (pass-through for the backend initializer).
        ///   - outputParamsURL: Sapling output params (pass-through for the backend initializer).
        ///   - network: the wallet's network.
        ///   - accountUUID: the account this migration is bound to.
        ///   - torDirURL: the main Tor directory.
        ///   - generalStorageURL: directory for the per-account sync-gate file.
        ///   - loggingPolicy: the logging policy.
        init(
            dataDbURL: URL,
            fsBlockDbRoot: URL,
            spendParamsURL: URL,
            outputParamsURL: URL,
            network: ZcashNetwork,
            accountUUID: AccountUUID,
            torDirURL: URL,
            generalStorageURL: URL,
            loggingPolicy: Initializer.LoggingPolicy = Initializer.LoggingPolicy.default(.debug)
        ) {
            self.dataDbURL = dataDbURL
            self.fsBlockDbRoot = fsBlockDbRoot
            self.spendParamsURL = spendParamsURL
            self.outputParamsURL = outputParamsURL
            self.network = network
            self.accountUUID = accountUUID
            self.torDirURL = torDirURL
            self.generalStorageURL = generalStorageURL
            self.loggingPolicy = loggingPolicy
        }
    }

    /// The post-broadcast privacy buffer: how long sync stays paused after a migration broadcast so
    /// the broadcast is not correlated with a fresh sync. A fixed production value.
    static let privacySyncBufferDuration: TimeInterval = 600

    /// The NU6.3 (Ironwood) activation height for `networkType`, or `nil` when NU6.3 is unset for
    /// that network. Stateless — no database access, and safe to call before constructing an
    /// ``OrchardMigration`` (e.g. to gate migration availability/UI on whether the chain has reached
    /// activation).
    ///
    /// - Note: Also returns `nil` for a network id outside `{testnet, mainnet}` (e.g. `.regtest`),
    ///   which has no fixed NU6.3 height; callers are expected to pass `.testnet`/`.mainnet`.
    ///
    /// Delegates to the canonical ``ZcashNetwork/ironwoodActivationHeight`` so the SDK has a single
    /// path to the underlying backend rather than two independent forwarders.
    static func ironwoodActivationHeight(for networkType: NetworkType) -> BlockHeight? {
        ZcashNetworkBuilder.network(for: networkType).ironwoodActivationHeight
    }

    private let welding: ZcashRustBackendWelding
    private let accountUUID: AccountUUID
    private let broadcaster: any MigrationBroadcasting
    private let syncGate: MigrationSyncGate
    private let logger: Logger

    /// Whether a broadcast-performing flow is currently in flight. Together with
    /// `broadcastFlowWaiters`, this implements ``serializedBroadcastFlow(_:)``'s single-flight
    /// discipline. Not a cache: it only ever describes the presently running call.
    private var isBroadcastFlowInFlight = false

    /// Callers waiting for the in-flight broadcast flow to finish, resumed in bulk when it does.
    private var broadcastFlowWaiters: [CheckedContinuation<Void, Never>] = []

    /// Creates an `OrchardMigration` from `config`, building its own Rust backend, a dedicated
    /// ``MigrationBroadcaster``, and sync gate. Standalone construction: use
    /// ``init(config:sharedBroadcaster:)`` instead when several accounts must share one broadcaster
    /// (as ``OrchardMigrationHost`` does) so they do not each race an independent Tor bootstrap
    /// against the shared `migration_tor` directory.
    init(config: Config) {
        let logger = config.loggingPolicy.makeLogger(category: "migrationLogs")
        self.init(
            config: config,
            sharedBroadcaster: MigrationBroadcaster(torDirURL: config.torDirURL, logger: logger)
        )
    }

    /// Creates an `OrchardMigration` from `config` and an externally owned `sharedBroadcaster`,
    /// building everything ``init(config:)`` does (its own Rust backend and sync gate, and the
    /// custom-network registration) except the broadcaster, which is supplied so several per-account
    /// migrations can share a single one (see ``OrchardMigrationHost``).
    ///
    /// - Note: When `config.network` is a custom network (``ZcashNetwork/customActivationHeights``
    ///   non-`nil`), this registers it with the Rust core exactly as `Initializer.setup` does, before
    ///   building the backend: `OrchardMigration` deliberately does not share the synchronizer's
    ///   backend (see the type doc), so it cannot rely on an `Initializer` having already registered
    ///   it -- an app may construct this before any `Initializer` exists at all. Process-global (see
    ///   `MIGRATING.md`); a conflicting re-registration is a host configuration bug (`assertionFailure`).
    init(config: Config, sharedBroadcaster: any MigrationBroadcasting) {
        if let activationHeights = config.network.customActivationHeights {
            let cleanRegistration = ZcashRustBackend.setCustomNetwork(
                base: config.network.customNetworkBase ?? config.network.networkType,
                activationHeights
            )
            if !cleanRegistration {
                // A different custom network was already registered in this process. The new values
                // are applied (last writer wins), but per-instance state of any earlier registrant
                // (e.g. its checkpoint source) no longer matches the process-global parameters -- a
                // host configuration bug worth failing fast on during development.
                assertionFailure(
                    "Conflicting custom-network registration: a different custom network was already registered in this process."
                )
            }
        }

        let logger = config.loggingPolicy.makeLogger(category: "migrationLogs")
        let welding = ZcashRustBackend(
            dbData: config.dataDbURL,
            fsBlockDbRoot: config.fsBlockDbRoot,
            spendParamsPath: config.spendParamsURL,
            outputParamsPath: config.outputParamsURL,
            networkType: config.network.networkType,
            logLevel: config.loggingPolicy.makeRustLogging(),
            // Migration welding calls are data-db operations that never consult these flags; the
            // dedicated broadcaster owns all migration networking.
            sdkFlags: SDKFlags(torEnabled: false, exchangeRateEnabled: false)
        )
        let accountUUID = config.accountUUID

        self.welding = welding
        self.accountUUID = accountUUID
        self.logger = logger
        self.broadcaster = sharedBroadcaster
        self.syncGate = MigrationSyncGate(
            directory: config.generalStorageURL,
            accountUUID: accountUUID,
            bufferDuration: OrchardMigration.privacySyncBufferDuration,
            overdueProvider: {
                // Degrade to "not overdue" on any engine error so the reactive gate never crashes.
                (try? await welding.migrationHasOverdueTransfers(for: accountUUID)) ?? false
            },
            logger: logger
        )
    }

    /// Injecting initializer for tests: supply the welding, broadcaster, sync gate (with its test
    /// clock/ticker), and logger directly.
    init(
        welding: ZcashRustBackendWelding,
        accountUUID: AccountUUID,
        broadcaster: any MigrationBroadcasting,
        syncGate: MigrationSyncGate,
        logger: Logger
    ) {
        self.welding = welding
        self.accountUUID = accountUUID
        self.broadcaster = broadcaster
        self.syncGate = syncGate
        self.logger = logger
    }

    // MARK: - State

    /// The current Orchard -> Ironwood migration state. Also the reconciliation hub: call it on
    /// launch and after every migration operation.
    func migrationState() async throws -> MigrationState {
        try await welding.migrationState(for: accountUUID)
    }

    /// Live migration progress, or `nil` when no migration is in progress.
    func migrationProgress() async throws -> MigrationProgress? {
        try await welding.migrationProgress(for: accountUUID)
    }

    // MARK: - Note splitting

    /// Whether the account's Orchard notes must be split before migration.
    ///
    /// - Note: Requires at least one completed sync. On a wallet that has never completed a sync (no
    ///   chain tip known) this throws rather than returning `false`.
    func isNoteSplitNeeded() async throws -> Bool {
        try await welding.migrationIsNoteSplitNeeded(for: accountUUID)
    }

    /// The optimal note split for the spendable Orchard balance.
    func prepareNoteSplit() async throws -> NoteSplitProposal {
        try await welding.migrationPrepareNoteSplit(for: accountUUID)
    }

    /// Signs, extracts, broadcasts, and records the note-split transaction, returning the broadcast
    /// outcome.
    ///
    /// Composition: sign the split, extract the broadcast bytes, broadcast once, and — only on a
    /// success outcome — start the privacy buffer, *before* recording the mapped result: the gate
    /// marks on submit success, independent of record bookkeeping. A transport failure or a server
    /// rejection is *returned* as a ``MigrationTransferResult`` (and recorded first, gate untouched).
    ///
    /// Throws: a pre-broadcast failure throws untouched (a signing error, or
    /// ``ZcashError/migrationTorUnavailable`` when `options.useTor` is set and Tor cannot be
    /// established — nothing was broadcast and nothing is recorded). A record failure *after* a
    /// successful broadcast throws ``ZcashError/migrationRecordFailedAfterBroadcast(_:)`` — the
    /// broadcast DID land and the privacy buffer is already running; the failure is transient from
    /// the migration's point of view, because a later execution window self-heals (re-submitting
    /// draws a duplicate rejection, which records as success).
    ///
    /// Broadcast flows are single-flight on this actor: when another broadcast-performing call
    /// (this method or ``executeNextPendingTransfer(options:)``) is in flight, this call first waits
    /// for it to finish — it never broadcasts concurrently with it and never throws on contention.
    func submitNoteSplit(
        proposal: NoteSplitProposal,
        usk: UnifiedSpendingKey,
        options: MigrationNetworkPrivacyOptions
    ) async throws -> MigrationTransferResult {
        try await serializedBroadcastFlow { () async throws -> MigrationTransferResult in
            let prepared = try await welding.migrationSignNoteSplit(proposal: proposal, usk: usk, for: accountUUID)
            return try await broadcastAndRecord(prepared: prepared, options: options)
        }
    }

    // MARK: - Migration proposal

    /// The full migration schedule for the spendable Orchard balance.
    func proposeMigrationTransfers() async throws -> MigrationSchedule {
        try await welding.migrationProposeTransfers(for: accountUUID)
    }

    /// Proposes the immediate (single-transaction) migration: an ordinary send-max that spends ALL
    /// spendable Orchard notes and pays everything minus the ZIP-317 fee to the account's own
    /// unified address -- post-NU6.3 the payment lands in the Ironwood pool (the UA's Orchard
    /// receiver doubles as the Ironwood receiver). Entirely outside the migration engine: the
    /// returned proposal is an ORDINARY proposal held by the caller, so no engine plan-cache
    /// staleness applies to it (unlike ``proposeMigrationTransfers()``).
    func proposeImmediateMigration() async throws -> ImmediateMigrationProposal {
        let ownAddress = try await welding.getCurrentAddress(accountUUID: accountUUID)
        let ffiProposal = try await welding.proposeSendMaxTransfer(
            accountUUID: accountUUID,
            recipient: ownAddress.stringEncoded,
            memo: nil,
            orchardOnly: true
        )
        let proposal = Proposal(inner: ffiProposal)
        let fee = proposal.totalFeeRequired()
        let amount = OrchardMigration.sweptPaymentValue(of: ffiProposal) - fee
        return ImmediateMigrationProposal(proposal: proposal, amount: amount, fee: fee)
    }

    /// Records a broadcast immediate-migration sweep so the platform migration state machine
    /// reports it: `InProgress` (0 of 1) while unmined, `Complete` once mined, or a re-offer
    /// (`NotStarted`) if it expires unmined. Not broadcast-performing itself (the broadcast rides
    /// the ordinary `createProposedTransactions`/`createTransactionFromPCZT` pipeline, already
    /// guarded there) -- this only records the outcome, so it is not gated by
    /// ``serializedBroadcastFlow(_:)``.
    func recordImmediateMigration(txid: Data) async throws {
        try await welding.migrationRecordImmediateRun(txid: txid, for: accountUUID)
    }

    /// The net value swept by an immediate-migration `FfiProposal` before its fee is subtracted:
    /// the total value of the notes it consumes, minus any declared change. A send-max proposal
    /// declares no change (there is nothing left to return), so this is ordinarily just the input
    /// total; the change subtraction is defensive rather than load-bearing.
    private static func sweptPaymentValue(of proposal: FfiProposal) -> Zatoshi {
        proposal.steps.reduce(Zatoshi.zero) { total, step in
            let stepInput = step.inputs.reduce(Zatoshi.zero) { inputTotal, input in
                guard case .receivedOutput(let output) = input.value else {
                    return inputTotal
                }
                return inputTotal + Zatoshi(Int64(output.value))
            }
            let stepChange = step.balance.proposedChange.reduce(Zatoshi.zero) { changeTotal, change in
                changeTotal + Zatoshi(Int64(change.value))
            }
            return total + stepInput - stepChange
        }
    }

    /// The leftover Orchard balance a migration would not cross, when large enough to be worth
    /// offering the user a choice about; `nil` when there is no such residual.
    ///
    /// - Note: Requires at least one completed sync. On a wallet that has never completed a sync (no
    ///   chain tip known) this throws rather than returning `nil`.
    func residualAfterMigration() async throws -> Zatoshi? {
        try await welding.migrationResidualAfterMigration(for: accountUUID)
    }

    /// Locks every currently-spendable, not-already-locked legacy-Orchard note until explicit
    /// unlock and returns the total value locked — the "Lock balance" choice at migration
    /// `Complete`. A straight delegation to the welding lock call, bound to this actor's own
    /// account; not broadcast-performing, so it is not gated by ``serializedBroadcastFlow(_:)``.
    func lockMigrationResidual() async throws -> Zatoshi {
        try await welding.lockMigrationResidual(accountUUID: accountUUID)
    }

    /// Unlocks the account's locked outputs — the release half of ``lockMigrationResidual()`` —
    /// and returns the number of outputs unlocked. A straight delegation to the welding unlock
    /// call, bound to this actor's own account.
    func unlockMigrationResidual() async throws -> Int {
        try await welding.unlockMigrationResidual(accountUUID: accountUUID)
    }

    /// The multi-run ("rounds") estimate for migrating the whole spendable Orchard balance. A
    /// straight delegation to the welding estimate call, bound to this actor's own account; the
    /// zero-run estimate is a legitimate answer, not an error.
    func estimateMigrationRuns() async throws -> MigrationRunEstimate {
        try await welding.estimateMigrationRuns(accountUUID: accountUUID)
    }

    /// Pre-signs and persists every transfer in `schedule` in the migration engine.
    ///
    /// The SDK does not retain the proposal list: hosts that need to render the committed schedule
    /// later must persist it themselves at confirmation time.
    func signAndStoreMigrationSchedule(_ schedule: MigrationSchedule, usk: UnifiedSpendingKey) async throws {
        try await welding.migrationSignAndStoreSchedule(schedule, usk: usk, for: accountUUID)
    }

    // MARK: - Background execution

    /// Broadcasts the next height-due transfer, or returns `nil` when nothing is currently due.
    ///
    /// Composition mirrors ``submitNoteSplit(proposal:usk:options:)``: fetch the next due transfer
    /// (nil ⇒ return nil, leaving the gate untouched), extract, broadcast once, and — only on a
    /// success outcome — start the privacy buffer, *before* recording the mapped result: the gate
    /// marks on submit success, independent of record bookkeeping. Transport/rejection outcomes are
    /// returned (recorded first, gate untouched). Pre-broadcast failures throw untouched; a record
    /// failure *after* a successful broadcast throws
    /// ``ZcashError/migrationRecordFailedAfterBroadcast(_:)`` — the broadcast DID land and the
    /// privacy buffer is already running; a later execution window self-heals the engine state
    /// (re-submitting draws a duplicate rejection, which records as success).
    ///
    /// Broadcast flows are single-flight on this actor: when another broadcast-performing call
    /// (this method or ``submitNoteSplit(proposal:usk:options:)``) is in flight, this call first
    /// waits for it to finish and only then fetches the next due transfer — so a concurrent call
    /// can never re-broadcast the in-flight transfer, and typically returns nil once the in-flight
    /// flow has recorded. It never throws on contention.
    ///
    /// - Important: This method must run only in a session that does **not** also sync. This actor
    ///   does not check sync state itself; the `Synchronizer` surface in front of it adds an
    ///   advisory point-in-time guard (``ZcashError/migrationBroadcastDuringSync``) plus the
    ///   10-minute privacy gate (see ``isSyncBlocked()``) — neither is a hard mutual-exclusion
    ///   lock, so hosts must still sequence sync and broadcast sessions.
    /// - Note: Immediately after ``storeSignedNoteSplitPCZT(_:)``, the engine treats the pending note
    ///   split as the next due transfer, so this method broadcasts that split first — it keeps
    ///   returning the split's prepared transfer until the split is reported broadcast, and only then
    ///   advances to the scheduled transfers.
    func executeNextPendingTransfer(options: MigrationNetworkPrivacyOptions) async throws -> MigrationTransferResult? {
        try await serializedBroadcastFlow { () async throws -> MigrationTransferResult? in
            guard let prepared = try await welding.migrationNextDueTransfer(for: accountUUID) else {
                return nil
            }
            return try await broadcastAndRecord(prepared: prepared, options: options)
        }
    }

    // MARK: - Sync coordination

    /// Whether ordinary wallet sync should currently be paused for this migration.
    ///
    /// `true` when a transfer is overdue **or** the post-broadcast privacy buffer has not yet
    /// elapsed. The overdue query is engine-backed; if it throws, this degrades to the persisted
    /// gate-file (privacy-buffer) state rather than crashing the app's sync gating.
    ///
    /// - Note: The gate is per-account (by file name). An app running several migrating accounts must
    ///   consult each account's `OrchardMigration`; this instance answers only for its bound account.
    /// - Note: Always consults the overdue query fresh (`await`s the engine), unlike
    ///   ``syncBlockedStream``'s synchronous subscribe-time seed -- see that property's documented
    ///   caveat about the two briefly disagreeing right after relaunch.
    func isSyncBlocked() async -> Bool {
        let hasOverdue = (try? await welding.migrationHasOverdueTransfers(for: accountUUID)) ?? false
        return syncGate.currentlyBlocked(hasOverdue: hasOverdue)
    }

    /// A stream of ``isSyncBlocked()``: emits the current value on subscribe, re-evaluates every 15 s
    /// and after every broadcast, and collapses consecutive duplicates.
    ///
    /// `nonisolated` so sync-gating UI/logic can subscribe without awaiting the actor; it is backed by
    /// the internally synchronized ``MigrationSyncGate``: concurrent recomputes (the ticker and every
    /// post-broadcast re-evaluation) publish through one lock-guarded, generation-ordered funnel, so a
    /// recompute that started earlier but finishes later after a fresher one already published is
    /// dropped rather than emitted — subscribers only ever see values in latest-wins order, never a
    /// stale one overwriting a fresher one.
    ///
    /// - Important: The value delivered synchronously on subscribe reflects only the persisted
    ///   privacy buffer, not overdue transfers -- overdue detection needs the engine query, which is
    ///   asynchronous. On relaunch with an overdue transfer and no active buffer, that first emission
    ///   can therefore briefly read `false` while ``isSyncBlocked()`` already reads `true`; the stream
    ///   corrects itself with its first asynchronous re-evaluation (the next tick, or sooner if a
    ///   broadcast happens first). A subscriber that must be correct from its very first value should
    ///   pair this stream with an initial ``isSyncBlocked()`` call rather than trusting the seed alone.
    nonisolated var syncBlockedStream: AnyPublisher<Bool, Never> {
        syncGate.blockedStream
    }

    // MARK: - On-launch reconciliation

    /// Whether any scheduled transfer is past its send height but not yet broadcast.
    func hasOverdueTransfers() async throws -> Bool {
        try await welding.migrationHasOverdueTransfers(for: accountUUID)
    }

    /// Whether the migration is in an invalid state (spendable Orchard remains but no scheduled
    /// transfer covers it).
    func hasInvalidTransfers() async throws -> Bool {
        try await welding.migrationHasInvalidTransfers(for: accountUUID)
    }

    /// The migration engine's next height-due pending transfer proposal, or `nil` when nothing is
    /// pending.
    ///
    /// A straight readback of the stored run's next due-and-unbroadcast transfer — deliberately
    /// with **no** local time-shifting of `nextExecutableAfterHeight` (the Android implementation
    /// clamps it to `now + interval` with a known unit bug the SDK does not port). The host re-arms
    /// its own background execution window from the returned proposal's heights; the local decision
    /// not to broadcast before that window *is* the reschedule, and the ZIP 318 "re-spread the
    /// remainder" property is carried by the delivery machinery itself (one broadcast per session,
    /// the 10-minute privacy buffer between sessions). `nil` means there is nothing to re-arm (no
    /// stored run, the run is terminal, or only preparation transactions are pending).
    /// - Throws: `rustMigrationPendingTransferProposal` if the engine returns an error.
    func rescheduleOverdueTransfer() async throws -> MigrationTransferProposal? {
        try await welding.migrationPendingTransferProposal(for: accountUUID)
    }

    // MARK: - Invalidity recovery

    /// Cancels the stored run and previews a fresh schedule against the live balance.
    ///
    /// The stored run is persisted as cancelled (its pre-signed transactions are abandoned;
    /// already-broadcast ones are unaffected on-chain), the invalid marks are cleared, and a fresh
    /// plan is previewed for the re-confirm lane — the follow-up
    /// ``signAndStoreMigrationSchedule(_:usk:)`` / ``submitNoteSplit(proposal:usk:options:)`` (or
    /// PCZT store) then commits it.
    func restartCurrentMigrationStep() async throws -> MigrationSchedule {
        try await welding.migrationRestartStep(for: accountUUID)
    }

    /// Rebuilds every EXPIRED transfer of the stored migration run in place through the engine and
    /// returns the number rebuilt (`0` when no run is stored, the run is terminal, or nothing has
    /// expired).
    ///
    /// Each rebuilt transfer re-spends the SAME funding note (recovered from the expired PCZT by
    /// nullifier identity, never an equal-value substitute) on a fresh schedule — a fresh
    /// memoryless delay from the current tip, a fresh canonical expiry, and a freshly drawn
    /// boundary anchor. Passing a spending key signs each rebuilt transfer anew in-process; passing
    /// `nil` (an external-signer account, whose spend authority never exists on this device) leaves
    /// it awaiting its signature, so the ``createUnsignedTransferPCZTs(for:)`` /
    /// ``storeSignedSchedulePCZTs(_:)`` ceremony re-serves and completes it.
    /// - Throws: notably, a `FundingNoteUnavailable`-class failure when an expired transfer's exact
    ///   funding note was spent outside the migration, where the message names
    ///   ``restartCurrentMigrationStep()`` (cancel and re-plan) as the remedy.
    func refreshStaleTransfers(usk: UnifiedSpendingKey?) async throws -> UInt32 {
        try await welding.migrationRefreshStaleTransfers(usk: usk, for: accountUUID)
    }

    // MARK: - External signing (PCZT)

    /// Builds the whole previewed migration UNSIGNED — the run is created by this call — and
    /// returns the preparation (note-split) subset of its PCZTs for the signing ceremony. The
    /// transfer subset of the same build is served by ``createUnsignedTransferPCZTs(for:)``, so one
    /// ceremony signs everything.
    func createUnsignedNoteSplitPCZTs() async throws -> [MigrationUnsignedTransferPczt] {
        try await welding.migrationCreateUnsignedNoteSplitPczts(for: accountUUID)
    }

    /// Applies the ceremony's signatures to the run's preparation (note-split) transactions,
    /// all-or-nothing, and returns a STORAGE RECEIPT for the first one (its `txid` is zeroed — the
    /// broadcastable, proven value is served by the delivery lane).
    func storeSignedNoteSplitPCZTs(_ signed: [MigrationSignedTransferPczt]) async throws -> PreparedMigrationTransfer {
        try await welding.migrationStoreSignedNoteSplitPczts(signed, for: accountUUID)
    }

    /// Builds one unsigned, proven PCZT per transfer of `schedule` for an external signer.
    func createUnsignedTransferPCZTs(for schedule: MigrationSchedule) async throws -> [MigrationUnsignedTransferPczt] {
        try await welding.migrationCreateUnsignedTransferPczts(for: schedule, for: accountUUID)
    }

    /// Accepts the full set of externally signed transfer PCZTs (all-or-nothing), persisting them in
    /// the migration engine.
    ///
    /// The SDK does not retain the proposal list: hosts that need to render the committed schedule
    /// later must persist it themselves at confirmation time.
    func storeSignedSchedulePCZTs(_ signed: [MigrationSignedTransferPczt]) async throws {
        try await welding.migrationStoreSignedSchedulePczts(signed, for: accountUUID)
    }

    // MARK: - Private

    /// Runs `flow` as the only broadcast-performing flow on this actor.
    ///
    /// The actor's methods are reentrant: the broadcast composition suspends at the welding hops and
    /// for the whole broadcast (a Tor bootstrap can take seconds), while the engine keeps reporting
    /// the same transfer as next-due until its result is recorded — so without this guard, a
    /// concurrent `executeNextPendingTransfer`/`submitNoteSplit` could re-fetch and re-broadcast the
    /// same bytes mid-flight. The serialization contract:
    /// - A concurrent caller never throws on contention and is never dropped: it awaits the
    ///   in-flight flow's completion (success or failure), then runs its own flow fresh, so its own
    ///   due-transfer fetch observes the recorded outcome (typically nil, or the next transfer).
    /// - Waiting is a suspension on a continuation that the finishing flow resumes exactly once —
    ///   no busy-waiting, and no unstructured tasks.
    /// - Cancelling a waiting caller never cancels the in-flight flow: the waiter holds no
    ///   reference to it, and the waiter's own cancellation is observed only by its own flow once
    ///   it proceeds.
    private func serializedBroadcastFlow<T>(_ flow: () async throws -> T) async rethrows -> T {
        while isBroadcastFlowInFlight {
            await withCheckedContinuation { continuation in
                broadcastFlowWaiters.append(continuation)
            }
        }
        isBroadcastFlowInFlight = true
        defer {
            isBroadcastFlowInFlight = false
            let waiters = broadcastFlowWaiters
            broadcastFlowWaiters = []
            for waiter in waiters {
                waiter.resume()
            }
        }
        return try await flow()
    }

    /// Shared broadcast/record composition for a prepared transfer: extract the broadcast bytes,
    /// broadcast once to the resolved endpoint, and classify the outcome. On a success outcome the
    /// privacy buffer starts *before* the result is recorded — ``MigrationSyncGate/markBroadcast()``
    /// is a non-throwing local write, and a record failure after a real broadcast must never skip
    /// the buffer; a record failure on that path throws
    /// ``ZcashError/migrationRecordFailedAfterBroadcast(_:)``. Non-success outcomes are recorded
    /// first and returned with the gate untouched (only success outcomes mark it, unchanged); only
    /// pre-broadcast failures throw untouched.
    private func broadcastAndRecord(
        prepared: PreparedMigrationTransfer,
        options: MigrationNetworkPrivacyOptions
    ) async throws -> MigrationTransferResult {
        let rawTransaction = try await welding.migrationExtractBroadcastTx(pczt: prepared.pczt, for: accountUUID)
        let outcome = try await broadcaster.broadcast(
            rawTransaction: rawTransaction,
            to: options.submissionEndpoint,
            useTor: options.useTor
        )
        let result = MigrationBroadcaster.map(outcome: outcome, successTxId: prepared.txid.toHexStringTxId())
        if case MigrationTransferResult.success = result {
            // The broadcast landed (or a duplicate rejection proved an earlier one did): start the
            // privacy buffer first, so a record failure cannot skip it.
            syncGate.markBroadcast()
            do {
                try await welding.migrationRecordTransferResult(transferId: prepared.id, result: result, for: accountUUID)
            } catch {
                logger.error("OrchardMigration: failed to record a successfully submitted broadcast: \(error)")
                throw ZcashError.migrationRecordFailedAfterBroadcast(error)
            }
        } else {
            try await welding.migrationRecordTransferResult(transferId: prepared.id, result: result, for: accountUUID)
        }
        return result
    }
}
