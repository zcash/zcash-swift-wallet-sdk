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
/// ``MigrationBroadcaster``, and a persisted ``MigrationSyncGate`` (the in-flight broadcast marker,
/// and nothing else — the gate is behavior-based, so see its type doc for why no timed
/// post-broadcast spacing lives there any more). The engine owns all migration state, including
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

    /// The NU6.3 (Ironwood) activation height for `networkType`, or `nil` when NU6.3 is unset for
    /// that network. Stateless — no database access, and safe to call before constructing an
    /// ``OrchardMigration``.
    ///
    /// SDK-internal: `OrchardMigration` is not `public`, so apps cannot reach this helper. The
    /// app-facing surface for the same value is the public ``ZcashNetwork/ironwoodActivationHeight``
    /// (`Model/ZcashNetwork+IronwoodActivation.swift`), which this delegates to so the SDK has a
    /// single path to the underlying backend rather than two independent forwarders.
    ///
    /// - Note: Also returns `nil` for a network id outside `{testnet, mainnet}` (e.g. `.regtest`),
    ///   which has no fixed NU6.3 height; callers are expected to pass `.testnet`/`.mainnet`.
    static func ironwoodActivationHeight(for networkType: NetworkType) -> BlockHeight? {
        ZcashNetworkBuilder.network(for: networkType).ironwoodActivationHeight
    }

    private let welding: ZcashRustBackendWelding
    private let accountUUID: AccountUUID
    private let broadcaster: any MigrationBroadcasting
    private let syncGate: MigrationSyncGate
    private let logger: Logger

    /// The clock every estimate-consulting path on this actor reads (mirroring
    /// ``OrchardMigrationHost``'s injected `now`), so tests can drive the wall-clock tip
    /// projection deterministically. Production passes the real clock.
    private let now: @Sendable () -> Date

    /// Whether a broadcast-performing flow is currently in flight. Together with
    /// `broadcastFlowWaiters`, this implements ``serializedBroadcastFlow(_:)``'s single-flight
    /// discipline. Not a cache: it only ever describes the presently running call.
    private var isBroadcastFlowInFlight = false

    /// Callers waiting for the in-flight broadcast flow to finish, resumed in bulk when it does.
    private var broadcastFlowWaiters: [CheckedContinuation<Void, Never>] = []

    /// The outlook (``MigrationAdvance/next``) most recently returned by ``advanceStep()`` --
    /// from ANY caller (the app's driver, or a direct host call, both of which fold through that
    /// one method). Replaced on every crank,
    /// including with `nil` when that crank's step carried none: the outlook holds only as of the
    /// state its call returned, so a stale value must never outlive the crank that superseded it.
    /// Read side for hosts is ``nextMigrationWake``.
    private var lastOutlook: MigrationNextWork?

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
        let now: @Sendable () -> Date = { Date() }

        self.welding = welding
        self.accountUUID = accountUUID
        self.logger = logger
        self.broadcaster = sharedBroadcaster
        self.now = now
        self.syncGate = MigrationSyncGate(
            directory: config.generalStorageURL,
            accountUUID: accountUUID,
            logger: logger
        )
    }

    /// Injecting initializer for tests: supply the welding, broadcaster, sync gate (with its test
    /// clock/ticker), logger, and — for the actor's own estimate-consulting paths — a clock,
    /// directly. `now` defaults to the real clock so call sites that do not exercise the
    /// estimate stay unchanged.
    init(
        welding: ZcashRustBackendWelding,
        accountUUID: AccountUUID,
        broadcaster: any MigrationBroadcasting,
        syncGate: MigrationSyncGate,
        logger: Logger,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.welding = welding
        self.accountUUID = accountUUID
        self.broadcaster = broadcaster
        self.syncGate = syncGate
        self.logger = logger
        self.now = now
    }

    // MARK: - State

    /// The engine's next step to advance the stored run, driven with the wallet's scanned target
    /// and wall-clock estimated target, paired with its advisory outlook (upstream #2936). `nil`
    /// means no run is stored; a terminal (complete or cancelled) run reports the returned
    /// advance's `.step` as ``MigrationAdvanceStep/complete`` (`.next` is always `nil` for it). See
    /// ``MigrationAdvanceStep`` for the step semantics and the discharge mapping, and
    /// ``MigrationAdvance`` / ``MigrationNextWork`` for the outlook's contract.
    ///
    /// IT ALWAYS PROJECTS THE ESTIMATE, and takes no parameter for it. The opt-out overload existed
    /// for the kind-filtered lanes that cranked with their own tip rule; there is one crank site
    /// now, so an opt-out would be a capability for a distinction the surface no longer draws. The
    /// estimate may only ever ACCELERATE schedule due-ness — expiry stays scanned-tip — and an
    /// estimator failure degrades to scanned-tip behavior rather than blocking the advance.
    func advanceStep() async throws -> MigrationAdvance? {
        let estimatedTip = await MigrationTipEstimation.gatingEstimatedTip(welding: welding, now: now())
        let advance = try await welding.migrationAdvanceStep(for: accountUUID, estimatedTip: estimatedTip)
        // Every crank -- regardless of which caller drove it -- replaces the retained outlook,
        // including with `nil`: a stale outlook must not outlive the crank that superseded it (see
        // `lastOutlook`'s doc). A throw above leaves the previous value in place, since it means no
        // new state was actually observed.
        lastOutlook = advance?.next
        return advance
    }

    /// The engine's OUTLOOK retained from the most recent ``advanceStep()`` crank —
    /// by ANY caller (the app's driver, or a direct host call) — so a host can ask
    /// "when is the next migration wake, per the drive's own plan" without re-cranking the engine
    /// itself.
    ///
    /// ADVISORY and a FLOOR, exactly as ``MigrationAdvance/next`` documents: the height is the
    /// earliest the outlook's work becomes serviceable, never an appointment — dependencies still
    /// have to mine, and this value holds only as of the crank that produced it. The VERY NEXT
    /// crank's outlook supersedes it unconditionally, including to `nil`: a stale outlook must
    /// never outlive the crank that superseded it.
    ///
    /// It complements, never replaces, ``syncWakeups()``: this is ONE height (the very next thing
    /// to plan for), while the sync-wakeup schedule is MANY (the run's whole proving calendar) — a
    /// host registering OS wake-ups should min-fold this outlook's height in alongside the
    /// schedule's own heights, as zodl-ios already does, never treat it as a replacement source.
    ///
    /// `nil` means either no crank has run yet this session (``advanceStep()`` has
    /// never completed), or the last step's own outcome decides what follows — a chain condition
    /// (a mining confirmation) or a user/spend-authority action, not a height.
    var nextMigrationWake: MigrationNextWork? {
        lastOutlook
    }

    /// Live migration progress, or `nil` when no snapshot is reportable: present only while an
    /// engine run is ACTIVE or a recorded immediate sweep is pending (unmined and unexpired);
    /// terminal — complete or cancelled — runs report `nil`.
    func migrationProgress() async throws -> MigrationProgress? {
        try await welding.migrationProgress(for: accountUUID)
    }

    /// The LIVE status of every committed migration transaction, keyed by its stable id -- the
    /// per-transaction detail view behind ``migrationProgress()``'s aggregate summary.
    func transactionStatuses() async throws -> [MigrationTransactionStatus] {
        try await welding.migrationTransactionStatuses(for: accountUUID)
    }

    /// The stored run's sync/proving wake-up schedule as of the scanned tip — the heights at
    /// which the host should wake, sync, crank ``advanceStep()`` and discharge the prove
    /// instruction it returns, plus the transfer ids each wake-up covers. Jitter is re-drawn on
    /// every call; recompute (and re-register with the OS) after any state change rather than
    /// caching. Empty when there is nothing left to prove.
    func syncWakeups() async throws -> [MigrationSyncWakeup] {
        try await welding.migrationSyncWakeups(for: accountUUID)
    }

    // MARK: - Instruction executors

    /// Proves up to `maxProofs` of the transactions `instruction` NAMES, and returns a
    /// ``MigrationProveOutcome``: how many were proved (`0` is the ordinary "nothing in this batch
    /// is provable right now" answer) and the txids of the PREPARATIONS it proved.
    ///
    /// THE TXIDS ARE THE HANDOFF. A proved preparation is a complete PCZT whose submission is the
    /// host's ORDINARY path — retrieve each txid with ``takePreparation(byTxid:)``, submit the
    /// bytes through the host's own raw-transaction machinery, record the outcome the standard way.
    /// Transfers are never named: they are delivered by a ``MigrationBroadcastInstruction`` alone.
    ///
    /// THE INSTRUCTION IS THE AUTHORITY: this never asks the engine what to prove.
    /// ``advanceStep()`` is the top-level call, and `instruction` is a
    /// ``MigrationAdvanceStep/prove(transactions:)`` batch that a crank handed out — the only way
    /// to hold one, since ``MigrationProveTarget`` has no public initializer. Whether a candidate
    /// is worth proving at all, its order, and whether a due broadcast outranks proving this
    /// session were all settled by the advance that issued the batch.
    ///
    /// THERE IS NO LOOP HERE. Proving a batch can unblock rows that were not in it, so a host that
    /// wants to drain the run cranks again and discharges the NEXT instruction — the drive, not
    /// this executor, decides whether more proving (or a now-due broadcast) follows.
    ///
    /// Per row the rust executor SKIPS what it cannot prove — a row no longer awaiting its proof,
    /// or one whose anchor the wallet cannot resolve yet — so acting on a stale instruction is
    /// safe, and a skip never spends the budget.
    ///
    /// Run it at sync wake-ups (``syncWakeups()``), never on the broadcast path: proving needs the
    /// wallet's commitment tree and takes real time, while a broadcast session must stay a pure
    /// delivery step.
    /// - Parameters:
    ///   - instruction: the prove batch a crank returned. An EMPTY batch proves nothing (the
    ///     engine never issues one; a caller that slices its instruction down to nothing gets the
    ///     benign `0`).
    ///   - maxProofs: the session's proof budget, at least `1`.
    /// - Throws: ``ZcashError/rustMigrationProveTransactions(_:)`` when `maxProofs` is below `1` —
    ///   a caller bug, named rather than silently treated as "prove nothing";
    ///   ``ZcashError/migrationProvingUnavailable(_:)`` when proving fails for a non-transient
    ///   reason.
    func proveTransactions(
        _ instruction: [MigrationProveTarget],
        maxProofs: Int
    ) async throws -> MigrationProveOutcome {
        guard maxProofs >= 1 else {
            throw ZcashError.rustMigrationProveTransactions(
                "`proveTransactions` was given a proof budget of \(maxProofs); it must be at least 1"
            )
        }

        return try await welding.migrationProveTransactions(
            ids: instruction.map(\.id),
            maxProofs: maxProofs,
            for: accountUUID
        )
    }

    /// Serves the PROVED PREPARATION with `txid` for submission — the retrieval half of the
    /// handoff ``proveTransactions(_:maxProofs:)`` opens by returning the preparations' txids.
    ///
    /// A proved preparation is a complete PCZT (signatures and
    /// proofs); its submission is the ORDINARY path, not the engine's delivery ceremony —
    /// preparations are ZIP 318-exempt, and the engine's own contract is that a preparation is
    /// broadcast as soon as it is proved. So this hands the finalized transaction back, the host
    /// submits it through whatever machinery it already uses for raw transactions, and then closes
    /// the loop with ``recordPreparationBroadcast(_:result:)`` — which takes the very value this
    /// returned, so the host needs no identity of its own. The WALLET's record needs no separate
    /// call: it bound at retrieval, below.
    ///
    /// THIS ACCESSOR IS THE TAKE SEAM, NOT A BYTE READ. `txid -> row -> the store's atomic
    /// broadcast seam` in one database transaction: the wallet's record of the transaction binds
    /// AT RETRIEVAL, so a host can never hold submittable bytes the wallet knows nothing about,
    /// and a consumer that crashed between retrieving and submitting re-retrieves exactly the same
    /// bytes over the same record.
    ///
    /// PREPARATION-GATED: a txid naming a TRANSFER is refused — transfers are served by the
    /// drive's broadcast instruction alone (``performBroadcast(_:options:)``).
    ///
    /// Retrieved-but-never-submitted is a bounded, engine-modelled state, not a leak: the record
    /// is idempotent, the preparation carries a ZIP 203 expiry, and an unsubmitted row surfaces
    /// through the ordinary attention path once it expires.
    ///
    /// Unlike ``performBroadcast(_:options:)`` this does NOT broadcast, so it is not serialized
    /// against the broadcast flows and carries no privacy options of its own: what the host does
    /// with the bytes, and over what transport, is the host's ordinary submission policy.
    /// - Parameter txid: a txid ``MigrationProveOutcome/preparationTxids`` named, in the SDK's
    ///   raw/internal byte order.
    /// - Throws: ``ZcashError/migrationProvingUnavailable(_:)`` when the stored artifact cannot be
    ///   turned into servable bytes; ``ZcashError/rustMigrationTakePreparation(_:)`` for a
    ///   transfer's txid, for a txid the stored run does not carry, and for the readiness refusal
    ///   of a preparation that is not proved — which a host discharges by proving again rather
    ///   than retrying this.
    func takePreparation(byTxid txid: Data) async throws -> PreparedMigrationTransfer {
        try await welding.migrationTakePreparation(txid: txid, for: accountUUID)
    }

    /// Records the engine-side outcome of a preparation the host retrieved and submitted ITSELF —
    /// the closing half of the txid seam.
    ///
    /// ``takePreparation(byTxid:)`` binds the WALLET's record at retrieval, but the ENGINE's own
    /// per-row mark (`Proved -> Broadcast`) is what ``performBroadcast(_:options:)`` does on its
    /// success arm, and a host-submitted preparation never travels that path. This is the same
    /// mark, made by the host at the same moment: after its submit landed, in place of the
    /// ceremony it deliberately skipped. Without it the run leans on the self-healing fallback
    /// below for every ordinary preparation rather than only for the accidents it exists to cover.
    ///
    /// KEYED ON THE RETRIEVAL RESULT. It takes the `PreparedMigrationTransfer` itself, not a bare
    /// id: possession of what the accessor returned is what says this host actually holds the
    /// submission it is reporting on, and the DTO's ``PreparedMigrationTransfer/id`` is already
    /// the engine transfer id the record path keys on.
    ///
    /// PREPARATION-GATED, in the same register as the accessor: an id naming a TRANSFER is refused
    /// — transfers are served by the drive's broadcast instruction alone, and
    /// ``performBroadcast(_:options:)`` records their outcome itself — as is an id the stored run
    /// does not carry.
    ///
    /// REPORT THE REAL OUTCOME. Pass a `.success` on an acceptance, and a `.invalidNote` /
    /// `.expired` on a PERMANENT server rejection — the engine's record path dates the verdict
    /// against the observed tip on the still-`Proved` row, and the next crank re-adjudicates, so
    /// a doomed row can raise attention instead of being re-served until expiry. A network-level
    /// non-acceptance needs no call at all, because the engine's "network error" outcome records
    /// nothing by design and leaves the row exactly as re-servable as not calling would (a
    /// `.networkError` is accepted and forwarded verbatim for hosts that would rather report
    /// every attempt).
    ///
    /// THE SELF-HEALING FALLBACK REMAINS, now covering the accident rather than the ordinary path:
    /// a host that crashed between submitting and marking, or whose mark failed, still converges —
    /// the engine promotes any in-flight transaction its scan sees mine (identified by the id it
    /// stored when it BUILT the transaction), and a later re-serve of the same bytes draws a
    /// duplicate rejection the SDK records as success.
    /// - Parameters:
    ///   - prepared: the value ``takePreparation(byTxid:)`` returned for this submission.
    ///   - result: the submission's outcome, in the engine's own vocabulary.
    /// - Throws: ``ZcashError/rustMigrationRecordTransferResult(_:)`` when `prepared` names a
    ///   transfer or a transaction the stored run does not carry, and for rust-layer failures of
    ///   the record itself.
    func recordPreparationBroadcast(
        _ prepared: PreparedMigrationTransfer,
        result: MigrationTransferResult
    ) async throws {
        // The gate reads the engine's own public status view rather than trusting the caller's
        // DTO: `PreparedMigrationTransfer` is a plain value type, so its `id` is an assertion, not
        // a capability. This is the same question the accessor's gate asks of a txid, asked of an
        // id.
        let statuses = try await welding.migrationTransactionStatuses(for: accountUUID)
        guard let row = statuses.first(where: { $0.id == prepared.id }) else {
            throw ZcashError.rustMigrationRecordTransferResult(
                "no migration transaction with id \(prepared.id) is stored, so its broadcast cannot be recorded"
            )
        }
        guard case MigrationTransactionStatus.Kind.preparation = row.kind else {
            throw ZcashError.rustMigrationRecordTransferResult(
                """
                migration transaction \(prepared.id) is a transfer, not a preparation: transfers \
                are served by the drive's broadcast instruction alone, and their outcome is \
                recorded by that broadcast
                """
            )
        }

        try await welding.migrationRecordTransferResult(transferId: prepared.id, result: result, for: accountUUID)
    }

    /// Broadcasts the transaction `instruction` names and returns the recorded outcome.
    ///
    /// THE INSTRUCTION IS THE AUTHORITY: this never advances the drive and never chooses a
    /// transaction. A ``MigrationBroadcastInstruction`` exists only because a
    /// ``advanceStep()`` crank returned
    /// ``MigrationAdvanceStep/broadcast(_:)`` (its initializer is internal), so holding one IS the
    /// proof that the re-spread, the satisfiability verification and the dueness judgement already
    /// happened. There is consequently no "nothing due" and no "awaiting proof" outcome to report:
    /// the driver saw the step itself.
    ///
    /// Composition (identical to ``submitNoteSplit(proposal:usk:options:)``'s, which shares the
    /// same private helper): serve the named transaction's already-finalized bytes through the
    /// store's atomic broadcast seam, broadcast once under the in-flight marker, and record the
    /// mapped result. Transport/rejection outcomes are RETURNED, not thrown.
    ///
    /// - Throws: a pre-broadcast failure throws untouched and nothing is recorded — a fail-closed
    ///   ``ZcashError/migrationTorUnavailable`` when `options.useTor` is set and Tor cannot be
    ///   established, or the seam's STALENESS refusal
    ///   (``ZcashError/rustMigrationTakeBroadcastTransaction(_:)``) of a row that is no longer
    ///   proved-and-servable. The staleness throw is the honest answer to a stale instruction —
    ///   discharge it by cranking ``advanceStep()`` again rather than retrying the executor. A
    ///   record failure *after* a successful broadcast throws
    ///   ``ZcashError/migrationRecordFailedAfterBroadcast(_:)`` — the broadcast DID land; the
    ///   failure is transient from the migration's point of view, because a later execution window
    ///   self-heals (re-submitting draws a duplicate rejection, which records as success).
    ///
    /// Broadcast flows are single-flight on this actor: when another broadcast-performing call
    /// (this method or ``submitNoteSplit(proposal:usk:options:)``) is in flight, this call first
    /// waits for it to finish and only then serves — so a concurrent call can never re-broadcast
    /// the in-flight transfer's bytes. It never throws on contention. A concurrent caller holding
    /// the SAME instruction meets the seam's staleness refusal once the first flow has recorded,
    /// which is the engine's per-row state gating doing exactly the job the removed re-advance
    /// used to do here.
    ///
    /// - Important: This method must run only in a session that does **not** also sync. This actor
    ///   does not check sync state itself; the `Synchronizer` surface in front of it adds an
    ///   advisory point-in-time guard (``ZcashError/migrationBroadcastDuringSync``) plus the
    ///   privacy gate (see ``isSyncBlocked()``) — neither is a hard mutual-exclusion
    ///   lock, so hosts must still sequence sync and broadcast sessions.
    func performBroadcast(
        _ instruction: MigrationBroadcastInstruction,
        options: MigrationNetworkPrivacyOptions
    ) async throws -> MigrationTransferResult {
        try await serializedBroadcastFlow { () async throws -> MigrationTransferResult in
            let prepared = try await welding.migrationTakeBroadcastTransaction(id: instruction.id, for: accountUUID)
            return try await broadcastAndRecord(prepared: prepared, options: options)
        }
    }

    // MARK: - Chain-tip estimation
    //
    // The public estimated-tip members (`estimatedMigrationChainTip()` /
    // `estimatedMigrationSecondsPerBlock()`) are WALLET-scoped, not account-scoped, so they live
    // on `OrchardMigrationHost` rather than on this per-account actor; this actor consults the
    // same shared `MigrationTipEstimation` composition only for its gate/delivery due-ness
    // checks below.

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
    /// Composition: sign the split (which serves the first preparation back as a finalized
    /// transaction through the store's broadcast seam), broadcast once under the in-flight marker,
    /// and record the mapped result. A transport failure or a server rejection is *returned* as a
    /// ``MigrationTransferResult``, not thrown.
    ///
    /// Throws: a pre-broadcast failure throws untouched (a signing error, or
    /// ``ZcashError/migrationTorUnavailable`` when `options.useTor` is set and Tor cannot be
    /// established — nothing was broadcast and nothing is recorded). A record failure *after* a
    /// successful broadcast throws ``ZcashError/migrationRecordFailedAfterBroadcast(_:)`` — the
    /// broadcast DID land; the failure is transient from the migration's point of view, because a
    /// later execution window self-heals (re-submitting draws a duplicate rejection, which records
    /// as success).
    ///
    /// Broadcast flows are single-flight on this actor: when another broadcast-performing call
    /// (this method or ``performBroadcast(_:options:)``) is in flight, this call first waits
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
        let amount = proposal.totalSpendValue() - fee
        return ImmediateMigrationProposal(proposal: proposal, amount: amount, fee: fee)
    }

    /// Records a broadcast immediate-migration sweep. The immediate lane surfaces ONLY through
    /// ``migrationProgress()`` — no engine state machine is involved: while the recorded sweep is
    /// unmined and unexpired, progress reports a `0` of `1` snapshot flagged
    /// ``MigrationProgress/isImmediate``; once it mines (consumed) or expires (the offer
    /// re-arms), progress reports `nil`. Not broadcast-performing itself (the broadcast rides
    /// the ordinary `createProposedTransactions`/`createTransactionFromPCZT` pipeline, already
    /// guarded there) -- this only records the outcome, so it is not gated by
    /// ``serializedBroadcastFlow(_:)``.
    func recordImmediateMigration(txid: Data) async throws {
        try await welding.migrationRecordImmediateRun(txid: txid, for: accountUUID)
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

    // MARK: - Sync coordination

    /// Whether ordinary wallet sync should currently be paused for this migration.
    ///
    /// `true` only while a submission is IN FLIGHT — the seconds between a migration submit
    /// reaching the network and its outcome being recorded. Nothing timed remains: a fixed
    /// post-broadcast delay is an identifiable pattern, so the gate is behavior-based (see
    /// `MigrationSyncGate`'s type doc). A user action that requires sync is never held here.
    ///
    /// - Note: The gate is per-account (by file name). An app running several migrating accounts must
    ///   consult each account's `OrchardMigration`; this instance answers only for its bound account.
    func isSyncBlocked() async -> Bool {
        syncGate.currentlyBlocked()
    }

    /// A stream of ``isSyncBlocked()``: emits the current value on subscribe, re-evaluates every 15 s
    /// (and at the in-flight marker's own expiry), and after every arm/clear of that marker, and
    /// collapses consecutive duplicates.
    ///
    /// `nonisolated` so sync-gating UI/logic can subscribe without awaiting the actor; it is backed by
    /// the internally synchronized ``MigrationSyncGate``: concurrent recomputes (the ticker and every
    /// marking-triggered re-evaluation) publish through one lock-guarded, generation-ordered funnel, so a
    /// recompute that started earlier but finishes later after a fresher one already published is
    /// dropped rather than emitted — subscribers only ever see values in latest-wins order, never a
    /// stale one overwriting a fresher one.
    ///
    /// - Important: The value delivered synchronously on subscribe is EXACT — the gate's input is
    ///   entirely its one persisted instant (see ``MigrationSyncGate``), so there is no caveat
    ///   about a briefly-wrong first emission. A subscriber that wants a belt anyway may still
    ///   pair this stream with an initial ``isSyncBlocked()`` call rather than trusting the seed
    ///   alone.
    nonisolated var syncBlockedStream: AnyPublisher<Bool, Never> {
        syncGate.blockedStream
    }

    /// The sync gate's LIVE in-memory input — the (clamped) in-flight marker expiry — for the
    /// host's wallet-scope predicate (A8): the gate persists file-first, but a FAILED file write
    /// still updates the cache, so the wallet-scope reader must consult this live view alongside
    /// the file and let blocked win, or a full disk (or any write failure) would silently blind it
    /// to a mark this process just made. `nonisolated` (the gate is internally lock-synchronized)
    /// so the host can read it without awaiting the actor.
    nonisolated func liveInFlightUntil() -> Date? {
        syncGate.currentInFlightUntil()
    }

    // MARK: - On-launch reconciliation

    /// Whether any scheduled transfer is past its send height but not yet broadcast — the "is
    /// there actionable work" query, counting an already-proved due transaction AND a due,
    /// dependency-satisfied `Signed` one that still needs its proof. An informational query for
    /// hosts (re-arm background execution, launch reconciliation) and for the app's est-aware
    /// dispatch; deliberately NOT consulted by any sync-gate path — since 2026-08-05 NO
    /// work-pending query is (see ``isSyncBlocked()``). It is a READ, never a substitute for
    /// ``advanceStep()``: it says whether cranking is worth the wake-up, never what to do.
    ///
    /// `useEstimatedTip` opts the check into the wall-clock chain-tip estimate: the estimate may
    /// only ACCELERATE due-ness (expiry stays scanned-tip), and an estimator failure degrades to
    /// the scanned-tip behavior — the same plumbing ``advanceStep()`` always applies.
    func hasOverdueTransfers(useEstimatedTip: Bool) async throws -> Bool {
        let estimatedTip = useEstimatedTip ? await MigrationTipEstimation.gatingEstimatedTip(welding: welding, now: now()) : nil
        return try await welding.migrationHasOverdueTransfers(for: accountUUID, estimatedTip: estimatedTip)
    }

    /// Whether the migration is in an invalid state (spendable Orchard remains but no scheduled
    /// transfer covers it).
    func hasInvalidTransfers() async throws -> Bool {
        try await welding.migrationHasInvalidTransfers(for: accountUUID)
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
    /// returns the run's FULL transfer schedule as stored AFTER the refresh (the current stored
    /// schedule when nothing had expired; empty when no run is stored or the run is terminal).
    ///
    /// Each rebuilt transfer re-spends the SAME funding note (recovered from the expired PCZT by
    /// nullifier identity, never an equal-value substitute) on a fresh schedule — a fresh
    /// memoryless delay from the current tip, a fresh canonical expiry, and a freshly drawn
    /// boundary anchor. The rebuilt rows' fresh scheduled/expiry heights exist nowhere but in the
    /// returned schedule — the atomically-persisted post-refresh truth the host must re-display.
    /// Once a run is stored (as it must be, to have anything to refresh), every subsequent
    /// commit-shaped call (``signAndStoreMigrationSchedule(_:usk:)``,
    /// ``createUnsignedNoteSplitPCZTs(for:)``, ``createUnsignedTransferPCZTs(for:)``) resumes it
    /// handle-free — the `schedule` argument identifies nothing at that point, so it is the stored
    /// run itself (already refreshed) that the external-signer ceremony converges on, not a
    /// comparison against whatever copy the host happens to pass. Passing a spending key signs each
    /// rebuilt transfer anew in-process; passing `nil` (an external-signer account, whose spend
    /// authority never exists on this device) leaves it awaiting its signature, so the
    /// ``createUnsignedTransferPCZTs(for:)`` / ``storeSignedSchedulePCZTs(_:)`` ceremony
    /// re-serves and completes it.
    /// - Throws: notably, a `FundingNoteUnavailable`-class failure when an expired transfer's exact
    ///   funding note was spent outside the migration, where the message names
    ///   ``restartCurrentMigrationStep()`` (cancel and re-plan) as the remedy. Rebuilds are
    ///   persisted ALL-OR-NOTHING: a mid-refresh throw (including this one) persists NONE of the
    ///   batch's rebuilds, so a non-throwing return's schedule is exactly what was atomically
    ///   persisted, never a partial batch.
    func refreshStaleTransfers(usk: UnifiedSpendingKey?) async throws -> MigrationSchedule {
        try await welding.migrationRefreshStaleTransfers(usk: usk, for: accountUUID)
    }

    // MARK: - External signing (PCZT)

    /// Builds the whole previewed migration UNSIGNED — the run is created by this call — and
    /// returns the preparation (note-split) subset of its PCZTs for the signing ceremony. The
    /// transfer subset of the same build is served by ``createUnsignedTransferPCZTs(for:)``, so one
    /// ceremony signs everything. Resumes a stored non-terminal run handle-free; replaces a
    /// terminal one. Only `schedule.proposalHandle` crosses to the native side, and only when this
    /// call is the one creating the run — the display fields are never echoed back.
    func createUnsignedNoteSplitPCZTs(for schedule: MigrationSchedule) async throws -> [MigrationUnsignedTransferPczt] {
        try await welding.migrationCreateUnsignedNoteSplitPczts(for: schedule, for: accountUUID)
    }

    /// Applies the ceremony's signatures to the run's preparation (note-split) transactions,
    /// all-or-nothing, and returns a STORAGE RECEIPT for the first one (its `txid` is zeroed — the
    /// broadcastable, proven value is served by ``performBroadcast(_:options:)``, once a crank
    /// names it).
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
    /// for the whole broadcast (a Tor bootstrap can take seconds), while the drive keeps naming the
    /// same transfer for broadcast until its result is recorded — so without this guard, a
    /// concurrent `performBroadcast`/`submitNoteSplit` could re-fetch and re-broadcast the
    /// same bytes mid-flight. The serialization contract:
    /// - A concurrent caller never throws on contention and is never dropped: it awaits the
    ///   in-flight flow's completion (success or failure), then runs its own flow fresh, so its own
    ///   serve meets the state the finished flow recorded (for the same instruction, the seam's
    ///   staleness refusal).
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

    /// Shared broadcast/record composition for a prepared transfer: broadcast its already-finalized
    /// bytes once to the resolved endpoint, and classify the outcome. A record failure after a
    /// successful broadcast throws ``ZcashError/migrationRecordFailedAfterBroadcast(_:)``.
    /// Non-success outcomes are recorded first and returned; a record throw on that path clears
    /// the in-flight marker first only for a DEFINITIVE rejection (`.expired`/`.invalidNote` —
    /// the server's answer proves nothing landed, so the window is over), while a `.networkError`
    /// record throw keeps the marker (protective: a transport failure cannot prove the submit did
    /// not land, exactly the ambiguity the marker exists for) — the raw record error rethrows
    /// either way. Only pre-broadcast failures throw untouched.
    ///
    /// The whole submit-to-record window is bracketed by the sync gate's persisted in-flight
    /// marker (``MigrationSyncGate/markBroadcastInFlight()``) — the gate's ONLY condition, and the
    /// only sync hold a broadcast produces: armed before the flow as a belt, RE-armed at the last
    /// instant before the submit RPC via the broadcaster's `onWillSubmit` hook (A9 — after the Tor
    /// bootstrap/connection setup, which can take many seconds and would otherwise burn the
    /// marker's 120 s window before anything reached the network), and cleared once the outcome is
    /// recorded — or immediately when the broadcaster throws before submitting anything (its
    /// fail-closed contract: a throw means nothing reached the network). Once cleared, sync is
    /// open again immediately; no timed spacing follows a broadcast (see
    /// ``MigrationSyncGate``'s type doc for the rationale). A crash — or a record throw the rules
    /// above retain it for — between submit and record leaves the marker behind, and it
    /// self-expires at ``MigrationSyncGate/broadcastInFlightGuardDuration`` (120 s), a
    /// crash-recovery ceiling rather than a privacy interval; while it lives, sync (and with it
    /// the reconciliation probe that must not observe a just-broadcast transfer) stays blocked.
    private func broadcastAndRecord(
        prepared: PreparedMigrationTransfer,
        options: MigrationNetworkPrivacyOptions
    ) async throws -> MigrationTransferResult {
        // Both producers that reach here — the delivery executor and the note-split ceremony —
        // serve through the store's atomic broadcast seam, so `prepared.pczt` is ALREADY the
        // finalized consensus transaction. There is no extract step: the wallet's own record of
        // this transaction was written in the same database transaction that produced these bytes.
        let rawTransaction = prepared.pczt

        // Arm the in-flight marker before the submit can reach the network (belt); the
        // broadcaster's onWillSubmit hook re-arms it at the last pre-submit instant so the 120 s
        // window covers the actual submit-to-record span rather than the Tor bootstrap. A crash
        // from the submit until the record lands leaves it to self-expire.
        syncGate.markBroadcastInFlight()

        let outcome: MigrationBroadcastOutcome
        do {
            let syncGate = self.syncGate
            outcome = try await broadcaster.broadcast(
                rawTransaction: rawTransaction,
                to: options.submissionEndpoint,
                useTor: options.useTor,
                onWillSubmit: { syncGate.markBroadcastInFlight() }
            )
        } catch {
            // The broadcaster throws only when nothing was submitted (fail-closed Tor, a
            // pre-connect failure): nothing is in flight, so clear the marker rather than
            // leaving sync blocked for the full self-expiry window.
            syncGate.clearBroadcastInFlight()
            throw error
        }

        let result = MigrationBroadcaster.map(outcome: outcome, successTxId: prepared.txid.toHexStringTxId())
        if case MigrationTransferResult.success = result {
            // The broadcast landed (or a duplicate rejection proved an earlier one did). Nothing
            // is armed here: the gate is behavior-based, so a completed broadcast leaves behind
            // no timed hold at all — only the in-flight marker above, which the record below
            // releases. (Until 2026-08-07 a post-broadcast privacy buffer started here, with a D2
            // carve-out that exempted note preparations from it; both are gone with the buffer.)
            do {
                try await welding.migrationRecordTransferResult(transferId: prepared.id, result: result, for: accountUUID)
            } catch {
                // Deliberately NOT clearing the in-flight marker: the result was never recorded,
                // which is exactly the submit-to-record gap the marker guards; it self-expires.
                logger.error("OrchardMigration: failed to record a successfully submitted broadcast: \(error)")
                throw ZcashError.migrationRecordFailedAfterBroadcast(error)
            }
        } else {
            do {
                try await welding.migrationRecordTransferResult(transferId: prepared.id, result: result, for: accountUUID)
            } catch {
                // A11: the record failed, so the engine still thinks the transfer is pending.
                // For a DEFINITIVE rejection the server's answer proves nothing landed — the
                // submit-to-record ambiguity is over, so clear the marker rather than blocking
                // sync for the full self-expiry window. A network error proves nothing (the
                // submit may have landed and the response been lost), so the marker stays —
                // mirroring the success path's retained-marker rationale above.
                switch result {
                case .expired, .invalidNote:
                    syncGate.clearBroadcastInFlight()
                case .networkError, .success:
                    break
                }
                throw error
            }
        }

        // The outcome is durably recorded: the submit-to-record window is closed.
        syncGate.clearBroadcastInFlight()
        return result
    }
}

// MARK: - Account-free static utilities

// Hosted in an extension rather than the actor body: neither touches per-account state (both take
// everything they need as parameters), so they sit with the actor for discoverability without
// growing its stateful core.
extension OrchardMigration {
    /// The order-preserving session split behind the synchronizers' account-free
    /// `batchMigrationPcztsForSigning(_:maxActionsPerSession:)`: the welding computes
    /// the per-session COUNTS from the rows' action weights (`MigrationUnsignedTransferPczt.actions`;
    /// upstream `NextFit` — order-preserving greedy, never the estimate's reorder-free optimal
    /// packing), and this re-slices the caller's own ordered array by them, so ids/bytes never
    /// round-trip through the FFI. Static (welding passed in) because the split is account-free —
    /// it weighs caller-held rows, never the wallet database — so it has no per-account instance
    /// counterpart on this actor.
    static func batchPcztsForSigning(
        welding: ZcashRustBackendWelding,
        pczts: [MigrationUnsignedTransferPczt],
        maxActionsPerSession: Int
    ) async throws -> [[MigrationUnsignedTransferPczt]] {
        // A row's `actions` weight outside `UInt32`'s range can only be a caller-constructed
        // value (the CREATE/RE-SERVE rows carry 16/3): reject it as the same caller bug the
        // welding reports for a wrong weight, never trap on the conversion (A7).
        let actionWeights = try pczts.map { pczt -> UInt32 in
            guard let actions = UInt32(exactly: pczt.actions) else {
                throw ZcashError.rustMigrationBatchPcztsByActions(
                    "`batchPcztsForSigning` was given a PCZT row whose `actions` weight (\(pczt.actions)) is outside the FFI's UInt32 range"
                )
            }
            return actions
        }

        let sizes = try await welding.migrationBatchPcztsByActions(
            actions: actionWeights,
            maxActionsPerSession: maxActionsPerSession
        )

        // The FFI contract guarantees the per-session counts sum to the input length; guard it
        // anyway (defensive, like the marshal-layer decode guards) so a drift can never crash the
        // re-slice below with an out-of-bounds range.
        guard sizes.reduce(0, +) == pczts.count else {
            throw ZcashError.rustMigrationBatchPcztsByActions(
                "`migrationBatchPcztsByActions` returned session sizes that do not sum to the batch size"
            )
        }

        var sessions: [[MigrationUnsignedTransferPczt]] = []
        sessions.reserveCapacity(sizes.count)
        var nextIndex = 0
        for size in sizes {
            sessions.append(Array(pczts[nextIndex ..< nextIndex + size]))
            nextIndex += size
        }
        return sessions
    }
}
