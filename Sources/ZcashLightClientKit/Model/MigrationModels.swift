//
//  MigrationModels.swift
//  ZcashLightClientKit
//

import Foundation

/// The top-level Orchard -> Ironwood migration state machine surfaced to the app.
///
/// The app fetches this via `ZcashRustBackendWelding.migrationState(for:)` on launch and after
/// every migration-related operation; it is the reconciliation hub for driving the migration UI.
public enum MigrationState: Equatable, Sendable {
    /// No migration run is stored: none was started, or a previous run was cancelled.
    case notStarted
    /// The run is committed and its preparation (note-split) transactions are not yet all mined.
    case splitPendingConfirmation
    /// Never emitted by the final engine (the note split and the transfer schedule commit
    /// atomically, so the v1 "split confirmed, schedule pending" moment no longer exists). Kept
    /// for source compatibility.
    case readyToPropose
    /// Preparation is mined and the run's transfers are executing.
    case inProgress(MigrationProgress)
    /// A transfer cannot proceed automatically; the app must act.
    case requiresAttention(MigrationAttentionReason)
    /// Every transaction of the STORED RUN is mined. This is PER-RUN — it does not mean the
    /// account has nothing left to migrate: a large balance can need several successive runs, and
    /// funds received later re-create a migratable balance. After completion, ask
    /// `proposeMigrationTransfers` whether anything remains (an empty schedule means no).
    case complete
}

/// A snapshot of an in-progress migration, as carried by `MigrationState.inProgress` or returned
/// standalone by `ZcashRustBackendWelding.migrationProgress(for:)`.
public struct MigrationProgress: Equatable, Sendable {
    /// The number of scheduled transfers confirmed on-chain so far.
    public let completedTransfers: Int
    /// The total number of transfers in the current schedule.
    public let totalTransfers: Int
    /// The Orchard-pool value not yet migrated to Ironwood: the account's live spendable Orchard
    /// balance (what is still in the old pool), not a run-internal remainder.
    public let remainingOrchard: Zatoshi
    /// The height at which the next transfer becomes broadcastable, or `nil` if none is scheduled.
    public let nextTransferReadyAtHeight: BlockHeight?

    /// Creates a `MigrationProgress`.
    public init(
        completedTransfers: Int,
        totalTransfers: Int,
        remainingOrchard: Zatoshi,
        nextTransferReadyAtHeight: BlockHeight?
    ) {
        self.completedTransfers = completedTransfers
        self.totalTransfers = totalTransfers
        self.remainingOrchard = remainingOrchard
        self.nextTransferReadyAtHeight = nextTransferReadyAtHeight
    }
}

/// The optimal note split proposed for the spendable Orchard balance, as returned by
/// `ZcashRustBackendWelding.migrationPrepareNoteSplit(for:)`.
public struct NoteSplitProposal: Equatable, Sendable {
    /// The per-note output values of the proposed split transaction.
    public let outputNotes: [Zatoshi]
    /// The fee paid by the split transaction itself.
    public let fee: Zatoshi

    /// Creates a `NoteSplitProposal`.
    public init(outputNotes: [Zatoshi], fee: Zatoshi) {
        self.outputNotes = outputNotes
        self.fee = fee
    }
}

/// A single scheduled Orchard -> Ironwood transfer, as one element of a `MigrationSchedule`.
public struct MigrationTransferProposal: Identifiable, Equatable, Sendable, Codable {
    /// The transfer's opaque, engine-issued id.
    public let id: String
    /// The value that crosses the turnstile.
    public let amount: Zatoshi
    /// The "now" reference height at proposal time (the chain tip). With ZIP 374 the real anchor
    /// is drawn per transfer and installed at proving time, so this field is NOT a commitment-tree
    /// anchor; it exists so duration math can measure waits from the proposal's own "now", and for
    /// `Codable` compatibility with previously persisted schedules.
    public let anchorHeight: BlockHeight
    /// The height after which the platform may broadcast this transfer.
    public let nextExecutableAfterHeight: BlockHeight
    /// The height after which this transfer is no longer valid.
    public let expiryHeight: BlockHeight

    /// Creates a `MigrationTransferProposal`.
    public init(
        id: String,
        amount: Zatoshi,
        anchorHeight: BlockHeight,
        nextExecutableAfterHeight: BlockHeight,
        expiryHeight: BlockHeight
    ) {
        self.id = id
        self.amount = amount
        self.anchorHeight = anchorHeight
        self.nextExecutableAfterHeight = nextExecutableAfterHeight
        self.expiryHeight = expiryHeight
    }
}

/// A full migration schedule presented to the user for one-time confirmation, as returned by
/// `ZcashRustBackendWelding.migrationProposeTransfers(includeResidual:for:)` and related calls.
///
/// `Codable` so the platform can cache the confirmed schedule (e.g. while awaiting an external
/// signer) without re-deriving it from the engine.
public struct MigrationSchedule: Equatable, Sendable, Codable {
    /// The scheduled transfers, in execution order.
    public let transfers: [MigrationTransferProposal]
    /// A rough estimate of how long the schedule takes to fully execute, in hours.
    public let estimatedDurationHours: Int

    /// Creates a `MigrationSchedule`.
    public init(transfers: [MigrationTransferProposal], estimatedDurationHours: Int) {
        self.transfers = transfers
        self.estimatedDurationHours = estimatedDurationHours
    }
}

/// An estimate of migrating the account's whole spendable Orchard balance across successive
/// migration RUNS ("rounds"), as returned by
/// `ZcashRustBackendWelding.estimateMigrationRuns(accountUUID:)`.
///
/// A balance beyond one run's capacity (the note cap times the maximum denomination) migrates
/// over several runs; each run carries BOTH what it migrates (the note-split crossings) and what
/// preparing it costs (the note-preparation layers and transactions), so the two can be compared
/// before anything is planned or committed. An external signer's per-session capacity is a query
/// parameter (`Run.signingSessions(maxTransactionsPerSession:)` /
/// `totalSigningSessions(maxTransactionsPerSession:)`), not part of the estimate, so any signer
/// capacity can be evaluated without re-running the planners.
public struct MigrationRunEstimate: Equatable, Sendable {
    /// A per-run entry: what one migration run migrates (the note-split side) and what preparing
    /// it costs (the note-preparation side), so the two can be compared.
    public struct Run: Equatable, Sendable {
        /// The total value that crosses the turnstile in this run (the sum of its crossing
        /// denominations).
        public let migratable: Zatoshi
        /// The number of pool-crossing transfers this run makes: one per self-funding note the
        /// note split produced for it.
        public let crossings: Int
        /// The number of sequential note-preparation layers this run needs — its wall-clock
        /// depth, since each layer waits for the previous one to mine before it can broadcast.
        public let preparationLayers: Int
        /// The number of note-preparation transactions this run builds across all its layers.
        public let preparationTransactions: Int

        /// Creates a `Run`.
        public init(migratable: Zatoshi, crossings: Int, preparationLayers: Int, preparationTransactions: Int) {
            self.migratable = migratable
            self.crossings = crossings
            self.preparationLayers = preparationLayers
            self.preparationTransactions = preparationTransactions
        }

        /// The total number of transactions this run builds and signs: its preparation
        /// transactions plus one pool-crossing transfer per funding note.
        public var transactions: Int {
            preparationTransactions + crossings
        }

        /// The number of signing sessions this run needs when an external signer (for example a
        /// Keystone hardware wallet) can sign at most `maxTransactionsPerSession` transactions in
        /// one interaction: `ceil(transactions / maxTransactionsPerSession)`. All of a run's
        /// transactions are built and signed together (anchors and witnesses are deferred to
        /// proving time, ZIP 374), so they pool into sessions bounded only by the signer's
        /// capacity.
        /// - Precondition: `maxTransactionsPerSession > 0`.
        public func signingSessions(maxTransactionsPerSession: Int) -> Int {
            precondition(maxTransactionsPerSession > 0, "maxTransactionsPerSession must be positive")
            return (transactions + maxTransactionsPerSession - 1) / maxTransactionsPerSession
        }
    }

    /// The per-run estimates, in run order. Empty when nothing migrates (a zero or fully
    /// sub-quantum balance) — a legitimate estimate, not an error.
    public let runs: [Run]
    /// The value left in Orchard after the last run — below the smallest self-funding note, so it
    /// never migrates. `.zero` when the balance divides exactly into self-funding notes and fees.
    public let finalResidual: Zatoshi

    /// Creates a `MigrationRunEstimate`.
    public init(runs: [Run], finalResidual: Zatoshi) {
        self.runs = runs
        self.finalResidual = finalResidual
    }

    /// The expected number of migration runs ("rounds") to migrate the whole balance: zero when
    /// the balance is below the smallest self-funding note, so nothing migrates.
    public var runCount: Int {
        runs.count
    }

    /// The total value that migrates across all runs (the sum of each run's `migratable`).
    public var totalMigratable: Zatoshi {
        runs.reduce(Zatoshi.zero) { $0 + $1.migratable }
    }

    /// The total number of pool-crossing transfers across all runs.
    public var totalCrossings: Int {
        runs.reduce(0) { $0 + $1.crossings }
    }

    /// The total number of note-preparation layers across all runs.
    public var totalPreparationLayers: Int {
        runs.reduce(0) { $0 + $1.preparationLayers }
    }

    /// The total number of note-preparation transactions across all runs.
    public var totalPreparationTransactions: Int {
        runs.reduce(0) { $0 + $1.preparationTransactions }
    }

    /// The total number of transactions the whole migration builds and signs across all runs
    /// (equivalently `totalPreparationTransactions` plus `totalCrossings`).
    public var totalTransactions: Int {
        runs.reduce(0) { $0 + $1.transactions }
    }

    /// The total number of signing sessions the whole migration needs when an external signer can
    /// sign at most `maxTransactionsPerSession` transactions in one interaction — the number of
    /// times the user must interact with a capacity-limited hardware signer.
    ///
    /// This is the SUM of each run's `signingSessions(maxTransactionsPerSession:)`, NOT
    /// `ceil(totalTransactions / maxTransactionsPerSession)`: signing sessions cannot span runs,
    /// because a later run's transactions spend notes an earlier run must mine first, so each run
    /// is signed on its own (any spare capacity in a run's last session goes unused).
    /// - Precondition: `maxTransactionsPerSession > 0`.
    public func totalSigningSessions(maxTransactionsPerSession: Int) -> Int {
        runs.reduce(0) { $0 + $1.signingSessions(maxTransactionsPerSession: maxTransactionsPerSession) }
    }
}

/// The proposal for the immediate (single-transaction) Orchard -> Ironwood migration, as returned
/// by `Synchronizer.proposeImmediateMigration(accountUUID:)`: an ordinary send-max transaction that
/// sweeps the account's whole spendable Orchard balance to its own address. Unlike
/// `MigrationSchedule`, this is held entirely by the caller -- there is no engine plan cache behind
/// it, so nothing about it can go stale beyond the proposal's own validity window.
public struct ImmediateMigrationProposal: Equatable {
    /// The underlying proposal: feed to `Synchronizer.createProposedTransactions(proposal:spendingKey:)`
    /// (software accounts) or `Synchronizer.createPCZTFromProposal(accountUUID:proposal:)` (Keystone
    /// accounts) exactly like any other ordinary transfer.
    public let proposal: Proposal
    /// The net swept amount -- what arrives in the Ironwood pool once mined. The proposal's single
    /// payment value: the account's spendable Orchard notes, minus `fee`.
    public let amount: Zatoshi
    /// The fee this proposal pays, per `Proposal.totalFeeRequired()`.
    public let fee: Zatoshi

    /// Creates an `ImmediateMigrationProposal`.
    public init(proposal: Proposal, amount: Zatoshi, fee: Zatoshi) {
        self.proposal = proposal
        self.amount = amount
        self.fee = fee
    }
}

/// A fully proven, signed migration transaction persisted by the engine, ready for the platform
/// to broadcast (see `ZcashRustBackendWelding.migrationExtractBroadcastTx(pczt:for:)`).
public struct PreparedMigrationTransfer: Equatable, Sendable {
    /// The transfer's opaque, engine-issued id.
    public let id: String
    /// The finalized transaction's id, in the SDK's raw/internal byte order (matching `TxId.id`,
    /// not the reversed display-hex order produced by `Data.toHexStringTxId()`). Zeroed when the
    /// value is a STORAGE RECEIPT (`migrationStoreSignedNoteSplitPczts`) whose transaction has not
    /// been proven yet — the broadcastable value is served by the delivery lane.
    public let txid: Data
    /// The serialized, signed PCZT backing this transfer.
    public let pczt: Data

    /// Creates a `PreparedMigrationTransfer`.
    public init(id: String, txid: Data, pczt: Data) {
        self.id = id
        self.txid = txid
        self.pczt = pczt
    }
}

/// The platform's outcome of broadcasting (or attempting to broadcast) a prepared migration
/// transfer, reported back to the migration engine via
/// `ZcashRustBackendWelding.migrationRecordTransferResult(transferId:result:for:)`.
public enum MigrationTransferResult: Equatable, Sendable {
    /// The transfer was accepted by the network as `txId`.
    ///
    /// `txId` is the display-form hex-encoded transaction id: the same byte order produced by
    /// `Data.toHexStringTxId()` and consumed by `TxId.init(_ id: String)` (reversed relative to
    /// the transaction's raw/internal byte order), matching how the SDK renders txids elsewhere.
    case success(txId: String)
    /// The broadcast failed for a network-level reason; `retryable` indicates whether the
    /// platform should retry the same prepared transfer later.
    case networkError(retryable: Bool)
    /// The transfer's input note was no longer valid (e.g. already spent) at broadcast time.
    case invalidNote
    /// The transfer's anchor/expiry elapsed before it could be broadcast.
    case expired
}

/// Why a migration requires user attention, as carried by `MigrationState.requiresAttention`.
public enum MigrationAttentionReason: Equatable, Sendable {
    /// The input note funding `transferId` was spent externally before its transfer broadcast.
    case invalidTransfer(transferId: String)
    /// A transaction's anchor/expiry elapsed before it could be broadcast.
    case transferExpired
    /// A transfer produced Orchard change that must be synced before the next spend.
    case syncRequiredBeforeNext
}

/// An unsigned-but-proven PCZT for one scheduled transfer, awaiting an external signer (see
/// `ZcashRustBackendWelding.migrationCreateUnsignedTransferPczts(for:for:)`).
public struct MigrationUnsignedTransferPczt: Equatable, Sendable {
    /// The transfer's opaque, engine-issued id.
    public let id: String
    /// The serialized, proven-but-unsigned PCZT.
    public let pczt: Data

    /// Creates a `MigrationUnsignedTransferPczt`.
    public init(id: String, pczt: Data) {
        self.id = id
        self.pczt = pczt
    }
}

/// An externally signed PCZT for one scheduled transfer, to be handed back to the engine via
/// `ZcashRustBackendWelding.migrationStoreSignedSchedulePczts(_:for:)`.
public struct MigrationSignedTransferPczt: Equatable, Sendable {
    /// The transfer's opaque, engine-issued id (must match the corresponding
    /// `MigrationUnsignedTransferPczt.id`).
    public let id: String
    /// The serialized, signed PCZT.
    public let pczt: Data

    /// Creates a `MigrationSignedTransferPczt`. Apps construct this directly after routing the
    /// corresponding `MigrationUnsignedTransferPczt` through an external signer.
    public init(id: String, pczt: Data) {
        self.id = id
        self.pczt = pczt
    }
}
