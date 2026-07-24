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
    /// Whether this snapshot belongs to the immediate (single-transaction) send-max migration lane
    /// rather than an engine-tracked schedule. The app uses it to keep the immediate aftermath
    /// quiet (no per-transfer progress UI). Engine-tracked runs report `false`.
    public let isImmediate: Bool

    /// Creates a `MigrationProgress`.
    public init(
        completedTransfers: Int,
        totalTransfers: Int,
        remainingOrchard: Zatoshi,
        nextTransferReadyAtHeight: BlockHeight?,
        isImmediate: Bool = false
    ) {
        self.completedTransfers = completedTransfers
        self.totalTransfers = totalTransfers
        self.remainingOrchard = remainingOrchard
        self.nextTransferReadyAtHeight = nextTransferReadyAtHeight
        self.isImmediate = isImmediate
    }
}

/// One migration transaction's LIVE status, as the engine computes it — an element of the array
/// returned by `ZcashRustBackendWelding.migrationTransactionStatuses(for:)` /
/// `Synchronizer.migrationTransactionStatuses(accountUUID:)`. A verbatim marshal of the engine's
/// own `MigrationState::transaction_statuses`: nothing here is derived independently of the
/// engine's view, and it is reconciled against mined transactions at every read (the same
/// read-path convention as `MigrationState`), so a transaction the wallet's own scan has since
/// observed mined is reported `.mined` here even if the stored run still marks it broadcast.
public struct MigrationTransactionStatus: Equatable, Sendable {
    /// This transaction's kind: a note-PREPARATION at a given dependency-layer/index, or a
    /// phase-2 pool-crossing TRANSFER at a given funding-note crossing index.
    public enum Kind: Equatable, Sendable {
        /// A note-preparation transaction: `layer` is its dependency-layer index, `index` its
        /// position within that layer.
        case preparation(layer: Int, index: Int)
        /// A pool-crossing transfer: `crossing` is its funding-note crossing index.
        case transfer(crossing: Int)
    }

    /// This transaction's lifecycle state. `broadcast`/`mined` fold the engine's `txid`/
    /// `mined_height` payloads into the matching case, so illegal combinations (a mined row still
    /// carrying a broadcast txid, or a broadcast row with none) are unrepresentable.
    ///
    /// - Note: A MINED row's txid is NOT carried by this state model: the engine's own `Mined`
    ///   state carries only the height, so the txid is available only while a transaction is
    ///   in flight (`.broadcast`), not once it is mined. A caller that needs a mined
    ///   transaction's id should look it up through transaction history instead.
    public enum State: Equatable, Sendable {
        /// Built but not yet signed.
        case awaitingSignature
        /// Signed but not yet proven.
        case signed
        /// Proven and ready to broadcast.
        case proved
        /// Broadcast to the network as `txid` (the SDK's raw/internal byte order), not yet
        /// observed mined.
        case broadcast(txid: Data)
        /// Mined at `height`.
        case mined(height: BlockHeight)
    }

    /// The action available now, when `isReady` is `true`.
    public enum NextAction: Equatable, Sendable {
        /// Signed and ready to be proven.
        case prove
        /// Proven and ready to be broadcast.
        case broadcast
    }

    /// Why this transaction is not yet actionable, when it is waiting (and not already broadcast
    /// or mined).
    public enum Blocker: Equatable, Sendable {
        /// Waiting on another transaction of the same run it depends on.
        case dependencies
        /// Waiting for its scheduled height.
        case schedule
        /// Waiting for a boundary anchor it can prove against.
        case anchorBoundary
        /// Waiting for its signature.
        case signature
        /// Its expiry height has elapsed.
        case expired
    }

    /// This transaction's stable id (the engine's own raw ordinal). Stable across reads and
    /// across a stale-transfer rebuild (a rebuilt transfer keeps its id; only its state and
    /// heights change), so a wallet may use it as a durable row key. It is the same ordinal the
    /// schedule surfaces carry as their opaque string id — `String(status.id)` equals
    /// ``MigrationTransferProposal/id`` / ``PreparedMigrationTransfer/id`` for the same
    /// transaction — so status rows (which carry no amount) join to their schedule row by id.
    public let id: UInt32
    /// This transaction's kind and per-kind payload.
    public let kind: Kind
    /// This transaction's lifecycle state.
    public let state: State
    /// The height at or after which this transaction is due to broadcast.
    public let scheduledHeight: BlockHeight
    /// The height after which this transaction can no longer be mined (ZIP 203); `nil` when it
    /// never expires (the engine's own `0` sentinel).
    public let expiryHeight: BlockHeight?
    /// Whether the wallet can act on this transaction right now.
    public let isReady: Bool
    /// The action available now, when `isReady` is `true`; `nil` otherwise.
    public let nextAction: NextAction?
    /// Why this transaction is not yet actionable, when waiting (and not already broadcast or
    /// mined); `nil` otherwise.
    public let blockedOn: Blocker?

    /// Creates a `MigrationTransactionStatus`.
    public init(
        id: UInt32,
        kind: Kind,
        state: State,
        scheduledHeight: BlockHeight,
        expiryHeight: BlockHeight?,
        isReady: Bool,
        nextAction: NextAction?,
        blockedOn: Blocker?
    ) {
        self.id = id
        self.kind = kind
        self.state = state
        self.scheduledHeight = scheduledHeight
        self.expiryHeight = expiryHeight
        self.isReady = isReady
        self.nextAction = nextAction
        self.blockedOn = blockedOn
    }
}

/// The optimal note split proposed for the spendable Orchard balance, as returned by
/// `ZcashRustBackendWelding.migrationPrepareNoteSplit(for:)`.
public struct NoteSplitProposal: Equatable, Sendable {
    /// The per-note output values of the proposed split transaction.
    public let outputNotes: [Zatoshi]
    /// The fee paid by the split transaction itself.
    public let fee: Zatoshi
    /// Opaque identifier of the SDK-native cached migration plan this proposal was rendered
    /// from. The plan's details never leave the native side: commit calls pass the handle back,
    /// and the native side refuses to sign any plan other than the one it identifies — throwing
    /// `migrationPlanStale` when a later propose/prepare call superseded it, so what gets signed
    /// is always exactly what the user reviewed. `0` means no plan was cached (the empty
    /// nothing-to-migrate proposal).
    public let proposalHandle: UInt64

    /// Creates a `NoteSplitProposal`.
    public init(outputNotes: [Zatoshi], fee: Zatoshi, proposalHandle: UInt64) {
        self.outputNotes = outputNotes
        self.fee = fee
        self.proposalHandle = proposalHandle
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
/// `ZcashRustBackendWelding.migrationProposeTransfers(for:)` and related calls.
///
/// `Codable` so the platform can cache the confirmed schedule (e.g. while awaiting an external
/// signer) without re-deriving it from the engine.
public struct MigrationSchedule: Equatable, Sendable, Codable {
    /// The scheduled transfers, in execution order.
    public let transfers: [MigrationTransferProposal]
    /// A rough estimate of how long the schedule takes to fully execute, in hours.
    public let estimatedDurationHours: Int
    /// Opaque identifier of the SDK-native cached plan this schedule was rendered from — see
    /// `NoteSplitProposal.proposalHandle` for the contract. The transfer fields above are for
    /// display; commit calls pass only this handle back, so the native side signs exactly the
    /// identified plan. `0` means no cached plan backs this schedule (the empty
    /// nothing-to-migrate answer, or a schedule read from the already-committed stored run —
    /// which commit calls resume without consulting a handle). A schedule decoded from a
    /// PERSISTED copy also carries `0`: the native cache is process-lifetime, so a persisted
    /// schedule can never identify a live plan — re-propose instead of committing it.
    public let proposalHandle: UInt64

    /// Creates a `MigrationSchedule`.
    public init(transfers: [MigrationTransferProposal], estimatedDurationHours: Int, proposalHandle: UInt64) {
        self.transfers = transfers
        self.estimatedDurationHours = estimatedDurationHours
        self.proposalHandle = proposalHandle
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.transfers = try container.decode([MigrationTransferProposal].self, forKey: .transfers)
        self.estimatedDurationHours = try container.decode(Int.self, forKey: .estimatedDurationHours)
        // Absent in copies persisted before the handle existed — and a persisted handle could
        // not identify a live plan anyway (the native cache is process-lifetime), so `0` ("no
        // plan") is the honest decode either way.
        self.proposalHandle = try container.decodeIfPresent(UInt64.self, forKey: .proposalHandle) ?? 0
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
}

/// An unsigned-but-proven PCZT for one scheduled transfer, awaiting an external signer (see
/// `ZcashRustBackendWelding.migrationCreateUnsignedTransferPczts(for:for:)`).
public struct MigrationUnsignedTransferPczt: Equatable, Sendable {
    /// The transfer's id.
    ///
    /// Engine-produced PCZTs carry the engine's numeric id, and the two signed-PCZT STORE calls
    /// (`storeSignedNoteSplitPCZTs` / `storeSignedMigrationSchedulePCZTs`) require exactly that —
    /// they look the transaction up by it. The Keystone batch-signing bridge, by contrast, treats
    /// this as an OPAQUE caller-side correlation label: `applyKeystoneBatchSignatures` never
    /// parses or looks it up, it only echoes it back onto the returned signed pairs positionally,
    /// so callers may carry any string through the signing ceremony (e.g. a sentinel-prefixed
    /// id) as long as what ultimately reaches a store call is the bare engine id.
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
    /// The transfer's id (must match the corresponding `MigrationUnsignedTransferPczt.id` — see
    /// that property's doc for the engine-numeric-vs-opaque split: the STORE calls consuming this
    /// type require the bare engine-numeric id, while `applyKeystoneBatchSignatures` produces
    /// these pairs with whatever ids it was given, echoed back verbatim).
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

/// A signing device's firmware version, as reported in a Keystone batch-signing response envelope
/// (see `KeystoneBatchDecodeResult.firmwareVersion`).
///
/// `Comparable` lexicographically (major, then minor, then build) so a host can gate a feature on
/// a minimum device firmware version.
public struct KeystoneFirmwareVersion: Equatable, Sendable, Comparable {
    public let major: UInt8
    public let minor: UInt8
    public let build: UInt8

    /// Creates a `KeystoneFirmwareVersion`.
    public init(major: UInt8, minor: UInt8, build: UInt8) {
        self.major = major
        self.minor = minor
        self.build = build
    }

    public static func < (lhs: KeystoneFirmwareVersion, rhs: KeystoneFirmwareVersion) -> Bool {
        if lhs.major != rhs.major {
            return lhs.major < rhs.major
        }
        if lhs.minor != rhs.minor {
            return lhs.minor < rhs.minor
        }
        return lhs.build < rhs.build
    }
}

/// The result of feeding one scanned QR frame to
/// `Synchronizer.decodeKeystoneSignBatchPart(_:expectedRequestId:)`.
///
/// `complete == false` means more frames are needed: `progress` is the 0-100 completion
/// percentage so far, and `data`/`firmwareVersion` are `nil`. `complete == true` means `data`
/// holds the serialized batch-signature response to pass to
/// `Synchronizer.applyKeystoneBatchSignatures(pczts:batchSignResponse:)` -- the response is
/// signatures-only, no PCZT is echoed back by the device.
///
/// - Note: `firmwareVersion` comes from the response envelope itself (the signing device's own
///   reported firmware version), not from any field recovered from a signed PCZT. It is set only
///   once `complete`, and only when the envelope carried it; it is the ONLY way to learn the
///   signing device's firmware version in the batch flow -- `applyKeystoneBatchSignatures`
///   reconstructs each "signed" PCZT from the caller's own retained unsigned bytes plus the
///   response's signatures, never from device-returned PCZT bytes, so there is no PCZT-embedded
///   firmware stamp to fall back on here (unlike the single-transaction Keystone sign flow).
public struct KeystoneBatchDecodeResult: Equatable, Sendable {
    /// Whether the full multi-part response has been decoded. `false` means feed more frames.
    public let complete: Bool
    /// The 0-100 decode completion percentage. Meaningful while `!complete`; `100` once complete.
    public let progress: Int
    /// The serialized batch-signature response, once `complete`; `nil` otherwise.
    public let data: Data?
    /// The signing device's reported firmware version, once `complete` and when the response
    /// envelope carried it; `nil` otherwise. See this type's provenance note above.
    public let firmwareVersion: KeystoneFirmwareVersion?

    /// Creates a `KeystoneBatchDecodeResult`.
    public init(complete: Bool, progress: Int, data: Data?, firmwareVersion: KeystoneFirmwareVersion?) {
        self.complete = complete
        self.progress = progress
        self.data = data
        self.firmwareVersion = firmwareVersion
    }
}
