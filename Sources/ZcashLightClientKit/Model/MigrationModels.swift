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
