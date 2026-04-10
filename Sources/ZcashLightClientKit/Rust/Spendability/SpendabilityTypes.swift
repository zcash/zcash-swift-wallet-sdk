// Swift types matching the JSON serde types in spendability.rs and witness.rs.
// All types are Codable for JSON serialization across the FFI boundary.

import Foundation

// MARK: - Result

/// Result of a spendability PIR check.
public struct SpendabilityResult: Codable, Sendable, Equatable {
    /// Earliest block height covered by the PIR database.
    public let earliestHeight: UInt64
    /// Latest block height covered by the PIR database.
    public let latestHeight: UInt64
    /// Note IDs whose nullifiers were found in the PIR database (i.e. spent).
    public let spentNoteIds: [Int64]
    /// Total zatoshi value of notes found spent by PIR.
    public let totalSpentValue: UInt64

    enum CodingKeys: String, CodingKey {
        case earliestHeight = "earliest_height"
        case latestHeight = "latest_height"
        case spentNoteIds = "spent_note_ids"
        case totalSpentValue = "total_spent_value"
    }

    /// Whether any notes were detected as spent by the PIR server.
    /// When true, the wallet should skip witness PIR and fall back to standard scanning.
    public var anySpent: Bool { !spentNoteIds.isEmpty }

    public init(earliestHeight: UInt64, latestHeight: UInt64, spentNoteIds: [Int64], totalSpentValue: UInt64) {
        self.earliestHeight = earliestHeight
        self.latestHeight = latestHeight
        self.spentNoteIds = spentNoteIds
        self.totalSpentValue = totalSpentValue
    }
}

// MARK: - Unspent note

/// An unspent Orchard note with its nullifier, for PIR spend-checking.
public struct PIRUnspentNote: Codable, Sendable, Equatable {
    public let id: Int64
    /// Raw nullifier bytes (32 bytes).
    public let nf: [UInt8]
    public let value: UInt64

    public init(id: Int64, nf: [UInt8], value: UInt64) {
        self.id = id
        self.nf = nf
        self.value = value
    }
}

// MARK: - Spend metadata

/// Per-nullifier metadata returned by the PIR server when a nullifier is found spent.
public struct PIRSpendMetadata: Codable, Sendable, Equatable {
    /// Block height at which the note was spent.
    public let spendHeight: UInt32
    /// Global Orchard commitment-tree position of the first output in the spending transaction.
    public let firstOutputPosition: UInt32
    /// Number of Orchard actions in the spending transaction.
    public let actionCount: UInt8

    enum CodingKeys: String, CodingKey {
        case spendHeight = "spend_height"
        case firstOutputPosition = "first_output_position"
        case actionCount = "action_count"
    }

    public init(spendHeight: UInt32, firstOutputPosition: UInt32, actionCount: UInt8) {
        self.spendHeight = spendHeight
        self.firstOutputPosition = firstOutputPosition
        self.actionCount = actionCount
    }
}

// MARK: - Nullifier check result

/// Result of checking nullifiers against the PIR server.
public struct PIRNullifierCheckResult: Codable, Sendable, Equatable {
    public let earliestHeight: UInt64
    public let latestHeight: UInt64
    /// Parallel to the input nullifiers: non-nil = spent (with metadata), nil = not spent.
    public let spent: [PIRSpendMetadata?]

    enum CodingKeys: String, CodingKey {
        case earliestHeight = "earliest_height"
        case latestHeight = "latest_height"
        case spent
    }

    public init(earliestHeight: UInt64, latestHeight: UInt64, spent: [PIRSpendMetadata?]) {
        self.earliestHeight = earliestHeight
        self.latestHeight = latestHeight
        self.spent = spent
    }
}

// MARK: - Progress

/// Closure type for spendability check progress reporting.
public typealias SpendabilityProgressHandler = @Sendable (Double) -> Void

// MARK: - Note position (input to witness PIR)

/// An Orchard note that needs a PIR witness: has a tree position but the shard
/// containing it is not fully scanned.
public struct PIRNotePosition: Codable, Sendable, Equatable {
    public let id: Int64
    public let position: UInt64
    public let value: UInt64

    public init(id: Int64, position: UInt64, value: UInt64) {
        self.id = id
        self.position = position
        self.value = value
    }
}

// MARK: - Witness entry (output from PIR server / input to DB write)

/// A PIR-obtained witness for a single note. Sibling hashes are hex-encoded
/// 32-byte values ordered leaf-to-root.
public struct PIRWitnessEntry: Codable, Sendable, Equatable {
    public let noteId: Int64
    public let position: UInt64
    /// 32 sibling hashes, each a 64-char hex string (32 bytes).
    public let siblings: [String]
    public let anchorHeight: UInt64
    /// The tree root at `anchorHeight`, as a 64-char hex string.
    public let anchorRoot: String

    enum CodingKeys: String, CodingKey {
        case noteId = "note_id"
        case position
        case siblings
        case anchorHeight = "anchor_height"
        case anchorRoot = "anchor_root"
    }

    public init(
        noteId: Int64,
        position: UInt64,
        siblings: [String],
        anchorHeight: UInt64,
        anchorRoot: String
    ) {
        self.noteId = noteId
        self.position = position
        self.siblings = siblings
        self.anchorHeight = anchorHeight
        self.anchorRoot = anchorRoot
    }
}

// MARK: - Witness fetch result (from PIR server)

/// Result of fetching witnesses from the PIR server.
public struct PIRWitnessResult: Codable, Sendable, Equatable {
    public let witnesses: [PIRWitnessEntry]

    public init(witnesses: [PIRWitnessEntry]) {
        self.witnesses = witnesses
    }
}

// MARK: - Orchestration result (returned to app layer)

/// Result of `fetchNoteWitnesses` — notes for which witnesses were obtained.
public struct WitnessResult: Sendable, Equatable {
    public let witnessedNoteIds: [Int64]
    public let totalWitnessedValue: UInt64

    public init(witnessedNoteIds: [Int64], totalWitnessedValue: UInt64) {
        self.witnessedNoteIds = witnessedNoteIds
        self.totalWitnessedValue = totalWitnessedValue
    }
}
