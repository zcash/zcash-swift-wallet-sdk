// VotingTypes.swift
// Swift types matching the JSON serde types in voting.rs.
// All types are Codable for JSON deserialization across the FFI boundary.

import Foundation

// MARK: - Round State

/// Phase of a voting round.
public enum VotingRoundPhase: UInt32, Codable, Sendable {
    case initialized = 0
    case hotkeyGenerated = 1
    case delegationConstructed = 2
    case delegationProved = 3
    case voteReady = 4
}

/// State of a voting round, decoded from FfiRoundState.
public struct VotingRoundState: Sendable {
    public let roundId: String
    public let phase: VotingRoundPhase
    public let snapshotHeight: UInt64
    public let hotkeyAddress: String?
    public let delegatedWeight: UInt64?
    public let proofGenerated: Bool
}

/// Summary of a voting round for list display.
public struct VotingRoundSummary: Sendable {
    public let roundId: String
    public let phase: VotingRoundPhase
    public let snapshotHeight: UInt64
    public let createdAt: UInt64
}

// MARK: - Hotkey

/// Voting hotkey (secret key, public key, address).
public struct VotingHotkey: Sendable {
    public let secretKey: [UInt8]
    public let publicKey: [UInt8]
    public let address: String
}

// MARK: - Bundle Setup

/// Result of setting up vote bundles.
public struct VotingBundleSetupResult: Sendable {
    public let bundleCount: UInt32
    public let eligibleWeight: UInt64
}

// MARK: - Vote Record

/// Record of a vote for a specific proposal/bundle.
public struct VotingVoteRecord: Sendable {
    public let proposalId: UInt32
    public let bundleIndex: UInt32
    public let choice: UInt32
    public let submitted: Bool
}

// MARK: - Note Info (JSON)

/// Note information for voting eligibility.
public struct VotingNoteInfo: Codable, Sendable {
    public let commitment: [UInt8]
    public let nullifier: [UInt8]
    public let value: UInt64
    public let position: UInt64
    public let diversifier: [UInt8]
    public let rho: [UInt8]
    public let rseed: [UInt8]
    public let scope: UInt32
    public let ufvkStr: String

    enum CodingKeys: String, CodingKey {
        case commitment, nullifier, value, position, diversifier, rho, rseed, scope
        case ufvkStr = "ufvk_str"
    }

    public init(
        commitment: [UInt8],
        nullifier: [UInt8],
        value: UInt64,
        position: UInt64,
        diversifier: [UInt8],
        rho: [UInt8],
        rseed: [UInt8],
        scope: UInt32,
        ufvkStr: String
    ) {
        self.commitment = commitment
        self.nullifier = nullifier
        self.value = value
        self.position = position
        self.diversifier = diversifier
        self.rho = rho
        self.rseed = rseed
        self.scope = scope
        self.ufvkStr = ufvkStr
    }
}

// MARK: - Voting PCZT (JSON)

/// Result of building a voting PCZT.
public struct VotingPczt: Codable, Sendable {
    public let pcztBytes: [UInt8]
    // swiftlint:disable:next identifier_name
    public let rk: [UInt8]
    public let alpha: [UInt8]
    public let nfSigned: [UInt8]
    public let cmxNew: [UInt8]
    public let govNullifiers: [[UInt8]]
    public let van: [UInt8]
    public let vanCommRand: [UInt8]
    public let dummyNullifiers: [[UInt8]]
    public let rhoSigned: [UInt8]
    public let paddedCmx: [[UInt8]]
    public let rseedSigned: [UInt8]
    public let rseedOutput: [UInt8]
    public let actionBytes: [UInt8]
    public let actionIndex: UInt32
    /// Each element is [rho, rseed].
    public let paddedNoteSecrets: [[[UInt8]]]
    public let pcztSighash: [UInt8]

    enum CodingKeys: String, CodingKey {
        case pcztBytes = "pczt_bytes"
        // swiftlint:disable:next identifier_name
        case rk, alpha
        case nfSigned = "nf_signed"
        case cmxNew = "cmx_new"
        case govNullifiers = "gov_nullifiers"
        case van
        case vanCommRand = "van_comm_rand"
        case dummyNullifiers = "dummy_nullifiers"
        case rhoSigned = "rho_signed"
        case paddedCmx = "padded_cmx"
        case rseedSigned = "rseed_signed"
        case rseedOutput = "rseed_output"
        case actionBytes = "action_bytes"
        case actionIndex = "action_index"
        case paddedNoteSecrets = "padded_note_secrets"
        case pcztSighash = "pczt_sighash"
    }
}

// MARK: - Witness Data (JSON)

/// Merkle witness data for a note.
public struct VotingWitnessData: Codable, Sendable {
    public let noteCommitment: [UInt8]
    public let position: UInt64
    public let root: [UInt8]
    public let authPath: [[UInt8]]

    enum CodingKeys: String, CodingKey {
        case noteCommitment = "note_commitment"
        case position, root
        case authPath = "auth_path"
    }

    public init(
        noteCommitment: [UInt8],
        position: UInt64,
        root: [UInt8],
        authPath: [[UInt8]]
    ) {
        self.noteCommitment = noteCommitment
        self.position = position
        self.root = root
        self.authPath = authPath
    }
}

// MARK: - Share Delegation (JSON)

/// Record of a share delegation sent to helper servers.
public struct VotingShareDelegation: Codable, Equatable, Sendable {
    public let roundId: String
    public let bundleIndex: UInt32
    public let proposalId: UInt32
    public let shareIndex: UInt32
    public let sentToURLs: [String]
    public let nullifier: [UInt8]
    public let confirmed: Bool
    public let submitAt: UInt64
    public let createdAt: UInt64

    enum CodingKeys: String, CodingKey {
        case roundId = "round_id"
        case bundleIndex = "bundle_index"
        case proposalId = "proposal_id"
        case shareIndex = "share_index"
        case sentToURLs = "sent_to_urls"
        case nullifier
        case confirmed
        case submitAt = "submit_at"
        case createdAt = "created_at"
    }
}

// MARK: - Delegation Proof Result (JSON)

/// Result of building and proving a delegation.
public struct VotingDelegationProofResult: Codable, Sendable {
    public let proof: [UInt8]
    public let publicInputs: [[UInt8]]
    public let nfSigned: [UInt8]
    public let cmxNew: [UInt8]
    public let govNullifiers: [[UInt8]]
    public let vanComm: [UInt8]
    // swiftlint:disable:next identifier_name
    public let rk: [UInt8]

    enum CodingKeys: String, CodingKey {
        case proof
        case publicInputs = "public_inputs"
        case nfSigned = "nf_signed"
        case cmxNew = "cmx_new"
        case govNullifiers = "gov_nullifiers"
        case vanComm = "van_comm"
        // swiftlint:disable:next identifier_name
        case rk
    }
}

// MARK: - Delegation Submission (JSON)

/// Delegation submission payload.
public struct VotingDelegationSubmission: Codable, Sendable {
    // swiftlint:disable:next identifier_name
    public let rk: [UInt8]
    public let spendAuthSig: [UInt8]
    public let sighash: [UInt8]
    public let nfSigned: [UInt8]
    public let cmxNew: [UInt8]
    public let govComm: [UInt8]
    public let govNullifiers: [[UInt8]]
    public let proof: [UInt8]
    public let voteRoundId: String

    enum CodingKeys: String, CodingKey {
        // swiftlint:disable:next identifier_name
        case rk
        case spendAuthSig = "spend_auth_sig"
        case sighash
        case nfSigned = "nf_signed"
        case cmxNew = "cmx_new"
        case govComm = "gov_comm"
        case govNullifiers = "gov_nullifiers"
        case proof
        case voteRoundId = "vote_round_id"
    }
}

// MARK: - Encrypted Share (JSON)

/// An encrypted vote share.
// MARK: - Vote Commitment Bundle (JSON)

/// A vote commitment bundle produced by ZKP #2.
public struct VotingVoteCommitmentBundle: Codable, Sendable {
    public let vanNullifier: [UInt8]
    public let voteAuthorityNoteNew: [UInt8]
    public let voteCommitment: [UInt8]
    public let proposalId: UInt32
    public let proof: [UInt8]
    public let encShares: [VotingWireEncryptedShare]
    public let anchorHeight: UInt32
    public let voteRoundId: String
    public let sharesHash: [UInt8]
    public let shareBlinds: [[UInt8]]
    public let shareComms: [[UInt8]]
    public let rVpkBytes: [UInt8]
    public let alphaV: [UInt8]

    enum CodingKeys: String, CodingKey {
        case vanNullifier = "van_nullifier"
        case voteAuthorityNoteNew = "vote_authority_note_new"
        case voteCommitment = "vote_commitment"
        case proposalId = "proposal_id"
        case proof
        case encShares = "enc_shares"
        case anchorHeight = "anchor_height"
        case voteRoundId = "vote_round_id"
        case sharesHash = "shares_hash"
        case shareBlinds = "share_blinds"
        case shareComms = "share_comms"
        case rVpkBytes = "r_vpk_bytes"
        case alphaV = "alpha_v"
    }

    public init(
        vanNullifier: [UInt8],
        voteAuthorityNoteNew: [UInt8],
        voteCommitment: [UInt8],
        proposalId: UInt32,
        proof: [UInt8],
        encShares: [VotingWireEncryptedShare],
        anchorHeight: UInt32,
        voteRoundId: String,
        sharesHash: [UInt8],
        shareBlinds: [[UInt8]],
        shareComms: [[UInt8]],
        rVpkBytes: [UInt8],
        alphaV: [UInt8]
    ) {
        self.vanNullifier = vanNullifier
        self.voteAuthorityNoteNew = voteAuthorityNoteNew
        self.voteCommitment = voteCommitment
        self.proposalId = proposalId
        self.proof = proof
        self.encShares = encShares
        self.anchorHeight = anchorHeight
        self.voteRoundId = voteRoundId
        self.sharesHash = sharesHash
        self.shareBlinds = shareBlinds
        self.shareComms = shareComms
        self.rVpkBytes = rVpkBytes
        self.alphaV = alphaV
    }
}

// MARK: - Wire Encrypted Share (JSON)

/// Wire-safe encrypted share — contains only the public ciphertext components.
/// Secrets (plaintextValue, randomness) stay inside Rust and never cross the FFI boundary.
public struct VotingWireEncryptedShare: Codable, Sendable {
    // swiftlint:disable:next identifier_name
    public let c1: [UInt8]
    // swiftlint:disable:next identifier_name
    public let c2: [UInt8]
    public let shareIndex: UInt32

    enum CodingKeys: String, CodingKey {
        // swiftlint:disable:next identifier_name
        case c1
        // swiftlint:disable:next identifier_name
        case c2
        case shareIndex = "share_index"
    }

    // swiftlint:disable:next identifier_name
    public init(c1: [UInt8], c2: [UInt8], shareIndex: UInt32) {
        self.c1 = c1
        self.c2 = c2
        self.shareIndex = shareIndex
    }
}

// MARK: - Share Payload (JSON)

/// Share payload for delegated share submission.
public struct VotingSharePayload: Codable, Sendable {
    public let sharesHash: [UInt8]
    public let proposalId: UInt32
    public let voteDecision: UInt32
    public let encShare: VotingWireEncryptedShare
    public let treePosition: UInt64
    public let allEncShares: [VotingWireEncryptedShare]
    public let shareComms: [[UInt8]]
    public let primaryBlind: [UInt8]

    enum CodingKeys: String, CodingKey {
        case sharesHash = "shares_hash"
        case proposalId = "proposal_id"
        case voteDecision = "vote_decision"
        case encShare = "enc_share"
        case treePosition = "tree_position"
        case allEncShares = "all_enc_shares"
        case shareComms = "share_comms"
        case primaryBlind = "primary_blind"
    }
}

// MARK: - Cast Vote Signature (JSON)

/// Signature for a cast vote transaction.
public struct VotingCastVoteSignature: Codable, Sendable {
    public let voteAuthSig: [UInt8]

    enum CodingKeys: String, CodingKey {
        case voteAuthSig = "vote_auth_sig"
    }
}

// MARK: - Delegation Inputs (JSON)

/// Inputs needed for delegation construction.
public struct VotingDelegationInputs: Codable, Sendable {
    public let fvkBytes: [UInt8]
    public let gDNewX: [UInt8]
    public let pkDNewX: [UInt8]
    public let hotkeyRawAddress: [UInt8]
    public let hotkeyPublicKey: [UInt8]
    public let hotkeyAddress: String
    public let seedFingerprint: [UInt8]

    enum CodingKeys: String, CodingKey {
        case fvkBytes = "fvk_bytes"
        case gDNewX = "g_d_new_x"
        case pkDNewX = "pk_d_new_x"
        case hotkeyRawAddress = "hotkey_raw_address"
        case hotkeyPublicKey = "hotkey_public_key"
        case hotkeyAddress = "hotkey_address"
        case seedFingerprint = "seed_fingerprint"
    }
}

// MARK: - VAN Witness (JSON)

/// VAN Merkle witness for ZKP #2.
public struct VotingVanWitness: Codable, Sendable {
    public let authPath: [[UInt8]]
    public let position: UInt32
    public let anchorHeight: UInt32

    enum CodingKeys: String, CodingKey {
        case authPath = "auth_path"
        case position
        case anchorHeight = "anchor_height"
    }
}

// MARK: - TX hash lookup

/// Result of a stored-tx-hash lookup for a delegation or vote bundle.
///
/// Making "the DB has no row for this key" an explicit case — rather than
/// letting it ride on an optional `String?` — disambiguates it from the
/// `throws` path, which covers FFI-level failures (null handle, serde decode
/// error, DB I/O error). Callers that only need to know "do we have a hash"
/// can pattern-match `.present(let hash)`; callers that need to branch on
/// absence-without-error can match `.notFound`.
public enum VotingTxHashLookup: Equatable, Sendable {
    /// No record exists for the given key (round/bundle or round/bundle/proposal).
    case notFound
    /// A record exists and contains the given tx hash.
    case present(String)
}
