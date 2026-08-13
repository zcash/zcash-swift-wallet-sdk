//
//  VotingTypes.swift
//  ZcashLightClientKit
//

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

/// State of a voting round.
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

/// A voting hotkey: the secret the wallet delegates voting power to, together
/// with the Orchard address derived from it.
///
/// A voting hotkey is an app-owned random value, not a wallet-seed derivation.
/// The application **must persist `storedSecret`**: it cannot be recovered from
/// the wallet seed, so restoring a wallet from its seed phrase does not restore
/// the ability to vote with a hotkey whose secret was lost. Everything else here
/// is derived from `storedSecret` and does not need to be stored.
///
/// Conforms to `Undescribable` so the secret cannot escape through
/// `print`, string interpolation, or reflection.
public struct VotingHotkey: Sendable, Undescribable {
    /// The material to persist. Treat it as key material, not as an identifier.
    public let storedSecret: [UInt8]
    /// Raw Orchard address bytes for the hotkey, derived from `storedSecret`.
    public let rawOrchardAddress: [UInt8]
    /// Address index the hotkey's Orchard address was derived at.
    public let addressIndex: UInt32
}

// MARK: - Bundle Setup

/// Result of setting up vote bundles.
public struct VotingBundleSetupResult: Sendable {
    public let bundleCount: UInt32
    public let eligibleWeight: UInt64
    /// Notes the canonical bundling policy discarded, and which are therefore
    /// not represented in `eligibleWeight`. A non-zero value here means the
    /// wallet holds voting notes that will not be voted with.
    public let droppedCount: UInt32
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
///
/// Conforms to `Undescribable` because `rho` and `rseed` are Orchard note
/// secrets: printing a note recovers the material needed to re-derive the note,
/// so reflection-based description must not expose them.
public struct VotingNoteInfo: Codable, Sendable, Undescribable {
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
///
/// Conforms to `Undescribable` because it carries the spend-authorization
/// randomizer `alpha` alongside the `rseed` values and padded note secrets of
/// the actions it authorizes; those are signing and note secrets, not wire data.
public struct VotingPczt: Codable, Sendable, Undescribable {
    public let pcztBytes: [UInt8]
    /// Randomized verification key (`rk` on the wire).
    public let randomizedKey: [UInt8]
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
        case randomizedKey = "rk"
        case alpha
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
    public let nullifier: String
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
    /// Randomized verification key (`rk` on the wire).
    public let randomizedKey: [UInt8]

    enum CodingKeys: String, CodingKey {
        case proof
        case publicInputs = "public_inputs"
        case nfSigned = "nf_signed"
        case cmxNew = "cmx_new"
        case govNullifiers = "gov_nullifiers"
        case vanComm = "van_comm"
        case randomizedKey = "rk"
    }
}

// MARK: - Delegation PIR Precompute Result (JSON)

/// Result of precomputing and caching PIR proofs needed by delegation proving.
public struct VotingDelegationPirPrecomputeResult: Codable, Sendable {
    public let cachedCount: UInt32
    public let fetchedCount: UInt32

    enum CodingKeys: String, CodingKey {
        case cachedCount = "cached_count"
        case fetchedCount = "fetched_count"
    }
}

// MARK: - Delegation Submission (JSON)

/// The chain-ready delegation submission body, in `zcash_voting`'s own wire
/// encoding.
///
/// The FFI returns `zcash_voting::wire::DelegationSubmissionWire` serialized by
/// the crate, so the field names and the base64 encoding are the crate's and the
/// SDK reshapes nothing. Two consequences for callers: `tx1Effects` — the
/// versioned Ironwood TX1 effecting data the vote chain requires, and whose
/// absence is the `400: tx1 effects must be 821 bytes, got 0` rejection — is
/// present without anyone assembling it, and the legacy `sighash` field is gone
/// from the wire. The signer's sighash still exists; it simply never belonged in
/// the submission body, because the server derives the signing digest itself.
///
/// Mirrors `zcash_voting::wire::DelegationSubmissionWire` (crate `src/wire.rs`);
/// the `CodingKeys` carry the crate's serde field names where the Swift names
/// differ (`signed_note_nullifier`, `van_cmx`).
public struct VotingDelegationSubmission: Codable, Sendable {
    /// Randomized verification key (`rk` on the wire), base64.
    public let randomizedKey: String
    /// SpendAuth signature over the PCZT sighash, base64.
    public let spendAuthSig: String
    /// Versioned Ironwood TX1 effecting data, base64 (821 bytes decoded).
    public let tx1Effects: String
    public let nfSigned: String
    public let cmxNew: String
    public let govComm: String
    public let govNullifiers: [String]
    public let proof: String
    public let voteRoundId: String

    enum CodingKeys: String, CodingKey {
        case randomizedKey = "rk"
        case spendAuthSig = "spend_auth_sig"
        case tx1Effects = "tx1_effects"
        case nfSigned = "signed_note_nullifier"
        case cmxNew = "cmx_new"
        case govComm = "van_cmx"
        case govNullifiers = "gov_nullifiers"
        case proof
        case voteRoundId = "vote_round_id"
    }
}

// MARK: - Vote Commit (JSON)

/// The result of committing one cast vote: the signed commitment fields destined
/// for the vote chain, and the encrypted shares the vote proof binds.
///
/// Helper-server payloads are deliberately not here. A commit made before the
/// vote's tree position is confirmed can only produce provisional payloads,
/// and provisional payloads must never be sent to a helper server. Build
/// helper payloads with
/// ``VotingRustBackend/recoverWireJson(commitmentBundleJson:proposalId:shareIndex:voteCommitmentTreePosition:submitAt:)``
/// after ``VotingRustBackend/confirmVoteSubmission(roundId:bundleIndex:proposalId:txHash:eventsJson:)``.
///
/// Every field here is wire data — it is published on chain — so the commit
/// result carries no secret the wallet must retain. The signing secrets used to
/// produce it stay inside `zcash_voting`.
///
/// Mirrors the FFI's `JsonVoteCommit` (`rust/src/voting/json.rs`), the JSON
/// shape of `zcash_voting::vote::VoteCommit` (crate `src/vote.rs`) minus its
/// provisional `share_payloads`; the `CodingKeys` carry that JSON's field
/// names (`r_vpk`, `enc_shares`) where the Swift names differ.
public struct VotingVoteCommit: Codable, Sendable {
    public let proposalId: UInt32
    public let vanNullifier: [UInt8]
    public let voteAuthorityNoteNew: [UInt8]
    public let voteCommitment: [UInt8]
    public let proof: [UInt8]
    public let anchorHeight: UInt32
    /// Randomizer for the vote public key (`r_vpk` on the wire).
    public let voteKeyRandomizer: [UInt8]
    public let voteAuthSig: [UInt8]
    public let encShares: [VotingWireEncryptedShare]

    enum CodingKeys: String, CodingKey {
        case proposalId = "proposal_id"
        case vanNullifier = "van_nullifier"
        case voteAuthorityNoteNew = "vote_authority_note_new"
        case voteCommitment = "vote_commitment"
        case proof
        case anchorHeight = "anchor_height"
        case voteKeyRandomizer = "r_vpk"
        case voteAuthSig = "vote_auth_sig"
        case encShares = "enc_shares"
    }
}

// MARK: - Wire Encrypted Share (JSON)

/// Wire-safe encrypted share — only the public ciphertext components.
///
/// Decoded straight from `zcash_voting::types::WireEncryptedShare`, which
/// base64-encodes both ciphertext components, so `ciphertext1` and `ciphertext2`
/// are base64 strings rather than byte arrays. Secrets (`plaintext_value`,
/// `randomness`) stay inside Rust and never cross the FFI boundary.
public struct VotingWireEncryptedShare: Codable, Sendable {
    /// First ciphertext component (`c1` on the wire), base64.
    public let ciphertext1: String
    /// Second ciphertext component (`c2` on the wire), base64.
    public let ciphertext2: String
    public let shareIndex: UInt32

    enum CodingKeys: String, CodingKey {
        case ciphertext1 = "c1"
        case ciphertext2 = "c2"
        case shareIndex = "share_index"
    }

    public init(ciphertext1: String, ciphertext2: String, shareIndex: UInt32) {
        self.ciphertext1 = ciphertext1
        self.ciphertext2 = ciphertext2
        self.shareIndex = shareIndex
    }
}

// MARK: - Delegation Inputs (JSON)

/// Inputs needed for delegation construction.
public struct VotingDelegationInputs: Codable, Sendable {
    public let fvkBytes: [UInt8]
    public let gDNewX: [UInt8]
    public let pkDNewX: [UInt8]
    public let hotkeyRawAddress: [UInt8]
    public let seedFingerprint: [UInt8]

    enum CodingKeys: String, CodingKey {
        case fvkBytes = "fvk_bytes"
        case gDNewX = "g_d_new_x"
        case pkDNewX = "pk_d_new_x"
        case hotkeyRawAddress = "hotkey_raw_address"
        case seedFingerprint = "seed_fingerprint"
    }
}

// MARK: - VAN Witness (JSON)

/// VAN Merkle witness for voting ZKP.
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

// MARK: - Keystone signature record (JSON)

/// A persisted Keystone-produced PCZT signature for a delegation bundle.
public struct VotingKeystoneSignatureRecord: Codable, Sendable, Equatable {
    public let bundleIndex: UInt32
    public let sig: [UInt8]
    public let sighash: [UInt8]
    /// Randomized verification key (`rk` on the wire).
    public let randomizedKey: [UInt8]

    enum CodingKeys: String, CodingKey {
        case bundleIndex = "bundle_index"
        case sig
        case sighash
        case randomizedKey = "rk"
    }

    public init(
        bundleIndex: UInt32,
        sig: [UInt8],
        sighash: [UInt8],
        randomizedKey: [UInt8]
    ) {
        self.bundleIndex = bundleIndex
        self.sig = sig
        self.sighash = sighash
        self.randomizedKey = randomizedKey
    }
}

// MARK: - Delegation key inputs

/// The wallet-side material `zcash_voting` needs to reconstruct the delegation
/// keys for one bundle.
///
/// `hotkeyStoredSecret` is the ``VotingHotkey/storedSecret`` the application
/// persisted. The hotkey's Orchard address, address index and network are all
/// derived from it, so no separate hotkey address is supplied. The network
/// itself comes from the database handle these inputs are used with, so it is
/// not carried here where it could drift from the one the round was opened for.
///
/// Conforms to `Undescribable` because `hotkeyStoredSecret` is the voting
/// hotkey's key material.
public struct VotingDelegationKeyInputs: Sendable, Undescribable {
    public let fvk: [UInt8]
    public let hotkeyStoredSecret: [UInt8]
    public let seedFingerprint: [UInt8]
    public let accountIndex: UInt32
    public let roundName: String

    public init(
        fvk: [UInt8],
        hotkeyStoredSecret: [UInt8],
        seedFingerprint: [UInt8],
        accountIndex: UInt32,
        roundName: String
    ) {
        self.fvk = fvk
        self.hotkeyStoredSecret = hotkeyStoredSecret
        self.seedFingerprint = seedFingerprint
        self.accountIndex = accountIndex
        self.roundName = roundName
    }
}

// MARK: - Build PCZT parameters

/// Parameters required to build a voting PCZT for a delegation bundle.
public struct VotingBuildPcztParams: Sendable {
    public let roundId: String
    public let bundleIndex: UInt32
    public let notes: [VotingNoteInfo]
    public let keys: VotingDelegationKeyInputs
    public let consensusBranchId: UInt32

    public init(
        roundId: String,
        bundleIndex: UInt32,
        notes: [VotingNoteInfo],
        keys: VotingDelegationKeyInputs,
        consensusBranchId: UInt32
    ) {
        self.roundId = roundId
        self.bundleIndex = bundleIndex
        self.notes = notes
        self.keys = keys
        self.consensusBranchId = consensusBranchId
    }
}

// MARK: - Delegation proving parameters

/// Parameters required to build and prove the delegation ZKP for a bundle.
public struct VotingDelegationProofParams: Sendable {
    public let roundId: String
    public let bundleIndex: UInt32
    public let notes: [VotingNoteInfo]
    public let keys: VotingDelegationKeyInputs

    public init(
        roundId: String,
        bundleIndex: UInt32,
        notes: [VotingNoteInfo],
        keys: VotingDelegationKeyInputs
    ) {
        self.roundId = roundId
        self.bundleIndex = bundleIndex
        self.notes = notes
        self.keys = keys
    }
}

// MARK: - PIR proof input

/// Inputs to `VotingRustBackend.validatePirProof(_:)`.
public struct VotingPirProof: Sendable, Equatable {
    public let root: [UInt8]
    public let nfBounds: [UInt8]
    public let leafPosition: UInt32
    public let path: [UInt8]
    public let nullifier: [UInt8]
    public let expectedRoot: [UInt8]

    public init(
        root: [UInt8],
        nfBounds: [UInt8],
        leafPosition: UInt32,
        path: [UInt8],
        nullifier: [UInt8],
        expectedRoot: [UInt8]
    ) {
        self.root = root
        self.nfBounds = nfBounds
        self.leafPosition = leafPosition
        self.path = path
        self.nullifier = nullifier
        self.expectedRoot = expectedRoot
    }
}

// MARK: - Stored commitment bundle

/// A previously-stored vote commitment bundle and its position in the
/// vote-commitment tree.
///
/// Returned by `VotingRustBackend.getCommitmentBundle(...)`.
public struct VotingStoredCommitmentBundle: Sendable, Equatable {
    /// The recovery bundle JSON `zcash_voting` wrote when the vote was
    /// committed. It is opaque to the SDK: only `zcash_voting` produces and
    /// consumes it.
    public let bundleJson: String
    /// Position of the vote commitment within the vote commitment tree.
    public let voteCommitmentTreePosition: UInt64
}

// MARK: - PIR layout

/// PIR tree geometry advertised by the round's resolved dynamic voting config.
///
/// Mirrors `zcash_voting::config::PirLayout` field for field. `zcash_voting`
/// runs the config/server layout handshake with these values and fails closed
/// before issuing any private query when the server disagrees, so they must come
/// from a resolved dynamic config rather than being assumed or compiled in.
public struct VotingPirLayout: Equatable, Sendable {
    public let pirDepth: UInt32
    public let tier0Layers: UInt32
    public let tier1Layers: UInt32

    /// YPIR RLWE polynomial degree; the crate accepts only 2048 or 4096.
    ///
    /// Any other value — including the `0` of ``unknown`` — fails closed in
    /// `zcash_voting` before any network I/O.
    public let polyLen: UInt32

    /// The crate's `PirLayout::UNKNOWN` sentinel, and its `Default`.
    ///
    /// `zcash_voting` rejects it — "pir_layout is unknown; resolve a current
    /// dynamic voting config first" — so this is a fail-closed placeholder for
    /// callers that have not resolved a config yet, never a usable layout.
    public static let unknown = VotingPirLayout(
        pirDepth: 0,
        tier0Layers: 0,
        tier1Layers: 0,
        polyLen: 0
    )

    public init(pirDepth: UInt32, tier0Layers: UInt32, tier1Layers: UInt32, polyLen: UInt32) {
        self.pirDepth = pirDepth
        self.tier0Layers = tier0Layers
        self.tier1Layers = tier1Layers
        self.polyLen = polyLen
    }
}

// MARK: - Vote confirmation (JSON)

/// The positions a mined cast-vote transaction confirmed.
///
/// Decoded from `zcash_voting::wire::VoteConfirmation`. Both positions are read
/// out of the chain's confirmation events by the crate, which also writes them
/// to the voting database in the same transaction that returns them — so this
/// value and the persisted state can never disagree.
public struct VotingVoteConfirmation: Codable, Sendable, Equatable {
    /// The confirmed transaction hash, echoed back from the events.
    public let txHash: String
    /// Confirmed vote-authority-note leaf position.
    public let vanLeafPosition: UInt32
    /// Confirmed position of the vote commitment within the vote commitment
    /// tree. This is the value to late-bind into helper-share payloads.
    public let voteCommitmentTreePosition: UInt64

    enum CodingKeys: String, CodingKey {
        case txHash = "tx_hash"
        case vanLeafPosition = "van_leaf_position"
        case voteCommitmentTreePosition = "vc_tree_position"
    }
}

// MARK: - Delegation signature (JSON)

/// A SpendAuth signature this wallet produced for one delegation bundle, with
/// the sighash it covers.
///
/// Both values go straight into
/// ``VotingRustBackend/getDelegationSubmission(roundId:bundleIndex:signature:sighash:)``.
/// The sighash is not informational: `zcash_voting` checks it against the one it
/// stored when the bundle's PCZT was set up and rejects the submission if they
/// disagree, so pass back the value that came out with the signature rather than
/// one recomputed elsewhere.
public struct VotingDelegationSignature: Codable, Sendable, Equatable {
    /// The 64-byte detached RedPallas SpendAuth signature.
    public let signature: [UInt8]
    /// The 32-byte ZIP-244 sighash the signature covers.
    public let sighash: [UInt8]

    enum CodingKeys: String, CodingKey {
        case signature = "sig"
        case sighash
    }
}
