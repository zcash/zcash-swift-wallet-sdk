//
//  VotingRustBackend.swift
//  ZcashLightClientKit
//

import Foundation
import libzcashlc

// MARK: - Error

/// Error type for voting Rust backend operations.
public enum VotingRustBackendError: LocalizedError, Equatable {
    /// The voting database is already open.
    case databaseAlreadyOpen
    /// The voting database is not open.
    case databaseNotOpen
    /// A Rust error occurred.
    case rustError(String)
    /// Invalid data was received.
    case invalidData(String)

    public var errorDescription: String? {
        switch self {
        case .databaseAlreadyOpen:
            return "Voting database is already open."
        case .databaseNotOpen:
            return "Voting database is not open."
        case .rustError(let message):
            return "Voting backend error: \(message)"
        case .invalidData(let message):
            return "Invalid data: \(message)"
        }
    }
}

// MARK: - VotingRustBackend

/// Wraps the voting `libzcashlc` C FFI surface.
///
/// Manages an opaque `VotingDatabaseHandle` pointer for the database-bound
/// methods. Stateless / static FFI (e.g. `computeShareNullifier`) is exposed
/// as type methods so callers do not need to open a database.
///
/// Thread safety: handle access is serialized by an `NSLock`. Database-bound
/// FFI calls hold the lock for their full duration so `close()` cannot free the
/// handle while Rust is using it.
public final class VotingRustBackend: @unchecked Sendable {
    private let lock = NSLock()
    private var handle: OpaquePointer?

    public init() {}

    deinit {
        if let handle {
            zcashlc_voting_db_free(handle)
        }
    }

    // MARK: - Database lifecycle

    /// Open the voting database at `path` for `networkId`.
    ///
    /// The network is fixed for the lifetime of the handle: every
    /// database-bound call takes its voting identity from `networkId` rather
    /// than accepting one of its own, so no later call can disagree with the
    /// network the database was opened for. A custom (regtest) network takes
    /// its voting identity from the registered base network, and opening fails
    /// if that network has not been configured yet.
    ///
    /// Throws `VotingRustBackendError.databaseAlreadyOpen` if the backend
    /// already holds an open handle.
    public func open(path: String, networkId: UInt32) throws {
        lock.lock()
        defer { lock.unlock() }

        guard handle == nil else {
            throw VotingRustBackendError.databaseAlreadyOpen
        }

        let pathBytes = [UInt8](path.utf8)
        guard let ptr = pathBytes.withUnsafeBufferPointer({ buf in
            zcashlc_voting_db_open(buf.baseAddress, UInt(buf.count), networkId)
        }) else {
            throw VotingRustBackendError.rustError(
                Self.staticLastErrorMessage(fallback: "`voting_db_open` failed")
            )
        }
        handle = ptr
    }

    /// Close the voting database, freeing the underlying handle.
    ///
    /// Idempotent: calling `close()` on an already-closed backend is a no-op.
    public func close() {
        lock.lock()
        defer { lock.unlock() }

        if let dbh = handle {
            zcashlc_voting_db_free(dbh)
            handle = nil
        }
    }
}

// MARK: - Wallet identity

extension VotingRustBackend {
    /// Set the wallet identifier for all subsequent voting operations.
    ///
    /// Must be called after `open(path:)` and before any round operations.
    public func setWalletId(_ walletId: String) throws {
        let walletIdBytes = [UInt8](walletId.utf8)

        try withHandle { dbh in
            let result = walletIdBytes.withUnsafeBufferPointer { buf in
                zcashlc_voting_set_wallet_id(dbh, buf.baseAddress, UInt(buf.count))
            }

            guard result == 0 else {
                throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`set_wallet_id` failed"))
            }
        }
    }
}

// MARK: - Delegation (PIR precompute)

extension VotingRustBackend {
    /// Resolve the round's PIR endpoint, fetch the IMT non-membership proofs
    /// needed for the delegation ZKP, and cache them in the voting database.
    ///
    /// This performs the network PIR lookup only, proof construction happens
    ///  elsewhere.
    ///
    /// `pirEndpoints` are probed in parallel via `pirResolver`. The first
    /// endpoint whose served snapshot height equals `expectedSnapshotHeight`
    /// exactly is used. See `PirSnapshotResolver` for the failure semantics.
    ///
    /// `pirLayout` must come from the round's resolved dynamic voting config.
    /// `zcash_voting` fails the config/server layout handshake closed before any
    /// private query, and rejects the `.unknown` default outright.
    public func precomputeDelegationPir(
        roundId: String,
        bundleIndex: UInt32,
        notes: [VotingNoteInfo],
        pirEndpoints: [String],
        expectedSnapshotHeight: UInt64,
        pirLayout: VotingPirLayout = .unknown,
        pirResolver: PirSnapshotResolver = PirSnapshotResolver()
    ) async throws -> VotingDelegationPirPrecomputeResult {
        try requireOpenDatabase()

        // PirSnapshotResolver expects `BlockHeight` (Int); voting snapshot
        // heights are `UInt64` everywhere else in the voting types, so convert
        // at the boundary. Snapshot heights well within Int.max in practice.
        let pirServerUrl = try await pirResolver.resolve(
            endpoints: pirEndpoints,
            expectedSnapshotHeight: BlockHeight(expectedSnapshotHeight)
        )

        let roundIdBytes = [UInt8](roundId.utf8)
        let notesJson = try JSONEncoder().encode(notes)
        let notesBytes = [UInt8](notesJson)
        let urlBytes = [UInt8](pirServerUrl.utf8)

        let ptr: UnsafeMutablePointer<FfiBoxedSlice> = try withHandle { dbh in
            let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = roundIdBytes.withUnsafeBufferPointer { ridBuf in
                notesBytes.withUnsafeBufferPointer { notesBuf in
                    urlBytes.withUnsafeBufferPointer { urlBuf in
                        zcashlc_voting_precompute_delegation_pir(
                            dbh,
                            ridBuf.baseAddress,
                            UInt(ridBuf.count),
                            bundleIndex,
                            notesBuf.baseAddress,
                            UInt(notesBuf.count),
                            urlBuf.baseAddress,
                            UInt(urlBuf.count),
                            pirLayout.pirDepth,
                            pirLayout.tier0Layers,
                            pirLayout.tier1Layers,
                            pirLayout.polyLen
                        )
                    }
                }
            }

            guard let ptr else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`precompute_delegation_pir` failed")
                )
            }
            return ptr
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }
}

// MARK: - Vote-tree sync

extension VotingRustBackend {
    /// Sync the vote commitment tree from a chain node.
    ///
    /// Returns the latest synced block height.
    public func syncVoteTree(roundId: String, nodeUrl: String) throws -> UInt32 {
        let roundIdBytes = [UInt8](roundId.utf8)
        let urlBytes = [UInt8](nodeUrl.utf8)

        return try withHandle { dbh in
            let result = roundIdBytes.withUnsafeBufferPointer { ridBuf in
                urlBytes.withUnsafeBufferPointer { urlBuf in
                    zcashlc_voting_sync_vote_tree(
                        dbh,
                        ridBuf.baseAddress,
                        UInt(ridBuf.count),
                        urlBuf.baseAddress,
                        UInt(urlBuf.count)
                    )
                }
            }

            guard result >= 0 else {
                throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`sync_vote_tree` failed"))
            }
            return UInt32(result)
        }
    }

    /// Generate a Vote Authority Note (VAN) Merkle witness for the given
    /// bundle at `anchorHeight`.
    public func generateVanWitness(
        roundId: String,
        bundleIndex: UInt32,
        anchorHeight: UInt32
    ) throws -> VotingVanWitness {
        let roundIdBytes = [UInt8](roundId.utf8)

        let ptr: UnsafeMutablePointer<FfiBoxedSlice> = try withHandle { dbh in
            let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = roundIdBytes.withUnsafeBufferPointer { buf in
                zcashlc_voting_generate_van_witness(
                    dbh,
                    buf.baseAddress,
                    UInt(buf.count),
                    bundleIndex,
                    anchorHeight
                )
            }

            guard let ptr else {
                throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`generate_van_witness` failed"))
            }
            return ptr
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }

    /// Reset the in-memory tree client for a round, forcing the next
    /// `syncVoteTree` call to start from a fresh client.
    ///
    /// Pass an empty `roundId` to reset all rounds.
    public func resetTreeClient(roundId: String = "") throws {
        let roundIdBytes = [UInt8](roundId.utf8)

        try withHandle { dbh in
            let result = roundIdBytes.withUnsafeBufferPointer { buf in
                zcashlc_voting_reset_tree_client(dbh, buf.baseAddress, UInt(buf.count))
            }

            guard result == 0 else {
                throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`reset_tree_client` failed"))
            }
        }
    }
}

// MARK: - Delegation witnesses

extension VotingRustBackend {
    /// Generate Merkle inclusion witnesses for a bundle's notes and cache them
    /// in the voting database.
    public func generateNoteWitnesses(
        roundId: String,
        bundleIndex: UInt32,
        walletDbPath: String,
        notes: [VotingNoteInfo],
        networkId: UInt32
    ) throws -> [VotingWitnessData] {
        let roundIdBytes = [UInt8](roundId.utf8)
        let walletPathBytes = [UInt8](walletDbPath.utf8)
        let notesJson = try JSONEncoder().encode(notes)
        let notesBytes = [UInt8](notesJson)

        let ptr: UnsafeMutablePointer<FfiBoxedSlice> = try withHandle { dbh in
            let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = roundIdBytes.withUnsafeBufferPointer { ridBuf in
                walletPathBytes.withUnsafeBufferPointer { pathBuf in
                    notesBytes.withUnsafeBufferPointer { notesBuf in
                        zcashlc_voting_generate_note_witnesses(
                            dbh,
                            ridBuf.baseAddress,
                            UInt(ridBuf.count),
                            bundleIndex,
                            pathBuf.baseAddress,
                            UInt(pathBuf.count),
                            notesBuf.baseAddress,
                            UInt(notesBuf.count),
                            networkId
                        )
                    }
                }
            }

            guard let ptr else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`generate_note_witnesses` failed")
                )
            }
            return ptr
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }
}

// MARK: - Vote casting

extension VotingRustBackend {
    /// Build, sign, and persist the cast-vote commitment for one proposal.
    ///
    /// This is the single entry point for casting a vote. It replaces the former
    /// four-call sequence — build the commitment, encrypt the shares, sign the
    /// cast vote, then build the share payloads — because `zcash_voting` now
    /// owns that orchestration and made the intermediate steps private. The
    /// returned ``VotingVoteCommit`` carries everything the caller previously
    /// assembled by hand.
    ///
    /// The call is idempotent: repeating it for the same round, bundle and
    /// proposal returns the persisted recovery bundle rather than re-proving.
    ///
    /// `hotkeyStoredSecret` is the ``VotingHotkey/storedSecret`` the application
    /// persisted, not wallet seed material. `networkId` must match the network
    /// the round was initialized with, because the vote is signed for the
    /// network the hotkey belongs to.
    ///
    /// The proof callback may be invoked from Rust worker threads. Do not call
    /// back into this backend from `progress`: the database handle lock is held
    /// while the FFI call is active, so re-entering the backend will deadlock.
    ///
    /// Safety: keep `progress` thread-safe, non-blocking, and limited to
    /// reporting state outside this backend.
    // swiftlint:disable:next function_parameter_count
    public func commitVote(
        roundId: String,
        bundleIndex: UInt32,
        hotkeyStoredSecret: [UInt8],
        proposalId: UInt32,
        choice: UInt32,
        numOptions: UInt32,
        voteCommitmentTreePosition: UInt64,
        vanWitness: VotingVanWitness,
        singleShare: Bool,
        progress: (@Sendable (Double) -> Void)? = nil
    ) async throws -> VotingVoteCommit {
        try requireOpenDatabase()

        let draft = VoteCommitDraft(
            roundId: roundId,
            bundleIndex: bundleIndex,
            hotkeyStoredSecret: hotkeyStoredSecret,
            proposalId: proposalId,
            choice: choice,
            numOptions: numOptions,
            voteCommitmentTreePosition: voteCommitmentTreePosition,
            vanWitness: vanWitness,
            singleShare: singleShare
        )

        return try await Task.detached { [self] in
            try syncCommitVote(draft, progress: progress)
        }.value
    }

    /// Record the transaction that carried a vote on chain.
    ///
    /// `txHash` is required: submission is recorded by persisting the
    /// transaction, so that a restarted wallet resumes polling for it instead of
    /// rebuilding the vote.
    public func markVoteSubmitted(
        roundId: String,
        bundleIndex: UInt32,
        proposalId: UInt32,
        txHash: String
    ) throws {
        let roundIdBytes = [UInt8](roundId.utf8)
        let txHashBytes = [UInt8](txHash.utf8)

        try withHandle { dbh in
            let result = roundIdBytes.withUnsafeBufferPointer { ridBuf in
                txHashBytes.withUnsafeBufferPointer { txBuf in
                    zcashlc_voting_mark_vote_submitted(
                        dbh,
                        ridBuf.baseAddress,
                        UInt(ridBuf.count),
                        bundleIndex,
                        proposalId,
                        txBuf.baseAddress,
                        UInt(txBuf.count)
                    )
                }
            }

            guard result == 0 else {
                throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`mark_vote_submitted` failed"))
            }
        }
    }

    /// Record a confirmed cast-vote transaction in one atomic step.
    ///
    /// `zcash_voting` parses the confirmation events, records the transaction
    /// hash, advances the vote-authority-note position and records the
    /// vote-commitment tree position inside a single database transaction, then
    /// returns both positions. Callers must not parse the events themselves:
    /// splitting the `leaf_index` attribute by hand is exactly the duplicated
    /// state this entry point exists to delete.
    ///
    /// `eventsJson` is the confirmation-events array the wallet's chain client
    /// already fetches, serialized as JSON — a list of
    /// `{"type": …, "attributes": [{"key": …, "value": …}]}` objects.
    ///
    /// Repeating the call with the same transaction hash and position is
    /// accepted; a stale confirmation cannot rewind a position that a later one
    /// already advanced.
    public func confirmVoteSubmission(
        roundId: String,
        bundleIndex: UInt32,
        proposalId: UInt32,
        txHash: String,
        eventsJson: String
    ) throws -> VotingVoteConfirmation {
        let roundIdBytes = [UInt8](roundId.utf8)
        let txHashBytes = [UInt8](txHash.utf8)
        let eventsBytes = [UInt8](eventsJson.utf8)

        let ptr: UnsafeMutablePointer<FfiBoxedSlice> = try withHandle { dbh in
            let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = roundIdBytes.withUnsafeBufferPointer { ridBuf in
                txHashBytes.withUnsafeBufferPointer { txBuf in
                    eventsBytes.withUnsafeBufferPointer { evBuf in
                        zcashlc_voting_confirm_vote_submission(
                            dbh,
                            ridBuf.baseAddress,
                            UInt(ridBuf.count),
                            bundleIndex,
                            proposalId,
                            txBuf.baseAddress,
                            UInt(txBuf.count),
                            evBuf.baseAddress,
                            UInt(evBuf.count)
                        )
                    }
                }
            }

            guard let ptr else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`confirm_vote_submission` failed")
                )
            }
            return ptr
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }
}

// MARK: - Share tracking (static)

extension VotingRustBackend {
    /// Compute the nullifier for a vote share.
    ///
    /// - Parameters:
    ///   - voteCommitment: 32-byte canonical Pallas-base-field encoding.
    ///   - shareIndex: Position of the share within its vote.
    ///   - primaryBlind: 32-byte canonical Pallas-base-field encoding.
    /// - Returns: 32-byte nullifier as 64 lowercase hex characters.
    /// - Throws: `VotingRustBackendError.invalidData` if either byte array is not
    ///   exactly 32 bytes; `VotingRustBackendError.rustError` if the underlying
    ///   Rust computation fails (for example, non-canonical field encoding).
    public static func computeShareNullifier(
        voteCommitment: [UInt8],
        shareIndex: UInt32,
        primaryBlind: [UInt8]
    ) throws -> String {
        guard
            voteCommitment.count == votingFieldElementByteCount,
            primaryBlind.count == votingFieldElementByteCount
        else {
            throw VotingRustBackendError.invalidData(
                "voteCommitment and primaryBlind must each be exactly \(votingFieldElementByteCount) bytes"
            )
        }

        let ptr = voteCommitment.withUnsafeBufferPointer { vcBuf in
            primaryBlind.withUnsafeBufferPointer { blindBuf in
                zcashlc_voting_compute_share_nullifier(
                    vcBuf.baseAddress,
                    blindBuf.baseAddress,
                    shareIndex
                )
            }
        }

        guard let ptr else {
            throw VotingRustBackendError.rustError(
                staticLastErrorMessage(fallback: "`compute_share_nullifier` failed")
            )
        }
        defer { zcashlc_string_free(ptr) }
        return String(cString: ptr)
    }

    /// Rebuild one helper-server share payload as `zcash_voting`'s own wire JSON.
    ///
    /// The crate parses the persisted recovery bundle, selects the requested
    /// share, late-binds the confirmed vote-commitment-tree position and the
    /// scheduled submission time, and serializes the payload itself. Nothing is
    /// re-proved and nothing is committed a second time.
    ///
    /// - Parameters:
    ///   - commitmentBundleJson: ``VotingStoredCommitmentBundle/bundleJson`` from
    ///     `getCommitmentBundle(roundId:bundleIndex:proposalId:)`.
    ///   - voteCommitmentTreePosition: the confirmed position, from
    ///     ``VotingVoteConfirmation/voteCommitmentTreePosition``.
    /// - Returns: the helper request body. POST it verbatim; do not decode,
    ///   re-shape or re-encode it.
    /// - Throws: `VotingRustBackendError.rustError` if the bundle JSON is
    ///   malformed, its proposal does not match `proposalId`, or the share index
    ///   is not present in it.
    public static func recoverWireJson(
        commitmentBundleJson: String,
        proposalId: UInt32,
        shareIndex: UInt32,
        voteCommitmentTreePosition: UInt64,
        submitAt: UInt64
    ) throws -> String {
        let bundleBytes = [UInt8](commitmentBundleJson.utf8)
        let payload = try staticBoxedSliceFFI(fallback: "`recover_wire_json` failed") {
            bundleBytes.withUnsafeBufferPointer { buf in
                zcashlc_voting_recover_wire_json(
                    buf.baseAddress,
                    UInt(buf.count),
                    proposalId,
                    shareIndex,
                    voteCommitmentTreePosition,
                    submitAt
                )
            }
        }
        return String(decoding: payload, as: UTF8.self)
    }

    /// List the share indices recoverable from a persisted vote recovery bundle.
    ///
    /// The crate parses the bundle and applies its own single-share slicing
    /// (one share when the vote was single-share, all of them otherwise);
    /// this reads off each recovered payload's own share index. Crash
    /// recovery calls this instead of guessing a share count from
    /// `singleShare` alone (`singleShare ? 1 : numOptions`), so a caller-side
    /// guess can never under- or over-deliver relative to what the crate
    /// actually reconstructs.
    ///
    /// - Parameter commitmentBundleJson: ``VotingStoredCommitmentBundle/bundleJson``
    ///   from `getCommitmentBundle(roundId:bundleIndex:proposalId:)`.
    /// - Returns: the recoverable share indices, in the crate's own order.
    /// - Throws: `VotingRustBackendError.rustError` if the bundle JSON is
    ///   malformed or its vote fields are out of range.
    public static func recoverableShareIndices(
        commitmentBundleJson: String
    ) throws -> [UInt32] {
        let bundleBytes = [UInt8](commitmentBundleJson.utf8)
        let ptr = bundleBytes.withUnsafeBufferPointer { buf in
            zcashlc_voting_recoverable_share_indices(buf.baseAddress, UInt(buf.count))
        }
        guard let ptr else {
            throw VotingRustBackendError.rustError(
                staticLastErrorMessage(fallback: "`recoverable_share_indices` failed")
            )
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try staticDecodeJSON(from: ptr)
    }
}

// MARK: - Foundation helpers (static)

extension VotingRustBackend {
    /// Warm process-lifetime proving-key caches used by voting proofs.
    ///
    /// Safe to call multiple times; subsequent calls are cheap. Call once at app
    /// startup (off the main actor) to avoid a multi-second pause inside the
    /// first proving call.
    public static func warmProvingCaches() throws {
        let result = zcashlc_voting_warm_proving_caches()
        guard result == 0 else {
            throw VotingRustBackendError.rustError(
                staticLastErrorMessage(fallback: "`warm_proving_caches` failed")
            )
        }
    }

    /// Generate the public delegation inputs for a sender seed + stored hotkey
    /// secret pair.
    ///
    /// `senderSeed` must be ≥ 32 bytes. `hotkeyStoredSecret` is the app-owned
    /// ``VotingHotkey/storedSecret``, not seed material; `zcash_voting` derives
    /// the hotkey's Orchard address from it at a fixed account and address
    /// index, and rejects a secret of the wrong length. `accountIndex` drives
    /// only the sender's UFVK derivation.
    public static func generateDelegationInputs(
        senderSeed: [UInt8],
        hotkeyStoredSecret: [UInt8],
        networkId: UInt32,
        accountIndex: UInt32
    ) throws -> VotingDelegationInputs {
        guard senderSeed.count >= votingMinSeedByteCount else {
            throw VotingRustBackendError.invalidData(
                "senderSeed must be at least \(votingMinSeedByteCount) bytes"
            )
        }
        let ptr = senderSeed.withUnsafeBufferPointer { senderBuf in
            hotkeyStoredSecret.withUnsafeBufferPointer { hotkeyBuf in
                zcashlc_voting_generate_delegation_inputs(
                    senderBuf.baseAddress,
                    UInt(senderBuf.count),
                    hotkeyBuf.baseAddress,
                    UInt(hotkeyBuf.count),
                    networkId,
                    accountIndex
                )
            }
        }
        guard let ptr else {
            throw VotingRustBackendError.rustError(
                staticLastErrorMessage(fallback: "`generate_delegation_inputs` failed")
            )
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try staticDecodeJSON(from: ptr)
    }

    /// Generate delegation inputs from an explicit sender FVK + stored hotkey
    /// secret, bypassing sender-seed derivation.
    public static func generateDelegationInputs(
        senderFvk: [UInt8],
        hotkeyStoredSecret: [UInt8],
        networkId: UInt32,
        seedFingerprint: [UInt8]
    ) throws -> VotingDelegationInputs {
        guard senderFvk.count == votingOrchardFvkByteCount else {
            throw VotingRustBackendError.invalidData(
                "senderFvk must be exactly \(votingOrchardFvkByteCount) bytes"
            )
        }
        guard seedFingerprint.count == votingSeedFingerprintByteCount else {
            throw VotingRustBackendError.invalidData(
                "seedFingerprint must be exactly \(votingSeedFingerprintByteCount) bytes"
            )
        }
        let ptr = senderFvk.withUnsafeBufferPointer { fvkBuf in
            hotkeyStoredSecret.withUnsafeBufferPointer { hotkeyBuf in
                seedFingerprint.withUnsafeBufferPointer { fpBuf in
                    zcashlc_voting_generate_delegation_inputs_with_fvk(
                        fvkBuf.baseAddress,
                        UInt(fvkBuf.count),
                        hotkeyBuf.baseAddress,
                        UInt(hotkeyBuf.count),
                        networkId,
                        fpBuf.baseAddress,
                        UInt(fpBuf.count)
                    )
                }
            }
        }
        guard let ptr else {
            throw VotingRustBackendError.rustError(
                staticLastErrorMessage(fallback: "`generate_delegation_inputs_with_fvk` failed")
            )
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try staticDecodeJSON(from: ptr)
    }

    /// Extract the ZIP-244 shielded sighash from a finalized PCZT.
    public static func extractPcztSighash(pczt: [UInt8]) throws -> [UInt8] {
        try staticBoxedSliceFFI(fallback: "`extract_pczt_sighash` failed") {
            pczt.withUnsafeBufferPointer { buf in
                zcashlc_voting_extract_pczt_sighash(buf.baseAddress, UInt(buf.count))
            }
        }
    }

    /// Extract the spend-auth signature for `actionIndex` from a signed PCZT.
    public static func extractSpendAuthSig(
        signedPczt: [UInt8],
        actionIndex: UInt32
    ) throws -> [UInt8] {
        try staticBoxedSliceFFI(fallback: "`extract_spend_auth_sig` failed") {
            signedPczt.withUnsafeBufferPointer { buf in
                zcashlc_voting_extract_spend_auth_sig(buf.baseAddress, UInt(buf.count), actionIndex)
            }
        }
    }

    /// Extract the 96-byte Orchard FVK from a UFVK string.
    public static func extractOrchardFvk(ufvk: String, networkId: UInt32) throws -> [UInt8] {
        let bytes = [UInt8](ufvk.utf8)
        return try staticBoxedSliceFFI(fallback: "`extract_orchard_fvk_from_ufvk` failed") {
            bytes.withUnsafeBufferPointer { buf in
                zcashlc_voting_extract_orchard_fvk_from_ufvk(buf.baseAddress, UInt(buf.count), networkId)
            }
        }
    }

    /// Extract the 32-byte Ironwood note-commitment-tree root from a
    /// protobuf-encoded `TreeState`.
    ///
    /// Voting rounds anchor to the Ironwood pool, so a round's `nc_root` is the
    /// Ironwood tree's root at the snapshot height — not the Orchard tree's.
    public static func extractNcRoot(treeState: [UInt8]) throws -> [UInt8] {
        try staticBoxedSliceFFI(fallback: "`extract_nc_root` failed") {
            treeState.withUnsafeBufferPointer { buf in
                zcashlc_voting_extract_nc_root(buf.baseAddress, UInt(buf.count))
            }
        }
    }

    /// Verify a Merkle witness against the witness's embedded root.
    ///
    /// Returns `true` if valid, `false` if well-formed but invalid.
    /// Throws `.rustError` if the witness JSON is malformed.
    public static func verifyWitness(_ witness: VotingWitnessData) throws -> Bool {
        let json = try JSONEncoder().encode(witness)
        let bytes = [UInt8](json)
        let result = bytes.withUnsafeBufferPointer { buf in
            zcashlc_voting_verify_witness(buf.baseAddress, UInt(buf.count))
        }
        switch result {
        case 1: return true
        case 0: return false
        default:
            throw VotingRustBackendError.rustError(
                staticLastErrorMessage(fallback: "`verify_witness` failed")
            )
        }
    }
}

// MARK: - Round lifecycle

extension VotingRustBackend {
    /// Initialize a voting round.
    ///
    /// The round is persisted with the network the database was opened for, so
    /// that governance PCZT consensus branch identifiers can later be validated
    /// against the round's snapshot.
    ///
    /// Round-parameter byte arrays are validated by Rust; invalid lengths
    /// throw `.rustError` rather than persisting a partial round.
    /// `sessionJson` is optional; pass `nil` to leave it unset.
    public func initRound(
        roundId: String,
        snapshotHeight: UInt64,
        eaPublicKey: [UInt8],
        ncRoot: [UInt8],
        nullifierImtRoot: [UInt8],
        sessionJson: String? = nil
    ) throws {
        let roundIdBytes = [UInt8](roundId.utf8)
        let sessionBytes = sessionJson.map { [UInt8]($0.utf8) }

        try withHandle { dbh in
            let result = roundIdBytes.withUnsafeBufferPointer { ridBuf in
                eaPublicKey.withUnsafeBufferPointer { eaBuf in
                    ncRoot.withUnsafeBufferPointer { ncBuf in
                        nullifierImtRoot.withUnsafeBufferPointer { nullBuf in
                            withOptionalBufferPointer(sessionBytes) { sessionBuf in
                                zcashlc_voting_init_round(
                                    dbh,
                                    ridBuf.baseAddress,
                                    UInt(ridBuf.count),
                                    snapshotHeight,
                                    eaBuf.baseAddress,
                                    UInt(eaBuf.count),
                                    ncBuf.baseAddress,
                                    UInt(ncBuf.count),
                                    nullBuf.baseAddress,
                                    UInt(nullBuf.count),
                                    sessionBuf?.baseAddress,
                                    UInt(sessionBuf?.count ?? 0)
                                )
                            }
                        }
                    }
                }
            }

            guard result == 0 else {
                throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`init_round` failed"))
            }
        }
    }

    /// Read the persisted state of a round.
    public func getRoundState(roundId: String) throws -> VotingRoundState {
        let roundIdBytes = [UInt8](roundId.utf8)

        let ptr: UnsafeMutablePointer<FfiRoundState> = try withHandle { dbh in
            let ptr: UnsafeMutablePointer<FfiRoundState>? = roundIdBytes.withUnsafeBufferPointer { buf in
                zcashlc_voting_get_round_state(dbh, buf.baseAddress, UInt(buf.count))
            }
            guard let ptr else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`get_round_state` failed")
                )
            }
            return ptr
        }
        defer { zcashlc_voting_free_round_state(ptr) }

        let raw = ptr.pointee
        let phase = try Self.decodeRoundPhase(raw.phase)
        let storedRoundId = try Self.decodeRequiredCString(raw.round_id, fieldName: "round_id")
        let hotkeyAddress = raw.hotkey_address.map { String(cString: $0) }
        let delegatedWeight: UInt64? = raw.delegated_weight < 0
            ? nil
            : UInt64(raw.delegated_weight)

        return VotingRoundState(
            roundId: storedRoundId,
            phase: phase,
            snapshotHeight: raw.snapshot_height,
            hotkeyAddress: hotkeyAddress,
            delegatedWeight: delegatedWeight,
            proofGenerated: raw.proof_generated
        )
    }

    /// List all voting rounds known to the database, in storage order.
    public func listRounds() throws -> [VotingRoundSummary] {
        let ptr: UnsafeMutablePointer<FfiRoundSummaries> = try withHandle { dbh in
            guard let ptr = zcashlc_voting_list_rounds(dbh) else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`list_rounds` failed")
                )
            }
            return ptr
        }
        defer { zcashlc_voting_free_round_summaries(ptr) }

        let summariesPtr = ptr.pointee.ptr
        let count = Int(ptr.pointee.len)
        guard count > 0, let summariesPtr else { return [] }

        var summaries: [VotingRoundSummary] = []
        summaries.reserveCapacity(count)
        for index in 0..<count {
            let raw = summariesPtr.advanced(by: index).pointee
            let storedRoundId = try Self.decodeRequiredCString(raw.round_id, fieldName: "round_id")
            let phase = try Self.decodeRoundPhase(raw.phase)
            summaries.append(
                VotingRoundSummary(
                    roundId: storedRoundId,
                    phase: phase,
                    snapshotHeight: raw.snapshot_height,
                    createdAt: raw.created_at
                )
            )
        }
        return summaries
    }

    /// Read all vote records persisted for a round.
    public func getVotes(roundId: String) throws -> [VotingVoteRecord] {
        let roundIdBytes = [UInt8](roundId.utf8)

        let ptr: UnsafeMutablePointer<FfiVoteRecords> = try withHandle { dbh in
            let ptr: UnsafeMutablePointer<FfiVoteRecords>? = roundIdBytes.withUnsafeBufferPointer { buf in
                zcashlc_voting_get_votes(dbh, buf.baseAddress, UInt(buf.count))
            }
            guard let ptr else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`get_votes` failed")
                )
            }
            return ptr
        }
        defer { zcashlc_voting_free_vote_records(ptr) }

        let recordsPtr = ptr.pointee.ptr
        let count = Int(ptr.pointee.len)
        guard count > 0, let recordsPtr else { return [] }

        var records: [VotingVoteRecord] = []
        records.reserveCapacity(count)
        for index in 0..<count {
            let raw = recordsPtr.advanced(by: index).pointee
            records.append(
                VotingVoteRecord(
                    proposalId: raw.proposal_id,
                    bundleIndex: raw.bundle_index,
                    choice: raw.choice,
                    submitted: raw.submitted
                )
            )
        }
        return records
    }

    /// Clear all persisted data for a round.
    public func clearRound(roundId: String) throws {
        let roundIdBytes = [UInt8](roundId.utf8)
        try withHandle { dbh in
            let result = roundIdBytes.withUnsafeBufferPointer { buf in
                zcashlc_voting_clear_round(dbh, buf.baseAddress, UInt(buf.count))
            }
            guard result == 0 else {
                throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`clear_round` failed"))
            }
        }
    }

    /// Delete bundle rows with index ≥ `keepCount`, returning the number of rows deleted.
    public func deleteSkippedBundles(roundId: String, keepCount: UInt32) throws -> UInt32 {
        let roundIdBytes = [UInt8](roundId.utf8)
        return try withHandle { dbh in
            let deleted = roundIdBytes.withUnsafeBufferPointer { buf in
                zcashlc_voting_delete_skipped_bundles(dbh, buf.baseAddress, UInt(buf.count), keepCount)
            }
            guard deleted >= 0 else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`delete_skipped_bundles` failed")
                )
            }
            return UInt32(deleted)
        }
    }
}

// MARK: - Wallet notes

extension VotingRustBackend {
    /// Read the wallet notes eligible for voting at `snapshotHeight`.
    ///
    /// `accountUuidBytes` must be exactly 16 bytes; the FFI scopes the query
    /// to a specific account and rejects any other length.
    public func getWalletNotes(
        accountUuidBytes: [UInt8],
        dataDbPath: String,
        snapshotHeight: UInt64,
        networkId: UInt32
    ) throws -> [VotingNoteInfo] {
        guard accountUuidBytes.count == votingAccountUuidByteCount else {
            throw VotingRustBackendError.invalidData(
                "accountUuidBytes must be exactly \(votingAccountUuidByteCount) bytes"
            )
        }
        let pathBytes = [UInt8](dataDbPath.utf8)

        let ptr: UnsafeMutablePointer<FfiBoxedSlice> = try withHandle { dbh in
            let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = pathBytes.withUnsafeBufferPointer { pathBuf in
                accountUuidBytes.withUnsafeBufferPointer { uuidBuf in
                    zcashlc_voting_get_wallet_notes(
                        dbh,
                        pathBuf.baseAddress,
                        UInt(pathBuf.count),
                        snapshotHeight,
                        networkId,
                        uuidBuf.baseAddress,
                        UInt(uuidBuf.count)
                    )
                }
            }
            guard let ptr else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`get_wallet_notes` failed")
                )
            }
            return ptr
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }
}

// MARK: - Recovery state

extension VotingRustBackend {
    /// Persist the on-chain transaction hash for a submitted delegation bundle.
    public func storeDelegationTxHash(
        roundId: String,
        bundleIndex: UInt32,
        txHash: String
    ) throws {
        let roundIdBytes = [UInt8](roundId.utf8)
        let txHashBytes = [UInt8](txHash.utf8)
        try withHandle { dbh in
            let result = roundIdBytes.withUnsafeBufferPointer { ridBuf in
                txHashBytes.withUnsafeBufferPointer { txBuf in
                    zcashlc_voting_store_delegation_tx_hash(
                        dbh,
                        ridBuf.baseAddress,
                        UInt(ridBuf.count),
                        bundleIndex,
                        txBuf.baseAddress,
                        UInt(txBuf.count)
                    )
                }
            }
            guard result == 0 else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`store_delegation_tx_hash` failed")
                )
            }
        }

    }

    /// Load a previously-stored delegation transaction hash, if any.
    public func getDelegationTxHash(
        roundId: String,
        bundleIndex: UInt32
    ) throws -> String? {
        let roundIdBytes = [UInt8](roundId.utf8)
        let ptr: UnsafeMutablePointer<FfiBoxedSlice> = try withHandle { dbh in
            let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = roundIdBytes.withUnsafeBufferPointer { buf in
                zcashlc_voting_get_delegation_tx_hash(
                    dbh,
                    buf.baseAddress,
                    UInt(buf.count),
                    bundleIndex
                )
            }
            guard let ptr else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`get_delegation_tx_hash` failed")
                )
            }
            return ptr
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }

    /// Persist the on-chain transaction hash for a submitted vote.
    public func storeVoteTxHash(
        roundId: String,
        bundleIndex: UInt32,
        proposalId: UInt32,
        txHash: String
    ) throws {
        let roundIdBytes = [UInt8](roundId.utf8)
        let txHashBytes = [UInt8](txHash.utf8)
        try withHandle { dbh in
            let result = roundIdBytes.withUnsafeBufferPointer { ridBuf in
                txHashBytes.withUnsafeBufferPointer { txBuf in
                    zcashlc_voting_store_vote_tx_hash(
                        dbh,
                        ridBuf.baseAddress,
                        UInt(ridBuf.count),
                        bundleIndex,
                        proposalId,
                        txBuf.baseAddress,
                        UInt(txBuf.count)
                    )
                }
            }
            guard result == 0 else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`store_vote_tx_hash` failed")
                )
            }
        }
    }

    /// Load a previously-stored vote transaction hash, if any.
    public func getVoteTxHash(
        roundId: String,
        bundleIndex: UInt32,
        proposalId: UInt32
    ) throws -> String? {
        let roundIdBytes = [UInt8](roundId.utf8)
        let ptr: UnsafeMutablePointer<FfiBoxedSlice> = try withHandle { dbh in
            let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = roundIdBytes.withUnsafeBufferPointer { buf in
                zcashlc_voting_get_vote_tx_hash(
                    dbh,
                    buf.baseAddress,
                    UInt(buf.count),
                    bundleIndex,
                    proposalId
                )
            }
            guard let ptr else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`get_vote_tx_hash` failed")
                )
            }
            return ptr
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }

    /// Record the vote-commitment-tree position of a confirmed vote.
    ///
    /// The recovery bundle itself is no longer supplied by the caller:
    /// `zcash_voting` writes it when the vote is committed, so the position is
    /// all that remains to be learned from the chain.
    public func recordVcPosition(
        roundId: String,
        bundleIndex: UInt32,
        proposalId: UInt32,
        voteCommitmentTreePosition: UInt64
    ) throws {
        let roundIdBytes = [UInt8](roundId.utf8)
        try withHandle { dbh in
            let result = roundIdBytes.withUnsafeBufferPointer { ridBuf in
                zcashlc_voting_record_vc_position(
                    dbh,
                    ridBuf.baseAddress,
                    UInt(ridBuf.count),
                    bundleIndex,
                    proposalId,
                    voteCommitmentTreePosition
                )
            }
            guard result == 0 else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`record_vc_position` failed")
                )
            }
        }
    }

    /// Load a previously-stored commitment bundle, if any.
    public func getCommitmentBundle(
        roundId: String,
        bundleIndex: UInt32,
        proposalId: UInt32
    ) throws -> VotingStoredCommitmentBundle? {
        let roundIdBytes = [UInt8](roundId.utf8)
        let ptr: UnsafeMutablePointer<FfiBoxedSlice> = try withHandle { dbh in
            let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = roundIdBytes.withUnsafeBufferPointer { buf in
                zcashlc_voting_get_commitment_bundle(
                    dbh,
                    buf.baseAddress,
                    UInt(buf.count),
                    bundleIndex,
                    proposalId
                )
            }
            guard let ptr else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`get_commitment_bundle` failed")
                )
            }
            return ptr
        }
        defer { zcashlc_free_boxed_slice(ptr) }

        // Rust returns `Option<(String, u64)>`; in JSON that is `null` or
        // a 2-element array `[bundle_json, vc_tree_position]`.
        let stored: StoredCommitmentBundleWire? = try decodeJSON(from: ptr)
        return stored.map {
            VotingStoredCommitmentBundle(
                bundleJson: $0.bundleJson,
                voteCommitmentTreePosition: $0.voteCommitmentTreePosition
            )
        }
    }

    /// Persist a Keystone-produced PCZT signature for a delegation bundle.
    ///
    /// `sig` must be exactly 64 bytes; `sighash` and `randomizedKey` must each
    /// be exactly 32 bytes (matches the Rust-side validation).
    public func storeKeystoneSignature(
        roundId: String,
        bundleIndex: UInt32,
        sig: [UInt8],
        sighash: [UInt8],
        randomizedKey: [UInt8]
    ) throws {
        guard sig.count == votingSpendAuthSignatureByteCount else {
            throw VotingRustBackendError.invalidData(
                "sig must be exactly \(votingSpendAuthSignatureByteCount) bytes"
            )
        }
        guard sighash.count == votingPcztSighashByteCount else {
            throw VotingRustBackendError.invalidData(
                "sighash must be exactly \(votingPcztSighashByteCount) bytes"
            )
        }
        guard randomizedKey.count == votingRandomizedKeyByteCount else {
            throw VotingRustBackendError.invalidData(
                "randomizedKey must be exactly \(votingRandomizedKeyByteCount) bytes"
            )
        }
        let roundIdBytes = [UInt8](roundId.utf8)
        try withHandle { dbh in
            let result = roundIdBytes.withUnsafeBufferPointer { ridBuf in
                sig.withUnsafeBufferPointer { sigBuf in
                    sighash.withUnsafeBufferPointer { shBuf in
                        randomizedKey.withUnsafeBufferPointer { rkBuf in
                            zcashlc_voting_store_keystone_signature(
                                dbh,
                                ridBuf.baseAddress,
                                UInt(ridBuf.count),
                                bundleIndex,
                                sigBuf.baseAddress,
                                UInt(sigBuf.count),
                                shBuf.baseAddress,
                                UInt(shBuf.count),
                                rkBuf.baseAddress,
                                UInt(rkBuf.count)
                            )
                        }
                    }
                }
            }
            guard result == 0 else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`store_keystone_signature` failed")
                )
            }
        }
    }

    /// Load all Keystone signatures stored for a round, in storage order.
    public func getKeystoneSignatures(roundId: String) throws -> [VotingKeystoneSignatureRecord] {
        let roundIdBytes = [UInt8](roundId.utf8)
        let ptr: UnsafeMutablePointer<FfiBoxedSlice> = try withHandle { dbh in
            let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = roundIdBytes.withUnsafeBufferPointer { buf in
                zcashlc_voting_get_keystone_signatures(dbh, buf.baseAddress, UInt(buf.count))
            }
            guard let ptr else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`get_keystone_signatures` failed")
                )
            }
            return ptr
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }

    /// Remove all recovery-state rows for a round.
    public func clearRecoveryState(roundId: String) throws {
        let roundIdBytes = [UInt8](roundId.utf8)
        try withHandle { dbh in
            let result = roundIdBytes.withUnsafeBufferPointer { buf in
                zcashlc_voting_clear_recovery_state(dbh, buf.baseAddress, UInt(buf.count))
            }
            guard result == 0 else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`clear_recovery_state` failed")
                )
            }
        }
    }
}

// MARK: - Share delegation tracking

extension VotingRustBackend {
    /// Record a share delegation after sending it to helper servers.
    ///
    /// The share's nullifier is no longer supplied by the caller: `zcash_voting`
    /// derives it from the committed vote's recovery state, so a caller cannot
    /// record a nullifier that disagrees with the share it belongs to. This
    /// requires the vote to have been committed already.
    // swiftlint:disable:next function_parameter_count
    public func recordShareDelegation(
        roundId: String,
        bundleIndex: UInt32,
        proposalId: UInt32,
        shareIndex: UInt32,
        sentToURLs: [String],
        submitAt: UInt64
    ) throws {
        let roundIdBytes = [UInt8](roundId.utf8)
        let urlsJson = try JSONEncoder().encode(sentToURLs)
        let urlsBytes = [UInt8](urlsJson)

        try withHandle { dbh in
            let result = roundIdBytes.withUnsafeBufferPointer { ridBuf in
                urlsBytes.withUnsafeBufferPointer { urlsBuf in
                    zcashlc_voting_record_share_delegation(
                        dbh,
                        ridBuf.baseAddress,
                        UInt(ridBuf.count),
                        bundleIndex,
                        proposalId,
                        shareIndex,
                        urlsBuf.baseAddress,
                        UInt(urlsBuf.count),
                        submitAt
                    )
                }
            }
            guard result == 0 else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`record_share_delegation` failed")
                )
            }
        }
    }

    /// Read all share delegations recorded for a round.
    public func getShareDelegations(roundId: String) throws -> [VotingShareDelegation] {
        try fetchShareDelegations(
            roundId: roundId,
            fallback: "`get_share_delegations` failed"
        ) { dbh, ptr, len in
            zcashlc_voting_get_share_delegations(dbh, ptr, len)
        }
    }

    /// Read all share delegations not yet confirmed on chain.
    public func getUnconfirmedDelegations(roundId: String) throws -> [VotingShareDelegation] {
        try fetchShareDelegations(
            roundId: roundId,
            fallback: "`get_unconfirmed_delegations` failed"
        ) { dbh, ptr, len in
            zcashlc_voting_get_unconfirmed_delegations(dbh, ptr, len)
        }
    }

    /// Mark a previously-recorded share delegation as confirmed on chain.
    public func markShareConfirmed(
        roundId: String,
        bundleIndex: UInt32,
        proposalId: UInt32,
        shareIndex: UInt32
    ) throws {
        let roundIdBytes = [UInt8](roundId.utf8)
        try withHandle { dbh in
            let result = roundIdBytes.withUnsafeBufferPointer { buf in
                zcashlc_voting_mark_share_confirmed(
                    dbh,
                    buf.baseAddress,
                    UInt(buf.count),
                    bundleIndex,
                    proposalId,
                    shareIndex
                )
            }
            guard result == 0 else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`mark_share_confirmed` failed")
                )
            }
        }
    }

    /// Append additional helper-server URLs to an existing share delegation's
    /// `sent_to_urls` set.
    public func addSentServers(
        roundId: String,
        bundleIndex: UInt32,
        proposalId: UInt32,
        shareIndex: UInt32,
        newURLs: [String]
    ) throws {
        let roundIdBytes = [UInt8](roundId.utf8)
        let urlsJson = try JSONEncoder().encode(newURLs)
        let urlsBytes = [UInt8](urlsJson)
        try withHandle { dbh in
            let result = roundIdBytes.withUnsafeBufferPointer { ridBuf in
                urlsBytes.withUnsafeBufferPointer { urlsBuf in
                    zcashlc_voting_add_sent_servers(
                        dbh,
                        ridBuf.baseAddress,
                        UInt(ridBuf.count),
                        bundleIndex,
                        proposalId,
                        shareIndex,
                        urlsBuf.baseAddress,
                        UInt(urlsBuf.count)
                    )
                }
            }
            guard result == 0 else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`add_sent_servers` failed")
                )
            }
        }
    }
}

// MARK: - Delegation workflow

extension VotingRustBackend {
    /// Generate a new voting hotkey for `networkId`.
    ///
    /// - Important: The application **must persist** the returned
    /// ``VotingHotkey/storedSecret``. A voting hotkey is an app-owned random
    /// value rather than a wallet-seed derivation, so it cannot be re-derived:
    /// restoring the wallet from its seed phrase does **not** restore the
    /// ability to vote with a hotkey whose secret was lost, and any voting power
    /// already delegated to that hotkey becomes unusable. The SDK does not store
    /// it on the application's behalf.
    ///
    /// Generate a hotkey once and reuse the stored secret; calling this again
    /// produces an unrelated hotkey rather than recovering the previous one.
    ///
    /// The secret is owned by Swift after this call. The Rust allocation is
    /// zeroized and freed before this method returns; treat the returned bytes
    /// with the same care as any other key material.
    public static func generateHotkey(networkId: UInt32) throws -> VotingHotkey {
        guard let ptr = zcashlc_voting_generate_hotkey(networkId) else {
            throw VotingRustBackendError.rustError(
                staticLastErrorMessage(fallback: "`generate_hotkey` failed")
            )
        }
        defer { zcashlc_voting_free_hotkey(ptr) }

        let raw = ptr.pointee
        return VotingHotkey(
            storedSecret: bytesFromRawPointer(raw.stored_secret, count: Int(raw.stored_secret_len)),
            rawOrchardAddress: bytesFromRawPointer(
                raw.raw_orchard_address,
                count: Int(raw.raw_orchard_address_len)
            ),
            addressIndex: raw.address_index
        )
    }

    /// Setup vote bundles for a round.
    public func setupBundles(
        roundId: String,
        notes: [VotingNoteInfo]
    ) throws -> VotingBundleSetupResult {
        let roundIdBytes = [UInt8](roundId.utf8)
        let notesJson = try JSONEncoder().encode(notes)
        let notesBytes = [UInt8](notesJson)

        let ptr: UnsafeMutablePointer<FfiBundleSetupResult> = try withHandle { dbh in
            let ptr: UnsafeMutablePointer<FfiBundleSetupResult>? = roundIdBytes.withUnsafeBufferPointer { ridBuf in
                notesBytes.withUnsafeBufferPointer { notesBuf in
                    zcashlc_voting_setup_bundles(
                        dbh,
                        ridBuf.baseAddress,
                        UInt(ridBuf.count),
                        notesBuf.baseAddress,
                        UInt(notesBuf.count)
                    )
                }
            }
            guard let ptr else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`setup_bundles` failed")
                )
            }
            return ptr
        }
        defer { zcashlc_voting_free_bundle_setup_result(ptr) }

        let raw = ptr.pointee
        return VotingBundleSetupResult(
            bundleCount: raw.bundle_count,
            eligibleWeight: raw.eligible_weight,
            droppedCount: raw.dropped_count
        )
    }

    /// Number of vote bundles persisted for a round, or 0 if the round is unknown.
    public func getBundleCount(roundId: String) throws -> UInt32 {
        let roundIdBytes = [UInt8](roundId.utf8)
        return try withHandle { dbh in
            let count = roundIdBytes.withUnsafeBufferPointer { buf in
                zcashlc_voting_get_bundle_count(dbh, buf.baseAddress, UInt(buf.count))
            }
            guard count >= 0 else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`get_bundle_count` failed")
                )
            }
            return UInt32(count)
        }
    }

    /// Build the voting PCZT for a bundle.
    public func buildPczt(_ params: VotingBuildPcztParams) throws -> VotingPczt {
        let keys = params.keys
        guard keys.seedFingerprint.count == votingSeedFingerprintByteCount else {
            throw VotingRustBackendError.invalidData(
                "seedFingerprint must be exactly \(votingSeedFingerprintByteCount) bytes"
            )
        }

        let roundIdBytes = [UInt8](params.roundId.utf8)
        let notesJson = try JSONEncoder().encode(params.notes)
        let notesBytes = [UInt8](notesJson)
        let roundNameBytes = [UInt8](keys.roundName.utf8)

        let ptr: UnsafeMutablePointer<FfiBoxedSlice> = try withHandle { dbh in
            let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = roundIdBytes.withUnsafeBufferPointer { ridBuf in
                notesBytes.withUnsafeBufferPointer { notesBuf in
                    keys.fvk.withUnsafeBufferPointer { fvkBuf in
                        keys.hotkeyStoredSecret.withUnsafeBufferPointer { secretBuf in
                            keys.seedFingerprint.withUnsafeBufferPointer { fpBuf in
                                roundNameBytes.withUnsafeBufferPointer { nameBuf in
                                    zcashlc_voting_build_pczt(
                                        dbh,
                                        ridBuf.baseAddress,
                                        UInt(ridBuf.count),
                                        params.bundleIndex,
                                        notesBuf.baseAddress,
                                        UInt(notesBuf.count),
                                        fvkBuf.baseAddress,
                                        UInt(fvkBuf.count),
                                        secretBuf.baseAddress,
                                        UInt(secretBuf.count),
                                        params.consensusBranchId,
                                        fpBuf.baseAddress,
                                        UInt(fpBuf.count),
                                        keys.accountIndex,
                                        nameBuf.baseAddress,
                                        UInt(nameBuf.count)
                                    )
                                }
                            }
                        }
                    }
                }
            }
            guard let ptr else {
                throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`build_pczt` failed"))
            }
            return ptr
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }

    /// Persist a `TreeState` blob keyed by round ID, for later witness generation.
    public func storeTreeState(roundId: String, treeState: [UInt8]) throws {
        let roundIdBytes = [UInt8](roundId.utf8)
        try withHandle { dbh in
            let result = roundIdBytes.withUnsafeBufferPointer { ridBuf in
                treeState.withUnsafeBufferPointer { tsBuf in
                    zcashlc_voting_store_tree_state(
                        dbh,
                        ridBuf.baseAddress,
                        UInt(ridBuf.count),
                        tsBuf.baseAddress,
                        UInt(tsBuf.count)
                    )
                }
            }
            guard result == 0 else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`store_tree_state` failed")
                )
            }
        }
    }

    /// Sign one delegation bundle's PCZT sighash with this account's own Orchard
    /// SpendAuth key.
    ///
    /// `zcash_voting` 2.0 stopped deriving account keys and signing for its
    /// callers, and prescribes this replacement for software wallets: load the
    /// bundle's signing request (account index, network, seed fingerprint,
    /// sighash and spend-auth randomizer), derive the account SpendAuth key from
    /// the wallet seed, randomize it with the randomizer, and sign the sighash.
    /// All of that happens in Rust — the seed goes in, only the detached
    /// signature comes back out.
    ///
    /// This is the software counterpart of the Keystone flow: there, the device
    /// produces the signature and the app extracts it from the signed PCZT; here
    /// the wallet produces it itself. Both then call the same
    /// ``getDelegationSubmission(roundId:bundleIndex:signature:sighash:)``,
    /// which is the only remaining path into a submission payload.
    ///
    /// - Parameters:
    ///   - keys: the same ``VotingDelegationKeyInputs`` used to build and prove
    ///     this bundle. The crate loads the signing request through them, so a
    ///     different account index, hotkey secret or seed fingerprint fails
    ///     instead of silently signing for the wrong account.
    ///   - seed: the wallet's root seed, at least 32 bytes. It is borrowed for
    ///     the duration of this call, is never persisted or logged, and must be
    ///     the seed whose fingerprint is in `keys` — a mismatch throws rather
    ///     than producing a signature the chain would reject.
    /// - Returns: the detached 64-byte SpendAuth signature and the 32-byte
    ///   ZIP-244 sighash it covers. Pass both to `getDelegationSubmission`
    ///   unchanged.
    /// - Throws: ``VotingRustBackendError/databaseNotOpen`` if no database is
    ///   open; ``VotingRustBackendError/invalidData`` if `seed` or the seed
    ///   fingerprint is the wrong length; ``VotingRustBackendError/rustError``
    ///   if the bundle has no stored signing request yet (its PCZT setup has not
    ///   run), or the seed does not match the request.
    public func signDelegationRequest(
        roundId: String,
        bundleIndex: UInt32,
        keys: VotingDelegationKeyInputs,
        seed: [UInt8]
    ) throws -> VotingDelegationSignature {
        guard keys.seedFingerprint.count == votingSeedFingerprintByteCount else {
            throw VotingRustBackendError.invalidData(
                "seedFingerprint must be exactly \(votingSeedFingerprintByteCount) bytes"
            )
        }
        guard seed.count >= votingMinSeedByteCount else {
            throw VotingRustBackendError.invalidData(
                "seed must be at least \(votingMinSeedByteCount) bytes"
            )
        }

        let roundIdBytes = [UInt8](roundId.utf8)
        let roundNameBytes = [UInt8](keys.roundName.utf8)

        let ptr: UnsafeMutablePointer<FfiBoxedSlice> = try withHandle { dbh in
            let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = roundIdBytes.withUnsafeBufferPointer { ridBuf in
                keys.fvk.withUnsafeBufferPointer { fvkBuf in
                    keys.hotkeyStoredSecret.withUnsafeBufferPointer { secretBuf in
                        keys.seedFingerprint.withUnsafeBufferPointer { fpBuf in
                            roundNameBytes.withUnsafeBufferPointer { nameBuf in
                                seed.withUnsafeBufferPointer { seedBuf in
                                    zcashlc_voting_sign_delegation_request(
                                        dbh,
                                        ridBuf.baseAddress,
                                        UInt(ridBuf.count),
                                        bundleIndex,
                                        fvkBuf.baseAddress,
                                        UInt(fvkBuf.count),
                                        secretBuf.baseAddress,
                                        UInt(secretBuf.count),
                                        fpBuf.baseAddress,
                                        UInt(fpBuf.count),
                                        keys.accountIndex,
                                        nameBuf.baseAddress,
                                        UInt(nameBuf.count),
                                        seedBuf.baseAddress,
                                        UInt(seedBuf.count)
                                    )
                                }
                            }
                        }
                    }
                }
            }
            guard let ptr else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`sign_delegation_request` failed")
                )
            }
            return ptr
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }

    /// Get the delegation submission payload for an externally produced
    /// signature.
    ///
    /// This is the only remaining path: `zcash_voting` no longer derives account
    /// keys or signs on the caller's behalf, so the SpendAuth signature and the
    /// ZIP-244 sighash must come from the wallet's signer — whether that signer
    /// is a Keystone device or the wallet itself.
    ///
    /// `signature` must be exactly 64 bytes; `sighash` must be exactly 32 bytes.
    public func getDelegationSubmission(
        roundId: String,
        bundleIndex: UInt32,
        signature: [UInt8],
        sighash: [UInt8]
    ) throws -> VotingDelegationSubmission {
        guard signature.count == votingSpendAuthSignatureByteCount else {
            throw VotingRustBackendError.invalidData(
                "signature must be exactly \(votingSpendAuthSignatureByteCount) bytes"
            )
        }
        guard sighash.count == votingPcztSighashByteCount else {
            throw VotingRustBackendError.invalidData(
                "sighash must be exactly \(votingPcztSighashByteCount) bytes"
            )
        }
        let roundIdBytes = [UInt8](roundId.utf8)

        let ptr: UnsafeMutablePointer<FfiBoxedSlice> = try withHandle { dbh in
            let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = roundIdBytes.withUnsafeBufferPointer { ridBuf in
                signature.withUnsafeBufferPointer { sigBuf in
                    sighash.withUnsafeBufferPointer { shBuf in
                        zcashlc_voting_get_delegation_submission_with_signature(
                            dbh,
                            ridBuf.baseAddress,
                            UInt(ridBuf.count),
                            bundleIndex,
                            sigBuf.baseAddress,
                            UInt(sigBuf.count),
                            shBuf.baseAddress,
                            UInt(shBuf.count)
                        )
                    }
                }
            }
            guard let ptr else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(
                        fallback: "`get_delegation_submission_with_signature` failed"
                    )
                )
            }
            return ptr
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }

    /// Persist the VAN leaf position after delegation transaction confirmation.
    public func storeVanPosition(
        roundId: String,
        bundleIndex: UInt32,
        position: UInt32
    ) throws {
        let roundIdBytes = [UInt8](roundId.utf8)
        try withHandle { dbh in
            let result = roundIdBytes.withUnsafeBufferPointer { buf in
                zcashlc_voting_store_van_position(
                    dbh,
                    buf.baseAddress,
                    UInt(buf.count),
                    bundleIndex,
                    position
                )
            }
            guard result == 0 else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`store_van_position` failed")
                )
            }
        }
    }

    /// Build and prove the real delegation ZKP for a bundle. Long-running.
    ///
    /// `progress` is invoked with values in `0.0...1.0` from the proving thread.
    /// The closure must be thread-safe; it may be called concurrently with the
    /// returned `Task`'s actor and is bridged through a `@convention(c)`
    /// trampoline. The closure is retained for the duration of the call only.
    ///
    /// Do not call back into this `VotingRustBackend` from `progress`. Rust may
    /// invoke the callback while the database-handle lock is held, so re-entering
    /// this backend can deadlock.
    public func buildAndProveDelegation(
        _ params: VotingDelegationProofParams,
        pirEndpoints: [String],
        expectedSnapshotHeight: UInt64,
        pirLayout: VotingPirLayout = .unknown,
        pirResolver: PirSnapshotResolver = PirSnapshotResolver(),
        progress: (@Sendable (Double) -> Void)? = nil
    ) async throws -> VotingDelegationProofResult {
        try requireOpenDatabase()

        guard params.keys.seedFingerprint.count == votingSeedFingerprintByteCount else {
            throw VotingRustBackendError.invalidData(
                "seedFingerprint must be exactly \(votingSeedFingerprintByteCount) bytes"
            )
        }

        let pirServerUrl = try await pirResolver.resolve(
            endpoints: pirEndpoints,
            expectedSnapshotHeight: BlockHeight(expectedSnapshotHeight)
        )

        // The proving FFI can run for minutes; detach so we do not block the
        // caller's executor for the full duration. `VotingRustBackend` is
        // `@unchecked Sendable`, the lock keeps `withHandle` correct, and
        // `notes`/byte arrays cross the boundary by value.
        return try await Task.detached { [self] in
            try syncBuildAndProveDelegation(
                params,
                pirServerUrl: pirServerUrl,
                pirLayout: pirLayout,
                progress: progress
            )
        }.value
    }

    /// Validate a PIR-fetched IMT non-membership proof bytewise.
    ///
    /// Returns `true` if the proof is well-formed and valid, `false` if it is
    /// well-formed but invalid. Throws `.invalidData` for length mismatches and
    /// `.rustError` if the underlying validation panics.
    public static func validatePirProof(_ proof: VotingPirProof) throws -> Bool {
        guard proof.root.count == votingPirRootByteCount else {
            throw VotingRustBackendError.invalidData(
                "root must be exactly \(votingPirRootByteCount) bytes"
            )
        }
        guard proof.nfBounds.count == votingPirNullifierBoundsByteCount else {
            throw VotingRustBackendError.invalidData(
                "nfBounds must be exactly \(votingPirNullifierBoundsByteCount) bytes"
            )
        }
        let pirPathDescription = "\(votingPirPathElementCount) * \(votingPirRootByteCount)"
        guard proof.path.count == votingPirPathByteCount else {
            throw VotingRustBackendError.invalidData(
                "path must be exactly \(votingPirPathByteCount) bytes (\(pirPathDescription))"
            )
        }
        guard proof.nullifier.count == votingPirNullifierByteCount else {
            throw VotingRustBackendError.invalidData(
                "nullifier must be exactly \(votingPirNullifierByteCount) bytes"
            )
        }
        guard proof.expectedRoot.count == votingPirRootByteCount else {
            throw VotingRustBackendError.invalidData(
                "expectedRoot must be exactly \(votingPirRootByteCount) bytes"
            )
        }

        let result = proof.root.withUnsafeBufferPointer { rootBuf in
            proof.nfBounds.withUnsafeBufferPointer { boundsBuf in
                proof.path.withUnsafeBufferPointer { pathBuf in
                    proof.nullifier.withUnsafeBufferPointer { nfBuf in
                        proof.expectedRoot.withUnsafeBufferPointer { expBuf in
                            zcashlc_voting_validate_pir_proof(
                                rootBuf.baseAddress,
                                boundsBuf.baseAddress,
                                proof.leafPosition,
                                pathBuf.baseAddress,
                                nfBuf.baseAddress,
                                expBuf.baseAddress
                            )
                        }
                    }
                }
            }
        }

        switch result {
        case 1: return true
        case 0: return false
        default:
            throw VotingRustBackendError.rustError(
                staticLastErrorMessage(fallback: "`validate_pir_proof` failed")
            )
        }
    }
}

// MARK: - Private helpers

private extension VotingRustBackend {
    /// Runs a database-bound operation while holding the handle lock. Keeping
    /// the lock through the FFI call prevents `close()` from freeing the handle
    /// before Rust is done using it.
    func withHandle<T>(_ operation: (OpaquePointer) throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        guard let dbh = handle else {
            throw VotingRustBackendError.databaseNotOpen
        }
        return try operation(dbh)
    }

    func requireOpenDatabase() throws {
        lock.lock()
        defer { lock.unlock() }

        guard handle != nil else {
            throw VotingRustBackendError.databaseNotOpen
        }
    }

    func lastErrorMessage(fallback: String) -> String {
        Self.staticLastErrorMessage(fallback: fallback)
    }

    func decodeJSON<T: Decodable>(from ptr: UnsafeMutablePointer<FfiBoxedSlice>) throws -> T {
        let data = Data(bytes: ptr.pointee.ptr, count: Int(ptr.pointee.len))
        return try JSONDecoder().decode(T.self, from: data)
    }

    /// Synchronous body of `commitVote`. Runs inside `Task.detached` so proving
    /// does not block the caller's executor.
    func syncCommitVote(
        _ draft: VoteCommitDraft,
        progress: (@Sendable (Double) -> Void)?
    ) throws -> VotingVoteCommit {
        let roundIdBytes = [UInt8](draft.roundId.utf8)
        let authPathJson = try JSONEncoder().encode(draft.vanWitness.authPath)
        let authPathBytes = [UInt8](authPathJson)

        let progressBox = progress.map(VotingProgressBox.init(report:))
        let progressContext = progressBox.map { Unmanaged.passRetained($0).toOpaque() }
        defer {
            if let progressContext {
                Unmanaged<VotingProgressBox>.fromOpaque(progressContext).release()
            }
        }
        let trampoline: VotingProgressCallback? = progressBox == nil ? nil : votingProgressCallbackTrampoline

        let ptr: UnsafeMutablePointer<FfiBoxedSlice> = try withHandle { dbh in
            let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = roundIdBytes.withUnsafeBufferPointer { ridBuf in
                draft.hotkeyStoredSecret.withUnsafeBufferPointer { secretBuf in
                    authPathBytes.withUnsafeBufferPointer { pathBuf in
                        zcashlc_voting_commit_vote(
                            dbh,
                            ridBuf.baseAddress,
                            UInt(ridBuf.count),
                            draft.bundleIndex,
                            secretBuf.baseAddress,
                            UInt(secretBuf.count),
                            draft.proposalId,
                            draft.choice,
                            draft.numOptions,
                            draft.voteCommitmentTreePosition,
                            pathBuf.baseAddress,
                            UInt(pathBuf.count),
                            draft.vanWitness.position,
                            draft.vanWitness.anchorHeight,
                            trampoline,
                            progressContext,
                            draft.singleShare ? 1 : 0
                        )
                    }
                }
            }

            guard let ptr else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`commit_vote` failed")
                )
            }
            return ptr
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }

    /// Reads the last error recorded by `libzcashlc` and clears it as a side
    /// effect, so subsequent failures do not surface a stale message.
    static func staticLastErrorMessage(fallback: String) -> String {
        let errorLen = zcashlc_last_error_length()
        defer { zcashlc_clear_last_error() }

        if errorLen > 0 {
            let error = UnsafeMutablePointer<Int8>.allocate(capacity: Int(errorLen))
            defer { error.deallocate() }
            zcashlc_error_message_utf8(error, errorLen)
            if let message = String(validatingUTF8: error) {
                return message
            }
        }

        return fallback
    }

    /// Decode JSON returned by static FFI calls.
    static func staticDecodeJSON<T: Decodable>(from ptr: UnsafeMutablePointer<FfiBoxedSlice>) throws -> T {
        let data = Data(bytes: ptr.pointee.ptr, count: Int(ptr.pointee.len))
        return try JSONDecoder().decode(T.self, from: data)
    }

    /// Decode Rust's persisted round phase without silently aliasing unknown values.
    static func decodeRoundPhase(_ rawValue: UInt32) throws -> VotingRoundPhase {
        guard let phase = VotingRoundPhase(rawValue: rawValue) else {
            throw VotingRustBackendError.invalidData("unknown phase \(rawValue)")
        }

        return phase
    }

    /// Decode required C strings from Rust, treating null as an invariant violation.
    static func decodeRequiredCString(
        _ pointer: UnsafePointer<CChar>?,
        fieldName: String
    ) throws -> String {
        guard let pointer else {
            throw VotingRustBackendError.invalidData("\(fieldName) must not be null")
        }

        return String(cString: pointer)
    }

    /// Calls a static FFI returning `*FfiBoxedSlice` and copies the resulting
    /// bytes into a Swift `[UInt8]`, freeing the slice in `defer`.
    static func staticBoxedSliceFFI(
        fallback: String,
        _ call: () -> UnsafeMutablePointer<FfiBoxedSlice>?
    ) throws -> [UInt8] {
        guard let ptr = call() else {
            throw VotingRustBackendError.rustError(staticLastErrorMessage(fallback: fallback))
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return [UInt8](Data(bytes: ptr.pointee.ptr, count: Int(ptr.pointee.len)))
    }

    /// Read share-delegation records from a DB-bound FFI JSON response.
    func fetchShareDelegations(
        roundId: String,
        fallback: String,
        _ call: (OpaquePointer, UnsafePointer<UInt8>?, UInt) -> UnsafeMutablePointer<FfiBoxedSlice>?
    ) throws -> [VotingShareDelegation] {
        let roundIdBytes = [UInt8](roundId.utf8)
        let ptr: UnsafeMutablePointer<FfiBoxedSlice> = try withHandle { dbh in
            let ptr = roundIdBytes.withUnsafeBufferPointer { buf in
                call(dbh, buf.baseAddress, UInt(buf.count))
            }
            guard let ptr else {
                throw VotingRustBackendError.rustError(lastErrorMessage(fallback: fallback))
            }
            return ptr
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }

    /// Synchronous body of `buildAndProveDelegation`. Lives on the FFI thread
    /// inside `Task.detached` so the calling actor is not blocked for the
    /// duration of proving (potentially minutes).
    func syncBuildAndProveDelegation(
        _ params: VotingDelegationProofParams,
        pirServerUrl: String,
        pirLayout: VotingPirLayout,
        progress: (@Sendable (Double) -> Void)?
    ) throws -> VotingDelegationProofResult {
        let keys = params.keys
        let roundIdBytes = [UInt8](params.roundId.utf8)
        let notesJson = try JSONEncoder().encode(params.notes)
        let notesBytes = [UInt8](notesJson)
        let roundNameBytes = [UInt8](keys.roundName.utf8)
        let urlBytes = [UInt8](pirServerUrl.utf8)

        let progressBox = progress.map(VotingProgressBox.init(report:))
        let progressContext = progressBox.map { Unmanaged.passRetained($0).toOpaque() }
        defer {
            if let progressContext {
                Unmanaged<VotingProgressBox>.fromOpaque(progressContext).release()
            }
        }
        let trampoline: VotingProgressCallback? = progressBox == nil ? nil : votingProgressCallbackTrampoline

        let ptr: UnsafeMutablePointer<FfiBoxedSlice> = try withHandle { dbh in
            let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = roundIdBytes.withUnsafeBufferPointer { ridBuf in
                notesBytes.withUnsafeBufferPointer { notesBuf in
                    keys.fvk.withUnsafeBufferPointer { fvkBuf in
                        keys.hotkeyStoredSecret.withUnsafeBufferPointer { secretBuf in
                            keys.seedFingerprint.withUnsafeBufferPointer { fpBuf in
                                roundNameBytes.withUnsafeBufferPointer { nameBuf in
                                    urlBytes.withUnsafeBufferPointer { urlBuf in
                                        zcashlc_voting_build_and_prove_delegation(
                                            dbh,
                                            ridBuf.baseAddress,
                                            UInt(ridBuf.count),
                                            params.bundleIndex,
                                            notesBuf.baseAddress,
                                            UInt(notesBuf.count),
                                            fvkBuf.baseAddress,
                                            UInt(fvkBuf.count),
                                            secretBuf.baseAddress,
                                            UInt(secretBuf.count),
                                            fpBuf.baseAddress,
                                            UInt(fpBuf.count),
                                            keys.accountIndex,
                                            nameBuf.baseAddress,
                                            UInt(nameBuf.count),
                                            urlBuf.baseAddress,
                                            UInt(urlBuf.count),
                                            pirLayout.pirDepth,
                                            pirLayout.tier0Layers,
                                            pirLayout.tier1Layers,
                                            pirLayout.polyLen,
                                            trampoline,
                                            progressContext
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
            guard let ptr else {
                throw VotingRustBackendError.rustError(
                    lastErrorMessage(fallback: "`build_and_prove_delegation` failed")
                )
            }
            return ptr
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }
}

// MARK: - File-private FFI bridges

/// The `commitVote` arguments, grouped so the detached proving body takes a
/// single `Sendable` value instead of eleven captured parameters.
///
/// Conforms to `Undescribable` because `hotkeyStoredSecret` is the voting
/// hotkey's key material.
private struct VoteCommitDraft: Sendable, Undescribable {
    let roundId: String
    let bundleIndex: UInt32
    let hotkeyStoredSecret: [UInt8]
    let proposalId: UInt32
    let choice: UInt32
    let numOptions: UInt32
    let voteCommitmentTreePosition: UInt64
    let vanWitness: VotingVanWitness
    let singleShare: Bool
}

/// JSON wire format for `Option<(String, u64)>` returned by the recovery FFI.
/// Decodes from a 2-element JSON array `[bundleJson, vcTreePosition]`.
private struct StoredCommitmentBundleWire: Decodable {
    let bundleJson: String
    let voteCommitmentTreePosition: UInt64

    init(from decoder: Decoder) throws {
        var container = try decoder.unkeyedContainer()
        bundleJson = try container.decode(String.self)
        voteCommitmentTreePosition = try container.decode(UInt64.self)
    }
}

/// C function-pointer type for the voting proof progress callback.
private typealias VotingProgressCallback = @convention(c) (Double, UnsafeMutableRawPointer?) -> Void

/// Heap-allocated container that retains the Swift progress closure across the
/// FFI call so the `@convention(c)` trampoline can recover it from the
/// `*mut c_void` context pointer.
private final class VotingProgressBox: @unchecked Sendable {
    let report: @Sendable (Double) -> Void
    init(report: @escaping @Sendable (Double) -> Void) {
        self.report = report
    }
}

/// Trampoline matching `VotingProgressCallback`. Passes the progress value to
/// the Swift closure stored in the `VotingProgressBox` reachable through
/// `context`.
private let votingProgressCallbackTrampoline: VotingProgressCallback = { progress, context in
    guard let context else { return }
    let box = Unmanaged<VotingProgressBox>.fromOpaque(context).takeUnretainedValue()
    box.report(progress)
}

/// Run `body` with the buffer pointer for `bytes` if it is non-nil, otherwise
/// pass `nil`. Used by FFI calls that take an optional `(ptr, len)` pair.
private func withOptionalBufferPointer<R>(
    _ bytes: [UInt8]?,
    _ body: (UnsafeBufferPointer<UInt8>?) throws -> R
) rethrows -> R {
    if let bytes {
        return try bytes.withUnsafeBufferPointer { try body($0) }
    } else {
        return try body(nil)
    }
}

/// Copy `count` bytes starting at `pointer` into a Swift `[UInt8]`.
/// Returns an empty array if either argument is degenerate.
private func bytesFromRawPointer(_ pointer: UnsafeMutablePointer<UInt8>?, count: Int) -> [UInt8] {
    guard let pointer, count > 0 else { return [] }
    return [UInt8](UnsafeBufferPointer(start: pointer, count: count))
}

#if DEBUG
extension VotingRustBackend {
    func withLockedHandleForTesting(_ operation: () -> Void) throws {
        try withHandle { _ in
            operation()
        }
    }
}
#endif
