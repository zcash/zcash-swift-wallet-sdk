// swiftlint:disable file_length
// VotingRustBackend.swift
// Swift wrapper for the hand-rolled voting C FFI in voting.rs.
// Manages the opaque VotingDatabaseHandle and bridges all voting operations.

import Foundation
import libzcashlc

// MARK: - Error

public enum VotingRustBackendError: Error, Equatable {
    case databaseAlreadyOpen
    case databaseNotOpen
    case rustError(String)
    case invalidData(String)
}

// MARK: - Progress callback

/// Closure type for proof progress reporting.
public typealias VotingProgressHandler = @Sendable (Double) -> Void

// MARK: - VotingRustBackend

/// Wraps the voting C FFI. Manages an opaque VotingDatabaseHandle pointer.
///
/// Thread safety: all methods that touch the database handle are isolated to a
/// private serial actor. The handle is opened once and freed on `close()` or deinit.
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

    /// Open the voting database at `path`.
    public func open(path: String) throws {
        lock.lock()
        defer { lock.unlock() }

        guard handle == nil else {
            throw VotingRustBackendError.databaseAlreadyOpen
        }

        let pathBytes = [UInt8](path.utf8)
        guard let ptr = pathBytes.withUnsafeBufferPointer({ buf in
            zcashlc_voting_db_open(buf.baseAddress, UInt(buf.count))
        }) else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`voting_db_open` failed"))
        }
        handle = ptr
    }

    /// Close the voting database, freeing the handle.
    public func close() {
        lock.lock()
        defer { lock.unlock() }
        if let dbh = handle {
            zcashlc_voting_db_free(dbh)
            handle = nil
        }
    }
}

// MARK: - Round management

extension VotingRustBackend {
    /// Initialize a voting round.
    // swiftlint:disable:next function_parameter_count
    public func initRound(
        roundId: String,
        snapshotHeight: UInt64,
        eaPk: [UInt8],
        ncRoot: [UInt8],
        nullifierImtRoot: [UInt8],
        sessionJson: String?
    ) throws {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)
        let sessionBytes: [UInt8]? = sessionJson.map { [UInt8]($0.utf8) }

        let result = roundIdBytes.withUnsafeBufferPointer { ridBuf in
            eaPk.withUnsafeBufferPointer { eaBuf in
                ncRoot.withUnsafeBufferPointer { ncBuf in
                    nullifierImtRoot.withUnsafeBufferPointer { nfBuf in
                        if let sessionBytes {
                            return sessionBytes.withUnsafeBufferPointer { sjBuf in
                                zcashlc_voting_init_round(
                                    dbh,
                                    ridBuf.baseAddress,
                                    UInt(ridBuf.count),
                                    snapshotHeight,
                                    eaBuf.baseAddress,
                                    UInt(eaBuf.count),
                                    ncBuf.baseAddress,
                                    UInt(ncBuf.count),
                                    nfBuf.baseAddress,
                                    UInt(nfBuf.count),
                                    sjBuf.baseAddress,
                                    UInt(sjBuf.count)
                                )
                            }
                        } else {
                            return zcashlc_voting_init_round(
                                dbh,
                                ridBuf.baseAddress,
                                UInt(ridBuf.count),
                                snapshotHeight,
                                eaBuf.baseAddress,
                                UInt(eaBuf.count),
                                ncBuf.baseAddress,
                                UInt(ncBuf.count),
                                nfBuf.baseAddress,
                                UInt(nfBuf.count),
                                nil,
                                0
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

    /// Get the state of a voting round.
    public func getRoundState(roundId: String) throws -> VotingRoundState {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)

        guard let ptr = roundIdBytes.withUnsafeBufferPointer({ buf in
            zcashlc_voting_get_round_state(dbh, buf.baseAddress, UInt(buf.count))
        }) else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`get_round_state` failed"))
        }

        defer { zcashlc_voting_free_round_state(ptr) }

        let state = ptr.pointee
        let phase = VotingRoundPhase(rawValue: state.phase) ?? .initialized

        let roundIdStr: String
        if let rid = state.round_id {
            roundIdStr = String(cString: rid)
        } else {
            roundIdStr = roundId
        }

        let hotkeyAddr: String?
        if let addr = state.hotkey_address {
            hotkeyAddr = String(cString: addr)
        } else {
            hotkeyAddr = nil
        }

        let weight: UInt64? = state.delegated_weight >= 0 ? UInt64(state.delegated_weight) : nil

        return VotingRoundState(
            roundId: roundIdStr,
            phase: phase,
            snapshotHeight: state.snapshot_height,
            hotkeyAddress: hotkeyAddr,
            delegatedWeight: weight,
            proofGenerated: state.proof_generated
        )
    }

    /// List all voting rounds.
    public func listRounds() throws -> [VotingRoundSummary] {
        let dbh = try requireHandle()

        guard let ptr = zcashlc_voting_list_rounds(dbh) else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`list_rounds` failed"))
        }

        defer { zcashlc_voting_free_round_summaries(ptr) }

        let summaries = ptr.pointee
        var roundSummaries: [VotingRoundSummary] = []
        for i in 0..<Int(summaries.len) {
            let entry = summaries.ptr.advanced(by: i).pointee
            let rid = entry.round_id != nil ? String(cString: entry.round_id) : ""
            let phase = VotingRoundPhase(rawValue: entry.phase) ?? .initialized
            roundSummaries.append(VotingRoundSummary(
                roundId: rid,
                phase: phase,
                snapshotHeight: entry.snapshot_height,
                createdAt: entry.created_at
            ))
        }
        return roundSummaries
    }

    /// Get vote records for a round.
    public func getVotes(roundId: String) throws -> [VotingVoteRecord] {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)

        guard let ptr = roundIdBytes.withUnsafeBufferPointer({ buf in
            zcashlc_voting_get_votes(dbh, buf.baseAddress, UInt(buf.count))
        }) else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`get_votes` failed"))
        }

        defer { zcashlc_voting_free_vote_records(ptr) }

        let records = ptr.pointee
        var result: [VotingVoteRecord] = []
        for i in 0..<Int(records.len) {
            let record = records.ptr.advanced(by: i).pointee
            result.append(VotingVoteRecord(
                proposalId: record.proposal_id,
                bundleIndex: record.bundle_index,
                choice: record.choice,
                submitted: record.submitted
            ))
        }
        return result
    }

    /// Clear all data for a voting round.
    public func clearRound(roundId: String) throws {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)

        let result = roundIdBytes.withUnsafeBufferPointer { buf in
            zcashlc_voting_clear_round(dbh, buf.baseAddress, UInt(buf.count))
        }

        guard result == 0 else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`clear_round` failed"))
        }
    }

    /// Delete skipped bundles (bundle_index >= keepCount).
    /// Returns the number of deleted rows.
    public func deleteSkippedBundles(roundId: String, keepCount: UInt32) throws -> Int64 {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)

        let result = roundIdBytes.withUnsafeBufferPointer { buf in
            zcashlc_voting_delete_skipped_bundles(dbh, buf.baseAddress, UInt(buf.count), keepCount)
        }

        guard result >= 0 else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`delete_skipped_bundles` failed"))
        }
        return result
    }
}

// MARK: - Wallet notes

extension VotingRustBackend {
    /// Get wallet notes eligible for voting at the snapshot height.
    public func getWalletNotes(
        walletDbPath: String,
        snapshotHeight: UInt64,
        networkId: UInt32,
        seedFingerprint: [UInt8]?,
        accountIndex: Int64
    ) throws -> [VotingNoteInfo] {
        let dbh = try requireHandle()
        let pathBytes = [UInt8](walletDbPath.utf8)

        let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = pathBytes.withUnsafeBufferPointer { pathBuf in
            if let sfp = seedFingerprint {
                return sfp.withUnsafeBufferPointer { sfpBuf in
                    zcashlc_voting_get_wallet_notes(
                        dbh,
                        pathBuf.baseAddress,
                        UInt(pathBuf.count),
                        snapshotHeight,
                        networkId,
                        sfpBuf.baseAddress,
                        UInt(sfpBuf.count),
                        accountIndex
                    )
                }
            } else {
                return zcashlc_voting_get_wallet_notes(
                    dbh,
                    pathBuf.baseAddress,
                    UInt(pathBuf.count),
                    snapshotHeight,
                    networkId,
                    nil,
                    0,
                    accountIndex
                )
            }
        }

        guard let ptr else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`get_wallet_notes` failed"))
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }
}

// MARK: - Hotkey & delegation setup

extension VotingRustBackend {
    /// Generate a voting hotkey for a round.
    public func generateHotkey(roundId: String, seed: [UInt8]) throws -> VotingHotkey {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)

        let ptr = roundIdBytes.withUnsafeBufferPointer { ridBuf in
            seed.withUnsafeBufferPointer { seedBuf in
                zcashlc_voting_generate_hotkey(
                    dbh,
                    ridBuf.baseAddress,
                    UInt(ridBuf.count),
                    seedBuf.baseAddress,
                    UInt(seedBuf.count)
                )
            }
        }

        guard let ptr else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`generate_hotkey` failed"))
        }
        defer { zcashlc_voting_free_hotkey(ptr) }
        return hotkeyFromFfi(ptr.pointee)
    }

    /// Set up note bundles for a voting round.
    public func setupBundles(roundId: String, notes: [VotingNoteInfo]) throws -> VotingBundleSetupResult {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)
        let notesJson = try JSONEncoder().encode(notes)

        let ptr = roundIdBytes.withUnsafeBufferPointer { ridBuf in
            notesJson.withUnsafeBytes { notesBuf in
                zcashlc_voting_setup_bundles(
                    dbh,
                    ridBuf.baseAddress,
                    UInt(ridBuf.count),
                    notesBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    UInt(notesBuf.count)
                )
            }
        }

        guard let ptr else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`setup_bundles` failed"))
        }
        defer { zcashlc_voting_free_bundle_setup_result(ptr) }

        return VotingBundleSetupResult(
            bundleCount: ptr.pointee.bundle_count,
            eligibleWeight: ptr.pointee.eligible_weight
        )
    }

    /// Get the number of bundles for a round.
    public func getBundleCount(roundId: String) throws -> UInt32 {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)

        let result = roundIdBytes.withUnsafeBufferPointer { buf in
            zcashlc_voting_get_bundle_count(dbh, buf.baseAddress, UInt(buf.count))
        }

        guard result >= 0 else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`get_bundle_count` failed"))
        }
        return UInt32(result)
    }

    /// Build a governance PCZT for a bundle.
    // swiftlint:disable:next function_parameter_count
    public func buildGovernancePczt(
        roundId: String,
        bundleIndex: UInt32,
        notes: [VotingNoteInfo],
        fvkBytes: [UInt8],
        hotkeyRawAddress: [UInt8],
        consensusBranchId: UInt32,
        coinType: UInt32,
        seedFingerprint: [UInt8],
        accountIndex: UInt32,
        roundName: String,
        addressIndex: UInt32
    ) throws -> VotingGovernancePczt {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)
        let notesJson = try JSONEncoder().encode(notes)
        let roundNameBytes = [UInt8](roundName.utf8)

        let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = roundIdBytes.withUnsafeBufferPointer { ridBuf in
            notesJson.withUnsafeBytes { notesBuf in
                fvkBytes.withUnsafeBufferPointer { fvkBuf in
                    hotkeyRawAddress.withUnsafeBufferPointer { hkBuf in
                        seedFingerprint.withUnsafeBufferPointer { sfBuf in
                            roundNameBytes.withUnsafeBufferPointer { rnBuf in
                                zcashlc_voting_build_governance_pczt(
                                    dbh,
                                    ridBuf.baseAddress,
                                    UInt(ridBuf.count),
                                    bundleIndex,
                                    notesBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                    UInt(notesBuf.count),
                                    fvkBuf.baseAddress,
                                    UInt(fvkBuf.count),
                                    hkBuf.baseAddress,
                                    UInt(hkBuf.count),
                                    consensusBranchId,
                                    coinType,
                                    sfBuf.baseAddress,
                                    UInt(sfBuf.count),
                                    accountIndex,
                                    rnBuf.baseAddress,
                                    UInt(rnBuf.count),
                                    addressIndex
                                )
                            }
                        }
                    }
                }
            }
        }

        guard let ptr else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`build_governance_pczt` failed"))
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }

    /// Store a tree state for witness generation.
    public func storeTreeState(roundId: String, treeStateBytes: [UInt8]) throws {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)

        let result = roundIdBytes.withUnsafeBufferPointer { ridBuf in
            treeStateBytes.withUnsafeBufferPointer { tsBuf in
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
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`store_tree_state` failed"))
        }
    }

    /// Generate Merkle inclusion witnesses for notes in a bundle.
    public func generateNoteWitnesses(
        roundId: String,
        bundleIndex: UInt32,
        walletDbPath: String,
        notes: [VotingNoteInfo]
    ) throws -> [VotingWitnessData] {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)
        let pathBytes = [UInt8](walletDbPath.utf8)
        let notesJson = try JSONEncoder().encode(notes)

        let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = roundIdBytes.withUnsafeBufferPointer { ridBuf in
            pathBytes.withUnsafeBufferPointer { pathBuf in
                notesJson.withUnsafeBytes { notesBuf in
                    zcashlc_voting_generate_note_witnesses(
                        dbh,
                        ridBuf.baseAddress,
                        UInt(ridBuf.count),
                        bundleIndex,
                        pathBuf.baseAddress,
                        UInt(pathBuf.count),
                        notesBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        UInt(notesBuf.count)
                    )
                }
            }
        }

        guard let ptr else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`generate_note_witnesses` failed"))
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }
}

// MARK: - Delegation proof

extension VotingRustBackend {
    /// Build and prove the delegation ZKP. Long-running; reports progress via callback.
    // swiftlint:disable:next function_parameter_count
    public func buildAndProveDelegation(
        roundId: String,
        bundleIndex: UInt32,
        notes: [VotingNoteInfo],
        hotkeyRawAddress: [UInt8],
        pirServerUrl: String,
        networkId: UInt32,
        progress: VotingProgressHandler?
    ) throws -> VotingDelegationProofResult {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)
        let notesJson = try JSONEncoder().encode(notes)
        let notesBytes = [UInt8](notesJson)
        let urlBytes = [UInt8](pirServerUrl.utf8)

        var context = ProgressContext(handler: progress)

        let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = roundIdBytes.withUnsafeBufferPointer { ridBuf in
            notesBytes.withUnsafeBufferPointer { notesBuf in
                hotkeyRawAddress.withUnsafeBufferPointer { hkBuf in
                    urlBytes.withUnsafeBufferPointer { urlBuf in
                        withUnsafeMutablePointer(to: &context) { ctxPtr in
                            let callback: (@convention(c) (Double, UnsafeMutableRawPointer?) -> Void)? =
                                progress != nil ? votingProgressTrampoline : nil
                            return zcashlc_voting_build_and_prove_delegation(
                                dbh,
                                ridBuf.baseAddress,
                                UInt(ridBuf.count),
                                bundleIndex,
                                notesBuf.baseAddress,
                                UInt(notesBuf.count),
                                hkBuf.baseAddress,
                                UInt(hkBuf.count),
                                urlBuf.baseAddress,
                                UInt(urlBuf.count),
                                networkId,
                                callback,
                                UnsafeMutableRawPointer(ctxPtr)
                            )
                        }
                    }
                }
            }
        }

        guard let ptr else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`build_and_prove_delegation` failed"))
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }

    /// Get delegation submission using a seed-derived signing key.
    public func getDelegationSubmission(
        roundId: String,
        bundleIndex: UInt32,
        senderSeed: [UInt8],
        networkId: UInt32,
        accountIndex: UInt32
    ) throws -> VotingDelegationSubmission {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)

        let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = roundIdBytes.withUnsafeBufferPointer { ridBuf in
            senderSeed.withUnsafeBufferPointer { seedBuf in
                zcashlc_voting_get_delegation_submission(
                    dbh,
                    ridBuf.baseAddress,
                    UInt(ridBuf.count),
                    bundleIndex,
                    seedBuf.baseAddress,
                    UInt(seedBuf.count),
                    networkId,
                    accountIndex
                )
            }
        }

        guard let ptr else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`get_delegation_submission` failed"))
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }

    /// Get delegation submission using a Keystone-provided signature.
    public func getDelegationSubmissionWithKeystoneSig(
        roundId: String,
        bundleIndex: UInt32,
        sig: [UInt8],
        sighash: [UInt8]
    ) throws -> VotingDelegationSubmission {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)

        let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = roundIdBytes.withUnsafeBufferPointer { ridBuf in
            sig.withUnsafeBufferPointer { sigBuf in
                sighash.withUnsafeBufferPointer { shBuf in
                    zcashlc_voting_get_delegation_submission_with_keystone_sig(
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
                lastErrorMessage(fallback: "`get_delegation_submission_with_keystone_sig` failed")
            )
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }

    /// Store the VAN leaf position after delegation TX is confirmed.
    public func storeVanPosition(roundId: String, bundleIndex: UInt32, position: UInt32) throws {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)

        let result = roundIdBytes.withUnsafeBufferPointer { buf in
            zcashlc_voting_store_van_position(dbh, buf.baseAddress, UInt(buf.count), bundleIndex, position)
        }

        guard result == 0 else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`store_van_position` failed"))
        }
    }
}

// MARK: - Vote & commitment

extension VotingRustBackend {
    /// Encrypt voting shares for a round.
    public func encryptShares(roundId: String, shares: [UInt64]) throws -> [VotingEncryptedShare] {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)
        let sharesJson = try JSONEncoder().encode(shares)

        let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = roundIdBytes.withUnsafeBufferPointer { ridBuf in
            sharesJson.withUnsafeBytes { sjBuf in
                zcashlc_voting_encrypt_shares(
                    dbh,
                    ridBuf.baseAddress,
                    UInt(ridBuf.count),
                    sjBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    UInt(sjBuf.count)
                )
            }
        }

        guard let ptr else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`encrypt_shares` failed"))
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }

    /// Build a vote commitment (ZKP #2) for a proposal.
    // swiftlint:disable:next function_parameter_count
    public func buildVoteCommitment(
        roundId: String,
        bundleIndex: UInt32,
        hotkeySeed: [UInt8],
        networkId: UInt32,
        proposalId: UInt32,
        choice: UInt32,
        numOptions: UInt32,
        vanAuthPath: [[UInt8]],
        vanPosition: UInt32,
        anchorHeight: UInt32,
        progress: VotingProgressHandler?
    ) throws -> VotingVoteCommitmentBundle {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)
        let authPathJson = try JSONEncoder().encode(vanAuthPath)

        var context = ProgressContext(handler: progress)

        let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = roundIdBytes.withUnsafeBufferPointer { ridBuf in
            hotkeySeed.withUnsafeBufferPointer { seedBuf in
                authPathJson.withUnsafeBytes { apBuf in
                    withUnsafeMutablePointer(to: &context) { ctxPtr in
                        let callback: (@convention(c) (Double, UnsafeMutableRawPointer?) -> Void)? =
                            progress != nil ? votingProgressTrampoline : nil
                        return zcashlc_voting_build_vote_commitment(
                            dbh,
                            ridBuf.baseAddress,
                            UInt(ridBuf.count),
                            bundleIndex,
                            seedBuf.baseAddress,
                            UInt(seedBuf.count),
                            networkId,
                            proposalId,
                            choice,
                            numOptions,
                            apBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            UInt(apBuf.count),
                            vanPosition,
                            anchorHeight,
                            callback,
                            UnsafeMutableRawPointer(ctxPtr)
                        )
                    }
                }
            }
        }

        guard let ptr else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`build_vote_commitment` failed"))
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }

    /// Build share payloads for delegated share submission.
    public func buildSharePayloads(
        encShares: [VotingEncryptedShare],
        commitment: VotingVoteCommitmentBundle,
        voteDecision: UInt32,
        numOptions: UInt32,
        vcTreePosition: UInt64
    ) throws -> [VotingSharePayload] {
        let dbh = try requireHandle()
        let sharesJson = try JSONEncoder().encode(encShares)
        let commitmentJson = try JSONEncoder().encode(commitment)

        let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = sharesJson.withUnsafeBytes { sjBuf in
            commitmentJson.withUnsafeBytes { cjBuf in
                zcashlc_voting_build_share_payloads(
                    dbh,
                    sjBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    UInt(sjBuf.count),
                    cjBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    UInt(cjBuf.count),
                    voteDecision,
                    numOptions,
                    vcTreePosition
                )
            }
        }

        guard let ptr else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`build_share_payloads` failed"))
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }

    /// Mark a vote as submitted.
    public func markVoteSubmitted(roundId: String, bundleIndex: UInt32, proposalId: UInt32) throws {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)

        let result = roundIdBytes.withUnsafeBufferPointer { buf in
            zcashlc_voting_mark_vote_submitted(dbh, buf.baseAddress, UInt(buf.count), bundleIndex, proposalId)
        }

        guard result == 0 else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`mark_vote_submitted` failed"))
        }
    }
}

// MARK: - Tree sync

extension VotingRustBackend {
    /// Sync the vote commitment tree from a chain node.
    /// Returns the latest synced block height.
    public func syncVoteTree(roundId: String, nodeUrl: String) throws -> UInt32 {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)
        let urlBytes = [UInt8](nodeUrl.utf8)

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

    /// Generate a VAN Merkle witness for ZKP #2.
    public func generateVanWitness(
        roundId: String,
        bundleIndex: UInt32,
        anchorHeight: UInt32
    ) throws -> VotingVanWitness {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)

        let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = roundIdBytes.withUnsafeBufferPointer { buf in
            zcashlc_voting_generate_van_witness(dbh, buf.baseAddress, UInt(buf.count), bundleIndex, anchorHeight)
        }

        guard let ptr else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`generate_van_witness` failed"))
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }

    /// Reset the in-memory TreeClient.
    public func resetTreeClient() throws {
        let dbh = try requireHandle()

        let result = zcashlc_voting_reset_tree_client(dbh)
        guard result == 0 else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`reset_tree_client` failed"))
        }
    }
}

// MARK: - Static / free functions (no database needed)

extension VotingRustBackend {
    /// Generate a standalone voting hotkey (no database).
    public static func generateHotkeyStandalone(seed: [UInt8]) throws -> VotingHotkey {
        let ptr = seed.withUnsafeBufferPointer { buf in
            zcashlc_voting_generate_hotkey_standalone(buf.baseAddress, UInt(buf.count))
        }

        guard let ptr else {
            throw VotingRustBackendError.rustError(staticLastErrorMessage(fallback: "`generate_hotkey_standalone` failed"))
        }
        defer { zcashlc_voting_free_hotkey(ptr) }
        return hotkeyFromFfi(ptr.pointee)
    }

    /// Decompose a weight into power-of-two components.
    public static func decomposeWeight(_ weight: UInt64) throws -> [UInt64] {
        guard let ptr = zcashlc_voting_decompose_weight(weight) else {
            throw VotingRustBackendError.rustError(staticLastErrorMessage(fallback: "`decompose_weight` failed"))
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSONStatic(from: ptr)
    }

    /// Generate delegation inputs from sender seed and hotkey seed.
    public static func generateDelegationInputs(
        senderSeed: [UInt8],
        hotkeySeed: [UInt8],
        networkId: UInt32,
        accountIndex: UInt32
    ) throws -> VotingDelegationInputs {
        let ptr = senderSeed.withUnsafeBufferPointer { sBuf in
            hotkeySeed.withUnsafeBufferPointer { hBuf in
                zcashlc_voting_generate_delegation_inputs(
                    sBuf.baseAddress,
                    UInt(sBuf.count),
                    hBuf.baseAddress,
                    UInt(hBuf.count),
                    networkId,
                    accountIndex
                )
            }
        }

        guard let ptr else {
            throw VotingRustBackendError.rustError(staticLastErrorMessage(fallback: "`generate_delegation_inputs` failed"))
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSONStatic(from: ptr)
    }

    /// Generate delegation inputs using an explicit FVK.
    public static func generateDelegationInputsWithFvk(
        fvkBytes: [UInt8],
        hotkeySeed: [UInt8],
        networkId: UInt32,
        accountIndex: UInt32,
        seedFingerprint: [UInt8]
    ) throws -> VotingDelegationInputs {
        let ptr = fvkBytes.withUnsafeBufferPointer { fvkBuf in
            hotkeySeed.withUnsafeBufferPointer { hBuf in
                seedFingerprint.withUnsafeBufferPointer { sfBuf in
                    zcashlc_voting_generate_delegation_inputs_with_fvk(
                        fvkBuf.baseAddress,
                        UInt(fvkBuf.count),
                        hBuf.baseAddress,
                        UInt(hBuf.count),
                        networkId,
                        accountIndex,
                        sfBuf.baseAddress,
                        UInt(sfBuf.count)
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
        return try decodeJSONStatic(from: ptr)
    }

    /// Extract the sighash from PCZT bytes.
    public static func extractPcztSighash(pcztBytes: [UInt8]) throws -> [UInt8] {
        let ptr = pcztBytes.withUnsafeBufferPointer { buf in
            zcashlc_voting_extract_pczt_sighash(buf.baseAddress, UInt(buf.count))
        }

        guard let ptr else {
            throw VotingRustBackendError.rustError(staticLastErrorMessage(fallback: "`extract_pczt_sighash` failed"))
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return bytesFromBoxedSlice(ptr)
    }

    /// Extract a spend auth signature from a signed PCZT.
    public static func extractSpendAuthSig(signedPcztBytes: [UInt8], actionIndex: UInt32) throws -> [UInt8] {
        let ptr = signedPcztBytes.withUnsafeBufferPointer { buf in
            zcashlc_voting_extract_spend_auth_sig(buf.baseAddress, UInt(buf.count), actionIndex)
        }

        guard let ptr else {
            throw VotingRustBackendError.rustError(staticLastErrorMessage(fallback: "`extract_spend_auth_sig` failed"))
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return bytesFromBoxedSlice(ptr)
    }

    /// Extract the Orchard FVK from a UFVK string.
    public static func extractOrchardFvkFromUfvk(ufvkStr: String, networkId: UInt32) throws -> [UInt8] {
        let ufvkBytes = [UInt8](ufvkStr.utf8)

        let ptr = ufvkBytes.withUnsafeBufferPointer { buf in
            zcashlc_voting_extract_orchard_fvk_from_ufvk(buf.baseAddress, UInt(buf.count), networkId)
        }

        guard let ptr else {
            throw VotingRustBackendError.rustError(
                staticLastErrorMessage(fallback: "`extract_orchard_fvk_from_ufvk` failed")
            )
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return bytesFromBoxedSlice(ptr)
    }

    /// Extract the nc_root from a protobuf-encoded TreeState.
    public static func extractNcRoot(treeStateBytes: [UInt8]) throws -> [UInt8] {
        let ptr = treeStateBytes.withUnsafeBufferPointer { buf in
            zcashlc_voting_extract_nc_root(buf.baseAddress, UInt(buf.count))
        }

        guard let ptr else {
            throw VotingRustBackendError.rustError(staticLastErrorMessage(fallback: "`extract_nc_root` failed"))
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return bytesFromBoxedSlice(ptr)
    }

    /// Sign a cast-vote transaction.
    // swiftlint:disable:next function_parameter_count
    public static func signCastVote(
        hotkeySeed: [UInt8],
        networkId: UInt32,
        voteRoundIdHex: String,
        rVpkBytes: [UInt8],
        vanNullifier: [UInt8],
        voteAuthorityNoteNew: [UInt8],
        voteCommitment: [UInt8],
        proposalId: UInt32,
        anchorHeight: UInt32,
        alphaV: [UInt8]
    ) throws -> VotingCastVoteSignature {
        let roundIdBytes = [UInt8](voteRoundIdHex.utf8)

        let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = hotkeySeed.withUnsafeBufferPointer { seedBuf in
            roundIdBytes.withUnsafeBufferPointer { ridBuf in
                rVpkBytes.withUnsafeBufferPointer { rvBuf in
                    vanNullifier.withUnsafeBufferPointer { vnBuf in
                        voteAuthorityNoteNew.withUnsafeBufferPointer { vanBuf in
                            voteCommitment.withUnsafeBufferPointer { vcBuf in
                                alphaV.withUnsafeBufferPointer { avBuf in
                                    zcashlc_voting_sign_cast_vote(
                                        seedBuf.baseAddress,
                                        UInt(seedBuf.count),
                                        networkId,
                                        ridBuf.baseAddress,
                                        UInt(ridBuf.count),
                                        rvBuf.baseAddress,
                                        UInt(rvBuf.count),
                                        vnBuf.baseAddress,
                                        UInt(vnBuf.count),
                                        vanBuf.baseAddress,
                                        UInt(vanBuf.count),
                                        vcBuf.baseAddress,
                                        UInt(vcBuf.count),
                                        proposalId,
                                        anchorHeight,
                                        avBuf.baseAddress,
                                        UInt(avBuf.count)
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        guard let ptr else {
            throw VotingRustBackendError.rustError(staticLastErrorMessage(fallback: "`sign_cast_vote` failed"))
        }
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSONStatic(from: ptr)
    }

    /// Verify a Merkle witness.
    public static func verifyWitness(_ witness: VotingWitnessData) throws -> Bool {
        let witnessJson = try JSONEncoder().encode(witness)

        let result = witnessJson.withUnsafeBytes { buf in
            zcashlc_voting_verify_witness(
                buf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                UInt(buf.count)
            )
        }

        guard result >= 0 else {
            throw VotingRustBackendError.rustError(staticLastErrorMessage(fallback: "`verify_witness` failed"))
        }
        return result == 1
    }

    /// Get the voting FFI version string.
    public static func version() -> String? {
        guard let cStr = zcashlc_voting_version() else { return nil }
        defer { zcashlc_string_free(cStr) }
        return String(validatingUTF8: cStr)
    }
}

// MARK: - Private helpers

private extension VotingRustBackend {
    func requireHandle() throws -> OpaquePointer {
        lock.lock()
        defer { lock.unlock() }
        guard let dbh = handle else {
            throw VotingRustBackendError.databaseNotOpen
        }
        return dbh
    }

    func lastErrorMessage(fallback: String) -> String {
        Self.staticLastErrorMessage(fallback: fallback)
    }

    func decodeJSON<T: Decodable>(from ptr: UnsafeMutablePointer<FfiBoxedSlice>) throws -> T {
        let data = Data(bytes: ptr.pointee.ptr, count: Int(ptr.pointee.len))
        return try JSONDecoder().decode(T.self, from: data)
    }

    static func staticLastErrorMessage(fallback: String) -> String {
        let errorLen = zcashlc_last_error_length()
        defer { zcashlc_clear_last_error() }

        if errorLen > 0 {
            let error = UnsafeMutablePointer<Int8>.allocate(capacity: Int(errorLen))
            defer { error.deallocate() }
            zcashlc_error_message_utf8(error, errorLen)
            if let msg = String(validatingUTF8: error) {
                return msg
            }
        }
        return fallback
    }

    static func decodeJSONStatic<T: Decodable>(from ptr: UnsafeMutablePointer<FfiBoxedSlice>) throws -> T {
        let data = Data(bytes: ptr.pointee.ptr, count: Int(ptr.pointee.len))
        return try JSONDecoder().decode(T.self, from: data)
    }

    static func bytesFromBoxedSlice(_ ptr: UnsafeMutablePointer<FfiBoxedSlice>) -> [UInt8] {
        let len = Int(ptr.pointee.len)
        var bytes = [UInt8](repeating: 0, count: len)
        for i in 0..<len {
            bytes[i] = ptr.pointee.ptr.advanced(by: i).pointee
        }
        return bytes
    }
}

/// Convert FfiVotingHotkey to VotingHotkey.
private func hotkeyFromFfi(_ ffi: FfiVotingHotkey) -> VotingHotkey {
    var secretKey = [UInt8](repeating: 0, count: Int(ffi.secret_key_len))
    for i in 0..<Int(ffi.secret_key_len) {
        secretKey[i] = ffi.secret_key.advanced(by: i).pointee
    }

    var publicKey = [UInt8](repeating: 0, count: Int(ffi.public_key_len))
    for i in 0..<Int(ffi.public_key_len) {
        publicKey[i] = ffi.public_key.advanced(by: i).pointee
    }

    let address = ffi.address != nil ? String(cString: ffi.address) : ""

    return VotingHotkey(secretKey: secretKey, publicKey: publicKey, address: address)
}

// MARK: - Progress callback trampoline

private struct ProgressContext {
    let handler: VotingProgressHandler?
}

private func votingProgressTrampoline(progress: Double, context: UnsafeMutableRawPointer?) {
    guard let context else { return }
    let ctx = context.assumingMemoryBound(to: ProgressContext.self).pointee
    ctx.handler?(progress)
}
