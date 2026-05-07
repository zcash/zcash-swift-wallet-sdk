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
/// Thread safety: handle access is serialized by an `NSLock`. The lock guards
/// the handle slot only — it is released before the FFI call runs, so callers
/// must not race `close()` against in-flight operations.
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
    ///
    /// Throws `VotingRustBackendError.databaseAlreadyOpen` if the backend
    /// already holds an open handle.
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
        let dbh = try requireHandle()
        let walletIdBytes = [UInt8](walletId.utf8)

        let result = walletIdBytes.withUnsafeBufferPointer { buf in
            zcashlc_voting_set_wallet_id(dbh, buf.baseAddress, UInt(buf.count))
        }

        guard result == 0 else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`set_wallet_id` failed"))
        }
    }
}

// MARK: - Delegation (PIR precompute)

extension VotingRustBackend {
    /// Resolve the round's PIR endpoint, fetch the IMT non-membership proofs
    /// needed for the delegation ZKP, and cache them in the voting database.
    ///
    /// This performs the network PIR lookup only; proof construction happens
    /// elsewhere (delegation ZKP build is added in a follow-up PR).
    ///
    /// `pirEndpoints` are probed in parallel via `pirResolver`; the first
    /// endpoint whose served snapshot height equals `expectedSnapshotHeight`
    /// exactly is used. See `PirSnapshotResolver` for the failure semantics.
    // swiftlint:disable:next function_parameter_count
    public func precomputeDelegationPir(
        roundId: String,
        bundleIndex: UInt32,
        notes: [VotingNoteInfo],
        pirEndpoints: [String],
        expectedSnapshotHeight: UInt64,
        networkId: UInt32,
        pirResolver: PirSnapshotResolver = PirSnapshotResolver()
    ) async throws -> VotingDelegationPirPrecomputeResult {
        // PirSnapshotResolver expects `BlockHeight` (Int); voting snapshot
        // heights are `UInt64` everywhere else in the voting types, so convert
        // at the boundary. Snapshot heights well within Int.max in practice.
        let pirServerUrl = try await pirResolver.resolve(
            endpoints: pirEndpoints,
            expectedSnapshotHeight: BlockHeight(expectedSnapshotHeight)
        )

        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)
        let notesJson = try JSONEncoder().encode(notes)
        let notesBytes = [UInt8](notesJson)
        let urlBytes = [UInt8](pirServerUrl.utf8)

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
                        networkId
                    )
                }
            }
        }

        guard let ptr else {
            throw VotingRustBackendError.rustError(
                lastErrorMessage(fallback: "`precompute_delegation_pir` failed")
            )
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

    /// Generate a Vote Authority Note (VAN) Merkle witness for the given
    /// bundle at `anchorHeight`.
    public func generateVanWitness(
        roundId: String,
        bundleIndex: UInt32,
        anchorHeight: UInt32
    ) throws -> VotingVanWitness {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)

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
        defer { zcashlc_free_boxed_slice(ptr) }
        return try decodeJSON(from: ptr)
    }

    /// Reset the in-memory tree client for a round, forcing the next
    /// `syncVoteTree` call to start from a fresh client.
    ///
    /// Pass an empty `roundId` to reset all rounds.
    public func resetTreeClient(roundId: String = "") throws {
        let dbh = try requireHandle()
        let roundIdBytes = [UInt8](roundId.utf8)

        let result = roundIdBytes.withUnsafeBufferPointer { buf in
            zcashlc_voting_reset_tree_client(dbh, buf.baseAddress, UInt(buf.count))
        }

        guard result == 0 else {
            throw VotingRustBackendError.rustError(lastErrorMessage(fallback: "`reset_tree_client` failed"))
        }
    }
}

// MARK: - Share tracking (static)

extension VotingRustBackend {
    /// Byte width of a Pallas base-field element as expected by the voting FFI.
    private static let fieldElementByteCount = 32

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
            voteCommitment.count == fieldElementByteCount,
            primaryBlind.count == fieldElementByteCount
        else {
            throw VotingRustBackendError.invalidData(
                "voteCommitment and primaryBlind must each be exactly \(fieldElementByteCount) bytes"
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
}

// MARK: - Private helpers

private extension VotingRustBackend {
    /// Snapshot the current handle under the lock, throwing if the database
    /// is not open. The pointer is read-only after `close()` resets it, so the
    /// snapshot is valid for the duration of the FFI call as long as callers
    /// do not race `close()` against other operations.
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

    /// Reads the last error recorded by `libzcashlc` and clears it as a side
    /// effect, so subsequent failures do not surface a stale message.
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
}
