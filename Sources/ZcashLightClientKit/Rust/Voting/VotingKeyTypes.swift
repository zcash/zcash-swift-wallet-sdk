//
//  VotingKeyTypes.swift
//  ZcashLightClientKit
//

import Foundation

// Semantic wrappers for the key material the voting API takes. Each one checks
// its length once, on construction, so a seed cannot be passed where a hotkey
// secret is expected and a malformed value is rejected before it reaches the
// FFI. Rust still validates the bytes themselves when they are used; the
// Swift side only enforces the shape the FFI accepts.

// MARK: - Seed

/// A wallet's root seed, borrowed for a single voting call.
///
/// The SDK never persists or logs it. Conforms to `Undescribable` so the seed
/// cannot escape through `print`, string interpolation, or reflection.
public struct VotingSeed: Equatable, Sendable, Undescribable {
    public let bytes: [UInt8]

    /// - Throws: ``VotingRustBackendError/invalidData`` if `bytes` is shorter
    ///   than 32 bytes.
    public init(bytes: [UInt8]) throws {
        guard bytes.count >= votingMinSeedByteCount else {
            throw VotingRustBackendError.invalidData(
                "seed must be at least \(votingMinSeedByteCount) bytes"
            )
        }
        self.bytes = bytes
    }
}

// MARK: - Seed fingerprint

/// The ZIP 32 fingerprint of the seed a voting account was derived from.
///
/// It identifies the seed without revealing it, so it is not redacted.
public struct VotingSeedFingerprint: Equatable, Hashable, Sendable, Codable {
    public let bytes: [UInt8]

    /// - Throws: ``VotingRustBackendError/invalidData`` unless `bytes` is
    ///   exactly 32 bytes.
    public init(bytes: [UInt8]) throws {
        guard bytes.count == votingSeedFingerprintByteCount else {
            throw VotingRustBackendError.invalidData(
                "seedFingerprint must be exactly \(votingSeedFingerprintByteCount) bytes"
            )
        }
        self.bytes = bytes
    }

    public init(from decoder: Decoder) throws {
        try self.init(bytes: try decoder.singleValueContainer().decode([UInt8].self))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(bytes)
    }
}

// MARK: - Hotkey secret

/// The app-owned secret behind a voting hotkey, as returned in
/// ``VotingHotkey/storedSecret``.
///
/// The application must persist ``bytes`` and rebuild this value with
/// ``init(bytes:)`` for the rest of the round: the secret is random, not
/// derived from the wallet seed, so it cannot be recovered any other way.
/// Conforms to `Undescribable` so the secret cannot escape through `print`,
/// string interpolation, or reflection.
public struct VotingHotkeySecret: Equatable, Sendable, Undescribable {
    public let bytes: [UInt8]

    /// - Throws: ``VotingRustBackendError/invalidData`` unless `bytes` is
    ///   exactly 64 bytes.
    public init(bytes: [UInt8]) throws {
        guard bytes.count == votingHotkeyStoredSecretByteCount else {
            throw VotingRustBackendError.invalidData(
                "hotkey secret must be exactly \(votingHotkeyStoredSecretByteCount) bytes"
            )
        }
        self.bytes = bytes
    }
}

// MARK: - Orchard full viewing key

/// The raw 96-byte Orchard full viewing key of a voting account.
///
/// Obtain it from a ``UnifiedFullViewingKey`` with
/// ``VotingRustBackend/extractOrchardFvk(ufvk:network:)``, which has Rust parse
/// the key, rather than assembling the bytes by hand. Conforms to
/// `Undescribable` because the key reveals every note the account receives.
public struct VotingOrchardFullViewingKey: Equatable, Sendable, Codable, Undescribable {
    public let bytes: [UInt8]

    /// - Throws: ``VotingRustBackendError/invalidData`` unless `bytes` is
    ///   exactly 96 bytes.
    public init(bytes: [UInt8]) throws {
        guard bytes.count == votingOrchardFvkByteCount else {
            throw VotingRustBackendError.invalidData(
                "Orchard full viewing key must be exactly \(votingOrchardFvkByteCount) bytes"
            )
        }
        self.bytes = bytes
    }

    public init(from decoder: Decoder) throws {
        try self.init(bytes: try decoder.singleValueContainer().decode([UInt8].self))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(bytes)
    }
}

// MARK: - Boundary conversions

extension BlockHeight {
    /// The height as the `u64` the voting FFI takes.
    ///
    /// - Throws: ``VotingRustBackendError/invalidData`` for a negative height.
    func votingFFIHeight() throws -> UInt64 {
        guard let height = UInt64(exactly: self) else {
            throw VotingRustBackendError.invalidData("height must not be negative")
        }
        return height
    }

    /// A height the voting FFI returned, as a ``BlockHeight``.
    ///
    /// - Throws: ``VotingRustBackendError/invalidData`` if it does not fit.
    static func fromVotingFFI(_ height: UInt64) throws -> BlockHeight {
        guard let height = BlockHeight(exactly: height) else {
            throw VotingRustBackendError.invalidData("height \(height) is out of range")
        }
        return height
    }
}

// `VotingDelegationKeyInputs` is `Sendable` and carries the account index
// across the detached proving task, so the index must be `Sendable` too. Its
// only stored property is a `UInt32`.
extension Zip32AccountIndex: Sendable {}
