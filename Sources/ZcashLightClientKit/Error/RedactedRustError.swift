//
//  RedactedRustError.swift
//
//  A failure from the Rust layer that has been classified and stripped of sensitive detail.
//

import Foundation

/// The classification of a Rust-layer failure, mirroring `ErrorKind` in `rust/src/error_report.rs`.
///
/// Raw values are part of the FFI contract. An unrecognised value decodes to ``unclassified``
/// rather than failing, so a Rust layer that gained a kind still works against an older SDK.
public enum RustErrorKind: UInt32, Equatable {
    case unclassified = 0
    case scanRequired = 1
    case insufficientFunds = 2
    case invalidAmount = 3
    case invalidRecipient = 4
    case invalidMemo = 5
    case invalidPaymentRequest = 6
    case accountNotFound = 7
    case accountCannotSpend = 8
    case keyNotAvailable = 9
    case noSupportedReceivers = 10
    case proposalNotSupported = 11
    case builderFailed = 12
    case dataSourceFailed = 13
    case noteSelectionFailed = 14
    case changeSelectionFailed = 15
    case commitmentTreeFailed = 16
    case proposalInvalid = 17
    case expiryHeightInvalid = 18
    case balanceOverflow = 19
    case noteMismatch = 20

    init(ffiValue: UInt32) {
        self = RustErrorKind(rawValue: ffiValue) ?? .unclassified
    }
}

/// A Rust-layer failure whose message has been redacted at the FFI boundary.
///
/// This type is the certificate of redaction, not just a container. ``ZcashError``'s
/// `errorDescription` renders an associated value only when its type is `RedactedRustError`, so
/// the raw strings returned by `lastErrorMessage(fallback:)` cannot reach a submitted error
/// report by construction rather than by review. Values are produced only by
/// `ZcashRustBackend.lastErrorReport(fallback:)`, which reads them from
/// `zcashlc_take_last_error_report`.
public struct RedactedRustError: Equatable, CustomStringConvertible {
    /// The condition, for callers that need to branch rather than display.
    public let kind: RustErrorKind

    /// Carries no amount, address, note identifier or txid, and is safe to submit off-device.
    public let message: String

    /// The spendable balance. Set only when ``kind`` is ``RustErrorKind/insufficientFunds``.
    ///
    /// Amounts are deliberately NOT redacted: they exist for the wallet to render to the user
    /// whose balance they describe, and they never enter ``message``.
    public let available: Zatoshi?

    /// The amount needed including the fee. Set only when ``kind`` is
    /// ``RustErrorKind/insufficientFunds``.
    public let required: Zatoshi?

    public init(kind: RustErrorKind, message: String, available: Zatoshi? = nil, required: Zatoshi? = nil) {
        self.kind = kind
        self.message = message
        self.available = available
        self.required = required
    }

    public var description: String { message }
}
