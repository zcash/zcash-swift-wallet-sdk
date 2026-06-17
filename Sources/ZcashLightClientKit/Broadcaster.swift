//
//  Broadcaster.swift
//  ZcashLightClientKit
//
//  Created by Adam Tucker on 2026-04-15.
//

import Foundation

/// Protocol for creating transactions without immediate submission and for
/// submitting them to one or more lightwalletd endpoints in parallel.
///
/// This separates transaction creation and network submission from the broader
/// synchronization lifecycle managed by ``Synchronizer``.
///
/// Transactions created through this API wait for the caller to submit them —
/// the SDK's background resubmission skips them until then. Once submitted,
/// the endpoint list is recorded as the transaction's retry plan and background
/// resubmission retries through those endpoints instead of the synchronizer's
/// default endpoint.
///
/// Typical usage:
/// ```swift
/// let transactions = try await synchronizer.broadcaster.createProposedTransactions(
///     proposal: proposal, spendingKey: spendingKey
/// )
/// let reports = await synchronizer.broadcaster.submit(
///     transactions: transactions, to: endpoints
/// )
/// ```
public protocol Broadcaster: AnyObject {
    /// Creates the transactions in the given proposal without submitting them.
    ///
    /// If `prepare()` hasn't been called since creation of the synchronizer
    /// instance or since the last wipe, throws `ZcashError.synchronizerNotPrepared`.
    func createProposedTransactions(
        proposal: Proposal,
        spendingKey: UnifiedSpendingKey
    ) async throws -> [CreatedTransaction]

    /// Finalizes a PCZT that has been separately proven and signed, stores it
    /// in the wallet, and returns the resulting transactions without submitting.
    ///
    /// If `prepare()` hasn't been called since creation of the synchronizer
    /// instance or since the last wipe, throws `ZcashError.synchronizerNotPrepared`.
    func createTransactionFromPCZT(
        pcztWithProofs: Pczt,
        pcztWithSigs: Pczt
    ) async throws -> [CreatedTransaction]

    /// Submits one transaction to all endpoints in parallel.
    ///
    /// Returns as soon as the outcome is decided (first acceptance, all
    /// endpoints failed, or timeout); in-flight submissions continue through
    /// the grace window in the background. The endpoint list is recorded as
    /// the transaction's retry plan before any network attempt, and the plan
    /// stays recorded even when the call is cancelled or times out. An empty
    /// endpoint list returns `.unreachable` immediately and records no retry
    /// plan — the transaction stays awaiting.
    ///
    /// If the surrounding task is cancelled, the call returns `.cancelled`
    /// promptly while in-flight submissions wind down in the background.
    func submit(
        transaction: CreatedTransaction,
        to endpoints: [LightWalletEndpoint],
        timing: SubmissionTiming
    ) async -> TransactionSubmissionOutcome

    /// Batch convenience: submits sequentially, stops at the first transaction
    /// that isn't accepted, and marks the remaining ones `.notAttempted`.
    /// Skipped transactions stay awaiting (excluded from background retry)
    /// until the caller submits them.
    func submit(
        transactions: [CreatedTransaction],
        to endpoints: [LightWalletEndpoint],
        timing: SubmissionTiming
    ) async -> [TransactionSubmissionReport]
}

extension Broadcaster {
    /// Forwards with `SubmissionTiming.default` (protocol requirements cannot
    /// declare default arguments).
    public func submit(
        transaction: CreatedTransaction,
        to endpoints: [LightWalletEndpoint]
    ) async -> TransactionSubmissionOutcome {
        await submit(transaction: transaction, to: endpoints, timing: SubmissionTiming.default)
    }

    /// Forwards with `SubmissionTiming.default`.
    public func submit(
        transactions: [CreatedTransaction],
        to endpoints: [LightWalletEndpoint]
    ) async -> [TransactionSubmissionReport] {
        await submit(transactions: transactions, to: endpoints, timing: SubmissionTiming.default)
    }
}

// MARK: - Multi-endpoint submission types

/// A transaction created locally, not yet broadcast to the network.
public struct CreatedTransaction: Equatable {
    /// The transaction id (also known as `rawID`).
    public let txId: Data
    /// The serialized transaction bytes suitable for submission.
    public let raw: Data
    /// The height at which the transaction expires, if known.
    public let expiryHeight: BlockHeight?

    /// Memberwise initializer, public so custom `Broadcaster` conformers
    /// (mocks, stubs, alternate transports) can construct return values.
    public init(txId: Data, raw: Data, expiryHeight: BlockHeight?) {
        self.txId = txId
        self.raw = raw
        self.expiryHeight = expiryHeight
    }
}

extension CreatedTransaction {
    /// Builds a submittable transaction from a wallet overview, e.g. to re-submit
    /// a transaction created in a previous app session. The overview must carry
    /// raw bytes; overviews returned by transaction-listing APIs do.
    /// - Throws: `TransactionEncoderError.notEncoded` when the overview carries no raw bytes.
    public init(overview: ZcashTransaction.Overview) throws {
        guard let raw = overview.raw else {
            throw TransactionEncoderError.notEncoded(txId: overview.rawID)
        }
        self.txId = overview.rawID
        self.raw = raw
        self.expiryHeight = overview.expiryHeight
    }

    var encodedTransaction: EncodedTransaction {
        EncodedTransaction(transactionId: txId, raw: raw)
    }
}

/// Timing knobs for multi-endpoint submission.
public struct SubmissionTiming: Equatable {
    /// How long to wait for the first endpoint decision before declaring timeout.
    public let responseTimeout: TimeInterval
    /// After the first acceptance, how long remaining in-flight submissions may
    /// continue (best-effort propagation) before being cancelled.
    public let postAcceptanceGraceDelay: TimeInterval

    public static let `default` = SubmissionTiming(responseTimeout: 30, postAcceptanceGraceDelay: 5)

    public init(responseTimeout: TimeInterval, postAcceptanceGraceDelay: TimeInterval) {
        self.responseTimeout = responseTimeout
        self.postAcceptanceGraceDelay = postAcceptanceGraceDelay
    }
}

/// Per-transaction outcome of a multi-endpoint submission.
public enum TransactionSubmissionOutcome: Equatable {
    /// At least one endpoint accepted the transaction.
    case accepted(by: LightWalletEndpoint)
    /// Every endpoint responded and none accepted. Carries the first
    /// lightwalletd rejection (error code + message) that was observed.
    case rejected(code: Int, message: String)
    /// Every endpoint failed at the transport level (gRPC/connection error);
    /// no server-level rejection was observed.
    case unreachable
    /// No clear decision within `responseTimeout`: at least one endpoint had
    /// not responded when the timer fired (others may have rejected or failed
    /// in the meantime — details are logged). The transaction may still have
    /// been broadcast — treat as pending, not failed.
    case timedOut
    /// Skipped because an earlier transaction in the batch was not accepted.
    case notAttempted
    /// The submission was cancelled by the caller. The retry plan recorded
    /// before the attempt stays in place, so background resubmission can still
    /// broadcast the transaction later — treat as "outcome unknown", not as
    /// "not sent".
    case cancelled
}

extension TransactionSubmissionOutcome {
    /// Short, log-friendly description (avoids dumping the whole endpoint struct).
    var logDescription: String {
        switch self {
        case let .accepted(endpoint): return "accepted by \(endpoint.host):\(endpoint.port)"
        case let .rejected(code, message): return "rejected (\(code) \(message))"
        case .unreachable: return "unreachable (all endpoints failed at transport level)"
        case .timedOut: return "timed out (may still have been broadcast)"
        case .notAttempted: return "not attempted"
        case .cancelled: return "cancelled (retry plan kept)"
        }
    }
}

/// Per-transaction result of a batch submission, pairing the transaction id with its outcome.
public struct TransactionSubmissionReport: Equatable {
    public let txId: Data
    public let outcome: TransactionSubmissionOutcome

    /// Memberwise initializer, public so custom `Broadcaster` conformers
    /// (mocks, stubs, alternate transports) can construct return values.
    public init(txId: Data, outcome: TransactionSubmissionOutcome) {
        self.txId = txId
        self.outcome = outcome
    }
}
