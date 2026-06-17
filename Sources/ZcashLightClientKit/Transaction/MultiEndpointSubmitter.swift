//
//  MultiEndpointSubmitter.swift
//  ZcashLightClientKit
//

import Foundation

/// Races one transaction against multiple endpoints in parallel.
///
/// Resumes the caller as soon as the outcome is decided (first acceptance, all
/// endpoints failed, timeout, or caller cancellation); in-flight submissions
/// continue through the grace window in the background before being cancelled.
final class MultiEndpointSubmitter {
    private let endpointSubmitter: EndpointSubmitter
    private let logger: Logger

    init(endpointSubmitter: EndpointSubmitter, logger: Logger) {
        self.endpointSubmitter = endpointSubmitter
        self.logger = logger
    }

    func submit(
        transaction: CreatedTransaction,
        to endpoints: [LightWalletEndpoint],
        timing: SubmissionTiming
    ) async -> TransactionSubmissionOutcome {
        guard !endpoints.isEmpty else {
            logger.warn("Multi-endpoint submission requested with an empty endpoint list.")
            return .unreachable
        }

        let race = SubmissionRace(
            transaction: transaction,
            endpoints: endpoints,
            timing: timing,
            endpointSubmitter: endpointSubmitter,
            logger: logger
        )

        // The worker is created before the cancellation handler is installed and
        // captured immutably by both closures — no lock needed (iOS 13 safe).
        let worker = Task {
            await race.run()
        }

        return await withTaskCancellationHandler {
            await race.outcome()
        } onCancel: {
            worker.cancel()
            // Release the caller right away: children stuck in work that
            // ignores task cancellation (e.g. blocking FFI on the Tor path)
            // must not delay the `.cancelled` resolution — and a straggler's
            // late rejection must not replace it. The race keeps winding down
            // inside the worker task.
            Task {
                await race.callerCancelled()
            }
        }
    }
}

/// Holds the race state and the two promises: the caller-facing outcome and the
/// internal "race finished" signal that releases the task group.
actor SubmissionRace {
    private let transaction: CreatedTransaction
    private let endpoints: [LightWalletEndpoint]
    private let timing: SubmissionTiming
    private let endpointSubmitter: EndpointSubmitter
    private let logger: Logger

    private var resolvedOutcome: TransactionSubmissionOutcome?
    private var outcomeContinuation: CheckedContinuation<TransactionSubmissionOutcome, Never>?
    private var raceFinished = false
    private var raceFinishedContinuation: CheckedContinuation<Void, Never>?
    private var winner: LightWalletEndpoint?
    private var firstRejection: (code: Int, message: String)?
    private var completedCount = 0
    private var graceTask: Task<Void, Never>?

    init(
        transaction: CreatedTransaction,
        endpoints: [LightWalletEndpoint],
        timing: SubmissionTiming,
        endpointSubmitter: EndpointSubmitter,
        logger: Logger
    ) {
        self.transaction = transaction
        self.endpoints = endpoints
        self.timing = timing
        self.endpointSubmitter = endpointSubmitter
        self.logger = logger
    }

    /// Runs the whole race. Returns only when every child task has ended.
    func run() async {
        logger.debug(
            """
            Starting submission race for \(transaction.txId.toHexStringTxId()): \(endpoints.count) endpoint(s), \
            timeout \(timing.responseTimeout)s, grace \(timing.postAcceptanceGraceDelay)s.
            """
        )
        await withTaskGroup(of: Void.self) { group in
            for endpoint in endpoints {
                group.addTask {
                    await self.submit(to: endpoint)
                }
            }
            group.addTask {
                await self.timeout()
            }

            await waitUntilRaceFinishes()
            group.cancelAll()
            await group.waitForAll()
        }

        graceTask?.cancel()
        // Safety net: if nothing resolved (every child ended via cancellation
        // before reporting), the caller must still be released.
        resolve(.cancelled)
    }

    /// External cancellation: resolves `.cancelled` immediately (unless an
    /// outcome already won) so the caller is released even while children sit
    /// in non-cancellable work, and so a straggler's later rejection or
    /// failure cannot win over the cancellation.
    func callerCancelled() {
        resolve(.cancelled)
    }

    /// The caller-facing promise. Resumes exactly once.
    func outcome() async -> TransactionSubmissionOutcome {
        if let resolvedOutcome { return resolvedOutcome }
        return await withCheckedContinuation { continuation in
            if let resolvedOutcome {
                continuation.resume(returning: resolvedOutcome)
            } else {
                outcomeContinuation = continuation
            }
        }
    }

    // MARK: - Child tasks

    private func submit(to endpoint: LightWalletEndpoint) async {
        do {
            try await endpointSubmitter.submit(transaction: transaction, to: endpoint)
            submissionSucceeded(at: endpoint)
        } catch let TransactionEncoderError.submitError(code, message) {
            submissionRejected(at: endpoint, code: code, message: message)
        } catch is CancellationError {
            submissionCancelled(at: endpoint)
        } catch {
            if Task.isCancelled {
                submissionCancelled(at: endpoint)
            } else {
                submissionFailed(at: endpoint, error: error)
            }
        }
    }

    private func timeout() async {
        do {
            try await Task.sleep(nanoseconds: timing.responseTimeout.nanosecondsClamped)
        } catch {
            return
        }
        timeoutFired()
    }

    // MARK: - Race events (actor-serialized; arrival order decides ties)

    private func submissionSucceeded(at endpoint: LightWalletEndpoint) {
        completedCount += 1
        if winner == nil {
            winner = endpoint
            logger.info("Transaction \(transaction.txId.toHexStringTxId()) accepted by \(endpoint.host):\(endpoint.port).")
            resolve(.accepted(by: endpoint))
            startGraceCountdown()
        } else {
            logger.info("Transaction \(transaction.txId.toHexStringTxId()) also accepted by \(endpoint.host):\(endpoint.port) in the grace window.")
        }
        finishRaceIfAllCompleted()
    }

    private func submissionRejected(at endpoint: LightWalletEndpoint, code: Int, message: String) {
        completedCount += 1
        if firstRejection == nil {
            firstRejection = (code: code, message: message)
        }
        logger.warn("Transaction \(transaction.txId.toHexStringTxId()) rejected by \(endpoint.host):\(endpoint.port): \(code) \(message)")
        resolveIfAllFailed()
        finishRaceIfAllCompleted()
    }

    private func submissionFailed(at endpoint: LightWalletEndpoint, error: Error) {
        completedCount += 1
        logger.warn("Transaction \(transaction.txId.toHexStringTxId()) submission to \(endpoint.host):\(endpoint.port) failed: \(error)")
        resolveIfAllFailed()
        finishRaceIfAllCompleted()
    }

    private func submissionCancelled(at endpoint: LightWalletEndpoint) {
        logger.debug("Transaction \(transaction.txId.toHexStringTxId()) submission to \(endpoint.host):\(endpoint.port) ended by cancellation.")
        completedCount += 1
        // Only external cancellation can end children unresolved: internal
        // cancellation (grace/timeout teardown) happens after a resolution.
        if resolvedOutcome == nil && completedCount >= endpoints.count {
            resolve(.cancelled)
        }
        finishRaceIfAllCompleted()
    }

    private func timeoutFired() {
        guard resolvedOutcome == nil else { return }
        let txId = transaction.txId.toHexStringTxId()
        logger.warn("Transaction \(txId) submission timed out after \(timing.responseTimeout)s; it may still have been broadcast.")
        resolve(.timedOut)
        finishRace()
    }

    // MARK: - Resolution

    private func resolveIfAllFailed() {
        guard winner == nil, resolvedOutcome == nil, completedCount >= endpoints.count else { return }
        let txId = transaction.txId.toHexStringTxId()
        if let firstRejection {
            logger.debug("Transaction \(txId) rejected by all endpoints; first rejection: \(firstRejection.code) \(firstRejection.message).")
            resolve(.rejected(code: firstRejection.code, message: firstRejection.message))
        } else {
            logger.debug("Transaction \(txId) unreachable; all \(endpoints.count) endpoint(s) failed at the transport level.")
            resolve(.unreachable)
        }
        finishRace()
    }

    private func finishRaceIfAllCompleted() {
        guard completedCount >= endpoints.count else { return }
        finishRace()
    }

    private func startGraceCountdown() {
        let graceNanoseconds = timing.postAcceptanceGraceDelay.nanosecondsClamped
        graceTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: graceNanoseconds)
            guard !Task.isCancelled else { return }
            await self?.finishRace()
        }
    }

    private func resolve(_ outcome: TransactionSubmissionOutcome) {
        guard resolvedOutcome == nil else { return }
        resolvedOutcome = outcome
        outcomeContinuation?.resume(returning: outcome)
        outcomeContinuation = nil
    }

    private func finishRace() {
        guard !raceFinished else { return }
        raceFinished = true
        raceFinishedContinuation?.resume()
        raceFinishedContinuation = nil
    }

    private func waitUntilRaceFinishes() async {
        if raceFinished { return }
        await withCheckedContinuation { continuation in
            if raceFinished {
                continuation.resume()
            } else {
                raceFinishedContinuation = continuation
            }
        }
    }
}

private extension TimeInterval {
    var nanosecondsClamped: UInt64 {
        guard self > 0 else { return 0 }
        let nanoseconds = self * 1_000_000_000
        guard nanoseconds < TimeInterval(UInt64.max) else { return UInt64.max }
        return UInt64(nanoseconds)
    }
}
