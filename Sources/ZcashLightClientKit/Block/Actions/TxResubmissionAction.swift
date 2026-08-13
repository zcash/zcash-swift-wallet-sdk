//
//  TxResubmissionAction.swift
//
//
//  Created by Lukas Korba on 06-17-2024.
//

import Foundation

final class TxResubmissionAction {
    private enum Constants {
        static let thresholdToTrigger = TimeInterval(300.0)
    }

    var latestResolvedTime: TimeInterval = Date().timeIntervalSince1970
    let transactionRepository: TransactionRepository
    var transactionEncoder: TransactionEncoder
    let submitPlanStore: SubmitPlanStoring
    let submitPlanExecutor: SubmitPlanExecutor
    let rustBackend: ZcashRustBackendWelding
    let logger: Logger

    init(container: DIContainer) {
        transactionRepository = container.resolve(TransactionRepository.self)
        transactionEncoder = container.resolve(TransactionEncoder.self)
        submitPlanStore = container.resolve(SubmitPlanStoring.self)
        submitPlanExecutor = container.resolve(SubmitPlanExecutor.self)
        rustBackend = container.resolve(ZcashRustBackendWelding.self)
        logger = container.resolve(Logger.self)
    }
}

extension TxResubmissionAction: Action {
    var removeBlocksCacheWhenFailed: Bool { true }

    func run(with context: ActionContext, didUpdate: @escaping (CompactBlockProcessor.Event) async -> Void) async throws -> ActionContext {
        let latestBlockHeight = await context.syncControlData.latestBlockHeight

        // Plans whose transactions are expired or gone are no longer retry
        // candidates; drop them. Mined transactions keep their plans until
        // expiry so a reorg that un-mines one still retries through its
        // recorded endpoints — findForResubmission excludes mined transactions,
        // so a retained plan costs nothing meanwhile. Decisions are made per
        // transaction from current repository state, so a transaction created
        // mid-pass can never be wrongly pruned.
        await pruneStalePlans(latestBlockHeight: latestBlockHeight)

        // find all candidates for the resubmission
        do {
            logger.info("TxResubmissionAction check started at \(latestBlockHeight) height.")
            let transactions = try await transactionRepository.findForResubmission(upTo: latestBlockHeight)
            logger.debug("TxResubmissionAction found \(transactions.count) resubmission candidate(s).")

            // no candidates, update the time and continue with the next action
            if transactions.isEmpty {
                latestResolvedTime = Date().timeIntervalSince1970
            } else {
                let now = Date().timeIntervalSince1970
                let diff = now - latestResolvedTime

                // the last time resubmission was triggered is more than 5 minutes ago so try again
                if diff > Constants.thresholdToTrigger {
                    // resubmission; per-transaction error handling so one
                    // transaction's dead endpoints can't starve the others
                    for transaction in transactions {
                        do {
                            try await resubmit(transaction: transaction)
                        } catch {
                            logger.error(
                                "TxResubmissionAction failed to resubmit transaction \(transaction.rawID.toHexStringTxId()): \(error)"
                            )
                        }
                    }

                    latestResolvedTime = Date().timeIntervalSince1970
                }
            }
        } catch {
            logger.error("TxResubmissionAction failed to find candidates.")
        }

        if await context.prevState == .enhance {
            await context.update(state: .updateChainTip)
        } else {
            await context.update(state: .finished)
        }
        return context
    }

    func stop() async { }
}

private extension TxResubmissionAction {
    func resubmit(transaction: ZcashTransaction.Overview) async throws {
        let plan = await submitPlanStore.plan(for: transaction.rawID)

        switch plan {
        case .awaiting:
            // Created through Broadcaster but never submitted by the app —
            // resubmitting would broadcast something the user may have cancelled.
            logger.info(
                "TxResubmissionAction skipping transaction \(transaction.rawID.toHexStringTxId()) until it is submitted by the app."
            )

        case .ready(let endpoints):
            logger.info("TxResubmissionAction trying to resubmit transaction \(transaction.rawID.toHexStringTxId()) via its submit plan.")
            let createdTransaction = try CreatedTransaction(overview: transaction)
            try await submitPlanExecutor.submit(transaction: createdTransaction, endpoints: endpoints)

        case .storeUnavailable:
            // Whether the app ever submitted this transaction is unknown.
            // Skip rather than risk broadcasting something the user never
            // released or using an endpoint the user didn't choose.
            logger.warn(
                "TxResubmissionAction skipping transaction \(transaction.rawID.toHexStringTxId()): the submit plan store is unavailable."
            )

        case nil:
            logger.info("TxResubmissionAction trying to resubmit transaction \(transaction.rawID.toHexStringTxId()).")
            let encodedTransaction = try transaction.encodedTransaction()
            try await transactionEncoder.submit(transaction: encodedTransaction)
        }
    }

    /// The expiry height of a planned transaction, or `nil` when no store holds it.
    ///
    /// `v_transactions` is a history projection, not an existence oracle. It omits a stored
    /// transaction none of whose inputs was recorded and which has no wallet-internal output, the
    /// shape of a shielding or cross-pay send, so its silence is not evidence that the transaction
    /// is gone. The wallet store answers that; the view is consulted first only because it is
    /// already open.
    ///
    /// A transaction with no expiry height reports `0`, which the caller treats as stale. That
    /// matches `findForResubmission`, which requires `expiryHeight > latestBlockHeight` and so
    /// never selects one.
    private func plannedTransactionExpiry(txId: Data) async throws -> BlockHeight? {
        do {
            let transaction = try await transactionRepository.find(rawID: txId)
            return transaction.expiryHeight ?? 0
        } catch ZcashError.transactionRepositoryEntityNotFound {
            let stored = try await rustBackend.getTransaction(txId: txId)
            return stored.map { $0.expiryHeight ?? 0 }
        }
    }

    func pruneStalePlans(latestBlockHeight: BlockHeight) async {
        let plannedTxIds = await submitPlanStore.allPlannedTransactionIds()
        guard !plannedTxIds.isEmpty else { return }

        var staleTxIds: [Data] = []
        for txId in plannedTxIds {
            do {
                guard let expiryHeight = try await plannedTransactionExpiry(txId: txId) else {
                    // No store holds it, so nothing will ever be resubmitted for this plan.
                    staleTxIds.append(txId)
                    continue
                }
                // Stale only once expired: pruning at "mined" would lose the
                // plan if a reorg un-mines the transaction inside its expiry
                // window. Transactions without an expiry height are never
                // resubmission candidates, so their plans are stale right away.
                if expiryHeight <= latestBlockHeight {
                    staleTxIds.append(txId)
                }
            } catch {
                // Unknown error — keep the plan, try again next pass.
                logger.warn("TxResubmissionAction could not check plan staleness for \(txId.toHexStringTxId()): \(error)")
            }
        }

        if !staleTxIds.isEmpty {
            logger.info("TxResubmissionAction pruning \(staleTxIds.count) stale submit plan(s).")
            await submitPlanStore.deletePlans(txIds: staleTxIds)
        }
    }
}
