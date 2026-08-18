//
//  TxResubmitter.swift
//  ZcashLightClientKit
//

import Foundation

/// Engine-independent resubmission core: prunes stale submit plans and
/// resubmits the transactions that qualify, throttled to at most once per
/// 300-second window. Shared by the old sync pipeline's `TxResubmissionAction`
/// and `SlipstreamSynchronizer`, so the retry policy lives in exactly one place.
package final class TxResubmitter {
    private enum Constants {
        static let thresholdToTrigger = TimeInterval(300.0)
    }

    var latestResolvedTime: TimeInterval = Date().timeIntervalSince1970
    let transactionRepository: TransactionRepository
    var transactionEncoder: TransactionEncoder
    let submitPlanStore: SubmitPlanStoring
    let submitPlanExecutor: SubmitPlanExecutor
    let logger: Logger

    package init(container: DIContainer) {
        transactionRepository = container.resolve(TransactionRepository.self)
        transactionEncoder = container.resolve(TransactionEncoder.self)
        submitPlanStore = container.resolve(SubmitPlanStoring.self)
        submitPlanExecutor = container.resolve(SubmitPlanExecutor.self)
        logger = container.resolve(Logger.self)
    }

    package func checkAndResubmit(latestBlockHeight: BlockHeight) async {
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
    }
}

private extension TxResubmitter {
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

    func pruneStalePlans(latestBlockHeight: BlockHeight) async {
        let plannedTxIds = await submitPlanStore.allPlannedTransactionIds()
        guard !plannedTxIds.isEmpty else { return }

        var staleTxIds: [Data] = []
        for txId in plannedTxIds {
            do {
                let transaction = try await transactionRepository.find(rawID: txId)
                // Stale only once expired: pruning at "mined" would lose the
                // plan if a reorg un-mines the transaction inside its expiry
                // window. Transactions without an expiry height are never
                // resubmission candidates, so their plans are stale right away.
                let isStale = (transaction.expiryHeight ?? 0) <= latestBlockHeight
                if isStale {
                    staleTxIds.append(txId)
                }
            } catch ZcashError.transactionRepositoryEntityNotFound {
                do {
                    guard let created = try await transactionEncoder.createdTransactions(forTxIds: [txId]).first,
                          let expiryHeight = created.expiryHeight,
                          expiryHeight > latestBlockHeight
                    else {
                        staleTxIds.append(txId)
                        continue
                    }
                    logger.warn(
                        "TxResubmissionAction keeping plan for view-invisible wallet-store transaction \(txId.toHexStringTxId())."
                    )
                } catch {
                    // An unreadable wallet store is inconclusive. Keep the plan and retry later.
                    logger.warn(
                        """
                        TxResubmissionAction could not verify view-invisible transaction \(txId.toHexStringTxId()): \
                        \(error.localizedDescription)
                        """
                    )
                }
            } catch {
                // Unknown repository error — keep the plan, try again next pass.
                logger.warn(
                    """
                    TxResubmissionAction could not check plan staleness for \(txId.toHexStringTxId()): \
                    \(error.localizedDescription)
                    """
                )
            }
        }

        if !staleTxIds.isEmpty {
            logger.info("TxResubmissionAction pruning \(staleTxIds.count) stale submit plan(s).")
            await submitPlanStore.deletePlans(txIds: staleTxIds)
        }
    }
}
