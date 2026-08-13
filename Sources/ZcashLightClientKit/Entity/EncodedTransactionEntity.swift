//
//  EncodedTransactionEntity.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 11/19/19.
//

import Foundation

package struct EncodedTransaction {
    let transactionId: Data
    let raw: Data
}

/// The wallet-store data available for a transaction, independent of whether it was sent or received.
package struct TransactionData: Equatable {
    let txId: Data
    let raw: Data
    let expiryHeight: BlockHeight?
}

extension EncodedTransaction: Hashable {
    package func hash(into hasher: inout Hasher) {
        hasher.combine(transactionId)
        hasher.combine(raw)
    }

    package static func == (lhs: Self, rhs: Self) -> Bool {
        guard lhs.transactionId == rhs.transactionId else { return false }
        guard lhs.raw == rhs.raw else { return false }
        return true
    }
}
