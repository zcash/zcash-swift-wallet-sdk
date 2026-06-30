//
//  EncodedTransactionEntity.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 11/19/19.
//

import Foundation

struct EncodedTransaction {
    let transactionId: Data
    let raw: Data
}

extension EncodedTransaction: Hashable {
    func hash(into hasher: inout Hasher) {
        hasher.combine(transactionId)
        hasher.combine(raw)
    }

    static func == (lhs: Self, rhs: Self) -> Bool {
        guard lhs.transactionId == rhs.transactionId else { return false }
        guard lhs.raw == rhs.raw else { return false }
        return true
    }
}
