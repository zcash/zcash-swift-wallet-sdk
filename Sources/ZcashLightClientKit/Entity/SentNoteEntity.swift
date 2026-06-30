//
//  Sent.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 11/14/19.
//

import Foundation

protocol SentNoteEntity {
    var id: Int { get }
    var transactionId: Int { get }
    var outputIndex: Int { get }
    var fromAccount: AccountId { get }
    var toAddress: String? { get }
    var toAccount: AccountId? { get }
    var value: Int { get }
    var memo: Data? { get }
}

extension SentNoteEntity {
    static func == (lhs: Self, rhs: Self) -> Bool {
        guard lhs.id == rhs.id,
            lhs.transactionId == rhs.transactionId,
            lhs.outputIndex == rhs.outputIndex,
            lhs.fromAccount == rhs.fromAccount,
            lhs.toAddress == rhs.toAddress,
            lhs.toAccount == rhs.toAccount,
            lhs.value == rhs.value,
            lhs.memo == rhs.memo else { return false }
        return true
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(id)
        hasher.combine(transactionId)
        hasher.combine(outputIndex)
        hasher.combine(fromAccount)
        hasher.combine(toAddress)
        hasher.combine(toAccount)
        hasher.combine(value)
        if let memo {
            hasher.combine(memo)
        } else {
            hasher.combine(Int(0))
        }
    }
}
