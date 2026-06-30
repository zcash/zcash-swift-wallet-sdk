//
//  UnspentTransactionOutputDAO.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 12/9/20.
//

import Foundation

struct UTXO: Decodable, Encodable {
    let address: String
    var prevoutTxId: Data
    var prevoutIndex: Int
    let script: Data
    let valueZat: Int
    let height: Int
}

extension UTXO: UnspentTransactionOutputEntity {
    var txid: Data {
        get {
            prevoutTxId
        }
        set {
            prevoutTxId = newValue
        }
    }

    var index: Int {
        get {
            prevoutIndex
        }
        set {
            prevoutIndex = newValue
        }
    }
}
