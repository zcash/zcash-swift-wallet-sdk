//
//  UnspentTransactionOutputEntityMock.swift
//
//
//  Created by Michal Fousek on 20.03.2023.
//

import Foundation
@testable import ZcashLightClientKit

class UnspentTransactionOutputEntityMock: UnspentTransactionOutputEntity, Equatable {
    var address: String
    var txid: Data
    var index: Int
    var script: Data
    var valueZat: Int
    var height: Int

    init(address: String, txid: Data, index: Int, script: Data, valueZat: Int, height: Int) {
        self.address = address
        self.txid = txid
        self.index = index
        self.script = script
        self.valueZat = valueZat
        self.height = height
    }

    static func == (lhs: UnspentTransactionOutputEntityMock, rhs: UnspentTransactionOutputEntityMock) -> Bool {
        return
            lhs.address == rhs.address &&
            lhs.txid == rhs.txid &&
            lhs.index == rhs.index &&
            lhs.script == rhs.script &&
            lhs.valueZat == rhs.valueZat &&
            lhs.height == rhs.height
    }
}
