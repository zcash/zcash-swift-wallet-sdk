//
//  AccountEntity.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 11/14/19.
//

import Foundation
import SQLite

protocol AccountEntity {
    var accountIndex: Zip32AccountIndex { get }
    var ufvk: String { get }
}

struct DbAccount: AccountEntity, Encodable, Decodable {
    let accountIndex: Zip32AccountIndex
    let ufvk: String
}

extension DbAccount: Hashable {
    func hash(into hasher: inout Hasher) {
        hasher.combine(accountIndex.index)
        hasher.combine(ufvk)
    }

    static func == (lhs: Self, rhs: Self) -> Bool {
        guard
            lhs.accountIndex == rhs.accountIndex,
            lhs.ufvk == rhs.ufvk
        else { return false }

        return true
    }
}
