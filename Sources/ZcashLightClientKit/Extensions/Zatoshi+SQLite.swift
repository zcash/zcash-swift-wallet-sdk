//
//  Zatoshi+SQLite.swift
//
//
//  Created by Francisco Gindre on 6/20/22.
//

import SQLite

extension Zatoshi: Value {
    public static let declaredDatatype = Int64.declaredDatatype

    public static func fromDatatypeValue(_ datatypeValue: Int64) -> Zatoshi {
        Zatoshi(datatypeValue)
    }

    public var datatypeValue: Int64 {
        self.amount
    }
}
