//
//  Error+ZcashError.swift
//
//
//  Created by Lukáš Korba on 09.05.2023.
//

import Foundation

public extension Error {
    func toZcashError() -> ZcashError {
        if let zcashError = self as? ZcashError {
            return zcashError
        } else {
            return ZcashError.unknown(self)
        }
    }
}
