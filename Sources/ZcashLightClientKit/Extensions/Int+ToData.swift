//
//  Int+ToData.swift
//
//
//  Created by Michal Fousek on 21.05.2023.
//

import Foundation

extension Int {
    func toData() -> Data {
        var value = self
        return withUnsafeBytes(of: &value) { Data($0) }
    }
}
