//
//  Data+ToOtherTypes.swift
//
//
//  Created by Michal Fousek on 21.05.2023.
//

import Foundation

extension Data {
    func toInt() -> Int {
        return self.withUnsafeBytes { $0.load(as: Int.self) }
    }

    func toBool() -> Bool {
        return self.withUnsafeBytes { $0.load(as: Bool.self) }
    }
}
