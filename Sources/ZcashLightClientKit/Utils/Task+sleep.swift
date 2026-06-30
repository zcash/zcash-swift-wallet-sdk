//
//  Task+sleep.swift
//
//
//  Created by Michal Fousek on 28.04.2023.
//

import Foundation

extension Task where Success == Never, Failure == Never {
    static func sleep(milliseconds duration: UInt64) async throws {
        try await Task.sleep(nanoseconds: duration * 1000_000)
    }
}
