//
//  CompactBlockProgress.swift
//
//
//  Created by Michal Fousek on 11.05.2023.
//

import Foundation

final actor CompactBlockProgress {
    static let zero = CompactBlockProgress()

    var progress: Float = 0.0
    var areFundsSpendable = false

    func hasProgressUpdated(_ event: CompactBlockProcessor.Event) -> Bool {
        guard case let .syncProgress(progress, areFundsSpendable) = event else {
            return false
        }

        self.progress = progress
        self.areFundsSpendable = areFundsSpendable

        return true
    }
}
