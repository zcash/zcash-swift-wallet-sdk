//
//  NumberFormatter+Zcash.swift
//
//  Created by Lukáš Korba on 02.06.2022.
//  modified by Francisco Gindre on 6/17/22.
//

import Foundation

public extension NumberFormatter {
    static let zcashNumberFormatter: NumberFormatter = {
        var formatter = NumberFormatter()
        formatter.maximumFractionDigits = 8
        formatter.maximumIntegerDigits = 8
        formatter.numberStyle = .decimal
        formatter.usesGroupingSeparator = true
        return formatter
    }()
}
