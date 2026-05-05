//
//  ScanRange.swift
//
//
//  Created by Jack Grigg on 17/07/2023.
//

import Foundation

struct ScanRange {
    enum Priority: UInt8 {
        case ignored = 0
        case scanned = 10
        case historic = 20
        case openAdjacent = 30
        case foundNote = 40
        case chainTip = 50
        case anchor = 55
        case verify = 60
        
        init(_ value: UInt8) {
            if let priority = Priority(rawValue: value) {
                self = priority
            } else {
                fatalError("The value \(value) is out of the range of priorities.")
            }
        }
    }
    
    let range: Range<BlockHeight>
    let priority: Priority
}
