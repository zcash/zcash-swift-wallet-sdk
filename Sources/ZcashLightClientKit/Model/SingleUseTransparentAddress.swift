//
//  SingleUseTransparentAddress.swift
//  ZcashLightClientKit
//
//  Created by Lukáš Korba on 2025-10-27.
//

import Foundation

public struct SingleUseTransparentAddress: Equatable {
    let address: String
    let gapPosition: UInt32
    let gapLimit: UInt32

    public init(address: String, gapPosition: UInt32, gapLimit: UInt32) {
        self.address = address
        self.gapPosition = gapPosition
        self.gapLimit = gapLimit
    }
}

public enum TransparentAddressCheckResult: Equatable {
    /// Some funds found with a string of the address associated with the funds
    case found(String)
    /// No funds found
    case notFound
    /// Fallback for the non-Tor path, there is no grpc method at the moment
    case torRequired
}
