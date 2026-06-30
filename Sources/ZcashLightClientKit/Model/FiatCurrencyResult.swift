//
//  FiatCurrencyResult.swift
//
//
//  Created by Lukáš Korba on 31.07.2024.
//

import Foundation

/// The model representing currency for ZEC-XXX conversion. Initial implementation
/// provides only USD value.
public struct FiatCurrencyResult: Equatable {
    public enum State: Equatable {
        /// Last fetch failed, cached value is returned instead.
        case error
        /// Refresh has been triggered, returning cached value but informing about request in flight.
        case fetching
        /// Fetch of the value ended up as success so new value in returned.
        case success
    }

    public let date: Date
    public let rate: NSDecimalNumber
    public var state: State

    public init(date: Date, rate: NSDecimalNumber, state: State) {
        self.date = date
        self.rate = rate
        self.state = state
    }
}
