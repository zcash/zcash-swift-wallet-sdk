//
//  CompactBlockProcessorEventHandler.swift
//
//
//  Created by Michal Fousek on 09.02.2023.
//

import Combine
import Foundation
import XCTest
@testable import ZcashLightClientKit

class CompactBlockProcessorEventHandler {
    enum EventIdentifier: String {
        case failed
        case finished
        case foundTransactions
        case minedTransaction
        case handleReorg
        case progressUpdated
        case syncProgress
        case storedUTXOs
        case startedEnhancing
        case startedFetching
        case startedSyncing
        case stopped
    }

    private let queue = DispatchQueue(label: "CompactBlockProcessorEventHandler")
    private var cancelables: [AnyCancellable] = []

    func subscribe(to blockProcessor: CompactBlockProcessor, expectations: [EventIdentifier: XCTestExpectation]) async {
        let closure: CompactBlockProcessor.EventClosure = { event in
            print("Received event: \(event.identifier)")
            expectations[event.identifier]?.fulfill()
        }

        await blockProcessor.updateEventClosure(identifier: "CompactBlockProcessorEventHandler", closure: closure)
    }
}

extension CompactBlockProcessor.Event {
    var identifier: CompactBlockProcessorEventHandler.EventIdentifier {
        switch self {
        case .failed:
            return .failed
        case .finished:
            return .finished
        case .foundTransactions:
            return .foundTransactions
        case .handledReorg:
            return .handleReorg
        case .progressUpdated:
            return .progressUpdated
        case .storedUTXOs:
            return .storedUTXOs
        case .startedEnhancing:
            return .startedEnhancing
        case .startedFetching:
            return .startedFetching
        case .startedSyncing:
            return .startedSyncing
        case .stopped:
            return .stopped
        case .minedTransaction:
            return .minedTransaction
        case .syncProgress:
            return .syncProgress
        }
    }
}
