//
//  SDKSynchronizerStateHandler.swift
//
//
//  Created by Michal Fousek on 15.03.2023.
//

import Combine
import Foundation
import XCTest
@testable import ZcashLightClientKit

class SDKSynchronizerInternalSyncStatusHandler {
    enum StatusIdentifier: String {
        case unprepared
        case syncing
        case enhancing
        case fetching
        case synced
        case stopped
        case disconnected
        case error
    }

    private let queue = DispatchQueue(label: "SDKSynchronizerInternalSyncStatusHandler")
    private var cancellables: [AnyCancellable] = []

    func subscribe(to stateStream: AnyPublisher<SynchronizerState, Never>, expectations: [StatusIdentifier: XCTestExpectation]) {
        stateStream
            .receive(on: queue)
            .map { $0.internalSyncStatus }
            .sink { status in expectations[status.identifier]?.fulfill() }
            .store(in: &cancellables)
    }
}

extension InternalSyncStatus {
    var identifier: SDKSynchronizerInternalSyncStatusHandler.StatusIdentifier {
        switch self {
        case .unprepared: return .unprepared
        case .syncing: return .syncing
        case .synced: return .synced
        case .stopped: return .stopped
        case .disconnected: return .disconnected
        case .error: return .error
        }
    }
}
