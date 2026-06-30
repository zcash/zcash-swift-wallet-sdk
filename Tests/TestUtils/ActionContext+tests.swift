//
//  ActionContext+tests.swift
//
//
//  Created by Lukáš Korba on 24.08.2023.
//

import XCTest
@testable import ZcashLightClientKit

enum ActionContextResult: Equatable {
    case `true`
    case isNotMock
    case called(Int)
    case nilState
    case wrongState(CBPState)
}

extension ActionContext {
    func checkStateIs(_ expectedState: CBPState) -> ActionContextResult {
        guard let nextContextMock = self as? ActionContextMock else {
            return .isNotMock
        }

        if nextContextMock.updateStateCallsCount != 1 {
            return .called(nextContextMock.updateStateCallsCount)
        }

        guard let updateStateReceivedState = nextContextMock.updateStateReceivedState else {
            return .nilState
        }

        if updateStateReceivedState != expectedState {
            return .wrongState(updateStateReceivedState)
        }

        return .true
    }
}

extension ActionContextMock {
    static func `default`() -> ActionContextMock {
        let context = ActionContextMock()

        context.underlyingState = .idle
        context.updateStateClosure = { _ in }

        return context
    }
}
