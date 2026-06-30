//
//  AfterSyncHooksManager.swift
//
//
//  Created by Michal Fousek on 20.02.2023.
//

import Foundation

class AfterSyncHooksManager {
    struct WipeContext {
        let prewipe: () -> Void
        let completion: (Error?) async -> Void
    }

    struct RewindContext {
        let height: BlockHeight?
        let completion: (Result<BlockHeight, Error>) async -> Void
    }

    enum Hook: Equatable, Hashable {
        case anotherSync
        case rewind(RewindContext)
        case wipe(WipeContext)

        static func == (lhs: Hook, rhs: Hook) -> Bool {
            switch (lhs, rhs) {
            case (.anotherSync, .anotherSync):
                return true
            case (.rewind, .rewind):
                return true
            case (.wipe, .wipe):
                return true
            default:
                return false
            }
        }

        func hash(into hasher: inout Hasher) {
            switch self {
            case .anotherSync: hasher.combine(0)
            case .rewind: hasher.combine(1)
            case .wipe: hasher.combine(2)
            }
        }

        static var emptyRewind: Hook {
            return .rewind(RewindContext(height: nil, completion: { _ in }))
        }

        static var emptyWipe: Hook {
            return .wipe(
                WipeContext(
                    prewipe: { },
                    completion: { _ in }
                )
            )
        }
    }

    private var hooks: Set<Hook> = []

    init() { }

    func insert(hook: Hook) {
        hooks.insert(hook)
    }

    func shouldExecuteAnotherSyncHook() -> Bool {
        return hooks.first(where: { $0 == .anotherSync }) != nil
    }

    func shouldExecuteWipeHook() -> WipeContext? {
        if case let .wipe(wipeContext) = hooks.first(where: { $0 == Hook.emptyWipe }) {
            return wipeContext
        } else {
            return nil
        }
    }

    func shouldExecuteRewindHook() -> RewindContext? {
        if case let .rewind(rewindContext) = hooks.first(where: { $0 == Hook.emptyRewind }) {
            return rewindContext
        } else {
            return nil
        }
    }
}
