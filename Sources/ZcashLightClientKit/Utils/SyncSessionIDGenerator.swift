//
//  SyncSessionIDGenerator.swift
//
//
//  Created by Francisco Gindre on 3/31/23.
//

import Foundation

protocol SyncSessionIDGenerator {
    func nextID() -> UUID
}

struct UniqueSyncSessionIDGenerator {}

extension UniqueSyncSessionIDGenerator: SyncSessionIDGenerator {
    func nextID() -> UUID {
        UUID()
    }
}

typealias SyncSession = GenericActor<UUID>

extension SyncSession {
    /// updates the current sync session to a new value with the given generator
    /// - Parameters generator: a `SyncSessionIDGenerator`
    /// - returns: the `UUID` of the newly updated value.
    @discardableResult
    func newSession(with generator: SyncSessionIDGenerator) async -> UUID {
        return await self.update(generator.nextID())
    }
}
