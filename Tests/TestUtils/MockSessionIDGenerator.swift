//
//  MockSessionIDGenerator.swift
//
//
//  Created by Francisco Gindre on 3/31/23.
//

import Foundation
@testable import ZcashLightClientKit

/// This generator will consume the list of UUID passed and fail if empty.
class MockSyncSessionIDGenerator: SyncSessionIDGenerator {
    var ids: [UUID]

    init(ids: [UUID]) {
        self.ids = ids
    }

    func nextID() -> UUID {
        ids.removeFirst()
    }
}
