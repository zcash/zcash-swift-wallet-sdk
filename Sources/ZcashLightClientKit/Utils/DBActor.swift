//
//  DBActor.swift
//
//
//  Created by Lukáš Korba on 04-08-2024.
//

import Foundation

/// Global actor used to protect access to the Data DB.
@globalActor
enum DBActor {
    typealias ActorType = Actor

    actor Actor { }
    static let shared = Actor()

    static var sharedUnownedExecutor: UnownedSerialExecutor {
        shared.unownedExecutor
    }
}
