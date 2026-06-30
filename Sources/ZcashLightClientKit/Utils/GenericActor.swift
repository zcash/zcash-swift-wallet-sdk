//
//  GenericActor.swift
//
//
//  Created by Michal Fousek on 20.03.2023.
//

import Foundation

actor GenericActor<T> {
    var value: T
    init(_ value: T) { self.value = value }
    func update(_ newValue: T) async -> T {
        let oldValue = value
        value = newValue
        return oldValue
    }
}
