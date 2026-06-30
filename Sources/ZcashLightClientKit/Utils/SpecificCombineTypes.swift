//
//  SpecificCombineTypes.swift
//
//
//  Created by Michal Fousek on 03.04.2023.
//

import Combine
import Foundation

/* These aliases are here to just make the API easier to read. */

// Publisher which emitts completed or error. No value is emitted.
public typealias CompletablePublisher<E: Error> = AnyPublisher<Void, E>
// Publisher that either emits one value and then finishes or it emits error.
public typealias SinglePublisher = AnyPublisher
