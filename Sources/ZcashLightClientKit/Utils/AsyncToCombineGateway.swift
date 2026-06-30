//
//  AsyncToCombineGateway.swift
//
//
//  Created by Michal Fousek on 03.04.2023.
//

import Combine
import Foundation

enum AsyncToCombineGateway {
    static func executeAction(action: @escaping () async -> Void) -> CompletablePublisher<Never> {
        let subject = PassthroughSubject<Void, Never>()
        Task {
            await action()
            subject.send(completion: .finished)
        }
        return subject.eraseToAnyPublisher()
    }

    static func executeAction<R>(action: @escaping () async -> R) -> SinglePublisher<R, Never> {
        let subject = PassthroughSubject<R, Never>()
        Task {
            let result = await action()
            subject.send(result)
            subject.send(completion: .finished)
        }
        return subject.eraseToAnyPublisher()
    }

    static func executeThrowingAction(action: @escaping () async throws -> Void) -> CompletablePublisher<Error> {
        let subject = PassthroughSubject<Void, Error>()
        Task {
            do {
                try await action()
                subject.send(completion: .finished)
            } catch {
                subject.send(completion: .failure(error))
            }
        }

        return subject.eraseToAnyPublisher()
    }

    static func executeThrowingAction<R>(action: @escaping () async throws -> R) -> SinglePublisher<R, Error> {
        let subject = PassthroughSubject<R, Error>()
        Task {
            do {
                let result = try await action()
                subject.send(result)
                subject.send(completion: .finished)
            } catch {
                subject.send(completion: .failure(error))
            }
        }

        return subject.eraseToAnyPublisher()
    }
}
