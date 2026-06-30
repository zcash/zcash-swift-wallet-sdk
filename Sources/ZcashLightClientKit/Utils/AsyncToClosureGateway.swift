//
//  AsyncToClosureGateway.swift
//
//
//  Created by Michal Fousek on 03.04.2023.
//

import Foundation

enum AsyncToClosureGateway {
    static func executeAction(_ completion: @escaping () -> Void, action: @escaping () async -> Void) {
        Task {
            await action()
            completion()
        }
    }

    static func executeAction<R>(_ completion: @escaping (R) -> Void, action: @escaping () async -> R) {
        Task {
            let result = await action()
            completion(result)
        }
    }

    static func executeThrowingAction(_ completion: @escaping (Error?) -> Void, action: @escaping () async throws -> Void) {
        Task {
            do {
                try await action()
                completion(nil)
            } catch {
                completion(error)
            }
        }
    }

    static func executeThrowingAction<R>(_ completion: @escaping (Result<R, Error>) -> Void, action: @escaping () async throws -> R) {
        Task {
            do {
                let result = try await action()
                completion(.success(result))
            } catch {
                completion(.failure(error))
            }
        }
    }
}
