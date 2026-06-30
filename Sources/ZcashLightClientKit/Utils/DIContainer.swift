//
//  DIContainer.swift
//
//
//  Created by Michal Fousek on 01.05.2023.
//

import Foundation

/// This class represents depedency injection containers.
class DIContainer {
    /// Structure that represents one registered dependency.
    struct Dependency {
        /// Closure which creates instance of the dependency.
        let factory: (DIContainer) -> Any
        /// Indicates if dependency is singleton. If this is `true` then `DIContainer` creates only one instance of this dependency and returns
        /// it every time `resolve()` for the dependency is called.
        let isSingleton: Bool
        /// If the dependency is singleton then instance is stored here.
        let instance: Any?
    }

    /// If this is `true` then `mockedDependencies` is used first to resolve dependencies. This is used for mocking in tests.
    var isTestEnvironment = false

    private let lock = NSRecursiveLock()
    /// Dependencies are stored here.
    private var dependencies: [String: Dependency] = [:]
    /// Mocked dependencies are stored here.
    private var mockedDependencies: [String: Dependency] = [:]

    init() { }

    private func key<T>(for type: T.Type) -> String {
        return String(describing: T.self)
    }

    func register<T>(type: T.Type, isSingleton: Bool, factory: @escaping (DIContainer) -> T) {
        lock.lock()
        let key = self.key(for: type)
        let depedency = Dependency(factory: factory, isSingleton: isSingleton, instance: nil)
        dependencies[key] = depedency
        lock.unlock()
    }

    func mock<T>(type: T.Type, isSingleton: Bool, factory: @escaping (DIContainer) -> T) {
        lock.lock()
        let key = self.key(for: type)
        let depedency = Dependency(factory: factory, isSingleton: isSingleton, instance: nil)
        mockedDependencies[key] = depedency
        lock.unlock()
    }

    func resolve<T>(_ type: T.Type) -> T {
        lock.lock()
        defer { lock.unlock() }
        let key = self.key(for: type)

        let possibleDependency = (isTestEnvironment ? mockedDependencies[key] : dependencies[key]) ?? dependencies[key]
        guard let dependency = possibleDependency else {
            // When dependency is resolved before it's registered then the app crashes. It would be possible to not crash and throw some error here.
            // But it complicates the rest of the code. And maybe it doesn't make sense because this kind of error is not recoverable. It can be fixed
            // only by updating the code.
            fatalError("Doesn't have registered dependency for type \(type).")
        }

        let instance: Any
        if dependency.isSingleton, let singleton = dependency.instance {
            instance = singleton
        } else {
            instance = dependency.factory(self)
        }

        if dependency.isSingleton && dependency.instance == nil {
            dependencies[key] = Dependency(factory: dependency.factory, isSingleton: dependency.isSingleton, instance: instance)
        }

        guard let instance = instance as? T else {
            // When dependency is resolved but instance of created depedency is different than expected type the app crashes. It would be possible to
            // not crash and throw some error here. But it complicates the rest of the code. And maybe it doesn't make sense because this kind of
            // error is not recoverable. It can be fixed only by updating the code.
            fatalError("Getting dependency for type \(type) but created instance is \(instance)")
        }
        return instance
    }
}
