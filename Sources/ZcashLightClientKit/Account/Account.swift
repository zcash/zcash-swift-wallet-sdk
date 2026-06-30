//
//  Account.swift
//  ZcashLightClientKit
//
//  Created by Lukáš Korba on 2024-11-19.
//

/// A [ZIP 32](https://zips.z.cash/zip-0032) account index.
///
/// This index must be paired with a seed, or other context that determines a seed,
/// in order to identify a ZIP 32 *account*.
public struct Zip32AccountIndex: Equatable, Codable, Hashable {
    public let index: UInt32

    /// - Parameter index: the ZIP 32 account index, which must be less than ``1<<31``.
    public init(_ index: UInt32) {
        guard index < (1 << 31) else {
            fatalError("Account index must be less than 1<<31. Input value is \(index).")
        }

        self.index = index
    }
}

public struct AccountId: Equatable, Codable, Hashable {
    public let id: Int

    /// - Parameter id: the local account id, which must be nonnegative.
    public init(_ id: Int) {
        guard id >= 0 else {
            fatalError("Account id must be >= 0. Input value is \(id).")
        }

        self.id = id
    }
}

public struct AccountUUID: Equatable, Codable, Hashable, Identifiable {
    public let id: [UInt8]

    init(id: [UInt8]) {
        guard id.count == 16 else {
            fatalError("Account UUID must be 16 bytes long. Input value is \(id).")
        }

        self.id = id
    }
}
