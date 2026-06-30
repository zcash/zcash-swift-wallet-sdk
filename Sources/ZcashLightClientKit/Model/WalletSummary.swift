//
//  WalletSummary.swift
//
//
//  Created by Jack Grigg on 06/09/2023.
//

import Foundation

public struct PoolBalance: Equatable {
    public let spendableValue: Zatoshi
    public let changePendingConfirmation: Zatoshi
    public let valuePendingSpendability: Zatoshi

    static let zero = PoolBalance(spendableValue: .zero, changePendingConfirmation: .zero, valuePendingSpendability: .zero)

    public func total() -> Zatoshi {
        self.spendableValue + self.changePendingConfirmation + self.valuePendingSpendability
    }
}

public struct AccountBalance: Equatable {
    public let saplingBalance: PoolBalance
    public let orchardBalance: PoolBalance
    public let unshielded: Zatoshi

    /// This field is reserved for special operations.
    /// Its current use relates to the time period when the chain tip has not yet been updated, and an attempt would otherwise be made to shield transparent funds.
    /// Such a scenario would result in failure, so the funds are moved to `awaitingResolution` until the chain tip is updated.
    /// The goal is to report the total amount along with the expected value.
    public let awaitingResolution: Zatoshi

    static let zero = AccountBalance(saplingBalance: .zero, orchardBalance: .zero, unshielded: .zero, awaitingResolution: .zero)

    init(saplingBalance: PoolBalance, orchardBalance: PoolBalance, unshielded: Zatoshi, awaitingResolution: Zatoshi = .zero) {
        self.saplingBalance = saplingBalance
        self.orchardBalance = orchardBalance
        self.unshielded = unshielded
        self.awaitingResolution = awaitingResolution
    }
}

struct ScanProgress: Equatable {
    let numerator: UInt64
    let denominator: UInt64

    var isComplete: Bool {
        numerator == denominator
    }

    func progress() throws -> Float {
        guard denominator != 0 else {
            return 1.0
        }

        let value = Float(numerator) / Float(denominator)

        // this shouldn't happen but if it does, we need to get notified by clients and work on a fix
        if value > 1.0 {
            throw ZcashError.rustScanProgressOutOfRange("\(value)")
        }

        return value
    }
}

struct WalletSummary: Equatable {
    let accountBalances: [AccountUUID: AccountBalance]
    let chainTipHeight: BlockHeight
    let fullyScannedHeight: BlockHeight
    let recoveryProgress: ScanProgress?
    let scanProgress: ScanProgress?
    let nextSaplingSubtreeIndex: UInt32
    let nextOrchardSubtreeIndex: UInt32
}
