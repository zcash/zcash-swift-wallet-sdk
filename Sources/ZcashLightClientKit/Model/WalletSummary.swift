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
    /// The value currently locked by an explicit output lock (e.g. the Orchard migration residual
    /// locked via the "Lock balance" choice) and therefore excluded from `spendableValue`. Locked
    /// value still belongs to the account — it is part of `total()` — it just cannot be selected
    /// for spending until it is unlocked.
    public let lockedValue: Zatoshi

    static let zero = PoolBalance(
        spendableValue: .zero,
        changePendingConfirmation: .zero,
        valuePendingSpendability: .zero,
        lockedValue: .zero
    )

    init(
        spendableValue: Zatoshi,
        changePendingConfirmation: Zatoshi,
        valuePendingSpendability: Zatoshi,
        lockedValue: Zatoshi = .zero
    ) {
        self.spendableValue = spendableValue
        self.changePendingConfirmation = changePendingConfirmation
        self.valuePendingSpendability = valuePendingSpendability
        self.lockedValue = lockedValue
    }

    public func total() -> Zatoshi {
        self.spendableValue + self.changePendingConfirmation + self.valuePendingSpendability + self.lockedValue
    }
}

public struct AccountBalance: Equatable {
    public let saplingBalance: PoolBalance
    public let orchardBalance: PoolBalance
    /// The Ironwood (Orchard note-version V3 / NU6.3) balance. Ironwood is received at the account's
    /// Orchard receiver. Non-zero only on NU6.3-active networks served by an Ironwood-aware
    /// lightwalletd (live on the public Ironwood testnet).
    public let ironwoodBalance: PoolBalance
    public let unshielded: Zatoshi

    /// This field is reserved for special operations.
    /// Its current use relates to the time period when the chain tip has not yet been updated, and an attempt would otherwise be made to shield transparent funds.
    /// Such a scenario would result in failure, so the funds are moved to `awaitingResolution` until the chain tip is updated.
    /// The goal is to report the total amount along with the expected value.
    public let awaitingResolution: Zatoshi

    static let zero = AccountBalance(
        saplingBalance: .zero,
        orchardBalance: .zero,
        ironwoodBalance: .zero,
        unshielded: .zero,
        awaitingResolution: .zero
    )

    init(
        saplingBalance: PoolBalance,
        orchardBalance: PoolBalance,
        ironwoodBalance: PoolBalance = .zero,
        unshielded: Zatoshi,
        awaitingResolution: Zatoshi = .zero
    ) {
        self.saplingBalance = saplingBalance
        self.orchardBalance = orchardBalance
        self.ironwoodBalance = ironwoodBalance
        self.unshielded = unshielded
        self.awaitingResolution = awaitingResolution
    }

    /// The spendable value summed across every shielded pool (Sapling, Orchard,
    /// Ironwood). Prefer this over summing pools at call sites — a new shielded
    /// pool then flows through automatically.
    public var shieldedSpendableValue: Zatoshi {
        saplingBalance.spendableValue + orchardBalance.spendableValue + ironwoodBalance.spendableValue
    }

    /// The total value (spendable + pending change + pending spendability + locked) summed
    /// across every shielded pool.
    public func shieldedTotal() -> Zatoshi {
        saplingBalance.total() + orchardBalance.total() + ironwoodBalance.total()
    }

    /// The change pending confirmation, summed across every shielded pool.
    public var shieldedChangePendingConfirmation: Zatoshi {
        saplingBalance.changePendingConfirmation + orchardBalance.changePendingConfirmation
            + ironwoodBalance.changePendingConfirmation
    }

    /// The value pending spendability, summed across every shielded pool.
    public var shieldedValuePendingSpendability: Zatoshi {
        saplingBalance.valuePendingSpendability + orchardBalance.valuePendingSpendability
            + ironwoodBalance.valuePendingSpendability
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

package struct WalletSummary: Equatable {
    package let accountBalances: [AccountUUID: AccountBalance]
    let chainTipHeight: BlockHeight
    package let fullyScannedHeight: BlockHeight
    let recoveryProgress: ScanProgress?
    let scanProgress: ScanProgress?
    let nextSaplingSubtreeIndex: UInt32
    let nextOrchardSubtreeIndex: UInt32
    let nextIronwoodSubtreeIndex: UInt32
}
