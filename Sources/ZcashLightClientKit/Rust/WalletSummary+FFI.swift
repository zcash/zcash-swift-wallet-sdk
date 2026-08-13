//
//  WalletSummary+FFI.swift
//  ZcashLightClientKit
//
//  The C `FfiWalletSummary` → Swift `WalletSummary` mapping, extracted from
//  `ZcashRustBackend.getWalletSummary()` so it exists as a single, shared
//  C → Swift wallet-summary mapping.
//

import libzcashlc

extension WalletSummary {
    /// Maps a C `FfiWalletSummary` into the Swift model.
    ///
    /// Returns `nil` when the wallet has no balance data yet (the FFI's "none" summary,
    /// `fully_scanned_height < 0`) — identical to the legacy wrapper's contract.
    /// The caller owns the pointer and must free it (`zcashlc_free_wallet_summary`).
    package static func fromFFI(_ summaryPtr: UnsafeMutablePointer<FfiWalletSummary>) -> WalletSummary? {
        if summaryPtr.pointee.fully_scanned_height < 0 {
            return nil
        }

        var accountBalances: [AccountUUID: AccountBalance] = [:]
        for i in (0 ..< Int(summaryPtr.pointee.account_balances_len)) {
            let accountBalance = summaryPtr.pointee.account_balances.advanced(by: i).pointee
            accountBalances[AccountUUID(id: accountBalance.uuidArray)] = accountBalance.toAccountBalance()
        }

        return WalletSummary(
            accountBalances: accountBalances,
            chainTipHeight: BlockHeight(summaryPtr.pointee.chain_tip_height),
            fullyScannedHeight: BlockHeight(summaryPtr.pointee.fully_scanned_height),
            recoveryProgress: summaryPtr.pointee.recovery_progress?.pointee.toScanProgress(),
            scanProgress: summaryPtr.pointee.scan_progress?.pointee.toScanProgress(),
            nextSaplingSubtreeIndex: UInt32(summaryPtr.pointee.next_sapling_subtree_index),
            nextOrchardSubtreeIndex: UInt32(summaryPtr.pointee.next_orchard_subtree_index),
            nextIronwoodSubtreeIndex: UInt32(summaryPtr.pointee.next_ironwood_subtree_index)
        )
    }

    /// The [#1591] stale-tip protection as a pure transform: every account's SPENDABLE value
    /// is masked to zero (shifted into `valuePendingSpendability`; transparent into
    /// `awaitingResolution`) — applied while `SDKFlags.chainTipUpdated == false`, i.e. until
    /// the current run has refreshed the wallet DB chain tip. `lockedValue` passes through
    /// unchanged: locked value is already non-spendable, so the mask has nothing to shift.
    /// Extracted VERBATIM from `ZcashRustBackend.getWalletSummary()` so the transform has a
    /// single, shared definition.
    package func withSpendableMasked() -> WalletSummary {
        var masked = accountBalances
        masked.forEach { key, _ in
            if let accountBalance = masked[key] {
                masked[key] = AccountBalance(
                    saplingBalance: PoolBalance(
                        spendableValue: .zero,
                        changePendingConfirmation: accountBalance.saplingBalance.changePendingConfirmation,
                        valuePendingSpendability: accountBalance.saplingBalance.valuePendingSpendability
                        + accountBalance.saplingBalance.spendableValue,
                        lockedValue: accountBalance.saplingBalance.lockedValue
                    ),
                    orchardBalance: PoolBalance(
                        spendableValue: .zero,
                        changePendingConfirmation: accountBalance.orchardBalance.changePendingConfirmation,
                        valuePendingSpendability: accountBalance.orchardBalance.valuePendingSpendability
                        + accountBalance.orchardBalance.spendableValue,
                        lockedValue: accountBalance.orchardBalance.lockedValue
                    ),
                    ironwoodBalance: PoolBalance(
                        spendableValue: .zero,
                        changePendingConfirmation: accountBalance.ironwoodBalance.changePendingConfirmation,
                        valuePendingSpendability: accountBalance.ironwoodBalance.valuePendingSpendability
                        + accountBalance.ironwoodBalance.spendableValue,
                        lockedValue: accountBalance.ironwoodBalance.lockedValue
                    ),
                    unshielded: .zero,
                    awaitingResolution: accountBalance.unshielded
                )
            }
        }
        return WalletSummary(
            accountBalances: masked,
            chainTipHeight: chainTipHeight,
            fullyScannedHeight: fullyScannedHeight,
            recoveryProgress: recoveryProgress,
            scanProgress: scanProgress,
            nextSaplingSubtreeIndex: nextSaplingSubtreeIndex,
            nextOrchardSubtreeIndex: nextOrchardSubtreeIndex,
            nextIronwoodSubtreeIndex: nextIronwoodSubtreeIndex
        )
    }
}
