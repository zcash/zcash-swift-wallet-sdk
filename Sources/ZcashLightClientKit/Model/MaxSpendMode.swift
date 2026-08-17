//
//  MaxSpendMode.swift
//  ZcashLightClientKit
//
//  Created by Michal Fousek on 2026-07-29.
//

/// Specifies how a "spend max" request should be evaluated.
public enum MaxSpendMode: Equatable, Sendable {
    /// Targets to spend all funds that are _currently_ spendable, where it could be the case that
    /// the wallet has received other funds that are not confirmed and therefore not spendable yet
    /// and the caller evaluates that as an acceptable scenario.
    case maxSpendable
    /// Targets to spend **all funds** and will fail if there are unspendable funds in the wallet
    /// or if the wallet is not yet synced.
    case everything
}
