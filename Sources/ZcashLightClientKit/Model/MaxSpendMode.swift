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
    /// Targets to spend **all non-dust funds** in the wallet. Dust notes — those valued at or below
    /// the ZIP-317 marginal fee — are excluded from note selection before this mode's eligibility
    /// check runs, so a wallet holding only dust neither has that dust spent nor fails because of
    /// it. This mode fails if the wallet holds other unspendable funds (for example unconfirmed or
    /// unmined funds) or if the wallet is not yet synced.
    case everything
}
