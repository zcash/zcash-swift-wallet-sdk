//
//  DenominationPlan.swift
//  ZcashLightClientKit
//

/// A plan for splitting a spendable Orchard balance into round-ZEC-denominated
/// outputs ahead of an Orchard -> Ironwood migration transfer.
public struct DenominationPlan: Equatable {
    /// Round-ZEC-denominated output values, descending order of denomination.
    public let migrationOutputs: [Int64]
    /// Sub-ZEC residual kept as Orchard change rather than migrated, when it's too
    /// small to be worth a dedicated migration output but still above the minimum
    /// output threshold.
    public let orchardChange: Int64?
    public let prepFeeZatoshi: Int64
    public let migrationFeeZatoshi: Int64
    public let totalInputZatoshi: Int64
    public let totalMigratableZatoshi: Int64
}
