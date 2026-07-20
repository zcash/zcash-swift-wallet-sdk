//
//  ZcashNetwork+IronwoodActivation.swift
//  ZcashLightClientKit
//

import Foundation

public extension ZcashNetwork {
    /// The NU6.3 (Ironwood) activation height for this network, or `nil` when there is no known
    /// Ironwood activation for it.
    ///
    /// The app-facing home for the Ironwood activation height: it replaces hosts' own hardcoded NU
    /// heights. Stateless — no database access, and safe to read before any ``Synchronizer`` or
    /// ``Initializer`` exists (e.g. to gate migration availability/UI on whether the chain has
    /// reached activation).
    ///
    /// - Note: ``NetworkType/mainnet`` and ``NetworkType/testnet`` return their protocol-defined
    ///   heights. A custom (regtest-slot) network carries no fixed NU6.3 height and therefore
    ///   returns `nil`.
    var ironwoodActivationHeight: BlockHeight? {
        ZcashRustBackend.ironwoodActivationHeight(networkType: networkType)
    }
}
