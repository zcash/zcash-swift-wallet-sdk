//
//  DandelionSubmitConfig.swift
//  ZcashLightClientKit
//

import Foundation

/// Controls how outgoing transactions are submitted to the Zcash network.
///
/// Choose ``DirectP2P`` to enable Dandelion++ Component A: the SDK connects
/// directly to a Zcash full node via the P2P wire protocol instead of routing
/// through a lightwalletd/Zaino server.  This prevents any intermediary from
/// observing the IP↔transaction correlation before the transaction enters the
/// P2P network's Dandelion++ stem phase.
///
/// ``LightWalletD`` is the legacy default.  Chain synchronisation always uses
/// lwd/Zaino regardless of this setting.
public enum DandelionSubmitConfig: Sendable {

    /// Default: submit transactions via lightwalletd's `SendTransaction` gRPC RPC.
    /// The lightwalletd operator sees your IP + transaction simultaneously.
    case lightWalletD

    /// Direct P2P submission.  The SDK performs:
    /// 1. DNS seeder lookup to find a live Zcash full node.
    /// 2. TCP connect + Zcash P2P version/verack handshake.
    /// 3. Sends the raw `tx` message without a prior `inv` (the "unadvertised tx"
    ///    convention from ZIP 327), signalling to the receiving node that this is
    ///    a direct wallet submission and should enter Dandelion++ stem phase immediately.
    /// 4. Disconnects.
    ///
    /// No intermediary server observes IP + transaction together.  Pairing this with
    /// Tor (if enabled) adds IP-level anonymity on top.
    ///
    /// - Parameters:
    ///   - network: The Zcash network to connect to (mainnet or testnet).
    ///   - fallbackToLightWalletD: If `true` (default), fall back to lwd submission
    ///     when all P2P peers are unreachable. Set to `false` to surface the P2P
    ///     failure to the caller instead.
    case directP2P(
        network: ZcashP2PNetwork = .mainnet,
        fallbackToLightWalletD: Bool = true
    )
}

/// Zcash network configuration for direct P2P connections.
public enum ZcashP2PNetwork: Sendable {
    case mainnet
    case testnet

    var magic: [UInt8] {
        switch self {
        case .mainnet: return [0x24, 0xe9, 0x27, 0x64]
        case .testnet: return [0xfa, 0x1a, 0xf9, 0xbf]
        }
    }

    var port: Int {
        switch self {
        case .mainnet: return 8233
        case .testnet: return 18233
        }
    }

    var dnsSeeds: [String] {
        switch self {
        case .mainnet:
            return [
                "dnsseed.z.cash",
                "dnsseed.str4d.xyz",
                "mainnet.seeder.zfnd.org",
                "mainnet.seeder.shieldedinfra.net"
            ]
        case .testnet:
            return [
                "dnsseed.testnet.z.cash",
                "testnet.seeder.zfnd.org"
            ]
        }
    }
}
