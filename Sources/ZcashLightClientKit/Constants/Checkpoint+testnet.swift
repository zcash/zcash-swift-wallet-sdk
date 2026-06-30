//
//  WalletBirthday+testnet.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 7/28/21.
//

import Foundation

extension Checkpoint {
    static let testnetMin = Checkpoint(
        height: 280000,
        hash: "000420e7fcc3a49d729479fb0b560dd7b8617b178a08e9e389620a9d1dd6361a",
        time: 1535262293,
        saplingTree: "000000",
        orchardTree: nil
    )

    static let testnetCheckpointDirectory = Bundle.module.bundleURL.appendingPathComponent("checkpoints/testnet/")
}
