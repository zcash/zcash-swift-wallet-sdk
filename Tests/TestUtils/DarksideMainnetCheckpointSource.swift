//
//  TestingCheckpoints.swift
//
//
//  Created by Francisco Gindre on 2023-10-31.
//

import Foundation
@testable import ZcashLightClientKit

struct DarksideMainnetCheckpointSource: CheckpointSource {
    // swiftlint:disable line_length
    private let treeState = Checkpoint(
        height: 663150,
        hash: "0000000002fd3be4c24c437bd22620901617125ec2a3a6c902ec9a6c06f734fc",
        time: 1576821833,
        saplingTree: "01ec6278a1bed9e1b080fd60ef50eb17411645e3746ff129283712bc4757ecc833001001b4e1d4a26ac4a2810b57a14f4ffb69395f55dde5674ecd2462af96f9126e054701a36afb68534f640938bdffd80dfcb3f4d5e232488abbf67d049b33a761e7ed6901a16e35205fb7fe626a9b13fc43e1d2b98a9c241f99f93d5e93a735454073025401f5b9bcbf3d0e3c83f95ee79299e8aeadf30af07717bda15ffb7a3d00243b58570001fa6d4c2390e205f81d86b85ace0b48f3ce0afb78eeef3e14c70bcfd7c5f0191c0000011bc9521263584de20822f9483e7edb5af54150c4823c775b2efc6a1eded9625501a6030f8d4b588681eddb66cad63f09c5c7519db49500fc56ebd481ce5e903c22000163f4eec5a2fe00a5f45e71e1542ff01e937d2210c99f03addcce5314a5278b2d0163ab01f46a3bb6ea46f5a19d5bdd59eb3f81e19cfa6d10ab0fd5566c7a16992601fa6980c053d84f809b6abcf35690f03a11f87b28e3240828e32e3f57af41e54e01319312241b0031e3a255b0d708750b4cb3f3fe79e3503fe488cc8db1dd00753801754bb593ea42d231a7ddf367640f09bbf59dc00f2c1d2003cc340e0c016b5b13",
        orchardTree: nil
    )

    var network: NetworkType {
        DarksideWalletDNetwork().networkType
    }

    var saplingActivation: Checkpoint {
        treeState
    }

    func latestKnownCheckpoint() -> Checkpoint {
        treeState
    }

    func birthday(for height: BlockHeight) -> Checkpoint {
        treeState
    }

    func estimateBirthdayHeight(for date: Date) -> ZcashLightClientKit.BlockHeight {
        663150
    }

    func estimateTimestamp(for height: ZcashLightClientKit.BlockHeight) -> TimeInterval? {
        1576821833
    }
}
