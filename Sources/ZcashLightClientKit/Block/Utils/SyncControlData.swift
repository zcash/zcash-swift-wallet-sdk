//
//  SyncControlData.swift
//
//
//  Created by Michal Fousek on 23.11.2022.
//

import Foundation

struct SyncControlData: Equatable {
    /// The tip of the blockchain
    let latestBlockHeight: BlockHeight
    /// The last height that has been scanned
    let latestScannedHeight: BlockHeight?
    /// The height from the enhancement must start
    let firstUnenhancedHeight: BlockHeight?

    static var empty: SyncControlData {
        SyncControlData(
            latestBlockHeight: 0,
            latestScannedHeight: nil,
            firstUnenhancedHeight: nil
        )
    }
}
