//
//  BundleCheckpointSource.swift
//
//
//  Created by Francisco Gindre on 2023-10-30.
//

import Foundation

struct BundleCheckpointSource: CheckpointSource {
    var network: NetworkType

    var saplingActivation: Checkpoint

    init(network: NetworkType) {
        self.network = network
        self.saplingActivation = if network == .mainnet { Checkpoint.mainnetMin } else { Checkpoint.testnetMin }
    }

    func latestKnownCheckpoint() -> Checkpoint {
        Checkpoint.birthday(
            with: .max,
            checkpointDirectory: BundleCheckpointURLProvider.default.url(self.network)
        ) ?? saplingActivation
    }

    func birthday(for height: BlockHeight) -> Checkpoint {
        Checkpoint.birthday(
            with: height,
            checkpointDirectory: BundleCheckpointURLProvider.default.url(self.network)
        ) ?? saplingActivation
    }

    // swiftlint:disable:next cyclomatic_complexity
    func estimateBirthdayHeight(for date: Date) -> BlockHeight {
        // the average time between 2500 blocks during last 10 checkpoints (estimated March 31, 2025) is 52.33 hours for mainnet
        // the average time between 10,000 blocks during last 10 checkpoints (estimated March 31, 2025) is 134.93 hours for testnet
        let avgIntervalTime: TimeInterval = network == .mainnet ? 52.33 : 134.93
        let blockInterval: Double = network == .mainnet ? 2500 : 10_000
        let saplingActivationHeight = network == .mainnet
        ? ZcashMainnet().constants.saplingActivationHeight
        : ZcashTestnet().constants.saplingActivationHeight

        let latestCheckpoint = latestKnownCheckpoint()
        let latestCheckpointTime = TimeInterval(latestCheckpoint.time)

        // above latest checkpoint, return it
        guard date.timeIntervalSince1970 < latestCheckpointTime else {
            return latestCheckpoint.height
        }

        // Phase 1, estimate possible height
        let nowTimeIntervalSince1970 = Date().timeIntervalSince1970
        let timeDiff = (nowTimeIntervalSince1970 - date.timeIntervalSince1970) - (nowTimeIntervalSince1970 - latestCheckpointTime)
        let blockDiff = ((timeDiff / 3600) / avgIntervalTime) * blockInterval

        var heightToLookAround = Double(Int(latestCheckpoint.height - Int(blockDiff)) / Int(blockInterval)) * blockInterval

        // bellow sapling activation height
        guard Int(heightToLookAround) > saplingActivationHeight else {
            return saplingActivationHeight
        }

        // Phase 2, load checkpoint and evaluate against given date
        guard let loadedCheckpoint = Checkpoint.birthday(
            with: BlockHeight(heightToLookAround),
            checkpointDirectory: BundleCheckpointURLProvider.default.url(self.network)
        ) else {
            return saplingActivationHeight
        }

        // loaded checkpoint is exactly the one
        var hoursApart = (TimeInterval(loadedCheckpoint.time) - date.timeIntervalSince1970) / 3600
        if hoursApart < 0 && abs(hoursApart) < avgIntervalTime {
            return loadedCheckpoint.height
        }

        if hoursApart < 0 {
            // loaded checkpoint is lower, increase until reached the one
            var closestHeight = loadedCheckpoint.height
            while abs(hoursApart) > avgIntervalTime {
                heightToLookAround += blockInterval

                if let loadedCheckpoint = Checkpoint.birthday(
                    with: BlockHeight(heightToLookAround),
                    checkpointDirectory: BundleCheckpointURLProvider.default.url(self.network)
                ) {
                    hoursApart = (TimeInterval(loadedCheckpoint.time) - date.timeIntervalSince1970) / 3600
                    if hoursApart < 0 && abs(hoursApart) < avgIntervalTime {
                        return loadedCheckpoint.height
                    } else if hoursApart >= 0 {
                        return closestHeight
                    }

                    closestHeight = loadedCheckpoint.height
                } else {
                    return saplingActivationHeight
                }
            }
        } else {
            // loaded checkpoint is higher, descrease until reached the one
            while hoursApart > 0 {
                heightToLookAround -= blockInterval

                if let loadedCheckpoint = Checkpoint.birthday(
                    with: BlockHeight(heightToLookAround),
                    checkpointDirectory: BundleCheckpointURLProvider.default.url(self.network)
                ) {
                    hoursApart = (TimeInterval(loadedCheckpoint.time) - date.timeIntervalSince1970) / 3600
                    if hoursApart < 0 {
                        return loadedCheckpoint.height
                    }
                } else {
                    return saplingActivationHeight
                }
            }
        }

        return saplingActivationHeight
    }

    func estimateTimestamp(for height: BlockHeight) -> TimeInterval? {
        let blockInterval: BlockHeight = network == .mainnet ? 2500 : 10_000
        var checkpointHeight = (height / blockInterval) * blockInterval

        // Ensure sapling activation is the lowest possible
        let saplingActivationHeight = network == .mainnet
        ? ZcashMainnet().constants.saplingActivationHeight
        : ZcashTestnet().constants.saplingActivationHeight

        if checkpointHeight < saplingActivationHeight {
            checkpointHeight = saplingActivationHeight
        }

        var checkpoint: Checkpoint?

        while checkpoint == nil || checkpointHeight > blockInterval {
            checkpoint = Checkpoint.birthday(
                with: BlockHeight(checkpointHeight),
                checkpointDirectory: BundleCheckpointURLProvider.default.url(self.network)
            )

            if let checkpoint {
                return TimeInterval(checkpoint.time)
            }

            checkpointHeight -= blockInterval

            if checkpointHeight < saplingActivationHeight {
                checkpointHeight = saplingActivationHeight
            }
        }

        return nil
    }
}
