//
//  Checkpoint.swift
//
//
//  Created by Francisco Gindre on 7/12/22.
//

import Foundation

/// Represents the wallet's birthday which can be thought of as a checkpoint at the earliest moment in history where
/// transactions related to this wallet could exist. Ideally, this would correspond to the latest block height at the
/// time the wallet key was created. Worst case, the height of Sapling activation could be used (280000).
///
/// Knowing a wallet's birthday can significantly reduce the amount of data that it needs to download because none of
/// the data before that height needs to be scanned for transactions. However, we do need the Sapling tree data in
/// order to construct valid transactions from that point forward. This birthday contains that tree data, allowing us
/// to avoid downloading all the compact blocks required in order to generate it.
///
/// New wallets can ignore any blocks created before their birthday.
///
/// - Parameters:
///  - height: the height at the time the wallet was born
///  - hash: the block hash corresponding to the given height
///  - time: the time the wallet was born, in seconds
///  - saplingTree: the sapling tree corresponding to the given height. This takes around 15 minutes of processing to generate from scratch because all blocks since activation need to be considered. So when it is calculated in advance it can save the user a lot of time.
///  - orchardTree: the orchard tree corresponding to the given height. This field is optional since it won't be available prior
///   to NU5 activation height for the given network.
struct Checkpoint: Equatable {
    let height: BlockHeight
    let hash: String
    let time: UInt32
    let saplingTree: String
    let orchardTree: String?
}

extension Checkpoint: Decodable {
    public enum CodingKeys: String, CodingKey {
        case height
        case hash
        case time
        case saplingTree
        case orchardTree
    }

    public init(from decoder: Decoder) throws {
        do {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.height = try Self.getHeight(from: container)
            self.hash = try container.decode(String.self, forKey: .hash)
            self.time = try container.decode(UInt32.self, forKey: .time)
            self.saplingTree = try container.decode(String.self, forKey: .saplingTree)
            self.orchardTree = try container.decodeIfPresent(String.self, forKey: .orchardTree)
        } catch {
            throw ZcashError.checkpointDecode(error)
        }
    }

    static func getHeight(from container: KeyedDecodingContainer<CodingKeys>) throws -> Int {
        guard
            let heightString = try? container.decode(String.self, forKey: .height),
            let height = Int(heightString)
        else {
            throw DecodingError.typeMismatch(
                String.self,
                DecodingError.Context(
                    codingPath: [CodingKeys.height],
                    debugDescription: "expected height to be encoded as a string",
                    underlyingError: nil
                )
            )
        }
        return height
    }

    public func treeState() -> TreeState {
        var ret = TreeState()
        ret.height = UInt64(height)
        ret.hash = hash
        ret.time = time
        ret.saplingTree = saplingTree
        if let tree = orchardTree {
            ret.orchardTree = tree
        }
        return ret
    }
}

public extension BlockHeight {
    /// Useful when creating a new wallet to reduce sync times.
    /// - Parameters:
    ///  - zcashNetwork: Network to use for the block height.
    /// - Returns: The block height of the newest checkpoint known by the SDK.
    static func ofLatestCheckpoint(network: ZcashNetwork) -> BlockHeight {
        Checkpoint.birthday(with: BlockHeight.max, network: network).height
    }
}
