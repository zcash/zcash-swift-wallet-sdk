//  BlockDao.swift
//  ZcashLightClientKit
//
//  Created by Lukas Korba on 2025-01-25.
//

import Foundation
import SQLite

protocol BlockDao {
    func block(at height: BlockHeight) throws -> Block?
}

struct Block: Codable {
    enum CodingKeys: String, CodingKey {
        case height
        case time
    }

    enum TableStructure {
        static let height = SQLite.Expression<Int>(Block.CodingKeys.height.rawValue)
        static let time = SQLite.Expression<Int>(Block.CodingKeys.time.rawValue)
    }

    let height: BlockHeight
    let time: Int

    static let table = Table("blocks")
}

class BlockSQLDAO: BlockDao {
    let dbProvider: ConnectionProvider
    let table: Table
    let height = SQLite.Expression<Int>("height")

    init(dbProvider: ConnectionProvider) {
        self.dbProvider = dbProvider
        self.table = Table("Blocks")
    }

    /// - Throws:
    ///     - `blockDAOCantDecode` if block data loaded from DB can't be decoded to `Block` object.
    ///     - `blockDAOBlock` if sqlite query to load block metadata failed.
    func block(at height: BlockHeight) throws -> Block? {
        do {
            return try dbProvider
                .connection()
                .prepare(Block.table.filter(Block.TableStructure.height == height).limit(1))
                .map {
                    do {
                        return try $0.decode()
                    } catch {
                        throw ZcashError.blockDAOCantDecode(error)
                    }
                }
                .first
        } catch {
            if let error = error as? ZcashError {
                throw error
            } else {
                throw ZcashError.blockDAOBlock(error)
            }
        }
    }
}
