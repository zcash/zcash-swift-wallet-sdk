//
//  SimpleConnectionProvider.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 10/13/19.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import Foundation
import SQLite

class SimpleConnectionProvider: ConnectionProvider {
    let path: String
    let readonly: Bool
    var db: Connection?

    init(path: String, readonly: Bool = false) {
        self.path = path
        self.readonly = readonly
    }

    /// throws ZcashError.simpleConnectionProvider
    func connection() throws -> Connection {
        guard let conn = db else {
            do {
                let conn = try Connection(path, readonly: readonly)
                self.db = conn
                return conn
            } catch {
                throw ZcashError.simpleConnectionProvider(error)
            }
        }
        return conn
    }

    /// throws ZcashError.simpleConnectionProvider
    func debugConnection() throws -> Connection {
        do {
            let conn = try Connection(path, readonly: true)
            try addDebugFunctions(conn: conn)
            return conn
        } catch {
            throw ZcashError.simpleConnectionProvider(error)
        }
    }

    func close() {
        self.db = nil
    }
}

private func addDebugFunctions(conn: Connection) throws {
    // `SELECT txid(txid) FROM transactions`
    _ = try conn.createFunction("txid", deterministic: true) { (txid: SQLite.Blob) in
        return txid.toHex().toTxIdString()
    }
    // `SELECT memo(memo) FROM sapling_received_notes`
    _ = try conn.createFunction("memo", deterministic: true) { (memoBytes: SQLite.Blob?) -> String? in
        guard let memoBytes else { return nil }
        do {
            let memo = try Memo(bytes: memoBytes.bytes)
            return memo.toString() ?? memoBytes.toHex()
        } catch {
            return nil
        }
    }
}
