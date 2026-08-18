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
    /// Seconds SQLite retries a locked DB before erroring. The Slipstream engine writes `data.db` (WAL
    /// journal) from Rust while the Swift side reads it concurrently; a read that lands during the
    /// engine's write / checkpoint — or while a cancelled write-behind task releases its lock, e.g. on a
    /// restart mid-pass — would otherwise get `SQLITE_BUSY` immediately. SQLite.swift's `FailableIterator`
    /// resolves a step error with `try!`, an UNCATCHABLE trap, so that `SQLITE_BUSY` crashes the app
    /// (no `do/catch` or `try?` can intercept it). A busy timeout makes the read wait for the lock to
    /// free and retry instead. Bounded so a genuinely stuck DB still surfaces rather than hanging forever.
    static let busyTimeoutSeconds: Double = 5

    let path: String
    let readonly: Bool
    /// Guards `db`. Since the DBActor read/write split, read-only DAO members call
    /// `connection()` from arbitrary threads concurrently, so the lazy init below must be
    /// single-flight — two racing first-touches used to construct two `Connection`s (one
    /// silently dropped, its serial queue with it). `NSLock` rather than
    /// `OSAllocatedUnfairLock` because the package floor (iOS 13 / macOS 12) predates the
    /// latter's availability.
    private let dbLock = NSLock()
    private var db: Connection?

    init(path: String, readonly: Bool = false) {
        self.path = path
        self.readonly = readonly
    }

    /// throws ZcashError.simpleConnectionProvider
    func connection() throws -> Connection {
        dbLock.lock()
        defer { dbLock.unlock() }

        if let conn = db {
            return conn
        }
        do {
            let conn = try Connection(path, readonly: readonly)
            conn.busyTimeout = Self.busyTimeoutSeconds
            db = conn
            return conn
        } catch {
            throw ZcashError.simpleConnectionProvider(error)
        }
    }

    /// throws ZcashError.simpleConnectionProvider
    func debugConnection() throws -> Connection {
        do {
            let conn = try Connection(path, readonly: true)
            conn.busyTimeout = Self.busyTimeoutSeconds
            try addDebugFunctions(conn: conn)
            return conn
        } catch {
            throw ZcashError.simpleConnectionProvider(error)
        }
    }

    func close() {
        dbLock.lock()
        defer { dbLock.unlock() }
        db = nil
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
