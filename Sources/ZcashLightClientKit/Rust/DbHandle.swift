//
//  DbHandle.swift
//  ZcashLightClientKit
//
//  Created by Claude Code on 2026-01-27.
//  Copyright (c) Electric Coin Company. All rights reserved.
//

import Foundation
import libzcashlc

/// A wrapper around the Rust wallet database handle that manages the lifecycle of
/// a persistent database connection.
///
/// This class holds a persistent database connection that can be reused across
/// multiple FFI calls, reducing connection overhead during wallet sync operations.
///
/// Usage:
/// ```swift
/// let walletDbHandle = WalletDbHandle(dbData: dbDataURL, networkType: .mainnet)
/// try await walletDbHandle.open()
/// // Use walletDbHandle.resolveHandle() in FFI calls
/// // walletDbHandle.close() is called automatically in deinit
/// ```
@DBActor
final class WalletDbHandle: Sendable {
    /// The opaque pointer to the Rust wallet database handle.
    /// Marked as `nonisolated(unsafe)` because:
    /// 1. All mutations happen only on @DBActor (open/close)
    /// 2. Read access through resolveHandle() is also on @DBActor
    /// 3. The deinit is safe because DBActor serializes access
    private nonisolated(unsafe) var handle: OpaquePointer?

    /// Path to the wallet database.
    private let dbDataPath: URL

    /// The network type (mainnet or testnet).
    private let networkType: NetworkType

    /// Creates a new WalletDbHandle instance without opening the database.
    ///
    /// - Parameters:
    ///   - dbData: URL pointing to the wallet database file.
    ///   - networkType: The network type (mainnet or testnet).
    nonisolated init(dbData: URL, networkType: NetworkType) {
        self.dbDataPath = dbData
        self.networkType = networkType
        self.handle = nil
    }

    deinit {
        // Note: deinit cannot be @DBActor, but since we're only reading/nulling
        // the handle and the Rust free function is safe to call from any thread,
        // this should be fine in practice. The DBActor serialization ensures
        // that no other code is actively using the handle during deinit.
        if let existingHandle = handle {
            zcashlc_free_wallet_db_handle(existingHandle)
            handle = nil
        }
    }

    /// Opens the database connection.
    ///
    /// This method must be called before the handle can be used in FFI calls.
    /// If the handle is already open, this method does nothing.
    ///
    /// - Throws: `ZcashError.rustOpenDb` if the database cannot be opened.
    func open() throws {
        guard handle == nil else { return }

        let dbData = dbDataPath.osStr()

        let newHandle = zcashlc_open_wallet_db(
            dbData.0,
            dbData.1,
            networkType.networkId
        )

        guard let newHandle else {
            throw ZcashError.rustOpenDb(lastErrorMessage(fallback: "`openWalletDb` failed with unknown error"))
        }

        handle = newHandle
    }

    /// Closes the database connection.
    ///
    /// After calling this method, the handle can be reopened by calling `open()`.
    /// This is automatically called in deinit, so manual calls are typically unnecessary
    /// unless you need to explicitly release database resources.
    func close() {
        if let existingHandle = handle {
            zcashlc_free_wallet_db_handle(existingHandle)
            handle = nil
        }
    }

    /// Returns the raw database handle pointer for use in FFI calls.
    ///
    /// - Returns: The opaque pointer to the Rust wallet database handle.
    /// - Throws: `ZcashError.rustOpenDb` if the handle has not been opened.
    func resolveHandle() throws -> OpaquePointer {
        guard let existingHandle = handle else {
            throw ZcashError.rustOpenDb("Wallet database handle has not been opened")
        }
        return existingHandle
    }

    /// Whether the database handle is currently open.
    var isOpen: Bool {
        handle != nil
    }
}

/// A wrapper around the Rust filesystem block database handle that manages the lifecycle of
/// a persistent database connection.
///
/// This class holds a persistent database connection that can be reused across
/// multiple FFI calls, reducing connection overhead during wallet sync operations.
///
/// Usage:
/// ```swift
/// let fsBlockDbHandle = FsBlockDbHandle(fsBlockDbRoot: cacheURL)
/// try await fsBlockDbHandle.open()
/// // Use fsBlockDbHandle.resolveHandle() in FFI calls
/// // fsBlockDbHandle.close() is called automatically in deinit
/// ```
@DBActor
final class FsBlockDbHandle: Sendable {
    /// The opaque pointer to the Rust filesystem block database handle.
    /// Marked as `nonisolated(unsafe)` because:
    /// 1. All mutations happen only on @DBActor (open/close)
    /// 2. Read access through resolveHandle() is also on @DBActor
    /// 3. The deinit is safe because DBActor serializes access
    private nonisolated(unsafe) var handle: OpaquePointer?

    /// Path to the block cache database root directory.
    private let fsBlockDbRootPath: URL

    /// Creates a new FsBlockDbHandle instance without opening the database.
    ///
    /// - Parameters:
    ///   - fsBlockDbRoot: URL pointing to the filesystem root directory where the block cache is stored.
    nonisolated init(fsBlockDbRoot: URL) {
        self.fsBlockDbRootPath = fsBlockDbRoot
        self.handle = nil
    }

    deinit {
        // Note: deinit cannot be @DBActor, but since we're only reading/nulling
        // the handle and the Rust free function is safe to call from any thread,
        // this should be fine in practice. The DBActor serialization ensures
        // that no other code is actively using the handle during deinit.
        if let existingHandle = handle {
            zcashlc_free_fs_block_db_handle(existingHandle)
            handle = nil
        }
    }

    /// Opens the database connection.
    ///
    /// This method must be called before the handle can be used in FFI calls.
    /// If the handle is already open, this method does nothing.
    ///
    /// - Throws: `ZcashError.rustOpenDb` if the database cannot be opened.
    func open() throws {
        guard handle == nil else { return }

        let fsBlockDbRoot = fsBlockDbRootPath.osPathStr()

        let newHandle = zcashlc_open_fs_block_db(
            fsBlockDbRoot.0,
            fsBlockDbRoot.1
        )

        guard let newHandle else {
            throw ZcashError.rustOpenDb(lastErrorMessage(fallback: "`openFsBlockDb` failed with unknown error"))
        }

        handle = newHandle
    }

    /// Closes the database connection.
    ///
    /// After calling this method, the handle can be reopened by calling `open()`.
    /// This is automatically called in deinit, so manual calls are typically unnecessary
    /// unless you need to explicitly release database resources.
    func close() {
        if let existingHandle = handle {
            zcashlc_free_fs_block_db_handle(existingHandle)
            handle = nil
        }
    }

    /// Returns the raw database handle pointer for use in FFI calls.
    ///
    /// - Returns: The opaque pointer to the Rust filesystem block database handle.
    /// - Throws: `ZcashError.rustOpenDb` if the handle has not been opened.
    func resolveHandle() throws -> OpaquePointer {
        guard let existingHandle = handle else {
            throw ZcashError.rustOpenDb("Block database handle has not been opened")
        }
        return existingHandle
    }

    /// Whether the database handle is currently open.
    var isOpen: Bool {
        handle != nil
    }
}
