//
//  ConnectorProvider.swift
//
//
//  Created by Francisco Gindre on 1/12/23.
//
import SQLite

protocol ConnectionProvider {
    func connection() throws -> Connection
    /// Opens a debugging connection to the database.
    ///
    /// The connection must always be opened in read-only mode, and should contain the following
    /// additional custom SQLite functions:
    /// - `txid(Blob) -> String`: converts a transaction ID from its byte form to the user-facing
    ///   hex-encoded-reverse-bytes string.
    /// - `memo(Blob?) -> String?`: prints the given blob as a string if it is a text memo, and as
    ///   hex-encoded bytes otherwise.
    func debugConnection() throws -> Connection
    func close()
}
