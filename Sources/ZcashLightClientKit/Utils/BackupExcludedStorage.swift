//
//  BackupExcludedStorage.swift
//  ZcashLightClientKit
//

import Foundation

/// Shared directory provisioning for the SDK's general-storage subdirectories: ensures a directory
/// exists and is excluded from iCloud/iTunes backup.
///
/// Extracted from, and mirrors exactly, ``SubmitPlanStore/connection()``'s directory handling --
/// that type's own inline copy is intentionally left untouched by this extraction (see the note
/// below); this is the shared home both it and ``MigrationSyncGate`` can depend on.
///
/// - Note: `SubmitPlanStore` is not yet migrated onto this helper. Its `connection()` method
///   provisions the exact same general-storage directory with the exact same two calls this helper
///   makes, so switching it over is a plausible follow-up once both call sites have proven identical
///   in practice -- out of scope here to keep this change to the one collaborator (`MigrationSyncGate`)
///   that was missing the backup exclusion (finding 15).
enum BackupExcludedStorage {
    /// Ensures `directory` exists (creating intermediate directories as needed) and is excluded from
    /// backup.
    ///
    /// Unconditional, not gated on whether `directory` already existed: a directory created by an
    /// older SDK version (before this exclusion existed), or by another collaborator that provisioned
    /// it first, must still get excluded the next time something provisions it. Both
    /// `FileManager.createDirectory` (with `withIntermediateDirectories: true`) and
    /// `URL.setResourceValues` are safe/idempotent to call on a directory that already has the
    /// property set.
    ///
    /// - Throws: whatever `FileManager.createDirectory` or `URL.setResourceValues` throw.
    static func provision(directory: URL) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        var mutableDirectoryURL = directory
        try mutableDirectoryURL.setResourceValues(resourceValues)
    }
}
