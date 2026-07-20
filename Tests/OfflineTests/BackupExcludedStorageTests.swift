//
//  BackupExcludedStorageTests.swift
//  ZcashLightClientKitTests
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

/// Direct coverage of the shared provisioning helper (finding 15); `MigrationLogicTests`'
/// `testGateInitExcludesItsStorageDirectoryFromBackup` covers the `MigrationSyncGate` consumer side.
final class BackupExcludedStorageTests: ZcashTestCase {
    func testProvisionCreatesTheDirectoryAndExcludesItFromBackup() throws {
        let directory = testGeneralStorageDirectory.appendingPathComponent("nested/storage", isDirectory: true)
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory.path))

        try BackupExcludedStorage.provision(directory: directory)

        var isDirectory: ObjCBool = false
        XCTAssertTrue(FileManager.default.fileExists(atPath: directory.path, isDirectory: &isDirectory))
        XCTAssertTrue(isDirectory.boolValue)

        let resourceValues = try directory.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(resourceValues.isExcludedFromBackup, true)
    }

    /// The upgrade scenario finding 15 cares about: a directory that already exists (e.g. created by
    /// an older SDK version, before this helper existed, or by a sibling collaborator that
    /// provisioned it first) must still get excluded when provisioned again -- provisioning is
    /// unconditional, not gated on "did I just create this directory".
    func testProvisionReExcludesAPreExistingDirectoryFromBackup() throws {
        let directory = testGeneralStorageDirectory!
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let before = try directory.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertNotEqual(before.isExcludedFromBackup, true, "precondition: the directory must not already be excluded")

        try BackupExcludedStorage.provision(directory: directory)

        let after = try directory.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(after.isExcludedFromBackup, true)
    }
}
