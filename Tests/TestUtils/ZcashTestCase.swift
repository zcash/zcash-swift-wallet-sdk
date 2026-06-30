//
//  ZcashTestCase.swift
//
//
//  Created by Michal Fousek on 01.05.2023.
//

import Foundation
@testable import ZcashLightClientKit
import XCTest

class ZcashTestCase: XCTestCase {
    var mockContainer: DIContainer!
    var testTempDirectory: URL!
    var testGeneralStorageDirectory: URL!

    // MARK: - DI

    private func createMockContainer() {
        guard mockContainer == nil else { return }
        mockContainer = DIContainer()
        mockContainer.isTestEnvironment = true
    }

    private func destroyMockContainer() {
        mockContainer = nil
    }

    // MARK: - Paths

    private func create(path: URL!) throws {
        try FileManager.default.createDirectory(at: path, withIntermediateDirectories: true)
    }

    private func delete(path: URL!) throws {
        if path != nil && FileManager.default.fileExists(atPath: path.path) {
            try FileManager.default.removeItem(at: path)
        }
    }

    private func createPaths() throws {
        if testTempDirectory == nil {
            testTempDirectory = Environment.uniqueTestTempDirectory
            try delete(path: testTempDirectory)
            try create(path: testTempDirectory)
        }

        if testGeneralStorageDirectory == nil {
            testGeneralStorageDirectory = Environment.uniqueGeneralStorageDirectory
            try delete(path: testGeneralStorageDirectory)
            try create(path: testGeneralStorageDirectory)
        }
    }

    private func deletePaths() throws {
        try delete(path: testTempDirectory)
        testTempDirectory = nil
        try delete(path: testGeneralStorageDirectory)
        testGeneralStorageDirectory = nil
    }

    // MARK: - XCTestCase

    override func setUp() async throws {
        try await super.setUp()
        createMockContainer()
        try createPaths()
    }

    override func setUp() {
        super.setUp()
        createMockContainer()
        try? createPaths()
    }

    override func setUpWithError() throws {
        try super.setUpWithError()
        createMockContainer()
        try createPaths()
    }

    override func tearDown() async throws {
        try await super.tearDown()
        destroyMockContainer()
        try deletePaths()
    }

    override func tearDown() {
        super.tearDown()
        destroyMockContainer()
        try? deletePaths()
    }

    override func tearDownWithError() throws {
        try super.tearDownWithError()
        destroyMockContainer()
        try deletePaths()
    }
}
