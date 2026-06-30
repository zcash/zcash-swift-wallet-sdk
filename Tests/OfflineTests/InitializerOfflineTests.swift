//
//  InitializerOfflineTests.swift
//
//
//  Created by Michal Fousek on 24.03.2023.
//

import Foundation
@testable import TestUtils
import XCTest
@testable import ZcashLightClientKit

class InitializerOfflineTests: XCTestCase {
    let validFileURL = URL(fileURLWithPath: "/some/valid/path/to.file")
    let validDirectoryURL = URL(fileURLWithPath: "/some/valid/path/to/directory")
    let invalidPathURL = URL(string: "https://whatever")!

    // MARK: - Utils

    private func makeInitializer(
        fsBlockDbRoot: URL,
        dataDbURL: URL,
        torDirURL: URL,
        generalStorageURL: URL,
        spendParamsURL: URL,
        outputParamsURL: URL,
        alias: ZcashSynchronizerAlias
    ) -> Initializer {
        return Initializer(
            cacheDbURL: nil,
            fsBlockDbRoot: fsBlockDbRoot,
            generalStorageURL: generalStorageURL,
            dataDbURL: dataDbURL,
            torDirURL: torDirURL,
            endpoint: LightWalletEndpointBuilder.default,
            network: ZcashNetworkBuilder.network(for: .testnet),
            spendParamsURL: spendParamsURL,
            outputParamsURL: outputParamsURL,
            saplingParamsSourceURL: .default,
            alias: alias,
            loggingPolicy: .default(.debug),
            isTorEnabled: false,
            isExchangeRateEnabled: false
        )
    }

    private func update(url: URL, with alias: ZcashSynchronizerAlias) -> URL {
        guard alias != .default else { return url }
        let lastPathComponent = url.lastPathComponent
        guard !lastPathComponent.isEmpty else { return url }
        return url
            .deletingLastPathComponent()
            .appendingPathComponent("\(alias.description)_\(lastPathComponent)")
    }

    // MARK: - Tests

    private func genericTestForURLsParsingFailures(
        fsBlockDbRoot: URL,
        dataDbURL: URL,
        torDirURL: URL,
        generalStorageURL: URL,
        spendParamsURL: URL,
        outputParamsURL: URL,
        alias: ZcashSynchronizerAlias,
        function: String = #function
    ) {
        let initializer = makeInitializer(
            fsBlockDbRoot: fsBlockDbRoot,
            dataDbURL: dataDbURL,
            torDirURL: torDirURL,
            generalStorageURL: generalStorageURL,
            spendParamsURL: spendParamsURL,
            outputParamsURL: outputParamsURL,
            alias: alias
        )

        if let error = initializer.urlsParsingError, case let .initializerCantUpdateURLWithAlias(failedURL) = error {
            XCTAssertEqual(failedURL, invalidPathURL, "Failing \(function)")
        } else {
            XCTFail("URLs parsing error expected. Failing \(function)")
        }

        XCTAssertEqual(initializer.fsBlockDbRoot, fsBlockDbRoot, "Failing \(function)")
        XCTAssertEqual(initializer.dataDbURL, dataDbURL, "Failing \(function)")
        XCTAssertEqual(initializer.spendParamsURL, spendParamsURL, "Failing \(function)")
        XCTAssertEqual(initializer.outputParamsURL, outputParamsURL, "Failing \(function)")
    }

    func test__defaultAlias__validURLs__updatedURLsAreBackwardsCompatible() {
        let initializer = makeInitializer(
            fsBlockDbRoot: validDirectoryURL,
            dataDbURL: validFileURL,
            torDirURL: validDirectoryURL,
            generalStorageURL: validDirectoryURL,
            spendParamsURL: validFileURL,
            outputParamsURL: validFileURL,
            alias: .default
        )

        XCTAssertNil(initializer.urlsParsingError)
        XCTAssertEqual(initializer.fsBlockDbRoot, validDirectoryURL)
        XCTAssertEqual(initializer.dataDbURL, validFileURL)
        XCTAssertEqual(initializer.spendParamsURL, validFileURL)
        XCTAssertEqual(initializer.outputParamsURL, validFileURL)
    }

    func test__defaultAlias__invalidFsBlockDbRootURL__errorIsGenerated() {
        genericTestForURLsParsingFailures(
            fsBlockDbRoot: invalidPathURL,
            dataDbURL: validFileURL,
            torDirURL: validDirectoryURL,
            generalStorageURL: validDirectoryURL,
            spendParamsURL: validFileURL,
            outputParamsURL: validFileURL,
            alias: .default
        )
    }

    func test__defaultAlias__invalidDataDbURL__errorIsGenerated() {
        genericTestForURLsParsingFailures(
            fsBlockDbRoot: validDirectoryURL,
            dataDbURL: invalidPathURL,
            torDirURL: validDirectoryURL,
            generalStorageURL: validDirectoryURL,
            spendParamsURL: validFileURL,
            outputParamsURL: validFileURL,
            alias: .default
        )
    }

    func test__defaultAlias__invalidTorDirURL__errorIsGenerated() {
        genericTestForURLsParsingFailures(
            fsBlockDbRoot: validDirectoryURL,
            dataDbURL: validFileURL,
            torDirURL: invalidPathURL,
            generalStorageURL: validDirectoryURL,
            spendParamsURL: validFileURL,
            outputParamsURL: validFileURL,
            alias: .default
        )
    }

    func test__defaultAlias__invalidSpendParamsURL__errorIsGenerated() {
        genericTestForURLsParsingFailures(
            fsBlockDbRoot: validDirectoryURL,
            dataDbURL: validFileURL,
            torDirURL: validDirectoryURL,
            generalStorageURL: validDirectoryURL,
            spendParamsURL: invalidPathURL,
            outputParamsURL: validFileURL,
            alias: .default
        )
    }

    func test__defaultAlias__invalidOutputParamsURL__errorIsGenerated() {
        genericTestForURLsParsingFailures(
            fsBlockDbRoot: validDirectoryURL,
            dataDbURL: validFileURL,
            torDirURL: validDirectoryURL,
            generalStorageURL: validDirectoryURL,
            spendParamsURL: validFileURL,
            outputParamsURL: invalidPathURL,
            alias: .default
        )
    }

    func test__defaultAlias__invalidGeneralStorageURL__errorIsGenerated() {
        genericTestForURLsParsingFailures(
            fsBlockDbRoot: validDirectoryURL,
            dataDbURL: validFileURL,
            torDirURL: validDirectoryURL,
            generalStorageURL: invalidPathURL,
            spendParamsURL: validFileURL,
            outputParamsURL: validFileURL,
            alias: .default
        )
    }

    func test__customAlias__validURLs__updatedURLsAreAsExpected() {
        let alias: ZcashSynchronizerAlias = .custom("alias")
        let initializer = makeInitializer(
            fsBlockDbRoot: validDirectoryURL,
            dataDbURL: validFileURL,
            torDirURL: validDirectoryURL,
            generalStorageURL: validDirectoryURL,
            spendParamsURL: validFileURL,
            outputParamsURL: validFileURL,
            alias: alias
        )

        XCTAssertNil(initializer.urlsParsingError)
        XCTAssertEqual(initializer.fsBlockDbRoot, update(url: validDirectoryURL, with: alias))
        XCTAssertEqual(initializer.dataDbURL, update(url: validFileURL, with: alias))
        XCTAssertEqual(initializer.spendParamsURL, update(url: validFileURL, with: alias))
        XCTAssertEqual(initializer.outputParamsURL, update(url: validFileURL, with: alias))
    }

    func test__customAlias__invalidFsBlockDbRootURL__errorIsGenerated() {
        genericTestForURLsParsingFailures(
            fsBlockDbRoot: invalidPathURL,
            dataDbURL: validFileURL,
            torDirURL: validDirectoryURL,
            generalStorageURL: validDirectoryURL,
            spendParamsURL: validFileURL,
            outputParamsURL: validFileURL,
            alias: .custom("alias")
        )
    }

    func test__customAlias__invalidDataDbURL__errorIsGenerated() {
        genericTestForURLsParsingFailures(
            fsBlockDbRoot: validDirectoryURL,
            dataDbURL: invalidPathURL,
            torDirURL: validDirectoryURL,
            generalStorageURL: validDirectoryURL,
            spendParamsURL: validFileURL,
            outputParamsURL: validFileURL,
            alias: .custom("alias")
        )
    }

    func test__customAlias__invalidTorDirURL__errorIsGenerated() {
        genericTestForURLsParsingFailures(
            fsBlockDbRoot: validDirectoryURL,
            dataDbURL: validFileURL,
            torDirURL: invalidPathURL,
            generalStorageURL: validDirectoryURL,
            spendParamsURL: validFileURL,
            outputParamsURL: validFileURL,
            alias: .custom("alias")
        )
    }

    func test__customAlias__invalidSpendParamsURL__errorIsGenerated() {
        genericTestForURLsParsingFailures(
            fsBlockDbRoot: validDirectoryURL,
            dataDbURL: validFileURL,
            torDirURL: validDirectoryURL,
            generalStorageURL: validDirectoryURL,
            spendParamsURL: invalidPathURL,
            outputParamsURL: validFileURL,
            alias: .custom("alias")
        )
    }

    func test__customAlias__invalidOutputParamsURL__errorIsGenerated() {
        genericTestForURLsParsingFailures(
            fsBlockDbRoot: validDirectoryURL,
            dataDbURL: validFileURL,
            torDirURL: validDirectoryURL,
            generalStorageURL: validDirectoryURL,
            spendParamsURL: validFileURL,
            outputParamsURL: invalidPathURL,
            alias: .custom("alias")
        )
    }

    func test__customAlias__invalidGeneralStorageURL__errorIsGenerated() {
        genericTestForURLsParsingFailures(
            fsBlockDbRoot: validDirectoryURL,
            dataDbURL: validFileURL,
            torDirURL: validDirectoryURL,
            generalStorageURL: invalidPathURL,
            spendParamsURL: validFileURL,
            outputParamsURL: validFileURL,
            alias: .custom("alias")
        )
    }
}
