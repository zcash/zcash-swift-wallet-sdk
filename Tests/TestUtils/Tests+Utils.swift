//
//  Tests+Utils.swift
//  ZcashLightClientKitTests
//
//  Created by Francisco Gindre on 18/09/2019.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import Combine
import Foundation
import GRPC
import XCTest
import NIO
import NIOTransportServices
@testable import ZcashLightClientKit

enum Environment {
    static let lightwalletdKey = "LIGHTWALLETD_ADDRESS"
    static let seedPhrase = """
    still champion voice habit trend flight survey between bitter process artefact blind carbon truly provide dizzy crush flush breeze blouse charge \
    solid fish spread
    """

    // Seed bytes for `seedPhrase`.
    static var seedBytes: [UInt8] {
        let seedString = Data(base64Encoded: "9VDVOZZZOWWHpZtq1Ebridp3Qeux5C+HwiRR0g7Oi7HgnMs8Gfln83+/Q1NnvClcaSwM4ADFL1uZHxypEWlWXg==")!
        return [UInt8](seedString)
    }

    static let testRecipientAddress = "zs17mg40levjezevuhdp5pqrd52zere7r7vrjgdwn5sj4xsqtm20euwahv9anxmwr3y3kmwuz8k55a"

    static var uniqueTestTempDirectory: URL {
        URL(fileURLWithPath: NSString(string: NSTemporaryDirectory())
            .appendingPathComponent("tmp-\(Int.random(in: 0 ... .max))"))
    }

    static var uniqueGeneralStorageDirectory: URL {
        URL(fileURLWithPath: NSString(string: NSTemporaryDirectory())
            .appendingPathComponent("gens-\(Int.random(in: 0 ... .max))"))
    }
}

public enum Constants {
    static let address: String = ProcessInfo.processInfo.environment[Environment.lightwalletdKey] ?? "localhost"
}

enum LightWalletEndpointBuilder {
    static var `default`: LightWalletEndpoint {
        LightWalletEndpoint(address: Constants.address, port: 9067, secure: false)
    }

    static var publicTestnet: LightWalletEndpoint {
        LightWalletEndpoint(address: "testnet.zec.rocks", port: 443, secure: true)
    }

    static var eccTestnet: LightWalletEndpoint {
        LightWalletEndpoint(address: "lightwalletd.testnet.electriccoin.co", port: 9067, secure: true)
    }
}

class ChannelProvider {
    func channel(endpoint: LightWalletEndpoint = LightWalletEndpointBuilder.default, secure: Bool = false) -> GRPCChannel {
        let connectionBuilder = secure ?
        ClientConnection.usingPlatformAppropriateTLS(for: NIOTSEventLoopGroup(loopCount: 1, defaultQoS: .default)) :
        ClientConnection.insecure(group: NIOTSEventLoopGroup(loopCount: 1, defaultQoS: .default))

        let channel = connectionBuilder
            .withKeepalive(
                ClientConnectionKeepalive(
                    interval: .seconds(15),
                    timeout: .seconds(10)
                )
            )
            .connect(host: endpoint.host, port: endpoint.port)

        return channel
    }
}

enum MockDbInit {
    @discardableResult
    static func emptyFile(at path: String) -> Bool {
        FileManager.default.createFile(atPath: path, contents: Data("".utf8), attributes: nil)
    }

    static func destroy(at path: String) throws {
        try FileManager.default.removeItem(atPath: path)
    }
}

/// Root directory for ALL test-created wallet artifacts (databases, fs caches, tor dirs,
/// downloaded params). Deliberately NOT the user's real `~/Documents`: on macOS,
/// `.documentDirectory` resolves there, and the timestamped per-run files created by
/// `TestCoordinator` (`data_db_<ts>.db`, `fs_cache_<ts>`) were never cleaned up —
/// hundreds of them accumulated in the maintainer's Documents folder. The OS purges
/// `temporaryDirectory` periodically, so leaked per-run artifacts are self-cleaning.
func __documentsDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("ZcashSDKTests", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

func __dataDbURL() throws -> URL {
    try __documentsDirectory().appendingPathComponent("data.db", isDirectory: false)
}

func __torDirURL() throws -> URL {
    try __documentsDirectory().appendingPathComponent("tor", isDirectory: true)
}

func __spendParamsURL() throws -> URL {
    try __documentsDirectory().appendingPathComponent("sapling-spend.params")
}

func __outputParamsURL() throws -> URL {
    try __documentsDirectory().appendingPathComponent("sapling-output.params")
}

func copyParametersToDocuments() throws -> (spend: URL, output: URL) {
    let spendURL = try __documentsDirectory().appendingPathComponent("sapling-spend.params", isDirectory: false)
    let outputURL = try __documentsDirectory().appendingPathComponent("sapling-output.params", isDirectory: false)
    try FileManager.default.copyItem(at: try __spendParamsURL(), to: spendURL)
    try FileManager.default.copyItem(at: try __outputParamsURL(), to: outputURL)

    return (spendURL, outputURL)
}

func deleteParametersFromDocuments() throws {
    let documents = try __documentsDirectory()
    deleteParamsFrom(
        spend: documents.appendingPathComponent("sapling-spend.params"),
        output: documents.appendingPathComponent("sapling-output.params")
    )
}

func deleteParamsFrom(spend: URL, output: URL) {
    try? FileManager.default.removeItem(at: spend)
    try? FileManager.default.removeItem(at: output)
}

func parametersReady() -> Bool {
    guard
        let output = try? __outputParamsURL(),
        let spend = try? __spendParamsURL(),
        FileManager.default.isReadableFile(atPath: output.absoluteString),
        FileManager.default.isReadableFile(atPath: spend.absoluteString)
    else {
        return false
    }

    return true
}

extension ZcashRustBackend {
    static func makeForTests(
        dbData: URL = try! __dataDbURL(),
        fsBlockDbRoot: URL,
        spendParamsPath: URL = SaplingParamsSourceURL.default.spendParamFileURL,
        outputParamsPath: URL = SaplingParamsSourceURL.default.outputParamFileURL,
        networkType: NetworkType
    ) -> ZcashRustBackend {
        ZcashRustBackend(
            dbData: dbData,
            fsBlockDbRoot: fsBlockDbRoot,
            spendParamsPath: spendParamsPath,
            outputParamsPath: outputParamsPath,
            networkType: networkType,
            sdkFlags: SDKFlags(torEnabled: false, exchangeRateEnabled: false)
        )
    }
}

extension Zatoshi: @retroactive CustomDebugStringConvertible {
    public var debugDescription: String {
        "Zatoshi(\(self.amount))"
    }
}
