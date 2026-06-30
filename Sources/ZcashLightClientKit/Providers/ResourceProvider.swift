//
//  ResourceProvider.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 19/09/2019.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import Foundation

public enum ResourceProviderError: Error {
    case unavailableResource
}
public protocol ResourceProvider {
    var dataDbURL: URL { get }
    var fsCacheURL: URL { get }
}
/**
Convenience provider for a data db and cache db resources.
*/
public struct DefaultResourceProvider: ResourceProvider {
    let network: ZcashNetwork

    public var dataDbURL: URL {
        let constants = network.constants
        do {
            let url = try FileManager.default.url(for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
            return url.appendingPathComponent(constants.defaultDataDbName)
        } catch {
            return URL(fileURLWithPath: "file://\(constants.defaultDataDbName)")
        }
    }

    public var torDirURL: URL {
        let constants = network.constants
        do {
            let url = try FileManager.default.url(for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
            return url.appendingPathComponent(constants.defaultTorDirName)
        } catch {
            return URL(fileURLWithPath: "file://\(constants.defaultTorDirName)")
        }
    }

    public var fsCacheURL: URL {
        let constants = network.constants
        do {
            let path = try FileManager.default.url(for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
            return path.appendingPathComponent(constants.defaultFsBlockDbRootName)
        } catch {
            return URL(fileURLWithPath: "file://\(constants.defaultFsBlockDbRootName)")
        }
    }

    public var spendParamsURL: URL {
        do {
            let path = try FileManager.default.url(for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
            return path.appendingPathComponent(ZcashSDK.spendParamFilename)
        } catch {
            return URL(fileURLWithPath: "file://\(ZcashSDK.spendParamFilename)")
        }
    }

    public var outputParamsURL: URL {
        do {
            let path = try FileManager.default.url(for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
            return path.appendingPathComponent(ZcashSDK.outputParamFilename)
        } catch {
            return URL(fileURLWithPath: "file://\(ZcashSDK.outputParamFilename)")
        }
    }

    init(network: ZcashNetwork) {
        self.network = network
    }
}
