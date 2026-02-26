//
//  Eip681TransactionRequest.swift
//  ZcashLightClientKit
//

import Foundation

/// The parsed result of an EIP-681 URI.
///
/// EIP-681 defines a standard URI format for Ethereum transaction requests,
/// commonly used in QR codes and deep links. This enum represents the three
/// recognized forms: native ETH transfers, ERC-20 token transfers, and
/// unrecognised (but syntactically valid) requests.
public enum Eip681TransactionRequest: Equatable {
    /// A native ETH/chain token transfer (no function call).
    case native(Eip681NativeRequest)
    /// An ERC-20 token transfer via `transfer(address,uint256)`.
    case erc20(Eip681Erc20Request)
    /// A valid EIP-681 request that is not a recognized transfer pattern.
    case unrecognised
}

/// A native ETH/chain token transfer extracted from a parsed EIP-681 request.
public struct Eip681NativeRequest: Equatable {
    /// The URI schema prefix (e.g. "ethereum").
    public let schemaPrefix: String
    /// Whether the URI uses the "pay-" prefix after the schema (e.g. "ethereum:pay-").
    public let hasPay: Bool
    /// The chain ID, if specified in the URI.
    public let chainId: UInt64?
    /// The recipient address (ERC-55 checksummed hex or ENS name).
    public let recipientAddress: String
    /// The transfer value as a `0x`-prefixed hex string, or nil if not specified.
    public let valueHex: String?
    /// The gas limit as a `0x`-prefixed hex string, or nil if not specified.
    public let gasLimitHex: String?
    /// The gas price as a `0x`-prefixed hex string, or nil if not specified.
    public let gasPriceHex: String?

    public init(
        schemaPrefix: String,
        hasPay: Bool,
        chainId: UInt64?,
        recipientAddress: String,
        valueHex: String?,
        gasLimitHex: String?,
        gasPriceHex: String?
    ) {
        self.schemaPrefix = schemaPrefix
        self.hasPay = hasPay
        self.chainId = chainId
        self.recipientAddress = recipientAddress
        self.valueHex = valueHex
        self.gasLimitHex = gasLimitHex
        self.gasPriceHex = gasPriceHex
    }
}

/// An ERC-20 token transfer extracted from a parsed EIP-681 request.
public struct Eip681Erc20Request: Equatable {
    /// The URI schema prefix (e.g. "ethereum").
    public let schemaPrefix: String
    /// Whether the URI uses the "pay-" prefix after the schema (e.g. "ethereum:pay-").
    public let hasPay: Bool
    /// The chain ID, if specified in the URI.
    public let chainId: UInt64?
    /// The ERC-20 token contract address (ERC-55 checksummed hex or ENS name).
    public let tokenContractAddress: String
    /// The transfer recipient address (ERC-55 checksummed hex or ENS name).
    public let recipientAddress: String
    /// The transfer value in atomic units as a `0x`-prefixed hex string.
    public let valueHex: String

    public init(
        schemaPrefix: String,
        hasPay: Bool,
        chainId: UInt64?,
        tokenContractAddress: String,
        recipientAddress: String,
        valueHex: String
    ) {
        self.schemaPrefix = schemaPrefix
        self.hasPay = hasPay
        self.chainId = chainId
        self.tokenContractAddress = tokenContractAddress
        self.recipientAddress = recipientAddress
        self.valueHex = valueHex
    }
}
