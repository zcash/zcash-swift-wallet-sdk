//
//  DerivationTool.swift
//  Pods
//
//  Created by Francisco Gindre on 10/8/20.
//

import Combine
import Foundation

public protocol KeyValidation {
    func isValidUnifiedFullViewingKey(_ ufvk: String) -> Bool
    func isValidUnifiedIncomingViewingKey(_ uivk: String) -> Bool
    func isValidTransparentAddress(_ tAddress: String) -> Bool
    func isValidSaplingAddress(_ zAddress: String) -> Bool
    func isValidSaplingExtendedSpendingKey(_ extsk: String) -> Bool
    func isValidUnifiedAddress(_ unifiedAddress: String) -> Bool
}

public protocol KeyDeriving {
    /// Derives and returns a UnifiedAddress from a UnifiedFullViewingKey
    /// - Parameter ufvk: UTF-8 encoded String containing a valid UFVK
    /// - Returns: the corresponding default `UnifiedAddress`
    func deriveUnifiedAddressFrom(ufvk: String) throws -> UnifiedAddress
    
    /// Given the seed bytes and ZIP 32 account index, return the corresponding UnifiedSpendingKey.
    /// - Parameter seed: `[Uint8]` seed bytes
    /// - Parameter accountIndex: the ZIP 32 index of the account
    /// - Throws:
    ///     - some `ZcashError.rust*` error if the derivation fails.
    /// - Returns a `UnifiedSpendingKey`
    func deriveUnifiedSpendingKey(seed: [UInt8], accountIndex: Zip32AccountIndex) throws -> UnifiedSpendingKey

    /// Given a spending key, return the associated viewing key.
    /// - Parameter spendingKey: the `UnifiedSpendingKey` from which to derive the `UnifiedFullViewingKey` from.
    /// - Throws: some `ZcashError.rust*` error if the derivation fails.
    /// - Returns: the viewing key that corresponds to the spending key.
    func deriveUnifiedFullViewingKey(from spendingKey: UnifiedSpendingKey) throws -> UnifiedFullViewingKey

    /// Extracts the `SaplingAddress` from the given `UnifiedAddress`
    /// - Parameter address: the `UnifiedAddress`
    /// - Throws: some `ZcashError.rust*` error if the derivation fails.
    func saplingReceiver(from unifiedAddress: UnifiedAddress) throws -> SaplingAddress

    /// Extracts the `TransparentAddress` from the given `UnifiedAddress`
    /// - Parameter address: the `UnifiedAddress`
    /// - Throws: some `ZcashError.rust*` error if the derivation fails.
    func transparentReceiver(from unifiedAddress: UnifiedAddress) throws -> TransparentAddress

    /// Extracts the `UnifiedAddress.ReceiverTypecodes` from the given `UnifiedAddress`
    /// - Throws: some `ZcashError.rust*` error if the derivation fails.
    /// - Parameter address: the `UnifiedAddress`
    func receiverTypecodesFromUnifiedAddress(_ address: UnifiedAddress) throws -> [UnifiedAddress.ReceiverTypecodes]

    static func getAddressMetadata(_ addr: String) -> AddressMetadata?

    /// Derives and returns a ZIP 32 Arbitrary Key from the given seed at the "wallet level", i.e.
    /// directly from the seed with no ZIP 32 path applied.
    ///
    /// The resulting key will be the same across all networks (Zcash mainnet, Zcash testnet,
    /// OtherCoin mainnet, and so on). You can think of it as a context-specific seed fingerprint
    /// that can be used as (static) key material.
    ///
    /// - Parameter contextString: a globally-unique non-empty sequence of at most 252 bytes that identifies the desired context.
    /// - Parameter seed: `[Uint8]` seed bytes
    /// - Throws:
    ///     - some `ZcashError.rust*` error if the derivation fails.
    /// - Returns a `[Uint8]`
    static func deriveArbitraryWalletKey(contextString: [UInt8], seed: [UInt8]) throws -> [UInt8]

    /// Derives and returns a ZIP 32 Arbitrary Key from the given seed at the account level.
    ///
    /// - Parameter contextString: a globally-unique non-empty sequence of at most 252 bytes that identifies the desired context.
    /// - Parameter seed: `[Uint8]` seed bytes
    /// - Parameter accountIndex: the ZIP 32 index of the account
    /// - Throws:
    ///     - some `ZcashError.rust*` error if the derivation fails.
    /// - Returns a `[Uint8]`
    func deriveArbitraryAccountKey(contextString: [UInt8], seed: [UInt8], accountIndex: Zip32AccountIndex) throws -> [UInt8]
}

public class DerivationTool: KeyDeriving {
    let backend: ZcashKeyDerivationBackendWelding
    
    public init(networkType: NetworkType) {
        self.backend = ZcashKeyDerivationBackend(networkType: networkType)
    }

    public func saplingReceiver(from unifiedAddress: UnifiedAddress) throws -> SaplingAddress {
        try backend.getSaplingReceiver(for: unifiedAddress)
    }

    public func transparentReceiver(from unifiedAddress: UnifiedAddress) throws -> TransparentAddress {
        try backend.getTransparentReceiver(for: unifiedAddress)
    }

    public static func getAddressMetadata(_ addr: String) -> AddressMetadata? {
        ZcashKeyDerivationBackend.getAddressMetadata(addr)
    }

    public func deriveUnifiedAddressFrom(ufvk: String) throws -> UnifiedAddress {
        try backend.deriveUnifiedAddressFrom(ufvk: ufvk)
    }
    
    /// Given a spending key, return the associated viewing key.
    /// - Parameter spendingKey: the `UnifiedSpendingKey` from which to derive the `UnifiedFullViewingKey` from.
    /// - Returns: the viewing key that corresponds to the spending key.
    public func deriveUnifiedFullViewingKey(from spendingKey: UnifiedSpendingKey) throws -> UnifiedFullViewingKey {
        try backend.deriveUnifiedFullViewingKey(from: spendingKey)
    }

    /// Given a seed and a number of accounts, return the associated spending keys.
    /// - Parameter seed: the seed from which to derive spending keys.
    /// - Parameter accountIndex: the ZIP 32 index of the account
    /// - Returns: the spending keys that correspond to the seed, formatted as Strings.
    public func deriveUnifiedSpendingKey(seed: [UInt8], accountIndex: Zip32AccountIndex) throws -> UnifiedSpendingKey {
        try backend.deriveUnifiedSpendingKey(from: seed, accountIndex: accountIndex)
    }

    public func receiverTypecodesFromUnifiedAddress(_ address: UnifiedAddress) throws -> [UnifiedAddress.ReceiverTypecodes] {
        try backend.receiverTypecodesOnUnifiedAddress(address.stringEncoded)
            .map { UnifiedAddress.ReceiverTypecodes(typecode: $0) }
    }

    /// Derives and returns a ZIP 32 Arbitrary Key from the given seed at the "wallet level", i.e.
    /// directly from the seed with no ZIP 32 path applied.
    ///
    /// The resulting key will be the same across all networks (Zcash mainnet, Zcash testnet,
    /// OtherCoin mainnet, and so on). You can think of it as a context-specific seed fingerprint
    /// that can be used as (static) key material.
    ///
    /// - Parameter contextString: a globally-unique non-empty sequence of at most 252 bytes that identifies the desired context.
    /// - Parameter seed: `[Uint8]` seed bytes
    /// - Throws:
    ///     - some `ZcashError.rust*` error if the derivation fails.
    /// - Returns a `[Uint8]`
    public static func deriveArbitraryWalletKey(contextString: [UInt8], seed: [UInt8]) throws -> [UInt8] {
        try ZcashKeyDerivationBackend.deriveArbitraryWalletKey(contextString: contextString, from: seed)
    }

    /// Derives and returns a ZIP 32 Arbitrary Key from the given seed at the account level.
    ///
    /// - Parameter contextString: a globally-unique non-empty sequence of at most 252 bytes that identifies the desired context.
    /// - Parameter seed: `[Uint8]` seed bytes
    /// - Parameter accountIndex: the ZIP 32 index of the account
    /// - Throws:
    ///     - some `ZcashError.rust*` error if the derivation fails.
    /// - Returns a `[Uint8]`
    public func deriveArbitraryAccountKey(contextString: [UInt8], seed: [UInt8], accountIndex: Zip32AccountIndex) throws -> [UInt8] {
        try backend.deriveArbitraryAccountKey(contextString: contextString, from: seed, accountIndex: accountIndex)
    }
}

public struct AddressMetadata {
    let networkType: NetworkType
    let addressType: AddressType

    public init(network: NetworkType, addrType: AddressType) {
        self.networkType = network
        self.addressType = addrType
    }
}

extension DerivationTool: KeyValidation {
    public func isValidUnifiedFullViewingKey(_ ufvk: String) -> Bool {
        backend.isValidUnifiedFullViewingKey(ufvk)
    }

    public func isValidUnifiedIncomingViewingKey(_ uivk: String) -> Bool {
        backend.isValidUnifiedIncomingViewingKey(uivk)
    }

    public func isValidUnifiedAddress(_ unifiedAddress: String) -> Bool {
        DerivationTool.getAddressMetadata(unifiedAddress).map {
            $0.networkType == backend.networkType && $0.addressType == AddressType.unified
        } ?? false
    }

    public func isValidTransparentAddress(_ tAddress: String) -> Bool {
        DerivationTool.getAddressMetadata(tAddress).map {
            $0.networkType == backend.networkType && (
                $0.addressType == AddressType.p2pkh || $0.addressType == AddressType.p2sh
            )
        } ?? false
    }

    public func isValidSaplingAddress(_ zAddress: String) -> Bool {
        DerivationTool.getAddressMetadata(zAddress).map {
            $0.networkType == backend.networkType && $0.addressType == AddressType.sapling
        } ?? false
    }

    public func isValidTexAddress(_ texAddress: String) -> Bool {
        DerivationTool.getAddressMetadata(texAddress).map {
            $0.networkType == backend.networkType && $0.addressType == AddressType.tex
        } ?? false
    }

    public func isValidSaplingExtendedSpendingKey(_ extsk: String) -> Bool {
        backend.isValidSaplingExtendedSpendingKey(extsk)
    }
}

extension TransparentAddress {
    /// This constructor is for internal use for Strings encodings that are assumed to be
    /// already validated by another function. only for internal use. Unless you are
    /// constructing an address from a primitive function of the FFI, you probably
    /// shouldn't be using this.
    init(validatedEncoding: String) {
        self.encoding = validatedEncoding
    }
}

extension SaplingAddress {
    /// This constructor is for internal use for Strings encodings that are assumed to be
    /// already validated by another function. only for internal use. Unless you are
    /// constructing an address from a primitive function of the FFI, you probably
    /// shouldn't be using this.
    init(validatedEncoding: String) {
        self.encoding = validatedEncoding
    }
}

extension UnifiedAddress {
    /// This constructor is for internal use for Strings encodings that are assumed to be
    /// already validated by another function. only for internal use. Unless you are
    /// constructing an address from a primitive function of the FFI, you probably
    /// shouldn't be using this..
    init(validatedEncoding: String, networkType: NetworkType) {
        self.encoding = validatedEncoding
        self.networkType = networkType
    }
}

extension TexAddress {
    /// This constructor is for internal use for Strings encodings that are assumed to be
    /// already validated by another function. only for internal use. Unless you are
    /// constructing an address from a primitive function of the FFI, you probably
    /// shouldn't be using this.
    init(validatedEncoding: String) {
        self.encoding = validatedEncoding
    }
}

extension UnifiedFullViewingKey {
    /// This constructor is for internal use for Strings encodings that are assumed to be
    /// already validated by another function. only for internal use. Unless you are
    /// constructing an address from a primitive function of the FFI, you probably
    /// shouldn't be using this.
    init(validatedEncoding: String) {
        self.encoding = validatedEncoding
    }
}

extension UnifiedIncomingViewingKey {
    /// This constructor is for internal use for Strings encodings that are assumed to be
    /// already validated by another function. only for internal use. Unless you are
    /// constructing an address from a primitive function of the FFI, you probably
    /// shouldn't be using this.
    init(validatedEncoding: String) {
        self.encoding = validatedEncoding
    }
}

extension SaplingExtendedFullViewingKey {
    /// This constructor is for internal use for Strings encodings that are assumed to be
    /// already validated by another function. only for internal use. Unless you are
    /// constructing an address from a primitive function of the FFI, you probably
    /// shouldn't be using this.
    init(validatedEncoding: String) {
        self.encoding = validatedEncoding
    }
}

extension SaplingExtendedSpendingKey {
    /// This constructor is for internal use for Strings encodings that are assumed to be
    /// already validated by another function. only for internal use. Unless you are
    /// constructing an address from a primitive function of the FFI, you probably
    /// shouldn't be using this.
    init(validatedEncoding: String) {
        self.encoding = validatedEncoding
    }
}

public extension UnifiedSpendingKey {
    func map<T>(_ transform: (UnifiedSpendingKey) throws -> T) rethrows -> T {
        try transform(self)
    }
}

public extension UnifiedAddress {
    /// Extracts the sapling receiver from this UA if available
    /// - Returns: an `Optional<SaplingAddress>`
    func saplingReceiver() throws -> SaplingAddress {
        try DerivationTool(networkType: networkType).saplingReceiver(from: self)
    }

    /// Extracts the transparent receiver from this UA if available
    /// - Returns: an `Optional<TransparentAddress>`
    func transparentReceiver() throws -> TransparentAddress {
        try DerivationTool(networkType: networkType).transparentReceiver(from: self)
    }
}
