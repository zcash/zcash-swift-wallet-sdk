//
//  ZcashEip681Backend.swift
//  ZcashLightClientKit
//

import Foundation
import libzcashlc

struct ZcashEip681Backend {
    /// Parse an EIP-681 URI string into an ``Eip681TransactionRequest``.
    ///
    /// - Parameter input: A valid EIP-681 URI string (e.g. `"ethereum:0xAbC...?value=1e18"`).
    /// - Throws: ``ZcashError/rustEip681Parse(_:)`` if the input is not a valid EIP-681 URI.
    /// - Returns: An ``Eip681TransactionRequest`` representing the parsed URI.
    static func parseTransactionRequest(_ input: String) throws -> Eip681TransactionRequest {
        let requestPtr = zcashlc_eip681_parse_transaction_request(
            [CChar](input.utf8CString)
        )

        guard let requestPtr else {
            throw ZcashError.rustEip681Parse(
                lastErrorMessage(fallback: "`parseTransactionRequest` failed with unknown error")
            )
        }

        defer { zcashlc_free_eip681_transaction_request(requestPtr) }

        return try extractTransactionRequest(requestPtr)
    }

    /// Serialize an EIP-681 transaction request back to a URI string.
    ///
    /// This parses the input URI and then serializes it back, which normalizes the URI format.
    ///
    /// - Parameter input: A valid EIP-681 URI string.
    /// - Throws: ``ZcashError/rustEip681Parse(_:)`` if the input is not a valid EIP-681 URI.
    /// - Returns: The normalized URI string.
    static func transactionRequestToUri(_ input: String) throws -> String {
        let requestPtr = zcashlc_eip681_parse_transaction_request(
            [CChar](input.utf8CString)
        )

        guard let requestPtr else {
            throw ZcashError.rustEip681Parse(
                lastErrorMessage(fallback: "`transactionRequestToUri` failed with unknown error")
            )
        }

        defer { zcashlc_free_eip681_transaction_request(requestPtr) }

        let uriCStr = zcashlc_eip681_transaction_request_to_uri(requestPtr)

        guard let uriCStr else {
            throw ZcashError.rustEip681Parse(
                lastErrorMessage(fallback: "`transactionRequestToUri` serialization failed with unknown error")
            )
        }

        defer { zcashlc_string_free(uriCStr) }

        guard let uri = String(validatingUTF8: uriCStr) else {
            throw ZcashError.rustEip681Parse("URI serialization produced invalid UTF-8")
        }

        return uri
    }

    /// Construct a native ETH/chain token transfer request from individual parts.
    ///
    /// - Parameters:
    ///   - schemaPrefix: The URI schema prefix (e.g. "ethereum").
    ///   - hasPay: Whether to use the "pay-" prefix after the schema.
    ///   - chainId: The chain ID, or nil to omit.
    ///   - recipientAddress: The recipient address (ERC-55 checksummed hex).
    ///   - valueHex: The transfer value as a `0x`-prefixed hex string, or nil to omit.
    ///   - gasLimitHex: The gas limit as a `0x`-prefixed hex string, or nil to omit.
    ///   - gasPriceHex: The gas price as a `0x`-prefixed hex string, or nil to omit.
    /// - Throws: ``ZcashError/rustEip681Parse(_:)`` if the parts do not form a valid request.
    /// - Returns: An ``Eip681TransactionRequest`` representing the constructed request.
    static func createNativeTransactionRequest(
        schemaPrefix: String,
        hasPay: Bool,
        chainId: UInt64?,
        recipientAddress: String,
        valueHex: String?,
        gasLimitHex: String?,
        gasPriceHex: String?
    ) throws -> Eip681TransactionRequest {
        let hasChainId = chainId != nil
        let chainIdValue = chainId ?? 0

        let requestPtr = valueHex.flatMapToCString { valueCStr in
            gasLimitHex.flatMapToCString { gasLimitCStr in
                gasPriceHex.flatMapToCString { gasPriceCStr in
                    zcashlc_eip681_native_request_from_parts(
                        [CChar](schemaPrefix.utf8CString),
                        hasPay,
                        hasChainId,
                        chainIdValue,
                        [CChar](recipientAddress.utf8CString),
                        valueCStr,
                        gasLimitCStr,
                        gasPriceCStr
                    )
                }
            }
        }

        guard let requestPtr else {
            throw ZcashError.rustEip681Parse(
                lastErrorMessage(fallback: "`createNativeTransactionRequest` failed with unknown error")
            )
        }

        defer { zcashlc_free_eip681_transaction_request(requestPtr) }

        return try extractTransactionRequest(requestPtr)
    }

    /// Construct an ERC-20 token transfer request from individual parts.
    ///
    /// - Parameters:
    ///   - schemaPrefix: The URI schema prefix (e.g. "ethereum").
    ///   - hasPay: Whether to use the "pay-" prefix after the schema.
    ///   - chainId: The chain ID, or nil to omit.
    ///   - tokenContractAddress: The ERC-20 token contract address (ERC-55 checksummed hex).
    ///   - recipientAddress: The transfer recipient address (ERC-55 checksummed hex).
    ///   - valueHex: The transfer value as a `0x`-prefixed hex string.
    /// - Throws: ``ZcashError/rustEip681Parse(_:)`` if the parts do not form a valid request.
    /// - Returns: An ``Eip681TransactionRequest`` representing the constructed request.
    static func createErc20TransactionRequest(
        schemaPrefix: String,
        hasPay: Bool,
        chainId: UInt64?,
        tokenContractAddress: String,
        recipientAddress: String,
        valueHex: String
    ) throws -> Eip681TransactionRequest {
        let hasChainId = chainId != nil
        let chainIdValue = chainId ?? 0

        let requestPtr = zcashlc_eip681_erc20_request_from_parts(
            [CChar](schemaPrefix.utf8CString),
            hasPay,
            hasChainId,
            chainIdValue,
            [CChar](tokenContractAddress.utf8CString),
            [CChar](recipientAddress.utf8CString),
            [CChar](valueHex.utf8CString)
        )

        guard let requestPtr else {
            throw ZcashError.rustEip681Parse(
                lastErrorMessage(fallback: "`createErc20TransactionRequest` failed with unknown error")
            )
        }

        defer { zcashlc_free_eip681_transaction_request(requestPtr) }

        return try extractTransactionRequest(requestPtr)
    }

    // MARK: - Private helpers

    /// Extract the typed ``Eip681TransactionRequest`` from a raw FFI pointer.
    private static func extractTransactionRequest(
        _ requestPtr: OpaquePointer
    ) throws -> Eip681TransactionRequest {
        let requestType = zcashlc_eip681_transaction_request_type(requestPtr)

        if requestType == FfiEip681TransactionRequestType_Native {
            return .native(try extractNativeRequest(requestPtr))
        } else if requestType == FfiEip681TransactionRequestType_Erc20 {
            return .erc20(try extractErc20Request(requestPtr))
        } else {
            return .unrecognised
        }
    }

    private static func extractNativeRequest(
        _ requestPtr: OpaquePointer
    ) throws -> Eip681NativeRequest {
        let nativePtr = zcashlc_eip681_transaction_request_as_native(requestPtr)

        guard let nativePtr else {
            throw ZcashError.rustEip681Parse(
                lastErrorMessage(fallback: "Failed to extract native request data")
            )
        }

        defer { zcashlc_free_eip681_native_request(nativePtr) }

        let native = nativePtr.pointee

        let chainId: UInt64? = native.has_chain_id ? native.chain_id : nil
        let schemaPrefix = String(cString: native.schema_prefix)
        let hasPay = native.has_pay
        let recipientAddress = String(cString: native.recipient_address)
        let valueHex = optionalString(native.value_hex)
        let gasLimitHex = optionalString(native.gas_limit_hex)
        let gasPriceHex = optionalString(native.gas_price_hex)

        return Eip681NativeRequest(
            schemaPrefix: schemaPrefix,
            hasPay: hasPay,
            chainId: chainId,
            recipientAddress: recipientAddress,
            valueHex: valueHex,
            gasLimitHex: gasLimitHex,
            gasPriceHex: gasPriceHex
        )
    }

    private static func extractErc20Request(
        _ requestPtr: OpaquePointer
    ) throws -> Eip681Erc20Request {
        let erc20Ptr = zcashlc_eip681_transaction_request_as_erc20(requestPtr)

        guard let erc20Ptr else {
            throw ZcashError.rustEip681Parse(
                lastErrorMessage(fallback: "Failed to extract ERC-20 request data")
            )
        }

        defer { zcashlc_free_eip681_erc20_request(erc20Ptr) }

        let erc20 = erc20Ptr.pointee

        let schemaPrefix = String(cString: erc20.schema_prefix)
        let hasPay = erc20.has_pay
        let chainId: UInt64? = erc20.has_chain_id ? erc20.chain_id : nil
        let tokenContractAddress = String(cString: erc20.token_contract_address)
        let recipientAddress = String(cString: erc20.recipient_address)
        let valueHex = String(cString: erc20.value_hex)

        return Eip681Erc20Request(
            schemaPrefix: schemaPrefix,
            hasPay: hasPay,
            chainId: chainId,
            tokenContractAddress: tokenContractAddress,
            recipientAddress: recipientAddress,
            valueHex: valueHex
        )
    }

    /// Convert a nullable C string pointer to an optional Swift String.
    private static func optionalString(_ ptr: UnsafeMutablePointer<CChar>?) -> String? {
        guard let ptr else { return nil }
        return String(cString: ptr)
    }
}

// MARK: - Optional String C interop

private extension Optional where Wrapped == String {
    /// If `self` is non-nil, converts to a C string and passes it to `body`.
    /// If `self` is nil, passes `nil` to `body`.
    func flatMapToCString<R>(_ body: (UnsafePointer<CChar>?) -> R) -> R {
        switch self {
        case .some(let string):
            return string.withCString { body($0) }
        case .none:
            return body(nil)
        }
    }
}
